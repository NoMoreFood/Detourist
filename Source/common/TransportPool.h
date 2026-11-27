#pragma once
#include "Protocol.h"
#include <algorithm>
#include <cstring>

namespace Detourist
{
inline OverflowSlot* PoolOverflowSlot(SharedHeader* header, uint64_t position)
{
    auto bytes = reinterpret_cast<std::byte*>(header) + header->overflowOffset;
    return reinterpret_cast<OverflowSlot*>(bytes + position * header->overflowStride);
}

inline std::byte* OverflowPayload(SharedHeader* header, uint64_t position)
{
    return reinterpret_cast<std::byte*>(PoolOverflowSlot(header, position)) + sizeof(OverflowSlot);
}

inline bool ValidPoolHeader(const SharedHeader* header, size_t bytes, uint64_t processId, uint64_t captureIdentity)
{
    // Validate the mapped extent and both slot tiers before using advertised boundaries.
    if (bytes < sizeof(SharedHeader) || header->magic != ProtocolMagic || header->version != ProtocolVersion ||
        header->processId != processId || (captureIdentity && header->captureIdentity != captureIdentity) ||
        header->capacity < 2 || header->capacity > PoolIndexMask ||
        (header->capacity & (header->capacity - 1)) || header->mappingBytes > TransportBudget ||
        header->mappingBytes > bytes || header->stride % alignof(Slot) ||
        !header->inlinePayloadCapacity || header->inlinePayloadCapacity > header->payloadCapacity ||
        header->stride < uint64_t{sizeof(Slot)} + header->inlinePayloadCapacity ||
        header->overflowCapacity > PoolIndexMask ||
        (header->overflowCapacity && (header->overflowStride % CacheLineBytes ||
            header->overflowStride < uint64_t{sizeof(OverflowSlot)} + header->payloadCapacity)) ||
        (!header->overflowCapacity && (header->overflowStride != 0 ||
            header->inlinePayloadCapacity != header->payloadCapacity)) ||
        sizeof(SharedHeader) + uint64_t{header->capacity} * header->stride != header->overflowOffset ||
        uint64_t{header->overflowOffset} + uint64_t{header->overflowCapacity} * header->overflowStride !=
            header->mappingBytes) return false;
    for (auto character : header->catalogMapping)
    {
        if (!character) return true;
    }
    return false;
}

inline Slot* PoolSlot(SharedHeader* header, uint64_t position)
{
    auto bytes = reinterpret_cast<std::byte*>(header) + sizeof(SharedHeader);
    return reinterpret_cast<Slot*>(bytes + (position & (header->capacity - 1)) * header->stride);
}

inline uint32_t EnsureSlotPayload(Slot* slot, SharedHeader* header, uint32_t neededBytes)
{
    const auto used = slot->payloadOffset + slot->event.payloadBytes;
    const auto fullCapacity = header->payloadCapacity;
    if (used >= fullCapacity) return 0;
    if (!header->inlinePayloadCapacity || slot->overflowIndex) return fullCapacity - used;
    const auto clampedNeeded = std::min<uint64_t>(neededBytes, fullCapacity - used);
    if (used + clampedNeeded <= header->inlinePayloadCapacity) return header->inlinePayloadCapacity - used;
    if (!header->overflowCapacity)
        return used < header->inlinePayloadCapacity ? header->inlinePayloadCapacity - used : 0;

    // Promote oversized snapshots into a shared overflow buffer while keeping inline slots compact.
    const auto deadline = header->frequency ? Clock() + header->frequency / 20 : 0;
    bool countedWaiter = false;
    uint32_t spins = 0;
    for (;;)
    {
        auto head = ReadShared64(header->freeOverflowSlots);
        while (auto index = PoolIndex(head))
        {
            auto overflow = PoolOverflowSlot(header, index - 1);
            auto next = NextPoolHead(head, static_cast<uint32_t>(overflow->next));
            auto observed = InterlockedCompareExchange64(&header->freeOverflowSlots, next, head);
            if (observed == head)
            {
                if (countedWaiter) InterlockedDecrement(&header->waiters);
                auto destination = OverflowPayload(header, index - 1);
                if (used) memcpy(destination, reinterpret_cast<const std::byte*>(slot) + sizeof(Slot), used);
                slot->overflowIndex = index;
                slot->bufferDelta = static_cast<int32_t>(
                    destination - (reinterpret_cast<std::byte*>(slot) + sizeof(Slot)));
                return fullCapacity - used;
            }
            head = observed;
        }
        if (header->stop >= TransportStopped || !deadline || Clock() >= deadline)
        {
            if (countedWaiter) InterlockedDecrement(&header->waiters);
            return used < header->inlinePayloadCapacity ? header->inlinePayloadCapacity - used : 0;
        }
        if (!countedWaiter)
        {
            countedWaiter = true;
            InterlockedIncrement(&header->waiters);
        }
        YieldProcessor();
#ifndef DETOURIST_INSTRUCTION_CLIENT
        if ((++spins & 63) == 0) SwitchToThread();
#else
        (void)spins;
#endif
    }
}

inline void StampSlotModuleEpoch(SharedHeader* header, Slot* slot)
{
    auto epoch = static_cast<uint64_t>(ReadShared64(header->moduleEpoch));
    auto lost = static_cast<uint64_t>(ReadShared64(header->moduleHistoryLost));
    slot->event.moduleEpoch = lost && epoch >= lost ? UINT64_MAX : epoch;
}

template<class WaitForSpace>
Slot* AcquireSlot(SharedHeader* header, WaitForSpace waitForSpace)
{
    // Reserve a buffer independently of records still being prepared by other threads.
    auto head = ReadShared64(header->freeSlots);
    int64_t waitStarted = 0;
    for (;;)
    {
        if (header->stop >= TransportStopped)
        {
            if (waitStarted) InterlockedDecrement(&header->waiters);
            return nullptr;
        }
        auto index = PoolIndex(head);
        if (index)
        {
            auto slot = PoolSlot(header, index - 1);
            auto next = NextPoolHead(head, static_cast<uint32_t>(slot->next));
            auto observed = InterlockedCompareExchange64(&header->freeSlots, next, head);
            if (observed == head)
            {
                slot->overflowIndex = 0;
                slot->bufferDelta = 0;
                slot->inputBytes = 0;
                slot->payloadOffset = 0;
                slot->entryTimestamp = 0;
                InterlockedIncrement64(&header->enqueue);
                if (waitStarted)
                {
                    InterlockedAdd64(&header->waitTicks, Clock() - waitStarted);
                    InterlockedDecrement(&header->waiters);
                }
                return slot;
            }
            head = observed;
        }
        else
        {
            if (!waitStarted)
            {
                waitStarted = Clock();
                InterlockedIncrement(&header->waiters);
            }
            if (!waitForSpace())
            {
                InterlockedExchange(&header->stop, TransportStopped);
                InterlockedDecrement(&header->waiters);
                return nullptr;
            }
            head = ReadShared64(header->freeSlots);
        }
    }
}

inline bool PublishSlot(SharedHeader* header, Slot* slot)
{
    // Calls retain the loader generation independently of delayed module notifications and queue delivery order.
    if (slot->event.kind == EventKind::Enter && !slot->entryTimestamp) StampSlotModuleEpoch(header, slot);

    // Make a completed record visible with one tagged list insertion.
    auto head = ReadShared64(header->readySlots);
    for (;;)
    {
        slot->next = PoolIndex(head);
        auto observed = InterlockedCompareExchange64(&header->readySlots, NextPoolHead(head, slot->index), head);
        if (observed == head) break;
        head = observed;
    }
    InterlockedIncrement64(&header->published);
    return !PoolIndex(head);
}
}

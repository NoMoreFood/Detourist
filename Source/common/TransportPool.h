#pragma once
#include "Protocol.h"

namespace Detourist
{
inline bool ValidPoolHeader(const SharedHeader* header, size_t bytes, uint64_t processId, uint64_t captureIdentity)
{
    // Validate the mapped extent before using its advertised slot boundaries.
    if (bytes < sizeof(SharedHeader) || header->magic != ProtocolMagic || header->version != ProtocolVersion ||
        header->processId != processId || (captureIdentity && header->captureIdentity != captureIdentity) ||
        header->capacity < 2 || header->capacity > PoolIndexMask ||
        (header->capacity & (header->capacity - 1)) || header->mappingBytes > TransportBudget ||
        header->mappingBytes > bytes || header->stride % alignof(Slot) ||
        header->stride < uint64_t{sizeof(Slot)} + header->payloadCapacity ||
        sizeof(SharedHeader) + uint64_t{header->capacity} * header->stride != header->mappingBytes) return false;
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
    if (slot->event.kind == EventKind::Enter)
    {
        auto epoch = static_cast<uint64_t>(ReadShared64(header->moduleEpoch));
        auto lost = static_cast<uint64_t>(ReadShared64(header->moduleHistoryLost));
        slot->event.moduleEpoch = lost && epoch >= lost ? UINT64_MAX : epoch;
    }

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

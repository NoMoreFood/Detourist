#pragma once
#include "CaptureValues.h"
#include <algorithm>
#include <cstring>
#include <optional>

namespace Detourist
{
inline uint64_t CapturePointer(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    bool guarded = false)
{
    // Only a complete recorded pointer establishes the referenced allocation.
    auto offset = slot->event.payloadBytes;
    if (CopyValue(slot, header, parameter, ValueKind::Scalar, address, sizeof(uintptr_t),
        {.guarded = guarded}) != sizeof(uintptr_t)) return 0;
    uintptr_t pointer = 0;
    memcpy(&pointer, Transport::Payload(slot) + offset + sizeof(Value), sizeof(pointer));
    return pointer;
}

// Specialize fixed pointer widths and string/count modes at each call site.
__forceinline void CaptureRecordReference(Slot* slot, SharedHeader* header, uint32_t parameter,
    const std::byte* record, uint32_t pointerOffset, std::optional<size_t> lengthOffset, ValueKind kind, uint32_t flags,
    uint32_t pointerBytes = sizeof(uintptr_t), bool guarded = false)
{
    // The caller bounds these fields within a retained SDK or catalog record before following references.
    uint64_t pointer = 0;
    uint32_t bytes = 0;
    memcpy(&pointer, record + pointerOffset, pointerBytes);
    if (lengthOffset) memcpy(&bytes, record + *lengthOffset, sizeof(bytes));
    if (!pointer || lengthOffset && !bytes) return;
    CopyValue(slot, header, parameter, kind, pointer, lengthOffset ? bytes : UINT64_MAX,
        {.terminated = !lengthOffset, .guarded = guarded, .flags = flags});
}

inline uint32_t CaptureTerminatedPointers(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, uint32_t flags)
{
    auto available = header->payloadCapacity - slot->event.payloadBytes;
    if (available < sizeof(Value)) return 0;
    auto maximum = std::min<uint32_t>(header->bufferLimit, available - sizeof(Value));
    uint64_t bytes = 0;
    bool terminated = false, unreadable = false;

    // Scan only the bounded pointer prefix that can be included in this snapshot.
    while (bytes + sizeof(uintptr_t) <= maximum)
    {
        uintptr_t pointer = 0;
        if (address > UINT64_MAX - bytes || !ReadCaptureMemory(
            reinterpret_cast<void*>(address + bytes), &pointer, sizeof(pointer)))
        {
            unreadable = true;
            break;
        }
        bytes += sizeof(pointer);
        if (!pointer)
        {
            terminated = true;
            break;
        }
    }
    return CopyValue(slot, header, parameter, ValueKind::Bytes, address, bytes ? bytes : sizeof(uintptr_t),
        {.unknownExtent = !terminated,
         .flags = flags | (terminated ? 0u : Truncated) | (unreadable ? Unreadable : 0u)});
}

template<class Capture>
void CapturePointerRecords(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint32_t flags, Capture capture)
{
    auto table = slot->event.payloadBytes;
    auto bytes = CaptureTerminatedPointers(slot, header, parameter, address, flags);

    // Only complete retained pointers establish indexed records; the null terminator owns no record.
    for (uint32_t index = 0; index < bytes / sizeof(uintptr_t); ++index)
    {
        uintptr_t pointer = 0;
        memcpy(&pointer, Transport::Payload(slot) + table + sizeof(Value) + uint64_t{index} * sizeof(pointer),
            sizeof(pointer));
        if (!pointer) break;
        capture((index << 8) | parameter, pointer);
    }
}

}

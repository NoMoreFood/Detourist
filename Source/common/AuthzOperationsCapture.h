#pragma once
#include "CaptureValues.h"
#include <algorithm>
#include <authz.h>
#include <cstring>

namespace Detourist
{
template<class State>
void CaptureAuthzOperations(State& call, Slot* slot, bool leaving, uint32_t index,
    const ExportParameter& parameter)
{
    if (leaving || !(parameter.flags & ExportInput) || index >= MaximumArguments) return;
    auto header = call.transport->Header();
    auto snapshot = slot->event.payloadBytes;
    if (snapshot > header->payloadCapacity || header->payloadCapacity - snapshot < sizeof(Value)) return;
    auto address = call.event.arguments[index];

    // Retain the first enum before following a context or attempting a larger array snapshot.
    if (!address) return;
    if (address > UINTPTR_MAX - (sizeof(uint32_t) - 1))
    {
        Value value{index, ValueKind::Bytes, Unreadable, 0, sizeof(uint32_t)};
        memcpy(Transport::Payload(slot) + snapshot, &value, sizeof(value));
        slot->event.payloadBytes += sizeof(value);
        return;
    }
    CopyValue(slot, header, index, ValueKind::Bytes, address, sizeof(uint32_t), {.guarded = true});
    if (slot->event.payloadBytes <= snapshot) return;
    Value value{};
    memcpy(&value, Transport::Payload(slot) + snapshot, sizeof(value));
    if (value.capturedBytes != sizeof(uint32_t)) return;
    uint32_t operation = 0;
    memcpy(&operation, Transport::Payload(slot) + snapshot + sizeof(Value), sizeof(operation));
    static_assert(AUTHZ_SID_OPERATION_REPLACE_ALL == 1 && AUTHZ_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL == 1);
    if (operation == AUTHZ_SID_OPERATION_REPLACE_ALL || !parameter.actualIndex ||
        parameter.actualIndex > MaximumArguments) return;
    auto context = call.event.arguments[parameter.actualIndex - 1];
    uint32_t count = 0;
    if (!context || context > UINTPTR_MAX - parameter.actualOffset - (sizeof(count) - 1) ||
        !ReadGuardedCaptureMemory(reinterpret_cast<const void*>(context + parameter.actualOffset),
            &count, sizeof(count)) ||
        count == 1) return;

    // The global and remaining payload limits bound reads while preserving the full logical array size.
    auto bytes = uint64_t{count} * sizeof(operation);
    auto limit = std::min<uint64_t>(bytes, header->bufferLimit);
    limit = std::min<uint64_t>(limit, header->payloadCapacity - snapshot - sizeof(Value));
    if (limit && address > UINTPTR_MAX - (limit - 1)) return;
    slot->event.payloadBytes = snapshot;
    CopyValue(slot, header, index, ValueKind::Bytes, address, bytes, {.guarded = true});
}
}

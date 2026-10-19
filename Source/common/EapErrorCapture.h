#pragma once
#include "PointerCaptureValues.h"
#include <eaptypes.h>
#include <cstddef>

namespace Detourist
{
template<class State>
void CaptureEapError(State& call, Slot* slot, bool leaving, uint32_t index, const ExportParameter& parameter)
{
    if (index >= MaximumArguments) return;
    const auto sample = uint32_t{1} << index;
    auto address = call.event.arguments[index];
    if (!leaving)
    {
        // A failed call establishes a new error only when it replaces a safely sampled output pointer.
        call.initializedOutputs &= ~sample;
        call.captureLimits[index] = 0;
        uintptr_t initial = 0;
        if ((parameter.flags & ExportOutput) && !(call.event.flags & (Skipped | Unwound)) && address &&
            ReadGuardedCaptureMemory(reinterpret_cast<const void*>(address), &initial, sizeof(initial)))
        {
            call.captureLimits[index] = initial;
            call.initializedOutputs |= sample;
        }
        return;
    }
    if (!(parameter.flags & ExportOutput) || !(call.initializedOutputs & sample) || !(call.event.flags & Failed) ||
        !static_cast<uint32_t>(call.event.result) || call.event.flags & (Skipped | Unwound | AsyncPending)) return;
    auto header = call.transport->Header();
    auto pointerSnapshot = slot->event.payloadBytes;
    if (pointerSnapshot > header->payloadCapacity) return;
    auto pointer = CapturePointer(slot, header, index, address, true);
    if (!pointer || pointer == call.captureLimits[index])
    {
        slot->event.payloadBytes = pointerSnapshot;
        return;
    }

    // The retained SDK record bounds both string pointers before any referenced text is read.
    auto snapshot = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, index, ValueKind::Bytes, pointer, sizeof(EAP_ERROR),
        {.guarded = true, .flags = ReferencedData});
    for (auto offset : {offsetof(EAP_ERROR, pRootCauseString), offsetof(EAP_ERROR, pRepairString)})
    {
        if (captured < offset + sizeof(uintptr_t)) continue;
        uintptr_t text = 0;
        memcpy(&text, Transport::Payload(slot) + snapshot + sizeof(Value) + offset, sizeof(text));
        if (!text) continue;
        CopyValue(slot, header, PackMemberParameter(index, offset),
            ValueKind::Utf16, text, header->bufferLimit,
            {.terminated = true, .guarded = true, .flags = MemberData | ReferencedData});
    }
}
}

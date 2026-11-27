#pragma once
#include "PointerCaptureValues.h"
#include <cstddef>

namespace Detourist
{
template<class State>
void CapturePrintDocumentEvent(State& call, Slot* slot, bool leaving, uint32_t index,
    const ExportParameter& parameter)
{
    if (index >= MaximumArguments) return;
    auto& capacity = call.captureLimits[index];
    if (!leaving) capacity = 0;
    if (parameter.extentIndex < 0 || parameter.extentIndex >= MaximumArguments ||
        !parameter.actualIndex || parameter.actualIndex > MaximumArguments ||
        !parameter.prefixBytes || parameter.prefixBytes > MaximumArguments ||
        call.event.flags & (Skipped | Unwound)) return;
    auto address = call.event.arguments[index];
    if (!address) return;
    const auto event = static_cast<uint16_t>(call.event.arguments[parameter.extentIndex]);
    const auto output = (parameter.flags & ExportOutput) != 0;
    auto header = call.transport->Header();

    // Ignored events may carry arbitrary pointers and capacities.
    if (!output)
    {
        if (leaving) return;
        switch (event)
        {
        case 1: case 2: case 3: case 4: case 5: case 11: case 13: case 14:
            break;
        default:
            return;
        }
        auto bytes = static_cast<uint32_t>(call.event.arguments[parameter.actualIndex - 1]);
        if (bytes) CopyValue(slot, header, index, ValueKind::Bytes, address, bytes, {.guarded = true});
        return;
    }
    const auto pointerResult = event == 1 || event == 3;
    if (!pointerResult && event != 11 && event != 14) return;
    uint64_t bytes = pointerResult ? sizeof(uintptr_t) :
        static_cast<uint32_t>(call.event.arguments[parameter.actualIndex - 1]);
    if (!leaving)
    {
        capacity = bytes;
        if (event == 14 && bytes) CopyValue(slot, header, index, ValueKind::Bytes, address, bytes, {.guarded = true});
        return;
    }

    // S_OK identifies an implemented callback; piResult independently establishes initialized output.
    if (!capacity || call.event.flags & Failed || static_cast<int32_t>(call.event.result) < 0) return;
    int32_t result = 0;
    if (!ReadGuardedCaptureMemory(reinterpret_cast<void*>(call.event.arguments[parameter.prefixBytes - 1]),
            &result, sizeof(result)) || result != 1) return;
    if (!pointerResult)
    {
        bytes = std::min<uint64_t>(bytes, capacity);
        if (bytes) CopyValue(slot, header, index, ValueKind::Bytes, address, bytes, {.guarded = true});
        return;
    }

    // DEVMODE results occupy a native pointer slot; cbOut is unused for these events.
    auto mode = CapturePointer(slot, header, index, address, true);
    constexpr auto sizesOffset = offsetof(DEVMODEW, dmSize);
    static_assert(sizesOffset == 68 && offsetof(DEVMODEW, dmDriverExtra) == 70);
    static_assert(offsetof(DEVMODEW, dmFields) == 72);
    struct { uint16_t bytes, extra; } sizes{};
    if (!mode || mode > UINTPTR_MAX - sizesOffset || !ReadGuardedCaptureMemory(
            reinterpret_cast<void*>(mode + sizesOffset), &sizes, sizeof(sizes)) ||
        sizes.bytes < offsetof(DEVMODEW, dmFields) + sizeof(DWORD)) return;
    uint32_t length = uint32_t{sizes.bytes} + sizes.extra;
    if (mode > UINTPTR_MAX - (length - 1)) return;

    // The public header and private driver bytes share one globally bounded referenced region.
    CopyValue(slot, header, index, ValueKind::Bytes, mode, length, {.guarded = true, .flags = ReferencedData});
}

enum class PrinterPayload : uint32_t { DriverInformation, JobAttributes, Notification };

inline void CapturePrinterPayload(const Event& event, Slot* slot, SharedHeader* header, bool leaving,
    uint32_t index, const ExportParameter& parameter)
{
    if (index >= MaximumArguments || !event.arguments[index] || event.flags & (Skipped | Unwound) ||
        parameter.indirectBytes || parameter.multiplier != 1 || parameter.actualIndex ||
        parameter.actualIndirectBytes || parameter.interfaceIndex || parameter.prefixBytes) return;
    auto address = event.arguments[index];
    auto mode = static_cast<PrinterPayload>(parameter.bytes);

    // Driver and job-attribute record sizes are selected by the documented level.
    if (mode == PrinterPayload::DriverInformation || mode == PrinterPayload::JobAttributes)
    {
        const auto driver = mode == PrinterPayload::DriverInformation;
        if (index != (driver ? 3u : 4u) || parameter.extentIndex != (driver ? 2 : 3) ||
            parameter.flags != (driver ? ExportInput : ExportInput | ExportOutput) ||
            leaving && (driver || event.flags & (Failed | AsyncPending) || static_cast<int32_t>(event.result) < 0))
            return;
        const auto level = static_cast<uint32_t>(event.arguments[parameter.extentIndex]);
        uint32_t bytes = 0;
        if (driver)
        {
            if (level == 1) bytes = sizeof(uintptr_t);
            else if (level == 2) bytes = 6 * sizeof(uintptr_t);
            else if (level == 3) bytes = 10 * sizeof(uintptr_t);
        }
        else
        {
            constexpr uint32_t sizes[] = {28, 32, 36, 56};
            if (level >= 1 && level <= 4) bytes = sizes[level - 1];
        }
        if (bytes) CopyValue(slot, header, index, ValueKind::Bytes, address, bytes, {.guarded = true});
        return;
    }
    if (mode != PrinterPayload::Notification || index != 3 || parameter.extentIndex != -1 ||
        parameter.flags != ExportInput || leaving) return;

    // Only a complete retained notification entry can establish a length and pointer to follow.
    constexpr uint32_t countOffset = 8;
    constexpr uint32_t arrayOffset = sizeof(uintptr_t) == 8 ? 16 : 12;
    constexpr uint32_t stride = sizeof(uintptr_t) == 8 ? 32 : 20;
    constexpr uint32_t lengthOffset = sizeof(uintptr_t) == 8 ? 16 : 12;
    constexpr uint32_t pointerOffset = sizeof(uintptr_t) == 8 ? 24 : 16;
    uint32_t count = 0;
    const auto available = EnsureSlotPayload(slot, header, static_cast<uint32_t>(sizeof(Value)) + 12);
    if (header->bufferLimit < 12 || available < sizeof(Value) + 12 || address > UINTPTR_MAX - countOffset ||
        !ReadGuardedCaptureMemory(reinterpret_cast<const void*>(address + countOffset), &count, sizeof(count)))
    {
        CopyValue(slot, header, index, ValueKind::Bytes, address, 12, {.guarded = true});
        return;
    }
    const auto snapshot = slot->event.payloadBytes;
    CopyValue(slot, header, index, ValueKind::Bytes, address,
        count ? uint64_t{arrayOffset} + uint64_t{count} * stride : 12, {.guarded = true});
    if (slot->event.payloadBytes <= snapshot) return;
    Value root{};
    memcpy(&root, Transport::Payload(slot) + snapshot, sizeof(root));
    if (root.capturedBytes < arrayOffset) return;
    const auto record = Transport::Payload(slot) + snapshot + sizeof(root);
    uint32_t retainedCount = 0;
    memcpy(&retainedCount, record + countOffset, sizeof(retainedCount));
    count = std::min(std::min(count, retainedCount), (root.capturedBytes - arrayOffset) / stride);
    for (uint32_t element = 0; element < count; ++element)
    {
        const auto offset = arrayOffset + element * stride;
        uint16_t type = 0, field = 0;
        memcpy(&type, record + offset, sizeof(type));
        memcpy(&field, record + offset + sizeof(type), sizeof(field));
        const bool referenced = type == 0 && field >= 1 && field <= 12 ||
            type == 1 && (field <= 9 || field == 11 || field == 13 || field == 16);
        if (!referenced || offset + pointerOffset >= ValueMemberMaxOffset) continue;
        CaptureRecordReference(slot, header, PackMemberParameter(index, offset + pointerOffset), record,
            offset + pointerOffset, offset + lengthOffset, ValueKind::Bytes, MemberData | ReferencedData,
            sizeof(uintptr_t), true);
    }
}
}

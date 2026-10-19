#pragma once
#include "PointerCaptureValues.h"

namespace Detourist
{
enum class RtmBuffer : uint32_t
{
    Route, Network, Criteria, BestRoute, AddInput, DeleteInput, BlockInput, AddCurrent, AddPrevious,
    DeleteCurrent, MessageCurrent, MessagePrevious, Enumerated
};

inline void CaptureRtmBuffer(const Event& event, Slot* slot, SharedHeader* header, bool leaving,
    uint32_t index, const ExportParameter& parameter)
{
    if (index >= MaximumArguments || parameter.indirectBytes || parameter.actualIndirectBytes ||
        parameter.multiplier != 1 || parameter.interfaceIndex || parameter.prefixBytes ||
        event.flags & (Skipped | Unwound) || !event.arguments[index] ||
        !(parameter.flags & (leaving ? ExportOutput : ExportInput))) return;
    auto mode = static_cast<RtmBuffer>(parameter.bytes);

    // Handle-based calls can expose only fields whose offsets are shared by both protocol families.
    if (mode >= RtmBuffer::AddInput && mode <= RtmBuffer::Enumerated)
    {
        if (parameter.actualIndex) return;
        bool input = mode <= RtmBuffer::BlockInput;
        if (parameter.flags != (input ? ExportInput : ExportOutput) || leaving == input) return;
        switch (mode)
        {
        case RtmBuffer::AddInput: case RtmBuffer::DeleteInput:
            if (index != 1 || parameter.extentIndex != -1) return;
            break;
        case RtmBuffer::BlockInput: case RtmBuffer::MessageCurrent:
            if (index != 2 || parameter.extentIndex != 1) return;
            break;
        case RtmBuffer::AddCurrent:
            if (index != 4 || parameter.extentIndex != 3) return;
            break;
        case RtmBuffer::AddPrevious:
            if (index != 5 || parameter.extentIndex != 3) return;
            break;
        case RtmBuffer::DeleteCurrent:
            if (index != 3 || parameter.extentIndex != 2) return;
            break;
        case RtmBuffer::MessagePrevious:
            if (index != 3 || parameter.extentIndex != 1) return;
            break;
        case RtmBuffer::Enumerated:
            if (index != 1 || parameter.extentIndex != -1) return;
            break;
        default: return;
        }
        auto address = event.arguments[index];
        if (input)
        {
            auto selected = mode == RtmBuffer::BlockInput ? static_cast<uint32_t>(event.arguments[1]) : 7u;
            if (selected & ~15u) return;
            auto field = [&](uint32_t offset, uint32_t bytes)
            {
                if (address > UINTPTR_MAX - offset || address + offset > UINTPTR_MAX - (bytes - 1)) return;
                CopyValue(slot, header, PackMemberParameter(index, offset), ValueKind::Bytes,
                    address + offset, bytes, {.guarded = true, .flags = MemberData});
            };
            if (mode == RtmBuffer::BlockInput && (selected & 4)) field(8, 4);
            if (selected & 2) field(12, 4);
            if (mode == RtmBuffer::AddInput) field(16, 16);
            if (selected & 1) field(32, 4);
            return;
        }

        // Returned records exist only for the documented change flag and successful completion.
        const bool message = mode == RtmBuffer::MessageCurrent || mode == RtmBuffer::MessagePrevious;
        auto result = static_cast<uint32_t>(event.result);
        if (event.flags & (Failed | AsyncPending) || result != NO_ERROR && !(message && result == ERROR_MORE_DATA))
            return;
        if (mode != RtmBuffer::Enumerated)
        {
            uint32_t flags = 0;
            if (!ReadGuardedCaptureMemory(reinterpret_cast<const void*>(event.arguments[parameter.extentIndex]),
                    &flags, sizeof(flags))) return;
            bool valid = mode == RtmBuffer::DeleteCurrent || mode == RtmBuffer::AddPrevious ? flags == 3 :
                mode == RtmBuffer::MessagePrevious ? flags == 2 || flags == 3 : flags == 1 || flags == 3;
            if (!valid) return;
        }
        CopyValue(slot, header, index, ValueKind::Bytes, address, 36, {.guarded = true});
        return;
    }
    if (parameter.extentIndex != 0 || static_cast<uint32_t>(event.arguments[0]) > 1) return;

    // These contracts use a ProtocolFamily argument, never a client or enumeration handle.
    switch (mode)
    {
    case RtmBuffer::Route:
        if (index != 2 || parameter.flags != (ExportInput | ExportOutput) || parameter.actualIndex) return;
        break;
    case RtmBuffer::Network:
        if (index != 1 || parameter.flags != ExportInput || parameter.actualIndex) return;
        break;
    case RtmBuffer::Criteria:
        if (index != 2 || (parameter.flags != ExportInput && parameter.flags != (ExportInput | ExportOutput)) ||
            parameter.actualIndex != 2) return;
        break;
    case RtmBuffer::BestRoute:
        if (index != 2 || parameter.flags != ExportOutput || parameter.actualIndex) return;
        break;
    default: return;
    }

    // Criteria fields are initialized only when their corresponding enumeration flags select them.
    const auto flags = static_cast<uint32_t>(event.arguments[1]);
    if (mode == RtmBuffer::Criteria && !leaving && (!(flags & 7) || (flags & ~15u))) return;
    if (leaving && (event.flags & (Failed | AsyncPending) || (mode == RtmBuffer::BestRoute ?
        static_cast<uint32_t>(event.result) == FALSE : static_cast<uint32_t>(event.result) != NO_ERROR))) return;
    const auto network = mode == RtmBuffer::Network;
    const uint32_t bytes = static_cast<uint32_t>(event.arguments[0]) == 1 ? network ? 8u : 92u : network ? 4u : 52u;
    CopyValue(slot, header, index, ValueKind::Bytes, event.arguments[index], bytes, {.guarded = true});
}
}

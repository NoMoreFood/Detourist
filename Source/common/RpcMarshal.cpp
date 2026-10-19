#include "RpcFormats.h"
#include <rpc.h>
#include <rpcndr.h>
#include <ndr64types.h>
#include <algorithm>

namespace Detourist
{
void (WINAPI* RpcMarshalObserver)(uint64_t, uint32_t, uint32_t) = nullptr;

void CaptureRpcMarshalValues(const Event& event, Slot* slot, SharedHeader* header,
    uint32_t operation, uint32_t nativeBytes, bool leaving)
{
    if (event.flags & (Skipped | Unwound)) return;
    auto capture = [&](uint32_t parameter, uint64_t address, uint64_t length, ValueKind kind)
    {
        const auto available = header->payloadCapacity - slot->event.payloadBytes;
        if (!address || !length || available < sizeof(Value)) return;
        const auto captured = std::min<uint64_t>(length,
            std::min<uint64_t>(header->bufferLimit, available - sizeof(Value)));
        Value value{parameter, kind, 0, static_cast<uint32_t>(captured), length};
        if (value.capturedBytes < length) value.flags |= Truncated;
        auto data = Transport::Payload(slot) + slot->event.payloadBytes;
        if (!ReadRpcMemory(reinterpret_cast<void*>(address), data + sizeof(Value), value.capturedBytes))
        { value.capturedBytes = 0; value.flags |= Unreadable; }
        memcpy(data, &value, sizeof(value));
        slot->event.payloadBytes += static_cast<uint32_t>(sizeof(Value)) + value.capturedBytes;
    };

    // Native values and completed wire spans are observed at the callback's own marshaling boundary.
    if (!leaving) capture(0, event.arguments[0], sizeof(ULONG), ValueKind::Scalar);
    if (leaving == (operation == 2)) capture(2, event.arguments[2], nativeBytes, ValueKind::Bytes);
    if (leaving && event.result >= event.arguments[1])
        capture(1, event.arguments[1], event.result - event.arguments[1], ValueKind::Bytes);
}

void DiscoverRpcMarshalers(const RpcCaptureState& state)
{
    if (!state.marshalRoutines || !RpcMarshalObserver) return;
    uint64_t formats[256]{};
    uint32_t count = 0;
    auto add = [&](uint64_t format)
    {
        if (!format || count == std::size(formats)) return;
        for (uint32_t index = 0; index < count; ++index) if (formats[index] == format) return;
        formats[count++] = format;
    };
    for (uint32_t index = 0; index < state.info.parameterCount; ++index)
        if (!(state.parameters[index].attributes & RpcBaseType)) add(state.parameters[index].type);
    const bool ndr64 = state.info.flags & RpcNdr64;

    // Traverse declared types before the call, including output-only values and every union arm.
    for (uint32_t index = 0; index < count; ++index)
    {
        auto format = formats[index];
        uint8_t code = 0, width = 0;
        if (!ReadRpc(format, code) || RpcScalar(code, ndr64, width) != RpcValueType::Unknown) continue;
        if (ndr64 ? code == 0xA2 : code == 0xB4)
        {
            uint16_t routine = 0;
            const auto bytes = RpcMemorySize(format, ndr64);
            if (bytes && ReadRpc(format + 2, routine)) RpcMarshalObserver(state.marshalRoutines, routine, bytes);
            continue;
        }
        if (ndr64 ? code >= 0x20 && code <= 0x23 : code >= 0x11 && code <= 0x14)
        {
            if (RpcPointer(format, ndr64, code)) add(format);
            continue;
        }
        if (!ndr64 && code == 0x4C)
        {
            int16_t relative = 0;
            if (ReadRpc(format + 2, relative)) add(format + 2 + relative);
            continue;
        }
        if (!ndr64 && code == 0x21)
        {
            add(format + 4 + 2 * state.correlationBytes);
            continue;
        }
        if (ndr64 && (code == 0x46 || code == 0x47))
        {
            NDR64_BOGUS_ARRAY_HEADER_FORMAT array{};
            if (ReadRpc(format, array)) add(reinterpret_cast<uint64_t>(array.Element));
            continue;
        }
        if (ndr64 ? code == 0x50 || code == 0x51 : code == 0x2A || code == 0x2B)
        {
            uint64_t arms = 0;
            uint32_t armCount = 0;
            if (ndr64)
            {
                arms = format + (code == 0x50 ? sizeof(NDR64_ENCAPSULATED_UNION) :
                    sizeof(NDR64_NON_ENCAPSULATED_UNION));
                NDR64_UNION_ARM_SELECTOR selector{};
                if (!ReadRpc(arms, selector)) continue;
                armCount = selector.Arms;
                arms += sizeof(selector);
            }
            else
            {
                arms = format + 2;
                if (code == 0x2B)
                {
                    int16_t relative = 0;
                    arms += state.correlationBytes;
                    if (!ReadRpc(arms, relative)) continue;
                    arms += relative;
                }
                uint16_t selector = 0;
                if (!ReadRpc(arms + 2, selector)) continue;
                armCount = selector & 0xFFF;
                arms += 4;
            }
            if (armCount > RpcMaxMembers) continue;
            for (uint32_t arm = 0; arm <= armCount; ++arm)
            {
                const auto address = arms + arm * (ndr64 ? sizeof(NDR64_UNION_ARM) : 6) +
                    (arm < armCount ? ndr64 ? offsetof(NDR64_UNION_ARM, Type) : 4 : 0);
                if (ndr64)
                {
                    uint32_t sentinel = 0;
                    uintptr_t type = 0;
                    if (arm == armCount && (!ReadRpc(address, sentinel) || !sentinel || sentinel == UINT32_MAX))
                        continue;
                    if (ReadRpc(address, type)) add(type);
                }
                else
                {
                    uint16_t relative = 0;
                    if (ReadRpc(address, relative) && relative && relative != UINT16_MAX &&
                        (relative & 0xFF00) != 0x8000) add(address + static_cast<int16_t>(relative));
                }
            }
            continue;
        }
        if (!ndr64 && (code == 0x15 || code == 0x1A))
        {
            auto member = format + 4;
            uint64_t pointers = 0;
            if (code == 0x1A)
            {
                int16_t array = 0, pointer = 0;
                if (!ReadRpc(format + 4, array) || !ReadRpc(format + 6, pointer)) continue;
                if (array) add(format + 4 + array);
                if (pointer) pointers = format + 6 + pointer;
                member += 4;
            }
            for (uint32_t item = 0; item < RpcMaxMembers; ++item)
            {
                uint8_t token = 0;
                if (!ReadRpc(member, token) || token == 0x5B) break;
                if (token == 0x4C) { add(member); member += 4; }
                else
                {
                    if (token == 0x36 && pointers) { add(pointers); pointers += 4; }
                    else if (RpcScalar(token, false, width) == RpcValueType::Unknown && token != 0x5C &&
                        !(token >= 0x37 && token <= 0x44)) break;
                    ++member;
                }
            }
            continue;
        }
        if (ndr64 && (code == 0x34 || code == 0x35))
        {
            NDR64_BOGUS_STRUCTURE_HEADER_FORMAT structure{};
            if (!ReadRpc(format, structure)) continue;
            auto member = structure.OriginalMemberLayout ? reinterpret_cast<uint64_t>(structure.OriginalMemberLayout) :
                format + sizeof(structure);
            auto pointers = reinterpret_cast<uint64_t>(structure.PointerLayout ?
                structure.PointerLayout : structure.OriginalPointerLayout);
            for (uint32_t item = 0; item < RpcMaxMembers; ++item)
            {
                uint8_t token = 0;
                if (!ReadRpc(member, token) || token == 0x93) break;
                if (token == 0x91)
                {
                    NDR64_EMBEDDED_COMPLEX_FORMAT embedded{};
                    if (!ReadRpc(member, embedded)) break;
                    add(reinterpret_cast<uint64_t>(embedded.Type));
                    member += sizeof(embedded);
                }
                else if (token == 0x90) member += sizeof(NDR64_MEMPAD_FORMAT);
                else if (token == 0x92) member += sizeof(NDR64_BUFFER_ALIGN_FORMAT);
                else
                {
                    if (token == 0x14 && pointers) { add(pointers); pointers += sizeof(NDR64_POINTER_FORMAT); }
                    else if (RpcScalar(token, true, width) == RpcValueType::Unknown) break;
                    member += sizeof(NDR64_SIMPLE_MEMBER_FORMAT);
                }
            }
        }
    }
}
}

#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "RpcFormats.h"
#include <rpcndr.h>
#include <ndr64types.h>
#include <algorithm>
#include <cstring>

namespace Detourist
{
bool ReadRpcMemory(const void* source, void* destination, size_t bytes)
{
    return ReadGuardedCaptureMemory(source, destination, bytes);
}

RpcValueType RpcScalar(uint8_t code, bool ndr64, uint8_t& bytes)
{
    bytes = 0;
    RpcValueType type = RpcValueType::Unknown;
    if (ndr64)
    {
        switch (code)
        {
        case 1: bytes = 1; type = RpcValueType::UInt8; break;
        case 2: case 0x10: bytes = 1; type = RpcValueType::Int8; break;
        case 3: case 0x11: bytes = 2; type = RpcValueType::UInt16; break;
        case 4: bytes = 2; type = RpcValueType::Int16; break;
        case 5: bytes = 4; type = RpcValueType::Int32; break;
        case 6: case 0x13: bytes = 4; type = RpcValueType::UInt32; break;
        case 7: bytes = 8; type = RpcValueType::Int64; break;
        case 8: bytes = 8; type = RpcValueType::UInt64; break;
        case 0xB: bytes = 4; type = RpcValueType::Float32; break;
        case 0xC: bytes = 8; type = RpcValueType::Float64; break;
        }
    }
    else
    {
        switch (code)
        {
        case 1: case 4: bytes = 1; type = RpcValueType::UInt8; break;
        case 2: case 3: bytes = 1; type = RpcValueType::Int8; break;
        case 5: case 7: bytes = 2; type = RpcValueType::UInt16; break;
        case 6: bytes = 2; type = RpcValueType::Int16; break;
        case 8: case 0xD: case 0xE: bytes = 4; type = RpcValueType::Int32; break;
        case 9: case 0x10: bytes = 4; type = RpcValueType::UInt32; break;
        case 0xA: bytes = 4; type = RpcValueType::Float32; break;
        case 0xB: bytes = 8; type = RpcValueType::Int64; break;
        case 0xC: bytes = 8; type = RpcValueType::Float64; break;
        case 0xB8: bytes = sizeof(void*); type = RpcValueType::Int64; break;
        case 0xB9: bytes = sizeof(void*); type = RpcValueType::UInt64; break;
        }
    }
    return type;
}

bool RpcPointer(uint64_t& format, bool ndr64, uint8_t& code)
{
    if (ndr64)
    {
        NDR64_POINTER_FORMAT pointer{};
        if (code < 0x20 || code > 0x23 || !ReadRpc(format, pointer)) return false;
        format = reinterpret_cast<uint64_t>(pointer.Pointee);
    }
    else
    {
        uint8_t flags = 0;
        int16_t offset = 0;
        if (code < 0x11 || code > 0x14 || !ReadRpc(format + 1, flags) ||
            !ReadRpc(format + 2, offset)) return false;
        format += 2;
        if (!(flags & 8)) format += offset;
    }
    return ReadRpc(format, code);
}

uint32_t RpcMemorySize(uint64_t format, bool ndr64, uint32_t correlationBytes)
{
    uint8_t code = 0, width = 0;
    if (!ReadRpc(format, code)) return 0;
    if (RpcScalar(code, ndr64, width) != RpcValueType::Unknown) return width;
    if (ndr64 ? code >= 0x20 && code <= 0x23 : code >= 0x11 && code <= 0x14) return RpcSlotBytes;
    uint32_t bytes = 0;
    if (ndr64 && (code >= 0x30 && code <= 0x37 || code == 0xA2 || code == 0x50 || code == 0x51))
        ReadRpc(format + (code == 0xA2 || code == 0x50 ? 8 : 4), bytes);
    else if (!ndr64 && (code >= 0x15 && code <= 0x1A || code == 0xB4))
    {
        uint16_t size = 0;
        if (ReadRpc(format + (code == 0xB4 ? 4 : 2), size)) bytes = size;
    }
    else if (!ndr64 && (code == 0x2A || code == 0x2B))
    {
        uint8_t layout = 0;
        uint16_t size = 0;
        int16_t displacement = 0;
        auto arms = format + 2;
        if (code == 0x2B)
        {
            arms += correlationBytes;
            if (!ReadRpc(arms, displacement)) return 0;
            arms += displacement;
        }
        if (!ReadRpc(arms, size) || !ReadRpc(format + 1, layout)) return 0;
        bytes = size + (code == 0x2A ? layout >> 4 : 0);
    }
    return bytes;
}

bool RpcStackValue(const RpcCaptureState& state, const Event& event, uint32_t offset, uint8_t width,
    bool leaving, uint64_t& value)
{
    if (offset % RpcSlotBytes || offset / RpcSlotBytes >=
        static_cast<uint32_t>(state.info.argumentCount - state.info.prefix) ||
        !width || width > 8) return false;
    const auto index = state.info.prefix + offset / RpcSlotBytes;
    bool input = false;
    for (uint32_t parameter = 0; parameter < state.info.parameterCount; ++parameter)
        if (state.parameters[parameter].stackOffset == offset && state.parameters[parameter].attributes & RpcIn)
            input = true;
    if (!leaving && !input) return false;
    value = event.arguments[index];
    if (width < 8) value &= (uint64_t{1} << (width * 8)) - 1;
    return true;
}

bool RpcInteger(uint64_t bits, RpcValueType type, uint8_t width, int64_t& value)
{
    if (!width || width > 8 || type == RpcValueType::Float32 || type == RpcValueType::Float64) return false;
    if (width < 8)
    {
        const auto mask = (uint64_t{1} << (width * 8)) - 1;
        bits &= mask;
        if ((type == RpcValueType::Int8 || type == RpcValueType::Int16 || type == RpcValueType::Int32) &&
            bits & (uint64_t{1} << (width * 8 - 1))) bits |= ~mask;
    }
    value = static_cast<int64_t>(bits);
    return true;
}

bool RpcVariable(const RpcCaptureState& state, const Event& event, bool leaving, bool ndr64,
    uint8_t code, int32_t offset, uint64_t base, int64_t& value)
{
    uint8_t width = 0;
    const auto type = RpcScalar(code, ndr64, width);
    uint64_t bits = 0;
    if (!width) return false;
    if (base)
    {
        if (offset < 0 && base < static_cast<uint32_t>(-int64_t{offset}) ||
            offset >= 0 && base > UINTPTR_MAX - offset ||
            !ReadRpcMemory(reinterpret_cast<void*>(base + offset), &bits, width)) return false;
    }
    else if (offset < 0 || !RpcStackValue(state, event, offset, width, leaving, bits)) return false;
    return RpcInteger(bits, type, width, value);
}

bool RpcArithmetic(uint8_t operation, int64_t left, int64_t right, int64_t& value)
{
    switch (operation)
    {
    case 0x0E:
        if (right > 0 && left > INT64_MAX - right || right < 0 && left < INT64_MIN - right) return false;
        value = left + right; break;
    case 0x0F:
        if (right > 0 && left < INT64_MIN + right || right < 0 && left > INT64_MAX + right) return false;
        value = left - right; break;
    case 0x10:
        if (left > 0 ? right > 0 ? left > INT64_MAX / right : right < INT64_MIN / left :
            left < 0 && (right > 0 ? left < INT64_MIN / right : right < 0 && left < INT64_MAX / right)) return false;
        value = left * right; break;
    case 0x11: case 0x12:
        if (!right || left == INT64_MIN && right == -1) return false;
        value = operation == 0x11 ? left / right : left % right; break;
    case 0x13:
        if (right < 0 || right > 63 || left < 0 || left > (INT64_MAX >> right)) return false;
        value = left << right; break;
    case 0x14:
        if (right < 0 || right > 63) return false;
        value = left >> right; break;
    case 0x15: value = left < right; break;
    case 0x16: value = left <= right; break;
    case 0x17: value = left >= right; break;
    case 0x18: value = left > right; break;
    case 0x19: value = left == right; break;
    case 0x1A: value = left != right; break;
    case 0x1B: value = left & right; break;
    case 0x1C: value = left | right; break;
    case 0x1D: value = left ^ right; break;
    case 0x1E: value = left && right; break;
    case 0x1F: value = left || right; break;
    default: return false;
    }
    return true;
}

bool RpcExpression(const RpcCaptureState& state, const Event& event, uint64_t& format, bool leaving,
    bool ndr64, uint64_t base, int64_t& value, uint32_t& budget, uint32_t depth = 0, bool evaluate = true)
{
    if (depth >= RpcMaxExpressionDepth || !budget--) return false;
    uint8_t data[4]{};
    if (!ReadRpc(format, data)) return false;
    const auto start = format;
    format += sizeof(data);
    if (data[0] == FC_EXPR_CONST32 || data[0] == FC_EXPR_CONST64)
    {
        uint64_t bits = 0;
        const uint8_t width = data[0] == FC_EXPR_CONST32 ? 4 : 8;
        if (ndr64 && width == 8) format = start + offsetof(NDR64_EXPR_CONST64, ConstValue);
        if (!ReadRpcMemory(reinterpret_cast<void*>(format), &bits, width)) return false;
        format += width;
        uint8_t scalarWidth = 0;
        return !evaluate || RpcInteger(bits, RpcScalar(data[1], ndr64, scalarWidth), width, value);
    }
    if (data[0] == FC_EXPR_VAR)
    {
        int32_t offset = 0;
        if (ndr64)
        {
            if (!ReadRpc(format, offset)) return false;
            format += sizeof(offset);
        }
        else
        {
            int16_t displacement = 0;
            memcpy(&displacement, data + 2, sizeof(displacement));
            offset = displacement;
        }
        return !evaluate || RpcVariable(state, event, leaving, ndr64, data[1], offset, base, value);
    }
    if (data[0] == FC_EXPR_NOOP)
    {
        if (data[1] < sizeof(data) || data[1] > 16) return false;
        format = start + data[1];
        return RpcExpression(state, event, format, leaving, ndr64, base, value, budget, depth + 1, evaluate);
    }
    if (data[0] != FC_EXPR_OPER) return false;
    auto expression = [&](int64_t& result, bool execute)
    {
        return RpcExpression(state, event, format, leaving, ndr64, base, result, budget, depth + 1, execute);
    };
    int64_t left = 0, right = 0;
    if (data[1] == 0x20)
    {
        // MIDL stores the two alternatives before the condition; skip their reads until selection is known.
        const auto positive = format;
        if (!expression(left, false)) return false;
        const auto negative = format;
        if (!expression(right, false) || !expression(value, evaluate)) return false;
        auto selected = value ? positive : negative;
        return !evaluate || RpcExpression(state, event, selected, leaving, ndr64, base, value, budget, depth + 1);
    }
    if (!expression(left, evaluate)) return false;
    if (data[1] >= 0x0E && data[1] <= 0x1F)
    {
        const bool execute = evaluate && !(data[1] == 0x1E && !left || data[1] == 0x1F && left);
        if (!expression(right, execute)) return false;
        return !evaluate || RpcArithmetic(data[1], left, right, value);
    }
    if (!evaluate) return data[1] >= 1 && data[1] <= 5;
    switch (data[1])
    {
    case 1: value = left; return true;
    case 2: if (left == INT64_MIN) return false; value = -left; return true;
    case 3: value = !left; return true;
    case 4: value = ~left; return true;
    case 5:
    {
        uint8_t width = 0;
        const auto type = RpcScalar(data[2], ndr64, width);
        uint64_t bits = 0;
        return width && ReadRpcMemory(reinterpret_cast<void*>(left), &bits, width) &&
            RpcInteger(bits, type, width, value);
    }
    default: return false;
    }
}

bool RpcCorrelation32(const RpcCaptureState& state, const Event& event, uint64_t format, bool leaving,
    uint64_t& count, uint64_t memory, uint64_t container)
{
    uint8_t data[4]{};
    if (!ReadRpc(format, data)) return false;
    int16_t offset = 0;
    memcpy(&offset, data + 2, sizeof(offset));
    const auto context = data[0] & 0xF0;
    if (context == 0x40) { count = data[1] | (uint32_t{static_cast<uint16_t>(offset)} << 8); return true; }
    uint64_t base = context == 0 ? memory : context == 0x10 ? container : 0;
    if (context != 0 && context != 0x10 && context != 0x20 && context != 0x80 ||
        (context == 0 || context == 0x10) && !base) return false;
    int64_t value = 0;
    if (data[1] == 0x5D)
    {
        uint16_t displacement = 0;
        if (!ReadRpc(state.expressionOffsets + static_cast<uint16_t>(offset) * 2, displacement) ||
            !state.expressionFormat) return false;
        auto expression = state.expressionFormat + displacement;
        uint32_t budget = RpcMaxExpressionBudget;
        if (!RpcExpression(state, event, expression, leaving, false, base, value, budget)) return false;
    }
    else
    {
        if (!RpcVariable(state, event, leaving, false, data[1] == 0x54 ? 0xB9 : data[0] & 15,
            offset, base, value)) return false;
        if (data[1] == 0x54)
        {
            uint8_t width = 0;
            const auto type = RpcScalar(data[0] & 15, false, width);
            uint64_t bits = 0;
            if (!width || !ReadRpcMemory(reinterpret_cast<void*>(value), &bits, width) ||
                !RpcInteger(bits, type, width, value)) return false;
        }
        else if (data[1] == 0x55) value /= 2;
        else if (data[1] == 0x56) { if (!RpcArithmetic(0x10, value, 2, value)) return false; }
        else if (data[1] == 0x57) { if (!RpcArithmetic(0x0F, value, 1, value)) return false; }
        else if (data[1] == 0x58) { if (!RpcArithmetic(0x0E, value, 1, value)) return false; }
        else if (data[1]) return false;
    }
    count = static_cast<uint64_t>(value);
    return true;
}

bool RpcCorrelation64(const RpcCaptureState& state, const Event& event, uint64_t format, bool leaving,
    uint64_t& count, uint64_t container)
{
    uint32_t flags = 0, budget = RpcMaxExpressionBudget;
    if (!ReadRpc(format, flags) || flags > 1) return false;
    format += sizeof(flags);
    int64_t value = 0;
    if (!RpcExpression(state, event, format, leaving, true, container, value, budget)) return false;
    count = static_cast<uint64_t>(value);
    return true;
}

bool RpcUnion(const RpcCaptureState& state, const Event& event, uint64_t format, bool leaving,
    uint64_t memory, uint64_t container, RpcUnionExtent& result)
{
    uint8_t code = 0, width = 0;
    if (!ReadRpc(format, code)) return false;
    const bool ndr64 = state.info.flags & RpcNdr64;
    uint64_t arms = 0;
    uint32_t count = 0;
    if (ndr64)
    {
        if (code == 0x50)
        {
            NDR64_ENCAPSULATED_UNION header{};
            if (!ReadRpc(format, header)) return false;
            result.switchCode = header.SwitchType;
            result.offset = header.MemoryOffset;
            result.bytes = header.MemorySize;
            arms = format + sizeof(header);
        }
        else if (code == 0x51)
        {
            NDR64_NON_ENCAPSULATED_UNION header{};
            if (!ReadRpc(format, header) || !RpcCorrelation64(state, event,
                reinterpret_cast<uint64_t>(header.Switch), leaving, result.switchValue, container)) return false;
            result.switchCode = header.SwitchType;
            result.bytes = header.MemorySize;
            arms = format + sizeof(header);
        }
        else return false;
        NDR64_UNION_ARM_SELECTOR selector{};
        if (!ReadRpc(arms, selector)) return false;
        count = selector.Arms;
        arms += sizeof(selector);
    }
    else
    {
        uint8_t layout = 0;
        if (!ReadRpc(format + 1, layout)) return false;
        result.switchCode = layout & 15;
        arms = format + 2;
        if (code == 0x2A) result.offset = layout >> 4;
        else if (code == 0x2B)
        {
            if (!RpcCorrelation32(state, event, arms, leaving, result.switchValue, memory, container)) return false;
            arms += state.correlationBytes;
            int16_t displacement = 0;
            if (!ReadRpc(arms, displacement)) return false;
            arms += displacement;
        }
        else return false;
        uint16_t size = 0, selector = 0;
        if (!ReadRpc(arms, size) || !ReadRpc(arms + 2, selector)) return false;
        result.bytes = size + result.offset;
        count = selector & 0xFFF;
        arms += 4;
    }
    const auto switchType = RpcScalar(result.switchCode, ndr64, width);
    if (!width || !result.bytes || result.offset > result.bytes || count > RpcMaxUnionArms) return false;
    if (result.offset && !ReadRpcMemory(reinterpret_cast<void*>(memory), &result.switchValue, width)) return false;
    int64_t selected = 0;
    if (!RpcInteger(result.switchValue, switchType, width, selected)) return false;
    bool selectedArm = false;
    for (uint32_t index = 0; index < count; ++index)
    {
        int64_t candidate = 0;
        uint64_t bits = 0;
        const auto size = ndr64 ? sizeof(NDR64_UNION_ARM) : 6;
        if (!ReadRpcMemory(reinterpret_cast<void*>(arms + index * size), &bits, ndr64 ? 8 : 4) ||
            !RpcInteger(bits, switchType, width, candidate)) return false;
        if (candidate != selected) continue;
        arms += index * size + (ndr64 ? offsetof(NDR64_UNION_ARM, Type) : 4);
        selectedArm = true;
        break;
    }
    if (!selectedArm) arms += count * (ndr64 ? sizeof(NDR64_UNION_ARM) : 6);
    if (ndr64)
    {
        uint32_t sentinel = 0;
        if (!selectedArm)
        {
            if (!ReadRpc(arms, sentinel) || sentinel == UINT32_MAX) return false;
            if (!sentinel) return true;
        }
        uintptr_t arm = 0;
        if (!ReadRpc(arms, arm)) return false;
        result.arm = arm;
        return ReadRpc(result.arm, result.armCode);
    }
    uint16_t arm = 0;
    if (!ReadRpc(arms, arm) || arm == UINT16_MAX) return false;
    if (!arm) return true;
    if ((arm & 0xFF00) == 0x8000) result.armCode = static_cast<uint8_t>(arm);
    else
    {
        result.arm = arms + static_cast<int16_t>(arm);
        if (!ReadRpc(result.arm, result.armCode)) return false;
    }
    return true;
}

bool RpcArray(const RpcCaptureState& state, const Event& event, uint64_t format, bool leaving,
    RpcArrayExtent& result, bool capacityOnly, uint64_t memory, uint64_t container)
{
    uint8_t code = 0;
    if (!ReadRpc(format, code)) return false;
    uint64_t count = 0, actual = 0;
    if (state.info.flags & RpcNdr64)
    {
        if (code == 0x40)
        {
            NDR64_FIX_ARRAY_HEADER_FORMAT array{};
            if (!ReadRpc(format, array)) return false;
            result.capacity = result.bytes = array.TotalSize;
            result.stride = 1;
            return true;
        }
        if (code == 0x46 || code == 0x47)
        {
            NDR64_CONF_VAR_BOGUS_ARRAY_HEADER_FORMAT array{};
            if (!ReadRpc(format, array) || array.FixedArrayFormat.NumberDims != 1) return false;
            result.element = reinterpret_cast<uint64_t>(array.FixedArrayFormat.Element);
            result.stride = RpcMemorySize(result.element, true);
            if (!result.stride) return false;
            count = array.FixedArrayFormat.NumberElements;
            if (array.ConfDescription && !RpcCorrelation64(state, event,
                reinterpret_cast<uint64_t>(array.ConfDescription), leaving, count, container)) return false;
            actual = count;
            if (!capacityOnly && array.VarDescription && !RpcCorrelation64(state, event,
                reinterpret_cast<uint64_t>(array.VarDescription), leaving, actual, container)) return false;
            uint64_t offset = 0;
            if (array.OffsetDescription &&
                (!RpcCorrelation64(
                     state, event, reinterpret_cast<uint64_t>(array.OffsetDescription), leaving, offset, container) ||
                    offset))
                return false;
        }
        else
        {
            if (code != 0x41 && code != 0x43) return false;
            NDR64_CONF_VAR_ARRAY_HEADER_FORMAT array{};
            if (!ReadRpcMemory(reinterpret_cast<void*>(format), &array,
                code == 0x41 ? sizeof(NDR64_CONF_ARRAY_HEADER_FORMAT) : sizeof(array)) || !array.ElementSize ||
                !RpcCorrelation64(state, event, reinterpret_cast<uint64_t>(array.ConfDescriptor),
                    leaving, count, container)) return false;
            result.stride = array.ElementSize;
            if (array.Flags.IsMultiDimensional) return false;
            if (array.Flags.HasPointerInfo)
                result.pointers = format + (code == 0x41 ? sizeof(NDR64_CONF_ARRAY_HEADER_FORMAT) : sizeof(array));
            actual = count;
            if (!capacityOnly && code == 0x43 &&
                !RpcCorrelation64(state, event, reinterpret_cast<uint64_t>(array.VarDescriptor),
                    leaving, actual, container)) return false;
        }
    }
    else
    {
        uint16_t shortSize = 0;
        if (!ReadRpc(format + 2, shortSize)) return false;
        if (code == 0x1D || code == 0x1E)
        {
            uint32_t size = shortSize;
            if (code == 0x1E && !ReadRpc(format + 2, size)) return false;
            result.capacity = result.bytes = size;
            result.stride = 1;
            return true;
        }
        if (code == 0x21)
        {
            uint32_t correlation = 0;
            if (!ReadRpc(format + 4, correlation)) return false;
            if (correlation == UINT32_MAX) count = shortSize;
            else if (!RpcCorrelation32(state, event, format + 4, leaving, count, memory, container)) return false;
            actual = count;
            const auto variance = format + 4 + state.correlationBytes;
            if (!ReadRpc(variance, correlation)) return false;
            if (!capacityOnly && correlation != UINT32_MAX &&
                !RpcCorrelation32(state, event, variance, leaving, actual, memory, container)) return false;
            auto element = variance + state.correlationBytes;
            uint8_t token = 0;
            if (!ReadRpc(element, token)) return false;
            if (token == 0x4C)
            {
                int16_t displacement = 0;
                if (!ReadRpc(element + 2, displacement)) return false;
                element += 2 + displacement;
            }
            result.element = element;
            result.stride = RpcMemorySize(element, false, state.correlationBytes);
            if (!result.stride) return false;
        }
        else
        {
            if ((code != 0x1B && code != 0x1C) || !shortSize ||
                !RpcCorrelation32(state, event, format + 4, leaving, count, memory, container)) return false;
            result.stride = shortSize;
            actual = count;
            if (!capacityOnly && code == 0x1C &&
                !RpcCorrelation32(
                    state, event, format + 4 + state.correlationBytes, leaving, actual, memory, container))
                return false;
        }
    }
    if (count > static_cast<uint64_t>(INT64_MAX) / result.stride || actual > count) return false;
    result.capacity = count * result.stride;
    result.bytes = actual * result.stride;
    return true;
}

}

#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "RpcCapture.h"
#include "TransportPool.h"
#include "RpcFormats.h"
#include "AsyncIo.h"
#include "CatalogView.h"
#include <rpc.h>
#include <rpcndr.h>
#include <ndr64types.h>
#include <algorithm>
#include <cstring>
#include <intrin.h>
#ifdef DETOURIST_INSTRUCTION_CLIENT
#pragma warning(push, 0)
#include "dr_api.h"
#pragma warning(pop)
#endif

namespace Detourist
{
struct RpcDecoderEntry { const char* name; uint32_t prefix; RpcDecoder decoder; };
constexpr RpcDecoderEntry RpcDecoders[] =
{
    {"NdrClientCall", 2, RpcDecoder::Client},
    {"NdrClientCall2", 2, RpcDecoder::Client2}, {"NdrClientCall3", 3, RpcDecoder::Client3},
    {"NdrAsyncClientCall", 2, RpcDecoder::Async2}, {"Ndr64AsyncClientCall", 3, RpcDecoder::Async3},
    {"NdrDcomAsyncClientCall", 2, RpcDecoder::Dcom2}, {"Ndr64DcomAsyncClientCall", 3, RpcDecoder::Dcom3},
    {"NdrMesProcEncodeDecode", 3, RpcDecoder::Pickle}, {"NdrMesProcEncodeDecode2", 3, RpcDecoder::Pickle2},
    {"NdrMesProcEncodeDecode3", 4, RpcDecoder::Pickle3}, {"NdrClientCall4", 2, RpcDecoder::Client4},
    {"NdrAsyncClientCall2", 2, RpcDecoder::Async4}, {"NdrMesProcEncodeDecode4", 3, RpcDecoder::Pickle4}
};

RpcDecoder RpcDecoderFor(const char* module, const char* name)
{
    if (!module || !name || _stricmp(module, "rpcrt4.dll")) return RpcDecoder::None;
    for (const auto& entry : RpcDecoders) if (!strcmp(entry.name, name)) return entry.decoder;
    return RpcDecoder::None;
}

uint32_t RpcPrefix(RpcDecoder decoder)
{
    for (const auto& entry : RpcDecoders) if (entry.decoder == decoder) return entry.prefix;
    return 0;
}

const char* RpcTypeName(RpcValueType type)
{
    constexpr const char* names[]{"Unknown", "UInt8", "Int8", "UInt16", "Int16", "UInt32", "Int32", "UInt64",
        "Int64", "Float32", "Float64", "char", "wchar_t", "void", "RPC structure", "RPC array",
        "handle_t", "RPC_ASYNC_STATE", "RPC context", "RPC custom value", "RPC union"};
    const auto index = static_cast<uint32_t>(type);
    return index < std::size(names) ? names[index] : names[0];
}

void DescribeRpcParameter(RpcCaptureState& state, uint32_t index)
{
    auto& parameter = state.parameters[index];
    auto& info = state.info.parameters[index];
    const bool ndr64 = state.info.flags & RpcNdr64;
    info.attributes = parameter.attributes;
    info.argument = parameter.attributes & RpcReturn ? UINT16_MAX :
        static_cast<uint16_t>(state.info.prefix + parameter.stackOffset / RpcSlotBytes);
    info.pointerDepth = (parameter.attributes & RpcSimpleRef) != 0;
    auto code = parameter.baseType;
    auto format = parameter.type;
    if (!code && !ReadRpc(format, code)) { state.info.flags |= RpcPartial | RpcDescriptorUnreadable; return; }
    for (uint32_t depth = 0; depth < RpcMaxPointerDepth; ++depth)
    {
        auto next = format;
        auto nextCode = code;
        if (!RpcPointer(next, ndr64, nextCode)) break;
        ++info.pointerDepth;
        format = next;
        code = nextCode;
        if (depth == RpcMaxPointerDepth - 1) state.info.flags |= RpcPartial;
    }
    info.type = RpcScalar(code, ndr64, info.width);
    if (info.type != RpcValueType::Unknown) { info.memorySize = info.width; return; }
    if (ndr64)
    {
        if (code >= 0x60 && code <= 0x64)
            info.type = code == 0x61 || code == 0x64 ? RpcValueType::Utf16 : RpcValueType::Ansi;
        else if (code >= 0x30 && code <= 0x37)
        {
            info.type = RpcValueType::Structure;
            ReadRpc(format + 4, info.memorySize);
        }
        else if (code >= 0x40 && code <= 0x47) info.type = RpcValueType::Array;
        else if (code == 0x70) info.type = RpcValueType::Context;
    }
    else
    {
        if (code >= 0x22 && code <= 0x29)
            info.type = code == 0x25 || code == 0x29 ? RpcValueType::Utf16 : RpcValueType::Ansi;
        else if (code >= 0x15 && code <= 0x1A)
        {
            info.type = RpcValueType::Structure;
            uint16_t size = 0;
            if (ReadRpc(format + 2, size)) info.memorySize = size;
        }
        else if (code >= 0x1B && code <= 0x21) info.type = RpcValueType::Array;
        else if (code == 0x30) info.type = RpcValueType::Context;
    }
    if (ndr64 ? code == 0x50 || code == 0x51 : code == 0x2A || code == 0x2B)
    {
        info.type = RpcValueType::Union;
        info.memorySize = RpcMemorySize(format, ndr64, state.correlationBytes);
    }
    if (ndr64 ? code == 0xA2 : code == 0xB4)
    {
        info.type = RpcValueType::Custom;
        info.memorySize = RpcMemorySize(format, ndr64);
        state.info.flags |= RpcPartial;
    }
    if (info.type == RpcValueType::Unknown) state.info.flags |= RpcPartial;
    if (parameter.attributes & RpcReturn) state.info.flags |= RpcPartial;
}

bool RpcProcedure32(RpcCaptureState& state, uint64_t format, uint64_t types, bool legacy = false)
{
    uint8_t first[2]{};
    if (!ReadRpc(format, first)) return false;
    uint64_t position = format + 2 + ((first[1] & 8) ? 4 : 0);
    uint16_t procedure = 0, stackBytes = 0;
    if (!ReadRpc(position, procedure) || !ReadRpc(position + 2, stackBytes)) return false;
    state.info.procedure = procedure;
    state.stackBytes = stackBytes;
    position += 4;
    if (!first[0])
    {
        uint8_t handle = 0;
        uint16_t offset = 0;
        if (!ReadRpc(position, handle) || !ReadRpc(position + 2, offset)) return false;
        if (handle != 0x30 && handle != 0x31 && handle != 0x32) return false;
        state.bindingOffset = offset;
        position += handle == 0x32 ? 4 : 6;
    }
    if (first[1] & 4) { state.bindingOffset = 0; state.info.flags |= RpcObjectProcedure; }

    // Oi descriptors give sequential stack sizes and directions instead of Oif attributes and offsets.
    if (legacy)
    {
        if (sizeof(void*) != 4 || stackBytes % 4 || stackBytes > MaximumArguments * 4) return false;
        uint32_t offset = first[1] & 4 ? 4u : 0u;
        while (offset < stackBytes)
        {
            uint8_t descriptor[2]{};
            if (state.info.parameterCount >= MaximumArguments || !ReadRpc(position, descriptor)) return false;
            auto& parameter = state.parameters[state.info.parameterCount];
            parameter = {};
            parameter.stackOffset = static_cast<uint16_t>(offset);
            uint32_t width = 0;
            if (descriptor[0] == 0x4E || descriptor[0] == 0x53)
            {
                uint8_t scalar = 0;
                RpcScalar(descriptor[1], false, scalar);
                if (!scalar && descriptor[1] != 0x0F) return false;
                width = std::max(4u, uint32_t{scalar});
                parameter.attributes = RpcBaseType | (descriptor[0] == 0x53 ? RpcOut | RpcReturn : RpcIn);
                parameter.baseType = descriptor[1];
                position += 2;
            }
            else
            {
                uint16_t type = 0;
                uint8_t code = 0;
                if (descriptor[0] < 0x4D || descriptor[0] > 0x52 || !descriptor[1] ||
                    !ReadRpc(position + 2, type) || !ReadRpc(types + type, code)) return false;
                width = descriptor[1] * 4u;
                parameter.type = types + type;
                parameter.attributes = descriptor[0] == 0x50 ? RpcIn | RpcOut :
                    descriptor[0] == 0x51 ? RpcOut : descriptor[0] == 0x52 ? RpcOut | RpcReturn : RpcIn;
                if (code >= 0x15 && code <= 0x1A || code == 0xB4) parameter.attributes |= RpcByValue;
                position += 4;
            }
            if (width > stackBytes - offset) return false;
            if (parameter.baseType != 0x0F) ++state.info.parameterCount;
            else if (state.bindingOffset != offset) return false;
            offset += width;
        }
        return true;
    }
    uint8_t interpreter[6]{};
    if (!ReadRpc(position, interpreter) || interpreter[5] > MaximumArguments) return false;
    if (interpreter[4] & 0xA0) state.info.flags |= RpcAsynchronous | RpcOutputsDeferred;
    position += sizeof(interpreter);
    if (interpreter[4] & 0x40)
    {
        uint8_t extension[2]{};
        if (!ReadRpc(position, extension) || extension[0] < 2 || extension[0] > 64) return false;
        state.correlationBytes = extension[1] & 1 ? 6 : 4;
        position += extension[0];
    }
    for (uint32_t index = 0; index < interpreter[5]; ++index)
    {
        uint16_t descriptor[3]{};
        if (!ReadRpc(position + index * sizeof(descriptor), descriptor)) return false;
        auto& parameter = state.parameters[state.info.parameterCount++];
        parameter.attributes = descriptor[0];
        parameter.stackOffset = descriptor[1];
        if (descriptor[0] & RpcBaseType) parameter.baseType = static_cast<uint8_t>(descriptor[2]);
        else parameter.type = types + descriptor[2];
    }
    return true;
}

bool RpcProcedure64(RpcCaptureState& state, uint64_t format)
{
    NDR64_PROC_FORMAT procedure{};
    if (!ReadRpc(format, procedure) || procedure.NumberOfParams > MaximumArguments ||
        procedure.ExtensionSize > 256) return false;
    state.info.flags |= RpcNdr64;
    state.stackBytes = procedure.StackSize;
    if ((procedure.Flags & 7) == NDR64_FC_EXPLICIT_HANDLE)
    {
        NDR64_BIND_AND_NOTIFY_EXTENSION extension{};
        if (procedure.ExtensionSize < sizeof(extension) || !ReadRpc(format + sizeof(procedure), extension))
            return false;
        state.bindingOffset = extension.Binding.StackOffset;
    }
    if (procedure.Flags & 0x100) { state.bindingOffset = 0; state.info.flags |= RpcObjectProcedure; }
    if (procedure.Flags & 0x200) state.info.flags |= RpcAsynchronous | RpcOutputsDeferred;
    for (uint32_t index = 0; index < procedure.NumberOfParams; ++index)
    {
        NDR64_PARAM_FORMAT descriptor{};
        if (!ReadRpc(format + sizeof(procedure) + procedure.ExtensionSize + index * sizeof(descriptor), descriptor))
            return false;
        auto& parameter = state.parameters[state.info.parameterCount++];
        memcpy(&parameter.attributes, &descriptor.Attributes, sizeof(parameter.attributes));
        parameter.stackOffset = descriptor.StackOffset;
        parameter.type = reinterpret_cast<uint64_t>(descriptor.Type);
    }
    return true;
}

void PrepareRpcCapture(RpcCaptureState& state, RpcDecoder decoder, const uint64_t* arguments)
{
    state = {};
    state.decoder = decoder;
    state.info.prefix = state.info.argumentCount = static_cast<uint8_t>(RpcPrefix(decoder));
    if (decoder == RpcDecoder::None) return;
    if (decoder == RpcDecoder::Async2 || decoder == RpcDecoder::Async3 ||
        decoder == RpcDecoder::Dcom2 || decoder == RpcDecoder::Dcom3 || decoder == RpcDecoder::Async4)
        state.info.flags |= RpcAsynchronous | RpcOutputsDeferred;
    const bool pickle = decoder == RpcDecoder::Pickle || decoder == RpcDecoder::Pickle2 ||
        decoder == RpcDecoder::Pickle3 || decoder == RpcDecoder::Pickle4;
    if (pickle)
    {
        state.info.flags |= RpcPickling;
        const auto operation = static_cast<RpcSerializationMode>(RpcSerializationOperation(arguments[0]));
        if (operation == RpcSerializationMode::Encode || operation == RpcSerializationMode::EncodeDynBuffer)
            state.info.flags |= RpcEncoding;
        else if (operation == RpcSerializationMode::Decode) state.info.flags |= RpcDecoding;
        else state.info.flags |= RpcPartial;
    }
    const bool proxy = decoder == RpcDecoder::Client3 || decoder == RpcDecoder::Async3 ||
        decoder == RpcDecoder::Dcom3 || decoder == RpcDecoder::Pickle3;
    MIDL_STUB_DESC stub{};
    uint64_t format = arguments[pickle ? 2 : 1];
    bool valid = false;
    if (proxy)
    {
        MIDL_STUBLESS_PROXY_INFO information{};
        auto number = static_cast<uint32_t>(arguments[pickle ? 2 : 1]);
        if (!ReadRpc(arguments[pickle ? 1 : 0], information) || number >= RpcMaxProxyProcedures ||
            !ReadRpc(reinterpret_cast<uint64_t>(information.pStubDesc), stub))
        { state.info.flags |= RpcDescriptorUnreadable; return; }
        state.info.procedure = number;
        constexpr GUID ndr64{0x71710533, 0xBEBA, 0x4937, {0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36}};
        for (uint32_t index = 0; index < std::min<ULONG_PTR>(information.nCount, 16); ++index)
        {
            MIDL_SYNTAX_INFO syntax{};
            if (!ReadRpc(reinterpret_cast<uint64_t>(information.pSyntaxInfo) + index * sizeof(syntax), syntax)) break;
            if (syntax.TransferSyntax.SyntaxGUID != ndr64) continue;
            uintptr_t descriptor = 0;
            if (ReadRpc(reinterpret_cast<uint64_t>(syntax.FmtStringOffset) + number * sizeof(void*), descriptor))
                valid = RpcProcedure64(state, descriptor);
            if (valid) state.marshalRoutines = reinterpret_cast<uint64_t>(syntax.aUserMarshalQuadruple);
            break;
        }
        if (!valid && information.ProcFormatString && information.FormatStringOffset)
        {
            state.info.parameterCount = 0;
            state.info.flags &= ~RpcNdr64;
            uint16_t offset = 0;
            if (ReadRpc(reinterpret_cast<uint64_t>(information.FormatStringOffset) + number * 2, offset))
                valid = RpcProcedure32(state, reinterpret_cast<uint64_t>(information.ProcFormatString) + offset,
                    reinterpret_cast<uint64_t>(stub.pFormatTypes));
        }
    }
    else if (ReadRpc(arguments[pickle ? 1 : 0], stub))
        valid = RpcProcedure32(state, format, reinterpret_cast<uint64_t>(stub.pFormatTypes), stub.Version < 0x20000);
    if (!valid) { state.info.flags |= RpcPartial | RpcDescriptorUnreadable; return; }

    if (!state.marshalRoutines) state.marshalRoutines = reinterpret_cast<uint64_t>(stub.aUserMarshalQuadruple);
    NDR_EXPR_DESC expressions{};
    if (ReadRpc(reinterpret_cast<uint64_t>(stub.pExprInfo), expressions))
    {
        state.expressionOffsets = reinterpret_cast<uint64_t>(expressions.pOffset);
        state.expressionFormat = reinterpret_cast<uint64_t>(expressions.pFormatExpr);
    }

    // Interpreter stacks include binding and async handles even when their parameter lists omit those slots.
    uint32_t slots = state.info.flags & RpcAsynchronous ? 1 : 0;
    if (state.bindingOffset != UINT32_MAX) slots = std::max(slots, state.bindingOffset / RpcSlotBytes + 1u);
    for (uint32_t index = 0; index < state.info.parameterCount; ++index)
    {
        const auto& parameter = state.parameters[index];
        if (parameter.stackOffset % RpcSlotBytes || parameter.stackOffset >= state.stackBytes ||
            !(parameter.attributes & RpcReturn) &&
                parameter.stackOffset / RpcSlotBytes >= MaximumArguments - state.info.prefix)
        { state.info.flags |= RpcPartial; return; }
        if (!(parameter.attributes & RpcReturn)) slots = std::max(slots, parameter.stackOffset / RpcSlotBytes + 1u);
    }
    state.info.argumentCount = static_cast<uint8_t>(state.info.prefix + slots);
    if (state.info.argumentCount > MaximumArguments) { state.info.flags |= RpcPartial; return; }
    state.info.flags |= RpcDescriptorValid;
    if ((state.info.flags & (RpcObjectProcedure | RpcAsynchronous)) == (RpcObjectProcedure | RpcAsynchronous) &&
        state.info.procedure >= IUnknownSlotCount && !(state.info.procedure & 1))
        state.info.flags &= ~RpcOutputsDeferred;
    RPC_CLIENT_INTERFACE contract{};
    if (ReadRpc(reinterpret_cast<uint64_t>(stub.RpcInterfaceInformation), contract))
    {
        state.info.interfaceId = contract.InterfaceId.SyntaxGUID;
        state.info.major = contract.InterfaceId.SyntaxVersion.MajorVersion;
        state.info.minor = contract.InterfaceId.SyntaxVersion.MinorVersion;
    }
    for (uint32_t index = 0; index < state.info.parameterCount; ++index) DescribeRpcParameter(state, index);
    auto handle = [&](uint32_t offset, RpcValueType type)
    {
        if (state.info.parameterCount == std::size(state.parameters)) { state.info.flags |= RpcPartial; return; }
        for (uint32_t index = 0; index < state.info.parameterCount; ++index)
            if (state.parameters[index].stackOffset == offset) return;
        auto index = state.info.parameterCount++;
        state.parameters[index].stackOffset = offset;
        state.parameters[index].attributes = RpcIn;
        state.info.parameters[index] = {static_cast<uint16_t>(state.info.prefix + offset / RpcSlotBytes),
            RpcIn, type, static_cast<uint8_t>(type == RpcValueType::AsyncHandle || type == RpcValueType::Pointer),
            static_cast<uint8_t>(RpcSlotBytes), RpcSlotBytes};
    };
    if (state.bindingOffset != UINT32_MAX) handle(state.bindingOffset,
        state.info.flags & RpcObjectProcedure ? RpcValueType::Pointer : RpcValueType::Binding);
    if (state.info.flags & RpcAsynchronous) handle(0, RpcValueType::AsyncHandle);
}

bool PrepareRpcProxyCapture(RpcCaptureState& state, uint64_t table, const GUID* iid, uint32_t slot,
    ExportSignature* signature)
{
    // Stubless proxy headers carry the interface identity and compiler-generated procedure descriptors.
    uintptr_t header[2]{};
    GUID identity{};
    MIDL_STUBLESS_PROXY_INFO proxy{};
    if (slot < IUnknownSlotCount || slot >= RpcMaxVtableSlots || table < sizeof(header) ||
        !ReadRpc(table - sizeof(header), header) ||
        !ReadRpc(header[1], identity) || iid && identity != *iid || !ReadRpc(header[0], proxy)) return false;
    uint16_t offset = 0;
    if (!ReadRpc(reinterpret_cast<uint64_t>(proxy.FormatStringOffset) + slot * 2, offset)) return false;
    uint64_t arguments[]{reinterpret_cast<uint64_t>(proxy.pStubDesc),
        reinterpret_cast<uint64_t>(proxy.ProcFormatString) + offset, 0};
    PrepareRpcCapture(state, RpcDecoder::Client2, arguments);
    constexpr auto required = RpcDescriptorValid | RpcObjectProcedure | RpcAsynchronous;
    if ((state.info.flags & required) != required || state.info.procedure != slot) return false;

    // The NDR32 procedure number bounds table discovery before selecting an available NDR64 description.
    arguments[0] = header[0];
    arguments[1] = slot;
    PrepareRpcCapture(state, RpcDecoder::Dcom3, arguments);
    if ((state.info.flags & required) != required || state.info.procedure != slot) return false;
    const auto prefix = state.info.prefix;
    state.info.prefix = 0;
    state.info.argumentCount -= prefix;
    state.info.interfaceId = identity;
    uint32_t bytes = 0, lastArgument = 0;
    ExportSignature abi{};
    abi.resultBytes = sizeof(HRESULT);
    abi.supported = true;
    abi.callingConvention = ExportCallingConvention::Stdcall;
    std::fill(std::begin(abi.argumentBytes), std::end(abi.argumentBytes), static_cast<uint8_t>(sizeof(void*)));
    for (uint32_t index = 0; index < state.info.parameterCount; ++index)
    {
        auto& parameter = state.info.parameters[index];
        if (parameter.attributes & RpcReturn)
        {
            if (parameter.pointerDepth || parameter.width != sizeof(HRESULT)) return false;
            if (bytes) return false;
            bytes = state.parameters[index].stackOffset;
            continue;
        }
        parameter.argument -= prefix;
        lastArgument = std::max(lastArgument, state.parameters[index].stackOffset);
        if (sizeof(void*) == 8 && !parameter.pointerDepth &&
            (parameter.type == RpcValueType::Float32 || parameter.type == RpcValueType::Float64) &&
            parameter.argument < 4) abi.floatingArguments |= static_cast<uint8_t>(1u << parameter.argument);
    }

    // The HRESULT's interpreter slot follows every physical argument, including packed x86 aggregates.
    if (!bytes || bytes % RpcSlotBytes || bytes > MaximumArguments * RpcSlotBytes ||
        bytes > state.stackBytes - sizeof(HRESULT) || lastArgument >= bytes) return false;
    state.info.argumentCount = static_cast<uint8_t>(bytes / RpcSlotBytes);
    if (signature) *signature = abi;
    return true;
}

void ReadRpcStackArguments(RpcCaptureState& state, uint64_t* arguments, uint64_t address)
{
    state.argumentStack = address;
    if (!(state.info.flags & RpcDescriptorValid)) return;

    // The 32-bit interpreter receives one pointer to the caller's packed native argument stack.
    for (uint32_t index = state.info.prefix; index < state.info.argumentCount; ++index)
    {
        arguments[index] = 0;
        auto offset = (index - state.info.prefix) * RpcSlotBytes;
        if (!address || address > UINTPTR_MAX - offset ||
            !ReadRpcMemory(reinterpret_cast<void*>(address + offset), arguments + index, RpcSlotBytes))
            state.info.flags |= RpcPartial | RpcDescriptorUnreadable;
    }
    for (uint32_t index = 0; index < state.info.parameterCount; ++index)
    {
        const auto& info = state.info.parameters[index];
        const auto& parameter = state.parameters[index];
        if (info.argument >= MaximumArguments || info.pointerDepth || address > UINTPTR_MAX - parameter.stackOffset)
            continue;
        const auto location = address + parameter.stackOffset;
        const auto width = parameter.attributes & RpcByValue &&
            (info.type == RpcValueType::Structure || info.type == RpcValueType::Custom ||
                info.type == RpcValueType::Union) ?
            info.memorySize : info.width;
        if (width > sizeof(uint64_t)) arguments[info.argument] = location;
        else if (width > RpcSlotBytes && (parameter.stackOffset > state.stackBytes ||
            width > state.stackBytes - parameter.stackOffset ||
                !ReadRpcMemory(reinterpret_cast<void*>(location), arguments + info.argument, width)))
            state.info.flags |= RpcPartial | RpcDescriptorUnreadable;
    }
}

bool WriteRpcStackArgument(const RpcCaptureState& state, uint32_t argument, uint64_t value)
{
    if (!(state.info.flags & RpcDescriptorValid) || argument < state.info.prefix ||
        argument >= state.info.argumentCount || !state.argumentStack) return false;
    const auto offset = (argument - state.info.prefix) * RpcSlotBytes;
    uint32_t bytes = RpcSlotBytes;
    bool structure = false;
    for (uint32_t index = 0; index < state.info.parameterCount; ++index)
    {
        const auto& info = state.info.parameters[index];
        if (info.argument != argument || info.pointerDepth) continue;
        const auto byValue = state.parameters[index].attributes & RpcByValue &&
            (info.type == RpcValueType::Structure || info.type == RpcValueType::Custom ||
                info.type == RpcValueType::Union);
        structure = byValue && info.memorySize > sizeof(value);
        bytes = std::max<uint32_t>(RpcSlotBytes, byValue ? info.memorySize : info.width);
        break;
    }
    BYTE record[256]{};
    if (offset > state.stackBytes || bytes > state.stackBytes - offset || bytes > sizeof(record) ||
        state.argumentStack > UINTPTR_MAX - offset ||
        structure && !ReadRpcMemory(reinterpret_cast<void*>(value), record, bytes)) return false;
#ifdef DETOURIST_INSTRUCTION_CLIENT
    return dr_safe_write(reinterpret_cast<void*>(state.argumentStack + offset), bytes,
        structure ? static_cast<const void*>(record) : &value, nullptr);
#else
    __try
    {
        memcpy(reinterpret_cast<void*>(state.argumentStack + offset),
            structure ? static_cast<const void*>(record) : &value, bytes);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
#endif
}

void ObserveRpcDescriptorEdits(RpcCaptureState& state, const uint64_t* before, Event& event)
{
    for (uint32_t index = 0; index < state.info.prefix; ++index)
    {
        if (before[index] == event.arguments[index]) continue;

        // A different procedure can require another ABI; forward the complete incoming call without stale decoding.
        state.info.flags = (state.info.flags & ~RpcDescriptorValid) | RpcPartial;
        state.info.parameterCount = 0;
        state.info.argumentCount = state.info.prefix;
        event.flags |= Continuation;
        return;
    }
}

struct RpcSerializationHandle { uint64_t handle; uint32_t operation; };
RpcSerializationHandle RpcSerializationHandles[RpcSerializationHandleCapacity]{};
volatile LONG RpcSerializationLock = 0;
volatile LONG RpcSerializationUncertain = 0;
uint32_t (WINAPI* RpcSerializationLookup)(uint64_t) = nullptr;

void InvalidateRpcSerialization()
{
    InterlockedExchange(&RpcSerializationUncertain, 1);
}

bool LockRpcSerialization()
{
    for (uint32_t attempt = 0; attempt < 64; ++attempt)
    {
        if (!InterlockedCompareExchange(&RpcSerializationLock, 1, 0)) return true;
        YieldProcessor();
    }
    return false;
}

void StoreRpcSerialization(uint64_t handle, uint32_t operation)
{
    if (!handle || handle == UINT64_MAX) return;
    if (!LockRpcSerialization()) { InvalidateRpcSerialization(); return; }

    // A missed lifetime transition invalidates cached modes until a writer can discard stale entries.
    if (InterlockedExchange(&RpcSerializationUncertain, 0))
        memset(RpcSerializationHandles, 0, sizeof(RpcSerializationHandles));
    const auto bucket = (handle >> 4) % std::size(RpcSerializationHandles);
    RpcSerializationHandle* vacant = nullptr;
    for (size_t step = 0; step < std::size(RpcSerializationHandles); ++step)
    {
        auto& entry = RpcSerializationHandles[(bucket + step) % std::size(RpcSerializationHandles)];
        if (!entry.handle || entry.handle == UINT64_MAX)
        {
            if (!vacant) vacant = &entry;
            if (!entry.handle) break;
        }
        else if (entry.handle == handle) { vacant = &entry; break; }
    }
    if (vacant) *vacant = operation ? RpcSerializationHandle{handle, operation} : RpcSerializationHandle{UINT64_MAX, 0};
    InterlockedExchange(&RpcSerializationLock, 0);
}

uint32_t RpcSerializationOperation(uint64_t handle)
{
    if (RpcSerializationLookup) return RpcSerializationLookup(handle);
    if (!handle || RpcSerializationUncertain || !LockRpcSerialization()) return 0;
    const auto bucket = (handle >> 4) % std::size(RpcSerializationHandles);
    uint32_t result = 0;
    for (size_t step = 0; step < std::size(RpcSerializationHandles); ++step)
    {
        const auto& entry = RpcSerializationHandles[(bucket + step) % std::size(RpcSerializationHandles)];
        if (!entry.handle) break;
        if (entry.handle == handle) { result = entry.operation; break; }
    }
    if (RpcSerializationUncertain) result = 0;
    InterlockedExchange(&RpcSerializationLock, 0);
    return result;
}

void BeginRpcSerialization(Api api, const uint64_t* arguments)
{
    if (api == Api::MesHandleFree || api == Api::MesIncrementalHandleReset || api == Api::MesBufferHandleReset)
        StoreRpcSerialization(arguments[0], static_cast<uint32_t>(RpcSerializationMode::None));
}

void ObserveRpcSerialization(Api api, const uint64_t* arguments, uint64_t result)
{
    if (static_cast<uint32_t>(result)) return;
    if (api == Api::MesHandleFree) return;
    if (api == Api::MesIncrementalHandleReset || api == Api::MesBufferHandleReset)
    {
        const auto operation = static_cast<uint32_t>(arguments[api == Api::MesIncrementalHandleReset ? 5 : 2]);
        if (operation <= 2) StoreRpcSerialization(arguments[0], operation + 1);
        return;
    }
    const auto output =
        api == Api::MesEncodeIncrementalHandleCreate || api == Api::MesEncodeFixedBufferHandleCreate ? 3 : 2;
    uint64_t handle = 0;
    if (!arguments[output] || !ReadCaptureMemory(reinterpret_cast<void*>(arguments[output]), &handle, RpcSlotBytes))
        return;
    StoreRpcSerialization(handle, static_cast<uint32_t>(api == Api::MesDecodeIncrementalHandleCreate ||
        api == Api::MesDecodeBufferHandleCreate ? RpcSerializationMode::Decode : RpcSerializationMode::Encode));
}

class RpcValueCapture
{
public:
    RpcValueCapture(RpcCaptureState& state, Event& event, Slot* slot, SharedHeader* header, bool leaving)
        : state_(state), event_(event), slot_(slot), header_(header), leaving_(leaving) {}

    uint16_t Append(uint32_t parameter, uint16_t parent, RpcValueType type, uint64_t address, uint64_t bytes,
        uint32_t offset = 0, uint32_t stride = 0, bool text = false, uint64_t storage = UINT64_MAX)
    {
        const auto desired = static_cast<uint32_t>(std::min<uint64_t>(bytes, header_->bufferLimit));
        const auto available = EnsureSlotPayload(slot_, header_,
            static_cast<uint32_t>(sizeof(Value) + sizeof(RpcValueInfo)) + desired);
        if (next_ >= RpcMaxValueNodes || available < sizeof(Value) + sizeof(RpcValueInfo))
        { state_.info.flags |= RpcPartial; return RpcNoParent; }
        auto data = Transport::Payload(slot_) + slot_->event.payloadBytes;
        Value value{parameter, ValueKind::RpcValue, 0, sizeof(RpcValueInfo), bytes};
        RpcValueInfo info{next_++, parent, type, 0, offset, stride, storage == UINT64_MAX ? address : storage};
        const auto limit = std::min<uint64_t>(std::min<uint64_t>(bytes, header_->bufferLimit),
            available - sizeof(Value) - sizeof(RpcValueInfo));
        auto destination = data + sizeof(Value) + sizeof(info);
        if (text)
        {
            const uint32_t width = type == RpcValueType::Utf16 ? 2 : 1;
            bool terminated = false;
            for (uint32_t position = 0; position + width <= limit; position += width)
            {
                uint16_t character = 0;
                if (address > UINT64_MAX - position ||
                    !ReadRpcMemory(reinterpret_cast<void*>(address + position), &character, width))
                { value.flags |= Unreadable; break; }
                memcpy(destination + position, &character, width);
                value.capturedBytes += width;
                if (!character) { terminated = true; break; }
            }
            value.originalBytes = terminated ? value.capturedBytes - sizeof(info) : 0;
            if (!terminated) value.flags |= Truncated;
        }
        else if (limit && address && ReadRpcMemory(reinterpret_cast<void*>(address), destination,
            static_cast<size_t>(limit)))
            value.capturedBytes += static_cast<uint32_t>(limit);
        else if (limit) value.flags |= Unreadable;
        if (!text && value.capturedBytes - sizeof(info) < bytes) value.flags |= Truncated;
        memcpy(data, &value, sizeof(value));
        memcpy(data + sizeof(value), &info, sizeof(info));
        slot_->event.payloadBytes += static_cast<uint32_t>(sizeof(value)) + value.capturedBytes;
        return info.node;
    }

    void Parameter(uint32_t index)
    {
        auto& parameter = state_.parameters[index];
        const auto& info = state_.info.parameters[index];
        if (parameter.attributes & RpcReturn || info.argument >= MaximumArguments) return;
        const auto value = event_.arguments[info.argument];
        if (info.type == RpcValueType::Binding || info.type == RpcValueType::AsyncHandle ||
            info.type == RpcValueType::Pointer && !parameter.type)
        {
            if (!leaving_) Append(info.argument, RpcNoParent, info.type,
                reinterpret_cast<uint64_t>(&value), RpcSlotBytes, 0, 0, false, 0);
            return;
        }
        const bool output = parameter.attributes & RpcOut;
        const bool input = parameter.attributes & RpcIn;
        if (state_.info.flags & RpcPickling)
        {
            if (state_.info.flags & RpcEncoding ? leaving_ : !(state_.info.flags & RpcDecoding) || !leaving_) return;
        }
        uint64_t format = parameter.type;
        uint8_t code = parameter.baseType;
        if (!code && !ReadRpc(format, code)) { state_.info.flags |= RpcPartial | RpcDescriptorUnreadable; return; }

        // Caller-owned output arrays retain their submitted capacity; returned allocations derive it on completion.
        if (!leaving_ && output && info.type == RpcValueType::Array && !(state_.info.flags & RpcDecoding))
        {
            for (uint32_t depth = 0; depth < RpcMaxPointerDepth; ++depth)
            {
                auto next = format;
                auto nextCode = code;
                if (!RpcPointer(next, state_.info.flags & RpcNdr64, nextCode)) break;
                format = next;
                code = nextCode;
            }
            RpcArrayExtent extent;
            parameter.capacityValid = RpcArray(state_, event_, format, false, extent, true);
            parameter.capacity = extent.capacity;
            if (!parameter.capacityValid && !input && info.pointerDepth > 1)
            { parameter.capacityValid = true; parameter.capacity = UINT64_MAX; }
            format = parameter.type;
            code = parameter.baseType;
            if (!code && !ReadRpc(format, code)) return;
        }
        if (!(state_.info.flags & RpcPickling) && (leaving_ ? !output : !input)) return;
        if (leaving_ && state_.info.flags & RpcOutputsDeferred) return;
        auto memory = value;
        uint8_t width = 0;
        auto type = RpcScalar(code, state_.info.flags & RpcNdr64, width);
        if (type != RpcValueType::Unknown && !(parameter.attributes & RpcSimpleRef))
        {
            Append(info.argument, RpcNoParent, type, reinterpret_cast<uint64_t>(&value), width, 0, 0, false, 0);
            return;
        }
        else if (parameter.attributes & RpcByValue &&
            (info.type == RpcValueType::Structure || info.type == RpcValueType::Custom ||
                info.type == RpcValueType::Union) &&
            info.memorySize <= sizeof(value)) memory = reinterpret_cast<uint64_t>(&value);
        Walk(index, format, code, memory, RpcNoParent, 0, 0, parameter.attributes & RpcSimpleRef);
    }

private:
    void Walk(uint32_t parameter, uint64_t format, uint8_t code, uint64_t memory, uint16_t parent,
        uint32_t offset, uint32_t depth, bool storedPointer, uint64_t container = 0, uint64_t path = 0)
    {
        if (depth >= std::size(visited_) || next_ >= RpcMaxValueNodes) { state_.info.flags |= RpcPartial; return; }
        if (!code && !ReadRpc(format, code)) { state_.info.flags |= RpcPartial | RpcDescriptorUnreadable; return; }
        for (uint32_t index = 0; index < depth; ++index)
            if (visited_[index].format == format && visited_[index].memory == memory)
            { state_.info.flags |= RpcPartial; return; }
        visited_[depth] = {format, memory};
        path = (path ^ (uint64_t{offset} + 1)) * Fnv1aPrime64;
        const auto argument = state_.info.parameters[parameter].argument;
        const bool ndr64 = state_.info.flags & RpcNdr64;
        uint8_t width = 0;
        auto type = RpcScalar(code, ndr64, width);
        if (type != RpcValueType::Unknown)
        {
            Append(argument, parent, type, memory, width, offset);
            return;
        }
        auto pointee = format;
        auto nextCode = code;
        if (RpcPointer(pointee, ndr64, nextCode))
        {
            uint64_t value = memory;
            if (storedPointer && !ReadRpcMemory(reinterpret_cast<void*>(memory), &value, RpcSlotBytes))
            {
                Append(argument, parent, RpcValueType::Pointer, memory, RpcSlotBytes, offset);
                return;
            }
            const auto node = Append(argument, parent, RpcValueType::Pointer,
                reinterpret_cast<uint64_t>(&value), RpcSlotBytes, offset, 0, false, storedPointer ? memory : 0);
            if (value && node != RpcNoParent)
                Walk(parameter, pointee, nextCode, value, node, 0, depth + 1, true, container, path);
            return;
        }
        const bool wide = ndr64 ? code == 0x61 || code == 0x64 : code == 0x25 || code == 0x29;
        const bool string = ndr64 ? code == 0x60 || code == 0x61 || code == 0x63 || code == 0x64 :
            code == 0x22 || code == 0x25 || code == 0x26 || code == 0x29;
        if (string)
        {
            uint64_t bytes = header_->bufferLimit;
            if (ndr64 && (code == 0x60 || code == 0x61))
            {
                uint32_t length = 0;
                if (!ReadRpc(format + 4, length)) { state_.info.flags |= RpcPartial; return; }
                bytes = length;
            }
            if (!ndr64 && (code == 0x26 || code == 0x29))
            {
                uint16_t length = 0;
                if (!ReadRpc(format + 2, length)) { state_.info.flags |= RpcPartial; return; }
                bytes = uint64_t{length} * (wide ? 2 : 1);
            }
            Append(argument, parent, wide ? RpcValueType::Utf16 : RpcValueType::Ansi, memory, bytes, offset, 0, true);
            return;
        }
        if (ndr64 ? code >= 0x40 && code <= 0x47 : code >= 0x1B && code <= 0x21)
        {
            RpcArrayExtent extent;
            if (!RpcArray(state_, event_, format, leaving_, extent, false, memory, container))
            {
                state_.info.flags |= RpcPartial;
                Append(argument, parent, RpcValueType::Array, memory, 0, offset);
                return;
            }
            // Nested referents keep independent submitted bounds even when their enclosing structure is mutable.
            if (!leaving_)
            {
                if (state_.arrayCount < std::size(state_.arrays))
                    state_.arrays[state_.arrayCount++] = {path, format, extent.capacity, parameter};
                else state_.info.flags |= RpcPartial;
            }
            else if (!(state_.info.flags & RpcDecoding))
            {
                const auto found = std::find_if(state_.arrays, state_.arrays + state_.arrayCount,
                    [&](const auto& array)
                    { return array.parameter == parameter && array.format == format && array.path == path; });
                const auto& submitted = state_.parameters[parameter];
                const bool topLevel = state_.info.parameters[parameter].type == RpcValueType::Array;
                if (found == state_.arrays + state_.arrayCount && !(topLevel && submitted.capacityValid))
                { state_.info.flags |= RpcPartial; return; }
                const auto capacity = found != state_.arrays + state_.arrayCount ?
                    found->capacity : submitted.capacity;
                if (extent.bytes > capacity) state_.info.flags |= RpcPartial;
                extent.bytes = std::min(extent.bytes, capacity);
            }
            const auto payloadStart = slot_->event.payloadBytes;
            const auto node =
                Append(argument, parent, RpcValueType::Array, memory, extent.bytes, offset, extent.stride);
            if (node == RpcNoParent) return;
            const auto bytes = slot_->event.payloadBytes - payloadStart - sizeof(Value) - sizeof(RpcValueInfo);
            if (memory > UINTPTR_MAX - bytes) { state_.info.flags |= RpcPartial; return; }
            if (extent.element)
                for (uint64_t position = 0; next_ < RpcMaxValueNodes && position + extent.stride <= bytes;
                    position += extent.stride)
                    Walk(parameter, extent.element, 0, memory + position, node,
                        static_cast<uint32_t>(position), depth + 1, true, memory + position, path);
            else if (extent.pointers)
            {
                // Repeated pointer layouts describe referents in each completed array element.
                NDR64_REPEAT_FORMAT repeat{};
                if (!ReadRpc(extent.pointers, repeat) || repeat.FormatCode != 0x82 ||
                    repeat.Increment != extent.stride || repeat.OffsetToArray ||
                    repeat.NumberOfPointers > RpcMaxPointers)
                { state_.info.flags |= RpcPartial; return; }
                auto descriptor = extent.pointers + sizeof(repeat);
                for (uint32_t pointer = 0; pointer < repeat.NumberOfPointers; ++pointer)
                {
                    NDR64_POINTER_INSTANCE_HEADER_FORMAT instance{};
                    if (!ReadRpc(descriptor, instance) || instance.Offset > extent.stride ||
                        RpcSlotBytes > extent.stride - instance.Offset)
                    { state_.info.flags |= RpcPartial; return; }
                    descriptor += sizeof(instance);
                    for (uint64_t position = 0; next_ < RpcMaxValueNodes && position + extent.stride <= bytes;
                        position += extent.stride)
                        Walk(parameter, descriptor, 0, memory + position + instance.Offset, node,
                            static_cast<uint32_t>(position + instance.Offset), depth + 1, true, memory + position,
                            path);
                    descriptor += sizeof(NDR64_POINTER_FORMAT);
                }
            }
            else if (ndr64)
            {
                uint8_t flags = 0;
                if (!ReadRpc(format + 2, flags) || flags & 5) state_.info.flags |= RpcPartial;
            }
            else if (code != 0x21)
            {
                uint64_t element = format + (code == 0x1D ? 4 : code == 0x1E ? 6 :
                    4 + state_.correlationBytes * (code == 0x1C ? 2 : 1));
                uint8_t elementCode = 0;
                if (!ReadRpc(element, elementCode) || elementCode == 0x4B || elementCode == 0x4C)
                    state_.info.flags |= RpcPartial;
            }
            return;
        }
        if (ndr64 ? code == 0x50 || code == 0x51 : code == 0x2A || code == 0x2B)
        {
            RpcUnionExtent extent;
            if (!RpcUnion(state_, event_, format, leaving_, memory, container, extent))
            { state_.info.flags |= RpcPartial; return; }
            const auto node = Append(argument, parent, RpcValueType::Union, memory, extent.bytes, offset);
            if (node == RpcNoParent) return;
            if (extent.offset)
                Walk(parameter, 0, extent.switchCode, memory, node, 0, depth + 1, false, container, path);
            if (extent.arm || extent.armCode)
            {
                const auto size = extent.arm ? RpcMemorySize(extent.arm, ndr64, state_.correlationBytes) :
                    (RpcScalar(extent.armCode, ndr64, width), width);
                if (size > extent.bytes - extent.offset || memory > UINTPTR_MAX - extent.offset)
                { state_.info.flags |= RpcPartial; return; }
                Walk(parameter, extent.arm, extent.armCode, memory + extent.offset, node, extent.offset,
                    depth + 1, true, container, path);
            }
            return;
        }
        if (ndr64 ? code >= 0x30 && code <= 0x37 : code >= 0x15 && code <= 0x1A)
        {
            uint32_t bytes = 0;
            if (ndr64) ReadRpc(format + 4, bytes);
            else
            {
                uint16_t size = 0;
                if (ReadRpc(format + 2, size)) bytes = size;
            }
            if (!bytes) { state_.info.flags |= RpcPartial; return; }
            const auto node = Append(argument, parent, RpcValueType::Structure, memory, bytes, offset);
            if (node == RpcNoParent) return;
            if (ndr64 && code == 0x31)
            {
                uint64_t pointer = format + sizeof(NDR64_STRUCTURE_HEADER_FORMAT);
                for (uint32_t entry = 0; entry < RpcMaxPointers; ++entry)
                {
                    uint8_t token = 0;
                    if (!ReadRpc(pointer, token)) { state_.info.flags |= RpcPartial; return; }
                    if (token == 0x93) return;
                    NDR64_POINTER_INSTANCE_HEADER_FORMAT instance{};
                    if (token != 0x80 || !ReadRpc(pointer + sizeof(NDR64_NO_REPEAT_FORMAT), instance) ||
                        instance.Offset > bytes || RpcSlotBytes > bytes - instance.Offset)
                    { state_.info.flags |= RpcPartial; return; }
                    auto descriptor = pointer + sizeof(NDR64_NO_REPEAT_FORMAT) + sizeof(instance);
                    Walk(parameter, descriptor, 0, memory + instance.Offset, node, instance.Offset, depth + 1, true,
                        memory, path);
                    pointer = descriptor + sizeof(NDR64_POINTER_FORMAT);
                }
                state_.info.flags |= RpcPartial;
            }
            else if (!ndr64 && (code == 0x15 || code == 0x1A))
                Members32(parameter, format, code, memory, bytes, node, depth + 1, path);
            else if (ndr64 && (code == 0x34 || code == 0x35))
                Members64(parameter, format, memory, bytes, node, depth + 1, path);
            else if (ndr64 ? code != 0x30 : true) state_.info.flags |= RpcPartial;
            return;
        }
        state_.info.flags |= RpcPartial;
        if (ndr64 ? code == 0xA2 : code == 0xB4)
        {
            // Capture the presented value's declared memory, never call user marshaling routines or infer wire layout.
            Append(argument, parent, RpcValueType::Custom, memory, RpcMemorySize(format, ndr64), offset);
            return;
        }
        Append(argument, parent, RpcValueType::Unknown, memory, 0, offset);
    }

    void Members32(uint32_t parameter, uint64_t format, uint8_t code, uint64_t memory,
        uint32_t bytes, uint16_t parent, uint32_t depth, uint64_t path)
    {
        uint64_t members = format + 4, pointers = 0;
        if (code == 0x1A)
        {
            int16_t array = 0, pointer = 0;
            if (!ReadRpc(format + 4, array) || !ReadRpc(format + 6, pointer))
            { state_.info.flags |= RpcPartial; return; }
            if (array) state_.info.flags |= RpcPartial;
            if (pointer) pointers = format + 6 + pointer;
            members += 4;
        }
        uint32_t offset = 0;
        for (uint32_t member = 0; member < RpcMaxMembers; ++member)
        {
            uint8_t token = 0, width = 0;
            if (!ReadRpc(members, token)) { state_.info.flags |= RpcPartial; return; }
            if (token == 0x5B) return;
            if (token == 0x5C) { ++members; continue; }
            if (token >= 0x37 && token <= 0x39)
            {
                const auto alignment = (1u << (token - 0x36)) - 1;
                offset = (offset + alignment) & ~alignment;
                ++members;
                continue;
            }
            if (token >= 0x3D && token <= 0x44) { offset += token - 0x3C; ++members; continue; }
            if (token == 0x4C)
            {
                int16_t displacement = 0;
                uint8_t padding = 0;
                if (!ReadRpc(members + 1, padding) || !ReadRpc(members + 2, displacement))
                { state_.info.flags |= RpcPartial; return; }
                offset += padding;
                const auto descriptor = members + 2 + displacement;
                const auto size = RpcMemorySize(descriptor, false, state_.correlationBytes);
                if (!size || offset > bytes || size > bytes - offset)
                { state_.info.flags |= RpcPartial; return; }
                Walk(parameter, descriptor, 0, memory + offset, parent, offset, depth, true, memory, path);
                offset += size;
                members += 4;
                continue;
            }
            if (token == 0x36)
            {
                width = RpcSlotBytes;
                if (offset > bytes || width > bytes - offset) { state_.info.flags |= RpcPartial; return; }
                if (pointers)
                {
                    Walk(parameter, pointers, 0, memory + offset, parent, offset, depth, true, memory, path);
                    pointers += 4;
                }
                else state_.info.flags |= RpcPartial;
            }
            else if (RpcScalar(token, false, width) != RpcValueType::Unknown)
            {
                if (offset > bytes || width > bytes - offset) { state_.info.flags |= RpcPartial; return; }
                Walk(parameter, members, token, memory + offset, parent, offset, depth, false, memory, path);
            }
            else { state_.info.flags |= RpcPartial; return; }
            offset += width;
            ++members;
        }
        state_.info.flags |= RpcPartial;
    }

    void Members64(uint32_t parameter, uint64_t format, uint64_t memory,
        uint32_t bytes, uint16_t parent, uint32_t depth, uint64_t path)
    {
        NDR64_BOGUS_STRUCTURE_HEADER_FORMAT structure{};
        if (!ReadRpc(format, structure))
        { state_.info.flags |= RpcPartial; return; }
        auto members = structure.OriginalMemberLayout ? reinterpret_cast<uint64_t>(structure.OriginalMemberLayout) :
            format + sizeof(structure);
        auto pointers = reinterpret_cast<uint64_t>(structure.PointerLayout ?
            structure.PointerLayout : structure.OriginalPointerLayout);
        uint32_t offset = 0;
        for (uint32_t member = 0; member < RpcMaxMembers; ++member)
        {
            uint8_t token = 0, width = 0;
            if (!ReadRpc(members, token)) { state_.info.flags |= RpcPartial; return; }
            if (token == 0x93) return;
            if (token == 0x90)
            {
                NDR64_MEMPAD_FORMAT padding{};
                if (!ReadRpc(members, padding) || offset > bytes || padding.MemPad > bytes - offset)
                { state_.info.flags |= RpcPartial; return; }
                offset += padding.MemPad;
                members += sizeof(padding);
                continue;
            }
            if (token == 0x92) { members += sizeof(NDR64_BUFFER_ALIGN_FORMAT); continue; }
            auto descriptor = members;
            uint32_t size = 0;
            if (token == 0x91)
            {
                NDR64_EMBEDDED_COMPLEX_FORMAT embedded{};
                if (!ReadRpc(members, embedded)) { state_.info.flags |= RpcPartial; return; }
                descriptor = reinterpret_cast<uint64_t>(embedded.Type);
                size = RpcMemorySize(descriptor, true);
                members += sizeof(embedded);
            }
            else if (token == 0x14)
            {
                if (!pointers) { state_.info.flags |= RpcPartial; return; }
                descriptor = pointers;
                size = RpcSlotBytes;
                pointers += sizeof(NDR64_POINTER_FORMAT);
                members += sizeof(NDR64_SIMPLE_MEMBER_FORMAT);
            }
            else
            {
                if (RpcScalar(token, true, width) == RpcValueType::Unknown)
                { state_.info.flags |= RpcPartial; return; }
                size = width;
                members += sizeof(NDR64_SIMPLE_MEMBER_FORMAT);
            }
            if (!size || offset > bytes || size > bytes - offset)
            { state_.info.flags |= RpcPartial; return; }
            Walk(parameter, descriptor, 0, memory + offset, parent, offset, depth, true, memory, path);
            offset += size;
        }
        state_.info.flags |= RpcPartial;
    }

    struct Visit { uint64_t format, memory; } visited_[RpcMaxPointerDepth]{};
    RpcCaptureState& state_;
    Event& event_;
    Slot* slot_;
    SharedHeader* header_;
    bool leaving_;
    uint16_t next_ = 0;
};

void BeginRpcAsync(RpcCaptureState& state, Event& event, SharedHeader* header)
{
    if (!(state.info.flags & RpcDescriptorValid) || !(state.info.flags & RpcAsynchronous) ||
        state.info.flags & RpcObjectProcedure || event.flags & (Skipped | Unwound)) return;
    const auto control = event.arguments[state.info.prefix];
    if (!control) return;

    // Shared session storage preserves descriptors and submitted capacities across engines and completion threads.
    if (!LockSession(header->rpcLock)) { state.info.flags |= RpcPartial; return; }
    auto pending = std::find_if(std::begin(header->rpcAsync), std::end(header->rpcAsync),
        [](const auto& entry) { return !entry.control; });
    if (pending != std::end(header->rpcAsync))
    {
        event.flags |= AsyncPending;
        *pending = {control, event, state};
        InterlockedIncrement(&header->rpcPending);
    }
    else state.info.flags |= RpcPartial;
    InterlockedExchange(&header->rpcLock, 0);
}

void FinishRpcAsync(const AsyncIoSink& sink, Event& event, AsyncIoRole role)
{
    const auto status = static_cast<uint32_t>(event.result);
    const bool unwound = (event.flags & Unwound) != 0;
    if (!unwound && (event.flags & Skipped || status == RPC_S_ASYNC_CALL_PENDING ||
        role == AsyncIoRole::RpcInitialize && status)) return;
    auto header = sink.header;
    for (uint32_t index = 0; index < std::size(header->rpcAsync); ++index)
    {
        PendingRpc pending{};
        if (!LockSession(header->rpcLock)) break;
        auto& entry = header->rpcAsync[index];
        if (entry.control && (unwound ? entry.event.callId == event.callId : entry.control == event.arguments[0]))
        {
            pending = entry;
            entry.control = 0;
            InterlockedDecrement(&header->rpcPending);
        }
        InterlockedExchange(&header->rpcLock, 0);
        if (!pending.control) continue;
        if (unwound) { event.flags &= ~AsyncPending; continue; }
        if (role == AsyncIoRole::RpcInitialize) continue;
        auto slot = sink.acquire(sink.context);
        if (!slot) continue;

        // Only a terminal completion exposes caller-owned outputs; failed calls retain their status without reading
        // them.
        auto original = pending.event;
        original.kind = EventKind::AsyncCompletion;
        original.flags = AsyncCompleted | (status ? Failed : 0u) |
            (status == RPC_S_CALL_CANCELLED ? AsyncCancelled : 0u);
        pending.state.info.flags &= ~RpcOutputsDeferred;
        slot->event = original;
        slot->event.payloadBytes = 0;
        CaptureRpcValues(pending.state, original, slot, header, true);
        auto& completed = slot->event;
        completed.kind = EventKind::AsyncCompletion;
        completed.timestamp = Clock();
        completed.threadId = event.threadId;
        memset(completed.arguments, 0, sizeof(completed.arguments));
        completed.arguments[0] = pending.control;
        completed.arguments[1] = event.callId;
        completed.arguments[3] = status;
        completed.arguments[4] = static_cast<uint32_t>(AsyncIoDomain::Rpc);
        completed.arguments[5] = static_cast<uint32_t>(AsyncIoSource::Rpc);
        sink.publish(sink.context, slot);
    }
}

void CaptureRpcValues(RpcCaptureState& state, Event& event, Slot* slot, SharedHeader* header, bool leaving)
{
    if (!leaving)
    {
        state.arrayCount = 0;
        if (state.info.flags & RpcDescriptorValid) DiscoverRpcMarshalers(state);
    }
    const bool objectAsync = (state.info.flags & (RpcObjectProcedure | RpcAsynchronous)) ==
        (RpcObjectProcedure | RpcAsynchronous);
    if (leaving && objectAsync && static_cast<int32_t>(event.result) < 0)
    {
        event.flags |= Failed;
        state.info.flags &= ~RpcOutputsDeferred;
    }
    const auto position = slot->event.payloadBytes;
    if (EnsureSlotPayload(slot, header, sizeof(Value) + sizeof(RpcCallInfo)) < sizeof(Value) + sizeof(RpcCallInfo))
        return;
    slot->event.payloadBytes += sizeof(Value) + sizeof(RpcCallInfo);
    if (state.info.flags & RpcDescriptorValid && !(leaving && event.flags & (Skipped | Unwound)) &&
        !(leaving && event.flags & Failed && (objectAsync || event.kind == EventKind::AsyncCompletion)))
    {
        RpcValueCapture capture(state, event, slot, header, leaving);
        for (uint32_t index = 0; index < state.info.parameterCount; ++index) capture.Parameter(index);
    }
    if (!leaving) BeginRpcAsync(state, event, header);
    auto data = Transport::Payload(slot) + position;
    const Value metadata{UINT32_MAX, ValueKind::RpcCall, 0, sizeof(RpcCallInfo), sizeof(RpcCallInfo)};
    memcpy(data, &metadata, sizeof(metadata));
    memcpy(data + sizeof(metadata), &state.info, sizeof(state.info));
    event.flags = (event.flags & ~FormattedArgumentMask) | RawArguments | FormattedArguments |
        (uint32_t{state.info.argumentCount} << FormattedArgumentShift);
    slot->event.flags = event.flags;
}
}

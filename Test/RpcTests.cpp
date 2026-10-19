#include "TestSupport.h"
#include "RpcCapture.h"
#include "RpcFormats.h"
#include <ndr64types.h>
#include "DetouristRpc32.h"
#ifdef _WIN64
#include "DetouristRpc64.h"
#endif
#include <midles.h>
extern "C" const MIDL_STUBLESS_PROXY_INFO* RpcObjectMetadata();

using namespace Detourist::Tests;

volatile LONG RpcGuardFaults = 0, RpcMarshalCallbacks = 0;
HANDLE RpcAsyncGate = nullptr;

LONG CALLBACK RpcGuardException(EXCEPTION_POINTERS* exception)
{
    if (exception->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
        InterlockedIncrement(&RpcGuardFaults);
    return EXCEPTION_CONTINUE_SEARCH;
}

ULONG __RPC_USER RpcMarshalSize(ULONG*, ULONG, void*)
{
    InterlockedIncrement(&RpcMarshalCallbacks);
    return 0;
}

void RpcDescriptorSafety()
{
    auto release = [](void* memory) { if (memory) VirtualFree(memory, 0, MEM_RELEASE); };
    std::unique_ptr<void, decltype(release)> payload(VirtualAlloc(nullptr, sizeof(Detourist::Slot) + 4096,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), release);
    std::unique_ptr<void, decltype(release)> guard(VirtualAlloc(nullptr, 4096,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), release);
    std::unique_ptr<void, decltype(&RemoveVectoredExceptionHandler)> handler(
        AddVectoredExceptionHandler(1, RpcGuardException), &RemoveVectoredExceptionHandler);
    Require(payload && guard && handler, "RPC memory-safety fixture could not initialize");
    auto header = std::make_unique<Detourist::SharedHeader>();
    header->payloadCapacity = 4096;
    header->bufferLimit = 32;
    auto slot = static_cast<Detourist::Slot*>(payload.get());
    const unsigned char procedure[]{0x33, 0x48, 0, 0, 0, 0, 0, 0, 8, 0,
        0, 0, 0, 0, 0x40, 1, 10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0x0B, 1, 0, 0, 0, 0};
    unsigned char unknown[]{0xB4, 3, 0, 0, 8, 0, 4, 0, 0, 0}, cycle[]{0x11, 0, 0xFE, 0xFF}, string[]{0x25, 0x5C};
    USER_MARSHAL_ROUTINE_QUADRUPLE marshal{RpcMarshalSize};
    MIDL_STUB_DESC descriptor{};
    descriptor.Version = 0x50002;
    descriptor.aUserMarshalQuadruple = &marshal;
    uint64_t pointer = reinterpret_cast<uint64_t>(&pointer);
    Detourist::Event event{};
    event.arguments[0] = reinterpret_cast<uint64_t>(&descriptor);
    event.arguments[1] = reinterpret_cast<uint64_t>(procedure);
    event.arguments[2] = pointer;
    for (auto format : {unknown, cycle})
    {
        descriptor.pFormatTypes = format;
        Detourist::RpcCaptureState state;
        Detourist::PrepareRpcCapture(state, Detourist::RpcDecoder::Client2, event.arguments);
        slot->event = {};
        Detourist::CaptureRpcValues(state, event, slot, header.get(), false);
        Require((state.info.flags & (Detourist::RpcDescriptorValid | Detourist::RpcPartial)) ==
            (Detourist::RpcDescriptorValid | Detourist::RpcPartial) && slot->event.payloadBytes < 1024 &&
            !RpcMarshalCallbacks, "Custom or cyclic descriptors escaped bounded decoding");
    }

    // Descriptor and string probes must leave the application's first guard-page exception untouched.
    DWORD protection = 0;
    Require(VirtualProtect(guard.get(), 4096, PAGE_READWRITE | PAGE_GUARD, &protection) != FALSE,
        "Create RPC guard page");
    event.arguments[1] = reinterpret_cast<uint64_t>(guard.get());
    Detourist::RpcCaptureState state;
    Detourist::PrepareRpcCapture(state, Detourist::RpcDecoder::Client2, event.arguments);
    Require(!(state.info.flags & Detourist::RpcDescriptorValid), "A guarded procedure descriptor was read");
    descriptor.pFormatTypes = string;
    event.arguments[1] = reinterpret_cast<uint64_t>(procedure);
    event.arguments[2] = reinterpret_cast<uint64_t>(guard.get());
    Detourist::PrepareRpcCapture(state, Detourist::RpcDecoder::Client2, event.arguments);
    slot->event = {};
    Detourist::CaptureRpcValues(state, event, slot, header.get(), false);
    Detourist::Value snapshot{};
    memcpy(&snapshot, Detourist::Transport::Payload(slot) + sizeof(Detourist::Value) +
        sizeof(Detourist::RpcCallInfo), sizeof(snapshot));
    MEMORY_BASIC_INFORMATION region{};
    Require(snapshot.kind == Detourist::ValueKind::RpcValue && (snapshot.flags & Detourist::Unreadable) &&
        VirtualQuery(guard.get(), &region, sizeof(region)) && (region.Protect & PAGE_GUARD) && !RpcGuardFaults,
        "RPC capture consumed a guard page or ran an application exception handler");

    // Conditional correlations must not evaluate an unselected dereference, even when the page is guarded.
    for (bool ndr64 : {false, true})
    {
        if (ndr64 && sizeof(void*) == 4) continue;
        Bytes expression;
        auto append = [&](auto value)
        {
            const auto source = reinterpret_cast<const BYTE*>(&value);
            expression.insert(expression.end(), source, source + sizeof(value));
        };
        if (ndr64) append(uint32_t{1});
        expression.insert(expression.end(), {4, 0x20, 0, 0, 4, 5, static_cast<BYTE>(ndr64 ? 6 : 9), 0,
            3, static_cast<BYTE>(ndr64 ? 8 : 0xB9), 0, 0});
        if (ndr64) append(uint32_t{0});
        expression.insert(expression.end(), {1, static_cast<BYTE>(ndr64 ? 5 : 8), 0, 0});
        append(uint32_t{4});
        expression.insert(expression.end(), {1, static_cast<BYTE>(ndr64 ? 5 : 8), 0, 0});
        append(uint32_t{0});
        const uint16_t expressionOffset = 0;
        const BYTE array32[]{0x1B, 0, 1, 0, 0x20, 0x5D, 0, 0, 1, 0, 1, 0x5B};
        NDR64_CONF_ARRAY_HEADER_FORMAT array64{};
        array64.FormatCode = 0x41;
        array64.ElementSize = 1;
        array64.ConfDescriptor = expression.data();
        Detourist::RpcCaptureState correlated;
        correlated.info.flags = ndr64 ? Detourist::RpcNdr64 : 0;
        correlated.info.parameterCount = correlated.info.argumentCount = 1;
        correlated.parameters[0].attributes = Detourist::RpcIn;
        correlated.expressionOffsets = reinterpret_cast<uint64_t>(&expressionOffset);
        correlated.expressionFormat = reinterpret_cast<uint64_t>(expression.data());
        event.arguments[0] = reinterpret_cast<uint64_t>(guard.get());
        Detourist::RpcArrayExtent extent;
        const auto format = reinterpret_cast<uint64_t>(ndr64 ? static_cast<const void*>(&array64) : array32);
        Require(Detourist::RpcArray(correlated, event, format, false, extent) && extent.bytes == 4,
            "An unselected correlation branch was evaluated");
        expression[expression.size() - 4] = 1;
        Require(!Detourist::RpcArray(correlated, event, format, false, extent) &&
            VirtualQuery(guard.get(), &region, sizeof(region)) && (region.Protect & PAGE_GUARD) && !RpcGuardFaults,
            "Correlation evaluation consumed the application's guard exception");
    }

}

void RpcObjectDescriptors()
{
    using namespace Detourist;
    const auto information = RpcObjectMetadata();
    for (bool ndr64 : {false, true})
    {
        if (sizeof(void*) == 4 && ndr64) continue;
        for (uint32_t method : {3u, 4u})
        {
            Event event{};
            auto decoder = ndr64 ? RpcDecoder::Dcom3 : RpcDecoder::Dcom2;
            auto prefix = RpcPrefix(decoder);
            event.arguments[0] = reinterpret_cast<uint64_t>(ndr64 ? static_cast<const void*>(information) :
                static_cast<const void*>(information->pStubDesc));
            event.arguments[1] = ndr64 ? method : reinterpret_cast<uint64_t>(information->ProcFormatString +
                information->FormatStringOffset[method]);
            event.arguments[prefix] = 0x12345678;
            long changed = 0xBAD;
            event.arguments[prefix + 1] = method == 3 ? 42 : reinterpret_cast<uint64_t>(&changed);
            RpcCaptureState state;
            PrepareRpcCapture(state, decoder, event.arguments);
            const auto required = RpcDescriptorValid | RpcAsynchronous | RpcObjectProcedure;
            Require((state.info.flags & required) == required && !(state.info.flags & RpcPartial) &&
                !!(state.info.flags & RpcNdr64) == ndr64 && state.info.argumentCount == prefix + 2 &&
                !!(state.info.flags & RpcOutputsDeferred) == (method == 3),
                "Compiler-generated asynchronous COM descriptor differs");
            const auto receiver = std::find_if(std::begin(state.info.parameters),
                std::begin(state.info.parameters) + state.info.parameterCount,
                [=](const auto& parameter) { return parameter.argument == prefix; });
            Require(receiver != std::begin(state.info.parameters) + state.info.parameterCount &&
                receiver->type == RpcValueType::Pointer, "COM receiver was described as an async handle");
        }
    }
}

void RpcSerializationContention()
{
    std::atomic<bool> valid = true;
    std::vector<std::thread> workers;
    for (uint64_t worker = 0; worker < 8; ++worker)
        workers.emplace_back([&, worker]()
        {
            for (uint64_t iteration = 0; iteration < 2000; ++iteration)
            {
                uint64_t handle = 0x100000 + (worker * 32 + iteration % 32) * 16;
                uint64_t arguments[7]{handle, 0, 0, reinterpret_cast<uint64_t>(&handle)};
                Detourist::ObserveRpcSerialization(Detourist::Api::MesEncodeFixedBufferHandleCreate, arguments, 0);
                auto operation = Detourist::RpcSerializationOperation(handle);
                if (operation && operation != 1) valid = false;
                Detourist::BeginRpcSerialization(Detourist::Api::MesBufferHandleReset, arguments);
                if (Detourist::RpcSerializationOperation(handle)) valid = false;
                arguments[2] = MES_DECODE;
                Detourist::ObserveRpcSerialization(Detourist::Api::MesBufferHandleReset, arguments, 0);
                operation = Detourist::RpcSerializationOperation(handle);
                if (operation && operation != 2) valid = false;
                Detourist::BeginRpcSerialization(Detourist::Api::MesHandleFree, arguments);
            }
        });
    for (auto& worker : workers) worker.join();
    Require(valid, "Contended serialization handle reuse retained an obsolete operation");
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
extern "C" void __RPC_USER midl_user_free(void* value) { free(value); }

long RpcValues(long signedValue, unsigned __int64 wideValue, double floatingValue,
    wchar_t* text, long* optional, long* changed)
{
    if (signedValue != -17 || wideValue != 0xFEDCBA9876543210 || floatingValue != 3.25 ||
        wcscmp(text, L"rpc-text") || optional && *optional != 15 || *changed != 9) return -1;
    *changed = 27;
    return 0x1234;
}

template<class Record> long RpcBuffers(ULONG count, unsigned char* input, ULONG capacity,
    unsigned char* output, ULONG* written, Record* record)
{
    if (count != 8 || capacity != 12 || record->number != 41 || record->large != 0x1122334455667788 ||
        wcscmp(record->label, L"rpc-record")) return -1;
    *written = 7;
    for (ULONG index = 0; index < *written; ++index) output[index] = input[*written - index - 1];
    record->number += 7;
    return 0x2345;
}

void RpcAsync(PRPC_ASYNC_STATE state, unsigned char* text, long* result)
{
    if (WaitForSingleObject(RpcAsyncGate, 10000) != WAIT_OBJECT_0) return;
    if (!strcmp(reinterpret_cast<char*>(text), "rpc-cancel"))
    {
        RpcAsyncAbortCall(state, RPC_S_CALL_CANCELLED);
        return;
    }
    *result = strcmp(reinterpret_cast<char*>(text), "rpc-async") ? -1 : 58;
    long returned = 55;
    RpcAsyncCompleteCall(state, &returned);
}

template<class Record> long RpcRecords(ULONG count, Record* records)
{
    if (count != 0 && count != 2) return -1;
    for (ULONG index = 0; index < count; ++index)
    {
        if (records[index].number != static_cast<long>(index + 10) ||
            wcscmp(records[index].label, index ? L"rpc-array-b" : L"rpc-array-a")) return -1;
        records[index].number += 20;
    }
    return 0x3456;
}

template<class Custom> long RpcMarshaled(Custom prior, Custom* value)
{
    if (prior.number != 71 || prior.complement != ~71 || value->number != 17 || value->complement != ~17) return -1;
    value->number = 30;
    value->complement = ~30;
    return 0x4567;
}

template<class Choice, class Envelope> long RpcUnions(long tag, Choice* choice, Envelope* envelope)
{
    if (tag == 1) choice->number += 10;
    else if (tag == 2) choice->text[0] = L'R';
    else if (tag == -1) choice->wide += 10;
    if (envelope->tag == 1) envelope->value.number += 20;
    else if (envelope->tag == 2) envelope->value.text[0] = L'R';
    else envelope->value.wide += 20;
    return 0x5678;
}

long RpcExpressions(ULONG count, ULONG extra, BYTE* input, ULONG capacity, BYTE* output, ULONG* written)
{
    if (count != 2 || extra != 2 || capacity != 5) return -1;
    *written = 7;
    for (ULONG index = 0; index < *written; ++index) output[index] = input[*written - index - 1];
    return 0x6789;
}

template<class Bundle> long RpcNested(Bundle* value)
{
    if (value->count != 4 || value->tag != 2 || wcscmp(value->choice.text, L"rpc-nested")) return -1;
    for (ULONG index = 0; index < value->count; ++index) value->values[index] += 10;
    value->choice.text[0] = L'R';
    return 0x789A;
}

template<class Bundle> long RpcMarshaledOutput(ULONG count, Bundle* values)
{
    if (count != 3) return -1;
    for (ULONG index = 0; index < count; ++index)
    {
        values[index].tag = index < 2 ? 1 : 9;
        if (index < 2) values[index].choice.value = {101 + static_cast<long>(index), ~(101 + static_cast<long>(index))};
        else values[index].choice.number = 303;
    }
    return 0x89AB;
}

// The wire value has four bytes while its native representation has eight.
#define RPC_CUSTOM(variant, type, suffix) \
extern "C" ULONG __RPC_USER DetouristRpc##variant##type##_UserSize##suffix(ULONG*, ULONG size, \
    DetouristRpc##variant##type*) \
{ InterlockedIncrement(&RpcMarshalCallbacks); return ((size + 3) & ~3u) + 4; } \
extern "C" BYTE* __RPC_USER DetouristRpc##variant##type##_UserMarshal##suffix(ULONG*, BYTE* wire, \
    DetouristRpc##variant##type* value) \
{ \
    InterlockedIncrement(&RpcMarshalCallbacks); \
    wire = reinterpret_cast<BYTE*>((reinterpret_cast<uintptr_t>(wire) + 3) & ~uintptr_t{3}); \
    memcpy(wire, &value->number, 4); return wire + 4; \
} \
extern "C" BYTE* __RPC_USER DetouristRpc##variant##type##_UserUnmarshal##suffix(ULONG*, BYTE* wire, \
    DetouristRpc##variant##type* value) \
{ \
    InterlockedIncrement(&RpcMarshalCallbacks); \
    wire = reinterpret_cast<BYTE*>((reinterpret_cast<uintptr_t>(wire) + 3) & ~uintptr_t{3}); \
    memcpy(&value->number, wire, 4); value->complement = ~value->number; return wire + 4; \
} \
extern "C" void __RPC_USER DetouristRpc##variant##type##_UserFree##suffix(ULONG*, DetouristRpc##variant##type*) \
{ InterlockedIncrement(&RpcMarshalCallbacks); }
RPC_CUSTOM(32, Custom, )
RPC_CUSTOM(32, OutputCustom, )
#ifdef _WIN64
RPC_CUSTOM(64, Custom, 64)
RPC_CUSTOM(64, OutputCustom, 64)
#endif
#undef RPC_CUSTOM

#define RPC_SERVER(variant) \
extern "C" long Server_DetouristRpc##variant##Values(handle_t, long value, MIDL_uhyper wide, double number, \
    wchar_t* text, long* optional, long* changed) \
{ return RpcValues(value, wide, number, text, optional, changed); } \
extern "C" long Server_DetouristRpc##variant##Buffers(handle_t, ULONG count, unsigned char* input, ULONG capacity, \
    unsigned char* output, ULONG* written, DetouristRpc##variant##Record* record) \
{ return RpcBuffers(count, input, capacity, output, written, record); } \
extern "C" void Server_DetouristRpc##variant##Async(PRPC_ASYNC_STATE state, handle_t, unsigned char* text, \
    long* result) \
{ RpcAsync(state, text, result); } \
extern "C" long Server_DetouristRpc##variant##Records(handle_t, ULONG count, DetouristRpc##variant##Record* records) \
{ return RpcRecords(count, records); } \
extern "C" long Server_DetouristRpc##variant##Marshaled(handle_t, DetouristRpc##variant##Custom prior, \
    DetouristRpc##variant##Custom* value) \
{ return RpcMarshaled(prior, value); } \
extern "C" long Server_DetouristRpc##variant##Unions(handle_t, long tag, \
    DetouristRpc##variant##Choice* choice, DetouristRpc##variant##Envelope* envelope) \
{ return RpcUnions(tag, choice, envelope); } \
extern "C" long Server_DetouristRpc##variant##Expressions(handle_t, ULONG count, ULONG extra, BYTE* input, \
    ULONG capacity, BYTE* output, ULONG* written) \
{ return RpcExpressions(count, extra, input, capacity, output, written); } \
extern "C" long Server_DetouristRpc##variant##Nested(handle_t, DetouristRpc##variant##Bundle* value) \
{ return RpcNested(value); } \
extern "C" long Server_DetouristRpc##variant##MarshaledOutput(handle_t, ULONG count, \
    DetouristRpc##variant##MarshaledBundle* values) \
{ return RpcMarshaledOutput(count, values); }
RPC_SERVER(32)

#ifdef _WIN64
RPC_SERVER(64)
#endif
#undef RPC_SERVER

bool RpcMalformed()
{
    __try
    {
        NdrClientCall2(reinterpret_cast<PMIDL_STUB_DESC>(1), reinterpret_cast<PFORMAT_STRING>(1));
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return true; }
}

template<class Pickle> bool RpcPickle(Pickle pickle, bool ndr64)
{
    alignas(16) char wire[1024]{};
    ULONG size = 0;
    handle_t handle = nullptr;
    if (MesEncodeFixedBufferHandleCreate(wire, sizeof(wire), &size, &handle)) return false;
    auto buffer = wire;
    if (ndr64 && MesBufferHandleReset(handle, MES_FIXED_BUFFER_HANDLE, MES_ENCODE_NDR64,
        &buffer, sizeof(wire), &size)) return false;
    long number = -34;
    wchar_t label[] = L"rpc-pickle";
    wchar_t* text = label;
    pickle(handle, &number, &text);
    if (!size || MesBufferHandleReset(handle, MES_FIXED_BUFFER_HANDLE, MES_DECODE, &buffer, size, nullptr))
        return false;
    number = 0;
    text = nullptr;
    pickle(handle, &number, &text);
    const auto valid = number == -34 && text && !wcscmp(text, label);
    if (text) midl_user_free(text);
    return MesHandleFree(handle) == RPC_S_OK && valid;
}

template<class Record, class Values, class Buffers, class Async>
bool RpcWorkload(handle_t binding, Values values, Buffers buffers, Async async)
{
    for (bool present : {false, true})
    {
        long optional = 15, changed = 9;
        if (values(binding, -17, 0xFEDCBA9876543210, 3.25, const_cast<wchar_t*>(L"rpc-text"),
            present ? &optional : nullptr, &changed) != 0x1234 || changed != 27) return false;
    }
    unsigned char input[]{1, 2, 3, 4, 5, 6, 7, 8}, output[16]{};
    memset(output, 0xA5, sizeof(output));
    ULONG written = 0xBAD;
    wchar_t label[] = L"rpc-record";
    Record record{41, 0x1122334455667788, label};
    if (buffers(binding, sizeof(input), input, 12, output, &written, &record) != 0x2345 ||
        written != 7 || output[0] != 7 || output[6] != 1 || output[7] != 0xA5 || record.number != 48) return false;
    RPC_ASYNC_STATE state{};
    Detourist::Handle event(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    if (!event) return false;

    // Reuse one handle after success and cancellation, and observe completion from a different thread.
    for (bool cancel : {false, true, false})
    {
        if (!ResetEvent(RpcAsyncGate) || RpcAsyncInitializeHandle(&state, sizeof(state))) return false;
        state.NotificationType = RpcNotificationTypeEvent;
        state.u.hEvent = event.get();
        long result = 0xBAD, returned = 0xBAD;
        const auto text = cancel ? "rpc-cancel" : "rpc-async";
        async(&state, binding, reinterpret_cast<unsigned char*>(const_cast<char*>(text)), &result);
        if (RpcAsyncCompleteCall(&state, &returned) != RPC_S_ASYNC_CALL_PENDING ||
            !SetEvent(RpcAsyncGate) || WaitForSingleObject(event.get(), 10000) != WAIT_OBJECT_0) return false;
        RPC_STATUS status = RPC_S_ASYNC_CALL_PENDING;
        std::thread completion([&]() { status = RpcAsyncCompleteCall(&state, &returned); });
        completion.join();
        if (status != (cancel ? RPC_S_CALL_CANCELLED : RPC_S_OK) ||
            !cancel && (returned != 55 || result != 58)) return false;
        result = returned = 0xBAD;
    }
    return true;
}

template<class Record, class Custom, class Records, class Marshaled>
bool RpcComplex(handle_t binding, Records records, Marshaled marshaled)
{
    wchar_t first[] = L"rpc-array-a", second[] = L"rpc-array-b";
    Record values[2]{{10, 101, first}, {11, 102, second}};
    if (records(binding, 2, values) != 0x3456 || values[0].number != 30 || values[1].number != 31 ||
        records(binding, 0, values) != 0x3456) return false;
    Custom value{17, ~17};
    return marshaled(binding, Custom{71, ~71}, &value) == 0x4567 && value.number == 30 && value.complement == ~30;
}

template<class Choice, class Envelope, class Bundle, class Unions, class Expressions, class Nested>
bool RpcCorrelated(handle_t binding, Unions unions, Expressions expressions, Nested nested)
{
    for (long tag : {1, 2, -1, 9})
    {
        Choice choice{};
        Envelope envelope{};
        envelope.tag = static_cast<short>(tag);
        wchar_t text[] = L"rpc-choice", label[] = L"rpc-envelope";
        if (tag == 1) { choice.number = 31; envelope.value.number = 51; }
        else if (tag == 2) { choice.text = text; envelope.value.text = label; }
        else { choice.wide = -17; envelope.value.wide = 71; }
        if (unions(binding, tag, &choice, &envelope) != 0x5678 ||
            tag == 1 && (choice.number != 41 || envelope.value.number != 71) ||
            tag == 2 && (wcscmp(choice.text, L"Rpc-choice") || wcscmp(envelope.value.text, L"Rpc-envelope")) ||
            tag == -1 && (choice.wide != -7 || envelope.value.wide != 91) ||
            tag == 9 && envelope.value.wide != 91) return false;
    }
    BYTE input[]{1, 2, 3, 4, 5, 6, 7, 8}, output[11]{};
    ULONG written = 0;
    if (expressions(binding, 2, 2, input, 5, output, &written) != 0x6789 || written != 7 || output[0] != 7)
        return false;
    BYTE values[]{1, 2, 3, 4};
    wchar_t text[] = L"rpc-nested";
    Bundle bundle{4, values, 2, {}};
    bundle.choice.text = text;
    return nested(binding, &bundle) == 0x789A && bundle.values[0] == 11 &&
        !wcscmp(bundle.choice.text, L"Rpc-nested");
}

template<class Bundle, class Output> bool RpcCustomOutput(handle_t binding, Output output)
{
    Bundle values[3];
    memset(values, 0xCC, sizeof(values));
    return output(binding, 3, values) == 0x89AB && values[0].tag == 1 && values[1].tag == 1 &&
        values[0].choice.value.number == 101 && values[0].choice.value.complement == ~101 &&
        values[1].choice.value.number == 102 && values[1].choice.value.complement == ~102 &&
        values[2].tag == 9 && values[2].choice.number == 303;
}

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 1 && count != 2) return 1;
#ifndef _WIN64
    // Raw snapshots of a zero-length native comparison must leave its guarded arguments untouched.
    auto guard = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD);
    using Compare = int(__cdecl*)(const void*, const void*, size_t);
    auto compare = reinterpret_cast<Compare>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "memcmp"));
    MEMORY_BASIC_INFORMATION region{};
    const auto intact = guard && compare && !compare(guard, guard, 0) &&
        VirtualQuery(guard, &region, sizeof(region)) && (region.Protect & PAGE_GUARD);
    if (guard) VirtualFree(guard, 0, MEM_RELEASE);
    if (!intact) return 6;
#endif
    Detourist::Handle gate(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!gate) return 1;
    RpcAsyncGate = gate.get();
    const auto endpoint = L"Detourist.Rpc." + std::to_wstring(GetCurrentProcessId());
    auto protocol = reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc"));
    auto name = reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(endpoint.c_str()));
    if (RpcServerUseProtseqEpW(protocol, RPC_C_PROTSEQ_MAX_REQS_DEFAULT, name, nullptr)) return 2;
    const RPC_IF_HANDLE contracts[]{Server_DetouristRpc32_v1_0_s_ifspec,
#ifdef _WIN64
        Server_DetouristRpc64_v1_0_s_ifspec
#endif
    };
    for (auto contract : contracts)
        if (RpcServerRegisterIfEx(contract, nullptr, nullptr, RPC_IF_AUTOLISTEN | RPC_IF_ALLOW_LOCAL_ONLY,
            RPC_C_LISTEN_MAX_CALLS_DEFAULT, nullptr)) return 3;
    RPC_WSTR text = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;
    if (RpcStringBindingComposeW(nullptr, protocol, nullptr, name, nullptr, &text) ||
        RpcBindingFromStringBindingW(text, &binding)) return 4;
    RpcStringFreeW(&text);
    auto valid = RpcWorkload<DetouristRpc32Record>(binding, Client_DetouristRpc32Values,
        Client_DetouristRpc32Buffers, Client_DetouristRpc32Async) &&
#ifdef _WIN64
        RpcWorkload<DetouristRpc64Record>(binding, Client_DetouristRpc64Values,
            Client_DetouristRpc64Buffers, Client_DetouristRpc64Async) &&
        RpcCorrelated<DetouristRpc64Choice, DetouristRpc64Envelope, DetouristRpc64Bundle>(binding,
            Client_DetouristRpc64Unions, Client_DetouristRpc64Expressions, Client_DetouristRpc64Nested) &&
        RpcCustomOutput<DetouristRpc64MarshaledBundle>(binding, Client_DetouristRpc64MarshaledOutput) &&
        RpcPickle(Client_DetouristRpc64Pickle, true) &&
        RpcComplex<DetouristRpc64Record, DetouristRpc64Custom>(binding,
            Client_DetouristRpc64Records, Client_DetouristRpc64Marshaled) &&
#endif
        RpcComplex<DetouristRpc32Record, DetouristRpc32Custom>(binding,
            Client_DetouristRpc32Records, Client_DetouristRpc32Marshaled) &&
        RpcCorrelated<DetouristRpc32Choice, DetouristRpc32Envelope, DetouristRpc32Bundle>(binding,
            Client_DetouristRpc32Unions, Client_DetouristRpc32Expressions, Client_DetouristRpc32Nested) &&
        RpcCustomOutput<DetouristRpc32MarshaledBundle>(binding, Client_DetouristRpc32MarshaledOutput) &&
        RpcPickle(Client_DetouristRpc32Pickle, false) && RpcMalformed();
    const bool detached = count == 2 && !wcscmp(arguments[1], L"detached");
    if (valid && detached)
    {
        const auto before = RpcMarshalCallbacks;
        valid = RpcCustomOutput<DetouristRpc32MarshaledBundle>(binding, Client_DetouristRpc32MarshaledOutput);
        const auto callbacks = RpcMarshalCallbacks - before;
        const auto eventPrefix = L"Local\\Detourist.Rpc." + std::to_wstring(GetCurrentProcessId());
        Detourist::Handle ready(CreateEventW(nullptr, TRUE, FALSE, (eventPrefix + L".Ready").c_str()));
        Detourist::Handle phaseGate(CreateEventW(nullptr, TRUE, FALSE, (eventPrefix + L".Gate").c_str()));
        valid &= ready && phaseGate && SetEvent(ready.get()) &&
            WaitForSingleObject(phaseGate.get(), 60000) == WAIT_OBJECT_0;
        const auto resumed = RpcMarshalCallbacks;
        valid &= RpcCustomOutput<DetouristRpc32MarshaledBundle>(binding, Client_DetouristRpc32MarshaledOutput) &&
            RpcMarshalCallbacks - resumed == callbacks;
    }
    RpcBindingFree(&binding);
    RpcServerUnregisterIf(nullptr, nullptr, TRUE);
    if (!valid || count == 2 && !detached && RpcMarshalCallbacks != wcstol(arguments[1], nullptr, 10)) return 5;
    printf("PASS: RPC values and completion; callbacks=%ld\n", RpcMarshalCallbacks);
    return 0;
}

Json RpcNodes(const Json& call, const char* side, uint32_t argument, uint32_t type = UINT32_MAX)
{
    Json result = Json::array();
    for (const auto& value : call[side])
        if (value["kind"] == static_cast<uint32_t>(Detourist::ValueKind::RpcValue) &&
            value["parameter"] == argument && (type == UINT32_MAX || value["typeId"] == type)) result.push_back(value);
    return result;
}

void Rpc(const Context& context)
{
    RpcDescriptorSafety();
    RpcObjectDescriptors();
    RpcSerializationContention();
    const auto baseline = RunTarget(context);
    Require(baseline.contains("PASS:") && baseline.contains("callbacks="), "RPC workload baseline failed");
    const auto callbacks = std::stoi(baseline.substr(baseline.find("callbacks=") + 10));
    for (bool instructions : {false, true})
    {
        Collector collector(context.collector, context.directory);
        auto database = Launch(collector, context,
            {.arguments = std::to_wstring(callbacks),
                .instructions = instructions,
                .excludedApis = {"MesEncodeFixedBufferHandleCreate", "MesBufferHandleReset", "MesHandleFree",
                    "RpcAsyncInitializeHandle", "RpcAsyncCompleteCall"}});
        auto ended = collector.Wait([](const Json& status) { return status["finished"] == true; });
        Require(!ended["message"].get<std::string>().contains("nonzero exit code"), "RPC workload failed", ended);
        auto calls = Query(database, "SELECT c.*,a.name,a.module FROM calls c JOIN apis a "
            "ON a.target=c.target AND a.id=c.api WHERE a.name IN('NdrClientCall2','NdrClientCall3',"
            "'NdrAsyncClientCall','Ndr64AsyncClientCall','NdrMesProcEncodeDecode2','NdrMesProcEncodeDecode3',"
            "'NdrClientCall4','NdrAsyncClientCall2','NdrMesProcEncodeDecode4') "
            "ORDER BY c.id");
        uint32_t ndr32 = 0, ndr64 = 0, asynchronous = 0, malformed = 0, encodes = 0, decodes = 0;
        Json inspections = Json::array();
        for (const auto& call : calls)
        {
            auto values = Values(call["input"]);
            auto metadata = std::find_if(values.begin(), values.end(), [](const auto& value)
            {
                return value.kind == static_cast<uint32_t>(Detourist::ValueKind::RpcCall);
            });
            Require(metadata != values.end() && metadata->data.size() == sizeof(Detourist::RpcCallInfo),
                "RPC interpreter omitted its descriptor", call);
            auto info = Read<Detourist::RpcCallInfo>(metadata->data);
            auto details = collector.Call("details", {{"database", Text(database)}, {"target", call["target"]},
                {"callId", call["id"]}});
            Require(details.contains("rpc") && details["arguments"].size() == info.argumentCount &&
                !details.contains("rawArguments"), "Collector retained unused RPC argument slots", details);
            inspections.push_back(details);
            if (!(info.flags & Detourist::RpcDescriptorValid))
            {
                Require((info.flags & Detourist::RpcDescriptorUnreadable) &&
                    (call["flags"].get<uint32_t>() & (Detourist::Unwound | Detourist::Continuation)),
                    "Malformed descriptor was presented as a decoded call", call);
                ++malformed;
                continue;
            }
            Require(!!(info.flags & Detourist::RpcPartial) == (info.procedure == 5),
                "RPC decoding completeness differs",
                {{"name", call["name"]}, {"procedure", info.procedure}, {"flags", info.flags}});
            auto expected =
                info.prefix + (info.flags & Detourist::RpcPickling || info.procedure == 4 || info.procedure == 9 ? 3
                                  : info.procedure == 5                        ? (sizeof(void*) == 4 ? 4 : 3)
                                  : info.procedure == 8                        ? 2
                                  : info.procedure == 2 || info.procedure == 6 ? 4
                                  : info.procedure == 0 && sizeof(void*) == 4  ? 9
                                                                               : 7);
            Require(info.argumentCount == expected, "RPC binding or async slot was lost", call);
            auto prefix = info.prefix;
            const auto extended = sizeof(void*) == 4 && info.procedure == 0 ? 2u : 0u;
            if (info.flags & Detourist::RpcPickling)
            {
                const auto side = info.flags & Detourist::RpcEncoding ? "input" : "output";
                Require(Read<int32_t>(Unhex(Only(RpcNodes(details, side, prefix + 1, 6))["bytes"])) == -34 &&
                    Unhex(Only(RpcNodes(details, side, prefix + 2, 12))["bytes"]) == Encode("rpc-pickle", true, true),
                    "Serialized RPC values or referenced string differ", details);
                if (info.flags & Detourist::RpcEncoding)
                {
                    Require(details["output"].size() == 1, "Encoding read output memory", details);
                    ++encodes;
                }
                else
                {
                    Require(RpcNodes(details, "input", prefix + 1).empty() &&
                        RpcNodes(details, "input", prefix + 2).empty(), "Decoding read uninitialized input", details);
                    ++decodes;
                }
            }
            else if (info.flags & Detourist::RpcAsynchronous)
            {
                auto text = Unhex(Only(RpcNodes(details, "input", prefix + 2, 11))["bytes"]);
                const bool cancelled = text == Encode("rpc-cancel", false, true);
                Require(cancelled || text == Encode("rpc-async", false, true), "Async RPC text differs", details);
                const auto flags = call["flags"].get<uint32_t>();
                Require((flags & Detourist::AsyncCompleted) && !(flags & Detourist::AsyncPending) &&
                    details.contains("completion") && details["completion"]["domain"] == 4 &&
                    details["completion"]["source"] == 6 &&
                    details["completion"]["tid"] != call["tid"] &&
                    !(details["rpc"]["flags"].get<uint32_t>() & Detourist::RpcOutputsDeferred),
                    "RPC completion was not correlated across threads", details);
                auto completions = Query(database, "SELECT status FROM async_completions WHERE target=? AND id=?",
                    Json::array({call["target"], call["id"]}));
                Require(Only(completions)["status"] == (cancelled ? RPC_S_CALL_CANCELLED : RPC_S_OK),
                    "RPC completion status differs", completions);
                if (cancelled)
                    Require((flags & (Detourist::Failed | Detourist::AsyncCancelled)) ==
                        (Detourist::Failed | Detourist::AsyncCancelled) &&
                        RpcNodes(details, "output", prefix + 3).empty(),
                        "Cancelled RPC exposed an uncompleted output", details);
                else
                    Require(!(flags & Detourist::Failed) &&
                        Read<int32_t>(Unhex(Only(RpcNodes(details, "output", prefix + 3, 6))["bytes"])) == 58,
                        "RPC output was not captured before the caller reused its buffer", details);
                ++asynchronous;
            }
            else
            {
                if (info.flags & Detourist::RpcNdr64) ++ndr64;
                else ++ndr32;
                if (info.procedure == 0)
                {
                    Require(Read<int32_t>(Unhex(Only(RpcNodes(details, "input", prefix + 1))["bytes"])) == -17 &&
                                Read<double>(Unhex(
                                    Only(RpcNodes(details, "input", prefix + 3 + extended / 2))["bytes"])) == 3.25 &&
                                Unhex(Only(RpcNodes(details, "input", prefix + 4 + extended, 12))["bytes"]) ==
                                    Encode("rpc-text", true, true),
                        "RPC scalar, floating or string input differs", details);
                    Require(
                        Read<int32_t>(Unhex(Only(RpcNodes(details, "input", prefix + 6 + extended))["bytes"])) == 9 &&
                            Read<int32_t>(Unhex(Only(RpcNodes(details, "output", prefix + 6 + extended))["bytes"])) ==
                                27,
                        "RPC scalar reference did not retain input and output values", details);
                    auto optional = RpcNodes(details, "input", prefix + 5 + extended, 13);
                    Require(optional.size() == 1 && (Read<uintptr_t>(Unhex(optional[0]["bytes"])) == 0 ||
                                                        Read<int32_t>(Unhex(Only(RpcNodes(details, "input",
                                                            prefix + 5 + extended, 6))["bytes"])) == 15),
                        "Optional RPC pointer differs", details);
                }
                else if (info.procedure == 4)
                {
                    const auto count = Read<uint32_t>(Unhex(Only(RpcNodes(details, "input", prefix + 1))["bytes"]));
                    const auto input = Only(RpcNodes(details, "input", prefix + 2, 15));
                    const auto output = Only(RpcNodes(details, "output", prefix + 2, 15));
                    Require(input["originalBytes"] == count * sizeof(DetouristRpc32Record) &&
                        output["originalBytes"] == input["originalBytes"], "Record-array extent differs", details);
                    for (const auto side : {"input", "output"})
                    {
                        auto strings = RpcNodes(details, side, prefix + 2, 12);
                        Require(strings.size() == count, "Record array lost its referenced strings", details);
                        for (uint32_t index = 0; index < count; ++index)
                            Require(Unhex(strings[index]["bytes"]) ==
                                        Encode(index ? "rpc-array-b" : "rpc-array-a", true, true),
                                "Record-array string differs", details);
                    }
                    if (count)
                        Require(Read<long>(Unhex(output["bytes"])) == 30 &&
                            Read<long>(Unhex(output["bytes"]), sizeof(DetouristRpc32Record)) == 31,
                            "Record array lost completed output", details);
                }
                else if (info.procedure == 5)
                {
                    const auto argument = prefix + (sizeof(void*) == 4 ? 3 : 2);
                    auto prior = Unhex(Only(RpcNodes(details, "input", prefix + 1, 19))["bytes"]);
                    Require(prior.size() == 8 && Read<long>(prior) == 71 && Read<long>(prior, 4) == ~71,
                        "By-value custom representation was not read from its native argument slot", details);
                    auto input = Unhex(Only(RpcNodes(details, "input", argument, 19))["bytes"]);
                    auto output = Unhex(Only(RpcNodes(details, "output", argument, 19))["bytes"]);
                    Require(input.size() == 8 && output.size() == 8 && Read<long>(input) == 17 &&
                        Read<long>(input, 4) == ~17 && Read<long>(output) == 30 && Read<long>(output, 4) == ~30,
                        "Custom marshaling did not preserve its opaque native representation", details);
                }
                else if (info.procedure == 6)
                {
                    const auto tag = Read<long>(Unhex(Only(RpcNodes(details, "input", prefix + 1))["bytes"]));
                    Require(RpcNodes(details, "input", prefix + 2, 20).size() == 1 &&
                        RpcNodes(details, "output", prefix + 3, 20).size() == 1, "Union nodes are missing", details);
                    if (tag == 2)
                        Require(Unhex(Only(RpcNodes(details, "input", prefix + 2, 12))["bytes"]) ==
                            Encode("rpc-choice", true, true) &&
                            Unhex(Only(RpcNodes(details, "output", prefix + 3, 12))["bytes"]) ==
                                Encode("Rpc-envelope", true, true), "Selected union string differs", details);
                    else if (tag == 1)
                        Require(Read<long>(Unhex(Only(RpcNodes(details, "output", prefix + 2, 6))["bytes"])) == 41 &&
                            Read<long>(Unhex(Only(RpcNodes(details, "output", prefix + 3, 6))["bytes"])) == 71,
                            "Selected union integer differs", details);
                    else
                    {
                        Require(Read<int64_t>(Unhex(Only(RpcNodes(details, "output", prefix + 3, 8))["bytes"])) == 91,
                            "Default union arm differs", details);
                        if (tag == -1)
                            Require(
                                Read<int64_t>(Unhex(Only(RpcNodes(details, "output", prefix + 2, 8))["bytes"])) == -7,
                                "Signed union discriminator selected the wrong arm", details);
                        else Require(RpcNodes(details, "input", prefix + 2).size() == 1,
                            "Empty union arm was dereferenced", details);
                    }
                }
                else if (info.procedure == 7)
                {
                    Require(Unhex(Only(RpcNodes(details, "input", prefix + 3, 15))["bytes"]) ==
                        Bytes({1, 2, 3, 4, 5, 6, 7, 8}) &&
                        Unhex(Only(RpcNodes(details, "output", prefix + 5, 15))["bytes"]) ==
                            Bytes({7, 6, 5, 4, 3, 2, 1}), "RPC expression extent differs", details);
                }
                else if (info.procedure == 9)
                {
                    Require(RpcNodes(details, "input", prefix + 2).empty(),
                        "Output-only custom values were read before initialization", details);
                    const auto custom = RpcNodes(details, "output", prefix + 2, 19);
                    Require(custom.size() == 2 && Read<long>(Unhex(custom[0]["bytes"])) == 101 &&
                        Read<long>(Unhex(custom[1]["bytes"])) == 102,
                        "Nested custom outputs were not preserved", details);
                }
                else if (info.procedure == 8)
                {
                    Require(Unhex(Only(RpcNodes(details, "input", prefix + 1, 15))["bytes"]) == Bytes({1, 2, 3, 4}) &&
                                Unhex(Only(RpcNodes(details, "output", prefix + 1, 15))["bytes"]) ==
                                    Bytes({11, 12, 13, 14}) &&
                                Unhex(Only(RpcNodes(details, "output", prefix + 1, 12))["bytes"]) ==
                                    Encode("Rpc-nested", true, true),
                        "Structure correlation or embedded union differs", details);
                }
                else
                {
                    Require(Unhex(Only(RpcNodes(details, "input", prefix + 2, 15))["bytes"]) ==
                        Bytes({1, 2, 3, 4, 5, 6, 7, 8}), "RPC array input differs", details);
                    auto output = Only(RpcNodes(details, "output", prefix + 4, 15));
                    Require(Unhex(output["bytes"]) == Bytes({7, 6, 5, 4, 3, 2, 1}) && output["originalBytes"] == 7,
                        "RPC array output included unused capacity", details);
                    Require(Read<int32_t>(Unhex(Only(RpcNodes(details, "output", prefix + 6, 14))["bytes"])) == 48 &&
                        Unhex(Only(RpcNodes(details, "output", prefix + 6, 12))["bytes"]) ==
                            Encode("rpc-record", true, true), "RPC structure or referenced string differs", details);
                }
            }
        }
        Require(ndr32 == 13 && ndr64 == (sizeof(void*) == 8 ? 13 : 0) &&
            asynchronous == (sizeof(void*) == 8 ? 6 : 3) && malformed == 1 &&
            encodes == (sizeof(void*) == 8 ? 2 : 1) && decodes == (sizeof(void*) == 8 ? 2 : 1),
            "RPC interpreter capture counts differ",
            {{"ndr32", ndr32}, {"ndr64", ndr64}, {"asynchronous", asynchronous}, {"malformed", malformed},
                {"encodes", encodes}, {"decodes", decodes}});
        auto marshalers = Query(database, "SELECT c.*,a.name FROM calls c JOIN apis a "
            "ON a.target=c.target AND a.id=c.api WHERE a.name LIKE 'RPC user %' ORDER BY c.id");
        Require(marshalers.size() == (sizeof(void*) == 8 ? 10u : 5u), "Custom marshaler calls are missing", marshalers);
        for (const auto& call : marshalers)
        {
            const bool marshal = call["name"].get<std::string>().starts_with("RPC user marshal #");
            const auto wire = Only(Snapshots(call["output"], 1, static_cast<uint32_t>(Detourist::ValueKind::Bytes)));
            const auto native = Only(Snapshots(call[marshal ? "input" : "output"], 2,
                static_cast<uint32_t>(Detourist::ValueKind::Bytes)));
            Require(wire.size() == 4 && native.size() == 8 && Read<long>(wire) == Read<long>(native) &&
                Read<long>(native, 4) == ~Read<long>(native), "Custom wire and native representations differ", call);
            auto ancestors = Query(database, "WITH RECURSIVE parents(id,parent,depth) AS (SELECT id,parent,0 "
                "FROM calls WHERE target=? AND id=? UNION ALL SELECT c.id,c.parent,p.depth+1 "
                "FROM calls c JOIN parents p ON c.id=p.parent WHERE c.target=? AND p.depth<32) SELECT id FROM parents",
                Json::array({call["target"], call["parent"], call["target"]}));
            Require(std::ranges::any_of(ancestors, [&](const auto& parent)
            {
                return std::ranges::any_of(calls, [&](const auto& rpc) { return rpc["id"] == parent["id"]; });
            }), "Custom marshaling lost its enclosing RPC call", call);
            auto details = collector.Call("details", {{"database", Text(database)}, {"target", call["target"]},
                {"callId", call["id"]}});
            inspections.push_back(details);
        }
        if (context.Has(L"--inspector")) Inspect(context, context.Option(L"--inspector"), "--rpc", inspections);
        WriteJson(context.directory / (instructions ? "rpc-instructions.json" : "rpc-typed.json"), inspections);
        collector.Close();
    }

}

void RpcMarshalLifecycle(const Context& context)
{
    // Callback table entries survive detach and reattachment with either capture engine.
    for (bool instructions : {false, true})
    for (int reattach : {0, 1, 2})
    {
        Collector collector(context.collector, context.directory);
        const auto first = Launch(collector, context, {.arguments = L"detached", .instructions = instructions});
        uint32_t pid = 0;
        Detourist::Handle ready;
        collector.Wait([&](const Json&)
        {
            const auto targets = Query(first, "SELECT pid FROM targets ORDER BY id LIMIT 1");
            if (targets.empty()) return false;
            pid = targets[0]["pid"].get<uint32_t>();
            const auto name = L"Local\\Detourist.Rpc." + std::to_wstring(pid) + L".Ready";
            if (!ready) ready.reset(OpenEventW(SYNCHRONIZE, FALSE, name.c_str()));
            return ready && WaitForSingleObject(ready.get(), 0) == WAIT_OBJECT_0;
        });
        const auto name = L"Local\\Detourist.Rpc." + std::to_wstring(pid) + L".Gate";
        Detourist::Handle gate(OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str()));
        Detourist::Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        Require(gate && process, "Open detached marshaling workload");
        collector.Call("stop");
        collector.Wait([](const Json& state) { return state["finished"] == true; });
        const auto second = context.directory / ("rpc-reconnected-" + std::to_string(instructions) + "-" +
            std::to_string(reattach) + ".sqlite");
        if (reattach)
        {
            collector.Call("attach", {{"pid", pid}, {"database", Text(second)},
                {"instructionEngine", reattach == 1 ? instructions : !instructions}});
            collector.Wait([](const Json& state) { return state["capturing"] == true; });
        }
        // Instrumented Debug CRT shutdown can outlast the marshaling workload.
        Require(SetEvent(gate.get()) && WaitForSingleObject(process.get(), 60000) == WAIT_OBJECT_0,
            "Custom marshaling did not return after detach");
        DWORD code = 1;
        Require(GetExitCodeProcess(process.get(), &code) && !code,
            "Custom marshaler behavior changed across capture sessions");
        if (reattach)
        {
            collector.Wait([](const Json& state) { return state["finished"] == true; });
            const auto calls = Query(second, "SELECT c.output FROM calls c JOIN apis a "
                "ON a.target=c.target AND a.id=c.api WHERE a.name LIKE 'RPC user unmarshal #%' ORDER BY c.id");
            Require(calls.size() == 2 &&
                Read<long>(Only(Snapshots(calls[0]["output"], 1, 0))) == 101 &&
                Read<long>(Only(Snapshots(calls[1]["output"], 1, 0))) == 102,
                "Reattachment lost custom marshalers or their wire values", calls);
        }
        collector.Close();
    }
}

int wmain(int argc, wchar_t** argv)
{
    return Run(argc, argv, [](const Context& context)
    {
        if (context.Has(L"--lifecycle")) RpcMarshalLifecycle(context);
        else Rpc(context);
    }, TargetMain);
}

#include "ComLayout.h"
#include "Agent.h"
#include "AutomationInterfaces.h"
#include "InvokeArguments.h"
#include "RpcFormats.h"
#include <detours.h>
#include <tlhelp32.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <memory>
#include <map>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace Detourist
{
void PrepareNativeTermination(HANDLE process);
constexpr size_t ExportHookCapacity = 65536;
constexpr size_t RpcMarshalCapacity = 4096;
constexpr size_t MaxPrologueScanBytes = 4096;
constexpr uint32_t MaxUnwindChainDepth = 32;
constexpr size_t MaxBranchQueue = 256;
constexpr size_t DetourPatchBytes = 5;
constexpr size_t MaxX86InstructionBytes = 15;
constexpr LONG MaxDosHeaderOffset = 1024 * 1024;
constexpr DWORD MaxExportNames = 65536;
constexpr uint32_t MaxImportDescriptors = 4096;
constexpr uint32_t MaxImportThunks = 8192;
constexpr size_t MaxImportNameBytes = 512;
constexpr int MaxSnapshotAttempts = 3;
constexpr uintptr_t MaxOrdinalValue = 0xFFFF;
constexpr uint32_t MaxRpcProxySlots = 512;
constexpr size_t ProxyMethodNameCapacity = 48;
constexpr size_t RpcProxyNameCapacity = 96;
struct ExportHook
{
    Api api;
    HMODULE module;
    std::string library, name;
    ExportSignature signature;
    uint32_t argumentCount;
    uint32_t ordinal = 0;
    RpcDecoder rpc = RpcDecoder::None;
    CatalogPlan proxyPlan{};
    uint32_t marshalOperation = 0;
    std::atomic<uint32_t> nativeBytes = 0;
    void* address;
    void* implementation;
    void* original;
    void** continuationOriginal = nullptr;
    void** table = nullptr;
    GUID iid{};
    uint32_t slot = 0;
    uint32_t interfaceIndex = 0;
    const ComMethodObserver* comObserver = nullptr;
    void* entry = nullptr;
    bool direct = false;
    std::atomic<bool> retired = false;
    std::atomic<bool> ready = false;
    std::atomic<uint64_t> publishedSession = 0;
    std::atomic<uint64_t> plannedSession = 0;
    ExportCallInfo callInfo;
    SRWLOCK publicationLock = SRWLOCK_INIT;
};
std::array<std::atomic<ExportHook*>, ExportHookCapacity> ExportHooks{};
std::array<std::atomic<ExportHook*>, ExportHookCapacity> ExportHookAddresses{};
std::array<std::atomic<ExportHook*>, ExportHookCapacity> ComMethodHooks{};
std::unordered_map<void**, std::vector<ExportHook*>> ComMethodTables;
SRWLOCK ComMethodLock = SRWLOCK_INIT;
std::array<std::atomic<ExportHook*>, RpcMarshalCapacity> RpcMarshalHooks{};
SRWLOCK RpcMarshalLock = SRWLOCK_INIT;
uint32_t RpcMarshalCount = 0;
uint32_t ExportHookCount = 0;
uint32_t ComMethodCount = 0;
uint32_t InstalledExportCount = 0;

struct ExportEntryFrame
{
#ifdef _WIN64
    uint64_t integer[4], floating[4][2];
    const uint64_t* stack;
    NativeCallResult result;
#else
    const uint32_t* stack;
    NativeCallResult result;
    uint32_t cleanup, floatingBytes;
    uint32_t integer[2];
#endif
};
#ifdef _WIN64
static_assert(offsetof(ExportEntryFrame, stack) == 96 && offsetof(ExportEntryFrame, result) == 104 &&
    sizeof(ExportEntryFrame) == 120);
#else
static_assert(offsetof(ExportEntryFrame, result) == 8 && offsetof(ExportEntryFrame, cleanup) == 24 &&
    offsetof(ExportEntryFrame, integer) == 32 && sizeof(ExportEntryFrame) == 40);
#endif
extern "C" void ExportHookEntry();

ExportHook* ExportHookFor(Api api)
{
    const auto marshal = static_cast<uint32_t>(api) - RpcMarshalApiStart;
    if (marshal < RpcMarshalHooks.size()) return RpcMarshalHooks[marshal].load(std::memory_order_acquire);
    if (IsInterfaceApi(api))
    {
        auto index = static_cast<uint32_t>(api) - FixedInterfaceApiStart;
        return index < ComMethodHooks.size() ? ComMethodHooks[index].load(std::memory_order_acquire) : nullptr;
    }
    auto index = static_cast<uint32_t>(api) - FixedExportApiStart;
    return index < ExportHooks.size() ? ExportHooks[index].load(std::memory_order_acquire) : nullptr;
}

FARPROC ExportInteropTarget(FARPROC function)
{
    // Generic trampolines have their own capacity and retain tombstones across module reloads.
    auto address = reinterpret_cast<void*>(function);
    auto bucket = (reinterpret_cast<uintptr_t>(address) >> 4) % ExportHookAddresses.size();
    for (size_t step = 0; step < ExportHookAddresses.size(); ++step)
    {
        auto hook = ExportHookAddresses[(bucket + step) % ExportHookAddresses.size()].load(std::memory_order_acquire);
        if (!hook) break;
        if (hook->implementation == address && hook->ready.load(std::memory_order_acquire) &&
            !hook->retired.load(std::memory_order_acquire) && hook->original)
            return reinterpret_cast<FARPROC>(hook->original);
    }
    return function;
}

const CatalogPlan* ExportPlanFor(const CatalogView& catalog, const char* library, const char* name)
{
    auto first = catalog.Plans(), last = first + catalog.Header()->exportCount;
    auto plan = std::lower_bound(first, last, name, [&](const auto& candidate, const char* value)
    {
        return strcmp(catalog.Text(candidate.name), value) < 0;
    });
    auto canonical = catalog.CanonicalModule(library);
    const CatalogPlan* alias = nullptr;
    const CatalogPlan* family = nullptr;
    const CatalogPlan* fallback = nullptr;
    for (; plan != last && !strcmp(catalog.Text(plan->name), name); ++plan)
    {
        auto provider = catalog.Text(plan->module);
        if (!_stricmp(provider, library)) return plan;
        if (!_stricmp(provider, canonical)) alias = plan;
        if (CatalogModuleMatches(provider, library)) family = plan;
        if (!strcmp(provider, "$image")) fallback = plan;
    }
    return alias ? alias : family ? family : fallback;
}

const CatalogPlan* ExportCallPlan(Api api, const CatalogView& catalog)
{
    auto hook = ExportHookFor(api);
    if (!hook || hook->retired.load(std::memory_order_acquire)) return nullptr;
    if (hook->marshalOperation || hook->table && hook->rpc != RpcDecoder::None) return &hook->proxyPlan;
    auto compatible = [&](const CatalogPlan& plan)
    {
        const auto& signature = plan.signature;

        // Reattachment may replace capture rules, but an installed entry must keep the same physical ABI.
        return signature.supported && (!plan.rawTailStart || hook->rpc != RpcDecoder::None &&
            plan.rawTailStart == RpcPrefix(hook->rpc)) && plan.argumentCount == hook->argumentCount &&
            signature.floatingArguments == hook->signature.floatingArguments &&
            signature.floatingResult == hook->signature.floatingResult &&
            signature.resultBytes == hook->signature.resultBytes &&
            (sizeof(void*) == 8 || hook->table || signature.callingConvention == hook->signature.callingConvention) &&
            signature.returnBufferBytes == hook->signature.returnBufferBytes &&
            !memcmp(signature.argumentBytes, hook->signature.argumentBytes, plan.argumentCount);
    };
    if (hook->table)
    {
        const CatalogInterface* contract = nullptr;
        if (hook->interfaceIndex < catalog.Header()->interfaceCount &&
            catalog.Interfaces()[hook->interfaceIndex].iid == hook->iid)
            contract = &catalog.Interfaces()[hook->interfaceIndex];
        else for (uint32_t index = 0; index < catalog.Header()->interfaceCount; ++index)
        {
            if (catalog.Interfaces()[index].iid != hook->iid) continue;
            contract = &catalog.Interfaces()[index];
            break;
        }
        if (!contract || hook->slot >= contract->slotCount) return nullptr;
        auto selected = catalog.Slots()[contract->firstSlot + hook->slot];
        if (selected >= catalog.Header()->planCount) return nullptr;
        const auto& plan = catalog.Plans()[selected];
        return compatible(plan) ? &plan : nullptr;
    }
    auto plan = ExportPlanFor(catalog, hook->library.c_str(), hook->name.c_str());
    return plan && compatible(*plan) ? plan : nullptr;
}

ApiCategory ExportCallCategory(Api api, const CatalogView& catalog)
{
    auto hook = ExportHookFor(api);
    if (hook && hook->marshalOperation) return ApiCategory::Ipc;
    return hook ? catalog.ClassifyApi(hook->library.c_str(), hook->name.c_str()) : ApiCategory::Unclassified;
}

ExportCallInfo ResolveExportCall(Api api, const Transport& transport)
{
    auto hook = ExportHookFor(api);
    if (!hook || hook->retired.load(std::memory_order_acquire)) return {};
    auto identity = transport.Header()->captureIdentity;

    // Admission holds CaptureLock, so reattachment cannot replace these facts while a caller reads them.
    if (hook->plannedSession.load(std::memory_order_acquire) != identity)
    {
        AcquireSRWLockExclusive(&hook->publicationLock);
        if (hook->plannedSession.load(std::memory_order_relaxed) != identity)
        {
            const auto& catalog = transport.Catalog();
            auto plan = ExportCallPlan(api, catalog);
            hook->callInfo = {plan, CategoryMask(ExportCallCategory(api, catalog)),
                ApiNameHash(hook->name.c_str()), plan ? AsyncRole(catalog.Text(plan->module),
                catalog.Text(plan->name)) : AsyncIoRole::None};
            hook->plannedSession.store(identity, std::memory_order_release);
        }
        ReleaseSRWLockExclusive(&hook->publicationLock);
    }
    return hook->callInfo;
}

bool PublishExportMetadata(Call& call)
{
    auto hook = ExportHookFor(call.event.api);
    if (!hook || !call.exportPlan) return false;
    auto header = call.transport->Header();
    if (hook->publishedSession.load(std::memory_order_acquire) == header->captureIdentity) return true;
    bool published = false;
    AcquireSRWLockExclusive(&hook->publicationLock);
    if (hook->publishedSession.load(std::memory_order_relaxed) == header->captureIdentity) published = true;
    else if (header->payloadCapacity >= sizeof(DynamicApiMetadata))
    {
        if (auto slot = call.transport->Acquire())
        {
            auto& catalog = call.transport->Catalog();
            DynamicApiMetadata metadata{};
            metadata.argumentCount = hook->rpc == RpcDecoder::None || hook->table ?
                call.exportPlan->argumentCount : MaximumArguments;
            metadata.category = ExportCallCategory(call.event.api, catalog);
            strncpy_s(metadata.module, hook->library.c_str(), _TRUNCATE);
            strncpy_s(metadata.name, hook->name.c_str(), _TRUNCATE);
            wcsncpy_s(metadata.parameters, hook->marshalOperation ?
                L"ULONG* flags, BYTE* wire, void* nativeValue -> BYTE*" : hook->table && hook->rpc != RpcDecoder::None ?
                L"instance and NDR-described arguments -> HRESULT" : catalog.WideText(call.exportPlan->description),
                _TRUNCATE);
            slot->event = {};
            slot->event.kind = EventKind::ApiMetadata;
            slot->event.api = call.event.api;
            slot->event.timestamp = Clock();
            slot->event.processId = call.event.processId;
            slot->event.threadId = call.event.threadId;
            slot->event.payloadBytes = sizeof(metadata);
            memcpy(Transport::Payload(slot), &metadata, sizeof(metadata));
            call.transport->Publish(slot);
            hook->publishedSession.store(header->captureIdentity, std::memory_order_release);
            published = true;
        }
    }
    ReleaseSRWLockExclusive(&hook->publicationLock);
    return published;
}

const GUID* ExportInterfaceIdentity(const CatalogView& catalog, uint16_t index)
{
    if (!index || index > catalog.Header()->interfaceCount) return nullptr;
    return &catalog.Interfaces()[index - 1].iid;
}

void DiscoverCatalogInterfaces(Call& call, uint64_t result, bool leaving)
{
    if (call.skipped || !call.transport) return;
    const auto& catalog = call.transport->Catalog();
    auto selected = call.exportPlan ? call.exportPlan : catalog.BuiltinPlan(call.event.api);
    if (!selected) return;
    const auto& plan = *selected;
    if (!plan.interfaceParameters && !plan.resultInterfaceIndex && !plan.signature.interfaceOutputIndex) return;
    if (leaving && ExportResultFailed(plan.resultRule, plan.signature.resultBytes, result,
        catalog.SuccessValues(plan), plan.resultSuccessCount)) return;
    auto error = GetLastError();
    auto status = NativeThreadStatus();
    auto parameters = catalog.Parameters(plan);
    for (uint32_t index = 0; index < plan.argumentCount; ++index)
    {
        if (!index && IsInterfaceApi(call.event.api)) continue;
        const auto& parameter = parameters[index];
        auto address = call.event.arguments[index];
        auto queried = plan.signature.interfaceIdIndex && plan.signature.interfaceOutputIndex == index + 1;
        if (!address) continue;
        auto iid = ExportInterfaceIdentity(catalog, parameter.interfaceIndex);
        if (queried)
            iid = reinterpret_cast<const GUID*>(call.event.arguments[plan.signature.interfaceIdIndex - 1]);
        auto variant = (parameter.flags & ExportAutomationVariant) != 0;
        if (!iid && !variant) continue;
        if (!(parameter.flags & ExportInterfaceArray) && !variant)
        {
            if (bool((parameter.flags & 2) || queried) == leaving)
                DiscoverComOutput(S_OK, leaving ? address : Bits(&address), iid);
            continue;
        }

        // Remember the caller's capacity even when no event is recorded; allocated outputs have no input capacity.
        if (!leaving) call.captureLimits[index] = 0;
        if (!leaving && ((parameter.flags & ExportReturnedBuffer) || parameter.extentIndex == -2))
        {
            call.captureLimits[index] = UINT64_MAX;
            continue;
        }
        uint64_t length = parameter.bytes;
        if (parameter.extentIndex >= 0)
        {
            length = call.event.arguments[parameter.extentIndex];
            if (parameter.indirectBytes)
            {
                uint64_t value = 0;
                if (!ReadCaptureMemory(reinterpret_cast<void*>(length), &value, parameter.indirectBytes)) continue;
                length = value;
            }
            if (parameter.productIndex)
            {
                auto factor = call.event.arguments[parameter.productIndex - 1];
                if (factor && length > UINT64_MAX / factor) continue;
                length *= factor;
            }
        }
        else if (parameter.extentIndex == -2) length = result;
        if (parameter.extentIndex != -1)
        {
            if (!parameter.multiplier || length > UINT64_MAX / parameter.multiplier) continue;
            length *= parameter.multiplier;
        }
        if (length > UINT64_MAX - parameter.prefixBytes) continue;
        length += parameter.prefixBytes;
        if (!leaving) call.captureLimits[index] = length;
        else length = std::min(length, call.captureLimits[index]);
        if (!(parameter.flags & (leaving ? 2u : 1u))) continue;
        if (leaving && parameter.actualIndex)
        {
            auto actual = parameter.actualIndex == ExportActualReturn ? result :
                call.event.arguments[parameter.actualIndex - 1];
            if (parameter.actualIndirectBytes)
            {
                uint64_t value = 0;
                if (actual > UINT64_MAX - parameter.actualOffset || !ReadCaptureMemory(
                    reinterpret_cast<void*>(actual + parameter.actualOffset), &value, parameter.actualIndirectBytes))
                    continue;
                actual = value;
            }
            if (!parameter.multiplier || actual > (UINT64_MAX - parameter.actualPrefixBytes) / parameter.multiplier)
                continue;
            length = std::min(length, actual * parameter.multiplier + parameter.actualPrefixBytes);
        }
        if (parameter.flags & ExportReturnedBuffer)
            if (!ReadCaptureMemory(reinterpret_cast<void*>(address), &address, sizeof(void*))) continue;
        if (!address || address > UINT64_MAX - length || length <= parameter.prefixBytes) continue;
        address += parameter.prefixBytes;
        length -= parameter.prefixBytes;

        // Discovery follows completed elements independently of the payload cap and does not add references.
        if (variant)
        {
            ForEachAutomationElement(address, length / sizeof(VARIANT), [](void* instance, const GUID& identity)
            {
                DiscoverComOutput(S_OK, Bits(&instance), &identity);
            }, parameter.kind == ExportValueKind::PropertyVariant);
            continue;
        }
        for (uint64_t offset = 0; offset < length / sizeof(void*); ++offset)
        {
            void* instance = nullptr;
            if (!ReadCaptureMemory(reinterpret_cast<void*>(address + offset * sizeof(void*)),
                &instance, sizeof(instance))) break;
            if (instance) DiscoverComOutput(S_OK, Bits(&instance), iid);
        }
    }
    if (leaving && result)
        if (auto iid = ExportInterfaceIdentity(catalog, plan.resultInterfaceIndex))
            DiscoverComOutput(S_OK, Bits(&result), iid);
    RestoreNativeThreadStatus(status);
    SetLastError(error);
}

struct ForwardedRpc { RpcDecoder decoder; uint64_t stub, format; };
[[msvc::no_tls_guard]] constinit thread_local ForwardedRpc ForwardingRpc{};

void InvokeRpcArguments(RpcDecoder decoder, void* original, const uint64_t* slots, uint32_t count,
    NativeCallResult* result)
{
    const auto previous = ForwardingRpc;
    const auto prefix = RpcPrefix(decoder);
    if (RpcDirectArguments(decoder)) ForwardingRpc = {decoder, slots[prefix - 2], slots[prefix - 1]};
    __try { InvokeNativeArguments(original, slots, count, result); }
    __finally { ForwardingRpc = previous; }
}

void* DispatchRpcHook(ExportHook* hook, ExportEntryFrame* frame, void* original, uint64_t caller)
{
    const auto error = GetLastError();
    const auto status = NativeThreadStatus();
    uint64_t arguments[MaximumArguments]{};
    const auto prefix = hook->table ? 0u : RpcPrefix(hook->rpc);
#ifdef _WIN64
    std::copy_n(frame->integer, prefix, arguments);
#else
    for (uint32_t index = 0; index < prefix; ++index) arguments[index] = frame->stack[index + 1];
#endif

    // ABI adapters can forward into an older interpreter; keep one observation of the application call.
    if (RpcForwardedInterpreter(ForwardingRpc.decoder, hook->rpc) && prefix >= 2 &&
        arguments[prefix - 2] == ForwardingRpc.stub && arguments[prefix - 1] == ForwardingRpc.format)
    {
        MEMORY_BASIC_INFORMATION region{};
        if (VirtualQuery(reinterpret_cast<void*>(caller), &region, sizeof(region)) &&
            region.AllocationBase == hook->module)
        {
            SetLastError(error);
            RestoreNativeThreadStatus(status);
            return original;
        }
    }
    RpcCaptureState rpc;
    ObserverActive = true;
    if (hook->table)
    {
        if (!PrepareRpcProxyCapture(rpc, Bits(hook->table), &hook->iid, hook->slot))
        {
            ObserverActive = false;
            SetLastError(error);
            RestoreNativeThreadStatus(status);
            return original;
        }
    }
    else PrepareRpcCapture(rpc, hook->rpc, arguments);
    const uint32_t count = rpc.info.argumentCount;
#ifdef _WIN64
    for (uint32_t index = prefix; index < count; ++index)
    {
        if (index < 4) arguments[index] = hook->table && (hook->signature.floatingArguments & (1u << index)) ?
            frame->floating[index][0] : frame->integer[index];
        else ReadCaptureMemory(frame->stack + index + 1, arguments + index, sizeof(uint64_t));
    }
#else
    ReadRpcStackArguments(rpc, arguments, hook->table || RpcDirectArguments(hook->rpc) ?
        Bits(frame->stack + prefix + 1) : frame->stack[prefix + 1]);
#endif
    ObserverActive = false;
    SetLastError(error);
    RestoreNativeThreadStatus(status);
    const auto flags = RawArguments | FormattedArguments | (count << FormattedArgumentShift) |
        (rpc.info.flags & RpcDescriptorValid ? 0u : Continuation);
    Call call(hook->api, {arguments, count}, reinterpret_cast<void*>(caller), {}, flags, 0, &rpc);
    if (!call.transport) return original;

    // Unknown descriptors preserve the complete incoming ABI and remain explicit entry-only observations.
    if (!(rpc.info.flags & RpcDescriptorValid) && !call.skipped)
    {
        for (uint32_t index = 0; index < prefix; ++index)
#ifdef _WIN64
            frame->integer[index] = call.event.arguments[index];
#else
            const_cast<uint32_t*>(frame->stack)[index + 1] = static_cast<uint32_t>(call.event.arguments[index]);
#endif
        call.ReleaseForContinuation();
        return original;
    }
    uint64_t slots[MaximumArguments]{};
#ifdef _WIN64
    for (uint32_t index = 0; index < count; ++index) slots[index] = call.event.arguments[index];
    const auto forwarded = std::max(count, 4u);
#else
    for (uint32_t index = 0; index < prefix; ++index) slots[index] = call.event.arguments[index];
    slots[prefix] = rpc.argumentStack;
    for (uint32_t index = prefix; index < count; ++index)
        if (arguments[index] != call.event.arguments[index])
            WriteRpcStackArgument(rpc, index, call.event.arguments[index]);
    const auto forwarded = hook->table || RpcDirectArguments(hook->rpc) ? count : prefix + 1;
    if (hook->table || RpcDirectArguments(hook->rpc))
        for (uint32_t index = 0; index < count; ++index) slots[index] = frame->stack[index + 1];
    frame->cleanup = hook->table ? count * sizeof(void*) : 0;
    frame->floatingBytes = 0;
#endif
    frame->result = {};
    call.Invoke([&]()
    {
        if (!call.skipped) InvokeRpcArguments(hook->rpc, original, slots, forwarded, &frame->result);
    });
    auto result = frame->result.integer;
    if (!hook->signature.resultBytes) result = 0;
    else if (hook->signature.resultBytes < sizeof(result))
        result &= (uint64_t{1} << (hook->signature.resultBytes * 8)) - 1;
    call.Finish(result, GetLastError());
    if (call.event.result != result) frame->result.integer = call.event.result;
    SetLastError(call.event.error);
    return nullptr;
}

extern "C" void* DispatchExportHook(ExportHook* hook, ExportEntryFrame* frame)
{
    auto function = hook->continuationOriginal ? *hook->continuationOriginal :
        hook->original ? hook->original : hook->address;
    if (!NativeThreadReady() || ObserverActive || BroadHooks && !hook->marshalOperation ||
        hook->retired.load(std::memory_order_acquire))
        return function;
    auto caller = frame->stack[0];
    auto self = reinterpret_cast<uintptr_t>(&__ImageBase);
    auto image = reinterpret_cast<const IMAGE_NT_HEADERS*>(self + __ImageBase.e_lfanew);
    if (caller >= self && caller - self < image->OptionalHeader.SizeOfImage) return function;
#ifndef _WIN64
    if (hook->continuationOriginal)
    {
        // Complete every C++ frame before a context transfer abandons the intercepted stack and its SEH chain.
        uint64_t arguments[MaximumArguments]{};
        uint32_t offsets[MaximumArguments]{}, words = 0;
        for (uint32_t index = 0; index < hook->argumentCount; ++index)
        {
            offsets[index] = words;
            const auto bytes = hook->signature.argumentBytes[index];
            if (!bytes || bytes > sizeof(uint64_t) || !ReadCaptureMemory(frame->stack + words + 1,
                arguments + index, bytes)) return function;
            words += (bytes + 3u) / 4;
        }
        Call call(hook->api, {arguments, hook->argumentCount}, reinterpret_cast<void*>(caller));
        if (!call.transport) return function;
        if (call.skipped)
        {
            call.Finish(0, GetLastError());
            frame->result = {call.event.result, call.event.result};
            frame->cleanup = words * sizeof(void*);
            frame->floatingBytes = 0;
            SetLastError(call.event.error);
            return nullptr;
        }
        for (uint32_t index = 0; index < hook->argumentCount; ++index)
        {
            auto value = call.InvocationArgument(index);
            memcpy(const_cast<uint32_t*>(frame->stack) + offsets[index] + 1, &value,
                hook->signature.argumentBytes[index]);
        }
        if (Definition(hook->api).hookFlags & HookProcessTermination)
            PrepareNativeTermination(reinterpret_cast<HANDLE>(call.event.arguments[0]));
        call.ReleaseForContinuation();
        return function;
    }
#endif
    void* original;
    {
        ObserverScope scope;
        original = reinterpret_cast<void*>(NativeInteropTarget(reinterpret_cast<FARPROC>(function)));
    }
    if (hook->rpc != RpcDecoder::None) return DispatchRpcHook(hook, frame, original, caller);
    const auto& signature = hook->signature;
#ifdef _WIN64
    uint64_t slots[MaximumArguments + 1]{};
    uint64_t arguments[MaximumArguments]{};
    auto hidden = signature.returnBufferBytes ? 1u : 0u;
    auto count = hook->argumentCount + hidden;
    auto position = [&](uint32_t index) { return index + (hidden && (!hook->table || index) ? 1u : 0u); };

    // Stack slots retain their full width; register positions select the declared Win64 register class.
    for (uint32_t index = 0; index < count; ++index)
        slots[index] = index < 4 ? (signature.floatingArguments & (1u << index) ?
            frame->floating[index][0] : frame->integer[index]) : frame->stack[index + 1];
    for (uint32_t index = 0; index < hook->argumentCount; ++index)
    {
        auto bytes = signature.argumentBytes[index];
        arguments[index] = slots[position(index)];
        if (bytes && bytes < 8) arguments[index] &= (UINT64_C(1) << (bytes * 8)) - 1;
    }
    if (hook->comObserver)
    {
        InvokeComMethodObserver(*hook->comObserver, original, hook->slot, caller, slots, &frame->result);
        return nullptr;
    }
    Call call(hook->api, {arguments, hook->argumentCount}, reinterpret_cast<void*>(caller), {}, 0,
        hidden ? slots[hook->table ? 1 : 0] : 0);
    if (!call.transport) return original;
    for (uint32_t index = 0; index < hook->argumentCount; ++index)
    {
        auto value = call.InvocationArgument(index);
        if (value != arguments[index]) slots[position(index)] = value;
    }
    DiscoverCatalogInterfaces(call, 0, false);
    frame->result = {};
    call.Invoke([&]()
    {
        if (!call.skipped) InvokeNativeArguments(original, slots, std::max(count, 4u), &frame->result);
    });
    auto result = signature.floatingResult ? frame->result.floating : frame->result.integer;
    if (!signature.resultBytes) result = 0;
    else if (signature.resultBytes < 8) result &= (UINT64_C(1) << (signature.resultBytes * 8)) - 1;
    DiscoverCatalogInterfaces(call, result, true);
    call.Finish(result, GetLastError());

    // Recording a logical void result must preserve ABI-only returns such as a constructor's receiver.
    if (call.event.result != result) frame->result.integer = frame->result.floating = call.event.result;
    SetLastError(call.event.error);
    return nullptr;
#else
    if (!hook->table && signature.callingConvention == ExportCallingConvention::Unknown) return original;
    uint64_t slots[MaximumArguments * (MaximumExportArgumentBytes / 4) + 1], arguments[MaximumArguments]{};
    const bool hidden = signature.returnBufferBytes != 0;
    uint32_t offsets[MaximumArguments]{}, words = hidden && !hook->table ? 1u : 0u;
    const bool fastcall = signature.callingConvention == ExportCallingConvention::Fastcall;
    for (uint32_t index = 0; index < hook->argumentCount; ++index)
    {
        const uint32_t width = signature.argumentBytes[index];
        if (!width || width > MaximumExportArgumentBytes) return original;
        offsets[index] = words;
        if (fastcall && index < 2)
        {
            if (width > sizeof(uint32_t)) return original;
            arguments[index] = frame->integer[index];
            if (width < sizeof(uint32_t)) arguments[index] &= (uint64_t{1} << (width * 8)) - 1;
            continue;
        }
        if (width > sizeof(uint64_t)) arguments[index] = reinterpret_cast<uint64_t>(frame->stack + words + 1);
        words += (width + 3u) / 4;
        if (hidden && hook->table && !index) ++words;
    }

    // Snapshot the packed stack once to avoid a separate WOW64 memory probe for each argument and word.
    if (words)
    {
        const auto error = GetLastError();
        const auto status = NativeThreadStatus();
        bool read = ReadCaptureMemory(frame->stack + 1, slots, words * sizeof(uint32_t));
        SetLastError(error);
        RestoreNativeThreadStatus(status);
        if (!read) return original;
    }
    auto packed = reinterpret_cast<const BYTE*>(slots);
    for (uint32_t index = 0; index < hook->argumentCount; ++index)
    {
        const auto width = signature.argumentBytes[index];
        if (width <= sizeof(uint64_t) && !(fastcall && index < 2))
            memcpy(arguments + index, packed + offsets[index] * sizeof(uint32_t), width);
    }

    // Expand backward so native DWORDs and invocation slots share the same storage.
    for (uint32_t word = words; word; --word)
    {
        uint32_t value;
        memcpy(&value, packed + (word - 1) * sizeof(value), sizeof(value));
        slots[word - 1] = value;
    }
    frame->cleanup = hook->table || fastcall ||
        signature.callingConvention == ExportCallingConvention::Stdcall ? words * 4 : 0;
    frame->floatingBytes = signature.floatingResult ? signature.resultBytes : 0;
    frame->result = {};
    if (hook->comObserver)
    {
        InvokeComMethodObserver(*hook->comObserver, original, hook->slot, caller, slots, &frame->result, words);
        return nullptr;
    }
    Call call(hook->api, {arguments, hook->argumentCount}, reinterpret_cast<void*>(caller), {}, 0,
        hidden ? slots[hook->table ? 1 : 0] : 0);
    if (!call.transport) return original;

    // Logical values retain their declared widths while the invocation uses native DWORD stack slots.
    for (uint32_t index = 0; index < hook->argumentCount; ++index)
    {
        const uint32_t width = signature.argumentBytes[index];
        auto value = call.InvocationArgument(index);
        if (width <= sizeof(value) && value == arguments[index]) continue;
        if (fastcall && index < 2)
        {
            frame->integer[index] = static_cast<uint32_t>(value);
            continue;
        }
        unsigned char bytes[MaximumExportArgumentBytes]{};
        if (width <= sizeof(value)) memcpy(bytes, &value, width);
        else if (!ReadCaptureMemory(reinterpret_cast<void*>(value), bytes, width))
            memcpy(bytes, frame->stack + offsets[index] + 1, width);
        for (uint32_t offset = 0; offset < width; offset += sizeof(uint32_t))
        {
            slots[offsets[index] + offset / sizeof(uint32_t)] = 0;
            memcpy(slots + offsets[index] + offset / sizeof(uint32_t), bytes + offset,
                std::min<uint32_t>(width - offset, sizeof(uint32_t)));
        }
    }
    DiscoverCatalogInterfaces(call, 0, false);
    call.Invoke([&]()
    {
        if (!call.skipped) InvokeNativeArguments(original, slots, words, &frame->result, frame->floatingBytes,
            fastcall ? frame->integer : nullptr);
    });
    auto result = signature.floatingResult ? frame->result.floating : frame->result.integer;
    if (!signature.resultBytes) result = 0;
    else if (signature.resultBytes < 8) result &= (uint64_t{1} << (signature.resultBytes * 8)) - 1;
    DiscoverCatalogInterfaces(call, result, true);
    call.Finish(result, GetLastError());
    if (call.event.result != result) frame->result.integer = frame->result.floating = call.event.result;
    SetLastError(call.event.error);
    return nullptr;
#endif
}

bool ExportCodeAddress(const void* address)
{
    MEMORY_BASIC_INFORMATION region{};
    return VirtualQuery(address, &region, sizeof(region)) && region.State == MEM_COMMIT &&
        !(region.Protect & PAGE_GUARD) && (region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}

bool ExportEntryPatchable(void* address)
{
    // A branch into the replaced prologue would bypass its relocated instructions and enter the detour bytes.
    auto start = static_cast<BYTE*>(address);
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(start, &region, sizeof(region))) return false;
    auto available = static_cast<BYTE*>(region.BaseAddress) + region.RegionSize - start;
    auto bytes = std::min<size_t>(available, MaxPrologueScanBytes);
    bool bounded = false;
#ifdef _WIN64
    DWORD64 image = 0;
    auto function = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(start), &image, nullptr);
    if (function)
    {
        bounded = true;
        if (image + function->BeginAddress != reinterpret_cast<DWORD64>(start) ||
            function->EndAddress - function->BeginAddress > bytes) return false;
        bytes = function->EndAddress - function->BeginAddress;
#ifdef _M_X64

        // Shrink-wrapped bodies continue in contiguous chained fragments that unwind through this entry.
        auto root = [&](const RUNTIME_FUNCTION* entry)
        {
            for (uint32_t depth = 0; depth < MaxUnwindChainDepth; ++depth)
            {
                auto info = reinterpret_cast<const BYTE*>(image + entry->UnwindData);
                if (!((info[0] >> 3) & UNW_FLAG_CHAININFO)) return entry->BeginAddress;
                entry = reinterpret_cast<const RUNTIME_FUNCTION*>(info + 4 + ((info[2] + 1u) & ~1u) * 2);
            }
            return DWORD{0};
        };
        while (auto next = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(start) + bytes, &image, nullptr))
        {
            if (image + next->BeginAddress != reinterpret_cast<DWORD64>(start) + bytes ||
                root(next) != function->BeginAddress ||
                next->EndAddress - function->BeginAddress > std::min<size_t>(available, MaxPrologueScanBytes)) break;
            bytes = next->EndAddress - function->BeginAddress;
        }
#endif
    }
#endif
    bool visited[MaxPrologueScanBytes]{};
    size_t pending[MaxBranchQueue]{}, count = 1, replaced = 0;
    __try
    {
        while (replaced < DetourPatchBytes)
        {
            auto next = static_cast<BYTE*>(DetourCopyInstruction(nullptr, nullptr, start + replaced, nullptr, nullptr));
            if (!next || next <= start + replaced || next - (start + replaced) > MaxX86InstructionBytes ||
                next > start + bytes)
                return false;
            replaced = next - start;
        }
        while (count)
        {
            auto offset = pending[--count];
            while (offset < bytes && !visited[offset])
            {
                visited[offset] = true;
                PVOID target = nullptr;
                auto instruction = start + offset;
                auto next = static_cast<BYTE*>(DetourCopyInstruction(nullptr, nullptr, instruction, &target, nullptr));
                if (!next || next <= instruction || next - instruction > MaxX86InstructionBytes ||
                    next > start + bytes) return false;
                auto opcode = instruction;
                while (opcode < next &&
                       ((sizeof(void*) == 8 && *opcode >= 0x40 && *opcode <= 0x4F) || *opcode == 0x66 ||
                           *opcode == 0x67 || *opcode == 0xF2 || *opcode == 0xF3 || *opcode == 0x2E ||
                           *opcode == 0x3E || *opcode == 0x26 || *opcode == 0x36 || *opcode == 0x64 || *opcode == 0x65))
                    ++opcode;
                if (opcode == next) return false;
                auto jump = *opcode == 0xEB || *opcode == 0xE9;
                auto conditional = (*opcode >= 0x70 && *opcode <= 0x7F) ||
                    (*opcode >= 0xE0 && *opcode <= 0xE3) || (*opcode == 0x0F && opcode + 1 < next &&
                    opcode[1] >= 0x80 && opcode[1] <= 0x8F);
                auto destination = reinterpret_cast<uintptr_t>(target) - reinterpret_cast<uintptr_t>(start);
                if (*opcode == 0xE8 && destination && destination < replaced) return false;
                if (jump || conditional)
                {
                    if (destination < replaced) return false;
                    if (destination < bytes)
                    {
                        if (count == std::size(pending)) return false;
                        if (!visited[destination]) pending[count++] = destination;
                    }
                    else if (!bounded) return false;
                    if (jump) break;
                }

                // Unknown jump targets can return to the entry; calls resume at the following instruction.
                if (*opcode == 0xFF && opcode + 1 < next && ((opcode[1] >> 3) & 7) >= 4 &&
                    ((opcode[1] >> 3) & 7) <= 5) return false;
                if (*opcode == 0xC3 || *opcode == 0xC2 || *opcode == 0xCB || *opcode == 0xCA || *opcode == 0xCC ||
                    (*opcode == 0x0F && opcode + 1 < next && opcode[1] == 0x0B)) break;
                offset = next - start;
                if (offset == bytes) return false;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return true;
}

std::unordered_map<void*, uint32_t> ExportAddressCounts(HMODULE module)
{
    std::unordered_map<void*, uint32_t> counts;
    auto base = reinterpret_cast<const BYTE*>(module);
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS image{};
    IMAGE_EXPORT_DIRECTORY exports{};
    if (!ReadCaptureMemory(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > MaxDosHeaderOffset ||
        !ReadCaptureMemory(base + dos.e_lfanew, &image, sizeof(image)) || image.Signature != IMAGE_NT_SIGNATURE)
        return counts;
    auto bytes = image.OptionalHeader.SizeOfImage;
    auto read = [&](uint64_t offset, void* destination, size_t size)
    {
        return offset < bytes && size <= bytes - offset && ReadCaptureMemory(base + offset, destination, size);
    };
    const auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!directory.VirtualAddress || !read(directory.VirtualAddress, &exports, sizeof(exports)) ||
        exports.NumberOfNames > MaxExportNames) return counts;

    // Count names and ordinal-only functions before choosing any physical implementation.
    std::vector<BYTE> named(exports.NumberOfFunctions, 0);
    for (uint32_t index = 0; index < exports.NumberOfNames; ++index)
    {
        WORD ordinal = 0;
        DWORD address = 0;
        if (!read(uint64_t{exports.AddressOfNameOrdinals} + index * sizeof(WORD), &ordinal, sizeof(ordinal)) ||
            ordinal >= exports.NumberOfFunctions ||
            !read(uint64_t{exports.AddressOfFunctions} + ordinal * sizeof(DWORD), &address, sizeof(address)))
            return {};
        named[ordinal] = 1;
        if (!address || address >= bytes || (address >= directory.VirtualAddress &&
            uint64_t{address} < uint64_t{directory.VirtualAddress} + directory.Size)) continue;
        if (!ExportCodeAddress(base + address)) continue;
        ++counts[DetourCodeFromPointer(const_cast<BYTE*>(base + address), nullptr)];
    }
    for (uint32_t ordinal = 0; ordinal < exports.NumberOfFunctions; ++ordinal)
    {
        if (named[ordinal]) continue;
        DWORD address = 0;
        if (!read(uint64_t{exports.AddressOfFunctions} + ordinal * sizeof(DWORD), &address, sizeof(address)))
            return {};
        if (!address || address >= bytes || (address >= directory.VirtualAddress &&
            uint64_t{address} < uint64_t{directory.VirtualAddress} + directory.Size)) continue;
        if (!ExportCodeAddress(base + address)) continue;
        ++counts[DetourCodeFromPointer(const_cast<BYTE*>(base + address), nullptr)];
    }
    return counts;
}

void PrepareExportEntries(std::vector<std::unique_ptr<ExportHook>>& additions, bool callbacks = false)
{
    // Each leaf stub selects its immutable definition; the common entry owns the unwindable frame.
    const auto stride = callbacks ? 48u : 32u;
    auto bytes = additions.size() * stride;
    auto allocation = static_cast<BYTE*>(VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!allocation) throw std::runtime_error("Cannot allocate capture entries.");
    for (size_t index = 0; index < additions.size(); ++index)
    {
        auto definition = additions[index].get();
        auto entry = &ExportHookEntry;
        auto address = allocation + index * stride + (callbacks ? 16 : 0);
#ifdef _WIN64
        BYTE code[32]{0x49, 0xBA};
        memcpy(code + 2, &definition, sizeof(definition));
        code[10] = 0x49; code[11] = 0xBB;
        memcpy(code + 12, &entry, sizeof(entry));
        code[20] = 0x41; code[21] = 0xFF; code[22] = 0xE3;
#else
        BYTE code[32]{0xB8};
        memcpy(code + 1, &definition, sizeof(definition));
        code[5] = 0xE9;
        const auto displacement = reinterpret_cast<uintptr_t>(entry) - reinterpret_cast<uintptr_t>(address + 10);
        memcpy(code + 6, &displacement, sizeof(displacement));
#endif
        if (callbacks)
        {
            // Indirect callback calls retain the application's extended control-flow type hash.
            const auto original = reinterpret_cast<uintptr_t>(definition->original);
            if (original >= 8) ReadRpcMemory(reinterpret_cast<void*>(original - 8), address - 8, 8);
        }
        memcpy(address, code, sizeof(code));
        definition->entry = address;
    }
    DWORD protection = 0;
    if (!VirtualProtect(allocation, bytes, PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), allocation, bytes))
    {
        VirtualFree(allocation, 0, MEM_RELEASE);
        throw std::runtime_error("Cannot prepare capture entries.");
    }
}

bool CaptureRpcMarshalValues(Call& call, Slot* slot, bool leaving)
{
    const auto hook = ExportHookFor(call.event.api);
    if (!hook || !hook->marshalOperation) return false;
    CaptureRpcMarshalValues(call.event, slot, call.transport->Header(), hook->marshalOperation,
        hook->nativeBytes.load(std::memory_order_relaxed), leaving);
    return true;
}

extern "C" __declspec(dllexport) uint64_t WINAPI DetouristRpcMarshalerOriginal(uint64_t address)
{
    // Published entries are immutable and remain valid while callers retain their callback pointers.
    for (auto& entry : RpcMarshalHooks)
    {
        const auto hook = entry.load(std::memory_order_acquire);
        if (!hook) break;
        if (reinterpret_cast<uint64_t>(hook->entry) == address && !hook->retired.load(std::memory_order_acquire))
            return reinterpret_cast<uint64_t>(hook->original);
    }
    return address;
}

extern "C" __declspec(dllexport) BOOL WINAPI DetouristRpcMarshalerOwns(uint32_t api, uint64_t slot)
{
    const auto hook = ExportHookFor(static_cast<Api>(api));
    return hook && hook->marshalOperation && !hook->retired.load(std::memory_order_acquire) &&
        reinterpret_cast<uint64_t>(hook->table + hook->slot) == slot;
}

extern "C" __declspec(dllexport) void WINAPI DetouristObserveRpcMarshaler(uint64_t routines,
    uint32_t index, uint32_t bytes)
{
    if (!routines || routines % alignof(void*) || index > UINT16_MAX || !bytes ||
        routines > UINTPTR_MAX - (uint64_t{index} + 1) * sizeof(void*) * 4 || ProcessShuttingDown) return;
    ObserverScope observer;
    AcquireSRWLockExclusive(&RpcMarshalLock);
    try
    {
        auto table = reinterpret_cast<void**>(routines) + index * 4;
        std::vector<std::unique_ptr<ExportHook>> additions;
        for (uint32_t operation : {1u, 2u})
        {
            void* original = nullptr;
            if (!ReadRpc(reinterpret_cast<uint64_t>(table + operation), original) || !ExportCodeAddress(original))
                continue;
            bool found = false;
            for (uint32_t current = 0; current < RpcMarshalCount; ++current)
            {
                const auto hook = RpcMarshalHooks[current].load(std::memory_order_acquire);
                if (hook->table != table || hook->slot != operation || hook->entry != original ||
                    hook->retired.load(std::memory_order_acquire)) continue;
                if (hook->nativeBytes.load(std::memory_order_relaxed) != bytes)
                    hook->nativeBytes.store(0, std::memory_order_relaxed);
                found = true;
                break;
            }
            if (found || RpcMarshalCount + additions.size() == RpcMarshalHooks.size()) continue;
            auto hook = std::make_unique<ExportHook>();
            hook->library = "RPC";
            hook->name = std::string(operation == 1 ? "RPC user marshal #" : "RPC user unmarshal #") +
                std::to_string(index);
            hook->signature.supported = true;
            hook->signature.resultBytes = sizeof(void*);
            hook->signature.callingConvention = ExportCallingConvention::Stdcall;
            std::fill_n(hook->signature.argumentBytes, 3, static_cast<uint8_t>(sizeof(void*)));
            hook->argumentCount = 3;
            hook->proxyPlan.signature = hook->signature;
            hook->proxyPlan.argumentCount = 3;
            hook->proxyPlan.parameters = hook->proxyPlan.members = UINT32_MAX;
            hook->address = hook->implementation = hook->original = original;
            hook->table = table;
            hook->slot = operation;
            hook->marshalOperation = operation;
            hook->nativeBytes.store(bytes, std::memory_order_relaxed);
            additions.push_back(std::move(hook));
        }
        if (!additions.empty()) PrepareExportEntries(additions, true);
        for (auto& addition : additions)
        {
            const auto hook = addition.get();
            hook->api = static_cast<Api>(RpcMarshalApiStart + RpcMarshalCount);
            hook->ready.store(true, std::memory_order_release);
            RpcMarshalHooks[RpcMarshalCount++].store(addition.release(), std::memory_order_release);
            auto address = table + hook->slot;
            MEMORY_BASIC_INFORMATION region{};
            DWORD protection = 0, ignored = 0;
            if (!VirtualQuery(address, &region, sizeof(region)) || region.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                continue;
            const auto writable = region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                PAGE_EXECUTE_WRITECOPY) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
            if (!VirtualProtect(address, sizeof(void*), writable, &protection)) continue;
            InterlockedCompareExchangePointer(address, hook->entry, hook->original);
            VirtualProtect(address, sizeof(void*), protection, &ignored);
        }
    }
    catch (...) {}
    ReleaseSRWLockExclusive(&RpcMarshalLock);
}

#ifndef _WIN64
void* PrepareNativeContinuation(Api api, void** original, const ExportSignature& signature)
{
    static std::array<ExportHook*, static_cast<uint32_t>(Api::Count)> entries{};
    auto& retained = entries[static_cast<uint32_t>(api)];
    if (retained) return retained->entry;
    auto hook = std::make_unique<ExportHook>();
    hook->api = api;
    hook->argumentCount = Definition(api).argumentCount;
    hook->signature = signature;
    hook->continuationOriginal = original;
    std::vector<std::unique_ptr<ExportHook>> additions;
    additions.push_back(std::move(hook));
    PrepareExportEntries(additions);
    retained = additions.front().release();
    return retained->entry;
}
#endif

bool GenericComProxyMethod(void* address, uint32_t slot)
{
    HMODULE owner = nullptr;
    if (slot < IUnknownSlotCount || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCWSTR>(address), &owner)) return false;
    char name[ProxyMethodNameCapacity]{};
    for (auto prefix : {"ObjectStublessClient", "NdrProxyForwardingFunction"})
    {
        sprintf_s(name, "%s%u", prefix, slot);
        if (reinterpret_cast<void*>(GetProcAddress(owner, name)) == address) return true;
    }
    return false;
}

void AddComMethodHooks(void** table, const GUID& iid, const CatalogView& catalog, const CatalogInterface* contract,
    std::span<const ComMethodObserver* const> observers)
{
    // CLR identifies its wrappers by their IUnknown function pointers; these vtables must remain intact.
    void* query = nullptr;
    HMODULE owner = nullptr;
    if (!ReadCaptureMemory(table, &query, sizeof(query))) return;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(query), &owner) &&
        (owner == GetModuleHandleW(L"clr.dll") || owner == GetModuleHandleW(L"coreclr.dll") ||
            owner == GetModuleHandleW(L"mscorwks.dll"))) return;

    auto count = std::max(contract ? contract->slotCount : 0, static_cast<uint32_t>(observers.size()));
    const bool hasCatalogLayout = iid != KsPropertySetIid || IsSystemDirectSound(table);
    RpcCaptureState proxy;
    const bool rpcProxy = PrepareRpcProxyCapture(proxy, Bits(table), &iid, IUnknownSlotCount);
    if (rpcProxy) count = std::max(count, MaxRpcProxySlots);

    // Generic runtime proxy tables serve unrelated IIDs whose methods have different native argument layouts.
    void* firstMethod = nullptr;
    if (!rpcProxy && count > IUnknownSlotCount &&
        ReadCaptureMemory(table + IUnknownSlotCount, &firstMethod, sizeof(firstMethod)) &&
        GenericComProxyMethod(firstMethod, IUnknownSlotCount)) count = IUnknownSlotCount;
    if (!count) return;
    AcquireSRWLockExclusive(&ComMethodLock);
    std::unique_ptr<SRWLOCK, decltype(&ReleaseSRWLockExclusive)> lock(&ComMethodLock, &ReleaseSRWLockExclusive);
    try
    {
        auto& methods = ComMethodTables[table];
        if (methods.size() < count) methods.resize(count);
        std::vector<std::unique_ptr<ExportHook>> additions;

        // A separate adapter for each vtable slot preserves identities even when implementations are shared.
        for (uint32_t slot = 0; slot < count; ++slot)
        {
            auto observer = slot < observers.size() ? observers[slot] : nullptr;
            auto selected = contract && slot < contract->slotCount && (slot < IUnknownSlotCount || hasCatalogLayout) ?
                catalog.Slots()[contract->firstSlot + slot] : UINT32_MAX;
            auto plan = selected < catalog.Header()->planCount ? &catalog.Plans()[selected] : nullptr;
            ExportSignature proxySignature{};
            const bool rpc = rpcProxy && slot >= IUnknownSlotCount && PrepareRpcProxyCapture(proxy, Bits(table), &iid,
                slot, &proxySignature);
            if (rpcProxy && slot >= IUnknownSlotCount && !rpc) break;
            if (!observer && !rpc &&
                (!plan || !plan->signature.supported || plan->rawTailStart || !plan->argumentCount))
                continue;
            void* original = nullptr;
            if (!ReadCaptureMemory(table + slot, &original, sizeof(original))) break;
            auto previous = methods[slot];
            if (previous && !previous->retired.load(std::memory_order_acquire) && original == previous->entry &&
                (!observer || previous->comObserver == observer)) continue;
            if (!ExportCodeAddress(original)) break;
            if (!rpc && GenericComProxyMethod(original, slot)) continue;
            auto self = reinterpret_cast<uintptr_t>(&__ImageBase);
            auto image = reinterpret_cast<const IMAGE_NT_HEADERS*>(self + __ImageBase.e_lfanew);
            auto address = reinterpret_cast<uintptr_t>(original);
            if (address >= self && address - self < image->OptionalHeader.SizeOfImage) continue;
            auto expected = original;
            if (previous && !previous->retired.load(std::memory_order_acquire) && original == previous->entry)
                original = previous->original;
            auto hook = std::make_unique<ExportHook>();
            hook->module = nullptr;
            hook->library = "COM";
            hook->name = observer ? Definition(observer->api).name : plan ?
                std::string(catalog.Text(contract->name)) + "::" + catalog.Text(plan->name) : "";
            if (rpc)
            {
                char name[RpcProxyNameCapacity]{};
                sprintf_s(name, "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}::%s %u",
                    iid.Data1, iid.Data2, iid.Data3, iid.Data4[0], iid.Data4[1], iid.Data4[2], iid.Data4[3],
                    iid.Data4[4], iid.Data4[5], iid.Data4[6], iid.Data4[7],
                    slot & 1 ? "Begin" : "Finish", (slot - IUnknownSlotCount) / 2);
                hook->name = name;
                hook->rpc = RpcDecoder::Dcom3;
                hook->signature = proxySignature;
                hook->argumentCount = proxy.info.argumentCount;
                hook->proxyPlan.signature = proxySignature;
                hook->proxyPlan.argumentCount = hook->argumentCount;
                hook->proxyPlan.resultRule = ExportResultRule::Negative;
                hook->proxyPlan.parameters = hook->proxyPlan.members = UINT32_MAX;
            }
            else
            {
                hook->signature = observer ? observer->signature : plan->signature;
                hook->argumentCount = observer ? observer->argumentCount : plan->argumentCount;
            }
            hook->address = expected;
            hook->implementation = hook->original = original;
            hook->table = table;
            hook->iid = iid;
            hook->slot = slot;
            hook->interfaceIndex = contract ? static_cast<uint32_t>(contract - catalog.Interfaces()) : UINT32_MAX;
            hook->comObserver = observer;
            additions.push_back(std::move(hook));
        }
        if (additions.empty()) return;
        if (ComMethodCount + additions.size() > ComMethodHooks.size())
            throw std::runtime_error("Capture interface generation limit reached.");
        PrepareExportEntries(additions);
        for (auto& addition : additions)
        {
            auto hook = addition.get();
            hook->api = static_cast<Api>(FixedInterfaceApiStart + ComMethodCount);
            hook->ready.store(true, std::memory_order_release);
            ComMethodHooks[ComMethodCount++].store(addition.release(), std::memory_order_release);
            auto address = table + hook->slot;
            MEMORY_BASIC_INFORMATION information{};
            DWORD protection = 0, ignored = 0;
            if (!VirtualQuery(address, &information, sizeof(information))) continue;
            auto writable = information.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                PAGE_EXECUTE_WRITECOPY) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
            if (!VirtualProtect(address, sizeof(void*), writable, &protection)) continue;
            auto previous = InterlockedCompareExchangePointer(address, hook->entry, hook->address);
            VirtualProtect(address, sizeof(void*), protection, &ignored);
            if (previous == hook->address) methods[hook->slot] = hook;
        }
    }
    catch (...)
    {
        // Allocation failure leaves the object's existing methods callable.
        ActiveTransport->Header()->moduleRefreshError = ERROR_NOT_ENOUGH_MEMORY;
    }
}

void ForgetComMethodModule(HMODULE module, size_t size)
{
    auto base = reinterpret_cast<uintptr_t>(module);
    AcquireSRWLockExclusive(&ComMethodLock);
    std::unique_ptr<SRWLOCK, decltype(&ReleaseSRWLockExclusive)> lock(&ComMethodLock, &ReleaseSRWLockExclusive);
    for (uint32_t index = 0; index < ComMethodCount; ++index)
    {
        auto hook = ComMethodHooks[index].load(std::memory_order_acquire);
        auto table = reinterpret_cast<uintptr_t>(hook->table);
        auto address = reinterpret_cast<uintptr_t>(hook->address);
        auto implementation = reinterpret_cast<uintptr_t>(hook->implementation);
        if ((table >= base && table - base < size) || (address >= base && address - base < size) ||
            (implementation >= base && implementation - base < size))
            hook->retired.store(true, std::memory_order_release);
    }
}

void AddExportHooks(std::vector<HookDefinition>& hooks, const CatalogView& catalog)
{
    RpcMarshalObserver = DetouristObserveRpcMarshaler;
    std::unordered_set<void*> occupied;
    std::unordered_multimap<void*, const char*> compiled;
    std::unordered_set<std::string> builtins;

    // Caller-sensitive loader functions must retain the application's return address.
    std::unordered_set<std::string> special{
        "ExitProcess", "ExitThread", "FreeLibraryAndExitThread", "FatalExit", "FatalAppExitA", "FatalAppExitW",
        "GetProcAddress", "GetProcAddressForCaller", "RaiseFailFastException", "RtlCaptureContext",
        "RtlCaptureStackBackTrace", "RtlGetCallersAddress",
        "RtlRestoreContext", "RtlUnwind", "RtlUnwindEx", "SwitchToFiber", "__chkstk", "_chkstk", "DllMain",
        "TlsCallback", "_CorDllMain", "_CorExeMain", "_CorExeMain2", "_CorImageUnloading", "_CorValidateImage"};
    for (const auto& hook : hooks)
    {
        auto address = DetourCodeFromPointer(*hook.original, nullptr);
        occupied.insert(address);
        if (static_cast<uint32_t>(hook.api) < std::size(ApiDefinitions))
            compiled.emplace(address, Definition(hook.api).name);
    }
    for (const auto& api : ApiDefinitions)
    {
        builtins.insert(std::string(api.module) + "!" + api.name);
        if (api.hookFlags & (HookContinuation | HookProcessTermination | HookDirectInterop)) special.insert(api.name);
    }
    std::unordered_map<std::string, HMODULE> modules;
    auto moduleLess = [](const std::string& left, const std::string& right)
    {
        return _stricmp(left.c_str(), right.c_str()) < 0;
    };
    std::map<std::string, std::vector<std::string>, decltype(moduleLess)> aliases(moduleLess);
    for (uint32_t index = 0; index < catalog.Header()->moduleAliasCount; ++index)
    {
        const auto& entry = catalog.ModuleAliases()[index];
        aliases[catalog.Text(entry.module)].emplace_back(catalog.Text(entry.alias));
    }
    std::unordered_map<HMODULE, std::unordered_map<void*, uint32_t>> addresses;
    std::vector<std::pair<std::string, HMODULE>> providers;
    std::vector<std::unique_ptr<ExportHook>> additions;
    std::unordered_map<HMODULE, std::unordered_set<std::string>> existing;

    // Live generations keep their executable entries across sessions; unloaded images get new definitions.
    for (uint32_t index = 0; index < ExportHookCount; ++index)
    {
        auto hook = ExportHooks[index].load(std::memory_order_acquire);
        if (!hook->retired.load(std::memory_order_acquire) && hook->original)
            existing[hook->module].insert(hook->name);
    }
    auto add = [&](const CatalogPlan& plan, const std::string& library, HMODULE module)
    {
        auto name = catalog.Text(plan.name);
        const auto rpc = RpcDecoderFor(library.c_str(), name);

        // Loader, runtime and continuation entries need policies beyond an ordinary return frame.
        if (!module || module == reinterpret_cast<HMODULE>(&__ImageBase) ||
            !plan.signature.supported || plan.rawTailStart && rpc == RpcDecoder::None || special.contains(name) ||
            strstr(name, "setjmp") || strstr(name, "longjmp") ||
            !_stricmp(library.c_str(), "ntdll.dll") || !_stricmp(library.c_str(), "win32u.dll") ||
            !_strnicmp(library.c_str(), "msvcr", 5) || !_strnicmp(library.c_str(), "vcruntime", 9) ||
            !_strnicmp(library.c_str(), "ucrtbase", 8) || builtins.contains(library + "!" + name) ||
            existing[module].contains(name)) return;
        auto address = GetProcAddress(module, name);
        if (!address && module)
        {
            auto ordinal = catalog.NameOrdinal(library.c_str(), name);
            if (ordinal) address = GetProcAddress(module, MAKEINTRESOURCEA(ordinal));
        }
        if (!address || !ExportCodeAddress(reinterpret_cast<void*>(address))) return;
        auto implementation = DetourCodeFromPointer(reinterpret_cast<void*>(address), nullptr);
        if (!ExportCodeAddress(implementation)) return;

        // API-set aliases keep the existing observer's category, capture rules and lifecycle policies.
        auto [first, last] = compiled.equal_range(implementation);
        for (; first != last; ++first)
            if (!strcmp(first->second, name)) return;
        auto counts = addresses.find(module);
        if (counts == addresses.end()) counts = addresses.emplace(module, ExportAddressCounts(module)).first;
        auto hook = std::make_unique<ExportHook>();
        hook->module = module;
        hook->library = library;
        hook->name = name;
        hook->signature = plan.signature;
        hook->argumentCount = plan.argumentCount;
        hook->ordinal = catalog.NameOrdinal(library.c_str(), name);
        hook->rpc = rpc;
        hook->address = reinterpret_cast<void*>(address);
        hook->implementation = implementation;
        hook->original = reinterpret_cast<void*>(address);
        auto count = counts->second.find(implementation);
        hook->direct = count != counts->second.end() && count->second == 1 &&
            !occupied.contains(implementation) && ExportEntryPatchable(implementation);
        if (hook->direct) occupied.insert(implementation);
        additions.push_back(std::move(hook));
        existing[module].insert(name);
    };
    for (uint32_t index = 0; index < catalog.Header()->exportCount; ++index)
    {
        const auto& plan = catalog.Plans()[index];
        auto library = catalog.Text(plan.module), name = catalog.Text(plan.name);
        if (!plan.signature.supported || plan.rawTailStart && RpcDecoderFor(library, name) == RpcDecoder::None ||
            special.contains(name)) continue;
        if (!strcmp(library, "$image") || strchr(library, '*'))
        {
            if (providers.empty())
            {
                Handle snapshot;
                for (int attempt = 0; attempt < MaxSnapshotAttempts; ++attempt)
                {
                    snapshot.reset(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId()));
                    if (snapshot || GetLastError() != ERROR_BAD_LENGTH) break;
                }
                MODULEENTRY32W entry{sizeof(entry)};
                if (!snapshot || !Module32FirstW(snapshot.get(), &entry))
                    throw std::runtime_error("Cannot inspect capture export providers.");
                do
                {
                    // Retain each exact image throughout inspection, including equal names in different paths.
                    auto module = ResolveHookModule(entry.szExePath);
                    if (!module || module != entry.hModule) continue;
                    auto provider = Utf8(entry.szModule);
                    for (auto& letter : provider) if (letter >= 'A' && letter <= 'Z') letter += 'a' - 'A';
                    providers.emplace_back(std::move(provider), module);
                } while (Module32NextW(snapshot.get(), &entry));
            }
            for (const auto& [provider, module] : providers)
            {
                // An explicit declaration wins even when its ABI is unsupported by fixed hooks.
                if (ExportPlanFor(catalog, provider.c_str(), name) == &plan) add(plan, provider, module);
            }
        }
        else if (library[0] != '$')
        {
            auto found = modules.find(library);
            if (found == modules.end())
                found = modules.emplace(library, ResolveHookModule(Wide(library).c_str())).first;
            add(plan, library, found->second);
            if (auto related = aliases.find(library); related != aliases.end())
                for (const auto& alias : related->second)
                {
                    auto target = modules.find(alias);
                    if (target == modules.end())
                        target = modules.emplace(alias, ResolveHookModule(Wide(alias).c_str())).first;
                    if (target->second && ExportPlanFor(catalog, alias.c_str(), name) == &plan)
                        add(plan, alias, target->second);
                }
        }
    }
    if (additions.empty()) return;
    if (ExportHookCount + additions.size() > ExportHooks.size())
        throw std::runtime_error("Capture export generation limit reached.");
    hooks.reserve(hooks.size() + additions.size());

    PrepareExportEntries(additions);
    for (auto& addition : additions)
    {
        auto hook = addition.get();
        hook->api = static_cast<Api>(FixedExportApiStart + ExportHookCount);
        if (hook->direct)
        {
            hooks.push_back({hook->api, &hook->original, hook->entry});
            auto bucket = (reinterpret_cast<uintptr_t>(hook->implementation) >> 4) % ExportHookAddresses.size();
            for (size_t step = 0; step < ExportHookAddresses.size(); ++step)
            {
                auto& slot = ExportHookAddresses[(bucket + step) % ExportHookAddresses.size()];
                auto previous = slot.load(std::memory_order_acquire);
                if (previous && previous->implementation != hook->implementation &&
                    !previous->retired.load(std::memory_order_acquire)) continue;
                slot.store(hook, std::memory_order_release);
                break;
            }
        }
        ExportHooks[ExportHookCount++].store(addition.release(), std::memory_order_release);
    }
}

void BindExportImports()
{
    if (BroadHooks) return;
    struct ImportHook { void* address; void* entry; };
    std::unordered_multimap<std::string, ImportHook> imports, compiled;
    std::unordered_map<void*, void*> compiledOrdinals;
    for (uint32_t index = 0; index < ExportHookCount; ++index)
    {
        auto hook = ExportHooks[index].load(std::memory_order_acquire);
        if (!hook->direct && hook->ready.load(std::memory_order_acquire) && hook->original &&
            !hook->retired.load(std::memory_order_acquire))
        {
            auto library = hook->library;
            for (auto& letter : library) if (letter >= 'A' && letter <= 'Z') letter += 'a' - 'A';
            ImportHook binding{hook->address, hook->entry};
            imports.emplace(library + "!" + hook->name, binding);
            if (hook->ordinal) imports.emplace(library + "!#" + std::to_string(hook->ordinal), binding);
        }
    }
    std::vector<HookDefinition> unpatched;
    AddUnpatchedWin32Hooks(unpatched);
    for (const auto& hook : unpatched)
    {
        compiled.emplace(Definition(hook.api).name, ImportHook{*hook.original, hook.observer});
        compiledOrdinals.emplace(*hook.original, hook.observer);
    }
    if (imports.empty() && compiled.empty()) return;

    // Import identities select calls whose implementations cannot safely receive a physical detour.
    Handle snapshot;
    for (int attempt = 0; attempt < MaxSnapshotAttempts; ++attempt)
    {
        snapshot.reset(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId()));
        if (snapshot || GetLastError() != ERROR_BAD_LENGTH) break;
    }
    MODULEENTRY32W entry{sizeof(entry)};
    if (!snapshot || !Module32FirstW(snapshot.get(), &entry))
        throw std::runtime_error("Cannot inspect capture import providers.");
    do
    {
        if (entry.hModule == reinterpret_cast<HMODULE>(&__ImageBase)) continue;
        auto module = ResolveHookModule(entry.szExePath);
        if (!module || module != entry.hModule) continue;
        auto base = reinterpret_cast<BYTE*>(module);
        auto bytes = uint64_t{entry.modBaseSize};
        auto read = [&](uint64_t offset, void* destination, size_t count)
        {
            return offset <= bytes && count <= bytes - offset &&
                ReadCaptureMemory(base + offset, destination, count);
        };
        auto name = [&](uint64_t offset) -> std::string
        {
            char text[MaxImportNameBytes]{};
            auto count = static_cast<size_t>(std::min<uint64_t>(sizeof(text), offset < bytes ? bytes - offset : 0));
            if (!count || !read(offset, text, count)) return {};
            auto end = static_cast<const char*>(memchr(text, 0, count));
            return end ? std::string(text, static_cast<size_t>(end - text)) : std::string{};
        };
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS image{};
        if (!read(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
            !read(static_cast<uint32_t>(dos.e_lfanew), &image, sizeof(image)) ||
            image.Signature != IMAGE_NT_SIGNATURE || image.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
            image.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) continue;
        const auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!directory.VirtualAddress ||
            directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) > MaxImportDescriptors) continue;
        for (uint32_t index = 0; index < directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); ++index)
        {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            if (!read(uint64_t{directory.VirtualAddress} + index * sizeof(descriptor), &descriptor,
                sizeof(descriptor)) || !descriptor.Name) break;
            if (!descriptor.FirstThunk || !descriptor.OriginalFirstThunk) continue;
            auto library = name(descriptor.Name);
            for (auto& letter : library) if (letter >= 'A' && letter <= 'Z') letter += 'a' - 'A';
            if (library.empty()) continue;
            library += '!';
            for (uint32_t slot = 0; slot < MaxImportThunks; ++slot)
            {
                IMAGE_THUNK_DATA thunk{};
                auto offset = uint64_t{descriptor.FirstThunk} + slot * sizeof(thunk);
                void* target = nullptr;
                if (!read(uint64_t{descriptor.OriginalFirstThunk} + slot * sizeof(thunk), &thunk, sizeof(thunk)) ||
                    !thunk.u1.AddressOfData || !read(offset, &target, sizeof(target))) break;
                std::string symbol;
                if (IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal))
                    symbol = "#" + std::to_string(IMAGE_ORDINAL(thunk.u1.Ordinal));
                else if (thunk.u1.AddressOfData <= UINT64_MAX - offsetof(IMAGE_IMPORT_BY_NAME, Name))
                    symbol = name(thunk.u1.AddressOfData + offsetof(IMAGE_IMPORT_BY_NAME, Name));
                if (symbol.empty()) continue;
                void* observer = nullptr;
                auto [first, last] = imports.equal_range(library + symbol);
                for (; first != last; ++first)
                {
                    const auto& hook = first->second;
                    if (target == hook.address) { observer = hook.entry; break; }
                }

                // Forwarded Win32 imports use the declared name and exact address to retain their typed adapter.
                if (!observer)
                {
                    auto [begin, end] = compiled.equal_range(symbol);
                    for (; begin != end; ++begin)
                        if (target == begin->second.address) { observer = begin->second.entry; break; }
                }
                if (!observer && IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal))
                {
                    auto found = compiledOrdinals.find(target);
                    if (found != compiledOrdinals.end()) observer = found->second;
                }
                if (!observer) continue;
                auto address = reinterpret_cast<void**>(base + offset);
                if (reinterpret_cast<uintptr_t>(address) % alignof(void*)) continue;

                // Preserve foreign slot changes and the original page protection during atomic publication.
                MEMORY_BASIC_INFORMATION information{};
                DWORD protection = 0, previous = 0;
                if (!VirtualQuery(address, &information, sizeof(information))) continue;
                auto writable = information.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
                if (!VirtualProtect(address, sizeof(void*), writable, &protection)) continue;
                InterlockedCompareExchangePointer(address, observer, target);
                if (!VirtualProtect(address, sizeof(void*), protection, &previous))
                    throw std::runtime_error("Cannot restore capture import protection.");
            }
        }
    } while (Module32NextW(snapshot.get(), &entry));
}

void ActivateExportHooks()
{
    // Named adapters become visible only after the physical patch transaction has finished.
    for (uint32_t index = 0; index < ExportHookCount; ++index)
    {
        auto hook = ExportHooks[index].load(std::memory_order_acquire);
        if (hook->original && !hook->retired.load(std::memory_order_acquire))
            hook->ready.store(true, std::memory_order_release);
    }
    BindExportImports();
}

FARPROC ExportInteropObserver(HMODULE module, LPCSTR name, FARPROC function)
{
    if (BroadHooks || !function) return function;
    auto ordinal = reinterpret_cast<uintptr_t>(name) <= MaxOrdinalValue ?
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(name)) : 0;
    for (auto& entry : ExportHooks)
    {
        auto hook = entry.load(std::memory_order_acquire);
        if (!hook) break;
        if (hook->module != module || !hook->ready.load(std::memory_order_acquire) || !hook->original ||
            hook->retired.load(std::memory_order_acquire)) continue;
        if (ordinal ? hook->ordinal == ordinal && (hook->address == function || hook->implementation == function) :
            hook->name == name)
            return reinterpret_cast<FARPROC>(hook->entry);
    }
    return function;
}

void ForgetExportModule(HMODULE module, size_t size)
{
    auto base = reinterpret_cast<uintptr_t>(module);
    AcquireSRWLockExclusive(&RpcMarshalLock);
    for (uint32_t index = 0; index < RpcMarshalCount; ++index)
    {
        const auto hook = RpcMarshalHooks[index].load(std::memory_order_acquire);
        const auto table = reinterpret_cast<uintptr_t>(hook->table);
        const auto address = reinterpret_cast<uintptr_t>(hook->original);
        if ((table >= base && table - base < size) || (address >= base && address - base < size))
            hook->retired.store(true, std::memory_order_release);
    }
    ReleaseSRWLockExclusive(&RpcMarshalLock);
    for (uint32_t index = 0; index < ExportHookCount; ++index)
    {
        auto hook = ExportHooks[index].load(std::memory_order_acquire);
        auto address = reinterpret_cast<uintptr_t>(hook->address);
        auto implementation = reinterpret_cast<uintptr_t>(hook->implementation);
        if (hook->module == module || (address >= base && address - base < size) ||
            (implementation >= base && implementation - base < size))
            hook->retired.store(true, std::memory_order_release);
    }
}
}

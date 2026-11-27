#include "Agent.h"
#include "CaptureValues.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <system_error>
#include <intrin.h>

extern "C" volatile LONG64 DetouristInternalCallerRanges[Detourist::InternalNativeImageCount * 2];
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace Detourist
{
constexpr uint32_t NtStatusPending = 0x103;
constexpr DWORD BreakpointPollMs = 1;
constexpr DWORD ResumeWaitMs = 50;
constexpr DWORD WorkerPollMs = 20;
constexpr DWORD SettlePollMs = 10;
constexpr size_t MaxRetiredTransports = 8;

[[msvc::no_tls_guard]] constinit thread_local CaptureClock CaptureTime;
SRWLOCK CaptureLock = SRWLOCK_INIT;
Transport* ActiveTransport = nullptr;
[[msvc::no_tls_guard]] constinit thread_local bool ObserverActive = false;
[[msvc::no_tls_guard]] constinit thread_local uint64_t ParentCall = 0;
[[msvc::no_tls_guard]] constinit thread_local uint32_t CallDepth = 0;
[[msvc::no_tls_guard]] constinit thread_local Api CallApi = Api::Count;
[[msvc::no_tls_guard]] constinit thread_local uint64_t CallIdentity = 0;
[[msvc::no_tls_guard]] constinit thread_local bool FollowingChild = false;
std::unique_ptr<Transport> SessionTransport;
std::vector<std::unique_ptr<Transport>> RetiredTransports;
std::atomic<bool> Initializing = false;
std::atomic<bool> WorkerRunning = false;
std::atomic<uint64_t> Installed = 0;
volatile LONG ProcessShuttingDown = 0;
uint32_t InstalledWin32Count = 0;
uint32_t AvailableWin32Count = 0;
uint32_t InstalledComCount = 0;

// Resolve static API purposes before hooks run; admission only reads a cached mask.
std::array<uint64_t, std::size(ApiDefinitions)> KnownCategoryMasks{};
std::array<uint64_t, std::size(ApiDefinitions)> KnownApiNameHashes{};
std::array<AsyncIoRole, std::size(ApiDefinitions)> KnownAsyncRoles{};

bool IsFailure(Api api, uint64_t result)
{
    if (IsManagedApi(api)) return false;
    if (IsWin32uApi(api)) return IsWin32uFailure(api, result);
    if (static_cast<uint32_t>(api) < NativeApiStart || IsWin32Api(api) || IsComApi(api))
        return PublicFailure(api, result);
    if (IsNativeApi(api))
        return NativeReturnsStatus(api) && static_cast<int32_t>(result) < 0;
    return result == 0;
}

void Emit(Call& call, bool leaving, std::span<const std::byte> payload)
{
    auto header = call.transport->Header();
    auto slot = call.transport->Acquire();
    if (!slot) return;
    slot->event = call.event;
    slot->event.kind = leaving ? EventKind::Leave : EventKind::Enter;
    slot->event.timestamp = Clock();
    slot->event.payloadBytes = 0;
    const auto& args = call.event.arguments;
    auto bytes = [&](uint32_t index, uint64_t size, ValueKind kind = ValueKind::Bytes)
    {
        CopyValue(slot, header, index, kind, args[index], size);
    };
    auto text = [&](uint32_t index)
    {
        CopyValue(slot, header, index, ValueKind::Utf16, args[index], header->bufferLimit, {.terminated = true});
    };

    // Capture the defined input and output shapes independently of presentation.
    if (!(call.event.flags & Unwound))
    {
        if (IsNativeApi(call.event.api)) EmitNative(call, slot, leaving);
        else if (IsWin32uApi(call.event.api)) EmitWin32u(call, slot, leaving);
        else if (IsWin32Api(call.event.api) || call.exportPlan) CaptureBuiltinParameters(call, slot, leaving);
        else if (IsComApi(call.event.api)) EmitCom(call, slot, leaving);
    }

    // Profiler snapshots obey the same per-value capture cap and shared queue budget.
    while (payload.size() >= sizeof(Value))
    {
        Value value;
        memcpy(&value, payload.data(), sizeof(value));
        payload = payload.subspan(sizeof(Value));
        if (value.capturedBytes > payload.size()) break;
        auto available = header->payloadCapacity - slot->event.payloadBytes;
        if (available < sizeof(Value)) break;
        auto captured = std::min({value.capturedBytes, header->bufferLimit,
            available - static_cast<uint32_t>(sizeof(Value))});
        auto originalCaptured = value.capturedBytes;
        if (captured < originalCaptured) value.flags |= Truncated;
        value.capturedBytes = captured;
        auto destination = Transport::Payload(slot) + slot->event.payloadBytes;
        memcpy(destination, &value, sizeof(value));
        memcpy(destination + sizeof(Value), payload.data(), captured);
        slot->event.payloadBytes += static_cast<uint32_t>(sizeof(Value)) + captured;
        payload = payload.subspan(originalCaptured);
    }
    if (!leaving)
    {
        switch (call.event.api)
        {
        case Api::CreateFileW: case Api::DeleteFileW: case Api::CreateDirectoryW:
        case Api::RemoveDirectoryW: case Api::GetFileAttributesW: case Api::FindFirstFileExW:
            text(0); break;
        case Api::MoveFileExW: text(0); text(1); break;
        case Api::WriteFile: bytes(1, args[2]); break;
        case Api::RegOpenKeyExW: case Api::RegQueryValueExW: text(1); break;
        case Api::RegCreateKeyExW: text(1); text(3); break;
        case Api::RegSetValueExW: text(1); bytes(4, args[5]); break;
        case Api::CreateProcessW: text(0); text(1); text(7); break;
        default: break;
        }
        CaptureCallStack(call, slot);
    }
    else if (!(call.event.flags & Unwound))
        CaptureCoreOutputs(call.event.api, call.event, call.requestedBytes, static_cast<DWORD>(args[2]), slot, header);
    call.transport->Publish(slot);
}

Call::Call(Api api, std::initializer_list<uint64_t> arguments, void* caller)
    : Call(api, std::span<const uint64_t>(arguments.begin(), arguments.size()), caller)
{
}

Call::Call(Api api, std::span<const uint64_t> arguments, void* caller, std::span<const std::byte> payload,
    uint32_t flags, uint64_t returnedBuffer, RpcCaptureState* rpc) : rpc(rpc), returnBuffer(returnedBuffer)
{
    std::copy_n(arguments.begin(), std::min(arguments.size(), size_t{MaximumArguments}), event.arguments);
    event.api = api;
    event.flags = flags;
    if (api == Api::NtContinue || api == Api::NtContinueEx || api == Api::NtCallbackReturn ||
        api == Api::NtRaiseException || api == Api::NtTerminateThread || api == Api::NtTerminateProcess)
        event.flags |= Continuation;
    if (!NativeThreadReady() || ObserverActive) return;

    // Error helpers can share exported implementations; observer calls must bypass them before reading error state.
    const auto self = reinterpret_cast<uintptr_t>(&__ImageBase);
    const auto address = reinterpret_cast<uintptr_t>(caller);
    const auto image = reinterpret_cast<const IMAGE_NT_HEADERS*>(self + __ImageBase.e_lfanew);
    if (address >= self && address - self < image->OptionalHeader.SizeOfImage)
    {
        internalRuntime = true;
        return;
    }
    auto savedError = GetLastError();
    auto savedStatus = NativeThreadStatus();
    if (api == Api::NtWaitForSingleObject && BroadHooks)
    {
        for (uint32_t index = 0; index < InternalNativeImageCount; ++index)
        {
            auto start = DetouristInternalCallerRanges[index * 2];
            if (start && static_cast<LONG64>(address) >= start &&
                static_cast<LONG64>(address) < DetouristInternalCallerRanges[index * 2 + 1])
            {
                internalRuntime = true;
                return;
            }
        }
    }
    ObserverActive = true;
    if (ParentCall || CaptureTime.depth)
    {
        observation.clock = &CaptureTime;
        observation.Resume(Clock());
    }

    // Admission protects the session pointer until this invocation finishes.
    AcquireSRWLockShared(&CaptureLock);
    auto candidate = ActiveTransport;
    ExportCallInfo exportInfo;
    if (candidate && (IsExportApi(api) || IsInterfaceApi(api)))
    {
        exportInfo = ResolveExportCall(api, *candidate);
        exportPlan = exportInfo.plan;
        if (!exportPlan) candidate = nullptr;
    }
    if (exportPlan && !rpc) asyncRole = exportInfo.asyncRole;
    else if (api < Api::Count) asyncRole = KnownAsyncRoles[static_cast<uint32_t>(api)];
    auto threadId = GetCurrentThreadId();
    auto categoryMask = IsManagedApi(api) ? ManagedApiCategoryMask(api) :
        exportPlan ? exportInfo.categoryMask :
        static_cast<uint32_t>(api) < KnownCategoryMasks.size() ? KnownCategoryMasks[static_cast<uint32_t>(api)] :
        CategoryMask(ApiCategory::Unclassified);
    bool enabled = candidate && FilterEnabled(candidate->Header()->enabledFilters, ApiMask(api), categoryMask);
    if (enabled && candidate->Header()->excludedApiCount)
    {
        const auto hash = IsManagedApi(api) ? ManagedApiNameHash(api) :
            exportPlan ? exportInfo.nameHash :
            static_cast<uint32_t>(api) < KnownApiNameHashes.size() ?
            KnownApiNameHashes[static_cast<uint32_t>(api)] : 0;
        enabled = !ApiExcluded(*candidate->Header(), hash);
    }
    // Retain list lifetimes while recording is paused, without emitting calls or stopping at breakpoints.
    auto mruLifetime = api == Api::CreateMRUListW || api == Api::FreeMRUList;
    const auto asyncObserver = AsyncObserver(asyncRole);

    // COM discovery still follows typed boundaries when the corresponding export events are filtered.
    auto interfacePlan = exportPlan ? exportPlan :
        candidate && IsWin32Api(api) ? candidate->Catalog().BuiltinPlan(api) : nullptr;
    auto exportInterfaces = interfacePlan && (candidate->Header()->enabledFilters & ComApis) &&
        (interfacePlan->interfaceParameters || interfacePlan->resultInterfaceIndex ||
        interfacePlan->signature.interfaceOutputIndex);
    if (candidate && !candidate->Header()->stop &&
        (!candidate->Header()->capturePaused || mruLifetime || asyncObserver) &&
        threadId != static_cast<DWORD>(candidate->Header()->agentThreadId) &&
        threadId != static_cast<DWORD>(candidate->Header()->instructionThreadId) &&
        (enabled || (candidate->Header()->entryBreaks | candidate->Header()->exitBreaks) & ApiMask(api) ||
        mruLifetime || asyncObserver || exportInterfaces ||
        candidate->Header()->entryApi == static_cast<LONG>(api) ||
        candidate->Header()->exitApi == static_cast<LONG>(api) ||
        (CreatesChild(api) && candidate->Header()->followChildren)))
    {
        transport = candidate;
        InterlockedIncrement64(&transport->Header()->activeCalls);
        mruOnly = candidate->Header()->capturePaused != 0;
        record = enabled && !mruOnly;
        if (record) InterlockedIncrement64(&transport->Header()->recordingCalls);
    }
    ReleaseSRWLockShared(&CaptureLock);
    if (transport)
    {
        if (!observation.clock)
        {
            observation.clock = &CaptureTime;
            observation.Resume(Clock());
        }
        auto header = transport->Header();
        event.callId = static_cast<uint64_t>(InterlockedIncrement64(&header->nextCallId));
        event.processId = GetCurrentProcessId();
        event.threadId = threadId;
        event.caller = reinterpret_cast<uint64_t>(caller);
        previousParent = ParentCall;
        previousIdentity = CallIdentity;
        previousDepth = CallDepth;
        previousApi = CallApi;
        event.depth = CallIdentity == header->captureIdentity ? CallDepth : 0;
        event.parentId = CallIdentity == header->captureIdentity ? ParentCall : 0;
        CallIdentity = header->captureIdentity;
        CallApi = api;
        CallDepth = event.depth + 1;
        ParentCall = event.callId;
        if (exportPlan && !PublishExportMetadata(*this)) record = false;
        Break(false);
        if (rpc) ObserveRpcDescriptorEdits(*rpc, arguments.data(), event);
        if (!skipped) ObserveMruCall(api, header->captureIdentity, event, false, mru);
        if (api == Api::RegQueryValueExW) requestedBytes = SafeDword(event.arguments[5]);
        if (record && IsManagedApi(api)) record = PublishManagedApiMetadata(api, transport);

        // A call whose metadata could not be published no longer owes a recorded return.
        if (!record && enabled && !mruOnly) InterlockedDecrement64(&header->recordingCalls);
        if (record && !skipped)
        {
            AsyncCallbackKind kind;
            auto parameter = AsyncCallbackParameter(asyncRole, kind);
            if (parameter != UINT32_MAX && event.arguments[parameter])
            {
                auto original = event.arguments[parameter];
                callbackArgument = DetouristAsyncCallback(header->captureIdentity, original,
                    static_cast<uint32_t>(kind), &event.arguments[parameter]);
                callbackParameter = parameter;
                if (callbackArgument == event.arguments[parameter])
                    InterlockedIncrement64(&header->asyncCallbackErrors);
            }
        }
        if (record) Emit(*this, false, payload);
        if (record && !skipped) BeginAsyncIo(header, event, asyncRole);
    }
    if (!transport) observation.Reset();
    ObserverActive = false;
    SetLastError(savedError);
    RestoreNativeThreadStatus(savedStatus);
}

void SafeDebugBreak()
{
    __try { DebugBreak(); }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {}
}

extern "C" __declspec(dllexport) uint32_t WINAPI DetouristRpcSerializationOperation(uint64_t handle)
{
    return RpcSerializationOperation(handle);
}

// The instruction engine reports serialization handles from exports that no agent hook observes.
extern "C" __declspec(dllexport) void WINAPI DetouristObserveRpcSerialization(uint32_t api, const uint64_t* arguments,
    uint64_t result, BOOL leaving)
{
    if (leaving) ObserveRpcSerialization(static_cast<Api>(api), arguments, result);
    else BeginRpcSerialization(static_cast<Api>(api), arguments);
}

void Call::Break(bool leaving)
{
    if (IsManagedApi(event.api) || mruOnly) return;
    auto header = transport->Header();
    auto mask = leaving ? header->exitBreaks : header->entryBreaks;
    auto exact = leaving ? header->exitApi : header->entryApi;
    bool matches = exact == static_cast<LONG>(event.api) || (mask & ApiMask(event.api));
    if (!matches ||
        header->stop || !header->debuggerActive) return;
    auto& breakpoint = header->breakpoint;

    // Serialize simultaneous hits while the external controller owns process suspension.
    while (InterlockedCompareExchange(&breakpoint.ownerThread, event.threadId, 0) != 0)
    {
        if (header->stop || !transport->CollectorAlive()) return;
        Sleep(BreakpointPollMs);
    }
    mask = leaving ? header->exitBreaks : header->entryBreaks;
    exact = leaving ? header->exitApi : header->entryApi;
    if (exact != static_cast<LONG>(event.api) && !(mask & ApiMask(event.api)))
    {
        InterlockedExchange(&breakpoint.ownerThread, 0);
        return;
    }
    ResetEvent(transport->ResumeEvent());
    breakpoint.event = event;
    breakpoint.phase = static_cast<LONG>(leaving ? BreakpointPhase::Leave : BreakpointPhase::Enter);
    breakpoint.action = static_cast<LONG>(BreakpointAction::Continue);
    InterlockedExchange(&breakpoint.waiting, 1);
    SetEvent(transport->BreakEvent());
    if (header->debuggerActive != CooperativeDebugger &&
        header->instructionState != static_cast<LONG>(InstructionState::Active) &&
        header->instructionState != static_cast<LONG>(InstructionState::Starting)) SafeDebugBreak();
    while (!header->stop && transport->CollectorAlive())
    {
        if (WaitForSingleObject(transport->ResumeEvent(), ResumeWaitMs) == WAIT_OBJECT_0) break;
    }
    if (memcmp(event.arguments, breakpoint.event.arguments, sizeof(event.arguments)) ||
        event.result != breakpoint.event.result || event.error != breakpoint.event.error)
        breakpoint.event.flags |= Edited;
    event = breakpoint.event;
    if (!leaving && breakpoint.action == static_cast<LONG>(BreakpointAction::Skip)) skipped = true;
    InterlockedExchange(&breakpoint.waiting, 0);
    InterlockedExchange(&breakpoint.ownerThread, 0);
}

void Call::BeginInvocation()
{
    if (!observation.clock || skipped) return;
    ObserverScope observer;
    auto now = Clock();
    invocationStarted = observation.clock->ApplicationTime(now);
    invocationRunning = true;
    observation.Pause(now);
}

void Call::EndInvocation()
{
    if (!invocationRunning) return;
    ObserverScope observer;
    auto now = Clock();
    event.adjustedDuration = std::max(int64_t{0}, observation.clock->ApplicationTime(now) - invocationStarted);
    event.flags |= DurationMeasured;
    invocationRunning = false;
    observation.Resume(now);
}

void Call::Finish(uint64_t result, DWORD error, std::span<const std::byte> payload)
{
    if (!skipped) { event.result = result; event.error = error; }
    if (!transport) { finished = true; return; }
    auto savedStatus = NativeThreadStatus();
    ObserverActive = true;
    if (skipped)
    {
        event.flags |= Skipped | DurationMeasured;
        event.adjustedDuration = 0;
    }
    auto failed = [&]()
    {
        return exportPlan ? ExportResultFailed(exportPlan->resultRule, exportPlan->signature.resultBytes,
            event.result, transport->Catalog().SuccessValues(*exportPlan), exportPlan->resultSuccessCount) :
            IsFailure(event.api, event.result);
    };
    if (failed()) event.flags |= Failed;
    if (NativeReturnsStatus(event.api) && event.result == NtStatusPending) event.flags |= AsyncPending;

    // Observe I/O outcomes before return-breakpoint edits change the application's visible result.
    FinishAsyncIo(AsyncSink(*transport), event, asyncRole);
    ObserveMruCall(event.api, transport->Header()->captureIdentity, event, true, mru);
    Break(true);
    if (failed()) event.flags |= Failed;
    else if (!IsManagedApi(event.api)) event.flags &= ~Failed;
    if (event.flags & AsyncPending) event.flags &= ~Failed;
    if (record)
    {
        Emit(*this, true, payload);
        InterlockedDecrement64(&transport->Header()->recordingCalls);
    }
    ParentCall = previousParent;
    CallIdentity = previousIdentity;
    CallDepth = previousDepth;
    CallApi = previousApi;
    InterlockedDecrement64(&transport->Header()->activeCalls);
    ObserverActive = false;
    finished = true;
    RestoreNativeThreadStatus(savedStatus);
}

void Call::ReleaseForContinuation()
{
    if (!transport || skipped) return;

    // Context transfer and process termination can abandon this stack without unwinding it.
    ObserverActive = true;
    event.flags |= Continuation;
    ParentCall = previousParent;
    CallIdentity = previousIdentity;
    CallDepth = previousDepth;
    CallApi = previousApi;
    if (record) InterlockedDecrement64(&transport->Header()->recordingCalls);
    InterlockedDecrement64(&transport->Header()->activeCalls);
    transport = nullptr;
    finished = true;
    auto error = GetLastError();
    auto status = NativeThreadStatus();
    observation.Reset();
    SetLastError(error);
    RestoreNativeThreadStatus(status);
    ObserverActive = false;
}

Call::~Call()
{
    if (!transport || finished)
    {
        if (!observation.active) return;
        ObserverScope observer;
        observation.Reset();
        return;
    }
    auto savedError = GetLastError();
    auto savedStatus = NativeThreadStatus();
    ObserverActive = true;
    event.flags |= Unwound;
    FinishAsyncIo(AsyncSink(*transport), event, asyncRole);
    if (record)
    {
        Emit(*this, true);
        InterlockedDecrement64(&transport->Header()->recordingCalls);
    }
    ParentCall = previousParent;
    CallIdentity = previousIdentity;
    CallDepth = previousDepth;
    CallApi = previousApi;
    InterlockedDecrement64(&transport->Header()->activeCalls);
    observation.Reset();
    ObserverActive = false;
    SetLastError(savedError);
    RestoreNativeThreadStatus(savedStatus);
}

DWORD WINAPI AgentWorker(void*)
{
    ObserverActive = true;
    auto transport = SessionTransport.get();
    auto header = transport->Header();
    header->agentThreadId = static_cast<LONG>(GetCurrentThreadId());
    BroadHooks = header->instructionState == static_cast<LONG>(InstructionState::Active) ||
        header->instructionState == static_cast<LONG>(InstructionState::Starting);
    auto failure = ERROR_SUCCESS;
    try
    {
        for (const auto& definition : ApiDefinitions)
        {
            KnownCategoryMasks[static_cast<uint32_t>(definition.id)] =
                CategoryMask(ClassifyApi(definition.module, definition.name));
            KnownApiNameHashes[static_cast<uint32_t>(definition.id)] = ApiNameHash(definition.name);
            KnownAsyncRoles[static_cast<uint32_t>(definition.id)] = AsyncRole(definition.module, definition.name);
        }
        if (!Installed) Installed = InstallHooks(*transport);
        else if (!BroadHooks)
            Installed.fetch_or(RefreshHooks(transport, true), std::memory_order_relaxed);
        if (!Installed) failure = ERROR_NOT_SUPPORTED;
    }
    catch (const std::system_error& error) { failure = static_cast<DWORD>(error.code().value()); }
    catch (...) { failure = ERROR_GEN_FAILURE; }
    PublishHookCoverage(*header);
    header->error = static_cast<LONG>(failure);
    if (!failure)
    {
        AcquireSRWLockExclusive(&CaptureLock);
        RefreshManagedApiCategories();
        ResetMruCapture(header->captureIdentity);
        transport->Header()->managedState = InterlockedCompareExchange(&ManagedProfilerState, 0, 0);
        BindModuleHistory(header);
        InvalidateStackImageCache();
        ActiveTransport = transport;
        ReleaseSRWLockExclusive(&CaptureLock);
        EnableModuleRefresh();
        ProcessModuleChanges();
    }
    InterlockedExchange(&header->state, static_cast<LONG>(failure ? AgentState::Failed : AgentState::Active));
    SetEvent(transport->ReadyEvent());

    // Close admission before draining calls; pinned hooks become pass-through after detach.
    while (!failure && !header->stop && transport->CollectorAlive())
    {
        ProcessModuleChanges();
        std::erase_if(RetiredTransports, [](const auto& retired)
        {
            return retired->Header()->activeCalls == 0;
        });
        Sleep(WorkerPollMs);
    }
    BindModuleHistory(nullptr);
    AcquireSRWLockExclusive(&CaptureLock);
    ActiveTransport = nullptr;
    InvalidateStackImageCache();
    ReleaseSRWLockExclusive(&CaptureLock);
    ResetMruCapture(0);

    // Recorded returns settle within a window each completion extends; calls without pending records do not delay
    // the stop and keep using the retained mapping until they return.
    constexpr ULONGLONG settleMilliseconds = 250;
    auto pending = header->recordingCalls;
    for (auto settled = GetTickCount64() + settleMilliseconds; !failure && pending > 0 &&
        header->stop < TransportStopped && transport->CollectorAlive() && GetTickCount64() < settled;)
    {
        Sleep(SettlePollMs);
        auto remaining = header->recordingCalls;
        if (remaining < pending) settled = GetTickCount64() + settleMilliseconds;
        pending = remaining;
    }
    InterlockedExchange(&header->state, static_cast<LONG>(failure ? AgentState::Failed : AgentState::Stopped));
    WorkerRunning = false;
    return failure;
}
}

extern "C" __declspec(dllexport) DWORD WINAPI DetouristStart(void* parameter)
{
    using namespace Detourist;
    auto observing = ObserverActive;
    ObserverActive = true;
    auto restoreObserver = [observing](bool* active) { *active = observing; };
    std::unique_ptr<bool, decltype(restoreObserver)> observer(&ObserverActive, restoreObserver);
    auto startup = static_cast<TransportStartup*>(parameter);
    std::unique_ptr<Transport> transport;
    try { transport = std::make_unique<Transport>(*startup); }
    catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
    if (Initializing.exchange(true)) return ERROR_BUSY;
    DWORD result = ERROR_SUCCESS;
    if (!WorkerRunning)
        std::erase_if(RetiredTransports, [](const auto& retired) { return retired->Header()->activeCalls == 0; });
    if (WorkerRunning || RetiredTransports.size() >= MaxRetiredTransports) result = ERROR_BUSY;
    else
    {
        try
        {
            // The observer retains startup access for hook installation and later module refresh transactions.
            HANDLE token = nullptr;
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, FALSE, &token) &&
                GetLastError() != ERROR_NO_TOKEN)
                throw std::system_error(GetLastError(), std::system_category());
            Handle startupToken(token);
            if (!transport->Open(startup->captureIdentity)) result = GetLastError();
            else
            {
                if (SessionTransport && SessionTransport->Header()->activeCalls)
                    RetiredTransports.push_back(std::move(SessionTransport));
                SessionTransport = std::move(transport);
                WorkerRunning = true;
                auto worker = CreateThreadWithToken(GetCurrentProcess(), AgentWorker, nullptr, startupToken.get());
                if (!worker) { result = GetLastError(); WorkerRunning = false; }
            }
        }
        catch (const std::system_error& error) { result = static_cast<DWORD>(error.code().value()); }
        catch (...) { result = ERROR_NOT_ENOUGH_MEMORY; }
    }
    Initializing = false;
    return result;
}

extern "C" __declspec(dllexport) DWORD WINAPI DetouristStartInstructions(void* parameter)
{
    using namespace Detourist;
    ObserverActive = true;
    DWORD result = ERROR_GEN_FAILURE;
    Transport transport;
    try
    {
        std::wstring text(static_cast<const wchar_t*>(parameter));
        auto separator = text.find(L'|');
        auto identitySeparator = separator == std::wstring::npos ? separator : text.find(L'|', separator + 1);
        if (identitySeparator == std::wstring::npos)
        {
            return ERROR_INVALID_PARAMETER;
        }
        auto path = text.substr(0, separator);
        uint64_t mapping = 0, identity = 0;
        if (!ParseTransportNumber(std::wstring_view(text).substr(separator + 1, identitySeparator - separator - 1),
            mapping) || !mapping || mapping > UINTPTR_MAX ||
            !ParseTransportNumber(std::wstring_view(text).substr(identitySeparator + 1), identity) || !identity)
            return ERROR_INVALID_PARAMETER;

        // The bootstrap channel must not replace definitions owned by the resident session mapping.
        if (!transport.Open(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(mapping)), identity, false))
        {
            return GetLastError();
        }
        transport.Header()->instructionThreadId = static_cast<LONG>(GetCurrentThreadId());
        // Keep failed starts resident; a completed detach releases the runtime's complete session state.
        static HMODULE runtime = nullptr;
        static int (*start)() = nullptr;
        static void (*stop)() = nullptr;
        if (!runtime) runtime = LoadLibraryW(path.c_str());
        if (!runtime)
        {
            result = GetLastError();
            transport.Header()->instructionState = static_cast<LONG>(InstructionState::Failed);
            return result;
        }
        if (!start) start = reinterpret_cast<int (*)()>(GetProcAddress(runtime, "dr_app_setup_and_start"));
        if (!stop) stop = reinterpret_cast<void (*)()>(GetProcAddress(runtime, "dr_app_stop_and_cleanup"));
        result = start && stop && EnableNativeGateways(runtime) ? static_cast<DWORD>(start()) : ERROR_PROC_NOT_FOUND;
        if (!result)
        {
            while (!transport.Header()->stop && transport.CollectorAlive()) Sleep(WorkerPollMs);
            DisableNativeGateways();
            stop();
            if (FreeLibrary(runtime))
            {
                runtime = nullptr;
                start = nullptr;
                stop = nullptr;
            }
            else result = GetLastError();
            InterlockedExchange(&transport.Header()->instructionState, static_cast<LONG>(InstructionState::Stopped));
        }
        else
        {
            DisableNativeGateways();
            transport.Header()->instructionState = static_cast<LONG>(InstructionState::Failed);
        }
    }
    catch (...)
    {
        DisableNativeGateways();
        if (transport.Header()) transport.Header()->instructionState = static_cast<LONG>(InstructionState::Failed);
    }
    return result;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void*)
{
    if (reason == DLL_THREAD_DETACH) Detourist::DetachObserverThread();
    if (reason == DLL_PROCESS_DETACH) InterlockedExchange(&Detourist::ProcessShuttingDown, 1);
    if (reason == DLL_PROCESS_ATTACH)
    {
        HMODULE pinned = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(instance), &pinned);
    }
    return TRUE;
}

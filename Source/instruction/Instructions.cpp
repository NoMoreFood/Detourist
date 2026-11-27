#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#include "dr_api.h"
#include "drmgr.h"
#pragma warning(pop)
#include "InstructionCapture.h"
#pragma warning(push, 0)
#include "drwrap.h"
#pragma warning(pop)
#include "TransportPool.h"
#include <atomic>
#include <utility>

namespace Detourist
{
constexpr uint32_t Win32uSyscallBase = 0x1000;
constexpr size_t SyscallTableCapacity = 8192;
constexpr size_t ExtendedSyscallBuckets = 1024;
constexpr size_t MaxSyscallNameBytes = 128;
constexpr uint32_t SpilledComScanLimit = 16;

constinit InstructionChannel InstructionTransport{};
std::array<std::atomic<InstructionDefinition*>, SyscallTableCapacity> InstructionDefinitions{};
std::array<std::atomic<InstructionDefinition*>, SyscallTableCapacity> NativeBoundaries{};
char SyscallNames[SyscallTableCapacity][MaxSyscallNameBytes]{};
uint32_t SyscallNumbers[SyscallTableCapacity]{};
uint8_t SyscallRawCounts[SyscallTableCapacity]{};
bool SyscallContinuations[SyscallTableCapacity]{};
bool SyscallInvalidatesStack[SyscallTableCapacity]{};
AsyncIoRole SyscallAsyncRoles[SyscallTableCapacity]{};

struct ExtendedSyscall
{
    InstructionDefinition definition;
    uint32_t number;
    ExtendedSyscall* next;
};
std::array<std::atomic<ExtendedSyscall*>, ExtendedSyscallBuckets> ExtendedSyscalls{};
uint32_t NextExtendedSyscallApi = SyscallApiStart + static_cast<uint32_t>(InstructionDefinitions.size());
void* DefinitionLock = nullptr;
void* WrapSyncLock = nullptr;
volatile LONGLONG AppliedWrapGeneration = 0;
int ThreadSlot = -1;
int SyscallSlot = -1;
uintptr_t NtdllStart = 0, NtdllEnd = 0, Win32uStart = 0, Win32uEnd = 0;

struct GuardDispatch
{
    app_pc module;
    app_pc slot;
    GuardDispatch* next;
};
GuardDispatch* GuardDispatches = nullptr;

void CopyDescription(wchar_t* output, size_t capacity, const wchar_t* text)
{
    size_t index = 0;
    while (index + 1 < capacity && text[index]) { output[index] = text[index]; ++index; }
    output[index] = 0;
}

uint32_t RawWin32uArguments(const char* name)
{
    for (uint32_t number = Win32uSyscallBase; number < std::size(SyscallNames); ++number)
        if (SyscallRawCounts[number] && !strcmp(SyscallNames[number], name))
            return SyscallRawCounts[number];
    return 0;
}

InstructionDefinition* DefinitionFor(int number)
{
    // Keep normal service lookups in the fixed table; uncommon full-width numbers use immutable sparse entries.
    auto service = static_cast<uint32_t>(number);
#ifndef _WIN64
    service &= 0xFFFF;
#endif
    auto normal = service < InstructionDefinitions.size();
    auto bucket = service % ExtendedSyscalls.size();
    if (normal)
    {
        if (auto value = InstructionDefinitions[service].load(std::memory_order_acquire)) return value;
    }
    else
    {
        for (auto entry = ExtendedSyscalls[bucket].load(std::memory_order_acquire); entry; entry = entry->next)
            if (entry->number == service) return &entry->definition;
    }
    dr_mutex_lock(DefinitionLock);
    auto value = normal ? InstructionDefinitions[service].load(std::memory_order_relaxed) : nullptr;
    if (!normal)
        for (auto entry = ExtendedSyscalls[bucket].load(std::memory_order_relaxed); entry; entry = entry->next)
            if (entry->number == service) { value = &entry->definition; break; }
    if (!value)
    {
        if (!normal && NextExtendedSyscallApi >= ExportApiStart)
        {
            InstructionTransport.Header()->moduleRefreshError = ERROR_TOO_MANY_NAMES;
            dr_mutex_unlock(DefinitionLock);
            return nullptr;
        }
        auto extended = normal ? nullptr : static_cast<ExtendedSyscall*>(dr_global_alloc(sizeof(ExtendedSyscall)));
        auto definition = extended ? &extended->definition :
            static_cast<InstructionDefinition*>(dr_global_alloc(sizeof(InstructionDefinition)));
        memset(definition, 0, sizeof(*definition));
        definition->typed = Api::Count;
        definition->id = static_cast<Api>(normal ? SyscallApiStart + service : NextExtendedSyscallApi++);
        dr_snprintf(definition->metadata.module, std::size(definition->metadata.module), "%s",
            normal ? (service >= Win32uSyscallBase ? "win32u.dll" : "ntdll.dll") : "syscall");
        auto name = normal ? SyscallNames[service] : "";
        if (*name) dr_snprintf(definition->metadata.name, std::size(definition->metadata.name), "%s [syscall]", name);
        else dr_snprintf(definition->metadata.name, std::size(definition->metadata.name), "Syscall %u", service);
        for (const auto& api : ApiDefinitions)
        {
            if (strcmp(name, api.name) || (!IsNativeApi(api.id) && !IsWin32uApi(api.id))) continue;
            definition->typed = api.id;
            definition->known = true;
            definition->metadata.argumentCount = api.argumentCount;
            CopyDescription(
                definition->metadata.parameters, std::size(definition->metadata.parameters), api.parameters);
            break;
        }
        // Direct syscalls use catalog capture plans even when a compiled hook identity is available.
        definition->runtime = RuntimeDefinitionFor(definition->metadata.module, name);
        // A process-information query needs its output buffer sized by the declared capacity argument.
        if (definition->typed == Api::NtQueryInformationProcess && definition->runtime &&
            (!(definition->runtime->parameters[2].flags & 2) ||
                definition->runtime->parameters[2].extentIndex != 3)) definition->runtime = nullptr;
        if (!definition->known)
        {
            auto rawCount = normal ? SyscallRawCounts[service] : 0;
            definition->metadata.argumentCount = definition->runtime ? definition->runtime->argumentCount :
                rawCount ? rawCount : RawArgumentCount;
            CopyDescription(definition->metadata.parameters, std::size(definition->metadata.parameters),
                definition->runtime ? definition->runtime->description :
                    rawCount ? L"Raw native slots; stack extent from win32k; types unknown" :
                        L"Raw syscall argument slots; parameter count, direction and pointee types are unavailable");
        }
        definition->signature = definition->runtime ? definition->runtime->signature : SignatureFor(definition->typed);
        definition->metadata.category = ClassifyApi(definition->metadata.module, name);
        definition->categoryMask = CategoryMask(definition->metadata.category);
        definition->nameHash = ApiNameHash(definition->metadata.name);
        definition->asyncRole = AsyncRole(definition->metadata.module, definition->metadata.name);
        definition->sourceNameHash = *name ? ApiNameHash(name) : definition->nameHash;
        definition->blockingCall = IsBlockingExportName(*name ? name : definition->metadata.name, definition->typed);
        PublishDefinition(*definition);
        value = definition;
        if (normal) InstructionDefinitions[service].store(value, std::memory_order_release);
        else
        {
            extended->number = service;
            extended->next = ExtendedSyscalls[bucket].load(std::memory_order_relaxed);
            ExtendedSyscalls[bucket].store(extended, std::memory_order_release);
        }
    }
    dr_mutex_unlock(DefinitionLock);
    return value;
}

ExportSignature SignatureFor(Api api)
{
#define NATIVE_API(name, status, ...) ExportFunction<__VA_ARGS__>::Signature(),
    static constexpr ExportSignature native[] =
    {
#include "NativeCatalog.inc"
    };
#undef NATIVE_API
#define WIN32U_API(name, failure, ...) ExportFunction<__VA_ARGS__>::Signature(),
    static constexpr ExportSignature win32u[] =
    {
#define WIN32U_UNSUPPORTED(name) ExportSignature{},
#include "Win32uCatalog.inc"
#undef WIN32U_UNSUPPORTED
    };
#undef WIN32U_API
    auto index = static_cast<uint32_t>(api);
    if (IsNativeApi(api)) return native[index - NativeApiStart];
    if (IsWin32uApi(api)) return win32u[index - Win32uApiStart];
    return PublicSignature(api);
}

bool InstructionFailure(Api api, uint64_t result)
{
    if (IsNativeApi(api)) return NativeReturnsStatus(api) && static_cast<int32_t>(result) < 0;
    if (IsWin32uApi(api))
    {
        switch (api)
        {
#define WIN32U_API(name, failure, ...) \
        case Api::name: return ExportResultFailed(static_cast<ExportResultRule>(failure & 255), \
        (failure >> 8) ? (failure >> 8) : 8, result);
#define WIN32U_UNSUPPORTED(name)
#include "Win32uCatalog.inc"
#undef WIN32U_UNSUPPORTED
#undef WIN32U_API
        default: return false;
        }
    }
    return PublicFailure(api, result);
}

void PublishDefinition(InstructionDefinition& definition)
{
    if (auto slot = InstructionTransport.Acquire())
    {
        slot->event = {};
        slot->event.kind = EventKind::ApiMetadata;
        slot->event.api = definition.id;
        slot->event.timestamp = Clock();
        slot->event.processId = static_cast<uint32_t>(dr_get_process_id());
        slot->event.threadId = static_cast<uint32_t>(dr_get_thread_id(dr_get_current_drcontext()));
        slot->event.payloadBytes = sizeof(DynamicApiMetadata);
        memcpy(InstructionChannel::Payload(slot), &definition.metadata, sizeof(DynamicApiMetadata));
        InstructionTransport.Publish(slot);
    }
}

void PublishInstruction(InstructionFrame& call, bool leaving, bool allowDefer)
{
    auto header = call.transport->Header();
    auto context = dr_get_current_drcontext();
    auto thread = context ? static_cast<InstructionThread*>(drmgr_get_tls_field(context, ThreadSlot)) : nullptr;
    Slot* slot = nullptr;
    bool fused = false;
    if (leaving && thread && call.deferredSlot && thread->pendingSlot == call.deferredSlot)
    {
        slot = std::exchange(thread->pendingSlot, nullptr);
        fused = true;
        const auto savedEpoch = slot->event.moduleEpoch;
        slot->inputBytes = slot->event.payloadBytes;
        slot->payloadOffset = slot->inputBytes;
        slot->event = call.event;
        slot->event.moduleEpoch = savedEpoch;
        slot->event.kind = EventKind::Completed;
        slot->event.timestamp = Clock();
        slot->event.payloadBytes = 0;
    }
    else
    {
        slot = call.transport->Acquire();
        if (!slot) return;
        slot->event = call.event;
        slot->event.kind = leaving ? EventKind::Leave : EventKind::Enter;
        slot->event.timestamp = !leaving && call.queryTimestamp ? call.queryTimestamp : Clock();
        slot->event.payloadBytes = 0;
    }
    // Pending operations have no completed output buffers to publish.
    if (!(call.event.flags & Unwound) && !(leaving && (call.event.flags & AsyncPending)))
    {
        auto api = call.definition->typed;
        if (call.definition->marshalOperation)
            CaptureRpcMarshalValues(call.event, slot, header, call.definition->marshalOperation,
                static_cast<uint32_t>(InterlockedCompareExchange(&call.definition->marshalBytes, 0, 0)), leaving);
        else if (call.definition->runtime && call.definition->runtime->IsAviSave())
            CaptureRuntimeAviSave(call, slot, leaving);
        else if (call.definition->runtime && call.definition->runtime->IsAuthzAudit())
            CaptureRuntimeAuthzAudit(call, slot, leaving);
        else if (call.rpc.decoder != RpcDecoder::None)
            CaptureRpcValues(call.rpc, call.event, slot, header, leaving);
        else if (call.definition->runtime)
        {
            // Complete formatter contracts avoid unused tail probes and broad argument-list storage reads.
            auto formatted = CaptureRuntimeFormat(call, slot, leaving);
            CaptureRuntimeParameters(call, slot, leaving, formatted.complete && formatted.listParameter);
            if (!leaving && formatted.complete && !formatted.listParameter)
            {
                call.event.flags = (call.event.flags & ~FormattedArgumentMask) | FormattedArguments |
                    (uint32_t{formatted.argumentCount} << FormattedArgumentShift);
                slot->event.flags = call.event.flags;
                std::copy(std::begin(call.event.arguments), std::end(call.event.arguments), slot->event.arguments);
            }
            auto recognized = formatted.recognized | CaptureRuntimeTraceMessage(call, slot, leaving);
            if (call.definition->runtime->rawTailStart)
            {
                recognized |= CaptureRuntimeBer(call, slot, leaving);
                for (uint32_t index = call.definition->runtime->rawTailStart;
                    index < call.definition->metadata.argumentCount; ++index)
                {
                    if (recognized & (uint32_t{1} << index)) continue;
                    auto address = call.event.arguments[index];
                    if (address >= MinimumUserAddress && address < MaximumUserAddress)
                        CopyValue(slot, header, index, ValueKind::Bytes, address, header->bufferLimit);
                }
            }
        }
        else if (!call.definition->known)
        {
            if (header->rawPointerProbes || call.definition->interfaceTable || call.definition->ambiguousExport)
                for (uint32_t index = 0; index < call.definition->metadata.argumentCount; ++index)
                {
                    auto address = call.event.arguments[index];
                    if (address >= MinimumUserAddress && address < MaximumUserAddress)
                        CopyValue(slot, header, index, ValueKind::Bytes, address, header->bufferLimit);
                }
        }
        else if (IsComApi(api)) CaptureInstructionCom(call, slot, leaving);
        else if ((!IsNativeApi(api) && !IsWin32uApi(api))) CapturePublicParameters(call, slot, leaving);
        else CaptureBuiltinParameters(call, slot, leaving);
    }
    if (!leaving && call.stackCount)
    {
        const auto position = slot->event.payloadBytes;
        CopyValue(slot, header, UINT32_MAX, ValueKind::Stack,
            reinterpret_cast<uint64_t>(call.stack), call.stackCount * sizeof(uint64_t));
        if (slot->event.payloadBytes > position)
        {
            auto value = reinterpret_cast<Value*>(InstructionChannel::Payload(slot) + position);
            value->flags |= call.stackFlags;
            if (value->capturedBytes < sizeof(uint64_t)) call.event.flags |= StackUnavailable;
        }
        else call.event.flags |= StackUnavailable;
        slot->event.flags = call.event.flags;
    }
    if (!leaving && allowDefer && thread && !slot->overflowIndex &&
        !(call.event.flags & (Skipped | Continuation | KernelDispatcher)) &&
        !call.definition->entryOnly && !call.definition->continuation && !call.definition->blockingCall &&
        !call.queryProbe && !call.nativeBoundary && !call.child &&
        call.asyncRole == AsyncIoRole::None && call.rpc.decoder == RpcDecoder::None &&
        !header->debuggerActive && !header->entryBreaks && !header->exitBreaks &&
        header->entryApi < 0 && header->exitApi < 0 && !CreatesChild(call.definition->typed))
    {
        if (auto previous = std::exchange(thread->pendingSlot, nullptr))
            call.transport->Publish(previous);
        StampSlotModuleEpoch(header, slot);
        slot->entryTimestamp = slot->event.timestamp;
        call.deferredSlot = slot;
        thread->pendingSlot = slot;
        return;
    }
    if (fused)
    {
        slot->event.payloadBytes += slot->inputBytes;
        slot->payloadOffset = 0;
    }
    call.transport->Publish(slot);
}

void UnwindSyscalls(InstructionSyscalls& syscalls, uint32_t depth, bool measureDuration = true)
{
    auto context = measureDuration ? dr_get_current_drcontext() : nullptr;
    auto thread = context ? static_cast<InstructionThread*>(drmgr_get_tls_field(context, ThreadSlot)) : nullptr;
    for (uint32_t index = depth; index < syscalls.depth; ++index)
    {
        auto& frame = syscalls.frames[index];
        if (frame.suspended) --syscalls.suspended;
        if (!frame.counted) continue;
        CaptureObservation capture(measureDuration ? ValidFrameClock(thread, frame.clock) : nullptr, Clock());
        if (capture.clock)
        {
            frame.event.adjustedDuration = std::max(int64_t{0}, capture.ApplicationTime() - frame.invocationStarted);
            frame.event.flags |= DurationMeasured;
        }
        if (frame.record)
        {
            frame.event.flags |= Unwound;
            FinishAsyncIo(AsyncSink(*frame.transport), frame.event, frame.asyncRole);
            PublishInstruction(frame, true);
        }
        InterlockedDecrement64(&InstructionTransport.Header()->activeCalls);
    }
    syscalls.depth = depth;
}

bool PublishNativeBoundary(InstructionFrame& frame, bool leaving)
{
    if (!frame.nativeBoundary) return false;
    if ((frame.nativeRecord || InstructionTransport.Header()->entryApi == static_cast<LONG>(frame.nativeBoundary->id) ||
        InstructionTransport.Header()->exitApi == static_cast<LONG>(frame.nativeBoundary->id)) &&
        IsDynamicApi(frame.nativeBoundary->id) && !frame.nativeBoundary->published)
    {
        dr_mutex_lock(DefinitionLock);
        if (!frame.nativeBoundary->published)
        {
            PublishDefinition(*frame.nativeBoundary);
            InterlockedExchange(&frame.nativeBoundary->published, 1);
        }
        dr_mutex_unlock(DefinitionLock);
    }
    auto event = frame.event;
    auto definition = frame.definition;
    auto record = frame.record;
    frame.definition = frame.nativeBoundary;
    frame.record = frame.nativeRecord;
    frame.event.api = frame.definition->id;
    frame.event.callId = frame.nativeCallId;
    frame.event.parentId = frame.nativeParentId;
    frame.event.depth = frame.nativeDepth;
    frame.event.flags = (frame.event.flags & ~Syscall) | frame.nativeFlags;
    bool skip = InstructionBreakpoint(frame, leaving);
    if (skip) frame.event.flags |= Skipped;

    // The boundary shares the syscall's event, so its own edit and skip markers persist from entry to return.
    frame.nativeFlags |= frame.event.flags & (Edited | Skipped);
    if (frame.record) PublishInstruction(frame, leaving, false);
    event.result = frame.event.result;
    event.error = frame.event.error;
    memcpy(event.arguments, frame.event.arguments, sizeof(event.arguments));
    frame.event = event;
    frame.definition = definition;
    frame.record = record;
    return skip;
}

bool PreSyscall(void* context, int number)
{
#ifndef _WIN64
    number &= 0xFFFF;
#endif
    if (NativeStackImageEpoch && static_cast<uint32_t>(number) < std::size(SyscallInvalidatesStack) &&
        SyscallInvalidatesStack[number])
        InterlockedIncrement64(NativeStackImageEpoch);
    auto thread = static_cast<InstructionThread*>(drmgr_get_tls_field(context, ThreadSlot));
    auto syscalls = static_cast<InstructionSyscalls*>(drmgr_get_cls_field(context, SyscallSlot));
    if (!thread || !syscalls) return true;
    if (syscalls->depth && (syscalls->frames[syscalls->depth - 1].event.flags & Continuation))
        UnwindSyscalls(*syscalls, syscalls->depth - 1);
    if (syscalls->depth >= std::size(syscalls->frames))
    {
        ++syscalls->overflow;
        InstructionTransport.Header()->moduleRefreshError = ERROR_STACK_OVERFLOW;
        InstructionTransport.Header()->stop = TransportStopped;
        return true;
    }
    auto& frame = syscalls->frames[syscalls->depth++];
    memset(&frame, 0, sizeof(frame));

    // Nonreturning syscalls must unwind their bookkeeping even when capture filters exclude them.
    bool continuation = number >= 0 && number < static_cast<int>(std::size(SyscallContinuations)) &&
        SyscallContinuations[number];
    if (continuation) frame.event.flags = Continuation;
    auto header = InstructionTransport.Header();
    if (ReadShared64(header->wrapGeneration) != ReadShared64(AppliedWrapGeneration)) SyncExportWraps();
    auto threadId = dr_get_thread_id(context);
    auto asyncRole = number >= 0 && number < static_cast<int>(std::size(SyscallNames)) ?
        SyscallAsyncRoles[number] : AsyncIoRole::None;
    const auto asyncObserver = AsyncObserver(asyncRole);
    if (header->stop || header->capturePaused && !asyncObserver ||
        threadId == static_cast<DWORD>(header->agentThreadId) ||
        threadId == static_cast<DWORD>(header->instructionThreadId)) return true;
    dr_mcontext_t machine{};
    machine.size = sizeof(machine);
    machine.flags = static_cast<dr_mcontext_flags_t>(DR_MC_CONTROL | DR_MC_INTEGER);
    dr_get_mcontext(context, &machine);
    auto site = reinterpret_cast<uintptr_t>(machine.pc);
    frame.event.caller = site;
    frame.stackPointer = machine.xsp;
    ObserverContext observer{};
    if (InstructionObserver(context, thread, site, &observer)) return true;
    CaptureObservation capture(observer.clock ? observer.clock : &thread->clock, Clock());
    frame.clock = capture.clock;
    frame.invocationStarted = capture.ApplicationTime();
    bool direct = site != UINTPTR_MAX && !(site >= NtdllStart && site < NtdllEnd) &&
        !(site >= Win32uStart && site < Win32uEnd);
    auto mask = direct ? DirectSyscalls : number >= static_cast<int>(Win32uSyscallBase) ? Win32uApis : NativeApis;
    auto filters = static_cast<uint64_t>(header->enabledFilters);
    auto record = !header->capturePaused && (filters & mask) != 0;
    bool child = header->followChildren && !(observer.flags & ObserverFollowingChild) && number >= 0 &&
        number < static_cast<int>(std::size(SyscallNames)) &&
        !strcmp(SyscallNames[number], "NtCreateUserProcess");

    // Sparse service identities are published before a selected breakpoint even when capture is disabled.
    auto service = static_cast<uint32_t>(number);
    auto extended = service >= InstructionDefinitions.size();
    auto definition = extended && (IsSyscallApi(static_cast<Api>(header->entryApi)) ||
        IsSyscallApi(static_cast<Api>(header->exitApi))) ? DefinitionFor(number) : nullptr;
    auto expectedApi = definition ? static_cast<uint32_t>(definition->id) : SyscallApiStart + service;
    bool selected = (!extended || definition) && (header->entryApi == static_cast<LONG>(expectedApi) ||
        header->exitApi == static_cast<LONG>(expectedApi));
    if (!record && !child && !asyncObserver && !((header->entryBreaks | header->exitBreaks) & mask) && !selected &&
        !(site >= Win32uStart && site < Win32uEnd &&
            (IsWin32uApi(static_cast<Api>(header->entryApi)) || IsWin32uApi(static_cast<Api>(header->exitApi)) ||
                IsExportApi(static_cast<Api>(header->entryApi)) || IsExportApi(static_cast<Api>(header->exitApi)))))
        return true;
    if (!definition) definition = DefinitionFor(number);
    if (!definition) return true;
    record = !header->capturePaused && FilterEnabled(filters, mask, definition->categoryMask) &&
        !ApiExcluded(*header, definition->nameHash) && !ApiExcluded(*header, definition->sourceNameHash);
    bool breaks = ((header->entryBreaks | header->exitBreaks) & mask) ||
        header->entryApi == static_cast<LONG>(definition->id) || header->exitApi == static_cast<LONG>(definition->id);
    InstructionDefinition* boundary = nullptr;
    if (site >= Win32uStart && site < Win32uEnd && number >= 0 &&
        number < static_cast<int>(std::size(NativeBoundaries)) &&
        (definition->typed == Api::Count || (observer.api != static_cast<uint32_t>(definition->typed) &&
            (!thread->current || thread->current->definition->id != definition->typed))))
    {
        auto& cached = NativeBoundaries[number];
        boundary = cached.load(std::memory_order_acquire);
        if (!boundary && *SyscallNames[number])
        {
            if (definition->typed != Api::Count)
            {
                auto candidate = static_cast<InstructionDefinition*>(dr_global_alloc(sizeof(InstructionDefinition)));
                *candidate = *definition;
                candidate->id = candidate->typed;
                const auto& api = Definition(candidate->id);
                dr_snprintf(candidate->metadata.name, std::size(candidate->metadata.name), "%s", api.name);
                candidate->nameHash = ApiNameHash(api.name);
                candidate->asyncRole = AsyncRole(candidate->metadata.module, candidate->metadata.name);
                if (!cached.compare_exchange_strong(boundary, candidate, std::memory_order_release,
                    std::memory_order_acquire)) dr_global_free(candidate, sizeof(*candidate));
                else boundary = candidate;
            }
            else
            {
                // Export metadata supplies raw or catalog-defined identities without a compiled adapter.
                auto address = dr_get_proc_address(reinterpret_cast<module_handle_t>(Win32uStart),
                    SyscallNames[number]);
                auto candidate = ExportDefinitionAt(reinterpret_cast<void*>(address));
                if (candidate && cached.compare_exchange_strong(boundary, candidate, std::memory_order_release,
                    std::memory_order_acquire)) boundary = candidate;
            }
        }
    }
    bool native = boundary && !boundary->retired && observer.api != static_cast<uint32_t>(boundary->id) &&
        (!thread->current || thread->current->definition->id != boundary->id);
    bool nativeRecord = native && FilterEnabled(filters, Win32uApis, boundary->categoryMask) &&
        !ApiExcluded(*header, boundary->nameHash);
    bool nativeBreaks = native && (((header->entryBreaks | header->exitBreaks) & Win32uApis) ||
        header->entryApi == static_cast<LONG>(boundary->id) || header->exitApi == static_cast<LONG>(boundary->id));
    if (!record && !child && !breaks && !nativeRecord && !nativeBreaks && !asyncObserver) return true;
    FlushThreadPendingSlots(context, *thread);

    // Keep invocation state in runtime-owned memory, independent of the target's allocator and thread locals.
    frame.transport = &InstructionTransport;
    frame.definition = definition;
    frame.mask = mask;
    frame.active = true;
    frame.record = record;
    frame.asyncRole = asyncRole;
    frame.counted = !continuation;
    if (frame.counted) InterlockedIncrement64(&header->activeCalls);
    frame.event.api = definition->id;
    frame.event.callId = static_cast<uint64_t>(InterlockedIncrement64(&header->nextCallId));
    frame.event.processId = static_cast<uint32_t>(dr_get_process_id());
    frame.event.threadId = static_cast<uint32_t>(threadId);
    frame.event.caller = site;
    frame.event.error = ApplicationError(context);
    frame.previousObserver = observer;
    if (observer.captureIdentity == header->captureIdentity)
    {
        frame.event.parentId = observer.parentId;
        frame.event.depth = observer.depth;
    }
    else if (thread->current)
    {
        frame.event.parentId = thread->current->event.callId;
        frame.event.depth = thread->current->event.depth + 1;
    }
    frame.event.flags = Syscall | (header->stackDepth ? StackUnavailable : 0u) |
        (definition->known || definition->runtime && !definition->runtime->rawTailStart ? 0u : RawArguments) |
        (frame.counted ? 0u : Continuation);
    [[maybe_unused]] uint32_t nativeSlot = 0;
    for (uint32_t index = 0; index < definition->metadata.argumentCount; ++index)
    {
        auto bytes = definition->signature.argumentBytes[index];
#ifdef _WIN64
        if (index < 4) frame.event.arguments[index] = dr_syscall_get_param(context, static_cast<int>(index));
        else dr_safe_read(reinterpret_cast<const void*>(machine.xsp + (index + 1ull) * sizeof(uint64_t)),
            sizeof(uint64_t), &frame.event.arguments[index], nullptr);
#else
        frame.event.arguments[index] = dr_syscall_get_param(context, static_cast<int>(nativeSlot++));
        if (bytes == 8)
            frame.event.arguments[index] |= uint64_t{dr_syscall_get_param(context, static_cast<int>(nativeSlot++))}
                                            << 32;
#endif
        if (bytes && bytes < sizeof(uint64_t)) frame.event.arguments[index] &= (uint64_t{1} << (bytes * 8)) - 1;
    }
    // Native callers may bypass drwrap; the provider's syscall callback retains their known export boundary.
    if (native)
    {
        frame.nativeBoundary = boundary;
        frame.nativeRecord = nativeRecord;
        frame.nativeCallId = static_cast<uint64_t>(InterlockedIncrement64(&header->nextCallId));
        frame.nativeParentId = frame.event.parentId;
        frame.nativeDepth = frame.event.depth;
        if (frame.nativeRecord)
        {
            frame.event.parentId = frame.nativeCallId;
            ++frame.event.depth;
        }
    }
    if (record || nativeRecord) CaptureInstructionStack(context, frame, machine, false);
    uint64_t arguments[MaximumArguments];
    memcpy(arguments, frame.event.arguments, sizeof(arguments));
    auto originalError = frame.event.error;
    // A skipped native boundary never issues its syscall, so the syscall is neither recorded nor stopped at.
    bool skip = PublishNativeBoundary(frame, false);
    if (skip) record = frame.record = false;
    else skip = InstructionBreakpoint(frame, false);
    if (originalError != frame.event.error) SetApplicationError(context, frame.event.error);
    nativeSlot = 0;
    for (uint32_t index = 0; index < definition->metadata.argumentCount; ++index)
    {
#ifndef _WIN64
        auto position = nativeSlot;
        nativeSlot += definition->signature.argumentBytes[index] == 8 ? 2u : 1u;
#endif
        if (arguments[index] == frame.event.arguments[index]) continue;
#ifdef _WIN64
        if (index < 4) dr_syscall_set_param(context, static_cast<int>(index), frame.event.arguments[index]);
        else dr_safe_write(reinterpret_cast<void*>(machine.xsp + (index + 1ull) * sizeof(uint64_t)),
            sizeof(uint64_t), &frame.event.arguments[index], nullptr);
#else
        dr_syscall_set_param(context, static_cast<int>(position), static_cast<reg_t>(frame.event.arguments[index]));
        if (definition->signature.argumentBytes[index] == 8)
            dr_syscall_set_param(context, static_cast<int>(position + 1),
                static_cast<reg_t>(frame.event.arguments[index] >> 32));
#endif
    }
    if (!skip && PrepareInstructionChild(frame))
    {
        auto flags = uint64_t{frame.childFlags | 1u};
#ifdef _WIN64
        if (!dr_safe_write(reinterpret_cast<void*>(machine.xsp + (frame.childFlagIndex + 1ull) * sizeof(uint64_t)),
            sizeof(flags), &flags, nullptr)) CompleteInstructionChild(frame, false);
#else
        dr_syscall_set_param(context, static_cast<int>(ExportStackBytes(definition->signature,
            frame.childFlagIndex) / sizeof(void*)), static_cast<reg_t>(flags));
#endif
    }
    if (record && !skip)
    {
        uint32_t parameter;
        auto callback = PrepareAsyncCallback(context, frame, parameter);
        if (callback) dr_syscall_set_param(context, static_cast<int>(parameter), static_cast<reg_t>(callback));
    }
    if (record) PublishInstruction(frame, false, !skip);
    if (record && !skip) BeginAsyncIo(header, frame.event, asyncRole);
    if (skip)
    {
        dr_syscall_set_result(context, static_cast<reg_t>(frame.event.result));
        frame.event.flags |= Skipped | DurationMeasured;
        frame.event.adjustedDuration = 0;
        if (ExportFailure(*definition, frame.event.result)) frame.event.flags |= Failed;
        if (record) PublishInstruction(frame, true);
        PublishNativeBoundary(frame, true);
        if (frame.counted) InterlockedDecrement64(&header->activeCalls);
        --syscalls->depth;
        return false;
    }
    return true;
}

void CompleteSyscall(void* context, InstructionFrame& frame, dr_mcontext_t* resumed = nullptr)
{
    if (!frame.active) return;
    auto thread = static_cast<InstructionThread*>(drmgr_get_tls_field(context, ThreadSlot));
    CaptureObservation capture(ValidFrameClock(thread, frame.clock), Clock());
    if (capture.clock)
    {
        frame.event.adjustedDuration = std::max(int64_t{0}, capture.ApplicationTime() - frame.invocationStarted);
        frame.event.flags |= DurationMeasured;
    }
    frame.event.result = resumed ? resumed->xax : dr_syscall_get_result(context);
    frame.event.error = ApplicationError(context);
    frame.event.flags &= ~Continuation;
    if (ExportFailure(*frame.definition, frame.event.result)) frame.event.flags |= Failed;
    if (NativeReturnsStatus(frame.definition->typed) && frame.event.result == STATUS_PENDING)
        frame.event.flags |= AsyncPending;
    FinishAsyncIo(AsyncSink(*frame.transport), frame.event, frame.asyncRole);
    auto originalResult = frame.event.result;
    auto originalError = frame.event.error;
    InstructionBreakpoint(frame, true);
    if (originalError != frame.event.error) SetApplicationError(context, frame.event.error);
    if (originalResult != frame.event.result)
    {
        if (resumed)
        {
            resumed->xax = static_cast<reg_t>(frame.event.result);
            dr_set_mcontext(context, resumed);
        }
        else dr_syscall_set_result(context, static_cast<reg_t>(frame.event.result));
        if (ExportFailure(*frame.definition, frame.event.result)) frame.event.flags |= Failed;
        else frame.event.flags &= ~Failed;
    }
    CompleteInstructionChild(frame, !(frame.event.flags & Failed));
    if (frame.event.flags & AsyncPending) frame.event.flags &= ~Failed;
    if (frame.record) PublishInstruction(frame, true);
    auto nativeResult = frame.event.result;
    auto nativeError = frame.event.error;
    PublishNativeBoundary(frame, true);
    if (nativeError != frame.event.error) SetApplicationError(context, frame.event.error);
    if (nativeResult != frame.event.result)
    {
        if (resumed) { resumed->xax = static_cast<reg_t>(frame.event.result); dr_set_mcontext(context, resumed); }
        else dr_syscall_set_result(context, static_cast<reg_t>(frame.event.result));
    }
    if (frame.counted) InterlockedDecrement64(&InstructionTransport.Header()->activeCalls);
}

void PostSyscall(void* context, int number)
{
#ifndef _WIN64
    number &= 0xFFFF;
#endif
    if (NativeStackImageEpoch && static_cast<uint32_t>(number) < std::size(SyscallInvalidatesStack) &&
        SyscallInvalidatesStack[number])
        InterlockedIncrement64(NativeStackImageEpoch);
    auto syscalls = static_cast<InstructionSyscalls*>(drmgr_get_cls_field(context, SyscallSlot));
    if (!syscalls) return;
    if (syscalls->overflow) { --syscalls->overflow; return; }
    if (!syscalls->depth) return;
    auto& frame = syscalls->frames[--syscalls->depth];
    if (frame.suspended) --syscalls->suspended;
    CompleteSyscall(context, frame);
}

void SyscallInterrupted(void* context, const dr_kernel_xfer_info_t* transfer)
{
    if (transfer->type != DR_XFER_APC_DISPATCHER || !transfer->source_mcontext) return;
    if (auto thread = static_cast<InstructionThread*>(drmgr_get_tls_field(context, ThreadSlot)))
        FlushThreadPendingSlots(context, *thread);
    auto syscalls = static_cast<InstructionSyscalls*>(drmgr_get_cls_field(context, SyscallSlot));
    if (!syscalls) return;
    auto& source = *transfer->source_mcontext;
    for (uint32_t index = syscalls->depth; index-- > 0;)
    {
        auto& frame = syscalls->frames[index];
        if (frame.event.caller != reinterpret_cast<uintptr_t>(source.pc) || frame.stackPointer != source.xsp)
            continue;
        if (!frame.suspended) { frame.suspended = true; ++syscalls->suspended; }
        break;
    }
}

void SyscallResumed(uintptr_t site)
{
    auto context = dr_get_current_drcontext();
    auto syscalls = static_cast<InstructionSyscalls*>(drmgr_get_cls_field(context, SyscallSlot));
    if (!syscalls || !syscalls->suspended) return;
    dr_mcontext_t machine{};
    machine.size = sizeof(machine);
    machine.flags = static_cast<dr_mcontext_flags_t>(DR_MC_CONTROL | DR_MC_INTEGER);
    if (!dr_get_mcontext(context, &machine)) return;
    for (uint32_t index = syscalls->depth; index-- > 0;)
    {
        auto& frame = syscalls->frames[index];
        if (!frame.suspended || frame.event.caller != site || frame.stackPointer != machine.xsp) continue;
        UnwindSyscalls(*syscalls, index + 1);
        --syscalls->depth;
        --syscalls->suspended;
        CompleteSyscall(context, frame, &machine);
        break;
    }
}

uint32_t SpilledComSlot(instr_t* call, opnd_t target)
{
    // Follow only local pointer copies; shared implementations require the actual loaded vtable slot.
    uint32_t remaining = SpilledComScanLimit;
    for (auto previous = instr_get_prev_app(call); previous && remaining--; previous = instr_get_prev_app(previous))
    {
        if (instr_is_cti(previous)) break;
        if (opnd_is_base_disp(target) &&
            instr_writes_to_reg(previous, opnd_get_base(target), DR_QUERY_DEFAULT)) break;
        const bool writes = opnd_is_reg(target) ?
            instr_writes_to_reg(previous, opnd_get_reg(target), DR_QUERY_DEFAULT) : instr_writes_memory(previous);
        if (!writes) continue;
        if (!instr_is_mov(previous) || instr_num_dsts(previous) != 1 || instr_num_srcs(previous) != 1 ||
            !opnd_same(instr_get_dst(previous, 0), target)) break;
        target = instr_get_src(previous, 0);
        if (opnd_size_in_bytes(opnd_get_size(target)) != sizeof(void*)) break;
        if (opnd_is_reg(target)) continue;
        if (!opnd_is_base_disp(target) || opnd_get_index(target) != DR_REG_NULL) break;
        const auto base = opnd_get_base(target);
        if (base == DR_REG_XSP || base == DR_REG_XBP) continue;
        const auto offset = opnd_get_disp(target);
        if (base != DR_REG_NULL && offset >= static_cast<int>(UnknownSlotCount * sizeof(void*)) &&
            offset % sizeof(void*) == 0 && offset / sizeof(void*) < MaxComVtableSlots)
            return static_cast<uint32_t>(offset / sizeof(void*));
        break;
    }
    return UINT32_MAX;
}

bool StaticIndirectTarget(instr_t* call, opnd_t target)
{
    // Static import slots in image data cannot hold a receiver-dependent COM vtable method pointer.
    uint32_t remaining = SpilledComScanLimit;
    for (auto previous = instr_get_prev_app(call); previous && remaining--; previous = instr_get_prev_app(previous))
    {
        if (instr_is_cti(previous)) break;
        if (opnd_is_base_disp(target) &&
            instr_writes_to_reg(previous, opnd_get_base(target), DR_QUERY_DEFAULT)) break;
        const bool writes = opnd_is_reg(target) ?
            instr_writes_to_reg(previous, opnd_get_reg(target), DR_QUERY_DEFAULT) : instr_writes_memory(previous);
        if (!writes) continue;
        if (!instr_is_mov(previous) || instr_num_dsts(previous) != 1 || instr_num_srcs(previous) != 1 ||
            !opnd_same(instr_get_dst(previous, 0), target)) break;
        target = instr_get_src(previous, 0);
        if (opnd_size_in_bytes(opnd_get_size(target)) != sizeof(void*)) break;
        if (InstructionStaticAddress(target)) return true;
        if (opnd_is_reg(target)) continue;
        if (!opnd_is_base_disp(target) || opnd_get_index(target) != DR_REG_NULL) break;
        const auto base = opnd_get_base(target);
        if (base == DR_REG_XSP || base == DR_REG_XBP) continue;
        break;
    }
    return false;
}

dr_emit_flags_t InstrumentInstruction(void* context, void* tag, instrlist_t* instructions,
    instr_t* instruction, bool, bool, void*)
{
    if (!instr_is_app(instruction)) return DR_EMIT_DEFAULT;

    // Resolve guarded dispatch during translation; the application's guard still checks the real call target.
    if (instr_is_call_indirect(instruction) || instr_get_opcode(instruction) == OP_jmp_ind)
    {
        auto target = instr_get_target(instruction);
#ifdef _WIN64
        const opnd_t arguments[]{opnd_create_reg(DR_REG_XCX), opnd_create_reg(DR_REG_XDX), opnd_create_reg(DR_REG_R8)};
#else
        const auto offset = instr_is_call_indirect(instruction) ? 0 : static_cast<int>(sizeof(void*));
        const opnd_t arguments[]{OPND_CREATE_MEMPTR(DR_REG_XSP, offset),
            OPND_CREATE_MEMPTR(DR_REG_XSP, offset + 4), OPND_CREATE_MEMPTR(DR_REG_XSP, offset + 8)};
#endif
        if (InstructionStaticAddress(target))
        {
            auto slot = static_cast<app_pc>(opnd_get_addr(target));
            dr_mutex_lock(DefinitionLock);
            for (auto dispatch = GuardDispatches; dispatch; dispatch = dispatch->next)
            {
                if (dispatch->slot != slot) continue;
                target = opnd_create_reg(DR_REG_XAX);
                break;
            }
            dr_mutex_unlock(DefinitionLock);
        }

        const bool stackTarget = opnd_is_base_disp(target) && opnd_get_index(target) == DR_REG_NULL &&
            (opnd_get_base(target) == DR_REG_XSP || opnd_get_base(target) == DR_REG_XBP);
        const bool copied = opnd_is_reg(target) || stackTarget;
        const bool staticTarget = copied && StaticIndirectTarget(instruction, target);

        // Observe derived dispatch only when its receiver belongs to an established COM table.
        if (!staticTarget && (copied || (opnd_is_base_disp(target) &&
            opnd_get_base(target) != DR_REG_NULL && opnd_get_index(target) == DR_REG_NULL &&
            opnd_get_disp(target) >= static_cast<int>(UnknownSlotCount * sizeof(void*)) &&
            opnd_get_disp(target) % sizeof(void*) == 0 &&
            opnd_get_disp(target) / sizeof(void*) < MaxComVtableSlots)))
        {
            auto skip = INSTR_CREATE_label(context), done = INSTR_CREATE_label(context);
            dr_save_arith_flags(context, instructions, instruction, SPILL_SLOT_2);
            instrlist_meta_preinsert(instructions, instruction, INSTR_CREATE_test(context,
                OPND_CREATE_ABSMEM(const_cast<LONGLONG*>(&InstructionTransport.Header()->enabledFilters), OPSZ_4),
                OPND_CREATE_INT32(static_cast<int>(ComApis))));
            instrlist_meta_preinsert(instructions, instruction,
                INSTR_CREATE_jcc(context, OP_jz, opnd_create_instr(skip)));
            if (copied)
            {
                instrlist_meta_preinsert(instructions, instruction, INSTR_CREATE_cmp(context,
                    OPND_CREATE_ABSMEM(const_cast<LONG*>(&ObservedComActive), OPSZ_4),
                    OPND_CREATE_INT32(0)));
                instrlist_meta_preinsert(instructions, instruction,
                    INSTR_CREATE_jcc(context, OP_jz, opnd_create_instr(skip)));
            }
            instrlist_meta_preinsert(instructions, instruction,
                INSTR_CREATE_cmp(context, arguments[0], OPND_CREATE_INT32(static_cast<int32_t>(MinimumUserAddress))));
            instrlist_meta_preinsert(instructions, instruction,
                INSTR_CREATE_jcc(context, OP_jb, opnd_create_instr(skip)));
            dr_restore_arith_flags(context, instructions, instruction, SPILL_SLOT_2);
            auto base = copied ? OPND_CREATE_INTPTR(0) : opnd_create_reg(opnd_get_base(target));
            auto slot = copied ? SpilledComSlot(instruction, target) :
                static_cast<uint32_t>(opnd_get_disp(target) / sizeof(void*));
            auto site = instr_get_app_pc(instruction);
            auto caller = instr_is_call_indirect(instruction) && site ?
                site + instr_length(context, instruction) : nullptr;
            dr_insert_clean_call_ex(context, instructions, instruction,
                reinterpret_cast<void*>(&DiscoverComCall), DR_CLEANCALL_MULTIPATH,
                5, target, arguments[0], base, OPND_CREATE_INT32(static_cast<int32_t>(slot)), OPND_CREATE_INTPTR(caller));
            instrlist_meta_preinsert(instructions, instruction, INSTR_CREATE_jmp(context, opnd_create_instr(done)));
            instrlist_meta_preinsert(instructions, instruction, skip);
            dr_restore_arith_flags(context, instructions, instruction, SPILL_SLOT_2);
            instrlist_meta_preinsert(instructions, instruction, done);
        }

        // Inspect register, spilled and first-slot calls; static import slots need no runtime probe.
        if (!staticTarget && (copied || (opnd_is_base_disp(target) &&
            opnd_get_base(target) != DR_REG_NULL &&
            opnd_get_index(target) == DR_REG_NULL && opnd_get_disp(target) == 0)))
        {
            auto skip = INSTR_CREATE_label(context), done = INSTR_CREATE_label(context);
            dr_save_arith_flags(context, instructions, instruction, SPILL_SLOT_2);
            instrlist_meta_preinsert(instructions, instruction, INSTR_CREATE_test(context,
                OPND_CREATE_ABSMEM(const_cast<LONGLONG*>(&InstructionTransport.Header()->enabledFilters), OPSZ_4),
                OPND_CREATE_INT32(static_cast<int>(ComApis))));
            instrlist_meta_preinsert(instructions, instruction,
                INSTR_CREATE_jcc(context, OP_jz, opnd_create_instr(skip)));
            for (auto argument : arguments)
            {
                instrlist_meta_preinsert(instructions, instruction,
                    INSTR_CREATE_cmp(context, argument, OPND_CREATE_INT32(static_cast<int32_t>(MinimumUserAddress))));
                instrlist_meta_preinsert(instructions, instruction,
                    INSTR_CREATE_jcc(context, OP_jb, opnd_create_instr(skip)));
            }
            dr_restore_arith_flags(context, instructions, instruction, SPILL_SLOT_2);
            dr_insert_clean_call_ex(context, instructions, instruction,
                reinterpret_cast<void*>(&DiscoverQueryInterface), DR_CLEANCALL_MULTIPATH,
                4, target, arguments[0], arguments[1], arguments[2]);
            instrlist_meta_preinsert(instructions, instruction, INSTR_CREATE_jmp(context, opnd_create_instr(done)));
            instrlist_meta_preinsert(instructions, instruction, skip);
            dr_restore_arith_flags(context, instructions, instruction, SPILL_SLOT_2);
            instrlist_meta_preinsert(instructions, instruction, done);
        }
    }
    auto site = instr_get_app_pc(instruction);
    if (site != static_cast<app_pc>(tag)) return DR_EMIT_DEFAULT;
    BYTE opcode[2]{};
    if (!dr_safe_read(site - 2, sizeof(opcode), opcode, nullptr) ||
        !((opcode[0] == 0x0F && opcode[1] == 0x05) || (opcode[0] == 0xCD && opcode[1] == 0x2E)))
        return DR_EMIT_DEFAULT;

    // Runtime-managed saves preserve application state during asynchronous context inspection and APC returns.
    dr_insert_clean_call_ex(context, instructions, instruction, reinterpret_cast<void*>(&SyscallResumed),
        static_cast<dr_cleancall_save_t>(DR_CLEANCALL_READS_APP_CONTEXT | DR_CLEANCALL_WRITES_APP_CONTEXT),
        1, OPND_CREATE_INTPTR(site));
    return DR_EMIT_DEFAULT;
}

void SyscallContextStarted(void* context, bool newDepth)
{
    if (!newDepth) return;

    // Windows callbacks interrupt pending syscalls; each callback depth keeps its own return state.
    auto syscalls = static_cast<InstructionSyscalls*>(dr_thread_alloc(context, sizeof(InstructionSyscalls)));
    memset(syscalls, 0, sizeof(*syscalls));
    syscalls->parent = static_cast<InstructionSyscalls*>(drmgr_get_parent_cls_field(context, SyscallSlot));
    drmgr_set_cls_field(context, SyscallSlot, syscalls);
}

void SyscallContextEnded(void* context, bool threadExit)
{
    auto syscalls = static_cast<InstructionSyscalls*>(drmgr_get_cls_field(context, SyscallSlot));
    if (!syscalls) return;

    // Thread exit releases thread-owned clocks before callback-local frames.
    UnwindSyscalls(*syscalls, 0, !threadExit);
    syscalls->overflow = 0;
    if (threadExit) dr_thread_free(context, syscalls, sizeof(*syscalls));
}

void ThreadStarted(void* context)
{
    auto thread = static_cast<InstructionThread*>(dr_thread_alloc(context, sizeof(InstructionThread)));
    memset(thread, 0, sizeof(*thread));
    drmgr_set_tls_field(context, ThreadSlot, thread);
}
void ThreadEnded(void* context)
{
    auto thread = static_cast<InstructionThread*>(drmgr_get_tls_field(context, ThreadSlot));
    if (!thread) return;
    if (thread->observerBound && thread->observer.slotGeneration)
    {
        auto expected = thread->observer.expectedGeneration;
        thread->observer.slotGeneration->compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
    }
    EndExportThread(context, *thread);
    dr_thread_free(context, thread, sizeof(*thread));
}
void ModuleLoaded(void*, const module_data_t* module, bool)
{
    // Remember each image's guard dispatch slot once, outside the application's execution path.
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS image{};
    auto extent = static_cast<uint64_t>(module->end - module->start);
    constexpr auto configBytes = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardCFDispatchFunctionPointer) +
        sizeof(IMAGE_LOAD_CONFIG_DIRECTORY::GuardCFDispatchFunctionPointer);
    IMAGE_LOAD_CONFIG_DIRECTORY config{};
    if (ReadCaptureMemory(module->start, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        dos.e_lfanew > 0 && uint64_t{static_cast<uint32_t>(dos.e_lfanew)} + sizeof(image) <= extent &&
        ReadCaptureMemory(module->start + dos.e_lfanew, &image, sizeof(image)) &&
        image.Signature == IMAGE_NT_SIGNATURE && image.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC &&
        image.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
    {
        const auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (directory.VirtualAddress && directory.Size >= configBytes &&
            uint64_t{directory.VirtualAddress} + configBytes <= extent &&
            ReadCaptureMemory(module->start + directory.VirtualAddress, &config, configBytes) &&
            config.Size >= configBytes && config.GuardCFDispatchFunctionPointer >=
                reinterpret_cast<uint64_t>(module->start) && config.GuardCFDispatchFunctionPointer <=
                reinterpret_cast<uint64_t>(module->end) - sizeof(void*))
        {
            dr_mutex_lock(DefinitionLock);
            auto existing = GuardDispatches;
            while (existing && existing->module != module->start) existing = existing->next;
            if (!existing)
            {
                auto dispatch = static_cast<GuardDispatch*>(dr_global_alloc(sizeof(GuardDispatch)));
                *dispatch = {module->start, reinterpret_cast<app_pc>(config.GuardCFDispatchFunctionPointer),
                    GuardDispatches};
                GuardDispatches = dispatch;
            }
            dr_mutex_unlock(DefinitionLock);
        }
    }
    const auto name = dr_module_preferred_name(module);
    ObserverModule(module);
    DiscoverExports(module);
    if (!name) return;
    if (!_stricmp(name, "ntdll.dll") && !NtdllStart)
    {
        NtdllStart = reinterpret_cast<uintptr_t>(module->start);
        NtdllEnd = reinterpret_cast<uintptr_t>(module->end);
    }
    if (!_stricmp(name, "win32u.dll") && !Win32uStart)
    {
        Win32uStart = reinterpret_cast<uintptr_t>(module->start);
        Win32uEnd = reinterpret_cast<uintptr_t>(module->end);
    }
}
void ModuleUnloaded(void*, const module_data_t* module)
{
    ForgetComTables(module);
    ForgetInstructionImports(module);
    // Remove slots before an unloaded image's addresses can be reused by an unrelated image.
    dr_mutex_lock(DefinitionLock);
    for (auto current = &GuardDispatches; *current;)
    {
        auto dispatch = *current;
        if (dispatch->module != module->start)
        {
            current = &dispatch->next;
            continue;
        }
        *current = dispatch->next;
        dr_global_free(dispatch, sizeof(*dispatch));
    }
    dr_mutex_unlock(DefinitionLock);
}

void InstructionExit()
{
    ResetMruCapture(0);
    InterlockedExchange(&ObservedComActive, 0);
    while (GuardDispatches)
    {
        auto dispatch = GuardDispatches;
        GuardDispatches = dispatch->next;
        dr_global_free(dispatch, sizeof(*dispatch));
    }
    InstructionTransport.Header()->instructionState = static_cast<LONG>(InstructionState::Stopping);
    for (auto& value : InstructionDefinitions)
        if (auto definition = value.load(std::memory_order_relaxed)) dr_global_free(definition, sizeof(*definition));

    for (auto& bucket : ExtendedSyscalls)
    {
        auto entry = bucket.load(std::memory_order_relaxed);
        while (entry)
        {
            auto next = entry->next;
            dr_global_free(entry, sizeof(*entry));
            entry = next;
        }
    }

    // Export entries belong to the export table; this cache owns only synthesized adapter definitions.
    for (auto& value : NativeBoundaries)
        if (auto definition = value.load(std::memory_order_relaxed); definition && !definition->address)
            dr_global_free(definition, sizeof(*definition));
    drwrap_exit();
    FreeExports();
    FreeInstructionImports();
    FreeCaptureCatalog();
    drmgr_exit();
    dr_mutex_destroy(WrapSyncLock);
    dr_mutex_destroy(DefinitionLock);
    InstructionTransport.Close();
}
}

DR_EXPORT void dr_client_main(client_id_t, int argc, const char* argv[])
{
    using namespace Detourist;
    uint64_t mapping = 0, identity = 0;
    if (argc != 4 || !ParseTransportNumber(std::string_view(argv[1]), mapping) || !mapping || mapping > UINTPTR_MAX ||
        !ParseTransportNumber(std::string_view(argv[2]), identity) || !identity) return;
    if (!InstructionTransport.Open(mapping, identity))
    {
        InstructionTransport.Close();
        return;
    }
    auto header = InstructionTransport.Header();
    DefinitionLock = dr_mutex_create();
    WrapSyncLock = dr_mutex_create();
    ResetMruCapture(header->captureIdentity);
    if (!drmgr_init() || !drwrap_init())
    {
        header->instructionState = static_cast<LONG>(InstructionState::Failed);
        return;
    }
    // Guard stale return slots after fiber deletion; ABI capture does not need nonparameter SIMD snapshots.
    drwrap_set_global_flags(static_cast<drwrap_global_flags_t>(DRWRAP_FAST_CLEANCALLS | DRWRAP_SAFE_READ_RETADDR));
    InitializeCaptureCatalog();
    InitializeExports();
    auto file = dr_open_file(argv[3], DR_FILE_READ);
    if (file != INVALID_FILE)
    {
        uint64 fileBytes = 0;
        dr_file_size(file, &fileBytes);
        auto bytes = static_cast<size_t>(fileBytes) + 1;
        auto text = static_cast<char*>(dr_global_alloc(bytes));
        memset(text, 0, bytes);
        dr_read_file(file, text, bytes - 1);
        dr_close_file(file);
        char* line = text;
        while (line && *line)
        {
            auto end = strchr(line, '\n');
            if (end) *end++ = 0;
            auto separator = strchr(line, '=');
            if (separator && *line == 'N' && line[1] == 't')
            {
                uint32_t number = 0;
                auto digit = separator + 1;
                if (digit[0] == '0' && digit[1] == 'x') digit += 2;
                while ((*digit >= '0' && *digit <= '9') || (*digit >= 'a' && *digit <= 'f'))
                {
                    number = number * 16 + (*digit <= '9' ? *digit - '0' : *digit - 'a' + 10);
                    ++digit;
                }
                *separator = 0;
                auto nativeNumber = number;
#ifndef _WIN64
                number &= 0xFFFF;
#endif
                if (number < std::size(SyscallNames))
                {
                    SyscallNumbers[number] = nativeNumber;
                    dr_snprintf(SyscallNames[number], MaxSyscallNameBytes, "%s", line);
                    if (!strncmp(digit, "|stack=", 7))
                    {
                        digit += 7;
                        uint32_t stack = 0;
                        bool valid = *digit >= '0' && *digit <= '9';
                        while (*digit >= '0' && *digit <= '9' && stack <= MaximumArguments * 4)
                        {
                            stack = stack * 10 + *digit - '0';
                            ++digit;
                        }
                        if (valid && (!*digit || *digit == '\r') && stack % 4 == 0 &&
                            stack <= (MaximumArguments - 4) * 4 && number >= Win32uSyscallBase)
                            SyscallRawCounts[number] = static_cast<uint8_t>(4 + stack / 4);
                    }
                    SyscallContinuations[number] = !strcmp(line, "NtContinue") || !strcmp(line, "NtContinueEx") ||
                        !strcmp(line, "NtCallbackReturn") || !strcmp(line, "NtRaiseException") ||
                        !strcmp(line, "NtTerminateProcess") || !strcmp(line, "NtTerminateThread");
                    SyscallInvalidatesStack[number] = !strcmp(line, "NtProtectVirtualMemory") ||
                        !strcmp(line, "NtFreeVirtualMemory") || !strcmp(line, "NtUnmapViewOfSection") ||
                        !strcmp(line, "NtUnmapViewOfSectionEx");
                }
            }
            line = end;
        }
        dr_global_free(text, bytes);
    }
    // Native managed transitions share capture plans and syscall callbacks with cached instructions.
    for (uint32_t number = 0; number < std::size(SyscallNames); ++number)
    {
        auto name = SyscallNames[number];
        SyscallAsyncRoles[number] = AsyncRole("ntdll.dll", name);
        // The native wait trampoline is unsafe during CLR startup; translated calls remain observable.
        if (!*name || SyscallContinuations[number] || !strcmp(name, "NtWaitForSingleObject")) continue;
        auto module = number >= Win32uSyscallBase ? "win32u.dll" : "ntdll.dll";
        auto typed = FindExportType(module, name);
        auto runtime = RuntimeDefinitionFor(module, name);
        auto count = runtime ? runtime->argumentCount : typed != Api::Count ?
            Definition(typed).argumentCount : SyscallRawCounts[number] ?
                SyscallRawCounts[number] : RawArgumentCount;
#ifndef _WIN64
        const auto signature = runtime ? runtime->signature : SignatureFor(typed);
        if (signature.supported) count = ExportStackBytes(signature, count) / sizeof(void*);
#endif
        if (!dr_syscall_intercept_natively(name, static_cast<int>(SyscallNumbers[number]), static_cast<int>(count), 0))
            header->moduleRefreshError = ERROR_NOT_SUPPORTED;
    }
    ThreadSlot = drmgr_register_tls_field();
    SyscallSlot = drmgr_register_cls_field(&SyscallContextStarted, &SyscallContextEnded);
    if (ThreadSlot < 0 || SyscallSlot < 0)
    {
        header->instructionState = static_cast<LONG>(InstructionState::Failed);
        return;
    }
    drmgr_register_thread_init_event(&ThreadStarted);
    drmgr_register_thread_exit_event(&ThreadEnded);
    drmgr_register_module_load_event(&ModuleLoaded);
    drmgr_register_module_unload_event(&ModuleUnloaded);
    drmgr_register_module_unload_event([](void*, const module_data_t* module) { RemoveExports(module); });
    dr_register_filter_syscall_event([](void*, int) { return true; });
    drmgr_register_pre_syscall_event(&PreSyscall);
    drmgr_register_post_syscall_event(&PostSyscall);

    // Publish readiness after the runtime installs native hooks and takes over application threads.
    if (!dr_register_post_attach_event([]()
    {
        InterlockedExchange(&InstructionTransport.Header()->instructionState,
            static_cast<LONG>(InstructionState::Active));
    }) || !drmgr_register_kernel_xfer_event(&SyscallInterrupted) ||
        !drmgr_register_bb_instrumentation_event(nullptr, &InstrumentInstruction, nullptr))
    {
        header->instructionState = static_cast<LONG>(InstructionState::Failed);
        return;
    }
    dr_register_exit_event(&InstructionExit);
    for (int pass = 0; pass < 2; ++pass)
    {
        auto modules = dr_module_iterator_start();
        while (dr_module_iterator_hasnext(modules))
        {
            auto module = dr_module_iterator_next(modules);
            if (!pass) ModuleLoaded(nullptr, module, true);
            else DiscoverExports(module, true);
            dr_free_module_data(module);
        }
        dr_module_iterator_stop(modules);
    }
}

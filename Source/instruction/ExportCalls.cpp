#pragma warning(push, 0)
#include <winsock2.h>
#include <mswsock.h>
#include <phnt_windows.h>
#include <phnt.h>
#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#pragma warning(pop)
#include "InstructionCapture.h"
#include "X86FloatingState.h"
#include <algorithm>

namespace Detourist
{
constexpr uint32_t MaxThreadFrames = 4096;
constexpr uint64_t OpenCreateFlag = 0x100;

uint32_t ApplicationError(void* context)
{
    dr_switch_to_app_state(context);
    auto value = NtCurrentTeb()->LastErrorValue;
    dr_switch_to_dr_state(context);
    return value;
}

bool ExportFailure(const InstructionDefinition& definition, uint64_t result)
{
    if (definition.rpcProxy) return static_cast<int32_t>(result) < 0;
    if (definition.runtime && (definition.runtime->resultRule != ExportResultRule::Unknown ||
        definition.runtime->resultSuccessCount))
        return ExportResultFailed(definition.runtime->resultRule, definition.runtime->signature.resultBytes, result,
            definition.runtime->resultSuccesses, definition.runtime->resultSuccessCount);
    return InstructionFailure(definition.typed, result);
}

InstructionFrame* TakeExportFrame(void* context, InstructionThread& thread)
{
    if (!thread.freeFrames && thread.allocatedFrames < MaxThreadFrames)
    {
        auto block = static_cast<InstructionFrames*>(dr_thread_alloc(context, sizeof(InstructionFrames)));
        memset(block, 0, sizeof(*block));
        block->next = thread.blocks;
        thread.blocks = block;
        for (auto& frame : block->frames)
        {
            frame.nextFree = thread.freeFrames;
            thread.freeFrames = &frame;
        }
        thread.allocatedFrames += static_cast<uint32_t>(std::size(block->frames));
    }
    if (!thread.freeFrames)
    {
        InstructionTransport.Header()->moduleRefreshError = ERROR_STACK_OVERFLOW;
        InterlockedExchange(&InstructionTransport.Header()->stop, TransportStopped);
        return nullptr;
    }
    auto frame = thread.freeFrames;
    thread.freeFrames = frame->nextFree;
    memset(frame, 0, sizeof(*frame));
    frame->previous = thread.current;
    thread.current = frame;
    return frame;
}

void ReleaseExportFrame(InstructionThread& thread, InstructionFrame& frame)
{
    if (frame.observerSet && thread.current == &frame)
        SetInstructionObserver(dr_get_current_drcontext(), thread, frame.previousObserver);
    auto link = &thread.current;
    while (*link && *link != &frame) link = &(*link)->previous;
    if (*link) *link = frame.previous;
    if (frame.counted) InterlockedDecrement64(&frame.transport->Header()->activeCalls);
    frame.active = frame.counted = false;
    frame.nextFree = thread.freeFrames;
    thread.freeFrames = &frame;
}

void ExportEntered(void* wrapped, void** state)
{
    [[maybe_unused]] X86FloatingState floating;
    auto definition = static_cast<InstructionDefinition*>(*state);
    *state = nullptr;
    auto context = drwrap_get_drcontext(wrapped);
    auto thread = static_cast<InstructionThread*>(drmgr_get_tls_field(context, ThreadSlot));
    auto header = InstructionTransport.Header();
    auto threadId = dr_get_thread_id(context);
    if (ReadShared64(header->wrapGeneration) != ReadShared64(AppliedWrapGeneration)) SyncExportWraps();
    bool mruLifetime = definition->typed == Api::CreateMRUListW || definition->typed == Api::FreeMRUList;
    bool moduleInitialization = !strcmp(definition->metadata.name, "DllMain");
    bool mruOnly = header->capturePaused != 0;
    auto asyncRole = definition->asyncRole;
    const auto asyncObserver = AsyncObserver(asyncRole);
    if (!thread || definition->retired || header->stop ||
        mruOnly && !mruLifetime && !asyncObserver && !RpcSerializationApi(definition->typed) && !moduleInitialization ||
        threadId == static_cast<DWORD>(header->agentThreadId) ||
        threadId == static_cast<DWORD>(header->instructionThreadId)) return;
    auto machine = drwrap_get_mcontext_ex(wrapped,
        static_cast<dr_mcontext_flags_t>(DR_MC_CONTROL | DR_MC_INTEGER));
    if (!machine) return;
    uint64_t caller = 0;
    if (!definition->entryOnly)
        dr_safe_read(reinterpret_cast<void*>(machine->xsp), sizeof(void*), &caller, nullptr);
    const auto receiver = ReadInstructionArgument(*machine, definition->signature, 0);
    uint32_t slot = UINT32_MAX;
    if (caller && thread->comCaller == caller)
    {
        if (thread->comTarget == definition->address && thread->comInstance == receiver)
            slot = thread->comSlot;
        thread->comCaller = 0;
    }
    ObserverContext observer{};
    if (InstructionObserver(context, thread, caller, &observer)) return;
    auto selectedClock = observer.clock ? observer.clock : &thread->clock;
    const bool nestedClock = selectedClock->depth != 0 || observer.parentId != 0 || thread->current != nullptr;
    CaptureObservation capture(nestedClock ? selectedClock : nullptr, nestedClock ? Clock() : 0);
    if (InterlockedCompareExchange(&definition->sharedExport, 0, 0))
        definition = ResolveInstructionImport(definition, caller);
    definition = ResolveInterfaceDefinition(definition, receiver, slot);
    if (!definition || definition->retired) return;
    bool queryProbe = InterlockedCompareExchange(&definition->queryProbe, 0, 0) != 0;
    GUID queryIdentity{};
    const auto second = ReadInstructionArgument(*machine, definition->signature, 1);
    moduleInitialization = moduleInitialization && second == DLL_PROCESS_ATTACH &&
        receiver == reinterpret_cast<uintptr_t>(definition->module);
    if (queryProbe && !ReadCaptureMemory(reinterpret_cast<void*>(second), &queryIdentity,
        sizeof(queryIdentity))) return;

    auto native = NativeOwnsCall(*definition, observer);
    auto filters = static_cast<uint64_t>(header->enabledFilters);
    auto record = !mruOnly && !native && FilterEnabled(filters, definition->mask, definition->categoryMask) &&
        !ApiExcluded(*header, definition->nameHash);
    bool queryRecord = queryProbe && record;
    if (queryProbe) record = false;
    bool discover = (filters & ComApis) && (queryProbe || definition->typed == Api::ComInvoke ||
        definition->typed == Api::ComEnumVariantNext ||
        definition->typed == Api::CoCreateInstanceFromApp ||
        definition->typed == Api::CoGetInstanceFromFile ||
        definition->typed == Api::CoGetInstanceFromIStorage ||
        definition->signature.interfaceOutputIndex ||
        definition->interfaceInputs ||
        PublicInterfaceOutputs(definition->typed) ||
        (definition->runtime && (definition->runtime->interfaceParameters ||
            definition->runtime->resultInterfaceIndex)));
    bool breaks = !mruOnly && !native && !queryProbe &&
        (((header->entryBreaks | header->exitBreaks) & definition->mask) ||
        header->entryApi == static_cast<LONG>(definition->id) || header->exitApi == static_cast<LONG>(definition->id));
    // Agent hooks gate children for the creation APIs they own.
    bool child = header->followChildren && !native && CreatesChild(definition->typed) &&
        !(observer.flags & ObserverFollowingChild);
    bool extension = definition->wglLookup || definition->typed == Api::WSAIoctl &&
        (static_cast<DWORD>(second) == SIO_GET_EXTENSION_FUNCTION_POINTER ||
            static_cast<DWORD>(second) == SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER);
    // Serialization handles keep their encode or decode mode for later pickling calls, even when filtered.
    bool serialization = !native && RpcSerializationApi(definition->typed);
    if (!record && !discover && !breaks && !child && !extension && !mruLifetime && !asyncObserver &&
        !serialization && !definition->callbackRegistration && !moduleInitialization) return;
    if (!capture.clock)
    {
        capture.clock = selectedClock;
        capture.Resume(Clock());
    }
    if (definition->signature.floatingArguments)
        machine = drwrap_get_mcontext_ex(wrapped,
            static_cast<dr_mcontext_flags_t>(DR_MC_CONTROL | DR_MC_INTEGER | DR_MC_MULTIMEDIA));
    if (!machine) return;
    auto frame = TakeExportFrame(context, *thread);
    if (!frame) return;
    FlushThreadPendingSlots(context, *thread);
    frame->transport = &InstructionTransport;
    frame->clock = capture.clock;
    frame->invocationStarted = capture.ApplicationTime();
    frame->definition = definition;
    frame->mask = definition->mask;
    frame->active = true;
    frame->record = record;
    frame->mruOnly = mruOnly;
    frame->asyncRole = asyncRole;
    frame->suppressed = native;
    frame->queryProbe = queryProbe;
    frame->queryRecord = queryRecord;
    frame->queryIdentity = queryIdentity;
    if (queryProbe) frame->queryTimestamp = Clock();
    frame->counted = !definition->continuation;
    if (frame->counted) InterlockedIncrement64(&header->activeCalls);
    frame->event.api = definition->id;
    frame->event.callId = static_cast<uint64_t>(InterlockedIncrement64(&header->nextCallId));
    frame->event.processId = static_cast<uint32_t>(dr_get_process_id());
    frame->event.threadId = static_cast<uint32_t>(threadId);
    frame->event.flags = (definition->known || definition->marshalOperation ||
        definition->runtime && !definition->runtime->rawTailStart ?
        0u : RawArguments) |
        (definition->continuation ? Continuation : 0u) | (definition->entryOnly ? KernelDispatcher : 0u) |
        (header->stackDepth ? StackUnavailable : 0u);
    if (definition->optionalMode && !(second & OpenCreateFlag)) frame->event.flags |= OptionalArgumentAbsent;
    if (observer.captureIdentity == header->captureIdentity)
    {
        frame->event.parentId = observer.parentId;
        frame->event.depth = observer.depth;
    }
    else if (frame->previous)
    {
        frame->event.parentId = frame->previous->event.callId;
        frame->event.depth = frame->previous->event.depth + 1;
    }

    // Read application registers and stack slots without invoking the application or its allocator.
    frame->event.caller = caller;
    frame->stackPointer = machine->xsp;
    const bool bufferedResult = definition->signature.returnBufferBytes != 0;
    const bool bufferAfterReceiver = bufferedResult &&
        (definition->interfaceTable || IsComApi(definition->typed));
    auto nativeSignature = definition->signature;
#ifndef _WIN64
    if (bufferedResult)
    {
        if (definition->metadata.argumentCount >= MaximumArguments)
        {
            ReleaseExportFrame(*thread, *frame);
            return;
        }
        // Native stack positions include the return pointer between a COM receiver and its declared arguments.
        const auto hidden = bufferAfterReceiver ? 1u : 0u;
        std::move_backward(nativeSignature.argumentBytes + hidden,
            nativeSignature.argumentBytes + definition->metadata.argumentCount,
            nativeSignature.argumentBytes + definition->metadata.argumentCount + 1);
        nativeSignature.argumentBytes[hidden] = sizeof(void*);
    }
#endif
    if (bufferedResult)
#ifdef _WIN64
        frame->event.result = frame->returnBuffer = bufferAfterReceiver ? second : receiver;
#else
        frame->event.result = frame->returnBuffer = ReadInstructionArgument(*machine, nativeSignature,
            bufferAfterReceiver ? 1 : 0);
#endif
    const bool stackProbe = definition->stackProbe;
    auto argumentCount = definition->metadata.argumentCount -
        bool(frame->event.flags & OptionalArgumentAbsent);
    const auto rpcDecoder = definition->rpcProxy ? RpcDecoder::Dcom3 :
        RpcDecoderFor(definition->metadata.module, definition->metadata.name);
    if (rpcDecoder != RpcDecoder::None) argumentCount = definition->rpcProxy ? 0u : RpcPrefix(rpcDecoder);
    if (definition->runtime && definition->runtime->IsAviSave())
    {
        // Only declared stream pairs belong to this call; trailing stack slots remain unobserved.
        auto streams = static_cast<int32_t>(ReadInstructionArgument(*machine, definition->signature, 3));
        argumentCount = std::min(argumentCount, 4u + 2u * static_cast<uint32_t>(
            std::clamp(streams, 1, static_cast<int32_t>((MaximumArguments - 4) / 2))));
        frame->event.flags = (frame->event.flags & ~FormattedArgumentMask) | RawArguments | FormattedArguments |
            (argumentCount << FormattedArgumentShift);
    }
    const auto audit = definition->runtime && definition->runtime->IsAuthzAudit();
    if (audit) argumentCount = 5;
    for (uint32_t index = 0; index < argumentCount; ++index)
    {
        auto position = index + (bufferedResult && (!bufferAfterReceiver || index) ? 1u : 0u);
        if (stackProbe)
            frame->event.arguments[index] = machine->xax;
        else frame->event.arguments[index] = ReadInstructionArgument(*machine, nativeSignature, position);
        auto bytes = definition->signature.argumentBytes[index];
        if (bytes && bytes < sizeof(uint64_t)) frame->event.arguments[index] &= (uint64_t{1} << (bytes * 8)) - 1;
    }
    if (rpcDecoder != RpcDecoder::None)
    {
        if (definition->rpcProxy)
        {
            if (!PrepareRpcProxyCapture(frame->rpc, reinterpret_cast<uint64_t>(definition->interfaceTable), nullptr,
                definition->interfaceSlot))
            {
                frame->rpc = {};
                frame->rpc.decoder = rpcDecoder;
                frame->rpc.info.flags = RpcDescriptorUnreadable;
            }
        }
        else PrepareRpcCapture(frame->rpc, rpcDecoder, frame->event.arguments);
        const auto prefix = argumentCount;
        argumentCount = frame->rpc.info.argumentCount;
#ifdef _WIN64
        for (uint32_t index = prefix; index < argumentCount; ++index)
        {
            frame->event.arguments[index] = ReadInstructionArgument(*machine, definition->signature, index);
        }
#else
        ReadRpcStackArguments(frame->rpc, frame->event.arguments,
            definition->rpcProxy || RpcDirectArguments(rpcDecoder) ? machine->xsp + (prefix + 1) * sizeof(void*) :
                ReadInstructionArgument(*machine, definition->signature, prefix));
#endif
    }
    if (auto previous = frame->previous; previous &&
        RpcForwardedInterpreter(previous->rpc.decoder, rpcDecoder))
    {
        const auto prefix = RpcPrefix(rpcDecoder);
        if (frame->event.arguments[prefix - 2] == previous->event.arguments[prefix - 2] &&
            frame->event.arguments[prefix - 1] == previous->event.arguments[prefix - 1])
        {
            auto module = dr_lookup_module(reinterpret_cast<app_pc>(caller));
            const bool forwarded = module && module->start == definition->module;
            if (module) dr_free_module_data(module);
            if (forwarded) { ReleaseExportFrame(*thread, *frame); return; }
        }
    }
    if (audit) ReadRuntimeAuthzArguments(*frame);
    frame->event.error = ApplicationError(context);
    frame->queryError = frame->event.error;
    frame->previousObserver = observer;
    if (record || queryRecord) CaptureInstructionStack(context, *frame, *machine, true);
    if (record)
    {
        SetInstructionObserver(context, *thread, {header->captureIdentity, frame->event.callId, frame->event.depth + 1,
            0, static_cast<uint32_t>(definition->id)});
        frame->observerSet = true;
    }
    if ((record || breaks) && IsDynamicApi(definition->id) && !definition->published)
    {
        dr_mutex_lock(DefinitionLock);
        if (!definition->published)
        {
            PublishDefinition(*definition);
            InterlockedExchange(&definition->published, 1);
        }
        dr_mutex_unlock(DefinitionLock);
    }
    uint64_t arguments[MaximumArguments];
    memcpy(arguments, frame->event.arguments, sizeof(arguments));
    auto originalError = frame->event.error;
    bool skip = !mruOnly && InstructionBreakpoint(*frame, false);
    if (rpcDecoder != RpcDecoder::None) ObserveRpcDescriptorEdits(frame->rpc, arguments, frame->event);
    const auto editableArguments = rpcDecoder == RpcDecoder::None ? definition->metadata.argumentCount : argumentCount;
    for (uint32_t index = 0; index < editableArguments; ++index)
    {
        if (arguments[index] == frame->event.arguments[index]) continue;
#ifndef _WIN64
        if (rpcDecoder != RpcDecoder::None && index >= frame->rpc.info.prefix)
        {
            WriteRpcStackArgument(frame->rpc, index, frame->event.arguments[index]);
            continue;
        }
#endif
        auto position = index + (bufferedResult && (!bufferAfterReceiver || index) ? 1u : 0u);
        if (stackProbe)
        {
            machine->xax = static_cast<reg_t>(frame->event.arguments[index]);
            drwrap_set_mcontext(wrapped);
        }
        else
            WriteInstructionArgument(wrapped, *machine, nativeSignature, position, frame->event.arguments[index]);
    }
    if (originalError != frame->event.error) SetApplicationError(context, frame->event.error);
    if (!skip && child && PrepareInstructionChild(*frame) &&
        !drwrap_set_arg(wrapped, static_cast<int>(frame->childFlagIndex),
            reinterpret_cast<void*>(
                static_cast<uintptr_t>(frame->childFlags | (frame->nativeChild ? 1u : CREATE_SUSPENDED)))))
        CompleteInstructionChild(*frame, false);
    if (!skip) ObserveMruCall(definition->typed, header->captureIdentity, frame->event, false, frame->mru);
    if (serialization && !skip) ObserveRpcSerializationCall(definition->typed, frame->event.arguments, 0, false);
    if (record && !skip)
    {
        uint32_t parameter;
        auto callback = PrepareAsyncCallback(context, *frame, parameter);
        if (callback) drwrap_set_arg(wrapped, static_cast<int>(parameter), reinterpret_cast<void*>(callback));
    }
    if (record) PublishInstruction(*frame, false, !skip);
    if (record && !skip) BeginAsyncIo(header, frame->event, asyncRole);
    if (discover && !skip) DiscoverInstructionInputs(*frame);
    if (definition->entryOnly)
    {
        // Kernel dispatchers receive a context frame rather than a function return address.
        ReleaseExportFrame(*thread, *frame);
        return;
    }
    uint32_t cleanup = 0;
#ifndef _WIN64
    if (!definition->signature.supported) skip = false;
    if (definition->signature.callingConvention == ExportCallingConvention::Stdcall ||
        definition->signature.callingConvention == ExportCallingConvention::Fastcall)
        cleanup = ExportStackBytes(definition->signature, definition->metadata.argumentCount) +
            (bufferedResult ? sizeof(void*) : 0);
#endif
    if (skip && drwrap_skip_call(wrapped, reinterpret_cast<void*>(frame->event.result), cleanup))
    {
#ifndef _WIN64
        if (!definition->signature.floatingResult && definition->signature.resultBytes == 8)
        {
            machine->xdx = static_cast<reg_t>(frame->event.result >> 32);
            drwrap_set_mcontext(wrapped);
        }
#endif
        if (definition->signature.floatingResult)
        {
#ifdef _WIN64
            machine = drwrap_get_mcontext_ex(wrapped, DR_MC_ALL);
            machine->simd[0].u64[0] = frame->event.result;
            drwrap_set_mcontext(wrapped);
#else
            floating.Write(frame->event.result, definition->signature.resultBytes, true);
#endif
        }
        frame->event.flags |= Skipped | DurationMeasured;
        frame->event.adjustedDuration = 0;
        if (ExportFailure(*definition, frame->event.result)) frame->event.flags |= Failed;
        if (record) PublishInstruction(*frame, true);
        ReleaseExportFrame(*thread, *frame);
        return;
    }
    *state = frame;
}

void ExportLeft(void* wrapped, void* state)
{
    [[maybe_unused]] X86FloatingState floating;
    auto frame = static_cast<InstructionFrame*>(state);
    if (!frame || !frame->active) return;
    auto context = wrapped ? drwrap_get_drcontext(wrapped) : dr_get_current_drcontext();
    auto thread = static_cast<InstructionThread*>(drmgr_get_tls_field(context, ThreadSlot));
    if (!thread) return;
    CaptureObservation capture(ValidFrameClock(thread, frame->clock), Clock());
    if (capture.clock)
    {
        frame->event.adjustedDuration = std::max(int64_t{0}, capture.ApplicationTime() - frame->invocationStarted);
        frame->event.flags |= DurationMeasured;
    }
    if (!wrapped) frame->event.flags |= Unwound;
    else
    {
        auto& signature = frame->definition->signature;
        auto flags = DR_MC_INTEGER | (signature.floatingResult ? DR_MC_MULTIMEDIA : 0);
        auto machine = drwrap_get_mcontext_ex(wrapped, static_cast<dr_mcontext_flags_t>(flags));
#ifdef _WIN64
        frame->event.result = machine ? signature.floatingResult ? machine->simd[0].u64[0] : machine->xax : 0;
#else
        frame->event.result = signature.floatingResult ? floating.Read(signature.resultBytes) :
            machine ? uint64_t{machine->xax} | (signature.resultBytes == 8 ? uint64_t{machine->xdx} << 32 : 0) : 0;
#endif
        if (signature.supported && !signature.resultBytes) frame->event.result = 0;
        else if (signature.resultBytes && signature.resultBytes < sizeof(uint64_t))
            frame->event.result &= (uint64_t{1} << (signature.resultBytes * 8)) - 1;
        frame->event.error = ApplicationError(context);
        frame->event.flags &= ~Continuation;
        auto api = frame->definition->typed;
        if (ExportFailure(*frame->definition, frame->event.result)) frame->event.flags |= Failed;
        if (NativeReturnsStatus(api) && frame->event.result == STATUS_PENDING) frame->event.flags |= AsyncPending;
        ObserveMruCall(api, frame->transport->Header()->captureIdentity, frame->event, true, frame->mru);
        if (!frame->suppressed && RpcSerializationApi(api))
            ObserveRpcSerializationCall(api, frame->event.arguments, frame->event.result, true);
        if (frame->queryProbe && ConfirmQueryInterface(*frame))
        {
            frame->record = frame->queryRecord;
            if (frame->record)
            {
                auto error = frame->event.error;
                frame->event.error = frame->queryError;
                PublishInstruction(*frame, false, false);
                frame->event.error = error;
            }
        }
        FinishAsyncIo(AsyncSink(*frame->transport), frame->event, frame->asyncRole);
        auto originalResult = frame->event.result;
        auto originalError = frame->event.error;
        if (!frame->mruOnly) InstructionBreakpoint(*frame, true);
        if (originalResult != frame->event.result)
        {
            if (signature.floatingResult && machine)
            {
#ifdef _WIN64
                machine->simd[0].u64[0] = frame->event.result;
                drwrap_set_mcontext(wrapped);
#else
                floating.Write(frame->event.result, signature.resultBytes);
#endif
            }
#ifndef _WIN64
            else if (signature.resultBytes == 8 && machine)
            {
                machine->xax = static_cast<reg_t>(frame->event.result);
                machine->xdx = static_cast<reg_t>(frame->event.result >> 32);
                drwrap_set_mcontext(wrapped);
            }
#endif
            else drwrap_set_retval(wrapped, reinterpret_cast<void*>(frame->event.result));
            if (ExportFailure(*frame->definition, frame->event.result)) frame->event.flags |= Failed;
            else frame->event.flags &= ~Failed;
        }
        if (originalError != frame->event.error) SetApplicationError(context, frame->event.error);
    }
    CompleteInstructionChild(*frame, wrapped && !(frame->event.flags & Failed));
    if (wrapped && !(frame->event.flags & Failed) && (frame->transport->Header()->enabledFilters & ComApis))
        DiscoverInstructionCom(*frame);
    if (!wrapped) FinishAsyncIo(AsyncSink(*frame->transport), frame->event, frame->asyncRole);
    if (frame->event.flags & AsyncPending) frame->event.flags &= ~Failed;
    if (frame->record) PublishInstruction(*frame, true);
    if (wrapped) DiscoverReturnedExtensions(*frame);

    // Providers can redirect export entries while initializing, after the module-load notification.
    if (wrapped && frame->event.result && !(frame->event.flags & Skipped) &&
        !strcmp(frame->definition->metadata.name, "DllMain") && frame->event.arguments[1] == DLL_PROCESS_ATTACH &&
        frame->event.arguments[0] == reinterpret_cast<uintptr_t>(frame->definition->module))
    {
        auto module = dr_lookup_module(static_cast<app_pc>(frame->definition->module));
        if (module)
        {
            DiscoverExports(module);
            dr_free_module_data(module);
        }
    }
    ReleaseExportFrame(*thread, *frame);
}

void EndExportThread(void* context, InstructionThread& thread)
{
    for (auto frame = thread.current; frame; frame = frame->previous)
    {
        if (!frame->active) continue;
        if (frame->record && frame->counted)
        {
            frame->event.flags |= Unwound;
            FinishAsyncIo(AsyncSink(*frame->transport), frame->event, frame->asyncRole);
            PublishInstruction(*frame, true);
        }
        if (frame->counted) InterlockedDecrement64(&InstructionTransport.Header()->activeCalls);
    }
    FlushThreadPendingSlots(context, thread);
    while (thread.blocks)
    {
        auto block = thread.blocks;
        thread.blocks = block->next;
        dr_thread_free(context, block, sizeof(*block));
    }
}
}

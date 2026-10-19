#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#include "dr_api.h"
#include "drmgr.h"
#pragma warning(pop)
#include "InstructionCapture.h"

namespace Detourist
{
void ChildDelay()
{
    LARGE_INTEGER delay{};
    delay.QuadPart = NtRelativeMilliseconds(1);
    NtDelayExecution(FALSE, &delay);
}

bool PrepareInstructionChild(InstructionFrame& call)
{
    auto header = call.transport->Header();
    if (!header->followChildren || !CreatesChild(call.definition->typed) ||
        (call.previousObserver.flags & ObserverFollowingChild)) return false;
    auto thread = static_cast<InstructionThread*>(drmgr_get_tls_field(dr_get_current_drcontext(), ThreadSlot));
    for (auto previous = call.previous; previous; previous = previous->previous)
        if (previous->child) return false;
    if (thread)
    {
        for (auto previous = thread->current; previous; previous = previous->previous)
            if (previous != &call && previous->child) return false;
    }
    auto syscalls = static_cast<InstructionSyscalls*>(drmgr_get_cls_field(dr_get_current_drcontext(), SyscallSlot));
    for (; syscalls; syscalls = syscalls->parent)
        for (uint32_t index = 0; index < syscalls->depth; ++index)
            if (&syscalls->frames[index] != &call && syscalls->frames[index].child) return false;
    auto api = call.definition->typed;
    call.nativeChild = api == Api::NtCreateUserProcess;
    call.childFlagIndex = ChildFlagsArgument(api);
    call.childOutput = ChildOutputArgument(api);
    call.childFlags = static_cast<uint32_t>(call.event.arguments[call.childFlagIndex]);

    // Hold the child's initial thread until its capture agent is ready, even when this API is filtered out.
    auto started = Clock();
    while (!header->stop && call.transport->CollectorAlive())
    {
        for (auto& request : header->children)
        {
            if (InterlockedCompareExchange(&request.state, static_cast<LONG>(ChildRequestState::Claimed),
                static_cast<LONG>(ChildRequestState::Idle)) != static_cast<LONG>(ChildRequestState::Idle)) continue;
            call.child = &request;
            InterlockedAdd64(&header->waitTicks, Clock() - started);
            return true;
        }
        ChildDelay();
    }
    return false;
}

void CompleteInstructionChild(InstructionFrame& call, bool success)
{
    auto request = call.child;
    if (!request) return;
    auto header = call.transport->Header();
    PROCESS_INFORMATION information{};
    if (success && call.nativeChild)
    {
        PROCESS_BASIC_INFORMATION process{};
        THREAD_BASIC_INFORMATION thread{};
        success =
            ReadCaptureMemory(
                reinterpret_cast<void*>(call.event.arguments[0]), &information.hProcess, sizeof(HANDLE)) &&
            ReadCaptureMemory(reinterpret_cast<void*>(call.event.arguments[1]), &information.hThread, sizeof(HANDLE)) &&
            NtQueryInformationProcess(
                information.hProcess, ProcessBasicInformation, &process, sizeof(process), nullptr) >= 0 &&
            NtQueryInformationThread(information.hThread, ThreadBasicInformation, &thread, sizeof(thread), nullptr) >=
                0;
        information.dwProcessId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(process.UniqueProcessId));
        information.dwThreadId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(thread.ClientId.UniqueThread));
    }
    else if (success)
        success = ReadCaptureMemory(reinterpret_cast<void*>(call.event.arguments[call.childOutput]),
            &information, sizeof(information));
    if (success)
    {
        request->processId = information.dwProcessId;
        request->threadId = information.dwThreadId;
        request->error = 0;
        request->suspended = (call.childFlags & (call.nativeChild ? 1u : CREATE_SUSPENDED)) != 0;
        InterlockedExchange(&request->state, static_cast<LONG>(ChildRequestState::Pending));
        NtSetEvent(call.transport->data, nullptr);
        auto started = Clock();
        while (request->state != static_cast<LONG>(ChildRequestState::Complete) && !header->stop &&
            call.transport->CollectorAlive()) ChildDelay();
        InterlockedAdd64(&header->waitTicks, Clock() - started);
    }
    if (information.hThread && !(call.childFlags & (call.nativeChild ? 1u : CREATE_SUSPENDED)))
        NtResumeThread(information.hThread, nullptr);
    for (;;)
    {
        auto state = request->state;
        auto nextState = state == static_cast<LONG>(ChildRequestState::Attaching) ?
            static_cast<LONG>(ChildRequestState::Abandoned) : static_cast<LONG>(ChildRequestState::Idle);
        if (InterlockedCompareExchange(&request->state, nextState, state) == state) break;
    }
    call.child = nullptr;
}
}

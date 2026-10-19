#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#include "dr_api.h"
#pragma warning(pop)
#include "InstructionCapture.h"

namespace Detourist
{
void SetApplicationError(void* context, uint32_t error)
{
    dr_switch_to_app_state(context);
    NtCurrentTeb()->LastErrorValue = error;
    dr_switch_to_dr_state(context);
}

bool InstructionBreakpoint(InstructionFrame& call, bool leaving)
{
    auto header = call.transport->Header();
    auto mask = leaving ? header->exitBreaks : header->entryBreaks;
    auto exact = leaving ? header->exitApi : header->entryApi;
    if ((call.queryProbe && (!leaving || InterlockedCompareExchange(&call.definition->queryProbe, 0, 0))) ||
        call.suppressed || header->stop || !header->debuggerActive ||
        (exact != static_cast<LONG>(call.event.api) && !(mask & call.mask))) return false;
    auto& breakpoint = header->breakpoint;
    LARGE_INTEGER interval{};
    interval.QuadPart = NtRelativeMilliseconds(1);
    while (InterlockedCompareExchange(&breakpoint.ownerThread, call.event.threadId, 0) != 0)
    {
        if (header->stop || !call.transport->CollectorAlive()) return false;
        NtDelayExecution(FALSE, &interval);
    }
    mask = leaving ? header->exitBreaks : header->entryBreaks;
    exact = leaving ? header->exitApi : header->entryApi;
    if (exact != static_cast<LONG>(call.event.api) && !(mask & call.mask))
    {
        InterlockedExchange(&breakpoint.ownerThread, 0);
        return false;
    }

    // The collector suspends the process after this invocation has published its editable state.
    NtResetEvent(call.transport->resume, nullptr);
    breakpoint.event = call.event;
    breakpoint.phase = static_cast<LONG>(leaving ? BreakpointPhase::Leave : BreakpointPhase::Enter);
    breakpoint.action = static_cast<LONG>(BreakpointAction::Continue);
    InterlockedExchange(&breakpoint.waiting, 1);
    NtSetEvent(call.transport->breakpoint, nullptr);
    interval.QuadPart = NtRelativeMilliseconds(50);
    while (!header->stop && call.transport->CollectorAlive())
        if (NtWaitForSingleObject(call.transport->resume, FALSE, &interval) == STATUS_SUCCESS) break;
    if (memcmp(call.event.arguments, breakpoint.event.arguments, sizeof(call.event.arguments)) ||
        call.event.result != breakpoint.event.result || call.event.error != breakpoint.event.error)
        breakpoint.event.flags |= Edited;
    call.event = breakpoint.event;
    bool skip = !leaving && !(call.event.flags & KernelDispatcher) &&
        breakpoint.action == static_cast<LONG>(BreakpointAction::Skip);
    InterlockedExchange(&breakpoint.waiting, 0);
    InterlockedExchange(&breakpoint.ownerThread, 0);
    return skip;
}
}

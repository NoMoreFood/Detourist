#ifdef DETOURIST_INSTRUCTION_CLIENT
#include "../instruction/InstructionCapture.h"
#else
#include "../agent/Agent.h"
#endif
#include "CatalogCaptureValues.h"
#include "WNetCaptureValues.h"

namespace Detourist
{

// Built-in hooks and instruction fallbacks read the same immutable catalog plans.
#ifdef DETOURIST_INSTRUCTION_CLIENT
using SdkState = InstructionFrame;
#else
using SdkState = Call;
#endif

void CaptureBuiltinParameters(SdkState& call, Slot* slot, bool leaving)
{
    if (CaptureMruValues(call.event.api, call.event, call.mru, slot, call.transport->Header(), leaving)) return;
    auto& catalog = call.transport->Catalog();
    auto api = call.event.api;
#ifdef DETOURIST_INSTRUCTION_CLIENT
    api = call.definition->typed;
#endif
    if (api == Api::AuthzReportSecurityEvent)
    {
        CaptureAuthzAudit(call.event, slot, call.transport->Header(), leaving);
        return;
    }
    auto plan = catalog.BuiltinPlan(api);
#ifndef DETOURIST_INSTRUCTION_CLIENT
    if (CaptureRpcMarshalValues(call, slot, leaving)) return;
    if (call.exportPlan) plan = call.exportPlan;
#endif
    if (!plan || sizeof(void*) == 4 && !plan->signature.supported) return;
#ifndef DETOURIST_INSTRUCTION_CLIENT
    if (call.rpc)
    {
        CaptureRpcValues(*call.rpc, call.event, slot, call.transport->Header(), leaving);
        return;
    }
#endif
    if (CaptureWNetParameters(call, slot, leaving, catalog.Text(plan->module), catalog.Text(plan->name),
        {catalog.Parameters(*plan), plan->argumentCount}, {catalog.Members(*plan), plan->memberCount})) return;
    if (api == Api::AVISave || api == Api::AVISaveA || api == Api::AVISaveW)
    {
        if (!leaving)
        {
            CaptureCatalogValues(call, slot, false, {catalog.Parameters(*plan), 4}, {});
            CaptureAviStreams(call.event, slot, call.transport->Header());
        }
        return;
    }
    if (api < Api::Count && leaving && (call.event.flags & (Failed | AsyncPending)) &&
        (catalog.Builtins()[static_cast<uint32_t>(api)].hookFlags & HookCompleteOutput)) return;
    CaptureCatalogValues(call, slot, leaving, {catalog.Parameters(*plan), plan->argumentCount},
        {catalog.Members(*plan), plan->memberCount}, plan->signature.returnBufferBytes,
        plan->countedResultBytes, plan->resultCaptureKind);
}
}

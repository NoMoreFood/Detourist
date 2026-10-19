#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "InstructionCapture.h"
#include "CatalogCaptureValues.h"
#include "AuthzCaptureValues.h"
#include "WNetCaptureValues.h"
#include <algorithm>

namespace Detourist
{
constexpr uint32_t MapiUnicodeFlag = 0x80000000;

void CaptureRuntimeAviSave(InstructionFrame& call, Slot* slot, bool leaving)
{
    const auto& definition = *call.definition->runtime;
    if (leaving) return;

    CaptureCatalogValues(call, slot, false, {definition.parameters, 4}, {});
    CaptureAviStreams(call.event, slot, call.transport->Header());
}

bool RuntimeImplicitArrayCount(const InstructionFrame& call, uint32_t index, uint64_t& count)
{
    auto definition = call.definition->runtime;
    if (!definition || call.event.result > 1) return false;
    auto name = call.definition->metadata.name;

    // Standard single-item enumerators derive the completed extent from their result when the count is omitted.
    auto method = strstr(name, "::Next");
    if (!strncmp(name, "IEnum", 5) && method && !strcmp(method, "::Next") &&
        index == 2 && definition->argumentCount == 4 && definition->parameters[index].extentIndex == 1 &&
        definition->parameters[index].actualIndex == 4 &&
        call.event.arguments[1] == 1 && !call.event.arguments[3])
    {
        count = call.event.result == S_OK ? 1 : 0;
        return true;
    }
    if (!strcmp(name, "IEnumObjects::Next") && index == 3 && definition->argumentCount == 5 &&
        !call.event.arguments[4] && (call.event.result == S_OK || call.event.arguments[1] == 1))
    {
        count = call.event.result == S_OK ? static_cast<uint32_t>(call.event.arguments[1]) : 0;
        return true;
    }
    return false;
}

void CaptureRuntimeParameters(InstructionFrame& call, Slot* slot, bool leaving, bool omitLast)
{
    if (CaptureMruValues(call.definition->typed, call.event, call.mru,
        slot, call.transport->Header(), leaving)) return;
    // Both tracing engines expand the same catalog extents and referenced buffers.
    const auto& definition = *call.definition->runtime;
    if (definition.IsShellMessage()) return;
    if (CaptureWNetParameters(call, slot, leaving, definition.module, definition.name,
        {definition.parameters, definition.argumentCount}, {definition.members, definition.memberCount})) return;
    if (call.definition->callbackRegistration && !(call.event.arguments[6] & MapiUnicodeFlag))
    {
        // MAPI's registration flags select ANSI or Unicode for the provider and address-type strings.
        std::array<ExportParameter, MaximumArguments> parameters;
        std::copy_n(definition.parameters, definition.argumentCount, parameters.begin());
        for (uint32_t index : {2u, 3u})
        {
            parameters[index].kind = ExportValueKind::Ansi;
            parameters[index].multiplier = 1;
        }
        CaptureCatalogValues(call, slot, leaving, {parameters.data(), definition.argumentCount},
            {definition.members, definition.memberCount});
        return;
    }
    uint64_t count = 0;
    uint32_t index = 0;
    if (leaving)
        for (; index < definition.argumentCount; ++index)
            if (RuntimeImplicitArrayCount(call, index, count)) break;
    if (leaving && index < definition.argumentCount)
    {
        std::array<ExportParameter, MaximumArguments> parameters;
        std::copy_n(definition.parameters, definition.argumentCount, parameters.begin());
        parameters[index].actualIndex = 0;
        if (!count)
        {
            parameters[index].bytes = 0;
            parameters[index].extentIndex = -1;
        }
        CaptureCatalogValues(call, slot, leaving, {parameters.data(), definition.argumentCount},
            {definition.members, definition.memberCount}, definition.signature.returnBufferBytes,
            definition.countedResultBytes, definition.resultCaptureKind);
        return;
    }
    CaptureCatalogValues(call, slot, leaving,
        {definition.parameters, definition.argumentCount - (omitLast && definition.argumentCount ? 1u : 0u)},
        {definition.members, definition.memberCount}, definition.signature.returnBufferBytes,
        definition.countedResultBytes, definition.resultCaptureKind);
}

void ReadRuntimeAuthzArguments(InstructionFrame& call)
{
    ReadAuditArguments(call.event, MaximumArguments, [&](uint64_t index, uint32_t bytes, uint64_t& value)
    {
        if (call.stackPointer > UINT64_MAX - (index + 1) * sizeof(void*)) return false;
        return ReadCaptureMemory(
            reinterpret_cast<void*>(call.stackPointer + (index + 1) * sizeof(void*)), &value, bytes);
    });
}

void CaptureRuntimeAuthzAudit(InstructionFrame& call, Slot* slot, bool leaving)
{
    CaptureAuthzAudit(call.event, slot, call.transport->Header(), leaving);
}
}

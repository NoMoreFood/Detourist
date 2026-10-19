#pragma once
#include "PointerCaptureValues.h"
#include "NetApiSecurityCapture.h"
#include "AuthzArguments.h"
#include <authz.h>

namespace Detourist
{
inline void CaptureAuditValue(Slot* slot, SharedHeader* header, uint32_t parameter, uint32_t type,
    uint64_t address, bool structured = false)
{
    if (!address) return;
    auto flags = structured ? AuditData | (2u << ValueDetailShift) | MemberData : 0u;
    auto offset = slot->event.payloadBytes;
    switch (type)
    {
    case APT_String:
        CopyValue(slot, header, parameter, ValueKind::Utf16, address, UINT64_MAX, {.terminated = true, .flags = flags});
        break;
    case APT_Sid:
        CaptureSid(slot, header, parameter, address, flags);
        return;
    case APT_Guid:
        CopyValue(slot, header, parameter, ValueKind::Bytes, address, sizeof(GUID), {.flags = flags});
        break;
    case APT_IpAddress:
        CopyValue(slot, header, parameter, ValueKind::Bytes, address, sizeof(AUDIT_IP_ADDRESS), {.flags = flags});
        break;
    case APT_ObjectTypeList:
    {
        if (CopyValue(slot, header, parameter, ValueKind::Bytes, address, sizeof(AUDIT_OBJECT_TYPES),
            {.flags = flags}) != sizeof(AUDIT_OBJECT_TYPES)) return;
        AUDIT_OBJECT_TYPES types{};
        memcpy(&types, Transport::Payload(slot) + offset + sizeof(Value), sizeof(types));
        if (!types.Count || !types.pObjectTypes) return;

        // Follow the object array only when its count and pointer survived the capture limit.
        CopyValue(slot, header, structured ? parameter :
            PackMemberParameter(parameter, offsetof(AUDIT_OBJECT_TYPES, pObjectTypes)),
            ValueKind::Bytes, reinterpret_cast<uint64_t>(types.pObjectTypes),
            uint64_t{types.Count} * sizeof(AUDIT_OBJECT_TYPE),
            {.flags = MemberData | (structured ? AuditData | (3u << ValueDetailShift) : 0u)});
        return;
    }
    default: return;
    }
}

inline void CaptureAuthzAudit(const Event& event, Slot* slot, SharedHeader* header, bool leaving)
{
    if (leaving) return;
    CaptureSid(slot, header, 3, event.arguments[3]);
    auto consumed = (event.flags & FormattedArgumentMask) >> FormattedArgumentShift;
    for (uint32_t index = 5; index < consumed;)
    {
        auto flags = static_cast<uint32_t>(event.arguments[index]);
        auto slots = AuditArgumentCount(flags);
        if (!slots || index + slots > consumed) break;
        auto parameter = index + 1;
        index += slots;
        if (slots == 1) continue;
        CaptureAuditValue(slot, header, parameter, flags & AP_ParamTypeMask, event.arguments[parameter]);
    }
}

inline void CaptureAuditParameters(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address)
{
    auto root = slot->event.payloadBytes;
    if (CopyValue(slot, header, parameter, ValueKind::Bytes, address, sizeof(AUDIT_PARAMS),
        {.flags = AuditData}) != sizeof(AUDIT_PARAMS)) return;
    AUDIT_PARAMS parameters{};
    memcpy(&parameters, Transport::Payload(slot) + root + sizeof(Value), sizeof(parameters));
    if (!parameters.Count || !parameters.Parameters) return;
    auto table = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, PackMemberParameter(parameter, offsetof(AUDIT_PARAMS, Parameters)),
        ValueKind::Bytes, reinterpret_cast<uint64_t>(parameters.Parameters),
        uint64_t{parameters.Count} * sizeof(AUDIT_PARAM),
        {.flags = AuditData | (1u << ValueDetailShift) | MemberData});

    // Complete records select the active union member; scalar and unknown types remain uninterpreted memory.
    for (uint32_t index = 0; index < captured / sizeof(AUDIT_PARAM); ++index)
    {
        AUDIT_PARAM value{};
        memcpy(&value, Transport::Payload(slot) + table + sizeof(Value) + index * sizeof(value), sizeof(value));
        auto member = static_cast<uint32_t>(index * sizeof(value) + offsetof(AUDIT_PARAM, Data0));
        CaptureAuditValue(slot, header, PackMemberParameter(parameter, member), value.Type, value.Data0, true);
    }
}

inline void CaptureAuthzRequest(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address)
{
    auto root = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address, sizeof(AUTHZ_ACCESS_REQUEST),
        {.flags = AuditData | (4u << ValueDetailShift)});
    if (!captured) return;
    AUTHZ_ACCESS_REQUEST request{};
    memcpy(&request, Transport::Payload(slot) + root + sizeof(Value), captured);
    constexpr uint32_t principal = offsetof(AUTHZ_ACCESS_REQUEST, PrincipalSelfSid);
    constexpr uint32_t list = offsetof(AUTHZ_ACCESS_REQUEST, ObjectTypeList);
    constexpr uint32_t stride = sizeof(OBJECT_TYPE_LIST), objectType = offsetof(OBJECT_TYPE_LIST, ObjectType);
    if (captured >= offsetof(AUTHZ_ACCESS_REQUEST, PrincipalSelfSid) + sizeof(void*))
        CaptureSid(slot, header, PackMemberParameter(parameter, principal),
            reinterpret_cast<uint64_t>(request.PrincipalSelfSid), AuditData | (5u << ValueDetailShift) | MemberData);
    if (captured < offsetof(AUTHZ_ACCESS_REQUEST, ObjectTypeListLength) + sizeof(ULONG) ||
        !request.ObjectTypeList || !request.ObjectTypeListLength) return;

    // Only complete retained object-list records supply a GUID pointer.
    auto table = slot->event.payloadBytes;
    captured = CopyValue(slot, header, PackMemberParameter(parameter, list), ValueKind::Bytes,
        reinterpret_cast<uint64_t>(request.ObjectTypeList), uint64_t{request.ObjectTypeListLength} * stride,
        {.flags = AuditData | (6u << ValueDetailShift) | MemberData});
    for (uint32_t index = 0; index < captured / sizeof(OBJECT_TYPE_LIST); ++index)
    {
        OBJECT_TYPE_LIST object{};
        memcpy(&object, Transport::Payload(slot) + table + sizeof(Value) + index * sizeof(object), sizeof(object));
        CopyValue(slot, header, PackMemberParameter(parameter, index * stride + objectType), ValueKind::Bytes,
            reinterpret_cast<uint64_t>(object.ObjectType), sizeof(GUID),
            {.flags = AuditData | (7u << ValueDetailShift) | MemberData});
    }
}

inline void CaptureSecurityDescriptors(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, uint32_t count)
{
    auto table = slot->event.payloadBytes;
    constexpr uint32_t stride = sizeof(void*);
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address, uint64_t{count} * sizeof(void*),
        {.flags = SecurityDescriptorData | (5u << ValueDetailShift)});
    for (uint32_t index = 0; index < captured / sizeof(void*); ++index)
    {
        uintptr_t descriptor = 0;
        memcpy(
            &descriptor, Transport::Payload(slot) + table + sizeof(Value) + index * sizeof(void*), sizeof(descriptor));
        CaptureSecurityDescriptor(slot, header, PackMemberParameter(parameter, index * stride), descriptor,
            SecurityDescriptorData | MemberData);
    }
}

template<class State>
void CaptureAuthzReply(State& call, Slot* slot, bool leaving, uint32_t parameter, bool audit)
{
    auto& capacity = call.captureLimits[parameter];
    if (!leaving) capacity = 0;
    else if (call.event.flags & (Failed | Skipped | Unwound)) return;
    auto header = call.transport->Header();
    auto offset = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, call.event.arguments[parameter],
        sizeof(AUTHZ_ACCESS_REPLY));
    if (captured < sizeof(DWORD)) return;
    AUTHZ_ACCESS_REPLY reply{};
    memcpy(&reply, Transport::Payload(slot) + offset + sizeof(Value), captured);
    if (!leaving)
    {
        capacity = reply.ResultListLength;
        return;
    }

    // Reply arrays are outputs; failed checks and absent audit requests cannot establish those results.
    auto count = std::min<uint64_t>(reply.ResultListLength, capacity);
    if (!count) return;
    for (uint32_t member = offsetof(AUTHZ_ACCESS_REPLY, GrantedAccessMask);
        member + sizeof(void*) <= captured; member += sizeof(void*))
    {
        if (member == offsetof(AUTHZ_ACCESS_REPLY, SaclEvaluationResults) && !audit) continue;
        uintptr_t pointer = 0;
        memcpy(&pointer, reinterpret_cast<const std::byte*>(&reply) + member, sizeof(pointer));
        CopyValue(slot, header, PackMemberParameter(parameter, member), ValueKind::Bytes, pointer,
            count * sizeof(DWORD), {.flags = MemberData});
    }
}
}

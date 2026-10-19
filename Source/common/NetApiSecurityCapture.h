#pragma once
#include "PointerCaptureValues.h"
#include <cstring>

namespace Detourist
{
inline void CaptureSid(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint32_t flags = 0)
{
    if (!address) return;
    auto offset = slot->event.payloadBytes;
    constexpr uint32_t sidHeaderBytes = offsetof(SID, SubAuthority);
    if (CopyValue(slot, header, parameter, ValueKind::Bytes, address, sidHeaderBytes,
        {.flags = flags | SidData}) != sidHeaderBytes) return;
    auto prefix = Transport::Payload(slot) + offset + sizeof(Value);
    auto revision = static_cast<uint8_t>(prefix[0]);
    auto count = static_cast<uint8_t>(prefix[1]);
    if (revision != SID_REVISION || count > SID_MAX_SUB_AUTHORITIES) return;

    // A complete SID header supplies the inline subauthority extent.
    slot->event.payloadBytes = offset;
    CopyValue(slot, header, parameter, ValueKind::Bytes, address,
        sidHeaderBytes + count * sizeof(DWORD), {.flags = flags | SidData});
}

inline void CaptureSecurityDescriptor(Slot* slot, SharedHeader* header, uint32_t parameterId, uint64_t address,
    uint32_t flags = NetApiData | ReferencedData | MemberData | SecurityDescriptorData)
{
    if (!address) return;
    // The common prefix selects the SDK header before any pointer or relative offset is inspected.
    auto snapshot = slot->event.payloadBytes;
    if (CopyValue(slot, header, parameterId, ValueKind::Bytes, address, 4, {.flags = flags}) != 4) return;
    auto data = Transport::Payload(slot) + snapshot + sizeof(Value);
    uint16_t control = 0;
    memcpy(&control, data + 2, sizeof(control));
    if (static_cast<uint8_t>(data[0]) != SECURITY_DESCRIPTOR_REVISION) return;
    auto relative = (control & SE_SELF_RELATIVE) != 0;
    auto bytes = relative ? sizeof(SECURITY_DESCRIPTOR_RELATIVE) : sizeof(SECURITY_DESCRIPTOR);
    slot->event.payloadBytes = snapshot;
    if (CopyValue(slot, header, parameterId, ValueKind::Bytes, address, bytes, {.flags = flags}) != bytes) return;
    data = Transport::Payload(slot) + snapshot + sizeof(Value);
    memcpy(&control, data + 2, sizeof(control));
    if (static_cast<uint8_t>(data[0]) != SECURITY_DESCRIPTOR_REVISION ||
        ((control & SE_SELF_RELATIVE) != 0) != relative) return;

    // Components retain their originating identity; the flag discriminator identifies each security part.
    for (uint32_t part = 1; part <= 4; ++part)
    {
        if ((part == 3 && !(control & SE_DACL_PRESENT)) || (part == 4 && !(control & SE_SACL_PRESENT))) continue;
        auto field = part <= 2 ? part - 1 : part == 3 ? 3u : 2u;
        uint64_t component = 0;
        if (relative)
        {
            uint32_t offset = 0;
            memcpy(&offset, data + 4 + field * sizeof(uint32_t), sizeof(offset));
            if (offset < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || offset % sizeof(uint32_t) ||
                address > UINT64_MAX - offset) continue;
            component = address + offset;
        }
        else memcpy(&component, data + offsetof(SECURITY_DESCRIPTOR, Owner) + field * sizeof(void*), sizeof(void*));
        if (!component) continue;
        auto selected = flags | (part << ValueDetailShift);
        if (part <= 2)
        {
            CaptureSid(slot, header, parameterId, component, selected);
            continue;
        }
        auto prefix = slot->event.payloadBytes;
        if (CopyValue(slot, header, parameterId, ValueKind::Bytes, component, sizeof(ACL),
            {.flags = selected}) != sizeof(ACL)) continue;
        auto captured = Transport::Payload(slot) + prefix + sizeof(Value);
        auto revision = static_cast<uint8_t>(captured[0]);
        uint16_t extent = 0;
        memcpy(&extent, captured + 2, sizeof(extent));
        if ((revision != ACL_REVISION && revision != ACL_REVISION_DS) || extent < sizeof(ACL)) continue;

        // Invalid prefixes remain visible; valid extents replace them with the globally bounded component.
        slot->event.payloadBytes = prefix;
        CopyValue(slot, header, parameterId, ValueKind::Bytes, component, extent, {.flags = selected});
    }
}
}

#pragma once
#include "PointerCaptureValues.h"
#include <winldap.h>
#include <algorithm>
#include <cstring>

namespace Detourist
{
inline void CaptureLdapBerValue(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint32_t flags = LdapData | (5u << ValueSubIndexShift),
    uint32_t dataFlags = LdapData | ReferencedData | (6u << ValueSubIndexShift))
{
    auto descriptor = slot->event.payloadBytes;
    if (CopyValue(slot, header, parameter, ValueKind::Bytes, address, sizeof(BERVAL),
        {.flags = flags}) != sizeof(BERVAL)) return;
    auto record = Transport::Payload(slot) + descriptor + sizeof(Value);
    CaptureRecordReference(slot, header, parameter, record, offsetof(BERVAL, bv_val),
        offsetof(BERVAL, bv_len), ValueKind::Bytes, dataFlags);
}

inline void CaptureLdapModifications(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, bool unicode)
{
    auto root = slot->event.payloadBytes;
    auto captured = CaptureTerminatedPointers(slot, header, parameter, address, LdapData);

    // Follow complete recorded pointer slots and descriptors, never an uncaptured caller field.
    for (uint32_t modification = 0; modification < captured / sizeof(uintptr_t); ++modification)
    {
        uintptr_t pointer = 0;
        memcpy(&pointer, Transport::Payload(slot) + root + sizeof(Value) + uint64_t{modification} * sizeof(uintptr_t),
            sizeof(uintptr_t));
        if (!pointer) break;
        auto identity = (modification << ValueSubIndexShift) | parameter;
        auto descriptor = slot->event.payloadBytes;
        if (CopyValue(slot, header, identity, ValueKind::Bytes, pointer, sizeof(LDAPModA),
            {.flags = LdapData | (1u << ValueSubIndexShift)}) != sizeof(LDAPModA)) continue;
        auto source = Transport::Payload(slot) + descriptor + sizeof(Value);
        uint32_t operation = 0;
        uintptr_t attribute = 0, values = 0;
        memcpy(&operation, source, sizeof(operation));
        memcpy(&attribute, source + offsetof(LDAPModA, mod_type), sizeof(attribute));
        memcpy(&values, source + offsetof(LDAPModA, mod_vals), sizeof(values));
        auto textKind = unicode ? ValueKind::Utf16 : ValueKind::Bytes;
        CopyValue(slot, header, identity, textKind, attribute, header->bufferLimit,
            {.terminated = true, .flags = LdapData | ReferencedData | (2u << ValueSubIndexShift)});
        if (!values) continue;
        auto table = slot->event.payloadBytes;
        auto valueBytes = CaptureTerminatedPointers(slot, header, identity, values,
            LdapData | ReferencedData | (3u << ValueSubIndexShift));
        for (uint32_t index = 0; index < valueBytes / sizeof(uintptr_t) && index <= UINT16_MAX; ++index)
        {
            uintptr_t value = 0;
            memcpy(&value, Transport::Payload(slot) + table + sizeof(Value) + uint64_t{index} * sizeof(uintptr_t),
                sizeof(uintptr_t));
            if (!value) break;
            auto flags = LdapData | ReferencedData | (index << ValueDetailShift);
            if (!(operation & LDAP_MOD_BVALUES))
            {
                CopyValue(slot, header, identity, textKind, value, header->bufferLimit,
                    {.terminated = true, .flags = flags | (4u << ValueSubIndexShift)});
                continue;
            }
            CaptureLdapBerValue(slot, header, identity, value, flags | (5u << ValueSubIndexShift),
                flags | (6u << ValueSubIndexShift));
        }
    }
}

inline void CaptureLdapControl(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address, bool unicode)
{
    auto descriptor = slot->event.payloadBytes;
    if (CopyValue(slot, header, parameter, ValueKind::Bytes, address, sizeof(LDAPControlA),
        {.flags = LdapData | (7u << ValueSubIndexShift)}) != sizeof(LDAPControlA)) return;

    // Follow only pointers whose complete descriptor is present in the recorded snapshot.
    auto record = Transport::Payload(slot) + descriptor + sizeof(Value);
    CaptureRecordReference(slot, header, parameter, record, offsetof(LDAPControlA, ldctl_oid), std::nullopt,
        unicode ? ValueKind::Utf16 : ValueKind::Bytes, LdapData | ReferencedData | (8u << ValueSubIndexShift));
    CaptureRecordReference(slot, header, parameter, record,
        offsetof(LDAPControlA, ldctl_value) + offsetof(BERVAL, bv_val),
        offsetof(LDAPControlA, ldctl_value) + offsetof(BERVAL, bv_len),
        ValueKind::Bytes, LdapData | ReferencedData | (9u << ValueSubIndexShift));
}

inline void CaptureLdapControls(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, bool unicode, bool array)
{
    if (!array)
    {
        CaptureLdapControl(slot, header, parameter, address, unicode);
        return;
    }
    CapturePointerRecords(slot, header, parameter, address, LdapData | (10u << ValueSubIndexShift),
        [&](uint32_t identity, uint64_t pointer)
    {
        CaptureLdapControl(slot, header, identity, pointer, unicode);
    });
}

inline void CaptureLdapBerValues(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address)
{
    // Each complete recorded pointer owns a separate counted binary descriptor and payload.
    CapturePointerRecords(slot, header, parameter, address, LdapData | (11u << ValueSubIndexShift),
        [&](uint32_t identity, uint64_t pointer)
    {
        CaptureLdapBerValue(slot, header, identity, pointer);
    });
}
}

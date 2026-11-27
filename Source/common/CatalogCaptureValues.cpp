#include "CatalogCaptureValues.h"
#include "NetApiRecordLayouts.h"
#include "ReplicationRecordLayouts.h"
#include <ntdsapi.h>
#include <schannel.h>

namespace Detourist
{
constexpr uint16_t MapiMultiValueFlag = 0x1000;
constexpr uint16_t MapiTypeShort = 2;
constexpr uint16_t MapiTypeLong = 3;
constexpr uint16_t MapiTypeFloat = 4;
constexpr uint16_t MapiTypeDouble = 5;
constexpr uint16_t MapiTypeCurrency = 6;
constexpr uint16_t MapiTypeAppTime = 7;
constexpr uint16_t MapiTypeError = 10;
constexpr uint16_t MapiTypeBoolean = 11;
constexpr uint16_t MapiTypeInt64 = 20;
constexpr uint16_t MapiTypeString8 = 0x1e;
constexpr uint16_t MapiTypeUnicode = 0x1f;
constexpr uint16_t MapiTypeSysTime = 64;
constexpr uint16_t MapiTypeClsid = 0x48;
constexpr uint16_t MapiTypeBinary = 0x102;
constexpr uint32_t WnodeFlagUseGuidPtr = 0x00080000;
constexpr uint32_t WnodeFlagUseMofPtr = 0x00100000;

void CaptureStringPairs(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint64_t bytes, bool wide, bool guarded)
{
    auto snapshot = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address, bytes, {.guarded = guarded});

    // Follow only pointer pairs fully retained in the bounded structure-array snapshot.
    for (uint32_t index = 0; index < captured / (2 * sizeof(uintptr_t)); ++index)
    {
        auto base = index * (2 * sizeof(uintptr_t));
        auto record = Transport::Payload(slot) + snapshot + sizeof(Value) + base;
        for (uint32_t field = 0; field < 2; ++field)
        {
            auto member = base + field * sizeof(uintptr_t);
            if (member >= ValueMemberMaxOffset) return;
            CaptureRecordReference(slot, header, PackMemberParameter(parameter, member),
                record, static_cast<uint32_t>(field * sizeof(uintptr_t)), std::nullopt,
                wide ? ValueKind::Utf16 : ValueKind::Bytes, MemberData | ReferencedData, sizeof(uintptr_t), guarded);
        }
    }
}

static void CaptureAviOptions(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address)
{
    if (!address) return;

    // The x64 compression options contain two independently sized, caller-owned buffers.
    auto offset = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address, 56);
    if (!captured) return;
    auto record = Transport::Payload(slot) + offset + sizeof(Value);
    for (uint32_t field : {24u, 40u})
        if (field + 12 <= captured)
            CaptureRecordReference(slot, header, PackMemberParameter(parameter, field), record,
                field, field + 8, ValueKind::Bytes, MemberData, 8);
}

void CaptureAviStreams(const Event& event, Slot* slot, SharedHeader* header)
{
    // Stream identities are opaque; only the options belonging to declared, recorded pairs are followed.
    auto streams = static_cast<int32_t>(event.arguments[3]);
    auto observed = std::clamp(streams, 0, static_cast<int32_t>((MaximumArguments - 4) / 2));
    for (int32_t index = 0; index < observed; ++index)
    {
        auto parameter = 5u + static_cast<uint32_t>(index) * 2u;
        CaptureAviOptions(slot, header, parameter, event.arguments[parameter]);
    }
}

struct MapiBinary
{
    uint32_t bytes;
    uintptr_t data;
};
struct MapiAddressEntry
{
    uint32_t reserved, count;
    uintptr_t properties;
};
struct MapiAddressList
{
    uint32_t count;
    MapiAddressEntry entries[1];
};
constexpr uint32_t MapiPropertyBytes = 8 + 2 * sizeof(uintptr_t);
constexpr uint32_t MapiAddressHeaderBytes = offsetof(MapiAddressList, entries);

uint64_t MapiAddressBytes(uint32_t count)
{
    return MapiAddressHeaderBytes + uint64_t{count} * sizeof(MapiAddressEntry);
}

void CaptureMapiProperties(Slot* slot, SharedHeader* header, uint32_t parameter, uint32_t snapshot)
{
    Value array{};
    if (slot->event.payloadBytes <= snapshot) return;
    memcpy(&array, Transport::Payload(slot) + snapshot, sizeof(array));
    auto count = std::min<uint32_t>(array.capturedBytes / MapiPropertyBytes, UINT16_MAX + 1u);

    // Follow only complete property descriptors present in the recorded array prefix.
    for (uint32_t index = 0; index < count; ++index)
    {
        auto source = Transport::Payload(slot) + snapshot + sizeof(Value) + uint64_t{index} * MapiPropertyBytes;
        uint16_t type = 0;
        uintptr_t pointer = 0;
        uint32_t elements = 0;
        memcpy(&type, source, sizeof(type));
        memcpy(&pointer, source + 8, sizeof(pointer));
        auto flags = (array.flags & MemberData) | ReferencedData | StringArrayElement | (index << ValueDetailShift);
        auto copy = [&](ValueKind kind, uint64_t address, uint64_t bytes, bool terminated = false)
        {
            return CopyValue(slot, header, parameter, kind, address, bytes, {.terminated = terminated, .flags = flags});
        };
        auto scalar = type & ~MapiMultiValueFlag;
        if (!(type & MapiMultiValueFlag))
        {
            if (scalar == MapiTypeString8 || scalar == MapiTypeUnicode)
                copy(scalar == MapiTypeUnicode ? ValueKind::Utf16 : ValueKind::Bytes,
                    pointer, header->bufferLimit, true);
            else if (scalar == MapiTypeClsid) copy(ValueKind::Bytes, pointer, sizeof(GUID));
            else if (scalar == MapiTypeBinary)
            {
                memcpy(&elements, source + 8, sizeof(elements));
                memcpy(&pointer, source + 8 + offsetof(MapiBinary, data), sizeof(pointer));
                copy(ValueKind::Bytes, pointer, elements);
            }
            continue;
        }

        // MAPI multi-valued properties carry an element count followed by their storage pointer.
        uint32_t width = scalar == MapiTypeShort || scalar == MapiTypeBoolean ? 2u :
            scalar == MapiTypeLong || scalar == MapiTypeFloat || scalar == MapiTypeError ? 4u :
            scalar == MapiTypeDouble || scalar == MapiTypeCurrency || scalar == MapiTypeAppTime ||
                scalar == MapiTypeInt64 || scalar == MapiTypeSysTime ? 8u :
            scalar == MapiTypeString8 || scalar == MapiTypeUnicode ? sizeof(uintptr_t) :
            scalar == MapiTypeClsid ? sizeof(GUID) : scalar == MapiTypeBinary ? sizeof(MapiBinary) : 0u;
        if (!width) continue;
        memcpy(&elements, source + 8, sizeof(elements));
        memcpy(&pointer, source + 8 + offsetof(MapiBinary, data), sizeof(pointer));
        auto offset = slot->event.payloadBytes;
        auto captured = copy(ValueKind::Bytes, pointer, uint64_t{elements} * width);
        if (scalar != MapiTypeString8 && scalar != MapiTypeUnicode && scalar != MapiTypeBinary) continue;
        for (uint32_t element = 0; element < captured / width; ++element)
        {
            auto item = Transport::Payload(slot) + offset + sizeof(Value) + uint64_t{element} * width;
            uintptr_t address = 0;
            uint32_t bytes = header->bufferLimit;
            if (scalar == MapiTypeBinary)
            {
                memcpy(&bytes, item, sizeof(bytes));
                memcpy(&address, item + offsetof(MapiBinary, data), sizeof(address));
            }
            else memcpy(&address, item, sizeof(address));
            copy(scalar == MapiTypeUnicode ? ValueKind::Utf16 : ValueKind::Bytes,
                address, bytes, scalar != MapiTypeBinary);
        }
    }
}

void CaptureMapiAddressList(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint64_t capacity)
{
    uint32_t count = 0;
    auto readable = ReadCaptureMemory(reinterpret_cast<void*>(address), &count, sizeof(count));
    auto snapshot = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address,
        std::min(MapiAddressBytes(readable ? count : 0), capacity));
    if (captured < MapiAddressHeaderBytes) return;
    count = std::min<uint32_t>(count, (captured - MapiAddressHeaderBytes) / sizeof(MapiAddressEntry));

    // Expand recipient properties only through entries fully present in the captured list.
    for (uint32_t index = 0; index < count; ++index)
    {
        auto source = Transport::Payload(slot) + snapshot + sizeof(Value) + MapiAddressHeaderBytes +
            uint64_t{index} * sizeof(MapiAddressEntry);
        uint32_t values = 0;
        uintptr_t pointer = 0;
        memcpy(&values, source + 4, sizeof(values));
        memcpy(&pointer, source + 8, sizeof(pointer));
        auto identity = PackMemberParameter(parameter,
            MapiAddressHeaderBytes + offsetof(MapiAddressEntry, properties) + index * sizeof(MapiAddressEntry));
        auto offset = slot->event.payloadBytes;
        if (CopyValue(slot, header, identity, ValueKind::Bytes, pointer, uint64_t{values} * MapiPropertyBytes,
            {.flags = MemberData | ReferencedData}))
            CaptureMapiProperties(slot, header, identity, offset);
    }
}

void CaptureX509Certificate(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    bool indirect)
{
    if (indirect) address = CapturePointer(slot, header, parameter, address);
    if (!address) return;

    // Follow only pointer fields present in the captured native X509Certificate descriptor.
    auto snapshot = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address, sizeof(X509Certificate));
    CaptureStringMember(slot, header, parameter, offsetof(X509Certificate, pszIssuer), false);
    CaptureStringMember(slot, header, parameter, offsetof(X509Certificate, pszSubject), false);
    if (captured < sizeof(X509Certificate)) return;
    uintptr_t key = 0;
    constexpr auto keyOffset = offsetof(X509Certificate, pPublicKey);
    memcpy(&key, Transport::Payload(slot) + snapshot + sizeof(Value) + keyOffset, sizeof(key));
    if (!key) return;

    // PctPublicKey retains its type and byte count together with the declared inline key bytes.
    uint32_t descriptor[2]{};
    auto readable = ReadCaptureMemory(reinterpret_cast<void*>(key), descriptor, sizeof(descriptor));
    CopyValue(slot, header, PackMemberParameter(parameter, keyOffset), ValueKind::Bytes, key,
        sizeof(descriptor) + (readable ? uint64_t{descriptor[1]} : 0), {.flags = MemberData});
}

void CaptureEtwDescriptors(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, uint32_t count, uint32_t format)
{
    auto snapshot = slot->event.payloadBytes;
    auto flags = EtwData | (format << ValueDetailShift);
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address, uint64_t{count} * 16,
        {.flags = flags});

    // Each complete descriptor retains its counted bytes without interpreting the event schema.
    for (uint32_t index = 0; index < std::min(captured / 16, format == 3 ? 16u : UINT32_MAX); ++index)
    {
        auto member = index * 16;
        if (member >= ValueMemberMaxOffset || SlotMaxRemaining(slot, header) < sizeof(Value)) return;
        auto record = Transport::Payload(slot) + snapshot + sizeof(Value) + member;
        CaptureRecordReference(slot, header, PackMemberParameter(parameter, member), record,
            0, 8, ValueKind::Bytes, flags | MemberData | ReferencedData, 8);
    }
}

void CaptureClassicEtwEvent(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, uint32_t headerBytes)
{
    if (headerBytes != 48 && headerBytes != 56) return;
    uint16_t bytes = 0;
    auto readable = ReadCaptureMemory(reinterpret_cast<void*>(address), &bytes, sizeof(bytes));
    auto snapshot = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address, readable ? bytes : headerBytes,
        {.flags = EtwData | ((headerBytes == 48 ? 1u : 2u) << ValueDetailShift)});
    if (captured < headerBytes || bytes < headerBytes || address > UINT64_MAX - headerBytes) return;
    uint32_t flags = 0;
    memcpy(&flags, Transport::Payload(slot) + snapshot + sizeof(Value) + 44, sizeof(flags));

    // Instance headers contain a registration handle where classic headers store their GUID pointer.
    if (headerBytes == 48 && flags & WnodeFlagUseGuidPtr)
    {
        uint64_t pointer = 0;
        memcpy(&pointer, Transport::Payload(slot) + snapshot + sizeof(Value) + 24, sizeof(pointer));
        if (pointer)
        {
            CopyValue(slot, header, PackMemberParameter(parameter, 24), ValueKind::Bytes, pointer, sizeof(GUID),
                {.flags = EtwData | (4u << ValueDetailShift) | MemberData | ReferencedData});
        }
    }
    if (flags & WnodeFlagUseMofPtr)
        CaptureEtwDescriptors(slot, header, parameter, address + headerBytes, (bytes - headerBytes) / 16, 3);
}

void CaptureNetApiRecords(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t output, uint64_t countPointer, uint32_t family, uint32_t level, bool singleRecord)
{
    auto address = CapturePointer(slot, header, parameter, output);
    if (!address) return;
    if (family == 7) level &= 0xffff;
    auto found = std::find_if(NetApiRecordLayouts.begin(), NetApiRecordLayouts.end(),
        [family, level](auto& layout) { return layout.family == family && layout.level == level; });
    if (found == NetApiRecordLayouts.end()) return;
    uint32_t count = singleRecord ? 1 : 0;
    if (!singleRecord && !ReadCaptureMemory(reinterpret_cast<void*>(countPointer), &count, sizeof(count))) return;
    auto id = static_cast<uint32_t>(found - NetApiRecordLayouts.begin());
    auto flags = NetApiData | ReferencedData | (id << ValueDetailShift);
    auto snapshot = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address, uint64_t{count} * found->bytes,
        {.flags = flags});
    if (!found->stringCount && !found->sidCount && !found->securityDescriptorOffset &&
        !found->bufferCount && !found->logonHoursOffset) return;

    // Pointer fields are followed only through complete records in the bounded root snapshot.
    for (uint32_t index = 0; index < captured / found->bytes; ++index)
    {
        auto base = index * found->bytes;
        auto record = Transport::Payload(slot) + snapshot + sizeof(Value) + base;
        for (uint32_t field = 0; field < found->stringCount; ++field)
        {
            auto member = base + found->stringOffsets[field];
            if (member >= ValueMemberMaxOffset) return;
            CaptureRecordReference(slot, header, PackMemberParameter(parameter, member), record,
                found->stringOffsets[field], std::nullopt, ValueKind::Utf16, flags | MemberData);
        }
        for (uint32_t field = 0; field < found->sidCount; ++field)
        {
            auto member = base + found->sidOffsets[field];
            if (member >= ValueMemberMaxOffset) return;
            uintptr_t sid = 0;
            memcpy(&sid, Transport::Payload(slot) + snapshot + sizeof(Value) + member, sizeof(sid));
            CaptureSid(slot, header, PackMemberParameter(parameter, member), sid, flags | MemberData);
        }
        if (found->securityDescriptorOffset)
        {
            // Only a complete SDK share record establishes its security-descriptor pointer.
            auto member = base + found->securityDescriptorOffset;
            if (member >= ValueMemberMaxOffset) return;
            uintptr_t descriptor = 0;
            memcpy(&descriptor, Transport::Payload(slot) + snapshot + sizeof(Value) + member, sizeof(descriptor));
            if (descriptor)
                CaptureSecurityDescriptor(slot, header, PackMemberParameter(parameter, member), descriptor);
        }
        for (uint32_t field = 0; field < found->bufferCount; ++field)
        {
            // The copied SDK length bounds opaque byte fields without interpreting their contents.
            auto member = base + found->buffers[field].pointer;
            if (member >= ValueMemberMaxOffset) continue;
            CaptureRecordReference(slot, header, PackMemberParameter(parameter, member), record,
                found->buffers[field].pointer, found->buffers[field].length,
                ValueKind::Bytes, flags | MemberData | NetApiBytesData);
        }
        if (found->logonHoursOffset)
        {
            // The SDK unit count bounds the referenced weekly bitmap to the SAMR maximum.
            auto member = base + found->logonHoursOffset;
            if (member >= ValueMemberMaxOffset) return;
            uint32_t units = 0;
            uintptr_t hours = 0;
            memcpy(&units, record + found->unitsPerWeekOffset, sizeof(units));
            memcpy(&hours, record + found->logonHoursOffset, sizeof(hours));
            if (!hours || !units || units > 10080) continue;
            CopyValue(slot, header, PackMemberParameter(parameter, member),
                ValueKind::Bytes, hours, (units + 7) / 8, {.flags = flags | MemberData | NetApiBytesData});
        }
    }
}

void CaptureReplicationInformation(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, uint32_t selector)
{
    auto addressValue = CapturePointer(slot, header, parameter, address);
    if (!addressValue || selector >= ReplicationLayouts.size()) return;
    address = addressValue;
    const auto layout = ReplicationLayouts[selector];
    uint32_t count = 0;
    auto readable = address <= UINT64_MAX - layout.countOffset && ReadCaptureMemory(
        reinterpret_cast<void*>(address + layout.countOffset), &count, sizeof(count));
    auto snapshot = slot->event.payloadBytes;
    auto flags = ReplicaData | ReferencedData | (selector << ValueReplicaShift);
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address,
        layout.headerBytes + (readable ? uint64_t{count} * layout.elementBytes : 0), {.flags = flags});
    if (captured < layout.headerBytes || !layout.stringCount && !layout.binaryOffset) return;
    memcpy(&count, Transport::Payload(slot) + snapshot + sizeof(Value) + layout.countOffset, sizeof(count));
    count = std::min<uint32_t>(count, (captured - layout.headerBytes) / layout.elementBytes);

    // Referenced data is followed only through complete records retained in the bounded result snapshot.
    for (uint32_t index = 0; index < count; ++index)
    {
        auto base = layout.headerBytes + index * layout.elementBytes;
        auto record = Transport::Payload(slot) + snapshot + sizeof(Value) + base;
        for (uint32_t field = 0; field < layout.stringCount; ++field)
        {
            auto member = base + layout.stringOffsets[field];
            CaptureRecordReference(slot, header, PackMemberParameter(parameter, member), record,
                layout.stringOffsets[field], std::nullopt, ValueKind::Utf16, flags | MemberData);
        }
        if (!layout.binaryOffset) continue;
        auto member = base + layout.binaryOffset;
        CaptureRecordReference(slot, header, PackMemberParameter(parameter, member), record,
            layout.binaryOffset, layout.binaryCountOffset, ValueKind::Bytes, flags | MemberData);
    }
}

void CaptureSyncAllErrors(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address, bool wide)
{
    // Each complete pointer and error descriptor establishes its own two bounded server-name strings.
    CapturePointerRecords(slot, header, parameter, address, SyncAllData | (1u << ValueSyncAllShift),
        [&](uint32_t identity, uint64_t pointer)
    {
        auto descriptor = slot->event.payloadBytes;
        if (CopyValue(slot, header, identity, ValueKind::Bytes, pointer, sizeof(DS_REPSYNCALL_ERRINFOA),
            {.flags = SyncAllData | (2u << ValueSyncAllShift)}) != sizeof(DS_REPSYNCALL_ERRINFOA)) return;
        auto record = Transport::Payload(slot) + descriptor + sizeof(Value);
        constexpr uint32_t members[]{offsetof(DS_REPSYNCALL_ERRINFOA, pszSvrId),
            offsetof(DS_REPSYNCALL_ERRINFOA, pszSrcId)};
        for (auto member : members)
        {
            CaptureRecordReference(slot, header, identity, record, member, std::nullopt,
                wide ? ValueKind::Utf16 : ValueKind::Bytes,
                SyncAllData | ReferencedData | (3u << ValueSyncAllShift) | (member << ValueDetailShift));
        }
    });
}

void CaptureSamReferences(Slot* slot, SharedHeader* header, uint32_t parameter, uint32_t snapshot,
    uint32_t captured, bool sids)
{
    struct Entry
    {
        uintptr_t identity;
        uint16_t length, maximum;
        uintptr_t name;
    };
    static_assert(sizeof(Entry) == (sizeof(void*) == 8 ? 24 : 12));

    // Only complete enumeration records establish their counted strings and optional SID pointers.
    for (uint32_t index = 0; index < captured / sizeof(Entry); ++index)
    {
        auto base = index * static_cast<uint32_t>(sizeof(Entry));
        if (base + offsetof(Entry, name) >= ValueMemberMaxOffset) break;
        Entry entry{};
        memcpy(&entry, Transport::Payload(slot) + snapshot + sizeof(Value) + base, sizeof(entry));
        if (entry.name && entry.length && entry.maximum)
        {
            CopyValue(slot, header, PackMemberParameter(parameter, base + offsetof(Entry, name)),
                ValueKind::Utf16, entry.name, std::min(entry.length, entry.maximum),
                {.flags = MemberData | ReferencedData});
        }
        if (sids) CaptureSid(slot, header, PackMemberParameter(parameter, base),
            entry.identity, MemberData | ReferencedData);
    }
}
}

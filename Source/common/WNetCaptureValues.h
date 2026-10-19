#pragma once
#include "CatalogCaptureValues.h"
#include "NetApiRecordLayouts.h"

namespace Detourist
{
inline void CaptureWNetString(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    bool wide, uint32_t flags, uint64_t buffer, uint64_t capacity)
{
    if (!address) return;
    auto length = UINT64_MAX;
    if (buffer) length = address >= buffer && address - buffer < capacity ? capacity - (address - buffer) : 0;
    CopyValue(slot, header, parameter, wide ? ValueKind::Utf16 : ValueKind::Bytes, address, length,
        {.terminated = true, .flags = flags | (length ? 0u : Unreadable)});
}

inline void CaptureWNetRecords(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint32_t count, bool wide, uint64_t capacity = UINT64_MAX, uint32_t stringFields = 0b1111)
{
    if (!address || !count || !capacity) return;
    auto found = std::find_if(NetApiRecordLayouts.begin(), NetApiRecordLayouts.end(),
        [wide](const auto& layout) { return layout.family == 14 && layout.level == static_cast<uint32_t>(wide); });
    if (found == NetApiRecordLayouts.end()) return;
    auto flags = NetApiData | ReferencedData |
        (static_cast<uint32_t>(found - NetApiRecordLayouts.begin()) << ValueDetailShift);
    auto snapshot = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address,
        std::min(uint64_t{count} * found->bytes, capacity),
        {.flags = flags});

    // Only complete recorded structures establish pointers; returned strings must remain inside the caller's buffer.
    for (uint32_t index = 0; index < captured / found->bytes; ++index)
        for (uint32_t field = 0; field < found->stringCount; ++field)
        {
            if (!(stringFields & (1u << field))) continue;
            if (header->payloadCapacity - slot->event.payloadBytes < sizeof(Value)) return;
            auto member = index * found->bytes + found->stringOffsets[field];
            uint64_t text = 0;
            memcpy(&text, Transport::Payload(slot) + snapshot + sizeof(Value) + member, sizeof(text));
            CaptureWNetString(slot, header, PackMemberParameter(parameter, member), text, wide, flags | MemberData,
                capacity == UINT64_MAX ? 0 : address, capacity);
        }
}

template<class State>
bool CaptureWNetParameters(State& call, Slot* slot, bool leaving, std::string_view module, std::string_view name,
    std::span<const ExportParameter> parameters, std::span<const ExportMember> members)
{
    auto provider = name.starts_with("NP");
    if (!provider && (!name.starts_with("WNet") && !name.starts_with("Multinet") ||
        (module != "mpr.dll" && module != "kernel32.dll" && module != "unicows.dll")))
        return false;
    auto enumerate = name == "WNetEnumResourceA" || name == "WNetEnumResourceW" || name == "NPEnumResource";
    auto open = name == "WNetOpenEnumA" || name == "WNetOpenEnumW" || name == "NPOpenEnum";
    auto info = name == "WNetGetResourceInformationA" || name == "WNetGetResourceInformationW" ||
        name == "NPGetResourceInformation";
    auto parent = name == "WNetGetResourceParentA" || name == "WNetGetResourceParentW" || name == "NPGetResourceParent";
    auto add = name == "WNetAddConnection2A" || name == "WNetAddConnection2W" || name == "NPAddConnection";
    auto addOwner = name == "WNetAddConnection3A" || name == "WNetAddConnection3W" || name == "NPAddConnection3" ||
        name == "NPSearchDialog";
    auto add4 = name == "WNetAddConnection4A" || name == "WNetAddConnection4W" || name == "NPAddConnection4";
    auto use = name == "WNetUseConnectionA" || name == "WNetUseConnectionW";
    auto use4 = name == "WNetUseConnection4A" || name == "WNetUseConnection4W";
    auto performance = name == "MultinetGetConnectionPerformanceA" || name == "MultinetGetConnectionPerformanceW";
    if (!(enumerate || open || info || parent || add || addOwner || add4 || use || use4 || performance)) return false;
    auto expected = use4 ? 10u : use ? 8u : add4 ? 7u : open || addOwner ? 5u : performance ? 2u :
        parent || name == "NPAddConnection" ? 3u : 4u;
    if (parameters.size() != expected) return false;
    if (call.event.flags & Unwound || leaving && (call.event.flags & Skipped)) return true;
    auto header = call.transport->Header();
    const auto& args = call.event.arguments;
    auto wide = provider || name.back() == 'W';
    auto input = open ? 3u : addOwner || add4 || use || use4 ? 1u : 0u;
    auto output = enumerate ? 2u : 1u;
    auto size = enumerate ? 3u : 2u;
    auto result = static_cast<uint32_t>(call.event.result);

    // Retain generic scalar/string capture while replacing NETRESOURCE buffers with counted records.
    std::array<ExportParameter, MaximumArguments> adjusted{};
    std::copy(parameters.begin(), parameters.end(), adjusted.begin());
    if (!enumerate) adjusted[input].flags = 0;
    if (enumerate || info || parent) adjusted[output].flags = 0;
    if (info) adjusted[3].flags = 0;
    if (open && leaving && result) adjusted[4].flags = 0;
    if (!leaving && (enumerate || info || parent))
    {
        call.captureLimits[output] = SafeDword(args[size]);
        if (enumerate) call.captureLimits[0] = SafeDword(args[1]);
    }
    CaptureCatalogValues(call, slot, leaving, {adjusted.data(), parameters.size()}, members);
    if (!leaving)
    {
        // Queries ignore local names and comments; connection inputs also leave comments undefined.
        auto fields = open || name == "NPSearchDialog" ? 0b1111u : info || parent ? 0b1010u : 0b1011u;
        if (!enumerate) CaptureWNetRecords(slot, header, input, args[input], 1, wide, UINT64_MAX, fields);
        return true;
    }
    if (result || !(enumerate || info || parent)) return true;

    // Capacity errors and exhausted enumerations leave buffer contents undefined, unlike successful short pages.
    auto capacity = std::min(call.captureLimits[output], uint64_t{SafeDword(args[size])});
    auto count = enumerate ? std::min(uint64_t{SafeDword(args[1])}, call.captureLimits[0]) : 1;
    CaptureWNetRecords(slot, header, output, args[output], static_cast<uint32_t>(count), wide, capacity);
    if (info && args[3])
    {
        auto offset = slot->event.payloadBytes;
        CopyValue(slot, header, 3, ValueKind::Scalar, args[3], sizeof(uint64_t));
        if (slot->event.payloadBytes < offset + sizeof(Value) + sizeof(uint64_t)) return true;
        uint64_t text = 0;
        memcpy(&text, Transport::Payload(slot) + offset + sizeof(Value), sizeof(text));
        if (args[output]) CaptureWNetString(slot, header, 3, text, wide, ReferencedData, args[output], capacity);
    }
    return true;
}
}

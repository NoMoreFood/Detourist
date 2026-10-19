#include "InstructionCapture.h"
#include "LdapCaptureValues.h"
#include <algorithm>
#include <cstring>

namespace Detourist
{
static void CaptureBerVector(Slot* slot, SharedHeader* header, uint32_t parameter,
    uint64_t address, bool octets)
{
    if (!address) return;
    const auto limit = std::min<uint32_t>(header->bufferLimit, static_cast<uint32_t>(MaxFormatStringBytes));
    uint32_t bytes = 0;
    bool terminated = false;

    // Discover only the bounded pointer prefix and follow pointers present in its recorded snapshot.
    while (bytes + sizeof(uintptr_t) <= limit)
    {
        uintptr_t pointer = 0;
        if (address > UINT64_MAX - bytes || !ReadCaptureMemory(
            reinterpret_cast<void*>(address + bytes), &pointer, sizeof(pointer))) break;
        bytes += sizeof(pointer);
        if (!pointer) { terminated = true; break; }
    }
    auto offset = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, parameter, ValueKind::Bytes, address, bytes ? bytes : sizeof(uintptr_t),
        {.flags = ReferencedData | (terminated ? 0u : Truncated)});
    for (uint32_t element = 0; element < captured / sizeof(uintptr_t); ++element)
    {
        uintptr_t pointer = 0;
        memcpy(&pointer, Transport::Payload(slot) + offset + sizeof(Value) + uint64_t{element} * sizeof(uintptr_t),
            sizeof(uintptr_t));
        if (!pointer) break;
        auto flags = ReferencedData | StringArrayElement | (element << ValueDetailShift);
        if (octets) CaptureLdapBerValue(slot, header, parameter, pointer, flags, flags | ReferencedData);
        else CopyValue(slot, header, parameter, ValueKind::Bytes, pointer, header->bufferLimit,
            {.terminated = true, .flags = flags});
    }
}

uint32_t CaptureRuntimeBer(InstructionFrame& call, Slot* slot, bool leaving)
{
    if (_stricmp(call.definition->metadata.module, "wldap32.dll")) return 0;
    const bool encode = !strcmp(call.definition->metadata.name, "ber_printf");
    if (!encode && strcmp(call.definition->metadata.name, "ber_scanf")) return 0;
    const auto& definition = *call.definition->runtime;
    if (definition.rawTailStart != 2) return 0;
    const auto format = call.event.arguments[1];
    uint32_t next = definition.rawTailStart, recognized = 0;
    auto header = call.transport->Header();
    const bool capture = encode ? !leaving : leaving && static_cast<uint32_t>(call.event.result) != UINT32_MAX;

    // The decoder skips unknown tokens without consuming arguments; the encoder stops at them.
    for (uint32_t position = 0; position < MaxFormatStringBytes; ++position)
    {
        char token = 0;
        if (format > UINT64_MAX - position || !ReadCaptureMemory(
            reinterpret_cast<void*>(format + position), &token, sizeof(token))) break;
        if (!token)
        {
            // A complete format establishes the unused tail, which must not be probed as pointer arguments.
            recognized |= static_cast<uint32_t>(((uint64_t{1} << call.definition->metadata.argumentCount) - 1) &
                ~((uint64_t{1} << next) - 1));
            break;
        }
        if (token == '{' || token == '}' || token == '[' || token == ']' || token == 'n' ||
            !encode && (token == 'x' || token == 't')) continue;
        const bool scalar = token == 'b' || token == 'e' || token == 'i' || encode && token == 't';
        const bool pair = encode ? token == 'o' || token == 'X' : token == 'B';
        const bool vector = token == 'v' || token == 'V';
        const bool string = encode ? token == 's' : token == 'a';
        const bool octets = !encode && token == 'O';
        if (!scalar && !pair && !vector && !string && !octets)
        {
            if (encode) break;
            continue;
        }
        const auto count = pair ? 2u : 1u;
        if (next + count > call.definition->metadata.argumentCount || next + count > MaximumArguments) break;
        const auto parameter = next;
        for (uint32_t index = 0; index < count; ++index) recognized |= uint32_t{1} << next++;
        if (!capture) continue;
        auto address = call.event.arguments[parameter];
        if (scalar)
        {
            if (!encode) CopyValue(slot, header, parameter, ValueKind::Scalar, address, sizeof(uint32_t));
            continue;
        }

        // Decoder allocations are read only after success, retaining the returned pointer before its contents.
        uint32_t length = pair ? static_cast<uint32_t>(call.event.arguments[parameter + 1]) : 0;
        bool lengthReadable = true;
        if (pair && !encode)
        {
            auto offset = slot->event.payloadBytes;
            lengthReadable = CopyValue(slot, header, parameter + 1, ValueKind::Scalar,
                call.event.arguments[parameter + 1],
                sizeof(length)) == sizeof(length);
            if (lengthReadable)
                memcpy(&length, Transport::Payload(slot) + offset + sizeof(Value), sizeof(length));
        }
        if (!encode) address = CapturePointer(slot, header, parameter, address);
        if (vector) CaptureBerVector(slot, header, parameter, address, token == 'V');
        else if (octets) CaptureLdapBerValue(slot, header, parameter, address, ReferencedData, ReferencedData);
        else if (string) CopyValue(slot, header, parameter, ValueKind::Bytes, address,
            header->bufferLimit, {.terminated = true, .flags = encode ? 0u : ReferencedData});
        else
        {
            if (!lengthReadable) continue;
            uint64_t bytes = token == 'X' || token == 'B' ? (uint64_t{length} + 7) / 8 : length;
            if (bytes) CopyValue(slot, header, parameter, ValueKind::Bytes, address,
                bytes, {.flags = encode ? 0u : ReferencedData});
        }
    }
    return recognized;
}
}

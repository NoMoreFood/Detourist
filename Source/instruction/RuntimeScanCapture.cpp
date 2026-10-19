#include "InstructionCapture.h"
#include <algorithm>
#include <iterator>

namespace Detourist
{
FormatCaptureResult CaptureRuntimeScan(InstructionFrame& call, Slot* slot, bool leaving)
{
    const auto& definition = *call.definition->runtime;
    const auto module = call.definition->metadata.module;
    if (!IsFormatCrt(module)) return {};
    const bool ucrt = !_strnicmp(module, "ucrt", 4);
    const bool native = !_stricmp(module, "ntdll.dll");
    const bool systemCrt = native || !_stricmp(module, "msvcrt.dll");
    auto name = call.definition->metadata.name;
    if (!strncmp(name, "_o_", 3)) name += 3;
    uint32_t format = 0, list = UINT32_MAX;
    bool wide = false, secure = false, legacyWide = true;

    // Common UCRT entry points carry their secure-buffer and character-width contracts in the option bits.
    constexpr struct { const char* name; uint32_t format, list; bool wide; } common[]{
        {"__stdio_common_vsscanf", 3, 5, false}, {"__stdio_common_vswscanf", 3, 5, true},
        {"__stdio_common_vfscanf", 2, 4, false}, {"__stdio_common_vfwscanf", 2, 4, true},
        {"__conio_common_vcscanf", 1, 3, false}, {"__conio_common_vcwscanf", 1, 3, true}};
    auto entry = std::find_if(std::begin(common), std::end(common), [&](const auto& item)
        { return !strcmp(name, item.name); });
    if (entry != std::end(common))
    {
        if (!ucrt || call.event.arguments[0] & ~uint64_t{7}) return {};
        format = entry->format;
        list = entry->list;
        wide = entry->wide;
        secure = (call.event.arguments[0] & 1) != 0;
        legacyWide = (call.event.arguments[0] & 2) != 0;
    }
    else
    {
        char base[64]{};
        if (*name == '_') ++name;
        auto length = strlen(name);
        if (length >= sizeof(base)) return {};
        memcpy(base, name, length + 1);
        const bool localized = length >= 2 && !strcmp(base + length - 2, "_l");
        if (localized) base[length -= 2] = 0;
        secure = length >= 2 && !strcmp(base + length - 2, "_s");
        if (secure) base[length -= 2] = 0;
        const bool listed = base[0] == 'v';
        auto function = base + listed;
        constexpr struct { const char* name; uint32_t format; bool wide; } direct[]{
            {"scanf", 0, false}, {"wscanf", 0, true}, {"cscanf", 0, false}, {"cwscanf", 0, true},
            {"fscanf", 1, false}, {"fwscanf", 1, true}, {"sscanf", 1, false}, {"swscanf", 1, true},
            {"snscanf", 2, false}, {"snwscanf", 2, true}};
        auto selected = std::find_if(std::begin(direct), std::end(direct), [&](const auto& item)
            { return !strcmp(function, item.name); });
        if (selected == std::end(direct)) return {};
        format = selected->format;
        wide = selected->wide;
        auto tail = format + 1 + localized;
        if (listed) list = tail;
        else if (definition.rawTailStart != tail) return {};
    }
    const bool listed = list != UINT32_MAX;
    if (listed && (definition.rawTailStart || definition.argumentCount != list + 1)) return {};
    if (listed && leaving && !call.formatOutputs) return {};
    const auto address = call.event.arguments[format];
    if (address < MinimumUserAddress || address > MaximumUserAddress - MaxFormatStringBytes) return {};
    const uint32_t unit = wide ? 2u : 1u;
    const uint32_t count = listed ? MaximumArguments : call.definition->metadata.argumentCount;
    uint32_t next = listed ? 0 : definition.rawTailStart, recognized = 0, position = 0, assignments = 0;
    uint8_t characterWidths[256]{};
    bool localeReady = false, localeUtf8 = false;
    uint16_t token = 0;
    auto read = [&]()
    {
        token = 0;
        return position < MaxFormatStringBytes / unit && ReadCaptureMemory(
            reinterpret_cast<void*>(address + uint64_t{position++} * unit), &token, unit);
    };
    auto argument = [&](uint32_t index, uint64_t& value)
    {
        if (index >= count) return false;
        if (!listed) { value = call.event.arguments[index]; return true; }
        auto pointer = call.event.arguments[list];
        return pointer >= MinimumUserAddress && pointer < UINTPTR_MAX - MaximumArguments * sizeof(void*) &&
               ReadCaptureMemory(
                   reinterpret_cast<void*>(pointer + uint64_t{index} * sizeof(void*)), &value, sizeof(void*));
    };
    auto failure = [&]() { return FormatCaptureResult{recognized}; };
    if (!read()) return failure();

    // Suppressed conversions consume input only; successful assignments determine which destinations are complete.
    while (token)
    {
        if (!wide && token >= 128) return failure();
        if (token != '%') { if (!read()) return failure(); continue; }
        if (!read()) return failure();
        if (token == '%') { if (!read()) return failure(); continue; }
        const bool suppressed = token == '*';
        if (suppressed && !read()) return failure();
        uint64_t width = 0;
        while (token >= '0' && token <= '9')
        {
            width = std::min<uint64_t>(UINT32_MAX, width * 10 + token - '0');
            if (!read()) return failure();
        }
        uint16_t modifier = 0;
        if (token && token < 128 && strchr("hlLwjztI", token))
        {
            modifier = token;
            if (!read()) return failure();
            if (modifier == 'h' && token == 'h' || modifier == 'l' && token == 'l')
            {
                modifier = modifier == 'h' ? 'H' : 'q';
                if (!read()) return failure();
            }
            else if (modifier == 'I' && (token == '3' || token == '6'))
            {
                modifier = token;
                if (!read() || token != (modifier == '3' ? '2' : '4') || !read()) return failure();
            }
            if (!ucrt && !systemCrt && (modifier == 'j' || modifier == 'z' || modifier == 't'))
                return failure();
        }
        const auto conversion = token;
        const bool characters = token == 'c' || token == 'C';
        const bool string = token == 's' || token == 'S' || token == '[';
        const bool written = token == 'n';
        const bool integer = token && token < 128 && strchr("diuoxX", token);
        const bool floating = !native && token && token < 128 && strchr(ucrt ? "fFeEgGaA" : "feEgG", token);
        if (!characters && !string && !written && !integer && !floating && token != 'p') return failure();
        if (floating && modifier && modifier != 'l' && modifier != 'L' ||
            (integer || written) && (modifier == 'w' || modifier == 'L') || conversion == 'p' && modifier)
            return failure();
        if ((characters || string) && modifier && modifier != 'h' && modifier != 'l' && modifier != 'L' &&
            modifier != 'w' && !(ucrt && modifier == 'q')) return failure();
        if (token == '[')
        {
            if (!read()) return failure();
            if (token == '^' && !read()) return failure();
            if (token == ']' && !read()) return failure();
            while (token && token != ']') if (!read()) return failure();
            if (!token) return failure();
        }
        if (!read()) return failure();
        if (suppressed) continue;
        const auto index = next;
        const auto slots = secure && (characters || string) ? 2u : 1u;
        uint64_t pointer = 0, capacity = UINT32_MAX;
        if (next + slots > count || !argument(next, pointer) || slots == 2 && !argument(next + 1, capacity))
            return failure();
        capacity = static_cast<uint32_t>(capacity);
        for (uint32_t ordinal = next; ordinal < next + slots; ++ordinal)
        {
            recognized |= uint32_t{1} << ordinal;
            if (!listed || leaving) continue;
            auto value = ordinal == next ? pointer : capacity;
            CopyValue(slot, call.transport->Header(), list, ValueKind::Scalar, reinterpret_cast<uint64_t>(&value),
                sizeof(value), {.flags = StringArrayElement | (ordinal << ValueDetailShift)});
        }
        next += slots;
        if (!leaving) call.formatOutputs = true;
        if (!written) ++assignments;
        if (call.event.flags & Skipped || !written && (!leaving ||
            static_cast<int32_t>(call.event.result) < static_cast<int32_t>(assignments))) continue;

        // Count storage is observed on both sides because a later literal or conversion can fail after its write.
        uint64_t bytes = conversion == 'p' || modifier == 'q' || modifier == '6' || modifier == 'I' ||
            modifier == 'j' || modifier == 'z' || modifier == 't' ? 8u :
            modifier == 'h' ? 2u : modifier == 'H' && ucrt ? 1u : 4u;
        auto kind = ValueKind::Bytes;
        bool multibyteCharacters = false, destinationBuffer = false;
        if (floating) bytes = modifier == 'l' || modifier == 'L' ? 8 : 4;
        if (characters || string)
        {
            const bool wideValue = modifier == 'l' || modifier == 'q' || modifier == 'L' || modifier == 'w' ||
                modifier != 'h' && modifier != 'H' && (wide ?
                    legacyWide && conversion != 'C' && conversion != 'S' :
                    conversion == 'C' || conversion == 'S');
            kind = wideValue ? ValueKind::Utf16 : ValueKind::Bytes;
            bytes = (characters ? std::min(width ? width : 1, capacity) : capacity) * (wideValue ? 2u : 1u);
            multibyteCharacters = characters && wide && !wideValue;

            // Native secure cross-encoding writes need the declared buffer, including gaps and embedded zeroes.
            destinationBuffer = native && secure && wideValue != wide;
            if (destinationBuffer)
            {
                kind = ValueKind::Bytes;
                bytes = capacity * (wideValue ? 2u : 1u);
            }
        }

        // Wide scanners encode narrow character destinations using their thread locale, including localized entries.
        bool uncertain = false;
        if (multibyteCharacters && !native)
        {
            const auto requested = width ? width : 1;
            uint64_t encoded = 0, consumed = 0;
            while (consumed < requested && encoded < capacity && encoded < call.transport->Header()->bufferLimit)
            {
                uint8_t first = 0;
                if (!ReadCaptureMemory(reinterpret_cast<void*>(pointer + encoded), &first, 1)) break;
                if (first >= 128 && !localeReady)
                {
                    localeReady = FormatCharacterWidths(call, 0, ucrt, characterWidths, localeUtf8, true);
                    if (!localeReady) break;
                }
                const auto size = first < 128 ? 1u : characterWidths[first];
                if (size > capacity - encoded) break;
                encoded += size;
                consumed += localeUtf8 && size == 4 ? 2 : 1;
            }
            uncertain = consumed < requested;
            bytes = std::max(bytes, encoded);
        }
        // Unknown encodings and capped prefixes do not establish the complete destination extent.
        const auto flags = listed ? StringArrayElement | (index << ValueDetailShift) | ReferencedData : 0u;
        CopyValue(slot, call.transport->Header(), listed ? list : index, kind, pointer, bytes,
            {.terminated = string && !destinationBuffer, .unknownExtent = uncertain,
             .flags = flags | (uncertain ? Truncated : 0u)});
    }
    if (!listed)
    {
        const auto available = count < 32 ? (uint32_t{1} << count) - 1 : UINT32_MAX;
        const auto consumed = next < 32 ? (uint32_t{1} << next) - 1 : UINT32_MAX;
        recognized |= available & ~consumed;
    }
    return {recognized, static_cast<uint8_t>(format + 1), static_cast<uint8_t>(listed ? list + 1 : 0),
        static_cast<uint8_t>(next), true};
}
}

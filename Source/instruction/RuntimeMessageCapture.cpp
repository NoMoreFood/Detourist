#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "InstructionCapture.h"
#include <algorithm>
#include <iterator>

namespace Detourist
{
constexpr size_t ShellMessageBoxMaxChars = 514;
constexpr uint16_t MessageAnsiStringContract = 0x100;
constexpr uint16_t MessageWideStringContract = 0x101;
constexpr uint16_t MessagePointerContract = 0x200;
constexpr uint16_t MessageAnsiCountedContract = 0x300;
constexpr uint16_t MessageWideCountedContract = 0x301;

static bool ResourceString(uint64_t module, uint16_t identifier, bool wide,
    wchar_t (&text)[ShellMessageBoxMaxChars], uint32_t& length)
{
    // Use the provider's loader so language preferences, MUI satellites and data-file handles resolve identically.
    auto native = dr_lookup_module_by_name("ntdll.dll");
    const auto load = reinterpret_cast<decltype(&RtlLoadString)>(
        native ? dr_get_proc_address(native->handle, "RtlLoadString") : nullptr);
    if (native) dr_free_module_data(native);
    if (!load) return false;
    const auto context = dr_get_current_drcontext();
    constexpr auto state = static_cast<dr_state_flags_t>(DR_STATE_PEB | DR_STATE_TEB_MISC);
    dr_switch_to_app_state_ex(context, state);
    auto teb = NtCurrentTeb();
    const auto error = teb->LastErrorValue;
    const auto status = teb->LastStatusValue;
    const auto previous = teb->ResourceRetValue;
    LDR_RESLOADER_RET resource{};
    teb->ResourceRetValue = &resource;
    if (!module) module = reinterpret_cast<uint64_t>(NtCurrentPeb()->ImageBaseAddress);
    uint16_t signature = 0, count = 0;
    PCWSTR source = nullptr;
    bool valid = ReadCaptureMemory(reinterpret_cast<void*>(module & ~uint64_t{3}),
        &signature, sizeof(signature)) && signature == IMAGE_DOS_SIGNATURE && NT_SUCCESS(
        load(reinterpret_cast<void*>(module), identifier, nullptr, 1, &source, &count, nullptr, nullptr));
    if (valid && wide)
    {
        // ShellMessageBox loads at most 513 characters and appends its own terminator.
        length = std::min<uint32_t>(count, std::size(text) - 1);
        valid = !length || ReadCaptureMemory(source, text, length * sizeof(wchar_t));
        text[length] = 0;
    }
    else if (valid)
    {
        // Bound the read before conversion; a surrogate pair can consume two code units per output character.
        wchar_t input[2 * (std::size(text) - 1)];
        const auto units = std::min<uint32_t>(count, std::size(input));
        ULONG bytes = 0;
        valid = (!units || ReadCaptureMemory(source, input, units * sizeof(wchar_t))) &&
            NT_SUCCESS(RtlUnicodeToMultiByteN(reinterpret_cast<char*>(text), std::size(text) - 1,
                &bytes, input, units * sizeof(wchar_t)));
        length = bytes;
        reinterpret_cast<char*>(text)[length] = 0;
    }

    // Capture must not replace a pending application resource lookup or its error state.
    teb->ResourceRetValue = previous;
    teb->LastStatusValue = status;
    teb->LastErrorValue = error;
    dr_switch_to_dr_state_ex(context, state);
    return valid;
}

FormatCaptureResult CaptureRuntimeMessage(InstructionFrame& call, Slot* slot, bool leaving)
{
    // Message templates and insert strings are input-only, including calls skipped at a breakpoint.
    constexpr uint32_t first = 5, tail = UINT32_MAX << first;
    if (leaving) return {tail};
    const bool wide = !strcmp(call.definition->runtime->name, "ShellMessageBoxW");
    const auto width = wide ? 2u : 1u;
    const auto address = call.event.arguments[2];
    for (uint32_t index : {2u, 3u})
        if (call.event.arguments[index] >= MinimumUserAddress && call.event.arguments[index] < MaximumUserAddress)
            CopyValue(slot, call.transport->Header(), index, wide ? ValueKind::Utf16 : ValueKind::Bytes,
                call.event.arguments[index], UINT64_MAX, {.terminated = true});
    if (!address) return {tail, 3, 0, first, true};

    // A resource identifier selects the template from the supplied module's string table.
    wchar_t resource[ShellMessageBoxMaxChars];
    uint32_t resourceLength = 0;
    const bool resolved = address < MinimumUserAddress &&
        ResourceString(call.event.arguments[0], static_cast<uint16_t>(address), wide, resource, resourceLength);
    if (resolved)
        CopyValue(slot, call.transport->Header(), 2, wide ? ValueKind::Utf16 : ValueKind::Bytes,
            reinterpret_cast<uint64_t>(resource), (uint64_t{resourceLength} + 1) * width);
    else if (address < MinimumUserAddress || address >= MaximumUserAddress - MaxFormatStringBytes) return {};

    // Validate the complete insertion graph before following any variable string pointers.
    uint16_t contracts[MaximumArguments]{};
    uint64_t extents[MaximumArguments]{};
    uint32_t cache[MaximumArguments]{}, cached = 0, next = first, position = 0;
    uint16_t character = 0;
    auto read = [&]()
    {
        character = 0;
        if (resolved)
        {
            if (position > resourceLength) return false;
            character = wide ? resource[position++] : reinterpret_cast<const uint8_t*>(resource)[position++];
            return true;
        }
        return position < MaxFormatStringBytes / width && ReadCaptureMemory(
            reinterpret_cast<void*>(address + uint64_t{position++} * width), &character, width);
    };
    auto decimal = [&](uint64_t& value)
    {
        value = 0;
        while (character >= '0' && character <= '9')
        {
            value = std::min(uint64_t{INT_MAX}, value * 10 + character - '0');
            if (!read()) return false;
        }
        return true;
    };
    auto assign = [&](uint32_t index, uint16_t contract)
    {
        if (index >= MaximumArguments || contracts[index] && contracts[index] != contract) return false;
        contracts[index] = contract;
        return true;
    };
    uint64_t arguments[MaximumArguments]{};
    std::copy(std::begin(call.event.arguments), std::end(call.event.arguments), arguments);
    auto parse = [&](bool evaluating)
    {
        if (!read()) return false;
        while (character)
        {
            if (character != '%')
            {
                if (!read()) return false;
                continue;
            }
            if (!read()) return false;
            if (character == '0') break;
            if (!character) return false;
            if (character < '1' || character > '9')
            {
                if (!read()) return false;
                continue;
            }
            uint64_t ordinal = 0;
            if (!decimal(ordinal) || ordinal > MaximumArguments - first) return false;
            uint64_t precision = UINT64_MAX, ignored = 0;
            bool widthArgument = false, precisionArgument = false;
            uint16_t modifier = 0, specifier = 's';
            if (character == '!')
            {
                if (!read()) return false;
                while (character && character < 128 && strchr("-+ #0", character)) if (!read()) return false;
                if (character == '*')
                {
                    widthArgument = true;
                    if (!read()) return false;
                }
                else if (!decimal(ignored)) return false;
                if (character == '.')
                {
                    if (!read()) return false;
                    if (character == '*')
                    {
                        precisionArgument = true;
                        if (!read()) return false;
                    }
                    else if (!decimal(precision)) return false;
                }
                if (character && character < 128 && strchr("hlwI", character))
                {
                    modifier = character;
                    if (!read()) return false;
                    if (modifier == 'l' && character == 'l')
                    {
                        modifier = '6';
                        if (!read()) return false;
                    }
                    else if (modifier == 'I' && (character == '3' || character == '6'))
                    {
                        modifier = character;
                        if (!read() || character != (modifier == '3' ? '2' : '4') || !read()) return false;
                    }
                }
                specifier = character;
                if (!read() || character != '!' || !read()) return false;
            }
            const bool string = specifier == 's' || specifier == 'S';
            const bool scalar = specifier == 'c' || specifier == 'C';
            const bool counted = specifier == 'Z';
            const bool integer = specifier && specifier < 128 && strchr("diuoxX", specifier);
            if (string || scalar || counted)
            {
                if (modifier && modifier != 'h' && modifier != 'l' && modifier != 'w') return false;
            }
            else if (integer)
            {
                if (modifier == 'w') return false;
            }
            else if (specifier != 'p' || modifier) return false;

            // FormatMessage's va_list caches numbered values but consumes the first star's extra slot uncached.
            while (cached < ordinal)
            {
                if (next >= MaximumArguments) return false;
                cache[cached++] = next++;
            }
            uint32_t indices[3]{cache[ordinal - 1]}, stars = widthArgument + precisionArgument;
            for (uint32_t index = 1; index <= stars; ++index)
            {
                if (next >= MaximumArguments || cached >= MaximumArguments) return false;
                indices[index] = next++;
                if (index == 2) cache[cached++] = indices[index];
            }
            for (uint32_t index = 0; index < stars; ++index)
                if (!assign(indices[index], 4)) return false;
            if (precisionArgument && evaluating)
            {
                const auto value = static_cast<int32_t>(arguments[indices[widthArgument ? 1 : 0]]);
                precision = value < 0 ? UINT64_MAX : static_cast<uint32_t>(value);
            }
            if (precisionArgument && !evaluating) precision = 0;
            // Counted inserts ignore precision; only the w modifier selects a UNICODE_STRING over an ANSI_STRING.
            const bool wideValue = counted ? modifier == 'w' : modifier == 'l' || modifier == 'w' || !modifier &&
                (specifier == 's' || specifier == 'c' ? wide : !wide);
            const auto contract = static_cast<uint16_t>(string ?
                (wideValue ? MessageWideStringContract : MessageAnsiStringContract) :
                counted ? (wideValue ? MessageWideCountedContract : MessageAnsiCountedContract) :
                scalar ? 4u : specifier == 'p' ? MessagePointerContract :
                modifier == '6' ? 8u : modifier == 'I' ? sizeof(void*) : 4u);
            const auto index = indices[stars];
            if (!assign(index, contract)) return false;
            if (string) extents[index] = std::max(extents[index], precision == UINT64_MAX ? precision :
                precision * (wideValue ? 2u : 1u));
        }

        return true;
    };
#ifndef _WIN64
    if (!parse(false)) return {};
    auto cursor = call.stackPointer + sizeof(void*) + ExportStackBytes(call.definition->signature, first);
    for (uint32_t index = first; index < next; ++index)
    {
        const auto bytes = contracts[index] == 8 ? 8u : sizeof(void*);
        arguments[index] = 0;
        if (!ReadCaptureMemory(reinterpret_cast<void*>(cursor), arguments + index, bytes)) return {};
        cursor += bytes;
    }
    cached = position = 0;
    next = first;
    std::fill(std::begin(extents), std::end(extents), 0);
#endif
    if (!parse(true)) return {};
#ifndef _WIN64
    std::copy(arguments + first, arguments + next, call.event.arguments + first);
#endif

    // Repeated inserts use one snapshot covering the largest consumed span; gaps stay scalar and unprobed.
    for (uint32_t index = first; index < next; ++index)
        if (contracts[index] == MessageAnsiCountedContract || contracts[index] == MessageWideCountedContract)
        {
            // Counted descriptors precede the bounded payload FormatMessage reads; null descriptors print "(null)".
            CountedString text{};
            const auto descriptor = call.event.arguments[index];
            if (!descriptor) continue;
            if (!ReadCaptureMemory(reinterpret_cast<void*>(descriptor), &text, sizeof(text)))
            {
                CopyValue(slot, call.transport->Header(), index, ValueKind::Bytes, descriptor, sizeof(text));
                continue;
            }
            CopyValue(slot, call.transport->Header(), index, ValueKind::Bytes,
                reinterpret_cast<uint64_t>(&text), sizeof(text));
            const auto length = std::min(text.length, text.maximumLength);
            if (!text.buffer || !length) continue;
            CopyValue(slot, call.transport->Header(), index,
                contracts[index] == MessageWideCountedContract ? ValueKind::Utf16 : ValueKind::Bytes,
                text.buffer, length, {.flags = ReferencedData});
        }
        else if ((contracts[index] == MessageAnsiStringContract || contracts[index] == MessageWideStringContract) &&
            extents[index])
        {
            auto length = extents[index];
            if (contracts[index] == MessageAnsiStringContract && length != UINT64_MAX)
            {
                // Native ANSI conversion consumes an entire character even when precision ends inside its bytes.
                uint64_t bytes = 0;
                while (bytes < length && bytes < call.transport->Header()->bufferLimit)
                {
                    uint8_t sequence[4]{};
                    if (!ReadCaptureMemory(reinterpret_cast<void*>(call.event.arguments[index] + bytes),
                        sequence, 1) || !sequence[0]) { ++bytes; break; }
                    auto end = sequence + 1;
                    if (sequence[0] >= 128)
                    {
                        end = sequence;
                        RtlAnsiCharToUnicodeChar(&end);
                    }
                    if (end <= sequence || end > sequence + sizeof(sequence)) return {};
                    bytes += end - sequence;
                }
                length = bytes;
            }
            CopyValue(slot, call.transport->Header(), index,
                contracts[index] == MessageWideStringContract ? ValueKind::Utf16 : ValueKind::Bytes,
                call.event.arguments[index], length, {.terminated = true});
        }
    return {tail, 3, 0, static_cast<uint8_t>(next), true};
}

FormatCaptureResult CaptureRuntimePrompt(InstructionFrame& call, Slot* slot, bool leaving)
{
    // The dialog title precedes inserts that the system prompt templates fix with explicit %ls or %hs directives.
    constexpr uint32_t first = 2, tail = UINT32_MAX << first;
    uint32_t inserts = 0;
    bool wideInsert = false;
    switch (static_cast<uint32_t>(call.event.arguments[0]))
    {
    case 1008: case 1020: case 1023: case 1024: break;
    case 1021: case 1022: inserts = 1; wideInsert = true; break;
    case 1025: case 1026: inserts = 1; break;
    default: return {};
    }
    if (leaving) return {tail};
    const bool wide = !strcmp(call.definition->runtime->name, "OleUIPromptUserW");
    for (uint32_t index = first; index <= first + inserts; ++index)
    {
        const auto address = call.event.arguments[index];
        const bool text = index == first ? wide : wideInsert;
        if (address >= MinimumUserAddress && address < MaximumUserAddress)
            CopyValue(slot, call.transport->Header(), index, text ? ValueKind::Utf16 : ValueKind::Bytes,
                address, UINT64_MAX, {.terminated = true});
    }
    return {tail, 1, 0, static_cast<uint8_t>(first + 1 + inserts), true};
}

FormatCaptureResult CaptureRuntimeWdsLog(InstructionFrame& call, Slot* slot, bool leaving)
{
    // Documented client log codes fix how many wide strings follow; other codes keep their raw tail.
    constexpr uint32_t first = 3, tail = UINT32_MAX << first;
    uint32_t inserts = 0;
    switch (static_cast<uint32_t>(call.event.arguments[2]))
    {
    case 2: case 3: case 5: case 6: break;
    case 1: case 7: inserts = 1; break;
    case 4: inserts = 2; break;
    default: return {};
    }
    if (leaving) return {tail};
    for (uint32_t index = first; index < first + inserts; ++index)
    {
        const auto address = call.event.arguments[index];
        if (address >= MinimumUserAddress && address < MaximumUserAddress)
            CopyValue(slot, call.transport->Header(), index, ValueKind::Utf16, address, UINT64_MAX,
                {.terminated = true});
    }
    return {tail, 3, 0, static_cast<uint8_t>(first + inserts), true};
}
}

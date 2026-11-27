#include "InstructionCapture.h"
#include "PointerCaptureValues.h"
#include <algorithm>
#include <cstring>
#include <iterator>

namespace Detourist
{
constexpr uint32_t Utf8CodePage = 65001;
constexpr uint16_t LeadByteFlag = 0x8000;
constexpr uint16_t FormatIntegerBase = 0x100;
constexpr uint16_t FormatInt32Contract = 0x104;
constexpr uint16_t FormatStringBase = 0x200;
constexpr uint16_t FormatCharBase = 0x300;
constexpr uint16_t FormatPointerContract = 0x500;
constexpr uint16_t FormatCountedContract = 0x600;
constexpr uint16_t FormatWrittenContract = 0x610;
constexpr uint16_t FormatFloatingContract = 0x700;

bool IsFormatCrt(const char* module)
{
    constexpr const char* crtModules[]{"ntdll.dll", "msvcrt.dll", "ucrtbase.dll", "ucrtbased.dll",
        "ucrtbase_clr0400.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll", "msvcr120.dll",
        "msvcr120_clr0400.dll"};
    return std::any_of(std::begin(crtModules), std::end(crtModules), [&](const auto* candidate)
    {
        return !_stricmp(module, candidate);
    });
}

bool FormatCharacterWidths(InstructionFrame& call, uint64_t localeAddress, bool ucrt,
    uint8_t (&widths)[256], bool& utf8, bool completed)
{
    // UCRT locales publish their classification prefix; legacy CRT accessors identify the table field.
    auto locale = reinterpret_cast<void*>(localeAddress);
    void* information = nullptr;
    const uint16_t* table = nullptr;
    if (locale ? !ReadCaptureMemory(locale, &information, sizeof(information)) :
        !CurrentFormatLocale(call, ucrt, information, completed)) return false;
    if (ucrt)
    {
        __crt_locale_data_public data{};
        if (!ReadCaptureMemory(information, &data, sizeof(data))) return false;
        table = data._locale_pctype;
        utf8 = data._locale_lc_codepage == Utf8CodePage;
    }
    else
    {
        const auto module = reinterpret_cast<module_handle_t>(call.definition->module);
        auto accessor = reinterpret_cast<app_pc>(dr_get_proc_address(module, "__pctype_func"));
        byte code[128]{};
        if (!accessor || !ReadCaptureMemory(accessor, code, sizeof(code))) return false;
        auto context = dr_get_current_drcontext();
        int displacement = -1;
        bool returned = false;
        for (uint32_t offset = 0; offset + MaxX86InstructionBytes <= sizeof(code) && !returned;)
        {
            instr_t instruction;
            instr_init(context, &instruction);
            auto next = decode_from_copy(context, code + offset, accessor + offset, &instruction);
            auto size = next ? static_cast<uint32_t>(next - code - offset) : 0;
            if (!size || size > sizeof(code) - offset)
            {
                instr_free(context, &instruction);
                return false;
            }
            if (instr_writes_to_reg(&instruction, DR_REG_XAX, DR_QUERY_INCLUDE_ALL))
            {
                displacement = -1;
                if (instr_get_opcode(&instruction) == OP_mov_ld && instr_num_srcs(&instruction) == 1 &&
                    instr_num_dsts(&instruction) == 1 &&
                    opnd_same(instr_get_dst(&instruction, 0), opnd_create_reg(DR_REG_XAX)))
                {
                    auto source = instr_get_src(&instruction, 0);
                    if (opnd_is_base_disp(source) && opnd_get_index(source) == DR_REG_NULL &&
                        (opnd_get_base(source) == DR_REG_XAX || opnd_get_base(source) == DR_REG_XCX) &&
                        opnd_get_segment(source) == DR_REG_NULL && opnd_get_size(source) == OPSZ_PTR)
                        displacement = opnd_get_disp(source);
                }
            }
            returned = instr_is_return(&instruction);
            instr_free(context, &instruction);
            offset += size;
        }
        if (!returned || displacement < 0 || displacement > 512 || !ReadCaptureMemory(
            static_cast<byte*>(information) + displacement, &table, sizeof(table))) return false;
        utf8 = false;
    }

    // Reading the table avoids executing application code or taking the provider's locale and heap locks.
    uint16_t classes[256]{};
    if (!ReadCaptureMemory(table, classes, sizeof(classes))) return false;
    for (uint32_t index = 0; index < 256; ++index)
        widths[index] = utf8 ? (index & 0xE0) == 0xC0 ? 2 : (index & 0xF0) == 0xE0 ? 3 :
            (index & 0xF8) == 0xF0 ? 4 : 1 : classes[index] & LeadByteFlag ? 2 : 1;
    return true;
}

FormatCaptureResult CaptureRuntimeFormat(InstructionFrame& call, Slot* slot, bool leaving)
{
    if (strstr(call.definition->metadata.name, "scanf")) return CaptureRuntimeScan(call, slot, leaving);
    if (call.definition->runtime->IsShellMessage()) return CaptureRuntimeMessage(call, slot, leaving);
    if (call.definition->runtime->IsPromptUser()) return CaptureRuntimePrompt(call, slot, leaving);
    if (call.definition->runtime->IsWdsClientLog()) return CaptureRuntimeWdsLog(call, slot, leaving);

    // Only printf-style providers describe their variable arguments through the format string.
    constexpr struct
    {
        const char* module;
        const char* name;
        uint32_t parameter;
        bool wide;
        bool legacy;
        uint32_t list = UINT32_MAX;
    } formats[] = {
        {"user32.dll", "wsprintfA", 1, false, true}, {"user32.dll", "wsprintfW", 1, true, true},
        {"shlwapi.dll", "wnsprintfA", 2, false, true}, {"shlwapi.dll", "wnsprintfW", 2, true, true},
        {"setupapi.dll", "SetupWriteTextLog", 3, false, false},
        {"setupapi.dll", "SetupWriteTextLogError", 4, false, false},
        {"devrtl.dll", "DevRtlWriteTextLog", 3, false, false},
        {"devrtl.dll", "DevRtlWriteTextLogError", 4, false, false},
        {"ntdll.dll", "DbgPrint", 0, false, false}, {"ntdll.dll", "DbgPrintEx", 2, false, false},
        {"$dbgeng", "Output", 2, false, false}, {"$dbgeng", "ControlledOutput", 3, false, false},
        {"$dbgeng", "OutputPrompt", 2, false, false}, {"$dbgeng", "OutputWide", 2, true, false},
        {"$dbgeng", "ControlledOutputWide", 3, true, false}, {"$dbgeng", "OutputPromptWide", 2, true, false},
        {"$dbgeng", "OutputVaList", 2, false, false, 3},
        {"$dbgeng", "ControlledOutputVaList", 3, false, false, 4},
        {"$dbgeng", "OutputPromptVaList", 2, false, false, 3},
        {"$dbgeng", "OutputVaListWide", 2, true, false, 3},
        {"$dbgeng", "ControlledOutputVaListWide", 3, true, false, 4},
        {"$dbgeng", "OutputPromptVaListWide", 2, true, false, 3},
        {"snmpapi.dll", "SnmpUtilDbgPrint", 1, false, false},
        {"wdspxe.dll", "PxeTrace", 2, true, false},
        {"wdspxe.dll", "PxeTraceV", 2, true, false, 3},
        {"wdsmc.dll", "WdsTransportServerTrace", 2, true, false},
        {"wdsmc.dll", "WdsTransportServerTraceV", 2, true, false, 3},
        {"msvcrt.dll", "swprintf", 1, true, false},
        {"msvcrt.dll", "vswprintf", 1, true, false, 2},
        {"$crt", "vswprintf", 2, true, false, 3},
        {"$crt", "_vswprintf_l", 1, true, false, 3},
        {"$crt", "vsnprintf", 2, false, false, 3},
        {"$crt", "vsnprintf_s", 3, false, false, 4},
        {"$crt", "_CrtDbgReport", 4, false, false},
        {"$crt", "_CrtDbgReportW", 4, true, false},
        {"$crt", "_VCrtDbgReportA", 5, false, false, 6},
        {"$crt", "_VCrtDbgReportW", 5, true, false, 6},
        {"$crt", "__swprintf_l", 1, true, false},
        {"$crt", "_cprintf", 0, false, false}, {"$crt", "_cprintf_l", 0, false, false},
        {"$crt", "_cprintf_p", 0, false, false}, {"$crt", "_cprintf_p_l", 0, false, false},
        {"$crt", "_cprintf_s", 0, false, false}, {"$crt", "_cprintf_s_l", 0, false, false},
        {"$crt", "_cwprintf", 0, true, false}, {"$crt", "_cwprintf_l", 0, true, false},
        {"$crt", "_cwprintf_p", 0, true, false}, {"$crt", "_cwprintf_p_l", 0, true, false},
        {"$crt", "_cwprintf_s", 0, true, false}, {"$crt", "_cwprintf_s_l", 0, true, false},
        {"$crt", "_fprintf_l", 1, false, false}, {"$crt", "_fprintf_p", 1, false, false},
        {"$crt", "_fprintf_p_l", 1, false, false}, {"$crt", "_fprintf_s_l", 1, false, false},
        {"$crt", "_fwprintf_l", 1, true, false}, {"$crt", "_fwprintf_p", 1, true, false},
        {"$crt", "_fwprintf_p_l", 1, true, false}, {"$crt", "_fwprintf_s_l", 1, true, false},
        {"$crt", "_printf_l", 0, false, false}, {"$crt", "_printf_p", 0, false, false},
        {"$crt", "_printf_p_l", 0, false, false}, {"$crt", "_printf_s_l", 0, false, false},
        {"$crt", "_scprintf", 0, false, false}, {"$crt", "_scprintf_l", 0, false, false},
        {"$crt", "_scprintf_p", 0, false, false}, {"$crt", "_scprintf_p_l", 0, false, false},
        {"$crt", "_scwprintf", 0, true, false}, {"$crt", "_scwprintf_l", 0, true, false},
        {"$crt", "_scwprintf_p", 0, true, false}, {"$crt", "_scwprintf_p_l", 0, true, false},
        {"$crt", "_snprintf", 2, false, false}, {"$crt", "_snprintf_c", 2, false, false},
        {"$crt", "_snprintf_c_l", 2, false, false}, {"$crt", "_snprintf_l", 2, false, false},
        {"$crt", "_snprintf_s", 3, false, false}, {"$crt", "_snprintf_s_l", 3, false, false},
        {"$crt", "_snwprintf", 2, true, false}, {"$crt", "_snwprintf_l", 2, true, false},
        {"$crt", "_snwprintf_s", 3, true, false}, {"$crt", "_snwprintf_s_l", 3, true, false},
        {"$crt", "_sprintf_l", 1, false, false}, {"$crt", "_sprintf_p", 2, false, false},
        {"$crt", "_sprintf_p_l", 2, false, false}, {"$crt", "_sprintf_s_l", 2, false, false},
        {"$crt", "_swprintf", 1, true, false}, {"$crt", "_swprintf_c", 2, true, false},
        {"$crt", "_swprintf_c_l", 2, true, false}, {"$crt", "_swprintf_p", 2, true, false},
        {"$crt", "_swprintf_p_l", 2, true, false}, {"$crt", "_swprintf_s_l", 2, true, false},
        {"$crt", "_wprintf_l", 0, true, false}, {"$crt", "_wprintf_p", 0, true, false},
        {"$crt", "_wprintf_p_l", 0, true, false}, {"$crt", "_wprintf_s_l", 0, true, false},
        {"$crt", "fprintf", 1, false, false}, {"$crt", "fprintf_s", 1, false, false},
        {"$crt", "fwprintf", 1, true, false}, {"$crt", "fwprintf_s", 1, true, false},
        {"$crt", "printf", 0, false, false}, {"$crt", "printf_s", 0, false, false},
        {"$crt", "sprintf", 1, false, false}, {"$crt", "sprintf_s", 2, false, false},
        {"$crt", "swprintf_s", 2, true, false}, {"$crt", "wprintf", 0, true, false},
        {"$crt", "wprintf_s", 0, true, false},
        {"$ucrt", "__stdio_common_vsprintf", 3, false, false, 5},
        {"$ucrt", "__stdio_common_vsprintf_s", 3, false, false, 5},
        {"$ucrt", "__stdio_common_vsprintf_p", 3, false, false, 5},
        {"$ucrt", "__stdio_common_vswprintf", 3, true, false, 5},
        {"$ucrt", "__stdio_common_vswprintf_s", 3, true, false, 5},
        {"$ucrt", "__stdio_common_vswprintf_p", 3, true, false, 5},
        {"$ucrt", "__stdio_common_vsnprintf_s", 4, false, false, 6},
        {"$ucrt", "__stdio_common_vsnwprintf_s", 4, true, false, 6},
        {"$ucrt", "__stdio_common_vfprintf", 2, false, false, 4},
        {"$ucrt", "__stdio_common_vfprintf_s", 2, false, false, 4},
        {"$ucrt", "__stdio_common_vfprintf_p", 2, false, false, 4},
        {"$ucrt", "__stdio_common_vfwprintf", 2, true, false, 4},
        {"$ucrt", "__stdio_common_vfwprintf_s", 2, true, false, 4},
        {"$ucrt", "__stdio_common_vfwprintf_p", 2, true, false, 4},
        {"$ucrt", "__conio_common_vcprintf", 1, false, false, 3},
        {"$ucrt", "__conio_common_vcprintf_s", 1, false, false, 3},
        {"$ucrt", "__conio_common_vcprintf_p", 1, false, false, 3},
        {"$ucrt", "__conio_common_vcwprintf", 1, true, false, 3},
        {"$ucrt", "__conio_common_vcwprintf_s", 1, true, false, 3},
        {"$ucrt", "__conio_common_vcwprintf_p", 1, true, false, 3},
    };
    const auto& definition = *call.definition->runtime;
    const auto module = call.definition->metadata.module;
    const char* name = call.definition->metadata.name;
    const bool dbgeng = !_stricmp(module, "COM") && (!strncmp(name, "IDebugControl::", 15) ||
        !strncmp(name, "IDebugControl", 13) && name[13] >= '2' && name[13] <= '7' &&
        name[14] == ':' && name[15] == ':');
    if (dbgeng) name = strchr(name, ':') + 2;
    auto formatName = !strncmp(name, "_o_", 3) ? name + 3 : name;
    const bool listCandidate = *formatName == 'v' || *formatName == '_' &&
        (formatName[1] == 'v' || formatName[1] == 'V' || formatName[1] == '_' && formatName[2] == 'v');

    // WDS trace wrappers take a trailing va_list without a CRT-style name.
    const bool traceList = definition.argumentCount == 4 &&
        (!_stricmp(module, "wdspxe.dll") || !_stricmp(module, "wdsmc.dll"));
    if (!definition.rawTailStart && strncmp(formatName, "__stdio_common_v", 16) &&
        strncmp(formatName, "__conio_common_v", 16) && !dbgeng && !listCandidate && !traceList) return {};
    const bool crt = IsFormatCrt(module);
    const bool ucrt = crt && !_strnicmp(module, "ucrt", 4);
    if (crt && !strncmp(name, "_o_", 3)) name += 3;
    auto findFormat = [&](const char* function)
    {
        return std::find_if(std::begin(formats), std::end(formats), [&](const auto& item)
        {
            return (!strcmp(item.module, "$crt") ? crt : !strcmp(item.module, "$ucrt") ? ucrt :
                !strcmp(item.module, "$dbgeng") ? dbgeng :
                !_stricmp(item.module, module)) && !strcmp(item.name, function);
        });
    };
    const auto nameLength = strlen(name);
    const bool localized = nameLength >= 2 && !strcmp(name + nameLength - 2, "_l");
    auto format = findFormat(name);
    bool legacyList = false;

    // Legacy argument-list variants share their direct formatter's prefix, followed by locale and va_list slots.
    if (format == std::end(formats) && crt && listCandidate && nameLength < 64)
    {
        char direct[64]{};
        uint32_t offset = 0;
        while (name[offset] == '_') { direct[offset] = '_'; ++offset; }
        if (name[offset] != 'v') return {};
        memcpy(direct + offset, name + offset + 1, nameLength - offset);
        format = findFormat(direct);
        legacyList = true;
    }
    if (format == std::end(formats)) return {};
    auto selectedFormat = *format;
    if (legacyList) selectedFormat.list = selectedFormat.parameter + 1 + localized;
    format = &selectedFormat;
    const bool listed = format->list != UINT32_MAX;
    const bool common = !strcmp(format->module, "$ucrt");
    if (listed ? definition.rawTailStart || definition.argumentCount != format->list + 1 ||
        common && (call.event.arguments[0] & ~uint64_t{7}) :
        format->parameter >= definition.rawTailStart) return {};
    if (listed && leaving && !call.formatOutputs) return {};
    const bool debug = !_stricmp(module, "ntdll.dll") && (!strcmp(name, "DbgPrint") || !strcmp(name, "DbgPrintEx"));
    auto address = call.event.arguments[format->parameter];

    // Debug reports accept a null format without consuming variable arguments.
    if (!address && crt && strstr(name, "CrtDbgReport"))
    {
        const auto count = call.definition->metadata.argumentCount;
        const auto consumed = listed ? 0u : definition.rawTailStart;
        const auto available = count < 32 ? (uint32_t{1} << count) - 1 : UINT32_MAX;
        const auto prefix = consumed < 32 ? (uint32_t{1} << consumed) - 1 : UINT32_MAX;
        return {listed ? 0u : available & ~prefix, static_cast<uint8_t>(format->parameter + 1),
            static_cast<uint8_t>(listed ? format->list + 1 : 0), static_cast<uint8_t>(consumed), true};
    }
    if (address < MinimumUserAddress || address >= MaximumUserAddress - MaxFormatStringBytes) return {};
    const uint32_t width = format->wide ? sizeof(wchar_t) : sizeof(char);
    uint32_t position = 0, next = listed ? 0 : definition.rawTailStart, recognized = 0;
    const uint32_t count = listed ? MaximumArguments : call.definition->metadata.argumentCount;
    const bool defaultWide = format->wide && (!common || call.event.arguments[0] & 4);
    uint8_t characterWidths[256]{};
    bool localeReady = false, localeUtf8 = false;
    uint64_t arguments[MaximumArguments]{};
    uint32_t loaded = 0;
    uint8_t argumentWidths[MaximumArguments]{};
    bool validating = false;
    auto value = [&](uint32_t index, uint64_t& result)
    {
        if (index >= count || index >= MaximumArguments) return false;
#ifdef _WIN64
        if (!listed) { result = call.event.arguments[index]; return true; }
        const uint32_t bytes = sizeof(uint64_t);
        auto pointer = call.event.arguments[format->list] + uint64_t{index} * bytes;
#else
        const auto bytes = std::max<uint32_t>(sizeof(void*), argumentWidths[index]);
        if (validating) { result = 0; return true; }
        if (!listed && leaving) { result = call.event.arguments[index]; return true; }
        const auto first = listed ? 0u : definition.rawTailStart;
        auto pointer = listed ? call.event.arguments[format->list] :
            call.stackPointer + sizeof(void*) + ExportStackBytes(definition.signature, first);
        for (uint32_t argument = first; argument < index; ++argument)
            pointer += std::max<uint32_t>(sizeof(void*), argumentWidths[argument]);
#endif
        if (!(loaded & (uint32_t{1} << index)))
        {
            if (pointer < MinimumUserAddress || pointer > UINTPTR_MAX - bytes ||
                !ReadCaptureMemory(reinterpret_cast<void*>(pointer), arguments + index, bytes)) return false;
            loaded |= uint32_t{1} << index;
        }
        result = arguments[index];
#ifndef _WIN64
        if (!listed) call.event.arguments[index] = result;
#endif
        return true;
    };
    uint16_t character = 0;
    auto read = [&]()
    {
        character = 0;
        return position < MaxFormatStringBytes / width && ReadCaptureMemory(
            reinterpret_cast<void*>(address + uint64_t{position++} * width), &character, width);
    };
    const bool positionalProvider = !format->legacy && (crt || ucrt) && strstr(name, "printf_p");
    const uint32_t first = listed ? 0 : definition.rawTailStart;
    uint16_t contracts[MaximumArguments];
    uint64_t extents[MaximumArguments];
    if (positionalProvider)
    {
        memset(contracts, 0, sizeof(contracts));
        memset(extents, 0, sizeof(extents));
    }
    uint32_t mode = 0;
    auto failure = [&]() { return FormatCaptureResult{validating ? 0u : recognized}; };
    for (uint32_t pass = 0; pass < (positionalProvider ? 2u : 1u); ++pass)
    {
        validating = positionalProvider && pass == 0;
        position = 0;
        next = first;
        recognized = 0;
        mode = 0;
        uint32_t used = 0, capturedData = 0;
        if (!read()) return {};
        while (character)
        {
            if (character != '%')
            {
                if (!read()) return failure();
                continue;
            }
            if (!read()) return failure();
            if (character == '%')
            {
                if (!read()) return failure();
                continue;
            }

            // Positional formats validate their whole argument graph before any referenced buffers are followed.
            auto argument = next;
            uint32_t ordinal = 0, widthIndex = UINT32_MAX, precisionIndex = UINT32_MAX;
            auto start = position;
            auto initial = character;
            while (character >= '0' && character <= '9')
            {
                ordinal = std::min(MaximumArguments + 1, ordinal * 10 + character - '0');
                if (!read()) return failure();
            }
            if (character == '$')
            {
                if (!positionalProvider || mode == 1 || !ordinal || first + ordinal > count) return failure();
                mode = 2;
                argument = first + ordinal - 1;
                if (!read()) return failure();
            }
            else
            {
                if (mode == 2) return failure();
                mode = 1;
                position = start;
                character = initial;
            }
            auto star = [&](uint32_t& index)
            {
                if (format->legacy || !read()) return false;
                if (mode == 1)
                {
                    index = argument++;
                    return index < count && !(character >= '0' && character <= '9');
                }
                uint32_t number = 0;
                while (character >= '0' && character <= '9')
                {
                    number = std::min(MaximumArguments + 1, number * 10 + character - '0');
                    if (!read()) return false;
                }
                if (!number || first + number > count || character != '$') return false;
                index = first + number - 1;
                return read();
            };
            while (character == '-' || character == '#' || character == '0' ||
                !format->legacy && (character == '+' || character == ' '))
                if (!read()) return failure();
            if (character == '*')
            {
                if (!star(widthIndex)) return failure();
            }
            else
                while (character >= '0' && character <= '9')
                    if (!read()) return failure();
            uint64_t precision = UINT64_MAX;
            if (character == '.')
            {
                precision = 0;
                if (!read()) return failure();
                if (character == '*')
                {
                    uint64_t supplied = 0;
                    if (!star(precisionIndex) || !value(precisionIndex, supplied)) return failure();
                    auto specified = static_cast<int32_t>(supplied);
                    precision = specified < 0 ? UINT64_MAX : static_cast<uint32_t>(specified);
                }
                else
                    while (character >= '0' && character <= '9')
                    {
                        precision = std::min<uint64_t>(UINT32_MAX, precision * 10 + character - '0');
                        if (!read()) return failure();
                    }
            }
            uint16_t modifier = 0;
            if (character == 'h' || character == 'l' || character == 'w' || character == 'L' ||
                character == 'I' || character == 'j' || character == 'z' || character == 't')
            {
                modifier = character;
                if (!read()) return failure();
                if ((modifier == 'h' || modifier == 'l') && character == modifier)
                {
                    modifier = modifier == 'h' ? 'H' : 'q';
                    if (!read()) return failure();
                }
                else if (modifier == 'I' && (character == '3' || character == '6'))
                {
                    const auto last = character == '3' ? '2' : '4';
                    modifier = character;
                    if (!read() || character != last || !read()) return failure();
                }
            }
            bool targetAddress = dbgeng && (character == 'p' || character == 'y');
            if (dbgeng && modifier == 'I' && character != 'd' && character != 'i' && character != 'u' &&
                character != 'o' && character != 'x' && character != 'X')
            {
                modifier = 0;
                character = 'I';
                --position;
            }

            // Debugger memory and symbol directives describe the debuggee's address space, not the caller's.
            if (dbgeng && character == 'm')
            {
                if (modifier || !read()) return failure();
                if (character == 's' && !read()) return failure();
                if (character != 'a' && character != 'u') return failure();
                targetAddress = true;
                character = 'p';
            }
            if (dbgeng && character == 'Y')
            {
                if (modifier && modifier != 'h' && modifier != 'w' || !read() || character != '{' || !read())
                    return failure();
                auto directive = character;
                if (!read()) return failure();
                if (directive == 'a' || directive == 'p')
                {
                    if (character != 's' || !read()) return failure();
                    targetAddress = true;
                }
                else if (directive == 'l') targetAddress = true;
                else if (directive != 't' && directive != 'T' && directive != 's' && directive != 'S')
                    return failure();
                if (character != '}' || targetAddress && modifier) return failure();
                character = targetAddress ? 'p' : 's';
            }
            bool string = character == 's' || character == 'S';
            bool scalar = character == 'c' || character == 'C';
            bool counted = !format->legacy && (debug || crt || ucrt) && character == 'Z';
            bool written = !format->legacy && (crt && _stricmp(module, "ntdll.dll") || ucrt) && character == 'n';
            if (string || scalar || counted)
            {
                if (modifier && modifier != 'h' && modifier != 'l' && modifier != 'w') return failure();
            }
            else if (character == 'd' || character == 'i' || character == 'u' || character == 'x' ||
                character == 'X' || !format->legacy && character == 'o')
            {
                if (modifier == 'w' || modifier == 'L') return failure();
            }
            else if (character == 'p' || dbgeng && (character == 'N' || character == 'I' || character == 'y'))
            {
                if (modifier && !(dbgeng && character == 'y' && modifier == 'l')) return failure();
            }
            else if (written)
            {
                if (modifier == 'w' || modifier == 'L' || !ucrt &&
                    (modifier == 'I' || modifier == 'j' || modifier == 'z' || modifier == 't')) return failure();
            }
            else if (!format->legacy && _stricmp(module, "ntdll.dll") && (character == 'f' || character == 'F' ||
                character == 'e' || character == 'E' || character == 'g' || character == 'G' ||
                character == 'a' || character == 'A'))
            {
                if (modifier && modifier != 'l' && modifier != 'L') return failure();
            }
            else return failure();
            uint64_t supplied = 0;
            const bool wideValue = modifier == 'l' || modifier == 'w' ||
                !modifier && (character == 's' || character == 'c' ? defaultWide : !defaultWide);
            auto integerBytes = modifier == 'H' ? ucrt ? 1u : 2u : modifier == 'h' ? 2u :
                modifier == 'q' || modifier == '6' || modifier == 'j' ? 8u :
                modifier == 'I' || modifier == 'z' || modifier == 't' ? static_cast<uint32_t>(sizeof(void*)) : 4u;
            const bool integer = character == 'd' || character == 'i' || character == 'u' ||
                character == 'o' || character == 'x' || character == 'X';
            const bool floating = !string && !scalar && !counted && !written && !integer &&
                character != 'p' && !targetAddress && !(dbgeng && (character == 'N' || character == 'I'));
            if (argument >= count || argument >= MaximumArguments) return failure();
            argumentWidths[argument] = static_cast<uint8_t>(floating || targetAddress ? 8u :
                integer ? std::max(4u, integerBytes) : sizeof(void*));
            if (!value(argument, supplied)) return failure();
            auto contract = static_cast<uint16_t>(
                string    ? FormatStringBase + wideValue
                : scalar  ? FormatCharBase + wideValue
                : counted ? FormatCountedContract
                : written ? FormatWrittenContract
                : character == 'p' || targetAddress || dbgeng && (character == 'N' || character == 'I') ?
                    FormatPointerContract
                : character == 'd' || character == 'i' || character == 'u' || character == 'o' || character == 'x' ||
                        character == 'X'
                    ? FormatIntegerBase + integerBytes + (modifier == 'I' ? 16u : 0u)
                    : FormatFloatingContract);
            const uint32_t indices[]{widthIndex, precisionIndex, argument};
            for (uint32_t role = 0; role < 3; ++role)
            {
                auto index = indices[role];
                if (index == UINT32_MAX) continue;
                auto type = role == 2 ? contract : FormatInt32Contract;
                if (mode == 2 && contracts[index] && contracts[index] != type) return failure();
                if (validating) contracts[index] = type;
                used |= uint32_t{1} << index;
            }
            auto stringBytes = precision == UINT64_MAX ? UINT64_MAX : precision * (wideValue ? 2u : 1u);
            if (validating && string) extents[argument] = std::max(extents[argument], stringBytes);
            if (validating)
            {
                next = std::max(next, argument + 1);
                if (widthIndex != UINT32_MAX) next = std::max(next, widthIndex + 1);
                if (precisionIndex != UINT32_MAX) next = std::max(next, precisionIndex + 1);
                if (!read()) return failure();
                continue;
            }
            if (written && !leaving) call.formatOutputs = true;
            for (auto index : {widthIndex, precisionIndex, argument})
            {
                if (index == UINT32_MAX || recognized & (uint32_t{1} << index)) continue;
                recognized |= uint32_t{1} << index;
                if (!listed || leaving) continue;
                uint64_t scalarValue = 0;
                if (!value(index, scalarValue)) return failure();
                const auto bytes = sizeof(void*) == 8 ? sizeof(scalarValue) :
                    std::max<uint32_t>(sizeof(void*), argumentWidths[index]);
                if (CopyValue(slot, call.transport->Header(), format->list, ValueKind::Scalar,
                    reinterpret_cast<uint64_t>(&scalarValue), bytes,
                    {.flags = StringArrayElement | (index << ValueDetailShift)}) !=
                    bytes) return failure();
            }
            const auto listFlags = listed ? StringArrayElement | (argument << ValueDetailShift) : 0u;
            // Counts can change before a later failure; retain both states without inferring which writes occurred.
            if (written && (!leaving || !(call.event.flags & Skipped)))
            {
                // Legacy CRTs store 64-bit count modifiers, and every CRT stores %In, through an int destination.
                const uint32_t bytes = ucrt && modifier != 'I' ? integerBytes : std::min(integerBytes, 4u);
                CopyValue(slot, call.transport->Header(), listed ? format->list : argument, ValueKind::Bytes,
                    supplied, bytes, {.flags = listed ? listFlags | ReferencedData : 0u});
            }

            // Counted strings retain their descriptor and byte extent without following a partial descriptor.
            if (counted && !leaving)
            {
                CountedString text{};
                auto pointer = supplied;
                auto parameter = listed ? format->list : argument;
                if (ReadCaptureMemory(reinterpret_cast<void*>(pointer), &text, sizeof(text)))
                {
                    CopyValue(slot, call.transport->Header(), parameter, ValueKind::Bytes,
                        reinterpret_cast<uint64_t>(&text), sizeof(text), {.flags = listFlags});
                    const auto length = debug ? std::min(text.length, text.maximumLength) : text.length;
                    if (length)
                    {
                        const bool wide = modifier == 'w' || ucrt && modifier == 'l' ||
                            ucrt && !modifier && !defaultWide;
                        CopyValue(slot, call.transport->Header(), parameter,
                            wide ? ValueKind::Utf16 : ValueKind::Bytes, text.buffer, length,
                            {.flags = ReferencedData | listFlags});
                    }
                }
                else
                    CopyValue(slot, call.transport->Header(), parameter, ValueKind::Bytes, pointer, sizeof(text),
                        {.flags = listFlags});
            }

            // Typed string reads honor both the format precision and the configured global byte limit.
            if (string && !leaving && !(capturedData & (uint32_t{1} << argument)))
            {
                const bool wide = modifier == 'l' || modifier == 'w' ||
                    !modifier && (character == 's' ? defaultWide : !defaultWide);
                auto length = positionalProvider ? extents[argument] : stringBytes;
                if (length)
                {
                    // Wide output precision counts characters, including both halves of a UTF-8 surrogate pair.
                    if (format->wide && !wide && length != UINT64_MAX && (crt || ucrt) &&
                        _stricmp(module, "ntdll.dll"))
                    {
                        uint64_t bytes = 0, characters = 0;
                        while (characters < length && bytes < call.transport->Header()->bufferLimit)
                        {
                            uint8_t firstByte = 0;
                            if (!ReadCaptureMemory(reinterpret_cast<void*>(supplied + bytes), &firstByte, 1) ||
                                !firstByte) { ++bytes; break; }
                            if (firstByte >= 128 && !localeReady)
                            {
                                const auto locale = common || localized ? call.event.arguments[
                                    (listed ? format->list : definition.rawTailStart) - 1] : 0;
                                localeReady = FormatCharacterWidths(call, locale, ucrt, characterWidths, localeUtf8);
                                if (!localeReady)
                                {
                                    recognized &= ~(uint32_t{1} << argument);
                                    return failure();
                                }
                            }
                            auto size = firstByte < 128 ? 1 : characterWidths[firstByte];
                            characters += localeUtf8 && size == 4 ? 2 : 1;
                            bytes += size;
                        }
                        length = bytes;
                    }
                    CopyValue(slot, call.transport->Header(), listed ? format->list : argument,
                        wide ? ValueKind::Utf16 : ValueKind::Bytes, supplied, length,
                        {.terminated = true, .flags = listed ? listFlags | ReferencedData : 0u});
                }
                capturedData |= uint32_t{1} << argument;
            }
            next = std::max(next, argument + 1);
            if (widthIndex != UINT32_MAX) next = std::max(next, widthIndex + 1);
            if (precisionIndex != UINT32_MAX) next = std::max(next, precisionIndex + 1);
            if (!read()) return failure();
        }

        // Positional formats require every slot up to their largest referenced position.
        if (mode == 2)
        {
            auto available = next < 32 ? (uint32_t{1} << next) - 1 : UINT32_MAX;
            auto prefix = first ? (uint32_t{1} << first) - 1 : 0u;
            if (used != (available & ~prefix)) return failure();
        }
        if (validating) continue;

        // A terminating format establishes the consumed prefix; unsupported or unreadable formats retain raw fallback.
        if (!listed)
        {
            auto available = count < 32 ? (uint32_t{1} << count) - 1 : UINT32_MAX;
            auto consumed = next < 32 ? (uint32_t{1} << next) - 1 : UINT32_MAX;
            recognized |= available & ~consumed;
        }
        return {recognized, static_cast<uint8_t>(format->parameter + 1),
            static_cast<uint8_t>(listed ? format->list + 1 : 0), static_cast<uint8_t>(next), true};
    }
    return {};
}

uint32_t CaptureRuntimeTraceMessage(InstructionFrame& call, Slot* slot, bool leaving)
{
    const auto& metadata = call.definition->metadata;
    const bool listed = !strcmp(metadata.name, "TraceMessageVa") || !strcmp(metadata.name, "EtwTraceMessageVa");
    if (!listed && strcmp(metadata.name, "TraceMessage") && strcmp(metadata.name, "EtwTraceMessage")) return 0;
    if (_stricmp(metadata.module, "advapi32.dll") && _stricmp(metadata.module, "kernel32.dll") &&
        _stricmp(metadata.module, "kernelbase.dll") && _stricmp(metadata.module, "ntdll.dll")) return 0;
    const auto& definition = *call.definition->runtime;
    if (!definition.signature.supported || definition.argumentCount != (listed ? 5u : 4u) ||
        definition.rawTailStart != (listed ? 0u : 4u)) return 0;
    constexpr uint32_t recognized = 0xfffffff0;
    if (leaving) return recognized;
    const auto start = sizeof(void*) + ExportStackBytes(definition.signature, 4);
    if (!listed && call.stackPointer > UINTPTR_MAX - start) return recognized;
    auto address = listed ? call.event.arguments[4] : call.stackPointer + start;
    if (!address) return recognized;
    auto header = call.transport->Header();
    auto available = EnsureSlotPayload(slot, header, static_cast<uint32_t>(sizeof(Value)) + header->bufferLimit);
    if (available < sizeof(Value)) return recognized;
    const auto limit = std::min(header->bufferLimit, available - static_cast<uint32_t>(sizeof(Value)));
    uint32_t bytes = 0;
    bool terminated = false, unreadable = false;

    // Pointer/size pairs are an SDK-defined list, independent of WPP message formatting.
    while (bytes + sizeof(void*) <= limit)
    {
        uintptr_t pointer = 0, length = 0;
        if (address > UINT64_MAX - bytes || !ReadCaptureMemory(
            reinterpret_cast<void*>(address + bytes), &pointer, sizeof(pointer)))
        {
            unreadable = true;
            break;
        }
        bytes += sizeof(void*);
        if (bytes + sizeof(void*) > limit) break;
        if (address > UINT64_MAX - bytes || !ReadCaptureMemory(
            reinterpret_cast<void*>(address + bytes), &length, sizeof(length)))
        {
            unreadable = true;
            break;
        }
        bytes += sizeof(void*);
        if (!pointer) { terminated = true; break; }
    }
    auto offset = slot->event.payloadBytes;
    auto captured = CopyValue(slot, header, 4, ValueKind::Bytes, address, bytes ? bytes : sizeof(void*),
        {.unknownExtent = !terminated,
         .flags = EtwData | (5u << ValueDetailShift) | (terminated ? 0u : Truncated) |
             (unreadable ? Unreadable : 0u)});

    // Follow only complete pairs retained in the bounded snapshot, including readable prefixes of guarded lists.
    for (uint32_t member = 0; member + 2 * sizeof(void*) <= captured; member += 2 * sizeof(void*))
    {
        uintptr_t pointer = 0, length = 0;
        memcpy(&pointer, Transport::Payload(slot) + offset + sizeof(Value) + member, sizeof(pointer));
        memcpy(&length, Transport::Payload(slot) + offset + sizeof(Value) + member + sizeof(void*), sizeof(length));
        if (!pointer) break;
        if (!length) continue;
        auto payload = slot->event.payloadBytes;
        CopyValue(slot, header, PackMemberParameter(4u, member), ValueKind::Bytes, pointer, length,
            {.flags = EtwData | (6u << ValueDetailShift) | MemberData | ReferencedData});
        if (slot->event.payloadBytes <= payload) break;
    }
    return recognized;
}
}

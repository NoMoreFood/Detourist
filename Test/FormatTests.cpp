#include "TestSupport.h"
#include "ApiCategories.h"

#if defined(DETOURIST_TEST_DetouristFormatVariadicTests)

using namespace Detourist::Tests;

template<size_t... Index>
bool FormatLongTail(FARPROC function, std::index_sequence<Index...>)
{
    // Exercise late strings on both sides of the recorded argument window.
    auto format = "LONG" + std::to_string(sizeof...(Index)) + ":";
    auto expected = format;
    ((format += "%u|", expected += std::to_string(65536 + Index) + "|"), ...);
    format += "%s";
    expected += "Late CRT string";
    char output[512]{};
    auto call = reinterpret_cast<int (__cdecl *)(char*, size_t, const char*, ...)>(function);
    return call(output, sizeof(output), format.c_str(), static_cast<unsigned>(65536 + Index)...,
        "Late CRT string") == expected.size() && output == expected;
}

int TargetMain()
{
    // Exercise both character families without creating a window.
    char ansi[64]{};
    wchar_t wide[64]{};
    if (wsprintfA(ansi, "Detourist wsprintf %u", 7u) != 20 ||
            std::strcmp(ansi, "Detourist wsprintf 7") != 0 ||
            wsprintfW(wide, L"Detourist wsprintf %u", 8u) != 20 ||
            std::wcscmp(wide, L"Detourist wsprintf 8") != 0 ||
            wnsprintfA(ansi, 64, "Detourist wnsprintf %u", 9u) != 21 ||
            std::strcmp(ansi, "Detourist wnsprintf 9") != 0 ||
            wnsprintfW(wide, 64, L"Detourist wnsprintf %u", 10u) != 22 ||
            std::wcscmp(wide, L"Detourist wnsprintf 10") != 0)
    {
        return 1;
    }

    // The legacy formatters select string widths independently of their output character family.
    const char narrow[] = "Detourist ANSI tail";
    const wchar_t unicode[] = L"Detourist UTF16 tail";
    char formattedAnsi[256]{};
    wchar_t formattedWide[256]{};
    const char ansiFormat[] = "%s|%S|%hs|%ls|%u|%%";
    const wchar_t wideFormat[] = L"%s|%S|%hs|%ws|%u|%%";
    const char ansiExpected[] =
        "Detourist ANSI tail|Detourist UTF16 tail|Detourist ANSI tail|Detourist UTF16 tail|65536|%";
    const wchar_t wideExpected[] =
        L"Detourist UTF16 tail|Detourist ANSI tail|Detourist ANSI tail|Detourist UTF16 tail|65536|%";
    if (wsprintfA(formattedAnsi, ansiFormat, narrow, unicode, narrow, unicode, 65536u) <= 0 ||
        std::strcmp(formattedAnsi, ansiExpected) != 0 ||
        wsprintfW(formattedWide, wideFormat, unicode, narrow, narrow, unicode, 65536u) <= 0 ||
        std::wcscmp(formattedWide, wideExpected) != 0 ||
        wnsprintfA(formattedAnsi, 256, ansiFormat, narrow, unicode, narrow, unicode, 65536u) <= 0 ||
        std::strcmp(formattedAnsi, ansiExpected) != 0 ||
        wnsprintfW(formattedWide, 256, wideFormat, unicode, narrow, narrow, unicode, 65536u) <= 0 ||
        std::wcscmp(formattedWide, wideExpected) != 0)
    {
        return 2;
    }
    // Check direct CRT and Windows formatters against their own complete output.
    for (const auto provider : {L"shlwapi.dll", L"msvcrt.dll", L"msvcr120.dll"})
    {
        auto library = LoadLibraryExW(provider, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 3;
        auto function = GetProcAddress(library, !wcscmp(provider, L"shlwapi.dll") ? "wnsprintfA" : "_snprintf");
        if (!function || !FormatLongTail(function, std::make_index_sequence<20>{}) ||
            !FormatLongTail(function, std::make_index_sequence<28>{}) ||
            !FormatLongTail(function, std::make_index_sequence<29>{}) ||
            !FormatLongTail(function, std::make_index_sequence<36>{})) return 4;
        FreeLibrary(library);
    }
    return 0;
}

void FormatVariadic(const Context& context)
{
    // Fixed catalog prefixes and PE forwarders must agree before exercising the variadic workloads.
    auto catalog = context.collector.parent_path() / L"ApiCatalog.sqlite";
    std::map<std::pair<std::string, std::string>, uint32_t> counts;
    for (auto module : {"user32.dll", "shlwapi.dll", "shell32.dll"})
        for (auto suffix : {"A", "W"})
        {
            std::string name = std::string(module) == "user32.dll" ? "wsprintf" : "ShellMessageBox";
            counts[{module, name + suffix}] = name == "wsprintf" ? 2 : 5;
            if (std::string(module) == "shlwapi.dll") counts[{module, std::string("wnsprintf") + suffix}] = 3;
        }
    std::set<std::pair<std::string, std::string>> seen;
    for (const auto& row :
         Query(catalog, "SELECT f.id,f.module,f.name,f.parameters,p.argument_count,p.supported,"
                        "v.fixed_count FROM variadic_prefixes v JOIN plans p ON p.function_id=v.function_id "
                        "JOIN functions f ON f.id=v.function_id WHERE f.name IN "
                        "('wsprintfA','wsprintfW','wnsprintfA','wnsprintfW','ShellMessageBoxA','ShellMessageBoxW')"))
    {
        auto key = std::pair{row["module"].get<std::string>(), row["name"].get<std::string>()};
        if (!counts.contains(key)) continue;
        seen.insert(key);
        auto name = key.second;
        Require(row["supported"] != 0 && row["argument_count"] == counts.at(key) &&
                    row["fixed_count"] == counts.at(key),
                "Windows variadic prefix differs", row);
        Json names = Json::array();
        for (const auto& item : Json::parse(row["parameters"].get<std::string>()))
            names.push_back(item["name"]);
        Require(names == (name.starts_with("wsprintf") ? Json::array({"lpOut", "lpFmt"})
                          : name.starts_with("wnsprintf")
                              ? Json::array({"pszDest", "cchDest", "pszFmt"})
                              : Json::array({"hAppInst", "hWnd", "lpcText", "lpcTitle", "fuStyle"})),
                "Variadic parameter names differ", row);
        bool wide = name.ends_with('W');
        if (name.starts_with("wnsprintf"))
            Require(Query(catalog,
                          "SELECT bytes,extent_index,multiplier,flags FROM capture_parameters "
                          "WHERE function_id=? AND ordinal=0",
                          Json::array({row["id"]})) ==
                        Json::array({{{"bytes", 0}, {"extent_index", 1}, {"multiplier", wide ? 2 : 1}, {"flags", 2}}}),
                    "Windows format output capture differs", row);
        if (name.starts_with("ShellMessageBox"))
            Require(Query(catalog, "SELECT bytes,flags,kind FROM capture_parameters WHERE function_id=? AND ordinal=2",
                          Json::array({row["id"]})) ==
                        Json::array({{{"bytes", UINT32_MAX}, {"flags", 9}, {"kind", wide ? 2 : 3}}}),
                    "Shell message resource capture differs", row);
    }
    Require(seen.size() == counts.size(), "Windows variadic prefixes missing");
    auto shell = Image(L"C:\\Windows\\System32\\shell32.dll").Exports();
    auto provider = Image(L"C:\\Windows\\System32\\shlwapi.dll").Exports();
    for (auto name : {"ShellMessageBoxA", "ShellMessageBoxW"})
    {
        auto forwarder = shell[name]["forwarder"].get<std::string>();
        std::ranges::transform(forwarder, forwarder.begin(),
                               [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
        auto expected = std::string("shlwapi.") + name;
        std::ranges::transform(expected, expected.begin(),
                               [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
        Require(forwarder == expected && provider[name]["executable"] == true, "Shell message forwarder differs");
    }
    RunTarget(context);
    Capture::Run(context, {.limit = 32}, [&](Capture& capture)
    {
        auto rows = capture.Find("wsprintf[AW]|wnsprintf[AW]|_snprintf");
        std::set<std::pair<std::string, std::string>> formats;
        std::set<std::pair<std::string, uint32_t>> longCases;
        size_t tails = 0, longs = 0;
        for (const auto& row : rows)
        {
            auto name = row["name"].get<std::string>(), module = row["module"].get<std::string>();
            bool wide = name.ends_with('W'), windows = name.starts_with("wsprintf") || name.starts_with("wnsprintf");
            uint32_t parameter = name.starts_with("wsprintf") ? 1 : 2;
            auto pattern = Regions(row["input"], {.parameter = parameter});
            if (pattern.empty()) continue;
            auto bytes = pattern[0].data;
            auto text = String(bytes, wide);
            if (windows && (text.starts_with("Detourist ") || text.starts_with("%s|%S")))
            {
                Require(row["argument_count"] == 32 && Data(row["arguments"]).size() == 256 &&
                            (row["flags"].get<uint32_t>() & 256),
                        "Windows formatter raw prefix differs", row);
                CheckLimit(row, 32);
                if (text.starts_with("Detourist "))
                {
                    auto label = name.starts_with("wsprintf") ? "wsprintf" : "wnsprintf";
                    auto format = std::string("Detourist ") + label + " %u";
                    Require(bytes == Prefix(Encode(format, wide, true), 32), "Windows format input differs", row);
                    auto number = name == "wsprintfA" ? 7 : name == "wsprintfW" ? 8 : name == "wnsprintfA" ? 9 : 10;
                    auto output = Regions(row["output"], {.parameter = 0});
                    Require(!output.empty() && Starts(output[0].data, Prefix(Encode(std::string("Detourist ") + label +
                                                                                        " " + std::to_string(number),
                                                                                    wide, true),
                                                                             32)),
                            "Windows format output differs", row);
                    formats.emplace(module, name);
                }
                else
                {
                    ++tails;
                    auto first = name.starts_with("wsprintf") ? 2u : 3u;
                    std::array kinds = wide ? std::array{1u, 0u, 0u, 1u} : std::array{0u, 1u, 0u, 1u};
                    for (uint32_t index = 0; index < kinds.size(); ++index)
                    {
                        auto values = Regions(row["input"], {.parameter = first + index});
                        auto expected =
                            Encode(kinds[index] ? "Detourist UTF16 tail" : "Detourist ANSI tail", kinds[index], true);
                        Require(values.size() == 1 && values[0].kind == kinds[index] &&
                                    values[0].data == Prefix(expected, 32),
                                "Windows variadic string width differs", row);
                    }
                    Require(Regions(row["input"], {.parameter = first + 4}).empty(),
                            "Numeric variadic slot was dereferenced", row);
                    for (const auto& value : Values(row["output"]))
                        Require(value.index < first || value.index > first + 4,
                                "Input variadic tail has output capture", row);
                }
            }
            if (!Starts(bytes, Encode("LONG"))) continue;
            ++longs;
            auto count = static_cast<uint32_t>(std::stoul(text.substr(4)));
            longCases.emplace(module, count);
            Require(row["argument_count"] == 32 && Data(row["arguments"]).size() == 256 &&
                        (row["flags"].get<uint32_t>() & 256) &&
                        bool(row["flags"].get<uint32_t>() & 2048) == (count <= 28),
                    "Long formatter capture boundary differs", row);
            auto inputs = Values(row["input"]);
            for (uint32_t index = 3; index < std::min(32u, count + 3); ++index)
                Require(Read<uint32_t>(row["arguments"], index * 8) == 65536 + index - 3 &&
                            Regions(inputs, {.parameter = index}).empty(),
                        "Long format numeric slot differs", row);
            if (count <= 28)
            {
                Require(Snapshots(row["input"], count + 3, 0) ==
                            std::vector<Bytes>{Encode("Late CRT string", false, true)},
                        "Late format string missing", row);
                for (const auto& value : inputs)
                    Require(value.index < count + 4, "Unused format argument was probed", row);
            }
            auto expected = "LONG" + std::to_string(count) + ":";
            for (uint32_t index = 0; index < count; ++index)
                expected += std::to_string(65536 + index) + "|";
            expected += "Late CRT string";
            Require(Snapshots(row["output"], 0, 0) == std::vector<Bytes>{Prefix(Encode(expected, false, true), 32)},
                    "Long format native output differs", row);
        }
        Require(formats == std::set<std::pair<std::string, std::string>>{{"user32.dll", "wsprintfA"},
                                                                         {"user32.dll", "wsprintfW"},
                                                                         {"shlwapi.dll", "wnsprintfA"},
                                                                         {"shlwapi.dll", "wnsprintfW"}} &&
                    tails == 4,
                "Windows formatter coverage incomplete", rows);
        std::set<std::pair<std::string, uint32_t>> expectedLong;
        for (auto module : {"shlwapi.dll", "msvcrt.dll", "msvcr120.dll"})
            for (auto count : {20u, 28u, 29u, 36u})
                expectedLong.emplace(module, count);
        Require(longs == 12 && longCases == expectedLong, "Long formatter provider coverage incomplete", rows);
    }, 60);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, FormatVariadic); }

#elif defined(DETOURIST_TEST_DetouristUcrtVaListTests)

using namespace Detourist::Tests;

struct FormatCase
{
    const char* name;
    int count, format, list, buffer, capacity, maximum, stream;
    bool wide, console;
};
const FormatCase Cases[]{
    {"__conio_common_vcprintf", 4, 1, 3, -1, -1, -1, -1, false, true},
    {"__conio_common_vcwprintf", 4, 1, 3, -1, -1, -1, -1, true, true},
    {"__stdio_common_vfprintf", 5, 2, 4, -1, -1, -1, 1, false, false},
    {"__stdio_common_vfwprintf", 5, 2, 4, -1, -1, -1, 1, true, false},
    {"__stdio_common_vsnprintf_s", 7, 4, 6, 1, 2, 3, -1, false, false},
    {"__stdio_common_vsnwprintf_s", 7, 4, 6, 1, 2, 3, -1, true, false},
    {"__stdio_common_vsprintf", 6, 3, 5, 1, 2, -1, -1, false, false},
    {"__stdio_common_vsprintf_p", 6, 3, 5, 1, 2, -1, -1, false, false},
    {"__stdio_common_vswprintf", 6, 3, 5, 1, 2, -1, -1, true, false},
};

int Invoke(FARPROC function, const FormatCase& item, uint64_t options, void* buffer,
    void* stream, const void* format, ...)
{
    va_list list;
    va_start(list, format);
    uint64_t arguments[7]{};
    arguments[0] = options;
    arguments[item.format] = reinterpret_cast<uint64_t>(format);
    arguments[item.list] = reinterpret_cast<uint64_t>(list);
    if (item.buffer >= 0) arguments[item.buffer] = reinterpret_cast<uint64_t>(buffer);
    if (item.capacity >= 0) arguments[item.capacity] = 512;
    if (item.maximum >= 0) arguments[item.maximum] = 511;
    if (item.stream >= 0) arguments[item.stream] = reinterpret_cast<uint64_t>(stream);
    auto call = reinterpret_cast<int (__cdecl *)(uint64_t, ...)>(function);
    int result = call(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6]);
    va_end(list);
    return result;
}

template<size_t... Index>
bool FormatLongList(FARPROC function, const FormatCase& item, bool positional, std::index_sequence<Index...>)
{
    // Reversed positional formats exercise the highest slot before any lower argument is consumed.
    constexpr auto count = sizeof...(Index);
    auto format = std::string(positional ? "PLONG" : "LONG") + std::to_string(count) + ":";
    auto expected = format;
    if (positional)
    {
        format += "%" + std::to_string(count + 1) + "$hs|";
        expected += "UCRT late string|";
        for (auto index = count; index > 0; --index)
        {
            format += "%" + std::to_string(index) + "$u|";
            expected += std::to_string(65535 + index) + "|";
        }
    }
    else
    {
        ((format += "%u|", expected += std::to_string(65536 + Index) + "|"), ...);
        format += "%hs";
        expected += "UCRT late string";
    }
    char output[512]{};
    return Invoke(function, item, 0, output, nullptr, format.c_str(), static_cast<unsigned>(65536 + Index)...,
        "UCRT late string") == expected.size() && output == expected;
}

int TargetMain()
{
    const char narrow[] = "UCRT ANSI payload";
    const wchar_t wide[] = L"UCRT UTF16 payload";
    const wchar_t* modules[]{L"ucrtbase.dll"};
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto memory = static_cast<char*>(VirtualAlloc(nullptr, system.dwPageSize * 4,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    DWORD protection = 0;
    if (!memory || !VirtualProtect(memory + system.dwPageSize, system.dwPageSize, PAGE_NOACCESS, &protection) ||
        !VirtualProtect(memory + system.dwPageSize * 3, system.dwPageSize, PAGE_NOACCESS, &protection)) return 1;
    auto guardedAnsi = memory + system.dwPageSize - 3;
    auto guardedWide = reinterpret_cast<wchar_t*>(memory + system.dwPageSize * 3 - 6);
    memcpy(guardedAnsi, "ABC", 3);
    memcpy(guardedWide, L"XYZ", 6);

    // Each format parameter layout receives a compiler-created Windows x64 va_list.
    for (auto module : modules)
    {
        auto library = LoadLibraryExW(module, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 2;
        using InvalidHandler = decltype(&IgnoreInvalidParameter);
        auto setHandler = reinterpret_cast<InvalidHandler (__cdecl *)(InvalidHandler)>(
            GetProcAddress(library, "_set_invalid_parameter_handler"));
        auto previousHandler = setHandler ? setHandler(IgnoreInvalidParameter) : nullptr;
        auto setReportMode = reinterpret_cast<int (__cdecl *)(int, int)>(GetProcAddress(library, "_CrtSetReportMode"));
        auto previousReportMode = setReportMode ? setReportMode(2, 0) : 0;
        auto temporary = reinterpret_cast<void* (__cdecl *)()>(GetProcAddress(library, "tmpfile"));
        auto close = reinterpret_cast<int (__cdecl *)(void*)>(GetProcAddress(library, "fclose"));
        if (!temporary || !close) return 3;
        for (const auto& item : Cases)
        {
            auto function = GetProcAddress(library, item.name);
            if (!function) return 4;
            constexpr uint64_t flags[]{0, 1, 2, 3, 4, 5, 6, 7};
            for (auto options : flags)
            {
                char output[512]{};
                wchar_t wideOutput[512]{};
                auto buffer = item.wide ? static_cast<void*>(wideOutput) : output;
                void* stream = item.stream >= 0 ? temporary() : nullptr;
                if (item.stream >= 0 && !stream) return 5;
                const bool legacyWide = item.wide && (options & 4);
                int result = item.wide ?
                    Invoke(function, item, options, buffer, stream, L"MIX:%s|%S|%hs|%ls|%I64x|%.1f|%u|%%",
                        legacyWide ? static_cast<const void*>(wide) : narrow,
                        legacyWide ? static_cast<const void*>(narrow) : wide,
                        narrow, wide, 0x123456789abcdef0ull, 2.5, 65536u) :
                    Invoke(function, item, options, buffer, stream, "MIX:%s|%S|%hs|%ls|%I64x|%.1f|%u|%%",
                        narrow, wide, narrow, wide, 0x123456789abcdef0ull, 2.5, 65536u);
                if (stream) close(stream);
                if (!item.console && result <= 0) return 6;
                if (item.buffer >= 0)
                {
                    const char expected[] = "MIX:UCRT ANSI payload|UCRT UTF16 payload|UCRT ANSI payload|"
                        "UCRT UTF16 payload|123456789abcdef0|2.5|65536|%";
                    const wchar_t expectedIso[] = L"MIX:UCRT ANSI payload|UCRT UTF16 payload|UCRT ANSI payload|"
                        L"UCRT UTF16 payload|123456789abcdef0|2.5|65536|%";
                    const wchar_t expectedLegacy[] = L"MIX:UCRT UTF16 payload|UCRT ANSI payload|UCRT ANSI payload|"
                        L"UCRT UTF16 payload|123456789abcdef0|2.5|65536|%";
                    if (item.wide ? wcscmp(wideOutput, legacyWide ? expectedLegacy : expectedIso) :
                        strcmp(output, expected)) return 7;
                }
            }
        }

        // Guarded and positional strings retain their actual extents; unsupported options retain raw storage.
        const auto& item = Cases[6];
        auto function = GetProcAddress(library, item.name);
        char output[512]{};
        if (Invoke(function, item, 0, output, nullptr, "GUARD:%*.*hs|%.*ls", 6, 3,
            guardedAnsi, 3, guardedWide) <= 0 || strcmp(output, "GUARD:   ABC|XYZ")) return 8;
        if (Invoke(function, item, 0, output, nullptr, "ZERO:%.0hs|%.0ls", narrow, wide) != 6 ||
            strcmp(output, "ZERO:|")) return 9;
        if (Invoke(function, item, 1ull << 63, output, nullptr, "UNKNOWN:%ls", wide) <= 0 ||
            strcmp(output, "UNKNOWN:UCRT UTF16 payload")) return 10;
        const auto& positional = Cases[7];
        if (Invoke(GetProcAddress(library, positional.name), positional, 0, output, nullptr,
            "POS:%2$s|%1$u", 7u, narrow) <= 0 || strcmp(output, "POS:UCRT ANSI payload|7")) return 11;
        auto positionalFunction = GetProcAddress(library, positional.name);
        if (Invoke(positionalFunction, positional, 0, output, nullptr,
            "PWIDTH:%3$*1$.*2$hs|%3$.*2$hs", 6, 3, guardedAnsi) != 17 ||
            strcmp(output, "PWIDTH:   ABC|ABC") ||
            Invoke(positionalFunction, positional, 0, output, nullptr,
                "REUSE:%1$.3hs|%1$.8hs", narrow) != 18 || strcmp(output, "REUSE:UCR|UCRT ANS") ||
            Invoke(positionalFunction, positional, 0, output, nullptr,
                "PFLOAT:%2$hs|%1$.1f|%1$.2f", 2.5, narrow) != 33 ||
                strcmp(output, "PFLOAT:UCRT ANSI payload|2.5|2.50")) return 12;
        struct CountedString { uint16_t length, maximumLength; const char* buffer; };
        const char counted[]{'A', 'B', '\0', 'C', 'D'};
        CountedString descriptor{sizeof(counted), sizeof(counted), counted};
        if (Invoke(positionalFunction, positional, 0, output, nullptr,
            "PCOUNTED:%2$hs|%1$hZ", &descriptor, narrow) != 32) return 14;
        auto enableCounts = reinterpret_cast<int (__cdecl *)(int)>(GetProcAddress(library, "_set_printf_count_output"));
        if (!enableCounts) return 15;
        auto previousCounts = enableCounts(1);
        int written = -777;
        auto countedResult = Invoke(positionalFunction, positional, 0, output, nullptr,
            "PCOUNT:%2$hs|%1$n", &written, narrow);
        enableCounts(previousCounts);
        if (countedResult >= 0 || written != -777) return 16;
        for (auto invalid : {"GAP:%2$hs", "MIXED:%1$hs|%hs", "CONFLICT:%1$hs|%1$u", "ZERO_POS:%0$hs",
            "WIDTH_TYPE:%1$*1$hs"})
            if (Invoke(positionalFunction, positional, 0, output, nullptr, invalid, narrow, narrow) >= 0) return 13;

        // Native output remains complete when the argument list exceeds the captured slot window.
        for (bool usePositions : {false, true})
        {
            const auto& longItem = usePositions ? positional : item;
            auto longFunction = usePositions ? positionalFunction : function;
            if (!FormatLongList(longFunction, longItem, usePositions, std::make_index_sequence<20>{}) ||
                !FormatLongList(longFunction, longItem, usePositions, std::make_index_sequence<31>{}) ||
                !FormatLongList(longFunction, longItem, usePositions, std::make_index_sequence<32>{})) return 17;
        }
        if (setHandler) setHandler(previousHandler);
        if (setReportMode) setReportMode(2, previousReportMode);
        FreeLibrary(library);
    }
    VirtualFree(memory, 0, MEM_RELEASE);
    return 0;
}

void UcrtVaList(const Context& context)
{
    std::set<std::string> names{"__conio_common_vcprintf",  "__conio_common_vcwprintf",   "__stdio_common_vfprintf",
                                "__stdio_common_vfwprintf", "__stdio_common_vsnprintf_s", "__stdio_common_vsnwprintf_s",
                                "__stdio_common_vsprintf",  "__stdio_common_vsprintf_p",  "__stdio_common_vswprintf"};
    std::map<std::string, Json> plans;
    for (const auto& row : Query(context.collector.parent_path() / L"ApiCatalog.sqlite",
                                 "SELECT name,parameters FROM functions WHERE module='$crt'"))
    {
        auto name = row["name"].get<std::string>();
        if (names.contains(name)) plans[name] = Json::parse(row["parameters"].get<std::string>());
    }
    Require(plans.size() == names.size(), "UCRT formatter plans missing");
    auto parameter = [](const Json& plan, const char* name)
    {
        for (uint32_t index = 0; index < plan.size(); ++index)
            if (plan[index]["name"] == name) return index;
        throw std::runtime_error(std::string("UCRT formatter parameter missing: ") + name);
    };
    RunTarget(context, L"", 30000);
    Json details = Json::array();
    for (uint32_t limit : {16u, 64u, 128u, 512u})
    {
        Capture::Run(context, {.limit = limit}, [&](Capture& capture)
        {
            using Case = std::tuple<std::string, uint64_t, std::string>;
            std::map<Case, Json> cases;
            for (const auto& row : capture.Find("__(conio|stdio)_common_.*", "ucrtbase\\.dll"))
            {
                auto name = row["name"].get<std::string>();
                if (!plans.contains(name)) continue;
                const auto& plan = plans.at(name);
                auto index = parameter(plan, "_Format");
                bool wide = plan[index]["type"].get<std::string>().contains("wchar_t");
                for (const auto& value : Regions(row["input"], {.parameter = index}))
                {
                    auto text = String(value.data, wide);
                    auto marker = text.substr(0, text.find(':'));
                    cases[{name, Read<uint64_t>(row["arguments"]), marker}] = row;
                }
            }
            auto get = [&](const char* name, uint64_t options, const std::string& marker)
            {
                auto key = Case{name, options, marker};
                Require(cases.contains(key), "UCRT formatter case missing: " + std::string(name) + " " + marker);
                return cases.at(key);
            };
            auto children = [](const Json& payload, uint32_t index = 5)
            { return Regions(payload, {.parameter = index, .required = 64}); };
            auto indices = [](const auto& values, uint32_t count)
            {
                std::set<uint32_t> actual, expected;
                for (const auto& value : Regions(values, {.kind = 2}))
                    actual.insert(value.flags >> 16);
                for (uint32_t i = 0; i < count; ++i)
                    expected.insert(i);
                Require(actual == expected, "UCRT list scalar ordinals differ");
            };
            auto inspect = [&](const Json& row, const char* family, uint32_t index = 5)
            {
                details.push_back(
                    {{"family", family}, {"limit", limit}, {"call", capture.Details(row)}, {"parameter", index}});
            };

            // Whole argument slots precede referenced buffers, with one ordinal for each value.
            for (const auto& [name, plan] : plans)
                for (uint64_t options = 0; options < 8; ++options)
                {
                    auto row = get(name.c_str(), options, "MIX");
                    auto list = parameter(plan, "_ArgList");
                    bool wide = plan[parameter(plan, "_Format")]["type"].get<std::string>().contains("wchar_t");
                    bool legacy = wide && (options & 4);
                    auto values = children(row["input"], list);
                    Require(row["argument_count"] == plan.size() && !(row["flags"].get<uint32_t>() & 256) &&
                                row["parameters"].get<std::string>().contains("_ArgList") &&
                                Regions(row["input"], {.parameter = list, .kind = 0, .excluded = 64}).empty(),
                            "UCRT list argument contract differs", row);
                    CheckLimit(row, limit);
                    indices(values, 7);
                    std::map<uint32_t, Bytes> scalars;
                    for (const auto& value : Regions(values, {.kind = 2}))
                    {
                        Require(value.data.size() == 8, "UCRT scalar slot is incomplete", row);
                        scalars[value.flags >> 16] = value.data;
                    }
                    Require(Read<uint64_t>(scalars.at(4)) == 0x123456789abcdef0 && Read<double>(scalars.at(5)) == 2.5 &&
                                Read<uint32_t>(scalars.at(6)) == 65536,
                            "UCRT scalar values differ", row);
                    std::array widths =
                        legacy ? std::array{true, false, false, true} : std::array{false, true, false, true};
                    for (uint32_t ordinal = 0; ordinal < widths.size(); ++ordinal)
                    {
                        auto referenced = Regions(values, {.required = 8, .element = ordinal});
                        bool unicode = widths[ordinal];
                        Require(
                            referenced.size() == 1 && referenced[0].kind == uint32_t(unicode) &&
                                referenced[0].data ==
                                    Prefix(Encode(unicode ? "UCRT UTF16 payload" : "UCRT ANSI payload", unicode, true),
                                           limit),
                            "UCRT referenced string differs", row);
                    }
                    Require(children(row["output"], list).empty(), "Input UCRT list has captured output", row);
                    if ((name == "__stdio_common_vswprintf" && options == 4) ||
                        (limit == 128 && (options == 0 || options == 4)))
                        inspect(row, "ucrt", list);
                }

            // Guarded and positional graphs retain complete references and reject incompatible views.
            auto guard = get("__stdio_common_vsprintf", 0, "GUARD");
            for (auto [ordinal, text, wide] : {std::tuple{2u, "ABC", false}, {4u, "XYZ", true}})
            {
                auto values = Regions(children(guard["input"]), {.required = 8, .excluded = 2, .element = ordinal});
                Require(
                    std::ranges::any_of(values, [&](const Value& value) { return value.data == Encode(text, wide); }),
                    "Guarded UCRT string differs", guard);
            }
            Require(Regions(children(get("__stdio_common_vsprintf", 0, "ZERO")["input"]), {.required = 8}).empty(),
                    "Zero precision UCRT input was dereferenced");
            auto positional = get("__stdio_common_vsprintf_p", 0, "POS");
            auto values = children(positional["input"]);
            indices(values, 2);
            auto narrow = Prefix(Encode("UCRT ANSI payload", false, true), limit);
            Require(std::ranges::any_of(Regions(values, {.required = 8, .element = 1}),
                                        [&](const Value& value) { return value.data == narrow; }) &&
                        Regions(positional["input"], {.parameter = 5, .excluded = 64}).empty(),
                    "Positional UCRT references differ", positional);
            if (limit == 128 && !context.Optional(1).empty()) inspect(positional, "positional");
            for (auto [marker, count, ordinal, expected] : {std::tuple{"REUSE", 1u, 0u, Prefix(narrow, 8)},
                                                            {"PWIDTH", 3u, 2u, Encode("ABC")},
                                                            {"PFLOAT", 2u, 1u, narrow}})
            {
                auto row = get("__stdio_common_vsprintf_p", 0, marker);
                auto captured = children(row["input"]);
                indices(captured, count);
                auto references = Regions(captured, {.required = 8, .element = ordinal});
                Require(references.size() == 1 && references[0].data == expected,
                        "Positional UCRT reuse or width differs", row);
                if (limit == 128 && !context.Optional(1).empty()) inspect(row, "positional");
            }
            auto counted = get("__stdio_common_vsprintf_p", 0, "PCOUNTED");
            values = children(counted["input"]);
            Require(std::ranges::any_of(Regions(values, {.kind = 0, .excluded = 8, .element = 0}),
                                        [](const Value& value) { return value.data.size() == 16; }) &&
                        std::ranges::any_of(Regions(values, {.kind = 0, .required = 8, .element = 0}),
                                            [](const Value& value)
            { return value.data == Bytes{'A', 'B', 0, 'C', 'D'}; }),
                    "UCRT counted descriptor differs", counted);
            auto written = get("__stdio_common_vsprintf_p", 0, "PCOUNT");
            auto returned = children(written["output"]),
                 initial = Regions(written["input"], {.parameter = 5, .kind = 0, .required = 8, .element = 0});
            Require(returned.size() == 1 && returned[0].kind == 0 && (returned[0].flags & 8) &&
                        returned[0].flags >> 16 == 0 && returned[0].data == Integer(uint32_t(-777), 4) &&
                        initial.size() == 1 && initial[0].data == returned[0].data,
                    "UCRT positional count differs", written);
            auto unknown = get("__stdio_common_vsprintf", 1ull << 63, "UNKNOWN");
            auto raw = Regions(unknown["input"], {.parameter = 5});
            Require(Regions(unknown["input"], {.required = 64}).empty() && raw.size() == 1 && raw[0].kind == 0 &&
                        raw[0].original == UINT32_MAX && raw[0].data.size() == limit &&
                        Regions(unknown["output"], {.parameter = 5}).empty(),
                    "Unknown UCRT options were decoded", unknown);
            for (auto marker : {"GAP", "MIXED", "CONFLICT", "ZERO_POS", "WIDTH_TYPE"})
            {
                raw = Regions(get("__stdio_common_vsprintf_p", 0, marker)["input"], {.parameter = 5});
                Require(raw.size() == 1 && !(raw[0].flags & 64) && raw[0].original == UINT32_MAX,
                        "Invalid positional UCRT graph was decoded");
            }

            // Lists preserve complete slots through 31; overlong positional graphs fall back together.
            for (bool positionalList : {false, true})
                for (uint32_t integers : {20u, 31u, 32u})
                {
                    auto marker = std::string(positionalList ? "PLONG" : "LONG") + std::to_string(integers);
                    auto row = get(positionalList ? "__stdio_common_vsprintf_p" : "__stdio_common_vsprintf", 0, marker);
                    auto captured = Regions(row["input"], {.parameter = 5});
                    auto scalars = Regions(captured, {.kind = 2, .required = 64});
                    auto count = positionalList && integers == 32 ? 0u : std::min(32u, integers + 1);
                    indices(scalars, count);
                    for (uint32_t index = 0; index < std::min(integers, count); ++index)
                    {
                        auto scalar = Regions(scalars, {.element = index});
                        Require(scalar.size() == 1 && Read<uint32_t>(scalar[0].data) == 65536 + index,
                                "Long UCRT scalar differs", row);
                    }
                    auto references = Regions(captured, {.required = 8});
                    Require(integers < 32
                                ? references.size() == 1 && references[0].flags >> 16 == integers &&
                                      references[0].data == Prefix(Encode("UCRT late string", false, true), limit)
                                : references.empty(),
                            "Long UCRT string boundary differs", row);
                    raw = Regions(captured, {.excluded = 64});
                    Require(raw.empty() == (integers != 32) &&
                                (raw.empty() ||
                                 (raw.size() == 1 && raw[0].data.size() == limit && raw[0].original == UINT32_MAX)),
                            "Long UCRT fallback differs", row);
                    if (limit == 512 && integers < 32 && !context.Optional(1).empty()) inspect(row, "positional");
                }
        });
    }
    if (!context.Optional(0).empty()) WriteJson(context.Optional(0), details);
    Inspect(context, context.Optional(1), "--buffer-elements", details, 30000);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, UcrtVaList); }

#elif defined(DETOURIST_TEST_DetouristLegacyFormatListTests)

using namespace Detourist::Tests;

using Json = nlohmann::json;
std::string reportedMessage;

int __cdecl CaptureReport(int, char* message, int* result)
{
    reportedMessage = message;
    *result = 0;
    return 1;
}

std::string Hex(const void* data, size_t size)
{
    constexpr char digits[] = "0123456789ABCDEF";
    const auto bytes = static_cast<const uint8_t*>(data);
    std::string output;
    for (size_t index = 0; index < size; ++index)
    {
        output += digits[bytes[index] >> 4];
        output += digits[bytes[index] & 15];
    }
    return output;
}

template<size_t Size, size_t... Index>
int InvokeRaw(FARPROC function, const std::array<uint64_t, Size>& arguments, std::index_sequence<Index...>)
{
    return reinterpret_cast<int (__cdecl *)(uint64_t, ...)>(function)(arguments[Index]...);
}

int InvokeList(FARPROC function, std::array<uint64_t, 8> prefix, int listIndex, ...)
{
    va_list arguments;
    va_start(arguments, listIndex);
    prefix[listIndex] = reinterpret_cast<uint64_t>(arguments);
    const auto result = InvokeRaw(function, prefix, std::make_index_sequence<8>{});
    va_end(arguments);
    return result;
}

template<size_t... Index>
int Invoke(FARPROC function, std::array<uint64_t, 8> prefix, int list, int first,
    const std::array<uint64_t, 40>& values, std::index_sequence<Index...>)
{
    if (list >= 0) return InvokeList(function, prefix, list, values[Index]...);
    std::array<uint64_t, 48> direct{};
    for (int index = 0; index < first; ++index) direct[index] = prefix[index];
    for (size_t index = 0; index < values.size(); ++index) direct[first + index] = values[index];
    return InvokeRaw(function, direct, std::make_index_sequence<48>{});
}

bool Samples(HMODULE library, const std::string& module, const Json& item, uint8_t* memory,
    uint32_t pageSize, Json& samples)
{
    const auto name = item.at("name").get<std::string>();
    const auto wide = item.at("wide").get<bool>();
    const auto list = item.at("list").get<int>();
    const auto first = item.at("first").get<int>();
    const auto formatIndex = item.at("formatIndex").get<int>();
    const auto bufferIndex = item.at("buffer").get<int>();
    const auto streamIndex = item.at("stream").get<int>();
    const auto localeIndex = item.at("locale").get<int>();
    const auto console = item.at("console").get<bool>();
    const auto reporting = name.find("CrtDbgReport") != std::string::npos;
    const auto native = module == "ntdll.dll";
    const auto positional = name.find("printf_p") != std::string::npos;
    const auto bounded = name == "_vsnprintf" || name == "_vsnwprintf";
    const auto temporary = reinterpret_cast<void* (__cdecl *)()>(GetProcAddress(library, "tmpfile"));
    const auto rewind = reinterpret_cast<void (__cdecl *)(void*)>(GetProcAddress(library, "rewind"));
    const auto read = reinterpret_cast<size_t (__cdecl *)(void*, size_t, size_t, void*)>(
        GetProcAddress(library, "fread"));
    const auto close = reinterpret_cast<int (__cdecl *)(void*)>(GetProcAddress(library, "fclose"));
    const auto createLocale = reinterpret_cast<void* (__cdecl *)(int, const char*)>(
        GetProcAddress(library, "_create_locale"));
    const auto freeLocale = reinterpret_cast<void (__cdecl *)(void*)>(GetProcAddress(library, "_free_locale"));
    if (streamIndex >= 0 && (!temporary || !rewind || !read || !close)) return false;

    // Real providers consume compiler-created lists, including guarded strings and count storage.
    for (int scenario = 0; scenario < 8; ++scenario)
    {
        if (scenario == 2 && (native || reporting || console || name.find("_s") != std::string::npos) ||
            scenario == 3 && !positional || (scenario == 4 || scenario == 5) && !bounded ||
            scenario == 6 && (!wide || localeIndex < 0 || !createLocale || !freeLocale) ||
            scenario == 7 && !reporting) continue;
        const auto id = samples.size() + 1;
        const auto number = std::to_string(id);
        const auto prefix = "LF" + std::string(6 - number.size(), '0') + number + ":";
        std::string format = prefix, expected = prefix;
        std::array<uint64_t, 40> arguments{};
        auto fields = Json::array();
        auto add = [&](const char* type, uint64_t value, const void* data = nullptr,
            size_t bytes = 0, bool unicode = false, bool terminated = true, bool count = false)
        {
            const auto index = fields.size();
            arguments[index] = value;
            fields.push_back({{"index", index}, {"type", type}, {"value", value}, {"kind", unicode ? 1 : 0},
                {"data", data ? Hex(data, bytes) : ""}, {"terminated", terminated}, {"count", count}});
        };
        const char narrow[] = "Legacy ANSI payload";
        const wchar_t unicode[] = L"Legacy UTF16 payload";
        auto addText = [&](bool unicodeValue)
        {
            add(unicodeValue ? "wchar_t *" : "char *", reinterpret_cast<uint64_t>(
                unicodeValue ? static_cast<const void*>(unicode) : narrow),
                unicodeValue ? static_cast<const void*>(unicode) : narrow,
                unicodeValue ? sizeof(unicode) : sizeof(narrow), unicodeValue);
        };
        auto count = memory + pageSize * 5 - 4;
        memset(count, 0xCC, 4);
        void* locale = nullptr;
        switch (scenario)
        {
        case 0:
            format += "%s|%S|%hs|%ls|%I64x|";
            expected += wide ? "Legacy UTF16 payload|Legacy ANSI payload|" :
                "Legacy ANSI payload|Legacy UTF16 payload|";
            expected += "Legacy ANSI payload|Legacy UTF16 payload|123456789abcdef0|";
            addText(wide);
            addText(!wide);
            addText(false);
            addText(true);
            add("UInt64", 0x123456789abcdef0);
            if (!native)
            {
                double floating = 2.5;
                uint64_t bits = 0;
                memcpy(&bits, &floating, 8);
                format += "%.1f|";
                expected += "2.5|";
                add("Float64", bits);
            }
            format += "%u|%%";
            expected += "65536|%";
            add("UInt32", 65536);
            break;
        case 1:
        {
            auto ansi = memory + pageSize - 3;
            auto utf16 = memory + pageSize * 3 - 6;
            memcpy(ansi, "ABC", 3);
            memcpy(utf16, L"XYZ", 6);
            format += "%*.*hs|%.*ls";
            expected += "   ABC|XYZ";
            add("Int32", 6);
            add("Int32", 3);
            add("char *", reinterpret_cast<uint64_t>(ansi), ansi, 3, false, false);
            add("Int32", 3);
            add("wchar_t *", reinterpret_cast<uint64_t>(utf16), utf16, 6, true, false);
            break;
        }
        case 2:
            format += "%n%hs";
            expected += narrow;
            add("Int32 *", reinterpret_cast<uint64_t>(count), count, 4, false, false, true);
            addText(false);
            break;
        case 3:
            format += "%2$hs|%1$u|%2$.3hs";
            expected += std::string(narrow) + "|7|Leg";
            add("UInt32", 7);
            addText(false);
            break;
        case 4:
        case 5:
            for (unsigned index = 0; index < (scenario == 4 ? 31u : 32u); ++index)
            {
                format += "%u|";
                expected += std::to_string(100 + index) + "|";
                add("UInt32", 100 + index);
            }
            format += "%hs";
            expected += narrow;
            addText(false);
            break;
        case 6:
        {
            auto ansi = memory + pageSize - 2;
            memcpy(ansi, "\x82\xA0", 2);
            format += "%.*hs";
            add("Int32", 1);
            add("char *", reinterpret_cast<uint64_t>(ansi), ansi, 2, false, false);
            locale = createLocale(2, ".932");
            if (!locale) return false;
            break;
        }
        case 7:
            expected += "(0) : ";
            break;
        }
        const std::wstring wideFormat(format.begin(), format.end());
        std::wstring wideExpected(expected.begin(), expected.end());
        if (scenario == 6) { wideExpected += L"\x3042"; expected += "\x82\xA0"; }
        std::array<uint8_t, 2048> output{};
        std::array<uint64_t, 8> fixed{};
        fixed[formatIndex] = reinterpret_cast<uint64_t>(wide ?
            static_cast<const void*>(wideFormat.c_str()) : format.c_str());
        if (scenario == 7)
        {
            fixed[item.at("file").get<int>()] = fixed[formatIndex];
            fixed[formatIndex] = 0;
        }
        if (bufferIndex >= 0) fixed[bufferIndex] = reinterpret_cast<uint64_t>(output.data());
        if (item.at("capacity") >= 0) fixed[item.at("capacity").get<int>()] = 1024;
        if (item.at("maximum") >= 0) fixed[item.at("maximum").get<int>()] = 1023;
        if (localeIndex >= 0) fixed[localeIndex] = reinterpret_cast<uint64_t>(locale);
        void* stream = streamIndex >= 0 ? temporary() : nullptr;
        if (streamIndex >= 0 && !stream) return false;
        if (stream) fixed[streamIndex] = reinterpret_cast<uint64_t>(stream);
        reportedMessage.clear();
        auto function = GetProcAddress(library, name.c_str());
        const auto result = Invoke(function, fixed, list, first, arguments, std::make_index_sequence<40>{});
        bool valid = true;
        std::string outputBytes;
        if (bufferIndex >= 0)
        {
            valid = result == (wide ? wideExpected.size() : expected.size()) && (wide ?
                !wcscmp(reinterpret_cast<const wchar_t*>(output.data()), wideExpected.c_str()) :
                !strcmp(reinterpret_cast<const char*>(output.data()), expected.c_str()));
            outputBytes = Hex(output.data(), (wide ? wideExpected.size() * 2 : expected.size()));
        }
        else if (stream)
        {
            rewind(stream);
            const auto bytes = read(output.data(), 1, output.size(), stream);
            outputBytes = Hex(output.data(), bytes);
            valid = result == (wide ? wideExpected.size() : expected.size()) &&
                (outputBytes == Hex(expected.data(), expected.size()) ||
                    wide && outputBytes == Hex(wideExpected.data(), wideExpected.size() * 2));
            close(stream);
        }
        else if (reporting)
        {
            outputBytes = Hex(reportedMessage.data(), reportedMessage.size());
            valid = result == 0 && (module == "msvcrt.dll" || reportedMessage == expected);
        }
        else if (!console) valid = result == (wide ? wideExpected.size() : expected.size());
        if (scenario == 2)
        {
            int observed = 0;
            memcpy(&observed, count, 4);
            valid = result == -1 ? static_cast<uint32_t>(observed) == 0xCCCCCCCCu :
                valid && observed == prefix.size();
            fields[0]["after"] = Hex(count, 4);
        }
        if (locale) freeLocale(locale);
        if (!valid)
        {
            fprintf(stderr, "%s!%s scenario=%d result=%d expected=%zu output=%s\n",
                module.c_str(), name.c_str(), scenario, result, wide ? wideExpected.size() : expected.size(),
                outputBytes.c_str());
            return false;
        }
        samples.push_back({{"id", id}, {"module", module}, {"name", name}, {"wide", wide},
            {"scenario", scenario}, {"text", format}, {"formatIndex", formatIndex}, {"list", list}, {"first", first},
            {"result", result}, {"output", outputBytes}, {"console", console}, {"fields", fields},
            {"aliases", item.at("aliases")}, {"raw", item.at("raw")}});
    }
    return true;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 3) return 1;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::ifstream input{std::filesystem::path(argv[1])};
    const auto providers = Json::parse(input);
    auto samples = Json::array();
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, system.dwPageSize * 6,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!memory) return 2;
    for (unsigned page : {1u, 3u, 5u})
    {
        DWORD previous = 0;
        if (!VirtualProtect(memory + page * system.dwPageSize, system.dwPageSize, PAGE_NOACCESS, &previous)) return 3;
    }
    for (const auto& provider : providers)
    {
        const auto module = provider.at("module").get<std::string>();
        auto library = LoadLibraryExA(module.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 4;
        using InvalidHandler = decltype(&IgnoreInvalidParameter);
        auto setHandler = reinterpret_cast<InvalidHandler (__cdecl *)(InvalidHandler)>(
            GetProcAddress(library, "_set_invalid_parameter_handler"));
        if (setHandler) setHandler(IgnoreInvalidParameter);
        auto enableCounts = reinterpret_cast<int (__cdecl *)(int)>(
            GetProcAddress(library, "_set_printf_count_output"));
        if (enableCounts) enableCounts(1);
        auto setMode = reinterpret_cast<int (__cdecl *)(int, int)>(GetProcAddress(library, "_CrtSetReportMode"));
        if (setMode) for (int kind = 0; kind < 3; ++kind) setMode(kind, 0);
        using ReportHook = decltype(&CaptureReport);
        auto setHook = reinterpret_cast<ReportHook (__cdecl *)(ReportHook)>(
            GetProcAddress(library, "_CrtSetReportHook"));
        if (setHook) setHook(CaptureReport);
        for (const auto& item : provider.at("cases"))
            if (!Samples(library, module, item, memory, system.dwPageSize, samples)) return 5;
        if (setHook) setHook(nullptr);
        FreeLibrary(library);
    }
    std::ofstream report{std::filesystem::path(argv[2])};
    report << samples.dump();
    VirtualFree(memory, 0, MEM_RELEASE);
    return report ? 0 : 6;
}

Json LegacyContracts(const Path& catalog)
{
    auto names = Query(catalog, "SELECT name FROM functions WHERE module='$crt' AND name LIKE '%printf%' "
                                "AND name NOT LIKE '%common%' AND signature LIKE '%va_list%'");
    for (auto name : {"_CrtDbgReport", "_CrtDbgReportW", "_VCrtDbgReportA", "_VCrtDbgReportW"})
        names.push_back({{"name", name}});
    Json providers = Json::array();
    for (auto module : {"ntdll.dll", "msvcrt.dll", "msvcr100.dll", "msvcr110.dll", "msvcr120.dll", "ucrtbased.dll"})
    {
        std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)> library(
            LoadLibraryW(Detourist::Wide(module).c_str()), FreeLibrary);
        Require(bool(library), "Legacy CRT provider is unavailable: " + std::string(module));
        Json cases = Json::array();
        std::map<std::string, FARPROC> addresses;
        for (const auto& item : names)
        {
            auto name = item["name"].get<std::string>();
            auto function = GetProcAddress(library.get(), name.c_str());
            if (!function) continue;
            auto rows =
                Query(catalog,
                      "SELECT f.parameters,p.argument_count FROM functions f JOIN plans p ON p.function_id=f.id "
                      "WHERE f.module=? AND f.name=?",
                      Json::array({module, name}));
            Require(rows.size() == 1, "Legacy CRT catalog contract missing: " + std::string(module) + " " + name);
            auto parameters = Json::parse(rows[0]["parameters"].get<std::string>());
            Require(rows[0]["argument_count"] == parameters.size(), "Legacy formatter parameter count differs",
                    rows[0]);
            auto find = [&](const char* sought)
            {
                for (int index = 0; index < static_cast<int>(parameters.size()); ++index)
                {
                    auto value = parameters[index]["name"].get<std::string>();
                    value.erase(0, value.find_first_not_of('_'));
                    std::ranges::transform(value, value.begin(),
                                           [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
                    if (value == sought) return index;
                }
                return -1;
            };
            int pattern = find("format"), list = -1, buffer = find("buffer"), stream = find("stream");
            for (int index = 0; index < static_cast<int>(parameters.size()); ++index)
                if (parameters[index]["type"] == "va_list")
                {
                    list = index;
                    break;
                }
            Require(pattern >= 0, "Legacy formatter format parameter missing", rows[0]);
            cases.push_back({{"name", name},
                             {"wide", parameters[pattern]["type"].get<std::string>().contains("wchar_t")},
                             {"formatIndex", pattern},
                             {"list", list},
                             {"first", parameters.size()},
                             {"buffer", buffer},
                             {"stream", stream},
                             {"capacity", find("buffercount")},
                             {"maximum", find("maxcount")},
                             {"locale", find("locale")},
                             {"file", find("filename")},
                             {"console", buffer < 0 && stream < 0 && !name.contains("scprintf") &&
                                             !name.contains("scwprintf") && !name.contains("CrtDbgReport")}});
            addresses[name] = function;
        }
        Require(!cases.empty(), "Legacy CRT provider has no formatter cases");
        for (auto& item : cases)
        {
            bool raw = false;
            Json aliases = Json::array();
            for (const auto& other : cases)
                if (addresses.at(other["name"]) == addresses.at(item["name"]))
                {
                    aliases.push_back(other["name"]);
                    for (auto field : {"wide", "formatIndex", "list"})
                        raw |= other[field] != item[field];
                }
            item["raw"] = raw;
            item["aliases"] = aliases;
        }
        providers.push_back({{"module", module}, {"cases", cases}});
    }
    return providers;
}

void LegacyFormatList(const Context& context)
{
    auto config = context.directory / L"contracts.json", report = context.directory / L"formats.json";
    WriteJson(config, LegacyContracts(context.collector.parent_path() / L"ApiCatalog.sqlite"));
    auto arguments = Quote(config) + L" " + Quote(report);
    RunTarget(context, arguments, 60000);
    auto originals = Group(Report(report), {"id"});
    Require(originals.size() >= 500, "Legacy formatter baseline coverage incomplete");
    Json inspections = Json::array();
    auto hello = context.GetCollector().Call("hello");

    // Debug runtime bookkeeping otherwise dominates the formatter trace with critical-section calls.
    std::vector<std::string> excluded;
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    for (auto name : {"RtlEnterCriticalSection", "RtlLeaveCriticalSection"})
    {
        auto address = GetProcAddress(ntdll, name);
        if (!address) continue;
        auto rva = reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(ntdll);
        char alias[64]{};
        sprintf_s(alias, "Shared export RVA 0x%X", static_cast<unsigned>(rva));
        excluded.emplace_back(alias);
    }
    for (uint32_t limit : {16u, 64u, 512u})
    {
        Capture::Run(context, {.arguments = arguments, .limit = limit,
            .apiMask = Number(hello["allApis"]) & ~Number(hello["comMask"]),
            .categoryMask = Detourist::CategoryMask(Detourist::ApiCategory::Runtime), .excludedApis = excluded},
            [&](Capture& capture)
        {
            auto expected = Group(Report(report), {"id"});
            Require(expected.size() == originals.size(), "Legacy formatter native case count differs");
            std::set<std::string> seen;
            for (const auto& row : capture.Find(".*printf.*|.*CrtDbgReport.*|Shared export RVA .*"))
            {
                auto patterns = Select(Values(row["input"]), [](const Value& value)
                { return Starts(value.data, Encode("LF")) || Starts(value.data, Encode("LF", true)); });
                if (patterns.empty()) continue;
                auto bytes = Prefix(patterns[0].data, 16);
                auto text = String(bytes, bytes.size() > 1 && !bytes[1]);
                auto key = Json::array({std::stoul(text.substr(2, 6))}).dump();
                auto sample = expected.at(key)[0], original = originals.at(key)[0];
                auto name = row["name"].get<std::string>();
                bool raw = sample["raw"];
                if (row["module"] != sample["module"] ||
                    (raw ? !name.starts_with("Shared export RVA ")
                         : std::ranges::find(sample["aliases"], row["name"]) == sample["aliases"].end()))
                    continue;
                Require(seen.insert(key).second, "Duplicate legacy formatter case", sample);
                if (sample["console"] == false)
                    Require(sample["result"] == original["result"] && sample["output"] == original["output"],
                            "Legacy formatter native output differs", sample);
                Require(uint32_t(Number(row["result"])) == uint32_t(Number(sample["result"])),
                        "Legacy formatter result differs", row);
                auto before = Values(row["input"]), after = Values(row["output"]);
                if (raw)
                    Require((row["flags"].get<uint32_t>() & 256) && !(row["flags"].get<uint32_t>() & 2048) &&
                                Regions(before, {.required = 64}).empty() && Regions(after, {.required = 64}).empty(),
                            "Ambiguous legacy formatter was decoded", row);
                else
                {
                    int list = sample["list"], first = sample["first"];
                    bool listed = list >= 0;
                    auto count = std::min<size_t>(listed ? 32 : 32 - first, sample["fields"].size());
                    for (size_t ordinal = 0; ordinal < count; ++ordinal)
                    {
                        auto field = sample["fields"][ordinal];
                        uint32_t index = field["index"], parameter = listed ? list : first + index;
                        uint32_t flags = listed ? 72u | (index << 16) : 0;
                        auto references = [&](const auto& values)
                        {
                            return Select(Regions(values, {.parameter = parameter,
                                                           .required = listed ? 72u : 0u,
                                                           .element = listed ? std::optional{index} : std::nullopt}),
                                          [](const Value& value) { return value.kind != 2; });
                        };
                        auto old = references(before), current = references(after);
                        if (listed)
                        {
                            auto slots =
                                Regions(before, {.parameter = parameter, .kind = 2, .required = 64, .element = index});
                            Require(slots.size() == 1 && Read<uint64_t>(slots[0].data) == field["value"],
                                    "Legacy formatter list slot differs", row);
                        }
                        else
                            Require(Read<uint64_t>(row["arguments"], parameter * 8) == field["value"],
                                    "Legacy variadic argument differs", row);
                        auto bytes = Unhex(field["data"]);
                        if (bytes.empty())
                        {
                            Require(old.empty() && current.empty(), "Legacy scalar was dereferenced", row);
                            continue;
                        }
                        bool truncated =
                            field["count"] == false && (field["terminated"] == false || bytes.size() > limit);
                        Require(old == std::vector<Value>{{parameter, field["kind"], flags | uint32_t(truncated),
                                                           truncated ? 0 : bytes.size(), Prefix(bytes, limit)}},
                                "Legacy format input bytes differ", row);
                        if (field["count"] == true)
                            Require(field["after"] == original["fields"][index]["after"] &&
                                        current == std::vector<Value>{{parameter, 0, flags, 4, Unhex(field["after"])}},
                                    "Legacy format count output differs", row);
                        else
                            Require(current.empty(), "Legacy input-only argument has captured output", row);
                    }
                    if (listed)
                    {
                        Require(!Regions(before, {.parameter = uint32_t(list), .excluded = 64}).empty() ==
                                        (sample["fields"].size() > 32) &&
                                    Regions(after, {.parameter = uint32_t(list), .excluded = 64}).empty(),
                                "Legacy list fallback differs", row);
                    }
                    else
                        Require(row["flags"].get<uint32_t>() & 2048, "Legacy variadic completion metadata missing",
                                row);
                    CheckLimit(row, limit);
                }
                if (!context.Optional(0).empty() && limit == 512)
                {
                    sample["call"] = capture.Details(row);
                    inspections.push_back(sample);
                }
            }
            Require(seen.size() == expected.size(), "Legacy formatter capture coverage incomplete", seen);
        }, 150);
    }
    Inspect(context, context.Optional(0), "--legacy-formats", inspections);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, LegacyFormatList); }

#else
#error Select a native test target.
#endif

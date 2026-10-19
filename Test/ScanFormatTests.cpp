#include "TestSupport.h"

using namespace Detourist::Tests;

struct ScanProvider
{
    HMODULE library;
    const char* module;
    const char* name;
    bool wide, secure, listed, common, bounded, localized;
    uint64_t options;
    void* locale = nullptr;
};

int InvokeScanList(const ScanProvider& provider, const void* source, size_t length, const void* format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    auto function = GetProcAddress(provider.library, provider.name);
    auto result = provider.common ? reinterpret_cast<int (__cdecl *)(uint64_t, const void*, size_t,
        const void*, void*, va_list)>(function)(provider.options, source, length, format, provider.locale, arguments) :
        reinterpret_cast<int (__cdecl *)(const void*, const void*, va_list)>(function)(source, format, arguments);
    va_end(arguments);
    return result;
}

template<size_t... Index>
int InvokeScan(const ScanProvider& provider, const void* source, size_t length, const void* format,
    const std::array<uint64_t, 32>& arguments, std::index_sequence<Index...>)
{
    auto function = GetProcAddress(provider.library, provider.name);
    if (provider.listed) return InvokeScanList(provider, source, length, format, arguments[Index]...);
    if (provider.bounded)
        return reinterpret_cast<int (__cdecl *)(const void*, size_t, const void*, ...)>(function)(
            source, length, format, arguments[Index]...);
    if (provider.localized)
        return reinterpret_cast<int (__cdecl *)(const void*, const void*, void*, ...)>(function)(
            source, format, provider.locale, arguments[Index]...);
    return reinterpret_cast<int (__cdecl *)(const void*, const void*, ...)>(function)(
        source, format, arguments[Index]...);
}

bool ScanSamples(const ScanProvider& provider, std::ofstream& report, uint32_t& identifier)
{
    const bool ucrt = provider.common;
    const bool native = std::string_view(provider.module) == "ntdll.dll";
    const bool defaultWide = provider.wide && (!provider.common || provider.options & 2);
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, system.dwPageSize * 64,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!memory) return false;
    for (uint32_t index = 0; index < 32; ++index)
    {
        DWORD protection = 0;
        if (!VirtualProtect(memory + system.dwPageSize * (index * 2 + 1), system.dwPageSize,
            PAGE_NOACCESS, &protection)) return false;
    }
    struct Destination
    {
        uint32_t index, bytes, assignment;
        const char* type;
        bool wide, terminated, count, readable;
        uint8_t* pointer;
    };
    std::vector<Destination> destinations;
    std::array<uint64_t, 32> arguments{};
    uint32_t next = 0, assignments = 0;
    auto destination = [&](const char* type, uint32_t bytes, bool wide = false, bool terminated = false,
        bool count = false, bool readable = true, bool characters = false, uint32_t capacity = 0)
    {
        auto pointer = memory + system.dwPageSize * (destinations.size() * 2 + 1) - (readable ? bytes : 0);
        if (readable) memset(pointer, 0xCC, bytes);
        destinations.push_back({next, bytes, count ? assignments : ++assignments, type,
            wide, terminated, count, readable, pointer});
        arguments[next++] = reinterpret_cast<uint64_t>(pointer);
        if (provider.secure && (terminated || characters))
            arguments[next++] = capacity ? capacity : bytes / (wide ? 2 : 1);
    };

    // Guarded destinations distinguish storage widths and prevent probes of unassigned output arguments.
    for (unsigned scenario = 0; scenario < 25; ++scenario)
    {
        const bool encoded = scenario == 12 || scenario == 13 || scenario >= 15 && scenario <= 18;
        const bool utf8 = scenario == 13 || scenario == 16 || scenario == 18;
        const bool longEncoded = scenario == 15 || scenario == 16;
        const bool explicitLocale = scenario == 17 || scenario == 18;
        if (scenario == 1 && native || scenario == 9 && (ucrt || provider.secure) ||
            scenario == 10 && (provider.wide || !provider.secure || provider.common || provider.bounded) ||
            encoded && (native || !provider.wide) || utf8 && !ucrt ||
            explicitLocale && !provider.common && !provider.localized || scenario >= 19 && !native ||
            scenario == 20 && !provider.wide || scenario == 22 && !provider.secure) continue;
        destinations.clear();
        arguments.fill(0);
        next = assignments = 0;
        std::string format, source;
        int expected = 0;
        switch (scenario)
        {
        case 0:
            format = "%hhd %hd %d %ld %lld %I32u %I64x %p%n";
            source = "-7 -8 -9 -10 -123456789012 123 1234abcd 1234abcd";
            destination(ucrt ? "Int8 *" : "Int32 *", ucrt ? 1 : 4);
            destination("Int16 *", 2);
            destination("Int32 *", 4);
            destination("Int32 *", 4);
            destination("Int64 *", 8);
            destination("UInt32 *", 4);
            destination("UInt64 *", 8);
            destination("void **", 8);
            destination("Int32 *", 4, false, false, true);
            expected = 8;
            break;
        case 1:
            format = "%f %lf %e %lg";
            source = "1.25 -2.5 4.5e1 0.125";
            destination("Float32 *", 4);
            destination("Float64 *", 8);
            destination("Float32 *", 4);
            destination("Float64 *", 8);
            expected = 4;
            if (ucrt)
            {
                format += " %F %la %A";
                source += " 2.25 0x1.4p+3 0x1.8p+1";
                destination("Float32 *", 4);
                destination("Float64 *", 8);
                destination("Float32 *", 4);
                expected += 3;
            }
            break;
        case 2:
            format = "%d %d %d";
            source = "7 nope";
            destination("Int32 *", 4);
            destination("Int32 *", 4, false, false, false, false);
            destination("Int32 *", 4, false, false, false, false);
            expected = 1;
            break;
        case 3:
            format = "%n%d%nX%d";
            source = "7 Y";
            destination("Int32 *", 4, false, false, true);
            destination("Int32 *", 4);
            destination("Int32 *", 4, false, false, true);
            destination("Int32 *", 4, false, false, false, false);
            expected = 1;
            break;
        case 4:
            format = "%*d %3[]a-c] %*2c %c";
            source = "123 ]ab XY Z";
            destination(defaultWide ? "wchar_t *" : "char *", defaultWide ? 8 : 4, defaultWide, true);
            destination(defaultWide ? "wchar_t *" : "char *", defaultWide ? 2 : 1,
                defaultWide, false, false, true, true);
            expected = 2;
            break;
        case 5:
            format = "%3s|%3c";
            source = "ABC|XYZ";
            destination(defaultWide ? "wchar_t *" : "char *", defaultWide ? 8 : 4, defaultWide, true);
            destination(defaultWide ? "wchar_t *" : "char *", defaultWide ? 6 : 3,
                defaultWide, false, false, true, true);
            expected = 2;
            break;
        case 6:
            format = "%3ls|%3lc|%3hs|%3hc";
            source = "ABC|DEF|GHI|JKL";
            destination("wchar_t *", 8, true, true);
            destination("wchar_t *", 6, true, false, false, true, true);
            destination("char *", native && provider.wide ? 256 : 4, false, true);
            destination("char *", native && provider.wide ? 256 : 3, false, false, false, true, true);
            expected = 4;
            break;
        case 7:
            format = "%80s";
            source = std::string(80, 'A');
            destination(defaultWide ? "wchar_t *" : "char *", defaultWide ? 162 : 81, defaultWide, true);
            expected = 1;
            break;
        case 8:
            format = "%d%n";
            source = "nope";
            destination("Int32 *", 4, false, false, false, false);
            destination("Int32 *", 4, false, false, true);
            expected = 0;
            break;
        case 9:
            format = "%F %d";
            source = "1.25 7";
            destination("Float32 *", 4, false, false, false, false);
            destination("Int32 *", 4, false, false, false, false);
            expected = 0;
            break;
        case 10:
            for (unsigned index = 0; index < 29; ++index)
            {
                format += "%d";
                source += "7 ";
                destination("Int32 *", 4);
            }
            format += " %3c";
            source += "XYZ";
            destination("char *", 3, false, false, false, true, true);
            expected = 30;
            break;
        case 11:
            format = "%3c";
            source = "A";
            destination(defaultWide ? "wchar_t *" : "char *", defaultWide ? 6 : 3,
                defaultWide, false, false, true, true);
            expected = !ucrt || provider.options & 4 ? 1 : -1;
            break;
        case 12:
        case 13:
        case 15:
        case 16:
        case 17:
        case 18:
            format = longEncoded ? "%40hc|%40hs" : "%2hc|%2hs";
            destination("char *", (utf8 ? 5 : 4) * (longEncoded ? 20 : 1), false, false, false, true, true);
            destination("char *", (utf8 ? 5 : 4) * (longEncoded ? 20 : 1) + 1, false, true);
            expected = 2;
            break;
        case 14:
            format = "%hhn%hn%ln%lln%I64n";
            destination(ucrt ? "Int8 *" : "Int32 *", ucrt ? 1 : 4, false, false, true);
            destination("Int16 *", 2, false, false, true);
            destination("Int32 *", 4, false, false, true);
            destination("Int64 *", 8, false, false, true);
            destination("Int64 *", 8, false, false, true);
            break;
        case 19:
            format = provider.wide ? "%3S|%3C|%3h[A-C]" : "%3S|%3C|%3w[A-C]";
            source = "ABC|DEF|ABC";
            destination(provider.wide ? "char *" : "wchar_t *",
                provider.wide ? 256 : provider.secure ? 16 : 8, !provider.wide, true);
            destination(provider.wide ? "char *" : "wchar_t *",
                provider.wide ? 256 : provider.secure ? 16 : 6, !provider.wide, false, false, true, true);
            destination(provider.wide ? "char *" : "wchar_t *",
                provider.wide ? 256 : provider.secure ? 16 : 8, !provider.wide, true);
            expected = 3;
            break;
        case 20:
            format = "%4hc";
            destination("char *", 256, false, false, false, true, true);
            expected = 1;
            break;
        case 21:
        case 22:
            format = scenario == 21 ? "%3C" : "%8C";
            source = scenario == 22 && provider.wide ? "\1" : "A";
            destination(provider.wide ? "char *" : "wchar_t *", scenario == 22 ? (provider.wide ? 1 : 2) :
                provider.wide ? 256 : provider.secure ? 16 : 6, !provider.wide, false, false, true, true);
            expected = 1;
            break;
        case 23:
            format = "%S";
            source = "ABC";
            destination(provider.wide ? "char *" : "wchar_t *",
                provider.wide ? 256 : provider.secure ? 16 : 8, !provider.wide, true);
            expected = 1;
            break;
        case 24:
            format = "%*3C|%3C|%d%n";
            source = "ABC|DEF|7";
            destination(provider.wide ? "char *" : "wchar_t *",
                provider.wide ? 256 : provider.secure ? 16 : 6, !provider.wide, false, false, true, true);
            destination("Int32 *", 4);
            destination("Int32 *", 4, false, false, true);
            expected = 2;
            break;
        }
        const auto id = ++identifier;
        const auto digits = std::to_string(id);
        const auto prefix = "SC" + std::string(6 - digits.size(), '0') + digits + ":";
        format = prefix + format;
        source = prefix + source;
        const std::wstring wideFormat(format.begin(), format.end());
        std::wstring wideSource(source.begin(), source.end());

        // Zero-filled gaps expose sparse native writes that cannot be bounded by a string terminator.
        if (native && provider.wide)
            for (const auto& value : destinations)
                if (value.type == std::string_view("char *") && value.readable)
                    memset(value.pointer, 0, value.bytes);
        if (scenario == 20) wideSource = std::wstring(prefix.begin(), prefix.end()) + L"A\x100\xE9" L"B";
        const auto setLocale = reinterpret_cast<char* (__cdecl *)(int, const char*)>(
            GetProcAddress(provider.library, "setlocale"));
        auto invocation = provider;
        if (encoded)
        {
            if (!setLocale || !setLocale(2, utf8 ? ".UTF8" : ".932")) return false;
            std::wstring characters;
            for (int repeat = 0; repeat < (longEncoded ? 20 : 1); ++repeat)
                characters += utf8 ? L"\x4E2D\xE9" : L"\x3042\x30A2";
            wideSource = std::wstring(prefix.begin(), prefix.end()) + characters + L"|" + characters;
            if (explicitLocale)
            {
                const auto create = reinterpret_cast<void* (__cdecl *)(int, const char*)>(
                    GetProcAddress(provider.library, "_create_locale"));
                if (!create || !(invocation.locale = create(2, "C"))) return false;
            }
        }
        const void* text = provider.wide ? static_cast<const void*>(wideSource.c_str()) : source.c_str();
        const void* pattern = provider.wide ? static_cast<const void*>(wideFormat.c_str()) : format.c_str();
        auto result = InvokeScan(invocation, text, provider.wide ? wideSource.size() : source.size(),
            pattern, arguments, std::make_index_sequence<32>{});
        if (invocation.locale) reinterpret_cast<void (__cdecl *)(void*)>(
            GetProcAddress(provider.library, "_free_locale"))(invocation.locale);
        if (encoded && !setLocale(2, "C")) return false;
        if (result != expected)
        {
            fprintf(stderr, "%s!%s options=%llu scenario=%u result=%d expected=%d\n",
                provider.module, provider.name, provider.options, scenario, result, expected);
            return false;
        }
        const auto formatIndex = provider.common ? 3u : provider.bounded ? 2u : 1u;
        const auto tail = provider.common ? 5u : formatIndex + 1 + provider.localized;
        report << id << '\t' << provider.module << '\t' << provider.name << '\t' << provider.options << '\t'
            << provider.wide << '\t' << provider.listed << '\t' << formatIndex << '\t' << tail << '\t'
            << result << '\t' << format << '\t';
        constexpr char hex[] = "0123456789ABCDEF";
        for (const auto& value : destinations)
        {
            const bool assigned = value.count || result >= 0 && value.assignment <= static_cast<uint32_t>(result);
            report << value.index << ':' << value.type << ':' << value.wide << ':' << value.terminated << ':'
                << value.count << ':' << assigned << ':' << value.bytes << ':' << std::hex
                << reinterpret_cast<uintptr_t>(value.pointer) << std::dec << ':';
            if (value.readable)
                for (uint32_t byte = 0; byte < value.bytes; ++byte)
                    report << hex[value.pointer[byte] >> 4] << hex[value.pointer[byte] & 15];
            report << ';';
        }
        report << '\n';
    }
    VirtualFree(memory, 0, MEM_RELEASE);
    return true;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 2) return 1;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::ofstream report{std::filesystem::path(argv[1])};
    uint32_t identifier = 0;
    if (!report) return 2;
    for (auto module : {"ntdll.dll", "msvcrt.dll", "msvcr120.dll", "ucrtbase.dll"})
    {
        auto library = LoadLibraryExA(module, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 3;
        const bool common = std::string_view(module) == "ucrtbase.dll";
        if (common)
        {
            constexpr uint64_t optionsList[]{0, 1, 2, 3, 4, 5, 6, 7, uint64_t{1} << 63};
            for (auto name : {"__stdio_common_vsscanf", "__stdio_common_vswscanf"})
                for (auto options : optionsList)
                    if (!ScanSamples({library, module, name, strstr(name, "swscanf") != nullptr,
                        (options & 1) != 0, true, true, false, false, options}, report, identifier)) return 4;
        }
        else
        {
            for (auto name : {"sscanf", "sscanf_s", "swscanf_s", "_snscanf_s", "_snwscanf_s",
                "_sscanf_l", "_swscanf_l", "vsscanf", "vswscanf"})
            {
                if (!GetProcAddress(library, name)) continue;
                const bool wide = strstr(name, "wscanf") != nullptr;
                const bool secure = std::string_view(name).ends_with("_s");
                const bool listed = *name == 'v';
                if (!ScanSamples({library, module, name, wide, secure, listed, false,
                    !strncmp(name, "_sn", 3), std::string_view(name).ends_with("_l"), 0}, report, identifier)) return 5;
            }
        }
        FreeLibrary(library);
    }
    return report ? 0 : 6;
}

Json ScanReport(const Path& path)
{
    const std::regex integer("%d");
    auto rows = Columns(path, {"id", "module", "name", "options", "wide", "listed", "formatIndex", "tail",
        "result", "text", "outputs"}, {"id", "wide", "listed", "formatIndex", "tail", "result"});
    Json result = Json::object();
    for (auto row : rows)
    {
        row["options"] = Number(row["options"], 10);
        row["wide"] = row["wide"] != 0;
        row["listed"] = row["listed"] != 0;
        Json destinations = Json::array();
        for (const auto& entry : Split(row["outputs"].get<std::string>(), ';'))
        {
            if (entry.empty()) continue;
            auto fields = Split(entry, ':');
            Require(fields.size() == 9, "Scan destination report is incomplete", fields);
            auto type = fields[1];
            bool unicode = std::stoi(fields[2]) != 0;
            bool buffer = row["module"] == "ntdll.dll" && row["name"].get<std::string>().ends_with("_s") &&
                          (type == "char *" || type == "wchar_t *") && unicode != row["wide"].get<bool>();
            destinations.push_back({{"index", std::stoul(fields[0])},
                                    {"type", type},
                                    {"kind", buffer ? 0 : int(unicode)},
                                    {"buffer", buffer},
                                    {"terminated", std::stoi(fields[3]) != 0 && !buffer},
                                    {"count", std::stoi(fields[4]) != 0},
                                    {"assigned", std::stoi(fields[5]) != 0},
                                    {"size", std::stoul(fields[6])},
                                    {"pointer", std::stoull(fields[7], nullptr, 16)},
                                    {"data", fields[8]}});
        }
        row.erase("outputs");
        row["destinations"] = destinations;
        auto text = row["text"].get<std::string>();
        row["incomplete"] =
            std::distance(std::sregex_iterator(text.begin(), text.end(), integer), std::sregex_iterator()) == 29;
        row["multibyte"] = text.contains("hc|") && text.ends_with("hs");
        result[std::to_string(Number(row["id"]))] = row;
    }
    Require(result.size() >= 250, "Scan report coverage incomplete", result.size());
    return result;
}

void ScanFormat(const Context& context)
{
    auto report = context.directory / L"scans.tsv";
    RunTarget(context, Quote(report), 30000);
    auto baseline = ScanReport(report);
    Json inspections = Json::array();
    for (uint32_t limit : {16u, 32u, 128u, 256u})
    {
        Capture::Run(context, {.arguments = Quote(report), .limit = limit}, [&](Capture& capture)
        {
            auto expected = ScanReport(report);
            Require(expected.size() == baseline.size(), "Scan native case count differs");
            std::set<std::string> seen;
            for (const auto& row : capture.Find(".*scanf.*"))
            {
                auto formats = Select(Values(row["input"]), [](const Value& value)
                { return Starts(value.data, Encode("SC")) || Starts(value.data, Encode("SC", true)); });
                if (formats.empty()) continue;
                auto bytes = formats[0].data;
                auto text = String(bytes, bytes.size() >= 2 && !bytes[1]);
                auto id = std::to_string(std::stoul(text.substr(2, 6)));
                auto sample = expected.at(id), original = baseline.at(id);
                if (row["module"] != sample["module"] || row["name"] != sample["name"]) continue;
                Require(seen.insert(id).second && sample["result"] == original["result"] &&
                            uint32_t(Number(row["result"])) == uint32_t(Number(sample["result"])),
                        "Scan native result differs", sample);
                bool listed = sample["listed"], incomplete = sample["incomplete"];
                bool fallback =
                    sample["text"].get<std::string>().ends_with("%F %d") || (Number(sample["options"]) & ~7ull);
                auto before = Values(row["input"]), after = Values(row["output"]);
                uint32_t tail = sample["tail"];
                if (fallback || incomplete)
                    Require(!(row["flags"].get<uint32_t>() & 2048), "Incomplete scan format was marked complete", row);
                if (fallback)
                {
                    if (listed)
                        Require(Regions(before, {.required = 64}).empty() && Regions(after, {.required = 64}).empty(),
                                "Unsupported scan list was decoded", row);
                    else
                        for (const auto& value : after)
                            Require(value.index < tail || ((value.flags & 2) && value.data.empty()),
                                    "Unsupported scan destination was dereferenced", row);
                }
                Require(sample["destinations"].size() == original["destinations"].size(),
                        "Scan destination count differs", sample);
                for (size_t ordinal = 0; ordinal < sample["destinations"].size(); ++ordinal)
                {
                    auto destination = sample["destinations"][ordinal], initial = original["destinations"][ordinal];
                    if (destination["buffer"] == false || destination["type"] != "wchar_t *")
                        Require(destination["data"] == initial["data"], "Scan destination bytes differ from native",
                                destination);
                    uint32_t index = destination["index"], parameter = listed ? tail : tail + index;
                    auto references = [&](const auto& values)
                    {
                        auto regions = Regions(values, {.parameter = parameter,
                                                        .required = listed ? 72u : 0u,
                                                        .element = listed ? std::optional{index} : std::nullopt});
                        return Select(regions, [](const Value& value) { return value.kind != 2; });
                    };
                    auto old = references(before), current = references(after);
                    if (incomplete && index == 29)
                    {
                        Require(old.size() == 1 && current.size() == 1 && (old[0].flags & 2) && (current[0].flags & 2),
                                "Incomplete scan destination fallback differs", row);
                        continue;
                    }
                    if (fallback) continue;
                    if (destination["count"] == true)
                        Require(old.size() == 1 && old[0].data == Bytes(destination["size"].get<size_t>(), 0xcc),
                                "Scan count input differs", row);
                    else
                        Require(old.empty(), "Scan output-only destination has input capture", row);
                    if (destination["assigned"] == false)
                    {
                        Require(current.empty(), "Unassigned scan destination was captured", row);
                        continue;
                    }
                    auto raw = Unhex(destination["data"]);
                    bool uncertain = sample["multibyte"] == true && !index && raw.size() > limit;
                    bool truncated = uncertain || raw.size() > limit;
                    auto size = uncertain || (destination["terminated"] == true && truncated) ? 0 : raw.size();
                    auto flags = (listed ? 72u | (index << 16) : 0u) | uint32_t(truncated);
                    Require(current ==
                                std::vector<Value>{{parameter, destination["kind"], flags, size, Prefix(raw, limit)}},
                            "Scan destination capture differs", row);
                    if (listed)
                    {
                        auto scalar = Regions(before, {.parameter = parameter, .kind = 2, .element = index});
                        Require(scalar.size() == 1 && Read<uint64_t>(scalar[0].data) == destination["pointer"],
                                "Scan list destination pointer differs", row);
                    }
                }
                CheckLimit(row, limit);
                if (!listed && !fallback && !incomplete)
                    Require(row["flags"].get<uint32_t>() & 2048, "Complete scan format metadata missing", row);
                if (!context.Optional(0).empty() && limit >= 128)
                {
                    sample.update({{"call", capture.Details(row)}, {"limit", limit}});
                    inspections.push_back(sample);
                }
            }
            Require(seen.size() == expected.size(), "Scan capture coverage incomplete", seen);
        });
    }
    Inspect(context, context.Optional(0), "--scan-formats", inspections, 45000);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ScanFormat); }

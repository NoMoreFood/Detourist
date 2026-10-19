#include "TestSupport.h"
#include "ApiCategories.h"

#if defined(DETOURIST_TEST_DetouristCrtCountOutputTests)

using namespace Detourist::Tests;
using InvalidHandler = void (__cdecl *)(const wchar_t*, const wchar_t*, const wchar_t*, unsigned, uintptr_t);

int InvokeListed(FARPROC function, void* output, size_t capacity, uint64_t options, const void* format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    auto call = reinterpret_cast<int (__cdecl *)(uint64_t, void*, size_t, const void*, void*, va_list)>(function);
    auto result = call(options, output, capacity, format, nullptr, arguments);
    va_end(arguments);
    return result;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 2) return 1;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::ofstream report{std::filesystem::path(argv[1])};
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto memory = static_cast<BYTE*>(VirtualAlloc(nullptr, system.dwPageSize * 2,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    DWORD protection = 0;
    if (!report || !memory || !VirtualProtect(memory + system.dwPageSize,
        system.dwPageSize, PAGE_NOACCESS, &protection)) return 2;
    auto boundary = memory + system.dwPageSize;
    const wchar_t* providers[]{L"msvcr120.dll", L"ucrtbase.dll"};

    // Exercise direct variadic and va_list counts immediately before an inaccessible page.
    for (auto provider : providers)
    {
        auto library = LoadLibraryExW(provider, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 3;
        auto enable = reinterpret_cast<int (__cdecl *)(int)>(GetProcAddress(library, "_set_printf_count_output"));
        auto setHandler = reinterpret_cast<InvalidHandler (__cdecl *)(InvalidHandler)>(
            GetProcAddress(library, "_set_invalid_parameter_handler"));
        auto previousHandler = setHandler ? setHandler(IgnoreInvalidParameter) : nullptr;
        auto setReportMode = reinterpret_cast<int (__cdecl *)(int, int)>(
            GetProcAddress(library, "_CrtSetReportMode"));
        auto previousReportMode = setReportMode ? setReportMode(2, 0) : 0;
        auto previous = enable ? enable(1) : 0;
        auto module = std::wstring(provider);
        auto narrowModule = std::string(module.size(), '\0');
        for (size_t index = 0; index < module.size(); ++index) narrowModule[index] = static_cast<char>(module[index]);
        const bool listed = module.starts_with(L"ucrt");
        for (bool wide : {false, true})
        {
            const auto name = listed ? wide ? "__stdio_common_vswprintf" : "__stdio_common_vsprintf" :
                wide ? "_snwprintf" : "_snprintf";
            auto function = GetProcAddress(library, name);
            if (!function) return 4;
            for (const auto modifier : {"", "hh", "h", "l", "ll", "I32", "I64", "I", "j", "z", "t"})
            {
                if (!enable || !listed && (std::string_view(modifier) == "I" ||
                    std::string_view(modifier) == "j" || std::string_view(modifier) == "z" ||
                    std::string_view(modifier) == "t")) continue;
                const auto size = std::string_view(modifier) == "hh" ? listed ? 1u : 2u :
                    std::string_view(modifier) == "h" ? 2u : listed &&
                    (std::string_view(modifier) == "ll" || std::string_view(modifier) == "I64" ||
                        std::string_view(modifier) == "j" || std::string_view(modifier) == "z" ||
                        std::string_view(modifier) == "t") ? 8u : 4u;
                for (const std::string scenario : {"COUNT", "FAIL", "EARLY", "LATE", "ZERO", "SAME", "INVALID",
                    "UNREAD"})
                {
                    if ((scenario == "FAIL" || scenario == "UNREAD") && *modifier || scenario != "COUNT" &&
                        *modifier && strcmp(modifier, "hh") && strcmp(modifier, "h") && strcmp(modifier, "ll"))
                        continue;
                    const bool late = scenario == "LATE", zero = scenario == "ZERO" || scenario == "SAME";
                    const bool unreadable = scenario == "UNREAD", disabled = scenario == "FAIL" || unreadable;
                    const bool truncated = scenario == "EARLY" || late || zero;
                    const size_t capacity = truncated ? 8 : 256;
                    auto count = unreadable ? boundary : boundary - size;
                    if (!unreadable) memset(count, scenario == "SAME" ? 0 : 0xcc, size);
                    const auto conversion = "%" + std::string(modifier) + "n";
                    const auto format = late ? "LATE:%hs|" + conversion : zero ?
                        conversion + scenario + ":%hs" : scenario + ":" + conversion +
                        (scenario == "INVALID" ? "|%" : "|%hs");
                    const auto wideFormat = std::wstring(format.begin(), format.end());
                    auto text = wide ? static_cast<const void*>(wideFormat.c_str()) : format.c_str();
                    const auto tail = truncated ? "0123456789" : "Tail";
                    uint64_t before = 0, after = 0;
                    if (!unreadable) memcpy(&before, count, size);
                    if (disabled) enable(0);

                    // Truncation can fail before or after a count write; incomplete formats retain native behavior.
                    wchar_t output[512]{};
                    auto first = late ? static_cast<const void*>(tail) : count;
                    auto second = late ? static_cast<const void*>(count) : tail;
                    int result = listed ? InvokeListed(function, output, capacity, truncated ? 1 : 2,
                        text, first, second) :
                        reinterpret_cast<int (__cdecl *)(void*, size_t, const void*, ...)>(function)(
                            output, capacity, text, first, second);
                    if (disabled) enable(1);
                    if (!unreadable) memcpy(&after, count, size);
                    const uint64_t expected = disabled || late ? before : zero ? 0 : scenario == "INVALID" ? 8 : 6;
                    if (after != expected || (scenario == "COUNT" ? result != 11 :
                        scenario != "INVALID" && result >= 0))
                    {
                        fprintf(stderr, "Count case %s!%s %s/%s: result=%d before=%llu after=%llu expected=%llu\n",
                            narrowModule.c_str(), name, scenario.c_str(), modifier, result, before, after, expected);
                        return 5;
                    }
                    report << narrowModule << '\t' << name << '\t' << scenario << '\t'
                        << (*modifier ? modifier : "none") << '\t' << size << '\t' << result << '\t'
                        << std::hex << reinterpret_cast<uintptr_t>(count) << std::dec << '\t' << format << '\t';
                    if (unreadable) report << "-\t-";
                    else report << std::hex << before << '\t' << after << std::dec;
                    report << '\t' << (late ? 1 : 0) << '\n';
                    report.flush();
                }
            }
        }
        if (enable) enable(previous);
        if (setHandler) setHandler(previousHandler);
        if (setReportMode) setReportMode(2, previousReportMode);
        FreeLibrary(library);
    }
    VirtualFree(memory, 0, MEM_RELEASE);
    return report ? 0 : 6;
}

Json CountOutputReport(const Path& path)
{
    auto rows = Columns(
        path, {"module", "name", "case", "modifier", "size", "status", "pointer", "text", "before", "after", "element"},
        {"size", "status", "element"}, {"pointer"});
    std::set<int> sizes;
    std::set<std::string> cases;
    for (auto& row : rows)
    {
        sizes.insert(row["size"].get<int>());
        cases.insert(row["case"].get<std::string>());
        for (auto phase : {"before", "after"})
            row[phase] = row[phase] == "-" ? Json(nullptr) : Json(Number(row[phase], 16));
    }
    Require(sizes == std::set<int>{1, 2, 4, 8} &&
                cases == std::set<std::string>{"COUNT", "FAIL", "EARLY", "LATE", "ZERO", "SAME", "INVALID", "UNREAD"},
            "CRT count baseline coverage differs");
    return Group(rows, {"module", "name"});
}

void CrtCountOutput(const Context& context)
{
    // Count destinations retain their bytes on entry and after success, partial failure or disabled writes.
    auto path = context.directory / L"report.tsv";
    RunTarget(context, Quote(path));
    auto baseline = CountOutputReport(path);
    Json details = Json::array();
    for (uint32_t limit : {16u, 64u})
    {
        Capture::Run(context, {.arguments = Quote(path), .limit = limit}, [&](Capture& capture)
        {
            auto expected = CountOutputReport(path);
            Json groups = Json::object();
            for (const auto& row :
                 capture.Find("_snprintf|_snwprintf|__stdio_common_vsprintf|__stdio_common_vswprintf"))
            {
                auto key = Key(row, {"module", "name"});
                if (!expected.contains(key)) continue;
                auto name = row["name"].get<std::string>();
                auto listed = name.starts_with("__stdio"), wide = name.contains("wprintf");
                auto before = Values(row["input"]);
                if (std::ranges::any_of(before, [&](const Value& value)
                {
                    return value.index == (listed ? 3u : 2u) &&
                           std::ranges::any_of(expected[key], [&](const Json& sample)
                    { return value.data == Prefix(Encode(sample["text"], wide, true), limit); });
                }))
                    groups[key].push_back(row);
            }
            Require(groups.size() == expected.size(), "CRT count formatter set differs");
            for (const auto& [key, samples] : expected.items())
            {
                Require(groups[key].size() == samples.size(), "CRT count call count differs");
                for (size_t index = 0; index < samples.size(); ++index)
                {
                    const auto& row = groups[key][index];
                    auto sample = samples[index];
                    Require(Without(sample, {"pointer"}) == Without(baseline[key][index], {"pointer"}) &&
                                uint32_t(row["result"].get<uint64_t>()) == uint32_t(sample["status"].get<int64_t>()),
                            "CRT count native result differs", sample);
                    auto size = sample["size"].get<unsigned>(), element = sample["element"].get<unsigned>();
                    bool listed = row["name"].get<std::string>().starts_with("__stdio");
                    auto ordinal = listed ? 5u : 3u + element;
                    auto before = Values(row["input"]);
                    for (auto [phase, payload] : {std::pair{"before", "input"}, {"after", "output"}})
                    {
                        auto values = Regions(row[payload], {.parameter = ordinal, .kind = 0,
                            .required = listed ? 72u : 0u, .element = listed ? std::optional{element} : std::nullopt});
                        Require(values.size() == 1 && values[0].original == size, "CRT count extent differs", sample);
                        Require(sample[phase].is_null()
                                    ? (values[0].flags & 2) && values[0].data.empty()
                                    : !(values[0].flags & 2) &&
                                          values[0].data == Integer(sample[phase].get<uint64_t>(), size),
                                "CRT count destination differs", sample);
                    }
                    if (!listed)
                        Require(Read<uint64_t>(row["arguments"], ordinal * 8) == sample["pointer"],
                                "CRT count destination pointer differs", sample);
                    if (sample["case"] != "INVALID")
                    {
                        auto other = listed ? std::optional{1 - element} : std::nullopt;
                        auto tails = Regions(before, {.parameter = listed ? 5u : 4u - element, .kind = 0,
                                                      .required = listed ? 8u : 0u, .element = other});
                        auto label = sample["case"].get<std::string>();
                        auto tail = label == "EARLY" || label == "LATE" || label == "ZERO" || label == "SAME"
                                        ? "0123456789"
                                        : "Tail";
                        Require(tails.size() == 1 && tails[0].data == Encode(tail, false, true),
                                "CRT count tail differs", sample);
                    }
                    CheckLimit(row, limit);
                    if (limit == 64)
                    {
                        auto detail = capture.Details(row);
                        if (!listed && sample["case"] != "INVALID")
                            Require(detail["arguments"].size() == 5 && detail["rawArguments"].size() == 32,
                                    "CRT count raw argument display differs", detail);
                        sample.erase("module");
                        sample.erase("name");
                        sample.update({{"call", detail}, {"listed", listed}, {"parameter", ordinal}});
                        details.push_back(sample);
                    }
                }
            }
        });
    }
    Inspect(context, context.Optional(0), "--crt-counts", details, 30000);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, CrtCountOutput); }

#elif defined(DETOURIST_TEST_DetouristCrtCountedStringTests)

using namespace Detourist::Tests;
struct CountedString
{
    uint16_t length, maximumLength;
    void* buffer;
};
static_assert(sizeof(CountedString) == 16 && offsetof(CountedString, buffer) == 8);

int InvokeListed(FARPROC function, uint64_t options, void* output, const void* format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    auto call = reinterpret_cast<int (__cdecl *)(uint64_t, void*, size_t, const void*, void*, va_list)>(function);
    auto result = call(options, output, 256, format, nullptr, arguments);
    va_end(arguments);
    return result;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 2) return 1;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::ofstream report{std::filesystem::path(argv[1])};
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto memory = static_cast<BYTE*>(VirtualAlloc(nullptr, system.dwPageSize * 6,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!report || !memory) return 2;
    for (uint32_t page : {1u, 3u, 5u})
    {
        DWORD protection = 0;
        if (!VirtualProtect(memory + system.dwPageSize * page, system.dwPageSize,
            PAGE_NOACCESS, &protection)) return 3;
    }
    auto descriptor = reinterpret_cast<CountedString*>(memory + system.dwPageSize * 5 - sizeof(CountedString));
    const char* providers[]{"msvcr120.dll", "ucrtbase.dll"};

    // Capture real counted descriptors and unterminated data beside independent inaccessible pages.
    for (auto provider : providers)
    {
        auto library = LoadLibraryExA(provider, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 4;
        const bool listed = std::string_view(provider).starts_with("ucrt");
        for (bool wide : {false, true})
        {
            const auto name = listed ? wide ? "__stdio_common_vswprintf" : "__stdio_common_vsprintf" :
                wide ? "_snwprintf" : "_snprintf";
            auto function = GetProcAddress(library, name);
            if (!function) return 5;
            for (uint64_t options : {2ull, 6ull})
            {
                if (!listed && options != 2) continue;
                for (auto modifier : {"", "h", "w", "l"})
                {
                    auto format = "CS:%" + std::string(modifier) + "Z|%hs";
                    auto wideFormat = std::wstring(format.begin(), format.end());
                    const bool unicode = *modifier == 'w' || listed && (*modifier == 'l' ||
                        !*modifier && !(wide && (options & 4)));
                    for (auto label : {"TEXT", "EMBED", "LONG", "EMPTY",
                        "NULL", "NULL_EMPTY", "NO_DESCRIPTOR", "CAPACITY"})
                    {
                        auto sample = std::string_view(label);
                        const auto length = sample == "LONG" ? 80u :
                            sample == "EMPTY" || sample == "NULL_EMPTY" ? 0u : unicode ? 8u : 5u;
                        auto boundary = memory + system.dwPageSize * (unicode ? 3 : 1);
                        auto buffer = boundary - length;
                        std::vector<BYTE> bytes(length);
                        for (uint32_t index = 0; index < length; ++index)
                            bytes[index] = unicode && (index & 1) ? 0 :
                                static_cast<BYTE>('A' + (unicode ? index / 2 : index) % 26);
                        if (sample == "EMBED")
                        {
                            bytes[unicode ? 4 : 2] = 0;
                            if (unicode) bytes[5] = 0;
                        }
                        if (length) memcpy(buffer, bytes.data(), length);
                        *descriptor = {static_cast<uint16_t>(length),
                            static_cast<uint16_t>(sample == "CAPACITY" ? 1u : length),
                            sample == "NULL" || sample == "NULL_EMPTY" ? nullptr : buffer};
                        auto pointer = sample == "NO_DESCRIPTOR" ? nullptr : descriptor;
                        char output[512]{};
                        auto text = wide ? static_cast<const void*>(wideFormat.c_str()) : format.c_str();
                        auto result = listed ? InvokeListed(function, options, output, text, pointer, "Tail") :
                            reinterpret_cast<int (__cdecl *)(void*, size_t, const void*, ...)>(function)(
                                output, 256, text, pointer, "Tail");
                        auto expected = sample == "NULL" || sample == "NULL_EMPTY" || sample == "NO_DESCRIPTOR" ? 14 :
                            sample == "EMBED" && wide && !unicode ? -1 : 8 + length / (unicode ? 2 : 1);
                        if (result != static_cast<int>(expected)) return 6;
                        report << provider << '\t' << name << '\t' << options << '\t'
                            << (*modifier ? modifier : "none")
                            << '\t' << label << '\t' << unicode << '\t' << length << '\t' << result << '\t'
                            << std::hex << reinterpret_cast<uintptr_t>(pointer) << std::dec << '\n';
                    }
                }
            }
        }
        FreeLibrary(library);
    }
    VirtualFree(memory, 0, MEM_RELEASE);
    return report ? 0 : 7;
}

Json CountedReport(const Path& path)
{
    auto rows = Columns(path, {"module", "name", "options", "modifier", "label", "wide", "length", "result", "pointer"},
                        {"options", "wide", "length", "result"}, {"pointer"});
    std::set<std::string> labels, modifiers;
    std::set<int> widths;
    for (const auto& row : rows)
    {
        labels.insert(row["label"].get<std::string>());
        modifiers.insert(row["modifier"].get<std::string>());
        widths.insert(row["wide"].get<int>());
    }
    Require(labels == std::set<std::string>{"TEXT", "EMBED", "LONG", "EMPTY", "NULL", "NULL_EMPTY", "NO_DESCRIPTOR",
                                            "CAPACITY"} &&
                modifiers == std::set<std::string>{"none", "h", "w", "l"} && widths == std::set<int>{0, 1},
            "Counted string baseline coverage differs");
    return rows;
}

void CrtCountedString(const Context& context)
{
    // Descriptors and independently bounded text retain widths, embedded nulls and guarded extents.
    auto path = context.directory / L"report.tsv";
    RunTarget(context, Quote(path));
    auto baseline = CountedReport(path);
    Json details = Json::array();
    for (uint32_t limit : {16u, 24u, 64u})
    {
        Capture::Run(context, {.arguments = Quote(path), .limit = limit}, [&](Capture& capture)
        {
            auto expected = CountedReport(path);
            Json rows = Json::array();
            for (const auto& row :
                 capture.Find("_snprintf|_snwprintf|__stdio_common_vsprintf|__stdio_common_vswprintf"))
            {
                auto name = row["name"].get<std::string>();
                auto listed = name.starts_with("__stdio"), wide = name.contains("wprintf");
                auto values = Values(row["input"]);
                if (std::ranges::any_of(values, [&](const Value& value)
                { return value.index == (listed ? 3u : 2u) && Starts(value.data, Encode("CS:", wide)); }))
                    rows.push_back(row);
            }
            Require(rows.size() == expected.size() && expected.size() == baseline.size(),
                    "Counted string call count differs");
            for (size_t index = 0; index < rows.size(); ++index)
            {
                const auto& row = rows[index];
                const auto& sample = expected[index];
                auto name = sample["name"].get<std::string>(), label = sample["label"].get<std::string>();
                bool listed = name.starts_with("__stdio"), wide = sample["wide"] != 0;
                auto ordinal = listed ? 5u : 3u, length = sample["length"].get<uint32_t>();
                Require(Without(sample, {"pointer"}) == Without(baseline[index], {"pointer"}) &&
                            row["module"] == sample["module"] && row["name"] == name &&
                            uint32_t(row["result"].get<uint64_t>()) == uint32_t(sample["result"].get<int64_t>()),
                        "Counted string native result differs", sample);
                auto before = Values(row["input"]), after = Values(row["output"]);
                auto first = listed ? std::optional{0u} : std::nullopt;
                auto headers = Regions(before, {.parameter = ordinal, .kind = 0, .required = listed ? 64u : 0u,
                                                .excluded = 8, .element = first});
                auto payloads = Regions(before, {.parameter = ordinal, .required = 8, .element = first});
                if (label == "NO_DESCRIPTOR")
                    Require(headers.empty() && payloads.empty(), "Null counted descriptor was followed");
                else
                {
                    Require(headers.size() == 1 && headers[0].data.size() == 16 && headers[0].original == 16 &&
                                !(headers[0].flags & 2) && Read<uint16_t>(headers[0].data) == length,
                            "Counted descriptor differs");
                    if (label == "EMPTY" || label == "NULL" || label == "NULL_EMPTY")
                        Require(payloads.empty(), "Empty counted string exposed text");
                    else
                    {
                        Bytes bytes(length);
                        for (size_t position = 0; position < bytes.size(); ++position)
                            bytes[position] =
                                wide && (position & 1) ? 0 : uint8_t('A' + (wide ? position / 2 : position) % 26);
                        if (label == "EMBED")
                        {
                            bytes[wide ? 4 : 2] = 0;
                            if (wide) bytes[5] = 0;
                        }
                        Require(payloads.size() == 1 && payloads[0].kind == unsigned(wide) &&
                                    payloads[0].original == length && payloads[0].data == Prefix(bytes, limit) &&
                                    (payloads[0].flags & 3) == unsigned(length > limit),
                                "Counted string payload differs", sample);
                    }
                }
                for (const auto& value : after)
                    Require(value.index != ordinal || (listed && !(value.flags & 64)),
                            "Counted input captured on return");
                auto tails = Regions(before, {.parameter = listed ? 5u : 4u, .kind = 0, .required = listed ? 8u : 0u,
                                              .element = listed ? std::optional{1u} : std::nullopt});
                Require(tails.size() == 1 && tails[0].data == Encode("Tail", false, true),
                        "Counted string tail differs");
                CheckLimit(row, limit);
                if (limit == 64)
                    details.push_back({{"call", capture.Details(row)},
                                       {"label", label},
                                       {"wide", wide},
                                       {"listed", listed},
                                       {"parameter", ordinal}});
            }
        });
    }
    Inspect(context, context.Optional(0), "--crt-counted-strings", details, 30000);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, CrtCountedString); }

#elif defined(DETOURIST_TEST_DetouristNtdllFormatTests)

using namespace Detourist::Tests;
struct CountedString
{
    uint16_t length, maximumLength;
    void* buffer;
};
static_assert(sizeof(CountedString) == 16 && offsetof(CountedString, buffer) == 8);

char debugText[512]{};
size_t debugBytes = 0;

LONG CALLBACK ObserveDebugText(EXCEPTION_POINTERS* exception)
{
    // Observe the provider's emitted bytes without changing its own exception handling.
    const auto& record = *exception->ExceptionRecord;
    if (record.ExceptionCode == DBG_PRINTEXCEPTION_C && record.NumberParameters == 2 &&
        record.ExceptionInformation[0] <= sizeof(debugText))
    {
        debugBytes = record.ExceptionInformation[0];
        memcpy(debugText, reinterpret_cast<void*>(record.ExceptionInformation[1]), debugBytes);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 2) return 1;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    std::ofstream report{std::filesystem::path(argv[1])};
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto memory = static_cast<BYTE*>(VirtualAlloc(nullptr, system.dwPageSize * 4,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    auto observer = AddVectoredExceptionHandler(TRUE, ObserveDebugText);
    auto library = GetModuleHandleW(L"ntdll.dll");
    if (!report || !memory || !observer || !library) return 2;
    for (uint32_t page : {1u, 3u})
    {
        DWORD protection = 0;
        if (!VirtualProtect(memory + system.dwPageSize * page, system.dwPageSize,
            PAGE_NOACCESS, &protection)) return 3;
    }
    auto descriptor = reinterpret_cast<CountedString*>(memory + system.dwPageSize * 3 - sizeof(CountedString));

    // Counted formats keep their whole byte extent, independently of literal or dynamic precision.
    for (const char* name : {"DbgPrint", "DbgPrintEx"})
    {
        auto function = GetProcAddress(library, name);
        if (!function) return 4;
        const bool extended = std::string_view(name) == "DbgPrintEx";
        for (auto modifier : {"", "h", "w", "l"})
        {
            const bool wide = *modifier == 'w';
            for (int variant = 0; variant < 8; ++variant)
            {
                const char* precisions[]{"", ".0", ".1", ".64", ".*", ".*", ".*", "*.*"};
                auto format = "DS:%" + std::string(precisions[variant]) + modifier + "Z|%hs";
                const int precision = variant == 4 ? 0 : variant == 5 ? 3 : -1;
                const uint32_t parameter = (extended ? 3u : 1u) + (variant == 7 ? 2u : variant >= 4 ? 1u : 0u);
                for (auto label : {"TEXT", "EMBED", "LONG", "EMPTY", "NULL", "NULL_EMPTY", "NO_DESCRIPTOR"})
                {
                    const auto sample = std::string_view(label);
                    const auto length = sample == "LONG" ? 80u :
                        sample == "EMPTY" || sample == "NULL_EMPTY" ? 0u : wide ? 8u : 5u;
                    auto buffer = memory + system.dwPageSize - (length ? length : 2u);
                    std::vector<BYTE> bytes(length ? length : 2u);
                    for (uint32_t index = 0; index < length; ++index)
                        bytes[index] = wide && (index & 1) ? 0 :
                            static_cast<BYTE>('A' + (wide ? index / 2 : index) % 26);
                    if (sample == "EMBED")
                    {
                        bytes[wide ? 4 : 2] = 0;
                        if (wide) bytes[5] = 0;
                    }
                    memcpy(buffer, bytes.data(), bytes.size());
                    *descriptor = {static_cast<uint16_t>(length), static_cast<uint16_t>(length),
                        sample == "NULL" || sample == "NULL_EMPTY" ? nullptr : buffer};
                    auto pointer = sample == "NO_DESCRIPTOR" ? nullptr : descriptor;
                    auto invoke = [&](auto... arguments)
                    {
                        return extended ? reinterpret_cast<ULONG (__cdecl *)(ULONG, ULONG, const char*, ...)>(
                            function)(ULONG_MAX, 0, format.c_str(), arguments...) :
                            reinterpret_cast<ULONG (__cdecl *)(const char*, ...)>(function)(
                                format.c_str(), arguments...);
                    };
                    debugBytes = 0;
                    const auto result = variant == 7 ? invoke(12, precision, pointer, "Tail") :
                        variant >= 4 ? invoke(precision, pointer, "Tail") : invoke(pointer, "Tail");
                    std::string text;
                    if (sample == "NULL" || sample == "NULL_EMPTY" || sample == "NO_DESCRIPTOR") text = "(null)";
                    else for (uint32_t index = 0; index < length; index += wide ? 2u : 1u)
                        text += static_cast<char>(bytes[index]);
                    if (variant == 7 && text.size() < 12) text.insert(0, 12 - text.size(), ' ');
                    auto expected = "DS:" + text + "|Tail";
                    expected.resize(strlen(expected.c_str()) + 1);
                    if (result || (extended || debugBytes) &&
                        (debugBytes != expected.size() || memcmp(debugText, expected.data(), debugBytes))) return 5;
                    report << "COUNT\t" << name << '\t' << variant << '\t' << label << '\t' << wide << '\t'
                        << length << '\t' << parameter << '\t' << result << '\t' << std::hex
                        << reinterpret_cast<uintptr_t>(pointer) << std::dec << '\t' << format << '\n';
                }
            }
        }
    }

    // Unsupported floating directives do not consume floating values; the next conversion sees the same slot.
    for (auto name : {"_snprintf", "_snwprintf", "sprintf"})
    {
        auto function = GetProcAddress(library, name);
        if (!function) return 6;
        const bool wide = std::string_view(name) == "_snwprintf";
        const bool bounded = *name == '_';
        for (auto conversion : {"f", "F", "e", "E", "g", "G", "a", "A", "lf", "Lf", "*.*f"})
        {
            const auto format = "NF:%" + std::string(conversion) + "|%u|%hs";
            const std::wstring wideFormat(format.begin(), format.end());
            const void* source = wide ? static_cast<const void*>(wideFormat.c_str()) : format.c_str();
            alignas(wchar_t) char output[512]{};
            auto invoke = [&](auto... arguments)
            {
                return bounded ? reinterpret_cast<int (__cdecl *)(void*, size_t, const void*, ...)>(function)(
                    output, 256, source, arguments...) :
                    reinterpret_cast<int (__cdecl *)(void*, const void*, ...)>(function)(output, source, arguments...);
            };
            const auto result = *conversion == '*' ? invoke(6, 2, 42u, "Tail") : invoke(42u, "Tail");
            const auto expected = "NF:" + (std::string_view(conversion) == "F" ? std::string{} :
                std::string(1, conversion[strlen(conversion) - 1])) + "|42|Tail";
            if (result != expected.size() || (wide ?
                std::wstring(reinterpret_cast<wchar_t*>(output)) != std::wstring(expected.begin(), expected.end()) :
                std::string(output) != expected)) return 7;
            report << "FLOAT\t" << name << "\t0\t" << conversion << '\t' << wide << "\t0\t"
                << (bounded ? 3 : 2) << '\t' << result << "\t0\t" << format << '\n';
        }
    }
    RemoveVectoredExceptionHandler(observer);
    VirtualFree(memory, 0, MEM_RELEASE);
    return report ? 0 : 8;
}

Json NativeFormatReport(const Path& path)
{
    auto rows =
        Columns(path, {"case", "name", "variant", "label", "wide", "length", "parameter", "result", "pointer", "text"},
                {"variant", "wide", "length", "parameter", "result"}, {"pointer"});
    auto groups = Group(rows, {"name"});
    for (auto [name, count] :
         {std::pair{"DbgPrint", 224u}, {"DbgPrintEx", 224u}, {"_snprintf", 11u}, {"_snwprintf", 11u}, {"sprintf", 11u}})
        Require(groups[Json::array({name}).dump()].size() == count, "NTDLL format baseline coverage differs");
    Require(groups.size() == 5, "Unexpected NTDLL formatter");
    return groups;
}

void NtdllFormat(const Context& context)
{
    // Counted precision, provider widths and unsupported floating formats retain native behavior.
    auto path = context.directory / L"report.tsv";
    RunTarget(context, Quote(path));
    auto baseline = NativeFormatReport(path);
    Json details = Json::array();
    for (uint32_t limit : {16u, 24u, 64u})
    {
        Capture::Run(context, {.arguments = Quote(path), .limit = limit}, [&](Capture& capture)
        {
            auto expected = NativeFormatReport(path);
            Json groups = Json::object();
            for (const auto& row : capture.Find("DbgPrint|DbgPrintEx|_snprintf|_snwprintf|sprintf", "ntdll\\.dll"))
            {
                auto name = row["name"].get<std::string>();
                auto format = name == "DbgPrint" ? 0u : name == "sprintf" ? 1u : 2u;
                auto prefix = Encode(name.starts_with("Dbg") ? "DS:" : "NF:", name == "_snwprintf");
                auto values = Values(row["input"]);
                if (std::ranges::any_of(values, [&](const Value& value)
                { return value.index == format && Starts(value.data, prefix); }))
                    groups[Key(row, {"name"})].push_back(row);
            }
            Require(groups.size() == expected.size(), "NTDLL formatter set differs");
            for (const auto& [key, samples] : expected.items())
            {
                Require(groups[key].size() == samples.size(), "NTDLL format call count differs");
                for (size_t index = 0; index < samples.size(); ++index)
                {
                    const auto& sample = samples[index];
                    const auto& row = groups[key][index];
                    auto parameter = sample["parameter"].get<uint32_t>(), length = sample["length"].get<uint32_t>();
                    auto flags = row["flags"].get<uint32_t>();
                    auto before = Values(row["input"]), after = Values(row["output"]);
                    Require(Without(sample, {"pointer"}) == Without(baseline[key][index], {"pointer"}) &&
                                uint32_t(row["result"].get<uint64_t>()) == uint32_t(sample["result"].get<int64_t>()),
                            "NTDLL native format result differs", sample);
                    if (sample["case"] == "FLOAT")
                    {
                        Require(!(flags & 2048) && Data(row["arguments"]).size() == 256, "Floating fallback differs",
                                row);
                        for (const auto& value : before)
                            Require(value.index < parameter || !(value.flags & 8),
                                    "Floating fallback followed a variadic buffer");
                    }
                    else
                    {
                        Require((flags & 2048) && Read<uint64_t>(row["arguments"], parameter * 8) == sample["pointer"],
                                "NTDLL variadic pointer differs", sample);
                        auto headers = Regions(before, {.parameter = parameter, .excluded = 8});
                        auto payloads = Regions(before, {.parameter = parameter, .required = 8});
                        auto label = sample["label"].get<std::string>();
                        if (label == "NO_DESCRIPTOR")
                            Require(headers.empty() && payloads.empty(), "Null NTDLL descriptor was followed");
                        else
                        {
                            Require(headers.size() == 1 && headers[0].kind == 0 && headers[0].flags == 0 &&
                                        headers[0].original == 16 && headers[0].data.size() == 16 &&
                                        Read<uint16_t>(headers[0].data) == length &&
                                        Read<uint16_t>(headers[0].data, 2) == length,
                                    "NTDLL counted descriptor differs");
                            if (label == "EMPTY" || label == "NULL" || label == "NULL_EMPTY")
                                Require(payloads.empty(), "Empty NTDLL string exposed text");
                            else
                            {
                                bool wide = sample["wide"] != 0;
                                Bytes bytes(length);
                                for (size_t position = 0; position < bytes.size(); ++position)
                                    bytes[position] = wide && (position & 1)
                                                          ? 0
                                                          : uint8_t('A' + (wide ? position / 2 : position) % 26);
                                if (label == "EMBED")
                                {
                                    bytes[wide ? 4 : 2] = 0;
                                    if (wide) bytes[5] = 0;
                                }
                                Require(payloads == std::vector<Value>{{parameter, unsigned(wide),
                                                                        8u | unsigned(length > limit), length,
                                                                        Prefix(bytes, limit)}},
                                        "NTDLL counted payload differs", sample);
                            }
                        }
                        auto tails = Regions(before, {.parameter = parameter + 1});
                        Require(tails.size() == 1 && tails[0].data == Encode("Tail", false, true),
                                "NTDLL tail differs");
                        for (const auto& value : after)
                            Require(value.index < parameter, "NTDLL input captured on return");
                    }
                    CheckLimit(row, limit);
                    if (limit == 64)
                    {
                        auto item = sample;
                        item.update({{"call", capture.Details(row)}, {"listed", false}, {"wide", sample["wide"] != 0}});
                        details.push_back(item);
                    }
                }
            }
        });
    }
    Inspect(context, context.Optional(0), "--ntdll-formats", details, 45000);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, NtdllFormat); }

#elif defined(DETOURIST_TEST_DetouristLocaleFormatTests)

using namespace Detourist::Tests;
std::atomic<unsigned> nextSample{1};
std::mutex reportLock;

int InvokeListed(FARPROC function, uint64_t options, wchar_t* buffer, void* locale, const wchar_t* format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    const auto result = reinterpret_cast<int (__cdecl *)(uint64_t, wchar_t*, size_t,
        const wchar_t*, void*, va_list)>(function)(options, buffer, 256, format, locale, arguments);
    va_end(arguments);
    return result;
}

bool FormatLocale(HMODULE library, const char* module, const char* localeName, const char* mode, std::ofstream& report)
{
    const bool ucrt = std::string_view(module).starts_with("ucrt");
    const bool isolated = std::string_view(mode) == "ISOLATED";
    const bool explicitLocale = std::string_view(mode) == "EXPLICIT";
    const bool cold = std::string_view(mode) == "COLD" || std::string_view(mode) == "INHERIT";
    const auto configure = reinterpret_cast<int (__cdecl *)(int)>(
        GetProcAddress(library, isolated ? "_o__configthreadlocale" : "_configthreadlocale"));
    const auto set = reinterpret_cast<char* (__cdecl *)(int, const char*)>(
        GetProcAddress(library, isolated ? "_o_setlocale" : "setlocale"));
    const auto create = reinterpret_cast<void* (__cdecl *)(int, const char*)>(
        GetProcAddress(library, "_create_locale"));
    const auto release = reinterpret_cast<void (__cdecl *)(void*)>(GetProcAddress(library, "_free_locale"));
    const auto error = reinterpret_cast<int* (__cdecl *)()>(GetProcAddress(library, isolated ? "_o__errno" : "_errno"));
    const auto dosError = reinterpret_cast<unsigned long* (__cdecl *)()>(GetProcAddress(library, "__doserrno"));
    if (!set || !create || !release || !error || !dosError) return false;
    if (!cold && std::string_view(mode) != "CACHED")
    {
        if (configure) configure(isolated || std::string_view(mode) == "THREAD" ||
            std::string_view(mode) == "FIBER" ? 1 : 2);
        if (!set(2, explicitLocale ? "C" : localeName)) return false;
    }
    auto locale = explicitLocale ? create(2, localeName) : nullptr;
    if (explicitLocale && !locale) return false;
    auto errorSlot = cold ? nullptr : error();
    auto dosSlot = cold ? nullptr : dosError();
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto memory = static_cast<char*>(VirtualAlloc(nullptr, system.dwPageSize * 2,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    DWORD protection = 0;
    if (!memory || !VirtualProtect(memory + system.dwPageSize, system.dwPageSize, PAGE_NOACCESS, &protection))
        return false;

    // Known character sequences distinguish byte precision from UTF-16 character precision at a guard boundary.
    std::vector<std::pair<std::string, std::wstring>> characters{{"A", L"A"}, {"B", L"B"}, {"C", L"C"}};
    if (std::string_view(localeName) == ".932")
        characters = {{"\x82\xA0", L"\x3042"}, {"\x83\x41", L"\x30A2"}, {"C", L"C"}};
    else if (std::string_view(localeName) == ".1252")
        characters = {{"\xE9", L"\xE9"}, {"B", L"B"}, {"\xF1", L"\xF1"}};
    else if (std::string_view(localeName) == ".UTF8")
        characters = {{"\xE4\xB8\xAD", L"\x4E2D"}, {"\xF0\x9F\x98\x80", L"\xD83D\xDE00"},
            {"\xC3\xA9", L"\xE9"}};
    auto textFor = [&](int count)
    {
        std::pair<std::string, std::wstring> result;
        for (size_t index = 0; result.second.size() < static_cast<size_t>(count); ++index)
        {
            result.first += characters[index % characters.size()].first;
            result.second += characters[index % characters.size()].second;
        }
        return result;
    };
    const uint64_t options = std::string_view(mode) == "GLOBAL" ? 4 : 0;
    for (const char* style : {"DYNAMIC", "LITERAL", "POSITIONAL"})
    {
        const bool positional = std::string_view(style) == "POSITIONAL";
        const bool literal = std::string_view(style) == "LITERAL";
        const auto name = ucrt ? positional ? "__stdio_common_vswprintf_p" : "__stdio_common_vswprintf" :
            positional ? "_swprintf_p_l" : explicitLocale ? "_snwprintf_l" : "_snwprintf";
        const auto symbol = isolated ? "_o_" + std::string(name) : name;
        const auto function = GetProcAddress(library, symbol.c_str());
        if (!function) return false;
        for (int precision : {1, 0, 2, 3, 80, -1})
        {
            const auto identifier = nextSample.fetch_add(1);
            auto number = std::to_string(identifier);
            const auto prefix = "LC" + std::string(6 - number.size(), '0') + number + ":";
            const auto first = textFor(precision < 0 ? 4 : precision);
            const auto second = textFor(3);
            const auto maximum = positional && first.first.size() < second.first.size() ? second : first;
            auto bytes = maximum.first;
            if (precision < 0) bytes += '\0';
            // UTF-8 conversion needs a terminated source; precision still bounds its captured prefix.
            const size_t padding = !bytes.empty() && std::string_view(localeName) == ".UTF8" ? 1u : 0u;
            auto source = memory + system.dwPageSize - bytes.size() - padding;
            if (!bytes.empty()) memcpy(source, bytes.data(), bytes.size());
            if (padding) memset(source + bytes.size(), 0, padding);
            auto format = prefix + (positional ? std::string("%2$.*1$") +
                (!ucrt || options & 4 ? "S" : "s") + "|%2$.3hs|%3$u" :
                literal ? "%" + (precision < 0 ? std::string{} : "." + std::to_string(precision)) + "hs|%u" :
                "%.*hs|%u");
            const std::wstring wideFormat(format.begin(), format.end());
            const auto expected = std::wstring(prefix.begin(), prefix.end()) + first.second +
                (positional ? L"|" + second.second : L"") + L"|42";
            wchar_t output[256]{};
            auto invoke = [&](auto... arguments)
            {
                if (ucrt) return InvokeListed(function, options, output, locale, wideFormat.c_str(), arguments...);
                if (positional || explicitLocale)
                    return reinterpret_cast<int (__cdecl *)(wchar_t*, size_t, const wchar_t*, void*, ...)>(function)(
                        output, 256, wideFormat.c_str(), locale, arguments...);
                return reinterpret_cast<int (__cdecl *)(wchar_t*, size_t, const wchar_t*, ...)>(function)(
                    output, 256, wideFormat.c_str(), arguments...);
            };
            if (errorSlot) *errorSlot = 1234;
            if (dosSlot) *dosSlot = 2345;
            SetLastError(3456);
            const auto result = literal ? invoke(source, 42u) : invoke(precision, source, 42u);
            const auto lastError = GetLastError();
            const auto crtError = *(errorSlot ? errorSlot : error());
            const auto crtDosError = *(dosSlot ? dosSlot : dosError());
            if (result != expected.size() || output != expected) return false;
            const auto element = literal ? 0 : 1;
            const auto parameter = ucrt ? 5 : (positional || explicitLocale ? 4 : 3) + element;
            std::lock_guard lock(reportLock);
            report << identifier << '\t' << module << '\t' << name << '\t' << mode << '\t' << localeName << '\t'
                << style << '\t' << precision << '\t' << parameter << '\t' << (ucrt ? element : -1) << '\t'
                << options << '\t' << result << '\t' << crtError << '\t' << crtDosError << '\t' << lastError << '\t'
                << std::hex << reinterpret_cast<uintptr_t>(source) << '\t';
            constexpr char digits[] = "0123456789ABCDEF";
            for (unsigned char byte : bytes) report << digits[byte >> 4] << digits[byte & 15];
            report << std::dec << '\t' << format << '\n';
        }
    }
    VirtualFree(memory, 0, MEM_RELEASE);
    if (locale) release(locale);
    if (!cold && std::string_view(mode) != "THREAD" && std::string_view(mode) != "FIBER") set(2, "C");
    return true;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc < 2 || argc > 3) return 1;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    auto errorPath = std::filesystem::path(argv[1]);
    errorPath += L".stderr.log";
    auto errorFile = std::unique_ptr<void, decltype(&CloseHandle)>(CreateFileW(errorPath.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr), CloseHandle);
    if (errorFile.get() == INVALID_HANDLE_VALUE) { errorFile.release(); return 2; }
    if (!SetStdHandle(STD_ERROR_HANDLE, errorFile.get())) return 2;
    std::ofstream report{std::filesystem::path(argv[1])};
    if (!report) return 2;
    for (auto module : {"msvcrt.dll", "msvcr100.dll", "msvcr110.dll", "msvcr120.dll",
        "ucrtbase.dll", "ucrtbased.dll"})
    {
        if (argc == 3 && std::wstring(module, module + strlen(module)) != argv[2]) continue;
        auto library = LoadLibraryExA(module, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 3;
        const bool ucrt = std::string_view(module).starts_with("ucrt");
        for (auto locale : {"C", ".1252", ".932", ".UTF8"})
        {
            if (!ucrt && std::string_view(locale) == ".UTF8") continue;
            for (auto mode : {"EXPLICIT", "GLOBAL"})
                if (!FormatLocale(library, module, locale, mode, report)) return 4;
            if (ucrt && !FormatLocale(library, module, locale, "ISOLATED", report)) return 4;
        }

        // Independent thread locales share one CRT image while producing different multibyte boundaries.
        if (GetProcAddress(library, "_configthreadlocale"))
        {
            bool first = false, second = false;
            std::thread one([&]() { first = FormatLocale(library, module, ".932", "THREAD", report); });
            std::thread two([&]() { second = FormatLocale(library, module, ucrt ? ".UTF8" : "C", "THREAD", report); });
            one.join();
            two.join();
            if (!first || !second) return 5;
        }
        bool cold = false;
        std::thread initial([&]() { cold = FormatLocale(library, module, "C", "COLD", report); });
        initial.join();
        if (!cold) return 5;

        // A fresh CRT thread inherits global state; a warm thread must resynchronize its stale cached locale.
        const auto set = reinterpret_cast<char* (__cdecl *)(int, const char*)>(GetProcAddress(library, "setlocale"));
        if (!set(2, ".932")) return 7;
        bool inherited = false, cached = false;
        std::thread fresh([&]() { inherited = FormatLocale(library, module, ".932", "INHERIT", report); });
        fresh.join();
        if (!inherited || !set(2, "C")) return 7;
        std::barrier synchronize(2);
        std::thread warm([&]()
        {
            const auto error = reinterpret_cast<int* (__cdecl *)()>(GetProcAddress(library, "_errno"));
            error();
            synchronize.arrive_and_wait();
            synchronize.arrive_and_wait();
            cached = FormatLocale(library, module, ".932", "CACHED", report);
        });
        synchronize.arrive_and_wait();
        const bool changed = set(2, ".932") != nullptr;
        synchronize.arrive_and_wait();
        warm.join();
        if (!changed || !cached || !set(2, "C")) return 7;

        // Each fiber owns separate CRT storage even though both execute on the same OS thread.
        if (GetProcAddress(library, "_configthreadlocale"))
        {
            auto parent = ConvertThreadToFiber(nullptr);
            if (!parent) return 8;
            struct FiberCase
            {
                HMODULE library;
                const char* module;
                const char* locale;
                void* parent;
                std::ofstream* report;
                bool passed = false;
            } first{library, module, ".932", parent, &report},
                second{library, module, ucrt ? ".UTF8" : "C", parent, &report};
            auto run = [](void* pointer)
            {
                auto& item = *static_cast<FiberCase*>(pointer);
                item.passed = FormatLocale(item.library, item.module, item.locale, "FIBER", *item.report);
                SwitchToFiber(item.parent);
            };
            auto one = CreateFiber(0, run, &first);
            auto two = CreateFiber(0, run, &second);
            if (!one || !two) return 8;
            SwitchToFiber(one);
            SwitchToFiber(two);
            DeleteFiber(one);
            DeleteFiber(two);
            if (!ConvertFiberToThread() || !first.passed || !second.passed) return 8;
        }
        FreeLibrary(library);
    }
    return report ? 0 : 6;
}

Json LocaleReport(const Path& path)
{
    auto rows =
        Columns(path,
                {"id", "module", "name", "mode", "locale", "style", "precision", "parameter", "element", "options",
                 "result", "error", "dosError", "lastError", "pointer", "data", "text"},
                {"id", "precision", "parameter", "element", "options", "result", "error", "dosError", "lastError"},
                {"pointer"});
    std::set<std::string> locales, modes;
    for (const auto& row : rows)
    {
        locales.insert(row["locale"].get<std::string>());
        modes.insert(row["mode"].get<std::string>());
    }
    Require(rows.size() == 1548 && locales == std::set<std::string>{"C", ".1252", ".932", ".UTF8"} &&
                modes == std::set<std::string>{"EXPLICIT", "GLOBAL", "THREAD", "COLD", "INHERIT", "CACHED", "FIBER",
                                               "ISOLATED"},
            "Locale baseline coverage differs");
    Json result = Json::object();
    for (const auto& row : rows)
        result[std::to_string(row["id"].get<unsigned>())] = Without(row, {"id"});
    return result;
}

void LocaleFormat(const Context& context)
{
    // Explicit, global, thread, fiber and isolated locales preserve source boundaries and caller state.
    auto path = context.directory / L"report.tsv";
    RunTarget(context, Quote(path), 25000);
    auto initial = LocaleReport(path);
    std::map<std::string, Json> baseline;
    for (const auto& sample : initial)
        baseline[Key(sample, {"module", "name", "mode", "locale", "style", "precision", "options"})] = sample;
    Json details = Json::array();
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
    for (uint32_t limit : {16u, 32u, 128u})
    {
        Capture::Run(context, {.arguments = Quote(path), .limit = limit,
            .apiMask = Number(hello["allApis"]) & ~Number(hello["comMask"]),
            .categoryMask = Detourist::CategoryMask(Detourist::ApiCategory::Runtime), .excludedApis = excluded},
            [&](Capture& capture)
        {
            auto expected = LocaleReport(path);
            std::set<std::string> seen;
            for (const auto& row : capture.Find(
                     "_snwprintf|_snwprintf_l|_swprintf_p_l|__stdio_common_vswprintf|__stdio_common_vswprintf_p"))
            {
                bool listed = row["name"].get<std::string>().starts_with("__stdio");
                auto before = Values(row["input"]), after = Values(row["output"]);
                auto formats = Select(before, [&](const Value& value)
                { return value.index == (listed ? 3u : 2u) && Starts(value.data, Encode("LC", true)); });
                if (formats.empty()) continue;
                auto identifier = std::to_string(std::stoul(String(formats[0].data, true).substr(2, 6)));
                Require(seen.insert(identifier).second && expected.contains(identifier), "Duplicate locale call", row);
                auto sample = expected[identifier];
                auto original =
                    baseline.at(Key(sample, {"module", "name", "mode", "locale", "style", "precision", "options"}));
                Require(row["module"] == sample["module"] && row["name"] == sample["name"],
                        "Locale call identity differs", sample);
                for (auto field : {"data", "result", "error", "dosError", "lastError"})
                    Require(sample[field] == original[field], "Locale native state differs", sample);
                auto parameter = sample["parameter"].get<unsigned>(), element = sample["element"].get<unsigned>();
                auto payloads = Regions(before, {.parameter = parameter, .kind = 0, .required = listed ? 72u : 0u,
                                                 .element = listed ? std::optional{element} : std::nullopt});
                auto bytes = Unhex(sample["data"]);
                if (bytes.empty())
                    Require(payloads.empty(), "Empty locale input exposed data", sample);
                else
                {
                    bool complete = bytes.back() == 0 && bytes.size() <= limit;
                    auto flags = (listed ? 72u | (element << 16) : 0u) | unsigned(!complete);
                    Require(payloads == std::vector<Value>{{parameter, 0, flags, complete ? bytes.size() : 0,
                                                            Prefix(bytes, limit)}},
                            "Locale source bytes differ", sample);
                }
                if (!listed)
                    Require((row["flags"].get<uint32_t>() & 2048) &&
                                Read<uint64_t>(row["arguments"], parameter * 8) == sample["pointer"],
                            "Locale source pointer differs", sample);
                else
                {
                    auto scalars = Regions(before, {.parameter = parameter, .kind = 2, .element = element});
                    Require(scalars.size() == 1 && Read<uint64_t>(scalars[0].data) == sample["pointer"],
                            "Locale list slot differs", sample);
                }
                for (const auto& value : after)
                    Require(value.index != parameter || (listed && !(value.flags & 64)),
                            "Locale input captured on return");
                CheckLimit(row, limit);
                if (limit == 128)
                {
                    sample.update({{"call", capture.Details(row)}, {"limit", limit}});
                    details.push_back(sample);
                }
            }
            Require(seen.size() == expected.size(), "Locale scenarios missing");
        });
    }
    Inspect(context, context.Optional(0), "--locale-formats", details, 45000);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, LocaleFormat); }

#else
#error Select a native test target.
#endif

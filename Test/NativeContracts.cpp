#include "TestSupport.h"
#include "GuardedPages.h"

#if defined(DETOURIST_TEST_DetouristAviSaveTests)

using namespace Detourist::Tests;
using namespace Detourist;
using Microsoft::WRL::ComPtr;
using nlohmann::json;

struct AviRuntime
{
    AviRuntime() { AVIFileInit(); }
    ~AviRuntime() { AVIFileExit(); }
};

thread_local uint32_t SaveCallbacks = 0;
thread_local bool CancelSave = false;
BOOL CALLBACK SaveProgress(int)
{
    ++SaveCallbacks;
    return CancelSave;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 2) return 1;
    try
    {
        // A private source contains distinct uncompressed frames; saved streams are reopened and read back.
        AviRuntime runtime;
        std::filesystem::path reportPath(argv[1]);
        auto directory = reportPath.parent_path() / reportPath.stem();
        std::filesystem::create_directories(directory);
        ComPtr<IAVIFile> source;
        Check(AVIFileOpenW(&source, (directory / "source.avi").c_str(), OF_CREATE | OF_READWRITE, nullptr) == S_OK,
            "Create AVI source");
        BITMAPINFOHEADER format{sizeof(format), 2, 2, 1, 24, BI_RGB, 16};
        std::array<ComPtr<IAVIStream>, 2> streams;
        std::array<std::array<BYTE, 16>, 2> pixels;
        for (size_t index = 0; index < streams.size(); ++index)
        {
            AVISTREAMINFOW info{};
            info.fccType = streamtypeVIDEO;
            info.dwScale = 1;
            info.dwRate = 10;
            info.dwSuggestedBufferSize = 16;
            info.dwQuality = UINT32_MAX;
            info.rcFrame = {0, 0, 2, 2};
            Check(AVIFileCreateStreamW(source.Get(), &streams[index], &info) == S_OK, "Create source stream");
            Check(AVIStreamSetFormat(streams[index].Get(), 0, &format, sizeof(format)) == S_OK,
                "Set source stream format");
            pixels[index].fill(static_cast<BYTE>(0x31 + index * 0x32));
            Check(AVIStreamWrite(streams[index].Get(), 0, 1, pixels[index].data(), 16,
                AVIIF_KEYFRAME, nullptr, nullptr) == S_OK, "Write source frame");
        }

        // Guard option structures and their referenced buffers at the end of readable memory.
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        auto pages = GuardedPages(system.dwPageSize, PAGE_NOACCESS, 4);
        auto guarded = [&](size_t page, size_t bytes)
        {
            return reinterpret_cast<BYTE*>(pages.get()) + (page + 1) * system.dwPageSize - bytes;
        };
        auto formatBytes = guarded(4, sizeof(format));
        memcpy(formatBytes, &format, sizeof(format));
        auto settings = guarded(6, 7);
        for (size_t index = 0; index < 7; ++index) settings[index] = static_cast<BYTE>(0x70 + index);
        std::array<LPAVICOMPRESSOPTIONS, 2> options;
        static_assert(sizeof(AVICOMPRESSOPTIONS) == 56 && offsetof(AVICOMPRESSOPTIONS, lpFormat) == 24 &&
            offsetof(AVICOMPRESSOPTIONS, lpParms) == 40);
        for (size_t index = 0; index < options.size(); ++index)
        {
            options[index] = reinterpret_cast<LPAVICOMPRESSOPTIONS>(guarded(index * 2, sizeof(AVICOMPRESSOPTIONS)));
            *options[index] = {streamtypeVIDEO, comptypeDIB, 0, UINT32_MAX, 0, AVICOMPRESSF_VALID,
                formatBytes, sizeof(format), settings, 7, 1};
        }
        auto bytes = [](const void* pointer, size_t length)
        {
            auto data = static_cast<const BYTE*>(pointer);
            return std::vector<BYTE>(data, data + length);
        };
        auto module = GetModuleHandleW(L"avifil32.dll");
        Check(module != nullptr, "Find AVI provider");
        json calls = json::array();
        auto save = [&](const char* name, int count, bool missing, bool imported = false,
            bool progress = false, bool cancel = false)
        {
            auto path = directory / (std::to_string(calls.size()) + ".avi");
            if (missing) path = directory / "absent" / "failed.avi";
            auto narrow = path.string();
            auto wide = path.wstring();
            auto unicode = std::string_view(name).ends_with('W');
            const void* filename = unicode ? static_cast<const void*>(wide.c_str()) : narrow.c_str();
            using Save = HRESULT (__cdecl*)(const void*, CLSID*, AVISAVECALLBACK, int,
                PAVISTREAM, LPAVICOMPRESSOPTIONS, ...);
            auto function = reinterpret_cast<Save>(GetProcAddress(module, name));
            Check(function != nullptr, "Resolve AVI save export");
            auto callback = progress ? &SaveProgress : nullptr;
            SaveCallbacks = 0;
            CancelSave = cancel;
            std::array<void*, 32> pairs{};
            for (size_t index = 0; index < 16; ++index)
            {
                pairs[index * 2] = streams[index % 2].Get();
                pairs[index * 2 + 1] = options[index % 2];
            }
            auto invoke = [&]<size_t... Index>(std::index_sequence<Index...>)
            {
                return function(filename, nullptr, callback, count, static_cast<PAVISTREAM>(pairs[0]),
                    static_cast<LPAVICOMPRESSOPTIONS>(pairs[1]), pairs[Index + 2]...);
            };
            std::vector<uint64_t> arguments{reinterpret_cast<uint64_t>(filename), 0,
                reinterpret_cast<uint64_t>(callback), static_cast<uint32_t>(count)};
            json buffers = json::array();
            for (int index = 0; index < std::max(1, count); ++index)
            {
                arguments.push_back(reinterpret_cast<uint64_t>(pairs[index * 2]));
                arguments.push_back(reinterpret_cast<uint64_t>(pairs[index * 2 + 1]));
                if (index < count) buffers.push_back(bytes(pairs[index * 2 + 1], sizeof(AVICOMPRESSOPTIONS)));
            }
            HRESULT result;
            if (imported)
            {
                result = unicode ? AVISaveW(wide.c_str(), nullptr, callback, count, streams[0].Get(), options[0],
                    streams[1].Get(), options[1]) :
                    AVISaveA(narrow.c_str(), nullptr, callback, count, streams[0].Get(), options[0],
                        streams[1].Get(), options[1]);
            }
            else switch (count)
            {
            case 15: result = invoke(std::make_index_sequence<28>{}); break;
            case 14: result = invoke(std::make_index_sequence<26>{}); break;
            case 8: result = invoke(std::make_index_sequence<14>{}); break;
            case 3: result = invoke(std::make_index_sequence<4>{}); break;
            default: result = invoke(std::make_index_sequence<2>{}); break;
            }
            auto error = GetLastError();
            Check(!progress || SaveCallbacks != 0, "Invoke the save progress callback");

            // Successful saves preserve every stream and pixel, including arguments beyond the capture window.
            json frames = json::array();
            if (SUCCEEDED(result))
            {
                ComPtr<IAVIFile> saved;
                Check(AVIFileOpenW(&saved, path.c_str(), OF_READ, nullptr) == S_OK, "Open saved AVI");
                AVIFILEINFOW info{};
                Check(AVIFileInfoW(saved.Get(), &info, sizeof(info)) == S_OK && info.dwStreams == count,
                    "Read saved stream count");
                for (int index = 0; index < count; ++index)
                {
                    ComPtr<IAVIStream> stream;
                    Check(AVIFileGetStream(saved.Get(), &stream, 0, index) == S_OK, "Open saved stream");
                    std::array<BYTE, 16> data{};
                    LONG copied = 0, samples = 0;
                    Check(AVIStreamRead(stream.Get(), 0, 1, data.data(), 16, &copied, &samples) == S_OK &&
                        copied == 16 && samples == 1 && data == pixels[index % 2], "Read saved frame");
                    frames.push_back(data);
                }
            }
            calls.push_back({{"name", name}, {"count", count}, {"missing", missing}, {"imported", imported},
                {"cancel", cancel}, {"callbackCount", SaveCallbacks}, {"error", error},
                {"result", static_cast<uint32_t>(result)}, {"arguments", arguments}, {"options", buffers},
                {"filename", bytes(filename, unicode ? (wide.size() + 1) * 2 : narrow.size() + 1)},
                {"format", bytes(formatBytes, sizeof(format))}, {"settings", bytes(settings, 7)}, {"frames", frames}});
        };
        save("AVISave", 1, false);
        save("AVISaveA", 3, false);
        save("AVISaveW", 2, false);
        save("AVISaveW", 8, false);
        save("AVISave", 14, false);
        save("AVISaveW", 15, false);
        save("AVISaveA", 2, true);
        save("AVISaveW", 0, true);
        save("AVISave", -1, true);
        save("AVISaveA", 2, false, true);
        save("AVISaveW", 2, false, true);
        save("AVISaveA", 15, false, false, true);
        save("AVISaveW", 3, false, false, true, true);
        auto image = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
        std::ofstream(reportPath, std::ios::binary) << json{{"calls", calls},
            {"image", {image, image + nt->OptionalHeader.SizeOfImage}}}.dump(2);
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 2;
    }
}

void AviSave(const Context& context)
{
    // Compare actual AVI output, including cancellation and missing stream options, in both engines.
    Json details = Json::array();
    auto path = context.directory / L"native.json";
    RunTarget(context, Quote(path), 30000);
    auto native = Report(path);
    for (const auto& call : native["calls"])
        Require(call["missing"] == true || call["cancel"] == true
                    ? (call["result"].get<uint32_t>() & 0x80000000) != 0
                    : call["result"] == 0 && call["frames"].size() == call["count"],
                "AVI baseline differs", call);
    for (bool instructions : {false, true})
        for (uint32_t limit : {17u, 40u, 128u})
        {
            Capture::Run(context, {.arguments = Quote(path), .limit = limit, .instructions = instructions},
                         [&](Capture& capture)
            {
                auto report = Report(path);
                CompareCalls(native, report,
                             {"name", "count", "missing", "imported", "cancel", "result", "frames"});
                auto rows = InImage(capture.Find("AVISave|AVISaveA|AVISaveW", "avifil32\\.dll"), report);
                Require(rows.size() == report["calls"].size(), "AVI call count differs", rows);
                for (size_t index = 0; index < rows.size(); ++index)
                {
                    const auto& row = rows[index];
                    const auto& call = report["calls"][index];
                    auto name = call["name"].get<std::string>();
                    auto flags = row["flags"].get<uint32_t>();
                    Require(row["name"] == name ||
                                (instructions && call["imported"] == false && name != "AVISaveW" &&
                                 (row["name"] == "AVISave" || row["name"] == "AVISaveA")),
                            "AVI import identity differs", row);
                    auto count = std::min(std::max(call["count"].get<int>(), 1) * 2 + 4, 32);
                    Require(!(flags & 4) && row["argument_count"] == 32 && (flags & (256 | 2048)) == (256 | 2048) &&
                                int((flags >> 12) & 63) == count && row["result"] == call["result"] &&
                                row["error"] == call["error"] &&
                                bool(flags & 1) == bool(call["result"].get<uint32_t>() & 0x80000000),
                            "AVI contract differs", row);
                    auto arguments = Data(row["arguments"]);
                    Require(arguments.size() == 256, "AVI argument storage differs", row);
                    for (int ordinal = 0; ordinal < 32; ++ordinal)
                        Require(Read<uint64_t>(arguments, ordinal * 8) ==
                                    (ordinal < count ? call["arguments"][ordinal].get<uint64_t>() : 0),
                                "AVI argument differs", row);
                    auto filename = Data(call["filename"]);
                    auto wide = name.ends_with('W');
                    auto text = Prefix(filename, wide ? limit & ~1u : limit);
                    bool truncated = text.size() < filename.size();
                    std::vector<Value> expected{
                        {0, uint32_t(wide), uint32_t(truncated), truncated ? 0 : filename.size(), text}};
                    size_t option = 0;
                    for (const auto& entry : call["options"])
                    {
                        if (option == 14) break;
                        auto parameter = 5u + static_cast<uint32_t>(option++) * 2;
                        auto data = Data(entry);
                        expected.push_back(
                            {parameter, 0, uint32_t(limit < data.size()), data.size(), Prefix(data, limit)});
                        for (auto [field, source] : {std::pair{24u, "format"}, {40u, "settings"}})
                        {
                            if (std::min<size_t>(limit, data.size()) < field + 12) continue;
                            auto reference = Data(call[source]);
                            expected.push_back({((field + 1) << 8) | parameter, 0,
                                                16u | uint32_t(limit < reference.size()), reference.size(),
                                                Prefix(reference, limit)});
                        }
                    }
                    Require(Values(row["input"]) == expected && Values(row["output"]).empty(),
                            "AVI stream options differ", call);
                    details.push_back({{"expected", call}, {"limit", limit}, {"call", capture.Details(row)}});
                }
            });
        }
    Inspect(context, context.Option(L"--inspector"), "--avi-save", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, AviSave); }

#elif defined(DETOURIST_TEST_DetouristPositionalRecordTests)

using namespace Detourist::Tests;

struct CountedString
{
    uint16_t length, maximum;
    void* buffer;
};
static_assert(sizeof(CountedString) == 16 && offsetof(CountedString, buffer) == 8);

int InvokeListed(FARPROC function, uint64_t options, void* output, const void* format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    auto call = reinterpret_cast<int (__cdecl *)(uint64_t, void*, size_t, const void*, void*, va_list)>(function);
    auto result = call(options, output, 512, format, nullptr, arguments);
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
    auto memory = static_cast<BYTE*>(VirtualAlloc(nullptr, system.dwPageSize * 4,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!report || !memory) return 2;
    for (uint32_t page : {1u, 3u})
    {
        DWORD protection = 0;
        if (!VirtualProtect(memory + system.dwPageSize * page, system.dwPageSize, PAGE_NOACCESS, &protection))
            return 3;
    }
    auto boundary = memory + system.dwPageSize;
    auto descriptor = reinterpret_cast<CountedString*>(memory + system.dwPageSize * 3 - sizeof(CountedString));
    const struct { const char* name; const char* format; const char* views; } formats[]{
        {"DUAL", "%1$hZ|%1$wZ", "AU"}, {"FLIP", "%1$wZ|%1$hZ", "UA"},
        {"PRECISION", "%1$.0hZ|%1$.1wZ|%1$.1hZ", "AUA"}, {"REPEAT", "%1$hZ|%1$hZ", "AA"},
        {"DEFAULT", "%1$hZ|%1$Z", "AD"},
        {"POINTER", "%1$hZ|%1$p", ""}, {"STRING", "%1$hZ|%1$hs", ""},
        {"WIDE", "%1$hZ|%1$ls", ""}, {"COUNT", "%1$hZ|%1$n", ""},
        {"POINTER_FIRST", "%1$p|%1$hZ", ""}, {"STRING_FIRST", "%1$hs|%1$hZ", ""},
        {"WIDE_FIRST", "%1$ls|%1$hZ", ""}, {"COUNT_FIRST", "%1$n|%1$hZ", ""}
    };

    // Native providers establish which positional record interpretations may share one argument.
    for (const auto provider : {"msvcr120.dll", "ucrtbase.dll"})
    {
        auto library = LoadLibraryExA(provider, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 4;
        using InvalidHandler = decltype(&IgnoreInvalidParameter);
        auto setHandler = reinterpret_cast<InvalidHandler (__cdecl *)(InvalidHandler)>(
            GetProcAddress(library, "_set_invalid_parameter_handler"));
        auto enableCounts = reinterpret_cast<int (__cdecl *)(int)>(
            GetProcAddress(library, "_set_printf_count_output"));
        if (!setHandler || !enableCounts) return 5;
        auto previousHandler = setHandler(IgnoreInvalidParameter);
        auto previousCounts = enableCounts(1);
        const bool listed = !strcmp(provider, "ucrtbase.dll");
        for (bool wide : {false, true})
        {
            const auto name = listed ? wide ? "__stdio_common_vswprintf_p" : "__stdio_common_vsprintf_p" :
                wide ? "_swprintf_p" : "_sprintf_p";
            auto function = GetProcAddress(library, name);
            if (!function) return 6;
            for (uint64_t options : {0ull, 4ull})
            {
                if (!listed && options) continue;
                for (const auto& item : formats)
                {
                    const bool rejected = !*item.views;
                    for (const std::string sample : {"FULL", "CAPACITY", "LONG", "EMPTY", "NULL", "NO_DESCRIPTOR"})
                    {
                        if (rejected && sample != "FULL") continue;
                        const uint16_t length = sample == "LONG" ? 64 : sample == "EMPTY" ? 0 : 4;
                        auto data = boundary - length;
                        for (uint32_t index = 0; index < length; ++index)
                            data[index] = wide || !(index & 1) ? 'A' : 0;
                        memset(descriptor, 0, sizeof(*descriptor));
                        descriptor->length = length;
                        descriptor->maximum = sample == "CAPACITY" ? 2 : length;
                        descriptor->buffer = sample == "NULL" ? nullptr : data;
                        auto pointer = rejected ? boundary : sample == "NO_DESCRIPTOR" ? nullptr :
                            reinterpret_cast<BYTE*>(descriptor);
                        const auto format = std::string(item.format);
                        const auto wideFormat = std::wstring(format.begin(), format.end());
                        auto text = wide ? static_cast<const void*>(wideFormat.c_str()) : format.c_str();
                        wchar_t output[512]{};
                        const auto result = listed ? InvokeListed(function, options, output, text, pointer) :
                            reinterpret_cast<int (__cdecl *)(void*, size_t, const void*, ...)>(function)(
                                output, 512, text, pointer);

                        // Counted precision does not shorten native text; empty and null records keep distinct states.
                        std::string views = item.views;
                        for (auto& view : views)
                            if (view == 'D') view = listed && !(wide && (options & 4)) ? 'U' : 'A';
                        std::wstring expected;
                        for (size_t view = 0; view < views.size(); ++view)
                        {
                            if (view) expected += L'|';
                            if (sample == "NULL" || sample == "NO_DESCRIPTOR") expected += L"(null)";
                            else if (views[view] == 'A')
                                for (uint32_t index = 0; index < length; ++index) expected += wchar_t(data[index]);
                            else
                                for (uint32_t index = 0; index + 1 < length; index += 2)
                                    expected += wchar_t(data[index] | uint16_t(data[index + 1]) << 8);
                        }
                        bool valid = rejected ? result < 0 : result == static_cast<int>(expected.size());
                        for (size_t index = 0; valid && index < expected.size(); ++index)
                            valid = wide ? output[index] == expected[index] :
                                reinterpret_cast<unsigned char*>(output)[index] == expected[index];
                        if (!valid)
                        {
                            fprintf(stderr, "%s!%s %s/%s: result=%d expected=%zu\n",
                                provider, name, item.name, sample.c_str(), result, expected.size());
                            return 7;
                        }
                        report << provider << '\t' << name << '\t' << options << '\t' << item.name << '\t'
                            << sample << '\t' << length << '\t' << descriptor->maximum << '\t' << result << '\t'
                            << std::hex << reinterpret_cast<uintptr_t>(pointer) << '\t'
                            << reinterpret_cast<uintptr_t>(descriptor->buffer) << std::dec << '\t'
                            << format << '\t' << views << '\n';
                        report.flush();
                    }
                }
            }
        }
        enableCounts(previousCounts);
        setHandler(previousHandler);
        FreeLibrary(library);
    }
    VirtualFree(memory, 0, MEM_RELEASE);
    return report ? 0 : 8;
}

Json PositionalReport(const Path& path)
{
    auto rows = Columns(path,
                        {"module", "name", "options", "case", "sample", "length", "maximum", "result", "pointer",
                         "buffer", "text", "views"},
                        {"options", "length", "maximum", "result"}, {"pointer", "buffer"});
    auto grouped = Group(rows, {"module", "name"});
    Require(rows.size() == 228 && grouped.size() == 4, "Positional record report incomplete", rows);
    return grouped;
}

void PositionalRecord(const Context& context)
{
    auto report = context.directory / L"positional.tsv";
    RunTarget(context, Quote(report));
    auto baseline = PositionalReport(report);
    Json inspections = Json::array();
    for (uint32_t limit : {16u, 24u, 96u})
    {
        Capture::Run(context, {.arguments = Quote(report), .limit = limit}, [&](Capture& capture)
        {
            auto expected = PositionalReport(report);
            Json grouped = Json::object();
            for (const auto& row :
                 capture.Find("_sprintf_p|_swprintf_p|__stdio_common_vsprintf_p|__stdio_common_vswprintf_p"))
            {
                auto key = Key(row, {"module", "name"});
                if (!expected.contains(key)) continue;
                bool listed = row["module"] == "ucrtbase.dll",
                     wide = row["name"].get<std::string>().contains("wprintf");
                auto formats = Regions(row["input"], {.parameter = listed ? 3u : 2u});
                if (std::ranges::any_of(expected[key], [&](const Json& sample)
                {
                    return std::ranges::any_of(formats, [&](const Value& value)
                    { return value.data == Prefix(Encode(sample["text"], wide, true), limit); });
                }))
                    grouped[key].push_back(row);
            }
            Require(grouped.size() == expected.size(), "Positional record providers missing", grouped);
            for (const auto& [key, samples] : expected.items())
            {
                Require(grouped[key].size() == samples.size(), "Positional record call count differs", grouped[key]);
                for (size_t index = 0; index < samples.size(); ++index)
                {
                    auto row = grouped[key][index], sample = samples[index];
                    bool listed = row["module"] == "ucrtbase.dll",
                         wide = row["name"].get<std::string>().contains("wprintf");
                    uint32_t parameter = listed ? 5 : 3;
                    Require(Without(sample, {"pointer", "buffer"}) ==
                                    Without(baseline[key][index], {"pointer", "buffer"}) &&
                                uint32_t(Number(row["result"])) == uint32_t(Number(sample["result"])),
                            "Positional record native result differs", sample);
                    CheckLimit(row, limit);
                    auto captured = Regions(row["input"], {.parameter = parameter});
                    auto views = sample["views"].get<std::string>();
                    if (views.empty())
                    {
                        Require(captured.size() == 1 && !(captured[0].flags & (8 | 64)) &&
                                    captured[0].original == (listed ? UINT32_MAX : limit) &&
                                    (listed || ((captured[0].flags & 2) && captured[0].data.empty())),
                                "Incompatible positional record fallback differs", row);
                    }
                    else
                    {
                        auto pointer = Number(sample["pointer"]), buffer = Number(sample["buffer"]);
                        auto length = sample["length"].get<uint16_t>(), maximum = sample["maximum"].get<uint16_t>();
                        if (listed)
                            Require(Snapshots(row["input"], parameter, 2) == std::vector<Bytes>{Integer(pointer)},
                                    "Positional record list slot differs", row);
                        else
                            Require(Read<uint64_t>(row["arguments"], parameter * 8) == pointer,
                                    "Positional record argument differs", row);
                        auto headers = Regions(captured, {.kind = 0, .excluded = 8});
                        auto references = Regions(captured, {.required = 8});
                        Require(headers.size() == (pointer ? views.size() : 0), "Positional descriptor views differ",
                                row);
                        for (const auto& header : headers)
                            Require(header.original == 16 && header.data.size() == std::min(16u, limit) &&
                                        Read<uint16_t>(header.data) == length &&
                                        Read<uint16_t>(header.data, 2) == maximum &&
                                        Read<uint64_t>(header.data, 8) == buffer,
                                    "Positional descriptor bytes differ", row);
                        auto wanted = pointer && buffer && length ? views : "";
                        Require(references.size() == wanted.size(), "Positional character view count differs", row);
                        Bytes data;
                        for (size_t offset = 0; offset < length; ++offset)
                            data.push_back(wide || offset % 2 == 0 ? 'A' : 0);
                        for (size_t view = 0; view < references.size(); ++view)
                            Require(references[view].kind == uint32_t(wanted[view] == 'U') &&
                                        references[view].original == length &&
                                        references[view].data == Prefix(data, limit),
                                    "Positional character view bytes differ", row);
                        Require(Regions(row["output"], {.parameter = parameter}).empty(),
                                "Input positional record has captured output", row);
                    }
                    if (!context.Optional(0).empty())
                    {
                        sample.update({{"call", capture.Details(row)},
                                       {"limit", limit},
                                       {"parameter", parameter},
                                       {"listed", listed},
                                       {"wide", wide}});
                        inspections.push_back(sample);
                    }
                }
            }
        });
    }
    Inspect(context, context.Optional(0), "--positional-records", inspections, 45000);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, PositionalRecord); }

#elif defined(DETOURIST_TEST_DetouristTraceLoggingTests)

using namespace Detourist::Tests;
TRACELOGGING_DEFINE_PROVIDER(Provider, "Detourist.TraceLogging",
    (0x5d1c0f3a, 0x8f0e, 0x4c3e, 0x9a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71));

int TargetMain()
{
    if (FAILED(TraceLoggingRegister(Provider))) return 1;

    // No session enables the fixture provider, so mark it enabled to reach EventWriteTransfer with real metadata.
    auto state = const_cast<_tlgProvider_t*>(Provider);
    state->LevelPlus1 = 256;
    state->KeywordAny = ~0ull;
    state->KeywordAll = 0;
    const GUID guid{0x01234567, 0x89ab, 0xcdef, {1, 2, 3, 4, 5, 6, 7, 8}};
    const UINT32 values[]{7, 8, 9};
    const BYTE blob[]{1, 2, 3};
    TraceLoggingWrite(Provider, "DetouristEvent",
        TraceLoggingInt32(-42, "Signed"),
        TraceLoggingUInt64(0x123456789ull, "Unsigned"),
        TraceLoggingHexUInt32(0xBEEF, "Hex"),
        TraceLoggingWideString(L"wide text", "Wide"),
        TraceLoggingString("narrow text", "Narrow"),
        TraceLoggingCountedWideString(L"counted", 7, "Counted"),
        TraceLoggingBoolean(TRUE, "Flag"),
        TraceLoggingGuid(guid, "Guid"),
        TraceLoggingUInt32Array(values, 3, "Values"),
        TraceLoggingStruct(2, "Point"),
            TraceLoggingInt32(3, "X"),
            TraceLoggingInt32(4, "Y"),
        TraceLoggingBinary(blob, 3, "Blob"),
        TraceLoggingHResult(E_FAIL, "Result"));
    TraceLoggingUnregister(Provider);
    return 0;
}

void TraceLogging(const Context& context)
{
    // Render a captured TraceLogging write through the desktop inspector.
    Capture::Run(context, {.limit = 512}, [&](Capture& capture)
    {
        auto rows =
            Query(capture.database, "SELECT c.id,c.target,c.depth FROM calls c "
                                    "LEFT JOIN apis a ON a.id=c.api AND a.target=0 "
                                    "LEFT JOIN apis d ON d.id=c.api AND d.target=c.target "
                                    "WHERE COALESCE(d.name,a.name) IN ('EventWriteTransfer','EtwEventWriteTransfer') "
                                    "AND c.ended IS NOT NULL ORDER BY c.depth,c.id");
        Require(!rows.empty(), "The TraceLogging write was not captured");
        Inspect(context, context.Extra(0), "--trace-logging", Json::array({capture.Details(rows[0])}));
    }, 120);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, TraceLogging); }

#elif defined(DETOURIST_TEST_DetouristCscSearchTests)

using namespace Detourist::Tests;
struct CCscSearchApiInterface;
using CscSearchApiGetInterface_t = LONG (WINAPI*)(ULONG, ULONG, CCscSearchApiInterface**);

struct CCscSearchApiInterface
{
    struct VTable
    {
        ULONG (WINAPI* AddRef)(CCscSearchApiInterface*);
        ULONG (WINAPI* DelRef)(CCscSearchApiInterface*);
        DWORD (WINAPI* OfflineFilesOpenIndexingHandle)(CCscSearchApiInterface*, HANDLE*, PCWSTR, DWORD, DWORD, void*);
    };
    VTable* vtable;
};

int TargetMain()
{
    // Query the IID-less search interface from cscapi.dll.
    auto library = LoadLibraryW(L"cscapi.dll");
    if (!library) return 1;
    auto getter = reinterpret_cast<CscSearchApiGetInterface_t>(GetProcAddress(library, "CscSearchApiGetInterface"));
    if (!getter)
    {
        FreeLibrary(library);
        return 2;
    }
    CCscSearchApiInterface* iface = nullptr;
    auto status = getter(0x10008, 0x8FB92809, &iface);
    if (status < 0 || !iface)
    {
        FreeLibrary(library);
        return 3;
    }
    if (iface->vtable->AddRef(iface) != 2) return 4;
    if (iface->vtable->DelRef(iface) != 1) return 5;
    if (iface->vtable->DelRef(iface) != 0) return 6;
    FreeLibrary(library);
    return 0;
}

void CscSearch(const Context& context)
{
    // Compare interface discovery and reference counts with the untraced workload in both engines.
    RunTarget(context);
    for (bool instructions : {true, false})
    {
        Capture::Run(context, {.limit = 16, .instructions = instructions}, [&](Capture& capture)
        {
            auto rows = capture.Calls();
            Require(Query(capture.database, "SELECT message FROM diagnostics").empty(), "Capture diagnostics");
            auto getter = Named(rows, "CscSearchApiGetInterface");
            auto add = Named(rows, "CCscSearchApiInterface::AddRef");
            auto release = Named(rows, "CCscSearchApiInterface::DelRef");
            Require(getter.size() == 1 && getter[0]["result"] == 0 && add.size() == 1 && add[0]["result"] == 2 &&
                        release.size() == 2 && release[0]["result"] == 1 && release[1]["result"] == 0,
                    "Interface identity or reference counts differ", rows);
        });
    }
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, CscSearch); }

#elif defined(DETOURIST_TEST_DetouristDavComplianceTests)

using namespace Detourist::Tests;
using DavCompliance_t = BOOL (WINAPI*)(LPCWSTR, LPCWSTR, LPBOOL, HWND, LPVOID);

int TargetMain()
{
    // Load wininet and invoke HttpCheckDavComplianceW directly by ordinal 105.
    auto library = LoadLibraryW(L"wininet.dll");
    if (!library) return 1;
    auto function = reinterpret_cast<DavCompliance_t>(GetProcAddress(library, MAKEINTRESOURCEA(105)));
    if (!function)
    {
        FreeLibrary(library);
        return 2;
    }
    BOOL found = FALSE;
    function(L"http://127.0.0.1:65534/dav-test", L"compliance-token", &found, nullptr, nullptr);
    FreeLibrary(library);
    return 0;
}

void DavCompliance(const Context& context)
{
    // An ordinal-only failure must retain the five-argument contract and both input strings.
    RunTarget(context);
    for (bool instructions : {true, false})
    {
        Capture::Run(context, {.limit = 128, .instructions = instructions}, [&](Capture& capture)
        {
            auto rows = Named(capture.Find(".*", "wininet\\.dll"), "HttpCheckDavComplianceW");
            Require(Query(capture.database, "SELECT message FROM diagnostics").empty(), "Capture diagnostics");
            Require(rows.size() == 1, "DAV compliance call missing", rows);
            const auto& row = rows[0];
            Require(row["argument_count"] == 5 && Data(row["arguments"]).size() == 40 && row["result"] == 0 &&
                        (row["flags"].get<uint32_t>() & 1),
                    "DAV contract differs", row);
            auto inputs = Values(row["input"]);
            for (auto [index, text] : {std::pair{0u, "http://127.0.0.1:65534/dav-test"}, {1u, "compliance-token"}})
                Require(std::ranges::any_of(inputs, [&](const Value& value)
                { return value.index == index && String(value.data, true).contains(text); }),
                        "DAV input string missing", row);
        });
    }
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, DavCompliance); }

#elif defined(DETOURIST_TEST_DetouristStackProbeTests)

using namespace Detourist::Tests;
extern "C" unsigned long long CallNativeStackProbe(unsigned long long bytes, void* address);

__declspec(noinline) int ProbeStack(int value)
{
    // Force a stack allocation that crosses guard pages on x64.
    volatile unsigned char storage[32768]{};
    for (int index = 0; index < sizeof(storage); index += 4096)
    {
        storage[index] = static_cast<unsigned char>(value + index / 4096);
    }
    return storage[0] + storage[28672];
}

int TargetMain()
{
    // Invoke the installed stack-probe export with its RAX argument convention.
    auto module = GetModuleHandleW(L"ntdll.dll");
    auto probe = module ? GetProcAddress(module, "__chkstk") : nullptr;
    if (!probe) return 1;
    auto size = CallNativeStackProbe(32768, reinterpret_cast<void*>(probe));
    return size == 32768 && ProbeStack(3) == 13 ? 0 : 2;
}

void StackProbe(const Context& context)
{
    // Verify the native workload and register-specific catalog plans before tracing.
    RunTarget(context, L"", 15000);
    auto plans = Query(context.collector.parent_path() / L"ApiCatalog.sqlite",
                       "SELECT f.module,p.argument_count,p.supported FROM functions f "
                       "JOIN plans p ON p.function_id=f.id WHERE f.name='__chkstk' "
                       "AND f.module IN ('ntdll.dll','kernelbase.dll','kernel32.dll')");
    std::set<std::string> modules;
    for (const auto& plan : plans)
        if (plan["argument_count"] == 1 && plan["supported"] == 1) modules.insert(plan["module"].get<std::string>());
    Require(modules == std::set<std::string>{"ntdll.dll", "kernelbase.dll", "kernel32.dll"},
            "Stack-probe catalog plans differ", plans);

    // The persisted RAX size and result must survive instruction capture.
    Capture::Run(context, {.limit = 16}, [&](Capture& capture)
    {
        auto rows = capture.Find("__chkstk", "ntdll\\.dll");
        Require(std::ranges::any_of(rows,
                                    [](const Json& row)
        {
            return Data(row["arguments"]).size() == 8 && UInt64(row["arguments"]) == 32768 && row["result"] == 32768 &&
                   !(row["flags"].get<uint32_t>() & 256);
        }),
                "The native stack probe lost its RAX size or result", rows);
    }, 75);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, StackProbe); }

#elif defined(DETOURIST_TEST_DetouristArrayArgumentTests)

using namespace Detourist::Tests;

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 2) return 1;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    auto library = LoadLibraryExW(L"icu.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto version = library ? reinterpret_cast<void (__cdecl*)(uint8_t*, int32_t*)>(
        GetProcAddress(library, "ulocdata_getCLDRVersion")) : nullptr;
    if (!version) return 2;

    // A four-byte array is still passed as a full-width pointer on Win64.
    uint8_t bytes[4]{};
    int32_t status = 0;
    version(bytes, &status);
    WriteJson(argv[1], {{"pointer", reinterpret_cast<uintptr_t>(bytes)},
        {"version", Bytes(std::begin(bytes), std::end(bytes))}, {"status", status}});
    FreeLibrary(library);
    return bytes[0] && status <= 0 ? 0 : 3;
}

void ArrayArguments(const Context& context)
{
    auto path = context.directory / L"version.json";
    RunTarget(context, Quote(path));
    auto baseline = Json::parse(ReadLog(path));
    auto instructions = context.Has(L"--instructions");
    Capture::Run(context, {.arguments = Quote(path), .limit = 16, .instructions = instructions}, [&](Capture& capture)
    {
        auto observed = Json::parse(ReadLog(path));
        Require(observed["version"] == baseline["version"] && observed["status"] == baseline["status"],
            "ICU version lookup changed under capture", observed);
        auto pointer = observed["pointer"].get<uint64_t>();
        Require(pointer > UINT32_MAX, "ICU fixture requires a pointer above four gigabytes", observed);
        auto calls = capture.Find("ulocdata_getCLDRVersion", "icu\\.dll");
        Require(calls.size() == 1 && Read<uint64_t>(Data(calls[0]["arguments"])) == pointer &&
            !calls[0]["ended"].is_null(), "ICU array argument lost its full-width pointer", calls);
        auto output = Snapshots(calls[0]["output"], 0, 0);
        Require(output == std::vector<Bytes>{observed["version"].get<Bytes>()},
            "ICU version array output differs", calls);
    });
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ArrayArguments); }

#else
#error Select a native test target.
#endif

#include "TestSupport.h"
#include "ApiCategories.h"

#if defined(DETOURIST_TEST_DetouristPromptUserTests)

using namespace Detourist::Tests;
nlohmann::json dialog;

std::string Utf8(const wchar_t* text)
{
    auto count = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    std::string result(count, '\0');
    if (count) WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), count, nullptr, nullptr);
    if (!result.empty()) result.pop_back();
    return result;
}

void CALLBACK InspectDialog(HWND window, UINT, UINT_PTR timer, DWORD)
{
    // Read the formatted title and static text after initialization, then cancel every template's dialog.
    KillTimer(window, timer);
    wchar_t title[256]{};
    GetWindowTextW(window, title, 256);
    dialog["title"] = Utf8(title);
    dialog["children"] = nlohmann::json::array();
    EnumChildWindows(window, [](HWND child, LPARAM)
    {
        wchar_t text[2048]{};
        GetWindowTextW(child, text, 2048);
        dialog["children"].push_back(Utf8(text));
        return TRUE;
    }, 0);
    PostMessageW(window, WM_COMMAND, IDCANCEL, 0);
}

LRESULT CALLBACK ObserveDialog(int code, WPARAM first, LPARAM second)
{
    // Inspect only dialogs created by this thread on its private desktop.
    if (code == HCBT_ACTIVATE)
    {
        const auto window = reinterpret_cast<HWND>(first);
        wchar_t type[32]{};
        GetClassNameW(window, type, 32);
        if (!wcscmp(type, L"#32770")) SetTimer(window, 0xD371, 1, InspectDialog);
    }
    return CallNextHookEx(nullptr, code, first, second);
}

int RunPrompts(HDESK desktop, const nlohmann::json& cases, std::ofstream& report)
{
    if (!SetThreadDesktop(desktop)) return 2;
    const auto hook = SetWindowsHookExW(WH_CBT, ObserveDialog, nullptr, GetCurrentThreadId());
    const auto library = LoadLibraryExW(L"oledlg.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hook || !library) return 3;

    // Each call supplies a title and one insert of the requested encoding, whether or not its template consumes it.
    for (const auto& item : cases)
    {
        const auto wide = item["wide"].get<bool>();
        const auto function = wide ? "OleUIPromptUserW" : "OleUIPromptUserA";
        const auto address = reinterpret_cast<int (__cdecl *)(int, HWND, ...)>(GetProcAddress(library, function));
        if (!address) return 3;
        const auto title = item["title"].get<std::string>(), insert = item["insert"].get<std::string>();
        const std::wstring wideTitle(title.begin(), title.end()), wideInsert(insert.begin(), insert.end());
        const void* titleArgument = wide ? static_cast<const void*>(wideTitle.c_str()) : title.c_str();
        const void* insertArgument = item["insertWide"].get<bool>() ?
            static_cast<const void*>(wideInsert.c_str()) : insert.c_str();
        dialog = {
            {"id", item["id"]}, {"function", function}, {"title", nullptr}, {"children", nlohmann::json::array()}};
        dialog["result"] = address(item["template"].get<int>(), nullptr, titleArgument, insertArgument);
        report << dialog.dump() << '\n' << std::flush;
    }
    UnhookWindowsHookEx(hook);
    FreeLibrary(library);
    return report ? 0 : 5;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 3) return 1;
    std::ifstream config{std::filesystem::path(argv[1])};
    std::ofstream report{std::filesystem::path(argv[2])};
    if (!config || !report) return 1;
    const auto cases = nlohmann::json::parse(config);
    const auto name = L"Detourist.PromptUser." + std::to_wstring(GetCurrentProcessId());
    const auto desktop = CreateDesktopW(name.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    if (!desktop) return 2;
    int result = 0;
    std::thread worker([&]() { result = RunPrompts(desktop, cases, report); });
    worker.join();
    CloseDesktop(desktop);
    return result;
}

Json PromptReports(const Path& path, const Json& samples)
{
    auto rows = JsonLines(path);
    Require(rows.size() == samples.size(), "Prompt report count differs");
    for (size_t index = 0; index < rows.size(); ++index)
    {
        const auto& row = rows[index];
        const auto& sample = samples[index];
        Require(row["id"] == sample["id"], "Prompt report identity differs", row);
        if (sample["known"] == false)
            Require(row["title"].is_null() && row["result"].get<int>() < 0, "Unknown prompt template succeeded", row);
        else
            Require(row["result"] == 2 && row["title"] == sample["title"] &&
                        std::ranges::any_of(row["children"], [&](const Json& text)
            { return text.get<std::string>().contains(sample["insert"].get<std::string>()); }) ==
                            (sample["inserts"] != 0),
                    "Prompt dialog rendering differs", row);
    }
    return rows;
}

void PromptUser(const Context& context)
{
    // Native dialogs establish the resource template's variable arguments and rendered text.
    Json samples = Json::array();
    for (bool wide : {false, true})
        for (auto [identifier, insert] : {std::pair{1008, -1},
                                          {1020, -1},
                                          {1021, 1},
                                          {1022, 1},
                                          {1023, -1},
                                          {1024, -1},
                                          {1025, 0},
                                          {1026, 0},
                                          {999, -1}})
        {
            std::ostringstream prefix;
            prefix << "PU" << std::setfill('0') << std::setw(2) << samples.size();
            samples.push_back({{"id", samples.size()},
                               {"wide", wide},
                               {"template", identifier},
                               {"title", prefix.str() + " prompt title"},
                               {"insert", prefix.str() + " object type"},
                               {"insertWide", insert == 1},
                               {"inserts", insert < 0 ? 0 : 1},
                               {"known", identifier != 999}});
        }
    auto config = context.directory / L"cases.json", report = context.directory / L"report.jsonl";
    WriteJson(config, samples);
    auto arguments = Quote(config) + L" " + Quote(report);
    RunTarget(context, arguments, 120000);
    auto baseline = PromptReports(report, samples);
    Json details = Json::array();
    auto hello = context.GetCollector().Call("hello");
    for (uint32_t limit : {16u, 512u})
    {
        Capture::Run(context, {.arguments = arguments, .limit = limit,
            .apiMask = Number(hello["allApis"]) & ~Number(hello["comMask"]),
            .categoryMask = Detourist::CategoryMask(Detourist::ApiCategory::Windows)}, [&](Capture& capture)
        {
            auto observed = PromptReports(report, samples);
            auto rows = capture.Find("OleUIPromptUserA|OleUIPromptUserW");
            Require(rows.size() == samples.size(), "Prompt capture count differs", rows);
            for (size_t index = 0; index < rows.size(); ++index)
            {
                const auto& row = rows[index];
                const auto& sample = samples[index];
                auto flags = row["flags"].get<uint32_t>();
                Require(row["name"] == observed[index]["function"] &&
                            observed[index]["result"] == baseline[index]["result"] &&
                            uint32_t(row["result"].get<uint64_t>()) ==
                                uint32_t(baseline[index]["result"].get<int64_t>()) &&
                            bool(flags & 2048) == sample["known"].get<bool>(),
                        "Prompt result differs", row);
                if (sample["known"] == false) continue;
                auto values = Values(row["input"]);
                Require(Values(row["output"]).empty() &&
                            ((flags >> 12) & 63) == 3 + sample["inserts"].get<unsigned>() &&
                            values.size() == 1 + sample["inserts"].get<unsigned>(),
                        "Prompt variable arguments differ", row);
                std::set<uint32_t> seen;
                for (const auto& value : values)
                {
                    Require(value.index == 2 || (value.index == 3 && sample["inserts"] != 0),
                            "Unexpected prompt insert", row);
                    auto wide = sample[value.index == 2 ? "wide" : "insertWide"].get<bool>();
                    auto bytes = Encode(sample[value.index == 2 ? "title" : "insert"], wide, true);
                    Require(seen.insert(value.index).second && value.kind == unsigned(wide) &&
                                value.data == Prefix(bytes, limit) && !(value.flags & 2) &&
                                bool(value.flags & 1) == (bytes.size() > limit),
                            "Prompt text capture differs", row);
                }
                if (limit == 512) details.push_back({{"sample", sample}, {"call", capture.Details(row)}});
            }
        }, 180);
    }
    Inspect(context, context.Optional(0), "--prompt-user", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, PromptUser); }

#elif defined(DETOURIST_TEST_DetouristWindowCompositionTests)

using namespace Detourist::Tests;
struct CompositionData
{
    DWORD attribute;
    void* data;
    SIZE_T bytes;
};
using CompositionFunction = BOOL (WINAPI*)(HWND, CompositionData*);

std::string Hex(const std::vector<BYTE>& bytes)
{
    std::string text;
    char digits[3]{};
    for (auto value : bytes)
    {
        std::snprintf(digits, sizeof(digits), "%02x", value);
        text += digits;
    }
    return text;
}

std::vector<BYTE> CompositionValue(DWORD value, size_t bytes = 4)
{
    std::vector<BYTE> data(bytes);
    memcpy(data.data(), &value, sizeof(value));
    return data;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 2) return 1;
    const auto user32 = GetModuleHandleW(L"user32.dll");
    const auto get = reinterpret_cast<CompositionFunction>(GetProcAddress(user32, "GetWindowCompositionAttribute"));
    const auto set = reinterpret_cast<CompositionFunction>(GetProcAddress(user32, "SetWindowCompositionAttribute"));
    const auto buttonText = reinterpret_cast<LPCWSTR (WINAPI*)(UINT)>(GetProcAddress(user32, "MB_GetString"));
    const auto window = CreateWindowExW(0, L"STATIC", L"Detourist composition", WS_OVERLAPPEDWINDOW,
        100, 100, 320, 200, nullptr, nullptr, nullptr, nullptr);
    if (!get || !set || !buttonText || !window) return 2;
    nlohmann::json report{{"calls", nlohmann::json::array()}, {"strings", nlohmann::json::array()}};

    // Each call records the documented DWM attribute that observes the same window state, when one exists.
    auto call = [&](bool write, DWORD attribute, std::vector<BYTE> payload, int dwm = -1)
    {
        auto buffer = payload;
        CompositionData data{attribute, buffer.data(), buffer.size()};
        const auto result = (write ? set : get)(window, &data);
        nlohmann::json item{{"set", write}, {"attribute", attribute}, {"input", Hex(payload)},
            {"output", Hex(buffer)}, {"result", result}};
        if (dwm >= 0)
        {
            std::vector<BYTE> observed(buffer.size());
            item["dwm"] = SUCCEEDED(DwmGetWindowAttribute(window, dwm, observed.data(),
                static_cast<DWORD>(observed.size()))) ? Hex(observed) : "";
        }
        report["calls"].push_back(item);
    };
    call(false, 1, CompositionValue(0), DWMWA_NCRENDERING_ENABLED);
    call(false, 5, std::vector<BYTE>(16), DWMWA_CAPTION_BUTTON_BOUNDS);
    call(false, 8, std::vector<BYTE>(16), DWMWA_EXTENDED_FRAME_BOUNDS);
    call(true, 2, CompositionValue(DWMNCRP_DISABLED), DWMWA_NCRENDERING_ENABLED);
    call(true, 2, CompositionValue(DWMNCRP_USEWINDOWSTYLE), DWMWA_NCRENDERING_ENABLED);
    call(true, 17, CompositionValue(TRUE), DWMWA_CLOAKED);
    call(false, 18, CompositionValue(0), DWMWA_CLOAKED);
    call(true, 17, CompositionValue(FALSE), DWMWA_CLOAKED);
    call(true, 20, CompositionValue(TRUE), DWMWA_FREEZE_REPRESENTATION);
    call(false, 20, CompositionValue(0), DWMWA_FREEZE_REPRESENTATION);
    call(true, 25, CompositionValue(TRUE), DWMWA_PASSIVE_UPDATE_MODE);
    call(false, 25, CompositionValue(0), DWMWA_PASSIVE_UPDATE_MODE);
    call(true, 26, CompositionValue(TRUE), DWMWA_USE_IMMERSIVE_DARK_MODE);
    call(false, 26, CompositionValue(0), DWMWA_USE_IMMERSIVE_DARK_MODE);
    call(true, 27, CompositionValue(DWMWCP_ROUNDSMALL), DWMWA_WINDOW_CORNER_PREFERENCE);
    call(false, 27, CompositionValue(0), DWMWA_WINDOW_CORNER_PREFERENCE);
    call(true, 30, CompositionValue(DWMSBT_TABBEDWINDOW), DWMWA_SYSTEMBACKDROP_TYPE);
    call(false, 30, CompositionValue(0), DWMWA_SYSTEMBACKDROP_TYPE);
    call(true, 24, CompositionValue(TRUE));
    call(false, 24, CompositionValue(0));
    std::vector<BYTE> accent(16);
    accent[0] = 3;
    call(true, 19, accent);
    call(false, 34, CompositionValue(0));
    call(true, 19, std::vector<BYTE>(16));
    call(false, 34, CompositionValue(0));
    call(false, 12, std::vector<BYTE>(20));

    // Button captions are localized user32 resources; out-of-range identifiers return no text.
    for (UINT button : {0u, 1u, 2u, 3u, 4u, 5u, 6u, 9u, 10u, 0xFFFFu})
    {
        const auto text = buttonText(button);
        std::string utf8;
        if (text)
        {
            utf8.resize(WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr));
            WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8.data(), static_cast<int>(utf8.size()), nullptr, nullptr);
            utf8.pop_back();
        }
        report["strings"].push_back({{"button", button}, {"text", text ? nlohmann::json(utf8) : nlohmann::json()},
            {"bytes", text ? Hex(std::vector<BYTE>(reinterpret_cast<const BYTE*>(text),
                reinterpret_cast<const BYTE*>(text + wcslen(text) + 1))) : ""}});
    }
    DestroyWindow(window);
    std::ofstream output(argv[1]);
    output << report.dump();
    return output ? 0 : 3;
}

void VerifyComposition(const Json& report)
{
    Require(report["calls"].size() == 25 && report["strings"].size() == 10, "Composition baseline coverage differs");
    std::map<int, std::string> previous;
    for (const auto& call : report["calls"])
    {
        Require(call["result"] != 0, "Native composition call failed", call);
        auto attribute = call["attribute"].get<int>();
        auto data = call[call["set"] == true ? "input" : "output"].get<std::string>();
        if (attribute == 2)
            Require(call["dwm"] == (data == "01000000" ? "00000000" : "01000000"), "DWM rendering policy differs");
        else if (call.contains("dwm"))
            Require(call["dwm"] == data, "Composition value differs from DWM", call);
        if (attribute == 24 && call["set"] == false) Require(data == previous.at(24), "Composition state was lost");
        if (attribute == 34)
            Require(data == (previous.at(19).starts_with("03") ? "01000000" : "00000000"),
                    "Composition accent state differs");
        previous[attribute] = data;
    }
    for (size_t index = 0; index < 10; ++index)
    {
        const auto& item = report["strings"][index];
        Require(item["text"].is_null() == (index == 9), "Composition caption coverage differs");
        if (index < 9) Require(Unhex(item["bytes"]) == Encode(item["text"], true, true), "Native caption bytes differ");
    }
}

void WindowComposition(const Context& context)
{
    // Compare documented DWM state with each composition read/write and returned button caption.
    std::map<int, std::string> names{{1, "NCRENDERING_ENABLED"},
                                     {2, "NCRENDERING_POLICY"},
                                     {5, "CAPTION_BUTTON_BOUNDS"},
                                     {8, "EXTENDED_FRAME_BOUNDS"},
                                     {12, "NCADORNMENTINFO"},
                                     {17, "CLOAK"},
                                     {18, "CLOAKED"},
                                     {19, "ACCENT_POLICY"},
                                     {20, "FREEZE_REPRESENTATION"},
                                     {24, "EXCLUDED_FROM_DDA"},
                                     {25, "PASSIVEUPDATEMODE"},
                                     {26, "USEDARKMODECOLORS"},
                                     {27, "CORNER_STYLE"},
                                     {30, "SYSTEMBACKDROP_TYPE"},
                                     {34, "HAS_ACCENT_POLICY"}};
    std::map<int, std::string> types{{1, "BOOL"},
                                     {2, "DWMNCRENDERINGPOLICY"},
                                     {5, "RECT"},
                                     {8, "RECT"},
                                     {17, "BOOL"},
                                     {18, "DWORD"},
                                     {20, "BOOL"},
                                     {24, "BOOL"},
                                     {25, "BOOL"},
                                     {26, "BOOL"},
                                     {27, "DWM_WINDOW_CORNER_PREFERENCE"},
                                     {30, "DWM_SYSTEMBACKDROP_TYPE"},
                                     {34, "BOOL"}};
    auto path = context.directory / L"report.json";
    RunTarget(context, Quote(path), 60000);
    VerifyComposition(Report(path));
    Json details = Json::array();
    for (uint32_t limit : {16u, 512u})
    {
        Capture::Run(context, {.arguments = Quote(path), .limit = limit}, [&](Capture& capture)
        {
            auto report = Report(path);
            VerifyComposition(report);
            auto rows = capture.Find("(Get|Set)WindowCompositionAttribute|MB_GetString");
            Require(!rows.empty(), "Composition calls missing");
            auto depth =
                std::ranges::min(rows, {}, [](const Json& row) { return row["depth"].get<unsigned>(); })["depth"];
            Json composition = Json::array(), strings = Json::array();
            for (const auto& row : rows)
                if (row["depth"] == depth) (row["name"] == "MB_GetString" ? strings : composition).push_back(row);
            Require(composition.size() == report["calls"].size() && strings.size() == report["strings"].size(),
                    "Composition call count differs");
            for (size_t index = 0; index < composition.size(); ++index)
            {
                const auto& row = composition[index];
                const auto& call = report["calls"][index];
                bool set = call["set"];
                Require(row["name"] == std::string(set ? "Set" : "Get") + "WindowCompositionAttribute",
                        "Composition direction differs");
                for (auto phase : {"input", "output"})
                {
                    auto members = Regions(row[phase], {.parameter = 1, .required = 16, .parameterMask = 255});
                    auto expected = set && std::string(phase) == "output" ? Json(nullptr) : call[phase];
                    if (expected.is_null())
                        Require(members.empty(), "Composition setter captured returned data");
                    else
                    {
                        auto bytes = Unhex(expected);
                        Require(members.size() == 1 && members[0].original == bytes.size() &&
                                    members[0].data == Prefix(bytes, limit) &&
                                    bool(members[0].flags & 1) == (bytes.size() > limit),
                                "Composition member bytes differ", call);
                    }
                }
                if (limit == 512)
                {
                    auto attribute = call["attribute"].get<int>();
                    details.push_back({{"kind", "composition"},
                                       {"attribute", attribute},
                                       {"name", "WCA_" + names.at(attribute)},
                                       {"type", types.contains(attribute) ? Json(types.at(attribute)) : Json(nullptr)},
                                       {"data", call[set ? "input" : "output"]},
                                       {"set", set},
                                       {"call", capture.Details(row)}});
                }
            }
            for (size_t index = 0; index < strings.size(); ++index)
            {
                const auto& row = strings[index];
                const auto& item = report["strings"][index];
                auto values = Regions(row["output"], {.parameter = UINT32_MAX});
                if (item["text"].is_null())
                {
                    Require(row["result"] == 0 && values.empty(), "Failed caption has text");
                    continue;
                }
                auto bytes = Unhex(item["bytes"]);
                Require(values.size() == 1 && values[0].kind == 1 && (values[0].flags & 8) &&
                            values[0].data == Prefix(bytes, limit) &&
                            bool(values[0].flags & 1) == (bytes.size() > limit),
                        "Caption result region differs", item);
                if (limit == 512)
                    details.push_back({{"kind", "string"}, {"text", item["text"]}, {"call", capture.Details(row)}});
            }
        }, 180);
    }
    Inspect(context, context.Optional(0), "--window-composition", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, WindowComposition); }

#elif defined(DETOURIST_TEST_DetouristRunAsTests)

using namespace Detourist::Tests;
using namespace Detourist;

struct RunAsParameters
{
    wchar_t eventName[0x38], executable[MAX_PATH], arguments[MAX_PATH - 4];
    BYTE reserved[0x600];
    wchar_t directory[MAX_PATH];
};
static_assert(sizeof(RunAsParameters) == 0xC80 && offsetof(RunAsParameters, executable) == 0x70 &&
    offsetof(RunAsParameters, arguments) == 0x278 && offsetof(RunAsParameters, directory) == 0xA78);

BOOL CALLBACK DismissLaunchError(HWND window, LPARAM process)
{
    // Shell error dialogs can run on a worker thread, but belong to this fixture's isolated process.
    DWORD owner = 0;
    GetWindowThreadProcessId(window, &owner);
    wchar_t type[32]{};
    if (owner == static_cast<DWORD>(process) && GetClassNameW(window, type, 32) && !wcscmp(type, L"#32770"))
    {
        PostMessageW(window, WM_COMMAND, IDOK, 0);
        PostMessageW(window, WM_CLOSE, 0, 0);
    }
    return TRUE;
}

int TargetMain(int argc, wchar_t** argv)
{
    // A launched child confirms both its argument and its requested working directory before signaling completion.
    if (argc == 4 && !wcscmp(argv[1], L"--signal"))
    {
        wchar_t directory[MAX_PATH]{};
        Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]));
        return ready && GetCurrentDirectoryW(MAX_PATH, directory) && !_wcsicmp(directory, argv[3]) &&
            SetEvent(ready.get()) ? 0 : 1;
    }
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    wchar_t executable[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, executable, MAX_PATH)) return 2;

    // Starting the worker on a private desktop isolates ShellExecuteExW's own UI threads as well.
    if (argc == 2)
    {
        auto desktopName = L"Detourist-RunAs-" + std::to_wstring(GetCurrentProcessId());
        auto desktop = CreateDesktopW(desktopName.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
        if (!desktop) return 3;
        STARTUPINFOW startup{sizeof(startup)};
        startup.lpDesktop = desktopName.data();
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION process{};
        auto command = L"\"" + std::wstring(executable) + L"\" --target --worker \"" + argv[1] + L"\"";
        DWORD result = 4;
        if (CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &process))
        {
            Handle worker(process.hProcess), thread(process.hThread);
            const auto deadline = GetTickCount64() + 60000;
            while (WaitForSingleObject(worker.get(), 50) == WAIT_TIMEOUT && GetTickCount64() < deadline)
                EnumDesktopWindows(desktop, DismissLaunchError, process.dwProcessId);
            if (!GetExitCodeProcess(worker.get(), &result) || result == STILL_ACTIVE)
            {
                TerminateProcess(worker.get(), 5);
                WaitForSingleObject(worker.get(), 5000);
                result = 5;
            }
        }
        CloseDesktop(desktop);
        return static_cast<int>(result);
    }
    if (argc != 3 || wcscmp(argv[1], L"--worker")) return 6;
    const auto prefix = L"Local\\Detourist-RunAs-" + std::to_wstring(GetCurrentProcessId());
    const auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    auto library = LoadLibraryExW(L"shell32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto function = library ? reinterpret_cast<int (WINAPI*)(HWND, HINSTANCE, LPCWSTR, int)>(
        GetProcAddress(library, "RunAsNewUser_RunDLLW")) : nullptr;
    auto result = [&]()
    {
        if (FAILED(initialized) || !function) return 7;
        const auto directory = std::filesystem::absolute(argv[2]).parent_path().wstring();
        std::ofstream report{std::filesystem::path(argv[2])};
        if (!report) return 6;
        auto observations = nlohmann::json::array();

        // Mapping and event lookup fail with HRESULTs; the launch path returns ShellExecuteExW's Boolean result.
        for (unsigned scenario = 0; scenario < 4; ++scenario)
        {
            const auto name = prefix + L"-" + std::to_wstring(scenario);
            const auto copiedName = name + L"-copied", readyName = name + L"-ready";
            Handle mapping, copied, ready;
            std::unique_ptr<void, decltype(&UnmapViewOfFile)> view(nullptr, UnmapViewOfFile);
            if (scenario)
            {
                mapping.reset(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                    0, sizeof(RunAsParameters), name.c_str()));
                view.reset(
                    mapping ? MapViewOfFile(mapping.get(), FILE_MAP_WRITE, 0, 0, sizeof(RunAsParameters)) : nullptr);
                if (!view) return 7;
                auto parameters = static_cast<RunAsParameters*>(view.get());
                wcscpy_s(parameters->eventName, copiedName.c_str());
                if (scenario >= 2) copied.reset(CreateEventW(nullptr, TRUE, FALSE, copiedName.c_str()));
                if (scenario == 2)
                    wcscpy_s(parameters->executable, (directory + L"\\missing-launch-target.exe").c_str());
                else if (scenario == 3)
                {
                    ready.reset(CreateEventW(nullptr, TRUE, FALSE, readyName.c_str()));
                    wcscpy_s(parameters->executable, executable);
                    wcscpy_s(parameters->arguments,
                        (L"--target --signal \"" + readyName + L"\" \"" + directory + L"\"").c_str());
                    wcscpy_s(parameters->directory, directory.c_str());
                }
                if (scenario >= 2 && !copied || scenario == 3 && !ready) return 8;
            }
            SetLastError(ERROR_SUCCESS);
            const auto returned = function(nullptr, nullptr, name.c_str(), SW_HIDE);
            const auto error = GetLastError();
            const bool signaled = copied && WaitForSingleObject(copied.get(), 0) == WAIT_OBJECT_0;
            const bool launched = ready && WaitForSingleObject(ready.get(), 10000) == WAIT_OBJECT_0;
            observations.push_back({{"scenario", scenario}, {"mapping", Utf8(name)}, {"result", returned},
                {"lastError", error}, {"copied", signaled}, {"launched", launched}});
            if ((scenario < 2 ? returned >= 0 : scenario == 2 ? returned != 0 : returned <= 0) ||
                signaled != (scenario >= 2) || launched != (scenario == 3)) return 9;
        }
        report << observations.dump();
        return report ? 0 : 10;
    }();
    if (library) FreeLibrary(library);
    if (SUCCEEDED(initialized)) CoUninitialize();
    return result;
}

void RunAs(const Context& context)
{
    // Verify mapping, launch failures and a successful launch with arguments and a working directory.
    auto path = context.directory / L"baseline.json";
    RunTarget(context, Quote(path), 75000);
    auto baseline = Report(path);
    Require(baseline.size() == 4, "RunAs scenario count differs", baseline);
    std::vector<int64_t> expected{-2147024894, -2147024894, 0, 1};
    for (size_t index = 0; index < expected.size(); ++index)
        Require(baseline[index]["result"] == expected[index], "RunAs native outcome differs", baseline);
    if (!context.Has(L"--capture")) return;
    Collector hello(context.collector, context.directory);
    auto shell = Named(hello.Call("hello")["catalog"], "ShellExecuteExW")[0];
    hello.Close();
    for (bool instructions : {true, false})
        for (uint32_t limit : {32u, 256u})
        {
            Capture::Run(context,
                         {.arguments = Quote(path),
                          .limit = limit,
                          .instructions = instructions,
                          .followChildren = true,
                          .apiMask = Number(shell["mask"]),
                          .categoryMask = uint64_t{1} << shell["category"].get<unsigned>()},
                         [&](Capture& capture)
            {
                auto actual = Report(path);
                auto rows = capture.Find("RunAsNewUser_RunDLLW");
                Require(rows.size() == 4 && actual.size() == 4, "RunAs captured count differs", rows);
                for (size_t index = 0; index < rows.size(); ++index)
                {
                    const auto& row = rows[index];
                    const auto& sample = actual[index];
                    for (auto field : {"scenario", "result", "copied", "launched"})
                        Require(sample[field] == baseline[index][field], "RunAs behavior differs", sample);
                    Require(row["module"] == "shell32.dll" &&
                                uint32_t(row["result"].get<uint64_t>()) == uint32_t(sample["result"].get<int64_t>()) &&
                                row["error"] == sample["lastError"] &&
                                bool(row["flags"].get<uint32_t>() & 1) == (sample["result"].get<int64_t>() <= 0),
                            "RunAs result differs", row);
                    auto text = Encode(sample["mapping"], true, true);
                    auto values = Values(row["input"]);
                    std::vector<Value> captured;
                    for (const auto& value : values)
                        if (value.index == 2) captured.push_back(value);
                    Require(captured ==
                                std::vector<Value>{{2, 1, uint32_t(text.size() > limit),
                                                    text.size() > limit ? 0 : text.size(), Prefix(text, limit)}},
                            "RunAs mapping differs", sample);
                }
            }, 75);
        }
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, RunAs); }

#else
#error Select a native test target.
#endif

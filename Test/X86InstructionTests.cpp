#include "TestSupport.h"
#include "CatalogView.h"

using namespace Detourist::Tests;

int Positional(void* function, char* buffer, size_t capacity, const char* format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    auto invoke = reinterpret_cast<int (__cdecl*)(uint64_t, char*, size_t, const char*, void*, va_list)>(function);
    const auto result = invoke(0, buffer, capacity, format, nullptr, arguments);
    va_end(arguments);
    return result;
}

int TargetMain(int count, wchar_t** arguments)
{
    auto module = LoadLibraryExW(L"msvcrt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    Require(module != nullptr, "Load the system CRT");
    auto hypotenuse = reinterpret_cast<double (__cdecl*)(double, double)>(GetProcAddress(module, "_hypot"));
    auto integer = reinterpret_cast<uint64_t (__cdecl*)(const char*, char**, int)>(
        GetProcAddress(module, "_strtoui64"));
    auto format = reinterpret_cast<int (__cdecl*)(char*, size_t, const char*, ...)>(
        GetProcAddress(module, "sprintf_s"));
    auto ucrt = LoadLibraryExW(L"ucrtbase.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto positional = ucrt ? reinterpret_cast<void*>(GetProcAddress(ucrt, "__stdio_common_vsprintf_p")) : nullptr;
    auto scan = reinterpret_cast<int (__cdecl*)(const char*, const char*, ...)>(GetProcAddress(module, "sscanf_s"));
    Require(hypotenuse && integer && format && positional && scan, "Resolve CRT capture fixtures");
    if (count > 1)
    {
        Require(hypotenuse(6.0, 8.0) == 10.0, "Warm the floating-point export");
        auto name = L"Local\\Detourist.X86.Float." + std::to_wstring(GetCurrentProcessId());
        Detourist::Handle gate(CreateEventW(nullptr, TRUE, FALSE, name.c_str()));
        Require(gate && WaitForSingleObject(gate.get(), 20000) == WAIT_OBJECT_0, "Floating edit gate timed out");
        return hypotenuse(3.0, 4.0) == (!wcscmp(arguments[1], L"skip") ? 7.25 : 9.5) ? 0 : 7;
    }

    // An invalid handle occupies one 32-bit result register.
    Require(CreateFileW(L"", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr) ==
        INVALID_HANDLE_VALUE, "Empty file name unexpectedly opened");

    // Real CRT exports exercise packed cdecl arguments, EDX:EAX integers and x87 floating-point returns.
    char* end = nullptr;
    Require(hypotenuse(3.0, 4.0) == 5.0 &&
        integer("18364758544493064720", &end, 10) == 0xFEDCBA9876543210 && end && !*end,
        "Integer or floating-point invocation changed");
    char text[128]{};
    Require(format(text, sizeof(text), "%I64u|%.2f|%Ix|%s", uint64_t{0xFEDCBA9876543210},
        3.25, size_t{0xABC}, "tail") == 34 && !strcmp(text, "18364758544493064720|3.25|abc|tail"),
        "Mixed variadic arguments changed");
    Require(Positional(positional, text, sizeof(text), "%3$s|%1$I64u|%2$.2f", uint64_t{0xFEDCBA9876543210},
        3.25, "tail") == 30 && !strcmp(text, "tail|18364758544493064720|3.25"),
        "Positional variadic arguments changed");
    uint64_t large = 0;
    double floating = 0;
    unsigned narrowValue = 0;
    Require(scan("18364758544493064720|3.25|abc", "%I64u|%lf|%x", &large, &floating, &narrowValue) == 3 &&
        large == 0xFEDCBA9876543210 && floating == 3.25 && narrowValue == 0xABC, "Scanned outputs changed");
    std::puts("PASS: x86 CRT integers, floating-point values and variadic arguments.");
    return 0;
}

void Instructions(const Context& context)
{
    Require(RunTarget(context).contains("PASS:"), "x86 instruction workload baseline failed");
    Capture::Run(context, {.limit = 128, .instructions = true}, [&](Capture& capture)
    {
        auto files = capture.Find("CreateFileW");
        Require(std::ranges::any_of(files, [](const Json& row)
        {
            auto result = row.at("result").get<uint32_t>();
            return result == UINT32_MAX && (row.at("flags").get<uint32_t>() & Detourist::Failed) &&
                Detourist::PublicFailure(Detourist::Api::CreateFileW, result);
        }), "A 32-bit invalid file handle was not recorded as a failed call", files);
        auto floating = Only(capture.Find("_hypot", "msvcrt.dll"));
        auto integer = Only(capture.Find("_strtoui64", "msvcrt.dll"));
        Require(floating["result"].get<uint64_t>() == std::bit_cast<uint64_t>(5.0) &&
                    integer["result"].get<uint64_t>() == 0xFEDCBA9876543210,
            "Native return registers were decoded incorrectly");
        auto format = Only(capture.Find("sprintf_s", "msvcrt.dll"));
        auto positions = Only(capture.Find("__stdio_common_vsprintf_p", "ucrtbase.dll"));
        auto args = Data(format["arguments"]);
        auto positional = Regions(positions["input"], {.parameter = 5, .kind = 2});
        Require(Read<uint64_t>(args, 3 * 8) == 0xFEDCBA9876543210 && Read<double>(args, 4 * 8) == 3.25 &&
            Read<uint64_t>(args, 5 * 8) == 0xABC &&
            std::ranges::any_of(positional, [](const auto& value)
            { return value.data.size() == 8 && Read<uint64_t>(value.data) == 0xFEDCBA9876543210; }) &&
            std::ranges::any_of(positional, [](const auto& value)
            { return value.data.size() == 8 && Read<double>(value.data) == 3.25; }),
            "Packed or positional variadic values were not normalized", {format, positions});
        auto scanned = Only(capture.Find("sscanf_s", "msvcrt.dll"));
        Require(Read<uint64_t>(Only(Snapshots(scanned["output"], 2, 0))) == 0xFEDCBA9876543210 &&
            Read<double>(Only(Snapshots(scanned["output"], 3, 0))) == 3.25,
            "Native scanf pointer widths lost completed outputs", scanned);
        capture.CheckDiagnostics(true);
    });

    // A breakpoint must update ST(0), including a skipped call that has no existing floating-point return value.
    for (bool skip : {false, true})
    {
        Collector collector(context.collector, context.directory);
        auto database = Launch(collector, context, {.arguments = skip ? L"skip" : L"edited", .instructions = true});
        collector.Wait([](const Json& state) { return state["capturing"] == true; });
        auto page = collector.Call("page", {{"database", Text(database)}, {"limit", 1}});
        auto pid = Only(page["targets"])["pid"].get<DWORD>();
        auto name = L"Local\\Detourist.X86.Float." + std::to_wstring(pid);
        Detourist::Handle gate;
        collector.Wait(
            [&](const Json&)
            {
                gate.reset(OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str()));
                return !!gate;
            });
        collector.Call("page", {{"database", Text(database)}, {"limit", 1}});
        auto api = Only(
            Query(database, "SELECT id FROM apis WHERE target<>0 AND module='msvcrt.dll' AND name='_hypot'"))["id"];
        collector.Call("breakApi", {{skip ? "entryApi" : "exitApi", api}});
        Require(SetEvent(gate.get()) != FALSE, "Release floating-point fixture");
        auto stopped = collector.Wait([](const Json& state) { return state["breakpoint"] == true; });
        Require(stopped["stoppedCall"]["name"] == "_hypot", "Floating-point breakpoint selected a different API");
        collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
        collector.Call("continue", {{"skip", skip}, {"result", std::bit_cast<uint64_t>(skip ? 7.25 : 9.5)}});
        auto ended = collector.Wait([](const Json& state) { return state["finished"] == true; });
        Require(!ended["message"].get<std::string>().contains("nonzero exit code"),
            "Floating-point edit or skip did not reach the application", ended);
        collector.Close();
    }
}

int wmain(int argc, wchar_t** argv) { return Run(argc, argv, Instructions, TargetMain); }

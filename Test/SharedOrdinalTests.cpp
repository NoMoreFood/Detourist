#include "TestSupport.h"
#include "Protocol.h"

using namespace Detourist;
using namespace Detourist::Tests;

extern "C" __declspec(dllimport) BOOL WINAPI OrdinalTextExtent(HDC, LPCWSTR, UINT, LPSIZE);
extern "C" __declspec(dllimport) BOOL WINAPI OrdinalUnregisterClass(DWORD);
extern "C" __declspec(dllimport) void WINAPI OrdinalDisconnectWindowDialog(HWND);
extern "C" __declspec(dllimport) BOOL WINAPI OrdinalDavCompliance(LPCSTR, LPCSTR, LPBOOL, HWND, LPVOID);
extern "C" __declspec(dllimport) BOOL WINAPI OrdinalProfilesEnabled();
extern "C" __declspec(dllimport) DWORD WINAPI OrdinalMapPolicy(void*, char*, ULONG, void*);
extern "C" __declspec(dllimport) DWORD WINAPI OrdinalGetPolicy(const char*, HANDLE, const char*, void*);
extern "C" __declspec(dllimport) DWORD WINAPI OrdinalFreePolicy(void*);
extern "C" __declspec(dllimport) DWORD WINAPI OrdinalPolicyStatus(void*);

// Small native import callers retain an unambiguous IAT call even when control-flow protection uses a register.
#define SHARED_IMPORT(type, name, parameters, arguments) \
__declspec(noinline) type WINAPI Imported##name parameters \
{ volatile auto result = Ordinal##name arguments; return result; }
SHARED_IMPORT(BOOL, TextExtent, (HDC dc, LPCWSTR text, UINT length, LPSIZE size), (dc, text, length, size))
SHARED_IMPORT(BOOL, UnregisterClass, (DWORD unused), (unused))
SHARED_IMPORT(BOOL, DavCompliance, (LPCSTR url, LPCSTR token, LPBOOL found, HWND window, LPVOID context),
    (url, token, found, window, context))
SHARED_IMPORT(BOOL, ProfilesEnabled, (), ())
SHARED_IMPORT(DWORD, MapPolicy, (void* resource, char* policy, ULONG length, void* signal),
    (resource, policy, length, signal))
SHARED_IMPORT(DWORD, GetPolicy, (const char* url, HANDLE destination, const char* transform, void* signal),
    (url, destination, transform, signal))
SHARED_IMPORT(DWORD, FreePolicy, (void* object), (object))
SHARED_IMPORT(DWORD, PolicyStatus, (void* object), (object))
#undef SHARED_IMPORT

__declspec(noinline) void WINAPI ImportedDisconnectWindowDialog(HWND window)
{
    OrdinalDisconnectWindowDialog(window);
    MemoryBarrier();
}

void CALLBACK CancelDialog(HWND window, UINT, UINT_PTR timer, DWORD)
{
    KillTimer(window, timer);
    PostMessageW(window, WM_COMMAND, IDCANCEL, 0);
}

LRESULT CALLBACK ObserveDialog(int code, WPARAM first, LPARAM second)
{
    // Cancel only dialogs on the fixture thread's private desktop after their initialization completes.
    if (code == HCBT_ACTIVATE)
    {
        const auto window = reinterpret_cast<HWND>(first);
        wchar_t type[32]{};
        GetClassNameW(window, type, 32);
        if (!wcscmp(type, L"#32770")) SetTimer(window, 0xD371, 1, CancelDialog);
    }
    return CallNextHookEx(nullptr, code, first, second);
}

void DisconnectDialog(bool dynamic)
{
    // Exercise the installed ordinal without exposing a modal dialog on the user's desktop.
    auto name = L"Detourist.Disconnect." + std::to_wstring(GetCurrentProcessId());
    auto desktop = CreateDesktopW(name.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    Require(desktop != nullptr, "Create disconnect dialog desktop");
    bool completed = false;
    std::thread worker([&]()
    {
        if (!SetThreadDesktop(desktop)) return;
        auto hook = SetWindowsHookExW(WH_CBT, ObserveDialog, nullptr, GetCurrentThreadId());
        if (!hook) return;
        auto address = dynamic ? reinterpret_cast<decltype(&OrdinalDisconnectWindowDialog)>(
            GetProcAddress(GetModuleHandleW(L"shell32.dll"), MAKEINTRESOURCEA(254))) :
            &ImportedDisconnectWindowDialog;
        if (address)
        {
            address(nullptr);
            completed = true;
        }
        UnhookWindowsHookEx(hook);
    });
    worker.join();
    CloseDesktop(desktop);
    Require(completed, "Complete disconnect dialog ordinal");
}

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 2) return 1;
    try
    {
        Json calls = Json::array();
        auto sample = [&](const char* module, const char* name, uint32_t parameters, DWORD result, bool failed,
            bool dynamic)
        {
            calls.push_back({{"module", module}, {"name", name}, {"count", parameters}, {"result", result},
                {"failed", failed}, {"dynamic", dynamic}});
        };
        auto lookup = [](const wchar_t* library, WORD ordinal, auto imported)
        {
            auto module = GetModuleHandleW(library);
            auto address = module ? GetProcAddress(module, MAKEINTRESOURCEA(ordinal)) : nullptr;
            Require(address != nullptr, "Resolve shared ordinal");
            return reinterpret_cast<decltype(imported)>(address);
        };

        // Exercise immutable ordinal imports and independently resolved pointers to folded implementations.
        for (bool dynamic : {false, true})
        {
            DisconnectDialog(dynamic);
            sample("shell32.dll", "DisconnectWindowDialog", 1, 0, false, dynamic);
            calls.back()["void"] = true;
            auto text = dynamic ? lookup(L"comctl32.dll", 420, &OrdinalTextExtent) : &ImportedTextExtent;
            auto dc = CreateCompatibleDC(nullptr);
            Require(dc != nullptr, "Create text measurement context");
            const wchar_t message[] = L"Ordinal \u6f22\u5b57";
            SIZE size{}, reference{};
            auto result = text(dc, message, static_cast<UINT>(wcslen(message)), &size);
            Require(GetTextExtentPointW(dc, message, static_cast<int>(wcslen(message)), &reference) &&
                result && size.cx == reference.cx && size.cy == reference.cy, "Preserve Unicode ordinal extent");
            DeleteDC(dc);
            sample("comctl32.dll", "GetTextExtentPoint32Wrap", 4, result, !result, dynamic);
            calls.back()["size"] = {size.cx, size.cy};
            auto unregister = dynamic ? lookup(L"shell32.dll", 259, &OrdinalUnregisterClass) : &ImportedUnregisterClass;
            result = unregister(0);
            sample("shell32.dll", "LinkWindow_UnregisterClass", 1, result, !result, dynamic);
            auto profiles = dynamic ? lookup(L"wininet.dll", 112, &OrdinalProfilesEnabled) : &ImportedProfilesEnabled;
            result = profiles();
            sample("wininet.dll", "IsProfilesEnabled", 0, result, !result, dynamic);
            auto dav = dynamic ? lookup(L"wininet.dll", 104, &OrdinalDavCompliance) : &ImportedDavCompliance;
            BOOL found = FALSE;
            result = dav("http://127.0.0.1:65534/shared-ordinal", "ordinal-token", &found, nullptr, nullptr);
            sample("wininet.dll", "HttpCheckDavComplianceA", 5, result, !result, dynamic);
            auto map = dynamic ? lookup(L"wininet.dll", 120, &OrdinalMapPolicy) : &ImportedMapPolicy;
            result = map(nullptr, nullptr, 0, nullptr);
            sample("wininet.dll", "MapResourceToPolicy", 4, result, result != 0, dynamic);
            auto policy = dynamic ? lookup(L"wininet.dll", 121, &OrdinalGetPolicy) : &ImportedGetPolicy;
            result = policy(nullptr, nullptr, nullptr, nullptr);
            sample("wininet.dll", "GetP3PPolicy", 4, result, result != 0, dynamic);
            auto release = dynamic ? lookup(L"wininet.dll", 122, &OrdinalFreePolicy) : &ImportedFreePolicy;
            result = release(nullptr);
            sample("wininet.dll", "FreeP3PObject", 1, result, result != 0, dynamic);
            auto status = dynamic ? lookup(L"wininet.dll", 123, &OrdinalPolicyStatus) : &ImportedPolicyStatus;
            result = status(nullptr);
            sample("wininet.dll", "GetP3PRequestStatus", 1, result, result != 0, dynamic);
        }
        WriteJson(arguments[1], {{"calls", calls}});
        return 0;
    }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}

void SharedOrdinals(const Context& context)
{
    auto report = context.directory / L"shared-ordinals.json";
    auto arguments = Quote(report);
    RunTarget(context, arguments);
    auto baseline = Report(report);
    for (bool instructions : {false, true})
    {
        Capture::Run(context, {.arguments = arguments, .limit = 128, .instructions = instructions},
        [&](Capture& capture)
        {
            auto expected = Report(report);
            CompareCalls(baseline, expected, {"module", "name", "result", "failed"});
            auto rows = TargetCalls(context, capture.database);
            for (const auto& sample : expected["calls"])
            {
                if (sample["dynamic"] == true) continue;
                auto matches = Select(rows, [&](const Json& row)
                { return row["name"] == sample["name"] && row["module"] == sample["module"]; });
                const auto shared = sample["name"] != "DisconnectWindowDialog";
                Require(matches.size() == (instructions && shared ? 1u : 2u),
                    "Identify shared ordinal independently", matches);
                for (const auto& row : matches)
                {
                    auto flags = row["flags"].get<uint32_t>();
                    Require(row["argument_count"] == sample["count"] && !(flags & RawArguments) &&
                        (sample.value("void", false) || (Number(row["result"]) & UINT32_MAX) == sample["result"]) &&
                        bool(flags & Detourist::Failed) == sample["failed"], "Preserve shared ordinal contract", row);
                    CheckLimit(row, 128);
                    if (sample["name"] == "GetTextExtentPoint32Wrap")
                    {
                        auto extent = Only(Regions(row["output"], {.parameter = 3}));
                        Require(extent.data.size() == sizeof(SIZE) && Read<LONG>(extent.data) == sample["size"][0] &&
                            Read<LONG>(extent.data, sizeof(LONG)) == sample["size"][1],
                            "Capture ordinal text extent output", row);
                    }
                }
            }
            if (instructions)
            {
                auto raw = Select(rows, [](const Json& row)
                { return (row["module"] == "comctl32.dll" || row["module"] == "shell32.dll" ||
                    row["module"] == "wininet.dll") &&
                    row["name"].get<std::string>().starts_with("Shared export RVA"); });
                Require(raw.size() == 8 && std::ranges::all_of(raw, [](const Json& row)
                { return (row["flags"].get<uint32_t>() & RawArguments) != 0; }),
                    "Unidentified shared pointers must retain raw capture", raw);
            }
        }, 90);
    }
}

int wmain(int argc, wchar_t** argv) { return Run(argc, argv, SharedOrdinals, TargetMain); }

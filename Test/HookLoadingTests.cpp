#include "WinSupport.h"
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>
#ifdef DETOURIST_DELAY_IMPORT
#include <delayimp.h>
#endif

using namespace Detourist;

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) return 1;
    auto report = std::filesystem::path(argv[1]) / (std::to_wstring(GetCurrentProcessId()) + L".txt");
    std::ofstream output(report);
    output << sizeof(void*) << '\n';
    wchar_t system[MAX_PATH]{};
    if (!GetSystemDirectoryW(system, MAX_PATH)) return 2;
    auto filename = std::wstring(system) + L"\\kernel32.dll";
    auto missing = std::wstring(argv[1]) + L"\\missing-version-file.dll";
    auto ansi = std::filesystem::path(filename).string(), missingAnsi = std::filesystem::path(missing).string();
    auto directoryAnsi = std::filesystem::path(argv[1]).string();

    // Observe the first call after resolution and after unload/reload, including the caller's error result.
    for (unsigned pass = 0; pass < 2; ++pass)
    {
#ifdef DETOURIST_DYNAMIC_IMPORT
        auto module = LoadLibraryW(L"advapi32.dll");
        if (!module) return 3;
        auto open = reinterpret_cast<decltype(&RegOpenKeyExW)>(GetProcAddress(module, "RegOpenKeyExW"));
        auto query = reinterpret_cast<decltype(&RegQueryValueExW)>(GetProcAddress(module, "RegQueryValueExW"));
        auto close = reinterpret_cast<decltype(&RegCloseKey)>(GetProcAddress(module, "RegCloseKey"));
        if (!open || !query || !close) return 4;
#else
        auto open = &RegOpenKeyExW;
        auto query = &RegQueryValueExW;
        auto close = &RegCloseKey;
#endif
        HKEY key = nullptr;
        if (open(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
            KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return 5;
        DWORD type = 0, bytes = 0;
        auto result = query(key, L"ProductName", nullptr, &type, nullptr, &bytes);
        SetLastError(ERROR_INVALID_FUNCTION);
        auto failed = query(key, L"Detourist-missing-value", nullptr, nullptr, nullptr, nullptr);
        auto lastError = GetLastError();
        close(key);
        if (result || type != REG_SZ || !bytes || failed != ERROR_FILE_NOT_FOUND) return 6;
        output << type << ' ' << bytes << ' ' << failed << ' ' << lastError << '\n';
#ifdef DETOURIST_DYNAMIC_IMPORT
        if (!FreeLibrary(module)) return 7;
#elif defined(DETOURIST_DELAY_IMPORT)
        if (!__FUnloadDelayLoadedDLL2("ADVAPI32.dll")) return 7;
#endif

        // Each version contract must preserve the x86 stack, return value, error and output data.
#ifdef DETOURIST_DYNAMIC_IMPORT
        auto version = LoadLibraryW(L"version.dll");
        if (!version) return 12;
#define VERSION_API(name) \
        auto name##Call = reinterpret_cast<decltype(&name)>(GetProcAddress(version, #name)); \
        if (!name##Call) return 13;
#else
#define VERSION_API(name) auto name##Call = &name;
#endif
        VERSION_API(GetFileVersionInfoSizeA)
        VERSION_API(GetFileVersionInfoSizeW)
        VERSION_API(GetFileVersionInfoSizeExW)
        VERSION_API(GetFileVersionInfoA)
        VERSION_API(GetFileVersionInfoW)
        VERSION_API(GetFileVersionInfoExW)
        VERSION_API(VerQueryValueA)
        VERSION_API(VerQueryValueW)
        VERSION_API(VerFindFileA)
        VERSION_API(VerFindFileW)
        VERSION_API(VerInstallFileA)
        VERSION_API(VerInstallFileW)
#undef VERSION_API
        auto observe = [&](const char* name, auto invoke)
        {
            SetLastError(ERROR_INVALID_FUNCTION);
            auto value = invoke();
            auto error = GetLastError();
            output << "version " << name << ' ' << value << ' ' << error << '\n';
            return value;
        };
        DWORD handle = MAXDWORD, maximum = 0;
        for (bool exists : {true, false})
        {
            auto path = exists ? filename.c_str() : missing.c_str();
            auto pathAnsi = exists ? ansi.c_str() : missingAnsi.c_str();
            DWORD sizes[]{
                observe("GetFileVersionInfoSizeA", [&]() { return GetFileVersionInfoSizeACall(pathAnsi, &handle); }),
                observe("GetFileVersionInfoSizeW", [&]() { return GetFileVersionInfoSizeWCall(path, &handle); }),
                observe("GetFileVersionInfoSizeExW", [&]()
                { return GetFileVersionInfoSizeExWCall(FILE_VER_GET_NEUTRAL, path, &handle); }),
                observe("GetFileVersionInfoSizeExA", [&]()
                {
                    // The SDK import library omits the ANSI extended exports; resolve their declared ABI by name.
                    auto function = reinterpret_cast<decltype(&GetFileVersionInfoSizeExA)>(
                        GetProcAddress(GetModuleHandleW(L"version.dll"), "GetFileVersionInfoSizeExA"));
                    return function ? function(FILE_VER_GET_NEUTRAL, pathAnsi, &handle) : 0;
                })};
            for (auto size : sizes)
            {
                if (exists != (size != 0)) return 14;
                maximum = (std::max)(maximum, size);
            }
        }
        std::vector<BYTE> data(maximum);
        auto infoExA = reinterpret_cast<decltype(&GetFileVersionInfoExA)>(
            GetProcAddress(GetModuleHandleW(L"version.dll"), "GetFileVersionInfoExA"));
        if (!infoExA) return 13;
        for (bool exists : {true, false})
        {
            auto path = exists ? filename.c_str() : missing.c_str();
            auto pathAnsi = exists ? ansi.c_str() : missingAnsi.c_str();
            BOOL results[]{
                observe("GetFileVersionInfoA", [&]()
                { return GetFileVersionInfoACall(pathAnsi, 0, maximum, data.data()); }),
                observe("GetFileVersionInfoW", [&]()
                { return GetFileVersionInfoWCall(path, 0, maximum, data.data()); }),
                observe("GetFileVersionInfoExA", [&]()
                { return infoExA(FILE_VER_GET_NEUTRAL, pathAnsi, 0, maximum, data.data()); }),
                observe("GetFileVersionInfoExW", [&]()
                { return GetFileVersionInfoExWCall(FILE_VER_GET_NEUTRAL, path, 0, maximum, data.data()); })};
            for (auto loaded : results) if (exists != (loaded != FALSE)) return 15;
            if (!exists) continue;
            for (bool wide : {false, true})
            {
                void* value = nullptr;
                UINT length = 0;
                auto queried = wide ? observe("VerQueryValueW", [&]()
                    { return VerQueryValueWCall(data.data(), L"\\", &value, &length); }) :
                    observe("VerQueryValueA", [&]()
                    { return VerQueryValueACall(data.data(), "\\", &value, &length); });
                if (!queried || !value || length != sizeof(VS_FIXEDFILEINFO)) return 16;
                auto info = static_cast<const VS_FIXEDFILEINFO*>(value);
                if (info->dwSignature != VS_FFI_SIGNATURE || !info->dwFileVersionMS) return 17;
                output << "data " << length << ' ' << info->dwFileVersionMS << ' ' << info->dwFileVersionLS << '\n';
            }
        }

        // Handle-based version reads allocate storage even on some failures; the caller owns that storage.
        using VersionByHandle = BOOL (WINAPI*)(DWORD, HANDLE, LPVOID*, PDWORD);
        auto byHandle = reinterpret_cast<VersionByHandle>(
            GetProcAddress(GetModuleHandleW(L"version.dll"), "GetFileVersionInfoByHandle"));
        Handle file(CreateFileW(filename.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr));
        if (!byHandle || !file) return 19;
        for (bool valid : {true, false})
        {
            void* resource = nullptr;
            DWORD length = 0;
            auto read = observe("GetFileVersionInfoByHandle", [&]()
            { return byHandle(FILE_VER_GET_NEUTRAL, valid ? file.get() : INVALID_HANDLE_VALUE, &resource, &length); });
            auto release = [](void* memory) { if (memory) LocalFree(memory); };
            std::unique_ptr<void, decltype(release)> allocation(resource, release);
            if (valid != (read != FALSE) || (valid && (!resource || !length))) return 20;
            if (!valid) continue;
            void* value = nullptr;
            UINT valueBytes = 0;
            if (!observe("VerQueryValueW", [&]()
                { return VerQueryValueWCall(resource, L"\\", &value, &valueBytes); }) ||
                !value || valueBytes != sizeof(VS_FIXEDFILEINFO)) return 21;
            auto info = static_cast<const VS_FIXEDFILEINFO*>(value);
            if (info->dwSignature != VS_FFI_SIGNATURE || !info->dwFileVersionMS) return 22;
            output << "data " << length << ' ' << info->dwFileVersionMS << ' ' << info->dwFileVersionLS << '\n';
        }

        // Eight-argument contracts run against missing files confined to this fixture's temporary directory.
        char currentAnsi[MAX_PATH]{}, destinationAnsi[MAX_PATH]{};
        wchar_t current[MAX_PATH]{}, destination[MAX_PATH]{};
        UINT currentLength = MAX_PATH, destinationLength = MAX_PATH;
        if (observe("VerFindFileA", [&]()
            { return VerFindFileACall(0, "missing-version-file.dll", directoryAnsi.c_str(), directoryAnsi.c_str(),
                currentAnsi, &currentLength, destinationAnsi, &destinationLength); }) & VFF_BUFFTOOSMALL) return 23;
        currentLength = destinationLength = MAX_PATH;
        if (observe("VerFindFileW", [&]()
            { return VerFindFileWCall(0, L"missing-version-file.dll", argv[1], argv[1],
                current, &currentLength, destination, &destinationLength); }) & VFF_BUFFTOOSMALL) return 23;
        currentLength = MAX_PATH;
        if (!(observe("VerInstallFileA", [&]()
            { return VerInstallFileACall(0, "missing-version-file.dll", "missing-destination.dll",
                directoryAnsi.c_str(), directoryAnsi.c_str(), directoryAnsi.c_str(), currentAnsi, &currentLength); }) &
                VIF_CANNOTREADSRC)) return 24;
        currentLength = MAX_PATH;
        if (!(observe("VerInstallFileW", [&]()
            { return VerInstallFileWCall(0, L"missing-version-file.dll", L"missing-destination.dll",
                argv[1], argv[1], argv[1], current, &currentLength); }) & VIF_CANNOTREADSRC)) return 24;
#ifdef DETOURIST_DYNAMIC_IMPORT
        if (!FreeLibrary(version)) return 18;
#elif defined(DETOURIST_DELAY_IMPORT)
        if (!__FUnloadDelayLoadedDLL2("VERSION.dll")) return 18;
#endif
    }
    output.close();
    if (!output) return 8;
    if (argc == 2) return 0;

    // Every generation must retain the caller's suspension until its parent explicitly resumes it.
    auto command = L"\"" + std::wstring(argv[2]) + L"\" \"" + argv[1] + L"\"";
    for (int index = 3; index < argc; ++index) command += L" \"" + std::wstring(argv[index]) + L"\"";
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(argv[2], command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &child)) return 9;
    Handle process(child.hProcess), thread(child.hThread);
    if (ResumeThread(thread.get()) != 1 || WaitForSingleObject(process.get(), 60000) != WAIT_OBJECT_0)
    {
        TerminateProcess(process.get(), ERROR_TIMEOUT);
        return 10;
    }
    DWORD code = 0;
    return GetExitCodeProcess(process.get(), &code) ? static_cast<int>(code) : 11;
}

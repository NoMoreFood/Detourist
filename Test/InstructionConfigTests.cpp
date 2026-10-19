#include "WinSupport.h"
#pragma warning(push, 0)
#include "dr_defines.h"
#include "dr_config.h"
#pragma warning(pop)
#include <iostream>
#include <memory>

using namespace Detourist;

void Require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

int wmain(int argc, wchar_t* argv[])
{
    try
    {
        const auto root = ModuleDirectory() + L"\\instruction";
        const auto path = argc == 2 ? std::wstring(argv[1]) :
            root + L"\\bin" + std::to_wstring(sizeof(void*) * 8) + L"\\drconfiglib.dll";
        std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)> library(
            LoadLibraryExW(path.c_str(), nullptr,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS), &FreeLibrary);
        Require(static_cast<bool>(library), "Cannot load instruction configuration library.");
        auto registerProcess = reinterpret_cast<decltype(&dr_register_process)>(
            GetProcAddress(library.get(), "dr_register_process"));
        auto unregisterProcess = reinterpret_cast<decltype(&dr_unregister_process)>(
            GetProcAddress(library.get(), "dr_unregister_process"));
        auto registerClient = reinterpret_cast<decltype(&dr_register_client)>(
            GetProcAddress(library.get(), "dr_register_client"));
        auto readClient = reinterpret_cast<decltype(&dr_get_client_info)>(
            GetProcAddress(library.get(), "dr_get_client_info"));
        Require(registerProcess && unregisterProcess && registerClient && readClient,
            "Instruction configuration exports are missing.");

        // Use only this test's unique process-name/PID registration; no application is started or configured.
        auto name = "DetouristConfigTest-" + std::to_string(GetCurrentProcessId()) + "-" +
            std::to_string(GetTickCount64()) + ".exe";
        const auto platform = sizeof(void*) == 8 ? DR_PLATFORM_64BIT : DR_PLATFORM_32BIT;
        auto pid = GetCurrentProcessId();
        Require(registerProcess(name.c_str(), pid, false, Utf8(root).c_str(), DR_MODE_CODE_MANIPULATION,
            false, platform, "") == DR_SUCCESS, "Cannot register instruction configuration fixture.");
        auto remove = [&](const char*) { unregisterProcess(name.c_str(), pid, false, platform); };
        std::unique_ptr<const char, decltype(remove)> registration(name.c_str(), remove);
        struct Scenario { const char* path; const char* options; bool valid; };
        const Scenario scenarios[]{
            {R"(C:\capture client\observer.dll)", R"(268 99 "C:\metadata path\syscalls.txt")", true},
            {R"(C:\O'Brien\observer.dll)", R"(268 99 "C:\metadata path\syscalls.txt")", true},
            {R"(C:\back`tick\observer.dll)", R"(268 99 "C:\metadata path\syscalls.txt")", true},
            {R"(C:\capture client\observer.dll)", R"(268 99 'C:\metadata path\syscalls.txt')", true},
            {R"(C:\capture;client\observer.dll)", "268 99", false},
            {R"(C:\capture client\observer.dll)", "268;99", false},
            {R"(C:\O'Brien\observer.dll)", R"(268 99 "C:\back`tick\syscalls.txt")", false}};
        size_t priority = 0;
        client_id_t id = 0;
        for (const auto& scenario : scenarios)
        {
            const auto status = registerClient(name.c_str(), pid, false, platform, ++id, priority,
                scenario.path, scenario.options);
            Require(status == (scenario.valid ? DR_SUCCESS : DR_CONFIG_OPTIONS_INVALID),
                "Instruction configuration accepted invalid delimiters or rejected a representable path.");
            if (!scenario.valid) continue;
            char clientPath[MAXIMUM_PATH]{}, clientOptions[DR_MAX_OPTIONS_LENGTH]{};
            size_t storedPriority = SIZE_MAX;
            Require(readClient(name.c_str(), pid, false, platform, id, &storedPriority, clientPath,
                clientOptions) == DR_SUCCESS && storedPriority == priority &&
                clientPath == std::string(scenario.path) && clientOptions == std::string(scenario.options),
                "Instruction client arguments changed in registration.");
            ++priority;
        }
        Require(unregisterProcess(name.c_str(), pid, false, platform) == DR_SUCCESS,
            "Cannot remove instruction configuration fixture.");
        registration.release();
        std::cout << "PASS: instruction client paths, argument quoting and invalid-delimiter rejection.\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}

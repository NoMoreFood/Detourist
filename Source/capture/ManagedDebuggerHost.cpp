#include "ManagedAttach.h"
#include <filesystem>
#include <cwchar>
#include <objbase.h>

int wmain(int count, wchar_t** arguments)
{
    using namespace Detourist;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    if (count != 5) return ERROR_INVALID_PARAMETER;
    auto processId = static_cast<DWORD>(wcstoul(arguments[1], nullptr, 10));
    Transport transport;
    if (!processId) return ERROR_INVALID_PARAMETER;
    const std::wstring name = arguments[2];
    if (!transport.Open(name, processId)) return GetLastError();
    Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, (name + L".managed.ready").c_str()));
    Handle stop(OpenEventW(SYNCHRONIZE, FALSE, (name + L".managed.stop").c_str()));
    Handle process(OpenProcess(SYNCHRONIZE, FALSE, processId));
    if (!ready || !stop || !process) return ERROR_INVALID_HANDLE;

    // Keep legacy runtime selection local to this observer process.
    bool legacy = !wcscmp(arguments[4], L"legacy");
    if (legacy)
    {
        auto directory = std::filesystem::path(arguments[3]).parent_path();
        SetEnvironmentVariableW(L"COMPLUS_InstallRoot", directory.parent_path().c_str());
        SetEnvironmentVariableW(L"COMPLUS_Version", L"v2.0.50727");
    }
    auto result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(result)) return static_cast<int>(result);
    try
    {
        auto debugger = AttachManagedDebugger(processId, transport, arguments[3], legacy, result);
        if (debugger)
        {
            SetEvent(ready.get());
            HANDLE events[]{stop.get(), process.get()};
            while (!transport.Header()->stop && transport.CollectorAlive() &&
                WaitForMultipleObjects(2, events, FALSE, 20) == WAIT_TIMEOUT) debugger->Refresh();
            result = debugger->Shutdown();
            if (WaitForSingleObject(process.get(), 0) == WAIT_OBJECT_0) result = S_OK;
        }
    }
    catch (...) { result = E_FAIL; }
    CoUninitialize();
    return static_cast<int>(result);
}

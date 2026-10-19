#include "WinSupport.h"
#include <mscoree.h>
#include <wrl/client.h>
#include <filesystem>
#include <cstdio>

int wmain(int count, wchar_t** arguments)
{
    if (count != 4 && count != 5) return 2;

    // Bind the isolated legacy runtime to its own framework directory.
    auto directory = std::filesystem::absolute(arguments[1]);
    SetEnvironmentVariableW(L"COMPLUS_InstallRoot", directory.parent_path().c_str());
    SetEnvironmentVariableW(L"COMPLUS_Version", L"v2.0.50727");
    auto module = LoadLibraryExW((directory / L"mscorwks.dll").c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    auto create = module ? reinterpret_cast<HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**)>(
        GetProcAddress(module, "DllGetClassObjectInternal")) : nullptr;
    if (!create) return 3;

    // Start the actual CLR 2 host rather than substituting a modern runtime for the fixture.
    Microsoft::WRL::ComPtr<IClassFactory> factory;
    auto result = create(CLSID_CLRRuntimeHost, IID_IClassFactory, reinterpret_cast<void**>(factory.GetAddressOf()));
    Microsoft::WRL::ComPtr<ICLRRuntimeHost> host;
    if (SUCCEEDED(result)) result = factory->CreateInstance(nullptr, IID_ICLRRuntimeHost,
        reinterpret_cast<void**>(host.GetAddressOf()));
    if (SUCCEEDED(result)) result = host->Start();
    DWORD code = 0;
    auto entry = count == 4 ? L"Execute" : !wcscmp(arguments[4], L"--attach-smoke") ?
        L"ExecuteAttachSmoke" : !wcscmp(arguments[4], L"--layouts") ? L"ExecuteLayouts" :
        !wcscmp(arguments[4], L"--layouts-lifecycle") ? L"ExecuteLayoutLifecycle" :
        !wcscmp(arguments[4], L"--arrays") ? L"ExecuteArrays" :
        !wcscmp(arguments[4], L"--arrays-debugger") ? L"ExecuteArraysDebugger" :
        !wcscmp(arguments[4], L"--arrays-debugger-copy") ? L"ExecuteArraysDebuggerCopy" :
        !wcscmp(arguments[4], L"--arrays-debugger-generic") ? L"ExecuteArraysDebuggerGeneric" :
        !wcscmp(arguments[4], L"--native-boundary") ?
        L"ExecuteNativeBoundary" : !wcscmp(arguments[4], L"--raw-native") ? L"ExecuteRawNative" : L"ExecuteAttach";
    if (SUCCEEDED(result)) result = host->ExecuteInDefaultAppDomain(arguments[2], L"ManagedTarget",
        entry, arguments[3], &code);
    if (FAILED(result))
    {
        std::fwprintf(stderr, L"Legacy CLR host failed: 0x%08lx\n", static_cast<ULONG>(result));
        return 4;
    }
    host->Stop();
    return static_cast<int>(code);
}

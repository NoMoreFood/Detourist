#include "TestSupport.h"

using namespace Detourist::Tests;

VOID CALLBACK CompleteThreadpoolWork(PTP_CALLBACK_INSTANCE, PVOID context, PTP_WORK)
{
    SetEvent(static_cast<HANDLE>(context));
}

class ChannelHook final : public IChannelHook
{
    std::atomic<ULONG> references = 1;
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override
    {
        if (!object) return E_POINTER;
        *object = nullptr;
        if (iid != __uuidof(IUnknown) && iid != __uuidof(IChannelHook)) return E_NOINTERFACE;
        *object = this;
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return ++references;
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        auto remaining = --references;
        if (!remaining) delete this;
        return remaining;
    }
    __declspec(noinline) void STDMETHODCALLTYPE ClientGetSize(REFGUID, REFIID, ULONG* size) override
    {
        *size = 0;
    }
    void STDMETHODCALLTYPE ClientFillBuffer(REFGUID, REFIID, ULONG* size, void*) override
    {
        *size = 0;
    }
    void STDMETHODCALLTYPE ClientNotify(REFGUID, REFIID, ULONG, void*, DWORD, HRESULT) override
    {
    }
    void STDMETHODCALLTYPE ServerNotify(REFGUID, REFIID, ULONG, void*, DWORD) override
    {
    }
    __declspec(noinline) void STDMETHODCALLTYPE ServerGetSize(REFGUID, REFIID, HRESULT, ULONG* size) override
    {
        *size = 0;
    }
    void STDMETHODCALLTYPE ServerFillBuffer(REFGUID, REFIID, ULONG* size, void*, HRESULT) override
    {
        *size = 0;
    }
};

bool ExerciseInvalidSerialParameters()
{
    // Target exception handlers must still receive faults raised inside an observed Windows API.
    __try { BuildCommDCBAndTimeoutsW(L"", nullptr, nullptr); }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
        EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return true; }
    return false;
}

bool ExerciseExportAliases()
{
    // Independently resolved aliases preserve their own names, argument types and return values.
    auto security = GetModuleHandleW(L"advapi32.dll");
    auto narrow = reinterpret_cast<decltype(&BuildTrusteeWithNameA)>(
        GetProcAddress(security, "BuildTrusteeWithNameA"));
    auto wide = reinterpret_cast<decltype(&BuildTrusteeWithNameW)>(
        GetProcAddress(security, "BuildTrusteeWithNameW"));
    if (!narrow || !wide) return false;
    CHAR narrowName[] = "Detourist alias";
    WCHAR wideName[] = L"Detourist alias";
    TRUSTEE_A narrowTrustee{};
    TRUSTEE_W wideTrustee{};
    narrow(&narrowTrustee, narrowName);
    wide(&wideTrustee, wideName);
    if (narrowTrustee.TrusteeForm != TRUSTEE_IS_NAME || narrowTrustee.ptstrName != narrowName ||
        wideTrustee.TrusteeForm != TRUSTEE_IS_NAME || wideTrustee.ptstrName != wideName) return false;
    auto cryptography = LoadLibraryExW(L"crypt32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!cryptography) return false;
    auto duplicate = reinterpret_cast<decltype(&CertDuplicateCertificateContext)>(
        GetProcAddress(cryptography, "CertDuplicateCertificateContext"));
    auto release = reinterpret_cast<decltype(&CertFreeCertificateContext)>(
        GetProcAddress(cryptography, "CertFreeCertificateContext"));
    auto valid = duplicate && release && !duplicate(nullptr) && release(nullptr);
    FreeLibrary(cryptography);
    return valid;
}

bool ExerciseWindowCallbacks(HWND parent)
{
    // Nested window-system callbacks retain the kernel's context frame through observed control creation.
    auto module = LoadLibraryExW(L"comctl32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return false;
    auto create = reinterpret_cast<decltype(&CreateUpDownControl)>(GetProcAddress(module, "CreateUpDownControl"));
    auto control = create ? create(WS_CHILD, 0, 0, 16, 32, parent, 1, GetModuleHandleW(nullptr),
        nullptr, 10, 0, 1) : nullptr;
    auto valid = control && DestroyWindow(control);
    FreeLibrary(module);
    return valid;
}

bool ExerciseLateComOutput()
{
    // Native export resolution leaves unique COM factories visible to typed output discovery.
    auto module = LoadLibraryExW(L"ole32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return false;
    auto allocate = reinterpret_cast<decltype(&CoGetMalloc)>(GetProcAddress(module, "CoGetMalloc"));
    auto registerChannel = reinterpret_cast<decltype(&CoRegisterChannelHook)>(
        GetProcAddress(module, "CoRegisterChannelHook"));
    IMalloc* allocator = nullptr;
    bool valid = false;
    if (allocate && SUCCEEDED(allocate(1, &allocator)) && allocator)
    {
        auto memory = allocator->Alloc(64);
        valid = memory && allocator->GetSize(memory) >= 64;
        allocator->Free(memory);
        allocator->Release();
    }

    // A public name forwarded to an unnamed implementation must still record the named API and its result.
    if (valid && registerChannel)
    {
        constexpr GUID extent{0x06A3BE38, 0xFC36, 0x4017, {0xA7, 0x20, 0xD9, 0x53, 0x3F, 0xC8, 0x71, 0x51}};
        auto hook = new ChannelHook;
        valid = SUCCEEDED(registerChannel(extent, hook));
        if (valid)
        {
            // A privately constructed input interface must become observable through its SDK boundary.
            auto channel = static_cast<IChannelHook*>(hook);
            ULONG clientSize = 0x31415926, serverSize = 0x27182818;
            channel->ClientGetSize(extent, __uuidof(IUnknown), &clientSize);
            channel->ServerGetSize(extent, __uuidof(IUnknown), S_OK, &serverSize);
            valid = !clientSize && !serverSize;
        }
        hook->Release();
    }
    else valid = false;
    FreeLibrary(module);
    return valid;
}

int TargetMain()
{
    if (!ExerciseExportAliases() || !ExerciseLateComOutput()) return 34;

    // Typed Win32 observers must preserve scalar, floating-point and small aggregate arguments.
    SetLastError(0x31415926);
    auto thread = GetCurrentThreadId();
    if (!thread || GetLastError() != 0x31415926) return 1;
    RECT rectangle{0, 0, 100, 100};
    if (!PtInRect(&rectangle, POINT{25, 50})) return 2;
    auto dc = CreateCompatibleDC(nullptr);
    FLOAT previous = 0;
    FLOAT current = 0;
    if (!dc || !SetMiterLimit(dc, 10.5f, &previous) || !GetMiterLimit(dc, &current) || current != 10.5f) return 3;
    if (!DeleteDC(dc)) return 4;

    // Public jump stubs remain observable alongside their native window-system implementations.
    auto window = CreateWindowExW(0, L"STATIC", L"Detourist capture fixture", WS_POPUP,
        0, 0, 32, 32, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    PAINTSTRUCT paint{};
    if (!window || !BeginPaint(window, &paint) || !EndPaint(window, &paint) ||
        !ExerciseWindowCallbacks(window) || !DestroyWindow(window)) return 31;
    if (AttachThreadInput(thread, thread, FALSE)) return 32;
    if (!ExerciseInvalidSerialParameters()) return 33;

    // Environment strings and a registry value exercise bounded input and output snapshots.
    const auto environmentName = L"DetouristWin32Fixture";
    std::wstring environment(200, L'W');
    if (!SetEnvironmentVariableW(environmentName, environment.c_str())) return 5;
    wchar_t output[256]{};
    if (GetEnvironmentVariableW(environmentName, output, 256) != environment.size() ||
        environment != output) return 6;
    if (!SetEnvironmentVariableW(environmentName, nullptr)) return 7;

    auto keyName = "Software\\DetouristWin32-" + std::to_string(GetCurrentProcessId());
    HKEY key = nullptr;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, keyName.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
        nullptr, &key, nullptr) != ERROR_SUCCESS) return 8;
    BYTE bytes[256];
    memset(bytes, 0x5a, sizeof(bytes));
    if (RegSetValueExA(key, "Payload", 0, REG_BINARY, bytes, sizeof(bytes)) != ERROR_SUCCESS) return 9;
    DWORD length = sizeof(bytes);
    memset(bytes, 0, sizeof(bytes));
    if (RegGetValueA(key, nullptr, "Payload", RRF_RT_REG_BINARY, nullptr, bytes, &length) != ERROR_SUCCESS ||
        length != sizeof(bytes) || bytes[0] != 0x5a) return 10;
    BYTE shortValue[8]{};
    length = sizeof(shortValue);
    if (RegGetValueA(key, nullptr, "Payload", RRF_RT_REG_BINARY, nullptr, shortValue, &length) != ERROR_MORE_DATA ||
        length != sizeof(bytes)) return 11;
    RegCloseKey(key);
    if (RegDeleteKeyA(HKEY_CURRENT_USER, keyName.c_str()) != ERROR_SUCCESS) return 12;

    // ANSI file entry points and socket entry points use different failure sentinels.
    auto invalidFile = CreateFileA("?:\\Detourist-invalid-file", GENERIC_READ, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (invalidFile != INVALID_HANDLE_VALUE) return 13;
    WSADATA sockets{};
    if (WSAStartup(MAKEWORD(2, 2), &sockets)) return 14;
    auto connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connection == INVALID_SOCKET || closesocket(connection) == SOCKET_ERROR || WSACleanup()) return 15;

    // A first call after a late DLL load must be observed without waiting for a polling interval.
    auto module = LoadLibraryExW(L"bcrypt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return 16;
    auto random = reinterpret_cast<decltype(&BCryptGenRandom)>(GetProcAddress(module, "BCryptGenRandom"));
    if (!random || random(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return 17;
    if (random(nullptr, bytes, sizeof(bytes), 0x80000000) >= 0) return 18;
    FreeLibrary(module);

    // Zero can be a normal message result, while mapping and wait failures use different sentinels.
    MSG message{};
    PeekMessageW(&message, nullptr, 0, 0, PM_NOREMOVE);
    PostQuitMessage(0);
    if (GetMessageW(&message, nullptr, 0, 0) != 0) return 19;
    if (CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 0, nullptr)) return 20;
    if (WaitForSingleObject(nullptr, 0) != WAIT_FAILED) return 21;

    // Worker-factory waits must keep their complete native signature even when capture filters change.
    auto completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    auto pool = CreateThreadpool(nullptr);
    if (!completed || !pool) return 22;
    SetThreadpoolThreadMaximum(pool, 1);
    if (!SetThreadpoolThreadMinimum(pool, 1)) return 23;
    TP_CALLBACK_ENVIRON environmentBlock;
    InitializeThreadpoolEnvironment(&environmentBlock);
    SetThreadpoolCallbackPool(&environmentBlock, pool);
    auto work = CreateThreadpoolWork(CompleteThreadpoolWork, completed, &environmentBlock);
    if (!work) return 24;
    Sleep(25);
    SubmitThreadpoolWork(work);
    if (WaitForSingleObject(completed, 5000) != WAIT_OBJECT_0) return 25;
    WaitForThreadpoolWorkCallbacks(work, FALSE);
    CloseThreadpoolWork(work);
    CloseThreadpool(pool);
    DestroyThreadpoolEnvironment(&environmentBlock);
    CloseHandle(completed);

    // Native callers still consume status returns from implementations shared with void Win32 facades.
    using NativeCriticalSection = LONG (NTAPI*)(LPCRITICAL_SECTION);
    auto nativeModule = GetModuleHandleW(L"ntdll.dll");
    auto initialize = reinterpret_cast<NativeCriticalSection>(
        GetProcAddress(nativeModule, "RtlInitializeCriticalSection"));
    auto enter = reinterpret_cast<NativeCriticalSection>(GetProcAddress(nativeModule, "RtlEnterCriticalSection"));
    auto leave = reinterpret_cast<NativeCriticalSection>(GetProcAddress(nativeModule, "RtlLeaveCriticalSection"));
    auto destroy = reinterpret_cast<NativeCriticalSection>(GetProcAddress(nativeModule, "RtlDeleteCriticalSection"));
    if (!initialize || !enter || !leave || !destroy) return 26;
    for (uint32_t iteration = 0; iteration < 32; ++iteration)
    {
        CRITICAL_SECTION section{};
        if (initialize(&section) != 0 || enter(&section) != 0 || leave(&section) != 0 || destroy(&section) != 0)
            return 27;
    }

    // Direct win32u exports preserve counted strings, output structures and by-value coordinates.
    auto graphical = GetModuleHandleW(L"win32u.dll");
    using CursorPosition = ULONG (WINAPI*)(POINT*, ULONG);
    using WindowAtPoint = HWND (WINAPI*)(POINT);
    auto cursor = reinterpret_cast<CursorPosition>(GetProcAddress(graphical, "NtUserGetCursorPos"));
    auto windowAt = reinterpret_cast<WindowAtPoint>(GetProcAddress(graphical, "NtUserWindowFromPoint"));
    POINT point{};
    if (!cursor || !windowAt) return 28;
    SetLastError(0x27182818);
    auto cursorResult = cursor(&point, 1);
    auto cursorError = GetLastError();
    if (!cursorResult && cursorError != ERROR_ACCESS_DENIED) return 28;
    std::printf("Cursor result=%lu error=%lu\n", cursorResult, cursorError);
    SetLastError(0x27182818);
    auto found = windowAt(POINT{-12345, -23456});
    if (found || GetLastError() != 0x27182818) return 29;
    RECT clip{};
    if (!GetClipCursor(&clip) || clip.right <= clip.left || clip.bottom <= clip.top) return 30;

    // Policy notifications reach the Secur32 forwarder and its installed provider.
    auto security = LoadLibraryExW(L"secur32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!security) return 31;
    auto registerPolicy = reinterpret_cast<decltype(&LsaRegisterPolicyChangeNotification)>(
        GetProcAddress(security, "LsaRegisterPolicyChangeNotification"));
    auto unregisterPolicy = reinterpret_cast<decltype(&LsaUnregisterPolicyChangeNotification)>(
        GetProcAddress(security, "LsaUnregisterPolicyChangeNotification"));
    auto notification = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!registerPolicy || !unregisterPolicy || !notification)
    {
        if (notification) CloseHandle(notification);
        FreeLibrary(security);
        return 32;
    }
    registerPolicy(PolicyNotifyAccountDomainInformation, notification);
    unregisterPolicy(PolicyNotifyAccountDomainInformation, notification);
    CloseHandle(notification);
    FreeLibrary(security);
    std::puts("Win32 fixture passed.");
    return 0;
}

void Win32(const Context& context)
{
    auto baseline = RunTarget(context);
    std::smatch cursor;
    Require(std::regex_search(baseline, cursor, std::regex("Cursor result=(\\d+) error=(\\d+)")),
            "Native cursor baseline missing");
    auto cursorResult = std::stoull(cursor[1]), cursorError = std::stoull(cursor[2]);
    bool instructions = context.Has(L"--instructions");
    Collector metadata(context.collector, context.directory);
    auto hello = metadata.Call("hello");
    metadata.Close();
    Capture::Run(context, {.limit = 64, .instructions = instructions}, [&](Capture& capture)
    {
        Require(capture.status["calls"] > 0, "Win32 capture contains no calls", capture.status);
        for (const auto& target :
             capture.collector.Call("page", {{"database", Text(capture.database)}, {"limit", 1}})["targets"])
            for (auto name : {"nativeCoverage", "win32Coverage"})
            {
                auto coverage = target[name];
                Require(coverage["installed"] > 0 && coverage["installed"] <= coverage["available"] &&
                            coverage["available"] <= coverage["catalog"],
                        "Win32 API coverage differs", coverage);
            }
        auto rows = capture.Calls("a.id IS NOT NULL");
        std::map<std::string, Json> grouped;
        for (const auto& row : rows)
            grouped[row["name"].get<std::string>()].push_back(row);
        for (auto name : {"GetCurrentThreadId",
                          "PtInRect",
                          "CreateCompatibleDC",
                          "SetMiterLimit",
                          "GetMiterLimit",
                          "SetEnvironmentVariableW",
                          "GetEnvironmentVariableW",
                          "RegCreateKeyExA",
                          "RegSetValueExA",
                          "RegGetValueA",
                          "RegDeleteKeyA",
                          "CreateFileA",
                          "WSAStartup",
                          "socket",
                          "closesocket",
                          "BCryptGenRandom",
                          "GetMessageW",
                          "CreateFileMappingW",
                          "WaitForSingleObject",
                          "NtWaitForWorkViaWorkerFactory",
                          "CreateThreadpoolWork",
                          "SubmitThreadpoolWork",
                          "NtUserGetCursorPos",
                          "NtUserWindowFromPoint",
                          "NtUserGetClipCursor"})
            Require(grouped.contains(name), "Win32 API missing: " + std::string(name));
        Require(
            Query(capture.database, "SELECT message FROM diagnostics WHERE lower(message) LIKE '%exit code%'").empty(),
            "Win32 capture reported a failed process");
        Require(Read<float>(grouped.at("SetMiterLimit")[0]["arguments"], 8) == 10.5f,
                "Win32 floating argument differs");
        auto environment = Only(Regions(grouped.at("GetEnvironmentVariableW")[0]["output"], {.parameter = 1}));
        Require(environment.kind == 1 && (environment.flags & 1) &&
                    environment.data == Encode(std::string(32, 'W'), true),
                "Win32 environment output differs");
        auto registry =
            Select(grouped.at("RegGetValueA"), [](const Json& row) { return !(row["flags"].get<uint32_t>() & 1); });
        Require(!registry.empty() && Only(Regions(registry[0]["output"], {.parameter = 5})).data == Bytes(64, 'Z'),
                "Win32 registry output differs");
        auto failed = [&](const char* name)
        {
            return std::ranges::any_of(grouped.at(name),
                                       [](const Json& row) { return row["flags"].get<uint32_t>() & 1; });
        };
        Require(failed("RegGetValueA") && (grouped.at("CreateFileA")[0]["flags"].get<uint32_t>() & 1) &&
                    failed("BCryptGenRandom") && failed("CreateFileMappingW") && failed("WaitForSingleObject"),
                "Win32 failure classification differs");
        Require(std::ranges::any_of(grouped.at("BCryptGenRandom"),
                                    [](const Json& row)
        {
            auto values = Regions(row["output"], {.parameter = 1});
            return !(row["flags"].get<uint32_t>() & 1) && !values.empty() && values[0].data.size() == 64;
        }),
                "Successful Win32 random output missing");
        Require(!failed("GetMessageW"), "Win32 message result classification differs");
        auto waits = grouped.at("NtWaitForWorkViaWorkerFactory");
        Require(Only(Named(hello["catalog"], "NtWaitForWorkViaWorkerFactory"))["argumentCount"] == 5 &&
                    std::ranges::any_of(waits,
                                        [](const Json& row)
        {
            auto count = Read<uint64_t>(row["arguments"], 16);
            return count > 0 && count <= 1024;
        }),
                "Worker factory ABI differs", waits);
        for (const auto& row : waits)
            Require(uint32_t(Number(row["result"])) != 0xc0000005, "Worker wait access violation", row);
        auto point = grouped.at("NtUserWindowFromPoint").back();
        Require(Data(point["arguments"]).size() == 8 && Read<int32_t>(point["arguments"]) == -12345 &&
                    Read<int32_t>(point["arguments"], 4) == -23456,
                "Packed Win32 point argument differs", point);
        auto cursorCall = grouped.at("NtUserGetCursorPos").back();
        Require(cursorCall["result"] == cursorResult && cursorCall["error"] == cursorError,
                "Native cursor result differs", cursorCall);
        auto cursorValues = Values(cursorCall["output"]);
        Require(cursorResult ? Only(Regions(cursorValues, {.parameter = 0})).data.size() == 8 : cursorValues.empty(),
                "Native cursor output differs", cursorCall);
        Require(Only(Regions(grouped.at("NtUserGetClipCursor").back()["output"], {.parameter = 0})).data.size() == 16,
                "Native clip cursor output differs");
        if (!instructions) return;
        for (auto name : {"BeginPaint", "EndPaint", "AttachThreadInput", "CreateUpDownControl"})
            Require(grouped.contains(name), "Public window-system stub missing: " + std::string(name));
        for (auto name : {"BuildTrusteeWithNameA", "BuildTrusteeWithNameW", "CertDuplicateCertificateContext",
                          "CertFreeCertificateContext", "CoRegisterChannelHook"})
            Require(grouped[name].size() == 1, "Late Win32 export count differs: " + std::string(name));
        auto channel = grouped.at("CoRegisterChannelHook")[0];
        auto parameters = channel["parameters"].get<std::string>();
        auto identifier = Only(Regions(channel["input"], {.parameter = 0})).data;
        Require(channel["argument_count"] == 2 && parameters.contains("ExtensionUuid") &&
                    parameters.contains("pChannelHook") && identifier.size() == 16 &&
                    Read<uint32_t>(identifier) == 0x06a3be38,
                "Channel hook registration contract differs", channel);
        for (auto name : {"LsaRegisterPolicyChangeNotification", "LsaUnregisterPolicyChangeNotification"})
            Require(std::ranges::any_of(Named(capture.Calls(), name),
                                        [](const Json& row)
            {
                auto parameters = row["parameters"].get<std::string>();
                return (row["module"] == "secur32.dll" || row["module"] == "sspicli.dll") &&
                       row["argument_count"] == 2 && parameters.contains("InformationClass") &&
                       parameters.contains("NotificationEventHandle") && Data(row["arguments"]).size() == 16;
            }),
                    "Policy notification contract missing: " + std::string(name));
        auto dynamic = Query(capture.database, "SELECT a.name,c.flags,c.ended FROM calls c JOIN apis a "
                                               "ON a.target=c.target AND a.id=c.api");
        auto dispatchers = Named(dynamic, "KiUserCallbackDispatcher");
        Require(!dispatchers.empty(), "User callback dispatcher missing");
        for (const auto& row : dispatchers)
            Require((row["flags"].get<uint32_t>() & (32 | 512)) == (32 | 512) && row["ended"].is_null(),
                    "User callback dispatcher completion differs", row);
        for (auto name : {"IMalloc::Alloc", "IMalloc::GetSize", "IMalloc::Free"})
            Require(!Named(dynamic, name).empty(), "Late COM factory method missing: " + std::string(name));
        for (auto [name, parameter] :
             {std::pair{"IChannelHook::ClientGetSize", 3u}, {"IChannelHook::ServerGetSize", 4u}})
        {
            auto row = Only(Named(capture.Calls(), name));
            auto output = Only(Regions(row["output"], {.parameter = parameter}));
            Require(!(row["flags"].get<uint32_t>() & 256) && output.kind == 2 && output.data == Bytes(4),
                    "Channel hook output differs", row);
        }
    }, 40);

    // Capture filters preserve native graphical ownership and input COM discovery.
    Capture::Run(context, {.limit = 64, .instructions = instructions, .apiMask = Number(hello["win32uMask"])},
                 [](Capture& capture)
    {
        auto modules =
            Query(capture.database, "SELECT DISTINCT a.module FROM calls c JOIN apis a ON a.target=0 AND a.id=c.api");
        Require(modules == Json::array({{{"module", "win32u.dll"}}}) &&
                    Query(capture.database, "SELECT message FROM diagnostics WHERE message LIKE '%exit code%'").empty(),
                "Graphical capture filter differs", modules);
    }, 40);
    if (instructions)
        Capture::Run(context, {.limit = 64, .comOnly = true}, [](Capture& capture)
        {
            for (auto name : {"IChannelHook::ClientGetSize", "IChannelHook::ServerGetSize"})
                Require(!(Only(Named(capture.Calls(), name))["flags"].get<uint32_t>() & 256),
                        "Filtered SDK input failed to discover its COM interface");
            Require(Named(capture.Calls(), "CoRegisterChannelHook").empty(),
                    "COM discovery enabled a filtered SDK record");
        }, 40);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, Win32); }

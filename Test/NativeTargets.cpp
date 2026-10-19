#if defined(DETOURIST_TEST_DetouristTestTarget)

#include "WinSupport.h"
#include "FixtureProtocol.h"
#include <psapi.h>
#include <filesystem>
#include <thread>
#include <vector>
#include <cstdio>
#include <atomic>
#include <winternl.h>
#ifdef _DEBUG
#include <crtdbg.h>
#endif

using namespace Detourist;

void NTAPI SuspendedChildStartup(void*, DWORD reason, void*)
{
    if (reason != DLL_PROCESS_ATTACH) return;
    wchar_t name[128]{};
    if (!GetEnvironmentVariableW(L"DETOURIST_TEST_STARTUP_GATE", name, static_cast<DWORD>(std::size(name)))) return;
    auto ready = OpenEventW(SYNCHRONIZE, FALSE, name);
    if (!ready || WaitForSingleObject(ready, 0) != WAIT_OBJECT_0) ExitProcess(80);
    CloseHandle(ready);
}

// Loader callbacks must not run before a suspended child's caller finishes its startup configuration.
#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB")) const PIMAGE_TLS_CALLBACK SuspendedChildCallback = SuspendedChildStartup;
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:SuspendedChildCallback")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_SuspendedChildCallback")
#endif

bool ExceptionProbe()
{
    bool breakpoint = false;
    bool exception = false;
    __try { RaiseException(EXCEPTION_BREAKPOINT, 0, 0, nullptr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { breakpoint = true; }
    __try { RaiseException(0xE0424242, 0, 0, nullptr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { exception = true; }
    return breakpoint && exception;
}

uint32_t Workload(uint32_t iterations, bool paced = false)
{
    // Each worker uses real files so snapshots and target results can be checked together.
    std::atomic<uint32_t> errors = 0;
    wchar_t temporary[MAX_PATH];
    GetTempPathW(MAX_PATH, temporary);
    auto root = std::wstring(temporary) + L"DetouristFixture-" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(root.c_str(), nullptr);
    std::vector<std::thread> threads;
    for (int worker = 0; worker < 4; ++worker)
    {
        threads.emplace_back([&, worker]()
        {
            auto file = root + L"\\payload-" + std::to_wstring(worker) + L".bin";
            auto handle = CreateFileW(file.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle == INVALID_HANDLE_VALUE) { ++errors; return; }
            BYTE output[2048];
            for (size_t index = 0; index < sizeof(output); ++index) output[index] = static_cast<BYTE>(index);
            for (uint32_t index = 0; index < iterations; ++index)
            {
                DWORD written;
                if (!WriteFile(handle, output, sizeof(output), &written, nullptr) || written != sizeof(output))
                    ++errors;
                GetFileAttributesW(file.c_str());
                if (paced) Sleep(2);
            }
            SetFilePointer(handle, 0, nullptr, FILE_BEGIN);
            BYTE input[2048];
            DWORD read;
            if (!ReadFile(handle, input, sizeof(input), &read, nullptr) || read != sizeof(input) ||
                memcmp(input, output, sizeof(input))) ++errors;
            CloseHandle(handle);
            DeleteFileW(file.c_str());
        });
    }
    for (auto& thread : threads) thread.join();
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_READ, &key) == ERROR_SUCCESS) RegCloseKey(key);
    WIN32_FIND_DATAW data{};
    auto search = FindFirstFileExW((root + L"\\*").c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, 0);
    if (search != INVALID_HANDLE_VALUE)
    {
        while (FindNextFileW(search, &data)) {}
        FindClose(search);
    }
    RemoveDirectoryW(root.c_str());
    return errors;
}

uint64_t CpuTime()
{
    FILETIME created, ended, kernel, user;
    GetProcessTimes(GetCurrentProcess(), &created, &ended, &kernel, &user);
    return (uint64_t{kernel.dwHighDateTime} << 32) + kernel.dwLowDateTime +
        (uint64_t{user.dwHighDateTime} << 32) + user.dwLowDateTime;
}

int ChildBurst(uint32_t count)
{
    // Release more launchers than the child request queue can admit at once.
    auto executable = ModuleDirectory() + L"\\DetouristTestTarget.exe";
    Handle start(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!start || count > 60) return 2;
    std::atomic<uint32_t> ready = 0, errors = 0;
    std::vector<std::jthread> launchers;
    for (uint32_t index = 0; index < count; ++index)
    {
        launchers.emplace_back([&]()
        {
            auto command = L"\"" + executable + L"\" --leaf 2";
            STARTUPINFOW startup{sizeof(startup)};
            PROCESS_INFORMATION process{};
            ++ready;
            WaitForSingleObject(start.get(), INFINITE);
            if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                nullptr, nullptr, &startup, &process))
            {
                ++errors;
                return;
            }
            Handle child(process.hProcess), thread(process.hThread);
            if (WaitForSingleObject(child.get(), 10000) != WAIT_OBJECT_0)
            {
                TerminateProcess(child.get(), ERROR_TIMEOUT);
                ++errors;
                return;
            }
            DWORD exitCode = ERROR_GEN_FAILURE;
            if (!GetExitCodeProcess(child.get(), &exitCode) || exitCode) ++errors;
        });
    }
    while (ready != count) Sleep(1);
    SetEvent(start.get());
    launchers.clear();
    return errors ? 1 : 0;
}

int NativeWorkload()
{
    auto module = GetModuleHandleW(L"ntdll.dll");
    auto tick = reinterpret_cast<ULONG (NTAPI*)()>(GetProcAddress(module, "NtGetTickCount"));
    if (!tick) return 6;
    tick();
    auto query = reinterpret_cast<NTSTATUS (NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(
        GetProcAddress(module, "NtQueryInformationProcess"));
    auto alias = reinterpret_cast<decltype(query)>(GetProcAddress(module, "ZwQueryInformationProcess"));
    auto allocate = reinterpret_cast<NTSTATUS (NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>(
        GetProcAddress(module, "NtAllocateVirtualMemory"));
    auto release = reinterpret_cast<NTSTATUS (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG)>(
        GetProcAddress(module, "NtFreeVirtualMemory"));
    if (!query || !alias || !allocate || !release) return 2;
    PROCESS_BASIC_INFORMATION information{};
    ULONG returned = 0;
    if (query(GetCurrentProcess(), ProcessBasicInformation, &information, sizeof(information), &returned) < 0 ||
        alias(GetCurrentProcess(), ProcessBasicInformation, &information, sizeof(information), &returned) < 0)
        return 3;
    void* memory = nullptr;
    SIZE_T size = 4096;
    if (allocate(GetCurrentProcess(), &memory, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0) return 4;
    memset(memory, 0x5A, size);
    size = 0;
    return release(GetCurrentProcess(), &memory, &size, MEM_RELEASE) < 0 ? 5 : 0;
}

bool TimingThrows = false;
int TimingWorkload(bool unwind)
{
    TimingThrows = unwind;
    __try
    {
        // Real callback execution remains part of its parent's duration, including an exceptional return.
        return EnumSystemLocalesW([](LPWSTR) -> BOOL
        {
            Sleep(40);
            GetFileAttributesW(L"Detourist-duration-probe.invalid");
            if (TimingThrows) RaiseException(0xE0424242, 0, 0, nullptr);
            return FALSE;
        }, LCID_SUPPORTED) ? 0 : 1;
    }
    __except (GetExceptionCode() == 0xE0424242 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        return unwind ? 0 : 1;
    }
}

int SequentialChildren(uint32_t count)
{
    // Launch bounded waves that exit before the next wave begins so retired slots and transports are reused.
    while (count)
    {
        auto wave = std::min(35u, count);
        if (ChildBurst(wave)) return 1;
        count -= wave;
    }
    return 0;
}

int StartupTokenFailure(const wchar_t* operation, DWORD error = GetLastError())
{
    fwprintf(stderr, L"Startup token fixture: %ls failed (%lu).\n", operation, error);
    return 90;
}

int StartupTokenChild(const wchar_t* mappingName, HANDLE reportHandle, bool lowIntegrity)
{
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return StartupTokenFailure(L"OpenProcessToken");
    Handle primary(raw);
    if (!IsTokenRestricted(primary.get())) return StartupTokenFailure(L"restricted primary token", ERROR_INVALID_DATA);
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &raw)) return StartupTokenFailure(L"startup token");
    Handle initial(raw);
    SECURITY_IMPERSONATION_LEVEL level{};
    DWORD returned = 0;
    if (!GetTokenInformation(initial.get(), TokenImpersonationLevel, &level, sizeof(level), &returned) ||
        level < SecurityImpersonation) return StartupTokenFailure(L"startup impersonation level");
    auto integrity = [](HANDLE token) -> DWORD
    {
        BYTE data[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE];
        DWORD bytes = 0;
        if (!GetTokenInformation(token, TokenIntegrityLevel, data, sizeof(data), &bytes)) return MAXDWORD;
        auto sid = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(data)->Label.Sid;
        return *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
    };
    if (lowIntegrity && (integrity(primary.get()) != SECURITY_MANDATORY_LOW_RID ||
        integrity(initial.get()) != SECURITY_MANDATORY_LOW_RID))
        return StartupTokenFailure(L"low integrity startup tokens", ERROR_INVALID_DATA);

    // Direct object paths test token access independently of Win32's named-object directory initialization.
    auto openSection = reinterpret_cast<NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenSection"));
    if (!openSection) return StartupTokenFailure(L"NtOpenSection");
    UNICODE_STRING name{};
    RtlInitUnicodeString(&name, mappingName);
    OBJECT_ATTRIBUTES attributes{sizeof(attributes), nullptr, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr};
    auto status = openSection(&raw, SECTION_MAP_READ, &attributes);
    if (status < 0) return StartupTokenFailure(L"startup IPC read access", RtlNtStatusToDosError(status));
    Handle mapping(raw);
    HANDLE writable = nullptr;
    status = openSection(&writable, SECTION_MAP_READ | SECTION_MAP_WRITE, &attributes);
    if (writable) CloseHandle(writable);
    if (lowIntegrity ? status != static_cast<NTSTATUS>(0xC0000022) : status < 0)
        return StartupTokenFailure(L"startup IPC write access", RtlNtStatusToDosError(status));
    Handle report(reportHandle);
    if (!report) return StartupTokenFailure(L"startup report access");
    constexpr char startup[] = "startup\n";
    DWORD written = 0;
    if (!WriteFile(report.get(), startup, static_cast<DWORD>(sizeof(startup) - 1), &written, nullptr) ||
        written != sizeof(startup) - 1) return StartupTokenFailure(L"startup report");
    mapping.reset();
    initial.reset();
    if (!RevertToSelf()) return StartupTokenFailure(L"RevertToSelf");

    // Capture must leave the application's restricted primary token and ordinary access checks intact.
    auto verifyRestricted = [&]() -> int
    {
        HANDLE token = nullptr;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
        {
            CloseHandle(token);
            return StartupTokenFailure(L"startup token removal", ERROR_INVALID_DATA);
        }
        if (GetLastError() != ERROR_NO_TOKEN || !IsTokenRestricted(primary.get()) ||
            lowIntegrity && integrity(primary.get()) != SECURITY_MANDATORY_LOW_RID)
            return StartupTokenFailure(L"restricted application context");
        HANDLE denied = nullptr;
        auto access = openSection(&denied, SECTION_MAP_READ | SECTION_MAP_WRITE, &attributes);
        if (denied) CloseHandle(denied);
        if (access != static_cast<NTSTATUS>(0xC0000022))
            return StartupTokenFailure(L"restricted write denial", RtlNtStatusToDosError(access));
        return 0;
    };
    if (auto result = verifyRestricted()) return result;
    status = openSection(&raw, SECTION_MAP_READ, &attributes);
    if (status < 0) return StartupTokenFailure(L"restricted read access", RtlNtStatusToDosError(status));
    mapping.reset(raw);

    // A module first loaded after lowering the token must still receive capture hooks.
    if (GetModuleHandleW(L"winmm.dll"))
        return StartupTokenFailure(L"module already loaded", ERROR_ALREADY_EXISTS);
    auto multimedia = LoadLibraryW(L"winmm.dll");
    if (!multimedia) return StartupTokenFailure(L"restricted module load");
    auto playSound = reinterpret_cast<BOOL (WINAPI*)(LPCWSTR, HMODULE, DWORD)>(
        GetProcAddress(multimedia, "PlaySoundW"));
    if (!playSound)
    {
        auto lookupError = GetLastError();
        FreeLibrary(multimedia);
        return StartupTokenFailure(L"PlaySoundW", lookupError);
    }
    playSound(nullptr, nullptr, 0);
    FreeLibrary(multimedia);
    if (auto result = verifyRestricted()) return result;
    constexpr char restricted[] = "restricted\n";
    if (!WriteFile(report.get(), restricted, static_cast<DWORD>(sizeof(restricted) - 1), &written, nullptr) ||
        written != sizeof(restricted) - 1) return StartupTokenFailure(L"restricted report");
    return 0;
}

int StartupTokenParent(const wchar_t* executable, const wchar_t* reportPath, bool lowIntegrity)
{
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &raw))
        return StartupTokenFailure(L"source token");
    Handle source(raw);
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sidBytes = sizeof(sid);
    if (!CreateWellKnownSid(WinRestrictedCodeSid, nullptr, sid, &sidBytes))
        return StartupTokenFailure(L"restricting SID");
    SID_AND_ATTRIBUTES restricting{sid, 0};
    if (!CreateRestrictedToken(source.get(), DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,
        0, nullptr, 0, nullptr, 1, &restricting, &raw)) return StartupTokenFailure(L"restricted token");
    Handle primary(raw);

    // Both tokens remain restricted; the startup token retains the caller's ordinary access.
    BYTE user[TOKEN_USER_MAX_SIZE];
    DWORD bytes = 0;
    if (!GetTokenInformation(source.get(), TokenUser, user, sizeof(user), &bytes))
        return StartupTokenFailure(L"source user SID");
    GetTokenInformation(source.get(), TokenGroups, nullptr, 0, &bytes);
    std::vector<BYTE> groupData(bytes);
    if (!GetTokenInformation(source.get(), TokenGroups, groupData.data(), bytes, &bytes))
        return StartupTokenFailure(L"source group SIDs");
    auto groups = reinterpret_cast<const TOKEN_GROUPS*>(groupData.data());
    std::vector<SID_AND_ATTRIBUTES> initialSids{{reinterpret_cast<TOKEN_USER*>(user)->User.Sid, 0}};
    for (DWORD index = 0; index < groups->GroupCount; ++index)
        if (!(groups->Groups[index].Attributes & SE_GROUP_INTEGRITY))
            initialSids.push_back({groups->Groups[index].Sid, 0});
    if (!CreateRestrictedToken(source.get(), 0, 0, nullptr, 0, nullptr,
        static_cast<DWORD>(initialSids.size()), initialSids.data(), &raw))
        return StartupTokenFailure(L"startup token restrictions");
    Handle startupPrimary(raw);
    if (!DuplicateTokenEx(startupPrimary.get(), TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
        nullptr, SecurityImpersonation, TokenImpersonation, &raw)) return StartupTokenFailure(L"initial token");
    Handle initial(raw);
    if (lowIntegrity)
    {
        BYTE lowSid[SECURITY_MAX_SID_SIZE];
        DWORD lowBytes = sizeof(lowSid);
        if (!CreateWellKnownSid(WinLowLabelSid, nullptr, lowSid, &lowBytes))
            return StartupTokenFailure(L"low integrity SID");
        TOKEN_MANDATORY_LABEL label{{lowSid, SE_GROUP_INTEGRITY}};
        auto labelBytes = static_cast<DWORD>(sizeof(label)) + lowBytes;
        if (!SetTokenInformation(primary.get(), TokenIntegrityLevel, &label, labelBytes) ||
            !SetTokenInformation(initial.get(), TokenIntegrityLevel, &label, labelBytes))
            return StartupTokenFailure(L"low integrity tokens");
    }

    // Medium objects deny writes from low integrity or the restricted primary token without any ACL changes.
    DWORD session = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session)) return StartupTokenFailure(L"session identity");
    auto objectName = L"DetouristStartupToken-" + std::to_wstring(GetCurrentProcessId());
    auto name = L"Local\\" + objectName;
    auto nativeName = L"\\Sessions\\" + std::to_wstring(session) + L"\\BaseNamedObjects\\" + objectName;
    Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, name.c_str()));
    Handle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!mapping || !job || !SetInformationJobObject(job.get(),
        JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return StartupTokenFailure(L"fixture objects");

    // Share only the report handle so a low integrity child can report results without opening a writable path.
    SECURITY_ATTRIBUTES inheritance{sizeof(inheritance), nullptr, TRUE};
    Handle report(CreateFileW(reportPath, GENERIC_WRITE, FILE_SHARE_READ, &inheritance, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!report) return StartupTokenFailure(L"report handle");
    auto command = L"\"" + std::wstring(executable) + L"\" --startup-token-leaf \"" +
        nativeName + L"\" " + std::to_wstring(reinterpret_cast<uintptr_t>(report.get()));
    if (lowIntegrity) command += L" --low-integrity";
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput = report.get();
    startup.StartupInfo.hStdError = report.get();
    SIZE_T attributeBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
    std::vector<BYTE> attributeData(attributeBytes);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeData.data());
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attributeBytes))
        return StartupTokenFailure(L"process attributes");
    HANDLE inherited[]{report.get()};
    PROCESS_INFORMATION information{};
    auto created = UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inherited, sizeof(inherited), nullptr, nullptr) &&
        CreateProcessAsUserW(primary.get(), executable, command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            nullptr, nullptr, &startup.StartupInfo, &information);
    auto creationError = GetLastError();
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    if (!created) return StartupTokenFailure(L"child creation", creationError);
    Handle child(information.hProcess), thread(information.hThread);
    if (!AssignProcessToJobObject(job.get(), child.get()))
    {
        auto error = GetLastError();
        TerminateProcess(child.get(), 90);
        return StartupTokenFailure(L"child job", error);
    }
    if (!SetThreadToken(&information.hThread, initial.get()) || ResumeThread(thread.get()) != 1)
        return StartupTokenFailure(L"child startup context");
    DWORD result = 90;
    if (WaitForSingleObject(child.get(), 60000) != WAIT_OBJECT_0 || !GetExitCodeProcess(child.get(), &result))
        return StartupTokenFailure(L"child completion");
    return static_cast<int>(result);
}

int wmain(int argc, wchar_t** argv)
{
    if ((argc == 4 || argc == 5 && !wcscmp(argv[4], L"--low-integrity")) && !wcscmp(argv[1], L"--startup-token"))
        return StartupTokenParent(argv[2], argv[3], argc == 5);
    if ((argc == 4 || argc == 5 && !wcscmp(argv[4], L"--low-integrity")) && !wcscmp(argv[1], L"--startup-token-leaf"))
        return StartupTokenChild(argv[2], reinterpret_cast<HANDLE>(static_cast<uintptr_t>(
            _wcstoui64(argv[3], nullptr, 10))), argc == 5);
    if (argc >= 3 && !wcscmp(argv[1], L"--suspended-children"))
    {
        auto count = static_cast<uint32_t>(_wtoi(argv[2]));
        auto executable = argc > 3 ? std::wstring(argv[3]) : ModuleDirectory() + L"\\DetouristTestTarget.exe";
        auto name = argc > 5 ? std::wstring(argv[5]) :
            L"Local\\DetouristStartup-" + std::to_wstring(GetCurrentProcessId());
        Handle ready(CreateEventW(nullptr, TRUE, FALSE, name.c_str()));
        Handle job(CreateJobObjectW(nullptr, nullptr));
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!count || count > 40 || !ready || !job || !SetInformationJobObject(job.get(),
            JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return 81;
        std::vector<std::pair<Handle, Handle>> children;
        SetEnvironmentVariableW(L"DETOURIST_TEST_STARTUP_GATE", name.c_str());

        // Create the entire batch before allowing any loader to run, exceeding both collector queues.
        for (uint32_t index = 0; index < count; ++index)
        {
            auto command = L"\"" + executable + L"\" --leaf 1";
            STARTUPINFOW startup{sizeof(startup)};
            PROCESS_INFORMATION information{};
            if (!CreateProcessAsUserW(nullptr, executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information)) return 82;
            Handle child(information.hProcess), thread(information.hThread);
            if (!AssignProcessToJobObject(job.get(), child.get()))
            {
                TerminateProcess(child.get(), 83);
                return 83;
            }
            children.emplace_back(std::move(child), std::move(thread));
        }
        SetEnvironmentVariableW(L"DETOURIST_TEST_STARTUP_GATE", nullptr);
        if (argc > 4)
        {
            auto pending = std::wstring(argv[4]) + L".pending";
            Handle marker(CreateFileW(pending.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr));
            std::string identifiers;
            for (const auto& [child, thread] : children)
                identifiers += std::to_string(GetProcessId(child.get())) + "\t" +
                    std::to_string(GetThreadId(thread.get())) + "\n";
            DWORD written = 0;
            if (!marker || !WriteFile(marker.get(), identifiers.data(), static_cast<DWORD>(identifiers.size()),
                &written, nullptr) || written != identifiers.size()) return 84;
            marker.reset();
            if (!MoveFileExW(pending.c_str(), argv[4], MOVEFILE_REPLACE_EXISTING) ||
                WaitForSingleObject(ready.get(), 30000) != WAIT_OBJECT_0) return 84;
        }
        else if (!SetEvent(ready.get())) return 84;
        auto alertResume = reinterpret_cast<NTSTATUS (NTAPI*)(HANDLE, PULONG)>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAlertResumeThread"));
        auto resumeProcess = reinterpret_cast<NTSTATUS (NTAPI*)(HANDLE)>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess"));
        if (!alertResume || !resumeProcess) return 85;
        for (size_t index = 0; index < children.size(); ++index)
        {
            auto& [child, thread] = children[index];
            if (argc <= 6 && !index && (SuspendThread(thread.get()) != 1 || ResumeThread(thread.get()) != 2 ||
                WaitForSingleObject(child.get(), 0) != WAIT_TIMEOUT)) return 86;
            ULONG previous = 0;
            if (argc <= 6 && (index % 3 == 0 ? ResumeThread(thread.get()) != 1 : index % 3 == 1 ?
                alertResume(thread.get(), &previous) < 0 || previous != 1 : resumeProcess(child.get()) < 0)) return 87;
            DWORD exitCode = ERROR_GEN_FAILURE;
            if (WaitForSingleObject(child.get(), 30000) != WAIT_OBJECT_0 ||
                !GetExitCodeProcess(child.get(), &exitCode) || exitCode) return 88;
        }
        return 0;
    }
#ifdef _DEBUG
    if (argc == 2 && !wcscmp(argv[1], L"--crt-assert"))
    {
        // Exercise the CRT's wide assertion report in a separate process.
        _ASSERTE(argc == 0 && "Detourist unattended assertion probe");
        return 1;
    }
#endif
    if (argc == 3 && !wcscmp(argv[1], L"--unfinished-wait"))
    {
        // The controller permits process exit while a recorded worker wait remains blocked.
        Handle finish(OpenEventW(SYNCHRONIZE, FALSE, argv[2]));
        Handle blocked(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        Handle worker(CreateThread(nullptr, 0, [](void* event) -> DWORD
        {
            WaitForSingleObject(event, INFINITE);
            return 0;
        }, blocked.get(), 0, nullptr));
        if (!finish || !blocked || !worker) return 1;
        HANDLE events[]{finish.get()};
        ExitProcess(WaitForMultipleObjects(1, events, FALSE, 30000) == WAIT_OBJECT_0 ? 0 : 2);
    }

    if (argc > 1 && (!wcscmp(argv[1], L"--handoff") || !wcscmp(argv[1], L"--protected-child")))
    {
        // A controller can hold a quiet capture open on either side of the skipped child.
        const bool protectedChild = !wcscmp(argv[1], L"--protected-child");
        Handle gate;
        if (protectedChild && argc == 3)
        {
            gate.reset(OpenEventW(SYNCHRONIZE, FALSE, argv[2]));
            if (!gate || WaitForSingleObject(gate.get(), 30000) != WAIT_OBJECT_0) return 6;
        }

        // Alternate creation APIs must follow children even when the parent exits immediately.
        auto executable = ModuleDirectory() + L"\\DetouristTestTarget.exe";
        auto command = L"\"" + executable + L"\" --paced 30";
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        DWORD flags = CREATE_NO_WINDOW;
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        std::vector<BYTE> attributes(bytes);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
        if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes)) return 1;
        DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
        if (protectedChild)
        {
            if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                &policy, sizeof(policy), nullptr, nullptr)) return 2;
            flags |= EXTENDED_STARTUPINFO_PRESENT;
        }
        else
        {
            startup.StartupInfo.cb = sizeof(STARTUPINFOW);
            flags |= CREATE_SUSPENDED;
            if (CreateProcessAsUserW(nullptr, L"Detourist-missing-handoff.invalid", nullptr, nullptr, nullptr,
                FALSE, flags, nullptr, nullptr, &startup.StartupInfo, &process)) return 3;
        }
        auto created = CreateProcessAsUserW(nullptr, executable.c_str(), command.data(), nullptr, nullptr,
            FALSE, flags, nullptr, nullptr, &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        if (!created) return 4;
        Handle child(process.hProcess), thread(process.hThread);
        if (!protectedChild && ResumeThread(thread.get()) != 1) return 5;
        return gate && WaitForSingleObject(gate.get(), 30000) != WAIT_OBJECT_0 ? 7 : 0;
    }
    if (argc > 2 && !wcscmp(argv[1], L"--noise"))
    {
        // Capture suppression must preserve query results and the caller's last error.
        auto thread = GetCurrentThreadId();
        auto heap = GetProcessHeap();
        auto fiber = FlsAlloc(nullptr);
        if (!heap || fiber == FLS_OUT_OF_INDEXES || !FlsSetValue(fiber, heap)) return 2;
        for (int index = 0; index < _wtoi(argv[2]); ++index)
        {
            if (GetProcessHeap() != heap || FlsGetValue(fiber) != heap || lstrcmpiW(L"Noise", L"NOISE"))
                return 3;
            SetLastError(ERROR_INVALID_PARAMETER);
            if (GetLastError() != ERROR_INVALID_PARAMETER || GetCurrentThreadId() != thread || IsThreadAFiber())
                return 1;
        }
        FlsFree(fiber);
        return Workload(1) ? 1 : 0;
    }
    if (argc > 1 && (!wcscmp(argv[1], L"--durations") || !wcscmp(argv[1], L"--duration-unwind")))
        return TimingWorkload(!wcscmp(argv[1], L"--duration-unwind"));
    if (argc > 2 && !wcscmp(argv[1], L"--orphan"))
    {
        auto executable = argc > 3 ? std::wstring(argv[3]) : ModuleDirectory() + L"\\DetouristTestTarget.exe";
        auto command = L"\"" + executable + L"\" --paced " + std::wstring(argv[2]);
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &process)) return 1;
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 0;
    }
    if (argc > 1 && !wcscmp(argv[1], L"--native")) return NativeWorkload();
    if (argc > 2 && !wcscmp(argv[1], L"--burst")) return ChildBurst(static_cast<uint32_t>(_wtoi(argv[2])));
    if (argc > 2 && !wcscmp(argv[1], L"--sequential"))
        return SequentialChildren(static_cast<uint32_t>(_wtoi(argv[2])));
    if (argc > 2 && !wcscmp(argv[1], L"--controlled"))
    {
        // Test commands share metrics with the harness without using the monitored APIs.
        std::wstring name = argv[2];
        Handle mapping(OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name.c_str()));
        auto metrics = static_cast<FixtureMetrics*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, 0));
        Handle run(OpenEventW(SYNCHRONIZE, FALSE, (name + L".run").c_str()));
        Handle done(OpenEventW(EVENT_MODIFY_STATE, FALSE, (name + L".done").c_str()));
        Handle stop(OpenEventW(SYNCHRONIZE, FALSE, (name + L".stop").c_str()));
        if (!metrics || !run || !done || !stop) return 2;
        std::jthread pulse([&](std::stop_token token)
        {
            while (!token.stop_requested()) { InterlockedIncrement(&metrics->heartbeat); Sleep(1); }
        });
        HANDLE commands[] = {stop.get(), run.get()};
        SetEvent(done.get());
        while (WaitForMultipleObjects(2, commands, FALSE, INFINITE) == WAIT_OBJECT_0 + 1)
        {
            auto cpu = CpuTime();
            auto clock = Clock();
            metrics->exceptionsHandled = ExceptionProbe() ? 1 : 0;
            metrics->errors = Workload(metrics->iterations);
            metrics->elapsedTicks = Clock() - clock;
            metrics->cpuTicks = CpuTime() - cpu;
            PROCESS_MEMORY_COUNTERS_EX memory{};
            GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),
                sizeof(memory));
            metrics->peakWorkingSet = memory.PeakWorkingSetSize;
            metrics->privateBytes = memory.PrivateUsage;
            SetEvent(done.get());
        }
        pulse.request_stop();
        pulse.join();
        UnmapViewOfFile(metrics);
        return 0;
    }
    if (argc > 1 && !wcscmp(argv[1], L"--wait")) Sleep(1500);
    uint32_t iterations = argc > 2 ? static_cast<uint32_t>(_wtoi(argv[2])) : 100;
    auto started = std::chrono::steady_clock::now();
    auto errors = Workload(iterations, argc > 1 && !wcscmp(argv[1], L"--paced"));
    if (argc > 1 && !wcscmp(argv[1], L"--child"))
    {
        auto executable = argc > 3 ? std::wstring(argv[3]) : ModuleDirectory() + L"\\DetouristTestTarget.exe";
        std::wstring command = L"\"" + executable + L"\" --leaf 10";
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION process{};
        if (CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, 0, nullptr,
            nullptr, &startup, &process))
        {
            WaitForSingleObject(process.hProcess, 10000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    }
    auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    std::printf("workload_ms=%.3f iterations=%u\n", elapsed, iterations);
    return errors ? 1 : 0;
}

#elif defined(DETOURIST_TEST_DetouristInstructionTarget)

#include "WinSupport.h"
#include <winternl.h>
#include <lmcons.h>
#include <lmapibuf.h>

using namespace Detourist;

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && !wcscmp(argv[1], L"--allocated-buffers"))
    {
        // Real SDK allocation and reallocation retain bounded data and expose their documented status convention.
        auto library = LoadLibraryExW(L"netapi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 24;
        auto allocate = reinterpret_cast<decltype(&NetApiBufferAllocate)>(
            GetProcAddress(library, "NetApiBufferAllocate"));
        auto reallocate = reinterpret_cast<decltype(&NetApiBufferReallocate)>(
            GetProcAddress(library, "NetApiBufferReallocate"));
        auto size = reinterpret_cast<decltype(&NetApiBufferSize)>(GetProcAddress(library, "NetApiBufferSize"));
        auto release = reinterpret_cast<decltype(&NetApiBufferFree)>(GetProcAddress(library, "NetApiBufferFree"));
        if (!allocate || !reallocate || !size || !release) return 25;
        BYTE* buffer = nullptr;
        if (allocate(128, reinterpret_cast<void**>(&buffer)) || !buffer) return 26;
        for (DWORD index = 0; index < 128; ++index) buffer[index] = static_cast<BYTE>(index ^ 0xA7);
        if (reallocate(buffer, 384, reinterpret_cast<void**>(&buffer)) || !buffer) return 27;
        for (DWORD index = 0; index < 128; ++index)
            if (buffer[index] != static_cast<BYTE>(index ^ 0xA7)) return 28;
        DWORD bytes = 0;
        bool valid = !size(buffer, &bytes) && bytes >= 384 && !release(buffer) && size(nullptr, &bytes) != 0;
        FreeLibrary(library);
        return valid ? 0 : 29;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--runtime"))
    {
        // Invoke real runtime exports through their DLL addresses so intrinsic expansion cannot bypass capture.
        auto library = LoadLibraryExW(L"ucrtbase.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return 6;
        auto copy = reinterpret_cast<void* (*)(void*, const void*, size_t)>(GetProcAddress(library, "memcpy"));
        auto fill = reinterpret_cast<void* (*)(void*, int, size_t)>(GetProcAddress(library, "memset"));
        auto compare = reinterpret_cast<LONG (NTAPI*)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN)>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCompareUnicodeString"));
        auto session = reinterpret_cast<ULONG (NTAPI*)()>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetCurrentServiceSessionId"));
        if (!copy || !fill || !compare || !session) { FreeLibrary(library); return 7; }
        BYTE input[4096], output[4096];
        for (size_t index = 0; index < sizeof(input); ++index) input[index] = static_cast<BYTE>(index ^ 0xA5);
        if (copy(output, input, sizeof(input)) != output || memcmp(input, output, sizeof(input))) return 8;
        if (copy(output, input, 17) != output || fill(output, 0x39, 23) != output) return 9;
        for (size_t index = 0; index < 23; ++index)
            if (output[index] != 0x39) return 10;
        wchar_t first[] = L"Runtime-export-first", second[] = L"Runtime-export-second";
        UNICODE_STRING left{sizeof(first) - sizeof(wchar_t), sizeof(first), first};
        UNICODE_STRING right{sizeof(second) - sizeof(wchar_t), sizeof(second), second};
        if (compare(&left, &right, FALSE) >= 0) return 11;
        session();
        FreeLibrary(library);
        return 0;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--teardown"))
    {
        wchar_t path[32768]{};
        if (!GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)))) return 2;
        auto terminate = reinterpret_cast<LONG (NTAPI*)(HANDLE, LONG)>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTerminateProcess"));
        if (!terminate || terminate(nullptr, 0) < 0) return 4;

        // The remaining thread records calls after process teardown removes the observer workers.
        return GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES ? 5 : 0;
    }
    return 1;
}

#elif defined(DETOURIST_TEST_DetouristDetachCallbackTarget)

#include <windows.h>
#include <atomic>
#include <string>
#include <thread>

std::wstring CallbackPrefix;
std::atomic<bool> CallbackPassed = false;

bool CallbackGate(const std::wstring& suffix)
{
    HANDLE file = CreateFileW((CallbackPrefix + suffix).c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    if (suffix == L".callback")
    {
        auto module = GetModuleHandleW(L"dynamorio.dll");
        auto running = module ? reinterpret_cast<bool (*)()>(GetProcAddress(module,
            "dr_app_running_under_dynamorio")) : nullptr;
        DWORD active = running && running();
        DWORD written = 0;
        if (!WriteFile(file, &active, sizeof(active), &written, nullptr) || written != sizeof(active))
        {
            CloseHandle(file);
            return false;
        }
    }
    CloseHandle(file);
    return true;
}

bool CallbackWait(const std::wstring& suffix)
{
    auto deadline = GetTickCount64() + 30000;
    while (GetFileAttributesW((CallbackPrefix + suffix).c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        if (GetTickCount64() >= deadline) return false;
        Sleep(10);
    }
    return true;
}

LRESULT CALLBACK DetachWindow(HWND window, UINT message, WPARAM word, LPARAM parameter)
{
    if (message == WM_APP)
    {
        CallbackPassed = CallbackGate(L".callback") && CallbackWait(L".release");
        return CallbackPassed ? 0x12345678 : 0;
    }
    return DefWindowProcW(window, message, word, parameter);
}

void CALLBACK DetachApc(ULONG_PTR)
{
    CallbackPassed = CallbackGate(L".callback") && CallbackWait(L".release");
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3) return 1;
    auto root = std::wstring(argv[2]);
    for (unsigned phase = 0; phase < 3; ++phase)
    {
        CallbackPrefix = root + L"." + std::to_wstring(phase);
        CallbackPassed = false;
        if (!CallbackGate(L".ready") || !CallbackWait(L".go")) return 2;
        if (!wcscmp(argv[1], L"apc"))
        {
            if (!QueueUserAPC(&DetachApc, GetCurrentThread(), 0) ||
                SleepEx(10000, TRUE) != WAIT_IO_COMPLETION || !CallbackPassed) return 3;
        }
        else
        {
            // A message-only window provides a real kernel callback without displaying or activating a window.
            WNDCLASSW type{};
            type.hInstance = GetModuleHandleW(nullptr);
            type.lpfnWndProc = &DetachWindow;
            type.lpszClassName = L"DetouristDetachCallback";
            if (phase == 0 && !RegisterClassW(&type)) return 4;
            HWND window = CreateWindowExW(0, type.lpszClassName, L"", 0, 0, 0, 0, 0,
                HWND_MESSAGE, nullptr, type.hInstance, nullptr);
            if (!window) return 5;
            std::atomic<bool> sent = false;
            std::jthread worker([&]
            {
                sent = SendMessageW(window, WM_APP, 0, 0) == 0x12345678;
                PostThreadMessageW(GetWindowThreadProcessId(window, nullptr), WM_QUIT, 0, 0);
            });
            MSG message{};
            while (GetMessageW(&message, nullptr, 0, 0) > 0)
            {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            worker.join();
            DestroyWindow(window);
            if (!sent || !CallbackPassed) return 6;
        }
        if (!CallbackGate(L".done") || !CallbackWait(L".next")) return 7;
    }
    return 0;
}

#else
#error Select a native test target.
#endif

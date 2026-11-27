#include "Agent.h"
#include "ImageIdentity.h"
#include <winternl.h>
#include <intrin.h>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <new>

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace Detourist
{
constexpr size_t ModuleUnloadCapacity = 1024;
constexpr size_t ProcedureResolutionBuckets = 1024;
constexpr uintptr_t MaxOrdinalValue = 0xFFFF;
constexpr uint32_t MaxRefreshPasses = 4;

struct ModuleNotification
{
    ULONG flags;
    const UNICODE_STRING* fullName;
    const UNICODE_STRING* baseName;
    void* base;
    ULONG size;
};
struct UnloadedModule
{
    volatile LONG state = 0;
    HMODULE base = nullptr;
    size_t size = 0;
};
UnloadedModule ModuleUnloads[ModuleUnloadCapacity];
std::atomic<SharedHeader*> ModuleHistory = nullptr;
volatile LONG ModuleHistoryReaders = 0;
volatile LONG ModulesDirty = 0;
volatile LONG ModuleNotificationError = 0;
volatile LONG ModuleRefreshReady = 0;
volatile LONG LastModuleRefreshError = 0;
SRWLOCK ModuleChangeLock = SRWLOCK_INIT;
void* ModuleNotificationCookie = nullptr;
using LoadDll = NTSTATUS (NTAPI*)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
using UnloadDll = NTSTATUS (NTAPI*)(HMODULE);
using NotificationCallback = void (CALLBACK*)(ULONG, const ModuleNotification*, void*);
using RegisterNotifications = NTSTATUS (NTAPI*)(ULONG, NotificationCallback, void*, void**);
LoadDll OriginalLdrLoadDll = nullptr;
UnloadDll OriginalLdrUnloadDll = nullptr;
decltype(&::GetProcAddress) OriginalGetProcAddress = &::GetProcAddress;
decltype(&::GetProcAddress) OriginalBaseGetProcAddress = nullptr;
using GetProcedureForCaller = FARPROC (WINAPI*)(HMODULE, LPCSTR, void*);
GetProcedureForCaller OriginalGetProcAddressForCaller = nullptr;
extern std::atomic<uint64_t> Installed;

struct ProcedureResolution
{
    ProcedureResolution* next;
    HMODULE module;
    FARPROC original;
    FARPROC resolved;
    uintptr_t ordinal;
    std::atomic<bool> retired;
    char name[1];
};
std::atomic<ProcedureResolution*> ProcedureResolutions[ProcedureResolutionBuckets]{};

FARPROC CanonicalExportObserver(HMODULE module, LPCSTR name, FARPROC original)
{
    auto error = GetLastError();
    auto status = NativeThreadStatus();
    auto ordinal = reinterpret_cast<uintptr_t>(name) <= MaxOrdinalValue ?
        reinterpret_cast<uintptr_t>(name) : UINTPTR_MAX;
    auto length = ordinal != UINTPTR_MAX ? size_t{0} : strlen(name);
    auto hash = reinterpret_cast<uintptr_t>(module) ^ reinterpret_cast<uintptr_t>(original) ^ ordinal;
    for (size_t index = 0; index < length; ++index)
        hash = (hash ^ static_cast<unsigned char>(name[index])) * Fnv1aPrime32;
    auto& bucket = ProcedureResolutions[hash % std::size(ProcedureResolutions)];
    ProcedureResolution* candidate = nullptr;
    FARPROC result = original;

    // The first successful lookup determines the export's identity throughout this module lifetime.
    for (auto head = bucket.load(std::memory_order_acquire);;)
    {
        for (auto entry = head; entry; entry = entry->next)
        {
            if (!entry->retired.load(std::memory_order_acquire) && entry->module == module &&
                entry->original == original && entry->ordinal == ordinal &&
                (ordinal != UINTPTR_MAX || !strcmp(entry->name, name)))
            {
                result = entry->resolved;
                goto done;
            }
        }
        if (!candidate)
        {
            auto memory = HeapAlloc(GetProcessHeap(), 0, sizeof(ProcedureResolution) + length);
            if (!memory) goto done;
            candidate = new (memory) ProcedureResolution{};
            candidate->module = module;
            candidate->original = original;
            candidate->resolved = ExportInteropObserver(module, name, original);
            candidate->ordinal = ordinal;
            if (ordinal == UINTPTR_MAX) memcpy(candidate->name, name, length + 1);
        }
        candidate->next = head;
        if (bucket.compare_exchange_weak(head, candidate, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            result = candidate->resolved;
            candidate = nullptr;
            break;
        }
    }
done:
    if (candidate) HeapFree(GetProcessHeap(), 0, candidate);
    RestoreNativeThreadStatus(status);
    SetLastError(error);
    return result;
}

void CALLBACK ObserveModuleChange(ULONG reason, const ModuleNotification* notification, void*)
{
    if (reason != static_cast<ULONG>(ModuleChangeReason::Load) &&
        reason != static_cast<ULONG>(ModuleChangeReason::Unload)) return;
    InvalidateStackImageCache();
    InterlockedIncrement(&ModuleHistoryReaders);
    auto header = ModuleHistory.load();
    if (header)
    {
        // The loader only copies into bounded shared storage; it never calls another DLL or waits for a reader.
        auto epoch = InterlockedIncrement64(&header->moduleEpoch);
        auto write = InterlockedCompareExchange64(&header->moduleChangeWrite, 0, 0);
        auto read = InterlockedCompareExchange64(&header->moduleChangeRead, 0, 0);
        if (write - read < ModuleHistoryCapacity)
        {
            auto& change = header->moduleChanges[static_cast<uint64_t>(write) & (ModuleHistoryCapacity - 1)];
            change.epoch = static_cast<uint64_t>(epoch);
            change.base = reinterpret_cast<uint64_t>(notification->base);
            change.size = notification->size;
            change.reason = reason;
            ReadImageIdentity(change.base, change.size, change.identity,
                [](uint64_t address, void* output, size_t bytes)
            {
                return ReadCaptureMemory(reinterpret_cast<void*>(address), output, bytes);
            });
            auto name = notification->fullName;
            if (!name || name->Length > sizeof(change.path)) name = notification->baseName;
            change.characters = name ? std::min<uint32_t>(name->Length / 2u, MaximumModulePath) : 0;
            for (uint32_t index = 0; index < change.characters; ++index) change.path[index] = name->Buffer[index];
            InterlockedExchange64(&header->moduleChangeWrite, write + 1);
        }
        else
        {
            InterlockedCompareExchange64(&header->moduleHistoryLost, epoch, 0);
            InterlockedExchange(&header->moduleRefreshError, ERROR_BUFFER_OVERFLOW);
        }
    }
    if (reason == static_cast<ULONG>(ModuleChangeReason::Unload))
    {
        auto base = reinterpret_cast<uintptr_t>(notification->base);
        for (auto& bucket : ProcedureResolutions)
            for (auto entry = bucket.load(std::memory_order_acquire); entry; entry = entry->next)
            {
                auto address = reinterpret_cast<uintptr_t>(entry->original);
                if (entry->module == notification->base ||
                    (address >= base && address - base < notification->size))
                    entry->retired.store(true, std::memory_order_release);
            }
        bool stored = false;

        // The loader callback calls no foreign module and never waits for the collector or installer.
        for (auto& slot : ModuleUnloads)
        {
            if (InterlockedCompareExchange(&slot.state, 1, 0) != 0) continue;
            slot.base = static_cast<HMODULE>(notification->base);
            slot.size = notification->size;
            InterlockedExchange(&slot.state, 2);
            stored = true;
            break;
        }
        if (!stored) InterlockedExchange(&ModuleNotificationError, ERROR_BUFFER_OVERFLOW);
    }
    InterlockedDecrement(&ModuleHistoryReaders);
    InterlockedExchange(&ModulesDirty, 1);
}

void BindModuleHistory(SharedHeader* header)
{
    // Wait outside the loader callback before replacing or unmapping a session's shared memory.
    ModuleHistory.store(nullptr);
    while (InterlockedCompareExchange(&ModuleHistoryReaders, 0, 0)) SwitchToThread();
    ModuleHistory.store(header);
}

void ReportModuleError(DWORD error)
{
    InterlockedExchange(&LastModuleRefreshError, static_cast<LONG>(error));
    AcquireSRWLockShared(&CaptureLock);
    if (ActiveTransport) ActiveTransport->Header()->moduleRefreshError = error;
    ReleaseSRWLockShared(&CaptureLock);
}

void WriteHookCoverage(SharedHeader& header)
{
    InterlockedExchange64(&header.installedApis, static_cast<LONGLONG>(Installed.load(std::memory_order_relaxed)));
    header.installedNativeCount = InstalledNativeCount;
    header.availableNativeCount = AvailableNativeCount;
    header.nativeExportCount = NativeExportCount;
    header.installedWin32Count = InstalledWin32Count;
    header.availableWin32Count = AvailableWin32Count;
    header.installedComCount = InstalledComCount;
    if (!BroadHooks) header.installedExportCount = InstalledExportCount;
    header.moduleRefreshError = header.moduleHistoryLost ? ERROR_BUFFER_OVERFLOW :
        static_cast<DWORD>(LastModuleRefreshError);
    memcpy(header.unknownNativeExports, UnknownNativeExports, sizeof(header.unknownNativeExports));
}

void PublishHookCoverage(SharedHeader& header)
{
    AcquireSRWLockExclusive(&ModuleChangeLock);
    WriteHookCoverage(header);
    ReleaseSRWLockExclusive(&ModuleChangeLock);
}

void ProcessModuleChanges()
{
    if (!ModuleRefreshReady || ProcessShuttingDown || !NativeThreadReady() || !NativeStackSafe()) return;
    if (!ModulesDirty && !ModuleNotificationError) return;
    ObserverScope observer;
    CaptureObservation capture(&CaptureTime, Clock());
    AcquireSRWLockExclusive(&ModuleChangeLock);
    if (!NativeStackSafe())
    {
        ReleaseSRWLockExclusive(&ModuleChangeLock);
        capture.Reset();
        return;
    }
    for (uint32_t pass = 0; pass < MaxRefreshPasses; ++pass)
    {
        bool changed = InterlockedExchange(&ModulesDirty, 0) != 0;

        // Invalidate unloaded images before resolving exports from any replacement image at the same address.
        for (auto& slot : ModuleUnloads)
        {
            if (InterlockedCompareExchange(&slot.state, 2, 2) != 2) continue;
            InvalidateHooks(slot.base, slot.size);
            InterlockedExchange(&slot.state, 0);
        }
        auto notificationError = static_cast<DWORD>(ModuleNotificationError);
        if (notificationError)
        {
            ReportModuleError(notificationError);
            break;
        }
        if (changed && !BroadHooks)
        {
            AcquireSRWLockShared(&CaptureLock);
            auto transport = ActiveTransport;
            if (transport) InterlockedIncrement64(&transport->Header()->activeCalls);
            ReleaseSRWLockShared(&CaptureLock);
            try
            {
                auto installed = RefreshHooks(transport);
                Installed.fetch_or(installed, std::memory_order_relaxed);
                InterlockedExchange(&LastModuleRefreshError, 0);
                AcquireSRWLockShared(&CaptureLock);
                if (ActiveTransport && !BroadHooks) WriteHookCoverage(*ActiveTransport->Header());
                ReleaseSRWLockShared(&CaptureLock);
            }
            catch (...)
            {
                if (transport) InterlockedDecrement64(&transport->Header()->activeCalls);
                ReportModuleError(ERROR_GEN_FAILURE);
                break;
            }
            if (transport) InterlockedDecrement64(&transport->Header()->activeCalls);
        }

        // Releasing temporary image references can publish more unloads during the same refresh.
        if (!ModulesDirty || !NativeStackSafe()) break;
    }
    ReleaseSRWLockExclusive(&ModuleChangeLock);
    capture.Reset();
}

NTSTATUS NTAPI HookLdrLoadDll(PWSTR path, PULONG flags, PUNICODE_STRING name, PHANDLE module)
{
    auto result = OriginalLdrLoadDll(path, flags, name, module);
    if (NativeThreadReady() && !ObserverActive) ProcessModuleChanges();
    return result;
}

NTSTATUS NTAPI HookLdrUnloadDll(HMODULE module)
{
    auto result = OriginalLdrUnloadDll(module);
    if (NativeThreadReady() && !ObserverActive) ProcessModuleChanges();
    return result;
}

FARPROC ResolveProcedure(HMODULE module, LPCSTR name, FARPROC result, void* caller)
{
    if (!result) return result;

    // Hook installation and this DLL's CRT must always use the loader's own addresses.
    const auto self = reinterpret_cast<uintptr_t>(&__ImageBase);
    const auto address = reinterpret_cast<uintptr_t>(caller);
    const auto image = reinterpret_cast<const IMAGE_NT_HEADERS*>(self + __ImageBase.e_lfanew);
    if (address >= self && address - self < image->OptionalHeader.SizeOfImage) return result;

    // Application CRT caches race during thread startup; suppression must not change a named export's identity.
    if (!NativeThreadReady() || ObserverActive) return CanonicalExportObserver(module, name, result);
    ObserverScope observer;
    HMODULE callerModule = nullptr;
    auto core = GetModuleHandleW(L"coreclr.dll"), framework = GetModuleHandleW(L"clr.dll"),
        legacy = GetModuleHandleW(L"mscorwks.dll");

    auto runtimeCaller = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCWSTR>(caller), &callerModule) &&
        ((core && callerModule == core) || (framework && callerModule == framework) ||
        (legacy && callerModule == legacy));

    // Managed interop thunks can execute outside runtime images while retaining their CLR thread identity.
    if (!runtimeCaller && !callerModule && (core || framework || legacy))
    {
        using ManagedThread = BOOL (WINAPI*)();
        auto profiler = GetModuleHandleW(L"DetouristProfiler.dll");
        auto managed = profiler ? reinterpret_cast<ManagedThread>(OriginalGetProcAddress(profiler,
            "DetouristIsManagedThread")) : nullptr;
        runtimeCaller = managed && managed();
    }

    // CLR-native P/Invoke resolution supplies typed observers without changing the system's syscall stubs.
    if (module == GetModuleHandleW(L"ntdll.dll"))
    {
        if (runtimeCaller) result = NativeInteropObserver(result);
    }
    else if (runtimeCaller && module == GetModuleHandleW(L"win32u.dll"))
        result = Win32uInteropObserver(result);
    else
    {
        auto observed = Win32InteropObserver(module, name, result, !runtimeCaller);
        result = observed == result ? CanonicalExportObserver(module, name, result) : observed;
    }
    return result;
}

FARPROC WINAPI HookGetProcAddress(HMODULE module, LPCSTR name)
{
    return ResolveProcedure(module, name, OriginalGetProcAddress(module, name), _ReturnAddress());
}

FARPROC WINAPI HookBaseGetProcAddress(HMODULE module, LPCSTR name)
{
    return ResolveProcedure(module, name, OriginalBaseGetProcAddress(module, name), _ReturnAddress());
}

FARPROC WINAPI HookGetProcAddressForCaller(HMODULE module, LPCSTR name, void* caller)
{
    return ResolveProcedure(module, name, OriginalGetProcAddressForCaller(module, name, caller), caller);
}

void AddModuleHooks(std::vector<HookDefinition>& hooks)
{
    auto module = GetModuleHandleW(L"ntdll.dll");
    if (!module) return;
    // Infrastructure hooks carry no API identity; retain their existing trampolines when changing capture mode.
    auto add = [&](auto& original, FARPROC address, auto observer)
    {
        auto entry = reinterpret_cast<void*>(observer);
        if (!address || std::any_of(hooks.begin(), hooks.end(),
            [&](const auto& hook) { return hook.observer == entry; })) return;
        original = reinterpret_cast<std::remove_reference_t<decltype(original)>>(address);
        hooks.push_back({Api::Count, reinterpret_cast<void**>(&original), entry});
    };
    add(OriginalLdrLoadDll, GetProcAddress(module, "LdrLoadDll"), &HookLdrLoadDll);
    add(OriginalLdrUnloadDll, GetProcAddress(module, "LdrUnloadDll"), &HookLdrUnloadDll);
    add(OriginalGetProcAddress, reinterpret_cast<FARPROC>(OriginalGetProcAddress), &HookGetProcAddress);
    auto base = GetModuleHandleW(L"kernelbase.dll");
    auto procedure = base ? GetProcAddress(base, "GetProcAddress") : nullptr;
    if (procedure != reinterpret_cast<FARPROC>(&::GetProcAddress))
        add(OriginalBaseGetProcAddress, procedure, &HookBaseGetProcAddress);
    add(OriginalGetProcAddressForCaller, base ? GetProcAddress(base, "GetProcAddressForCaller") : nullptr,
        &HookGetProcAddressForCaller);
}

void StartModuleNotifications()
{
    if (ModuleNotificationCookie) return;
    auto module = GetModuleHandleW(L"ntdll.dll");
    auto registration = reinterpret_cast<RegisterNotifications>(GetProcAddress(module, "LdrRegisterDllNotification"));
    if (!registration || registration(0, ObserveModuleChange, nullptr, &ModuleNotificationCookie) < 0)
        InterlockedExchange(&ModuleNotificationError, ERROR_NOT_SUPPORTED);
}

void EnableModuleRefresh()
{
    InterlockedExchange(&ModuleRefreshReady, 1);
}

}

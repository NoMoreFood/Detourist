#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "SystemHooks.h"
#include "ExportFunction.h"
#include <intrin.h>
#include <algorithm>
#include <limits>
#include <unordered_set>

extern "C" unsigned long _tls_index;

namespace Detourist
{
uint32_t NativeExportCount = 0;
char UnknownNativeExports[UnknownNativeExportsCapacity]{};
uintptr_t NativeImageStart = 0;
uintptr_t NativeImageEnd = 0;
DWORD NativeThreadStatus() { return static_cast<DWORD>(NtCurrentTeb()->LastStatusValue); }
void RestoreNativeThreadStatus(DWORD status) { NtCurrentTeb()->LastStatusValue = static_cast<NTSTATUS>(status); }
bool NativeThreadReady()
{
    if (ProcessShuttingDown) return false;
    // Loader syscalls can precede this DLL's TLS allocation on a newly created thread.
    auto slots = reinterpret_cast<void**>(NtCurrentTeb()->ThreadLocalStoragePointer);
    return slots && slots[_tls_index];
}

void PrepareNativeTermination(HANDLE process)
{
    // Process teardown kills observer threads before CRT destructors release the pinned transport.
    if (!process || process == reinterpret_cast<HANDLE>(-1)) InterlockedExchange(&ProcessShuttingDown, 1);
}

bool NativeStackSafe(uint64_t caller)
{
    if (caller >= NativeImageStart && caller < NativeImageEnd) return false;
    // Loader hooks can run while the unwind table is exclusively locked by this same thread.
    auto loaderLock = NtCurrentTeb()->ProcessEnvironmentBlock->LoaderLock;
    return !loaderLock || !loaderLock->OwningThread;
}

#define NATIVE_API(name, status, ...) using Type##name = __VA_ARGS__;
#include "NativeCatalog.inc"
#undef NATIVE_API

FARPROC NativeInteropObserver(FARPROC function)
{
    // Catalog policies retain original entries for context transfers and process creation.
#define NATIVE_API(name, ...) \
    if (function == reinterpret_cast<FARPROC>(SystemHook<Api::name, Type##name, true>::original)) \
        return (ApiDefinitions[static_cast<uint32_t>(Api::name)].hookFlags & HookDirectInterop) ? function : \
            reinterpret_cast<FARPROC>(&SystemHook<Api::name, Type##name, true>::Invoke);
#include "NativeCatalog.inc"
#undef NATIVE_API
    return function;
}

void EmitNative(Call& call, Slot* slot, bool leaving)
{
    CaptureBuiltinParameters(call, slot, leaving);
}

template<Api Id, class Function> void* NativeObserverEntry(void** original)
{
#ifndef _WIN64
    if (Definition(Id).hookFlags & HookContinuation)
        return PrepareNativeContinuation(Id, original, ExportFunction<Function>::Signature());
#else
    (void)original;
#endif
    return reinterpret_cast<void*>(&SystemHook<Id, Function, true>::Invoke);
}

void AddNativeHooks(std::vector<HookDefinition>& hooks)
{
    auto module = GetModuleHandleW(L"ntdll.dll");
    if (!module) return;

    // Nt and Zw normally share an address; preserve installed trampolines across capture sessions.
    std::unordered_set<Api> existing;
    for (const auto& hook : hooks) existing.insert(hook.api);
#define NATIVE_API(name, ...) \
    if (!existing.contains(Api::name)) \
    { \
        auto& original = SystemHook<Api::name, Type##name, true>::original; \
        original = reinterpret_cast<Type##name>(GetProcAddress(module, #name)); \
        if (original) hooks.push_back({Api::name, reinterpret_cast<void**>(&original), \
            NativeObserverEntry<Api::name, Type##name>(reinterpret_cast<void**>(&original))}); \
    }
#include "NativeCatalog.inc"
#undef NATIVE_API

    // Report exports whose signatures are absent instead of guessing a calling convention or parameter count.
    NativeExportCount = 0;
    UnknownNativeExports[0] = 0;
    auto base = reinterpret_cast<const std::byte*>(module);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    NativeImageStart = reinterpret_cast<uintptr_t>(module);
    NativeImageEnd = NativeImageStart + nt->OptionalHeader.SizeOfImage;
    auto directory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto names = reinterpret_cast<const DWORD*>(base + directory->AddressOfNames);
    for (DWORD index = 0; index < directory->NumberOfNames; ++index)
    {
        auto name = reinterpret_cast<const char*>(base + names[index]);
        if (name[0] != 'N' || name[1] != 't' || name[2] < 'A' || name[2] > 'Z') continue;
        ++NativeExportCount;
        bool known = std::any_of(std::begin(ApiDefinitions), std::end(ApiDefinitions), [&](const auto& definition)
        {
            return strcmp(definition.name, name) == 0;
        });
        if (known) continue;
        auto used = strlen(UnknownNativeExports);
        auto length = strlen(name);
        if (used + length + 2 >= sizeof(UnknownNativeExports)) continue;
        if (used) UnknownNativeExports[used++] = ',';
        memcpy(UnknownNativeExports + used, name, length + 1);
    }
}
}

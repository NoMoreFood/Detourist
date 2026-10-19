#include <windows.h>
#include <winternl.h>
#include <cstring>
#include <cstdint>
#include <string>

extern "C" NTSTATUS NTAPI SymbolSyscall(HANDLE, HANDLE, PIO_APC_ROUTINE, void*, IO_STATUS_BLOCK*,
    const void*, ULONG, LARGE_INTEGER*, ULONG*, DWORD);

DWORD SymbolSyscallNumber()
{
    wchar_t path[MAX_PATH + 16]{};
    auto length = GetSystemDirectoryW(path, MAX_PATH);
    if (!length || length >= MAX_PATH) return MAXDWORD;
    wcscat_s(path, L"\\ntdll.dll");
    auto file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return MAXDWORD;
    auto mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr);
    auto image = mapping ? static_cast<const BYTE*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0)) : nullptr;
    DWORD service = MAXDWORD;
    if (image)
    {
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + dos->e_lfanew);
        auto exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            image + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        auto names = reinterpret_cast<const DWORD*>(image + exports->AddressOfNames);
        auto ordinals = reinterpret_cast<const WORD*>(image + exports->AddressOfNameOrdinals);
        auto functions = reinterpret_cast<const DWORD*>(image + exports->AddressOfFunctions);
        for (DWORD index = 0; index < exports->NumberOfNames; ++index)
            if (!strcmp(reinterpret_cast<const char*>(image + names[index]), "NtWriteFile"))
            {
                auto code = image + functions[ordinals[index]];
#ifdef _WIN64
                if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8)
                    memcpy(&service, code + 4, sizeof(service));
#else
                if (code[0] == 0xB8) memcpy(&service, code + 1, sizeof(service));
#endif
                break;
            }
        UnmapViewOfFile(image);
    }
    if (mapping) CloseHandle(mapping);
    CloseHandle(file);
    return service;
}

__declspec(noinline) BOOL SYMBOL_INNER(HANDLE file, DWORD mode)
{
    const char normal[] = SYMBOL_LABEL;
    const char locked[] = "Locked" SYMBOL_LABEL;
    const char deep[] = "Deep" SYMBOL_LABEL;
    const char capped[] = "Capped" SYMBOL_LABEL;
    const char* message = mode == 2 ? locked : mode == 4 ? deep : mode == 5 ? capped : normal;
    const auto length = static_cast<DWORD>(strlen(message));
    if (mode != 1 && mode != 3)
    {
        DWORD written = 0;
        return WriteFile(file, message, length, &written, nullptr) && written == length;
    }
    using NativeWrite = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PIO_APC_ROUTINE, void*, IO_STATUS_BLOCK*,
        const void*, ULONG, LARGE_INTEGER*, ULONG*);
    auto write = reinterpret_cast<NativeWrite>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteFile"));
    IO_STATUS_BLOCK status{};
    if (mode == 3)
    {
        const auto service = SymbolSyscallNumber();
        return service != MAXDWORD && SymbolSyscall(file, nullptr, nullptr, nullptr, &status, message, length,
            nullptr, nullptr, service) == 0 && status.Information == length;
    }
    return write && write(file, nullptr, nullptr, nullptr, &status, message, length,
        nullptr, nullptr) == 0 && status.Information == length;
}

__declspec(noinline) BOOL SYMBOL_OUTER(HANDLE file, DWORD mode)
{
    // Retain repeated callers so full walks and depth-limited walks can be checked independently.
    volatile BOOL result = mode >= 256 ? SYMBOL_OUTER(file, mode - 256) : SYMBOL_INNER(file, mode);
    return result;
}

extern "C" __declspec(dllexport) BOOL WINAPI SymbolCapture(HANDLE file, DWORD mode)
{
    return SYMBOL_OUTER(file, mode);
}

extern "C" __declspec(dllexport) BOOL WINAPI SymbolLocked(HANDLE file)
{
    using Lock = NTSTATUS(NTAPI*)(ULONG, ULONG*, ULONG_PTR*);
    using Unlock = NTSTATUS(NTAPI*)(ULONG, ULONG_PTR);
    auto native = GetModuleHandleW(L"ntdll.dll");
    auto lock = reinterpret_cast<Lock>(GetProcAddress(native, "LdrLockLoaderLock"));
    auto unlock = reinterpret_cast<Unlock>(GetProcAddress(native, "LdrUnlockLoaderLock"));
    ULONG disposition = 0;
    ULONG_PTR cookie = 0;
    if (!lock || !unlock || lock(0, &disposition, &cookie) < 0) return FALSE;
    const auto result = SYMBOL_OUTER(file, 2);
    return unlock(0, cookie) == 0 && result;
}

#ifdef _WIN64
struct SymbolCallback
{
    volatile LONG lookups = 0;
    PRUNTIME_FUNCTION function = nullptr;
};
PRUNTIME_FUNCTION CALLBACK SymbolUnwindCallback(DWORD64, void* context)
{
    const auto callback = static_cast<SymbolCallback*>(context);
    InterlockedIncrement(&callback->lookups);
    return callback->function;
}
#endif

extern "C" __declspec(dllexport) BOOL WINAPI SymbolDynamic(HANDLE file, DWORD mode)
{
    [[maybe_unused]] const bool preexisting = (mode & 0x100) != 0;
    mode &= 0xFF;
    auto code = static_cast<BYTE*>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!code) return FALSE;
    char message[] = "Dynamic" SYMBOL_LABEL;
    if (mode) memcpy(message, mode == 2 || mode == 3 || mode == 5 ? "TableNo" : "TableOn", 7);
    DWORD written = 0;
#ifdef _WIN64
    BYTE stub[]{0x48, 0x83, 0xEC, 0x38, 0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,
        0x41, 0xB8, sizeof(message) - 1, 0, 0, 0, 0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0, 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x38, 0xC3};
    const auto text = reinterpret_cast<uint64_t>(message);
    const auto output = reinterpret_cast<uint64_t>(&written);
    const auto write = reinterpret_cast<uint64_t>(&WriteFile);
    memcpy(stub + 6, &text, sizeof(text));
    memcpy(stub + 22, &output, sizeof(output));
    memcpy(stub + 41, &write, sizeof(write));
#else
    BYTE stub[]{0x6A, 0, 0x68, 0, 0, 0, 0, 0x68, sizeof(message) - 1, 0, 0, 0,
        0x68, 0, 0, 0, 0, 0xFF, 0x74, 0x24, 0x14, 0xB8, 0, 0, 0, 0, 0xFF, 0xD0, 0xC2, 4, 0};
    const auto text = reinterpret_cast<uintptr_t>(message);
    const auto output = reinterpret_cast<uintptr_t>(&written);
    const auto write = reinterpret_cast<uintptr_t>(&WriteFile);
    memcpy(stub + 3, &output, sizeof(output));
    memcpy(stub + 13, &text, sizeof(text));
    memcpy(stub + 22, &write, sizeof(write));
#endif
    memcpy(code, stub, sizeof(stub));
#ifdef _WIN64
    auto function = reinterpret_cast<PRUNTIME_FUNCTION>(code + 128);
    const auto unwindOffset = mode == 3 || mode == 5 ? 4096u : 192u;
    *function = {0, sizeof(stub), unwindOffset};
    if (mode == 4)
    {
        function[0] = {64, 80, unwindOffset};
        function[1] = {80, 96, unwindOffset};
        function[2] = {0, sizeof(stub), unwindOffset};
    }
    const BYTE unwind[]{1, 4, 1, 0, 4, 0x62, 0, 0};
    memcpy(code + unwindOffset, unwind, sizeof(unwind));
#endif
    DWORD protection = 0;
    auto result = VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &protection) &&
        FlushInstructionCache(GetCurrentProcess(), code, sizeof(stub));

    // Exercise table lifetimes and passive reuse of metadata returned by application lookups.
#ifdef _WIN64
    bool waiting = preexisting;
    auto invoke = [&]()
    {
        if (waiting)
        {
            const auto name = L"Local\\Detourist.Symbol." + std::to_wstring(GetCurrentProcessId());
            auto ready = CreateEventW(nullptr, TRUE, FALSE, (name + L".Ready").c_str());
            auto gate = CreateEventW(nullptr, TRUE, FALSE, (name + L".Gate").c_str());
            const auto resumed = ready && gate && SetEvent(ready) && WaitForSingleObject(gate, 60000) == WAIT_OBJECT_0;
            if (ready) CloseHandle(ready);
            if (gate) CloseHandle(gate);
            if (!resumed) return false;
            waiting = false;
        }
        return reinterpret_cast<BOOL(WINAPI*)(HANDLE)>(code)(file) && written == sizeof(message) - 1;
    };
    if (mode == 1 || mode == 3 || mode == 4)
    {
        const auto registered = result && RtlAddFunctionTable(function, mode == 4 ? 3 : 1,
            reinterpret_cast<DWORD64>(code));
        if (mode == 3 && registered)
        {
            // Guarded unwind data must remain unread, including its application's pending guard exception.
            result = VirtualProtect(code + 4096, 4096, PAGE_READWRITE | PAGE_GUARD, &protection) && invoke();
            MEMORY_BASIC_INFORMATION region{};
            result &= VirtualQuery(code + 4096, &region, sizeof(region)) && (region.Protect & PAGE_GUARD);
            result &= VirtualProtect(code + 4096, 4096, PAGE_READWRITE, &protection) != FALSE;
        }
        else result = registered && invoke();
        if (registered)
        {
            result &= RtlDeleteFunctionTable(function) != FALSE;
            if (mode != 3)
            {
                memcpy(message, "TableNo", 7);
                result &= invoke();
            }
        }
    }
    else if (mode == 2)
    {
        using Add = DWORD(NTAPI*)(void**, PRUNTIME_FUNCTION, DWORD, DWORD, ULONG_PTR, ULONG_PTR);
        using Grow = void(NTAPI*)(void*, DWORD);
        using Delete = void(NTAPI*)(void*);
        auto native = GetModuleHandleW(L"ntdll.dll");
        auto add = reinterpret_cast<Add>(GetProcAddress(native, "RtlAddGrowableFunctionTable"));
        auto grow = reinterpret_cast<Grow>(GetProcAddress(native, "RtlGrowFunctionTable"));
        auto remove = reinterpret_cast<Delete>(GetProcAddress(native, "RtlDeleteGrowableFunctionTable"));
        void* table = nullptr;
        const auto base = reinterpret_cast<ULONG_PTR>(code);
        const auto registered = result && add && grow && remove && add(&table, function, 0, 1, base, base + 4096) == 0;
        result = registered && invoke();
        if (registered)
        {
            grow(table, 1);
            memcpy(message, "TableOn", 7);
            result &= invoke();
            remove(table);
            memcpy(message, "TableNo", 7);
            result &= invoke();
        }
    }
    else
    {
        SymbolCallback callback{0, mode == 5 ? function : nullptr};
        const auto base = reinterpret_cast<DWORD64>(code);
        const auto table = base | 3;
        auto registered = result && RtlInstallFunctionTableCallback(table, base,
            8192, SymbolUnwindCallback, &callback, nullptr);
        result = registered && invoke() && !callback.lookups;
        if (registered && mode == 5)
        {
            DWORD64 image = 0;
            result &= RtlLookupFunctionEntry(base + 50, &image, nullptr) == function && image == base;
            memcpy(message, "TableOn", 7);
            result &= invoke() && callback.lookups == 1;

            // Cached function entries must still respect guard protection on the application's unwind data.
            memcpy(message, "TableNo", 7);
            result &= VirtualProtect(code + 4096, 4096, PAGE_READWRITE | PAGE_GUARD, &protection) && invoke();
            MEMORY_BASIC_INFORMATION region{};
            result &= VirtualQuery(code + 4096, &region, sizeof(region)) && (region.Protect & PAGE_GUARD);
            result &= VirtualProtect(code + 4096, 4096, PAGE_READWRITE, &protection) != FALSE;
            memcpy(message, "TableOn", 7);
            result &= invoke() && callback.lookups == 1;

            // A naturally failed lookup invalidates its previously observed function.
            callback.function = nullptr;
            result &= RtlLookupFunctionEntry(base + 50, &image, nullptr) == nullptr;
            memcpy(message, "TableNo", 7);
            result &= invoke() && callback.lookups == 2;
            callback.function = function;
            result &= RtlLookupFunctionEntry(base + 50, &image, nullptr) == function;
            memcpy(message, "TableOn", 7);
            result &= invoke() && callback.lookups == 3;

            // Reusing the same identifier must not reuse the retired registration's cached function.
            result &= RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(table)) != FALSE;
            memcpy(message, "TableNo", 7);
            result &= invoke() && callback.lookups == 3;
            registered = RtlInstallFunctionTableCallback(table, base, 8192, SymbolUnwindCallback, &callback, nullptr);
            result &= registered && invoke() && callback.lookups == 3;
            result &= RtlLookupFunctionEntry(base + 50, &image, nullptr) == function;
            memcpy(message, "TableOn", 7);
            result &= invoke() && callback.lookups == 4;
        }
        if (registered) result &= RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(table)) != FALSE;
    }
#else
    if (result) result = reinterpret_cast<BOOL(WINAPI*)(HANDLE)>(code)(file) && written == sizeof(message) - 1;
#endif
    VirtualFree(code, 0, MEM_RELEASE);
    return result;
}

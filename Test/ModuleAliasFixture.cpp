#include <windows.h>
#include <cstddef>
#ifdef DETOURIST_PRIVATE_HOTPATCH
#include <cstdint>
#include <cstring>
#include <cwchar>
#endif

extern "C" __declspec(dllexport) int __cdecl CRYPTO_memcmp(const void* first, const void* second, size_t bytes)
{
    return first && second && bytes == 7 ? 37 : -1;
}

extern "C" __declspec(dllexport) const char* __cdecl SSL_get_version(const void* value)
{
    return value ? "Fixture" : nullptr;
}

extern "C" __declspec(dllexport) void WINAPI X3DAudioCalculate(const void*, const void*, const void*, UINT32, void*)
{
}

__declspec(noinline) HRESULT WINAPI Compile(const void* source, SIZE_T bytes, const char* name, const void* defines,
    void* include, const char* entry, const char* target, UINT flags, UINT effects, void** code, void** errors)
{
    return source || bytes || name || defines || include || entry || target || flags || effects || code || errors ?
        E_INVALIDARG : E_FAIL;
}

extern "C" __declspec(dllexport) __declspec(noinline) HRESULT WINAPI D3DCompile(const void* source, SIZE_T bytes,
    const char* name, const void* defines, void* include, const char* entry, const char* target,
    UINT flags, UINT effects, void** code, void** errors)
{
    return Compile(source, bytes, name, defines, include, entry, target, flags, effects, code, errors);
}

#ifdef DETOURIST_PRIVATE_HOTPATCH
void* PrivateCode = nullptr;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void*)
{
    if (reason == DLL_PROCESS_DETACH)
    {
        if (PrivateCode) VirtualFree(PrivateCode, 0, MEM_RELEASE);
        return TRUE;
    }
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    wchar_t path[MAX_PATH]{};
    auto length = GetModuleFileNameW(instance, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return FALSE;
    const bool privateEntry = wcsstr(path, L"private-entry") != nullptr;

    // A loader-owned export can redirect through a hotpatch to code outside every loaded image.
    auto entry = reinterpret_cast<BYTE*>(&D3DCompile);
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto base = reinterpret_cast<uintptr_t>(entry) & ~(uintptr_t{system.dwAllocationGranularity} - 1);
    for (uintptr_t distance = system.dwAllocationGranularity; !PrivateCode && distance < 0x7FFF0000;
        distance += system.dwAllocationGranularity)
    {
        if (base <= UINTPTR_MAX - distance)
            PrivateCode = VirtualAlloc(reinterpret_cast<void*>(base + distance), 64,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!PrivateCode) return FALSE;
    auto code = static_cast<BYTE*>(PrivateCode);
    auto destination = reinterpret_cast<uintptr_t>(&Compile);
#ifdef _WIN64
    code[0] = 0x48;
    code[1] = 0xB8;
    memcpy(code + 2, &destination, sizeof(destination));
    code[10] = 0xFF;
    code[11] = 0xE0;
#else
    code[0] = 0xB8;
    memcpy(code + 1, &destination, sizeof(destination));
    code[5] = 0xFF;
    code[6] = 0xE0;
#endif
    DWORD previous = 0, ignored = 0;
    MEMORY_BASIC_INFORMATION region{};
    bool prepared = VirtualProtect(code, 64, PAGE_EXECUTE_READ, &ignored) &&
        FlushInstructionCache(GetCurrentProcess(), code, 64) &&
        VirtualQuery(code, &region, sizeof(region)) && region.State == MEM_COMMIT && region.Type == MEM_PRIVATE;
    for (int index = 1; prepared && !privateEntry && index <= 5; ++index)
        prepared = entry[-index] == 0xCC || entry[-index] == 0x90;
    if (prepared && privateEntry)
    {
        // An export can itself point outside its provider image before the observer resolves it.
        auto image = reinterpret_cast<BYTE*>(instance);
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + dos->e_lfanew);
        auto exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            image + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        auto names = reinterpret_cast<const DWORD*>(image + exports->AddressOfNames);
        auto ordinals = reinterpret_cast<const WORD*>(image + exports->AddressOfNameOrdinals);
        auto functions = reinterpret_cast<DWORD*>(image + exports->AddressOfFunctions);
        prepared = false;
        for (DWORD index = 0; index < exports->NumberOfNames; ++index)
        {
            if (strcmp(reinterpret_cast<const char*>(image + names[index]), "D3DCompile")) continue;
            auto slot = &functions[ordinals[index]];
            if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &previous)) break;
            *slot = static_cast<DWORD>(reinterpret_cast<uintptr_t>(code) - reinterpret_cast<uintptr_t>(image));
            prepared = VirtualProtect(slot, sizeof(*slot), previous, &ignored) != FALSE;
            break;
        }
    }
    else if (prepared && (prepared = VirtualProtect(entry - 5, 7, PAGE_EXECUTE_READWRITE, &previous) != FALSE))
    {
        auto displacement = static_cast<int32_t>(static_cast<int64_t>(reinterpret_cast<uintptr_t>(code)) -
            static_cast<int64_t>(reinterpret_cast<uintptr_t>(entry)));
        entry[-5] = 0xE9;
        memcpy(entry - 4, &displacement, sizeof(displacement));
        entry[0] = 0xEB;
        entry[1] = 0xF9;
        prepared = VirtualProtect(entry - 5, 7, previous, &ignored) &&
            FlushInstructionCache(GetCurrentProcess(), entry - 5, 7);
    }
    if (prepared) return TRUE;
    VirtualFree(PrivateCode, 0, MEM_RELEASE);
    PrivateCode = nullptr;
    return FALSE;
}
#endif

extern "C" __declspec(dllexport) HRESULT WINAPI D3DX11CreateFFT(void*, const void*, UINT, void*, void** output)
{
    if (output) *output = nullptr;
    return S_OK;
}

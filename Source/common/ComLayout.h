#pragma once
#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)

namespace Detourist
{
// DirectSound and KSProxy declare incompatible method layouts under the same IID.
inline constexpr GUID KsPropertySetIid{0x31efac30, 0x515c, 0x11d0, {0xa9, 0xaa, 0, 0xaa, 0, 0x61, 0xbe, 0x93}};

inline bool IsSystemDirectSound(void* table)
{
    MEMORY_BASIC_INFORMATION image{};
    if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), table, MemoryBasicInformation,
        &image, sizeof(image), nullptr)) || image.Type != MEM_IMAGE) return false;

    // Open the system copy for this architecture independently of the provider's loader path.
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\dsound.dll");
#ifndef _WIN64
    if (USER_SHARED_DATA->NativeProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL)
        RtlInitUnicodeString(&name, L"\\SystemRoot\\SysWOW64\\dsound.dll");
#endif
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK io;
    HANDLE file, section;
    if (!NT_SUCCESS(NtOpenFile(&file, FILE_READ_DATA, &attributes, &io,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0))) return false;
    auto status = NtCreateSection(&section, SECTION_MAP_READ, nullptr, nullptr, PAGE_READONLY, SEC_COMMIT, file);
    NtClose(file);
    if (!NT_SUCCESS(status)) return false;

    // Compare the backing files using a read-only data view without loading another image.
    void* view = nullptr;
    SIZE_T size = 1;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &view, 0, 0, nullptr, &size, ViewUnmap, 0, PAGE_READONLY);
    NtClose(section);
    if (!NT_SUCCESS(status)) return false;
    const bool same = NtAreMappedFilesTheSame(image.AllocationBase, view) == STATUS_SUCCESS;
    NtUnmapViewOfSection(NtCurrentProcess(), view);
    return same;
}
}

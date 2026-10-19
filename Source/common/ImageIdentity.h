#pragma once
#include "Protocol.h"
#include <algorithm>
#include <cstring>

namespace Detourist
{
constexpr uint32_t CodeViewRsdsSignature = 0x53445352;
constexpr uint32_t MaxPeHeaderOffset = 1024 * 1024;
constexpr DWORD MaxDebugDirectories = 64;
constexpr size_t CodeViewTailBytes = 2048;

template<class Reader> bool ReadImageIdentity(uint64_t base, uint64_t size, ModuleIdentity& identity, Reader read)
{
    identity = {};
    auto extent = size ? size : UINT32_MAX;
    auto get = [&](uint64_t offset, void* value, size_t bytes)
    {
        return offset <= extent && bytes <= extent - offset && base <= UINT64_MAX - offset &&
            read(base + offset, value, bytes);
    };
    IMAGE_DOS_HEADER dos{};
    struct Header { DWORD signature; IMAGE_FILE_HEADER file; } header{};
    if (!get(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
        static_cast<uint32_t>(dos.e_lfanew) > MaxPeHeaderOffset ||
        !get(dos.e_lfanew, &header, sizeof(header)) || header.signature != IMAGE_NT_SIGNATURE) return false;
    const auto optional = static_cast<uint64_t>(dos.e_lfanew) + sizeof(header);
    WORD magic = 0;
    IMAGE_DATA_DIRECTORY debug{};
    ModuleIdentity value{};
    if (!get(optional, &magic, sizeof(magic))) return false;

    // Read PE32 and PE32+ headers independently of the controller's own architecture.
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER64 image{};
        if (header.file.SizeOfOptionalHeader < sizeof(image) || !get(optional, &image, sizeof(image))) return false;
        value.imageSize = image.SizeOfImage;
        value.checksum = image.CheckSum;
        if (image.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
            debug = image.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER32 image{};
        if (header.file.SizeOfOptionalHeader < sizeof(image) || !get(optional, &image, sizeof(image))) return false;
        value.imageSize = image.SizeOfImage;
        value.checksum = image.CheckSum;
        if (image.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
            debug = image.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }
    else return false;
    if (!value.imageSize || size && value.imageSize != size) return false;
    extent = value.imageSize;
    value.timestamp = header.file.TimeDateStamp;
    value.machine = header.file.Machine;
    value.flags = ImageIdentityValid;

    // A bounded read of the CodeView tail retains the filename without following its build-machine path.
    for (uint32_t index = 0;
        index < std::min<DWORD>(debug.Size / sizeof(IMAGE_DEBUG_DIRECTORY), MaxDebugDirectories); ++index)
    {
        IMAGE_DEBUG_DIRECTORY entry{};
        struct CodeView { uint32_t signature; GUID pdb; uint32_t age; } codeView{};
        if (!get(uint64_t{debug.VirtualAddress} + index * sizeof(entry), &entry, sizeof(entry))) break;
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData <= sizeof(codeView) ||
            !entry.AddressOfRawData || entry.AddressOfRawData > extent ||
            entry.SizeOfData > extent - entry.AddressOfRawData ||
            !get(entry.AddressOfRawData, &codeView, sizeof(codeView)) ||
            codeView.signature != CodeViewRsdsSignature) continue;
        char tail[CodeViewTailBytes]{};
        const auto bytes = std::min<DWORD>(entry.SizeOfData - static_cast<DWORD>(sizeof(codeView)), sizeof(tail));
        const auto skipped = entry.SizeOfData - static_cast<uint32_t>(sizeof(codeView)) - bytes;
        if (!get(uint64_t{entry.AddressOfRawData} + sizeof(codeView) + skipped, tail, bytes)) continue;
        uint32_t begin = 0, end = 0;
        while (end < bytes && tail[end])
        {
            if (tail[end] == '\\' || tail[end] == '/') begin = end + 1;
            ++end;
        }
        if (end == bytes || end == begin || end - begin >= sizeof(value.pdbName) || skipped && !begin) continue;
        memcpy(value.pdbName, tail + begin, end - begin);
        value.pdb = codeView.pdb;
        value.pdbAge = codeView.age;
        value.flags |= PdbIdentityValid;
        break;
    }
    identity = value;
    return true;
}
}

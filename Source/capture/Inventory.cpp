#include "Inventory.h"
#include <tlhelp32.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <map>

namespace Detourist
{
std::vector<ProcessInfo> Processes()
{
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    Check(static_cast<bool>(snapshot), "List processes");
    PROCESSENTRY32W entry{sizeof(entry)};
    std::vector<ProcessInfo> result;
    if (Process32FirstW(snapshot.get(), &entry))
    {
        do
        {
            if (!entry.th32ProcessID || entry.th32ProcessID == GetCurrentProcessId()) continue;
            ProcessInfo item{entry.th32ProcessID, entry.szExeFile, L"Unavailable"};
            Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID));
            if (auto machine = process ? ProcessMachine(process.get()) : IMAGE_FILE_MACHINE_UNKNOWN)
            {
                item.architecture = machine == IMAGE_FILE_MACHINE_AMD64 ? L"x64" :
                    machine == IMAGE_FILE_MACHINE_I386 ? L"x86" :
                    machine == IMAGE_FILE_MACHINE_ARM64 ? L"ARM64" : L"Other";
            }
            result.push_back(std::move(item));
        } while (Process32NextW(snapshot.get(), &entry));
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right)
    {
        return _wcsicmp(left.name.c_str(), right.name.c_str()) < 0;
    });
    return result;
}

std::vector<ExportInfo> ReadExports(const std::wstring& file)
{
    constexpr std::streamoff MaxPeImageBytes = 512ll * 1024 * 1024;
    constexpr size_t MaxExportNameBytes = 65536;
    constexpr uint32_t MaxExportEntries = 1000000;
    std::ifstream input(std::filesystem::path(file), std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("Cannot open the selected image.");
    auto size = input.tellg();
    if (size < sizeof(IMAGE_DOS_HEADER) || size > MaxPeImageBytes)
        throw std::runtime_error("The selected image has an unsupported size.");
    std::vector<std::byte> bytes(static_cast<size_t>(size));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(bytes.data()), size)) throw std::runtime_error("Cannot read the image.");
    auto range = [&](size_t position, size_t count) -> const std::byte*
    {
        if (position > bytes.size() || count > bytes.size() - position)
            throw std::runtime_error("The image contains an invalid file range.");
        return bytes.data() + position;
    };

    // Parse exports as data without loading or executing the inspected DLL.
    IMAGE_DOS_HEADER dos;
    memcpy(&dos, range(0, sizeof(dos)), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) throw std::runtime_error("Not a PE image.");
    DWORD signature;
    memcpy(&signature, range(dos.e_lfanew, sizeof(signature)), sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE) throw std::runtime_error("Not a PE image.");
    IMAGE_FILE_HEADER header;
    size_t position = static_cast<size_t>(dos.e_lfanew) + sizeof(signature);
    memcpy(&header, range(position, sizeof(header)), sizeof(header));
    position += sizeof(header);
    WORD magic;
    memcpy(&magic, range(position, sizeof(magic)), sizeof(magic));
    IMAGE_DATA_DIRECTORY exports{};
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && header.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        IMAGE_OPTIONAL_HEADER64 optional;
        memcpy(&optional, range(position, sizeof(optional)), sizeof(optional));
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
            exports = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && header.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        IMAGE_OPTIONAL_HEADER32 optional;
        memcpy(&optional, range(position, sizeof(optional)), sizeof(optional));
        if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
            exports = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else throw std::runtime_error("Unsupported PE optional header.");
    if (!exports.VirtualAddress) return {};
    position += header.SizeOfOptionalHeader;
    std::vector<IMAGE_SECTION_HEADER> sections(header.NumberOfSections);
    memcpy(sections.data(), range(position, sections.size() * sizeof(IMAGE_SECTION_HEADER)),
        sections.size() * sizeof(IMAGE_SECTION_HEADER));
    auto offset = [&](uint32_t rva, size_t length) -> size_t
    {
        for (const auto& section : sections)
        {
            if (rva >= section.VirtualAddress && uint64_t{rva} - section.VirtualAddress < section.SizeOfRawData)
            {
                auto delta = rva - section.VirtualAddress;
                if (length > section.SizeOfRawData - delta) break;
                auto location = size_t{section.PointerToRawData} + delta;
                range(location, length);
                return location;
            }
        }
        throw std::runtime_error("The export directory contains an invalid address.");
    };
    auto string = [&](uint32_t rva)
    {
        size_t location = offset(rva, 1);
        auto begin = reinterpret_cast<const char*>(bytes.data() + location);
        auto available = std::min<size_t>(bytes.size() - location, MaxExportNameBytes);
        auto end = static_cast<const char*>(memchr(begin, 0, available));
        if (!end) throw std::runtime_error("An export name is not terminated.");
        return std::string(begin, end);
    };
    IMAGE_EXPORT_DIRECTORY directory;
    memcpy(&directory, range(offset(exports.VirtualAddress, sizeof(directory)), sizeof(directory)), sizeof(directory));
    if (directory.NumberOfFunctions > MaxExportEntries || directory.NumberOfNames > MaxExportEntries)
        throw std::runtime_error("The export table exceeds the analysis limit.");
    if (!directory.NumberOfFunctions) return {};
    std::map<uint32_t, std::vector<std::string>> names;
    auto nameTable = directory.NumberOfNames ?
        offset(directory.AddressOfNames, size_t{directory.NumberOfNames} * sizeof(DWORD)) : 0;
    auto ordinalTable = directory.NumberOfNames ?
        offset(directory.AddressOfNameOrdinals, size_t{directory.NumberOfNames} * sizeof(WORD)) : 0;
    for (uint32_t index = 0; index < directory.NumberOfNames; ++index)
    {
        DWORD rva;
        WORD ordinal;
        memcpy(&rva, range(nameTable + index * sizeof(DWORD), sizeof(rva)), sizeof(rva));
        memcpy(&ordinal, range(ordinalTable + index * sizeof(WORD), sizeof(ordinal)), sizeof(ordinal));
        if (ordinal >= directory.NumberOfFunctions) throw std::runtime_error("Invalid export ordinal.");
        names[ordinal].push_back(string(rva));
    }
    std::vector<ExportInfo> result;
    auto functions = offset(directory.AddressOfFunctions, size_t{directory.NumberOfFunctions} * sizeof(DWORD));
    for (uint32_t index = 0; index < directory.NumberOfFunctions; ++index)
    {
        DWORD rva;
        memcpy(&rva, range(functions + index * sizeof(DWORD), sizeof(rva)), sizeof(rva));
        if (!rva) continue;
        ExportInfo item{"", index + directory.Base, rva, "", false};
        if (rva >= exports.VirtualAddress && uint64_t{rva} < uint64_t{exports.VirtualAddress} + exports.Size)
            item.forwarder = string(rva);
        else
            for (const auto& section : sections)
                if (rva >= section.VirtualAddress && uint64_t{rva} - section.VirtualAddress < section.Misc.VirtualSize)
                    item.executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        auto found = names.find(index);
        if (found == names.end())
        {
            item.name = "#" + std::to_string(item.ordinal);
            result.push_back(std::move(item));
        }
        else for (const auto& name : found->second) { item.name = name; result.push_back(item); }
    }
    return result;
}
}

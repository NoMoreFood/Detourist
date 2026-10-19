#include "InstructionEngine.h"
#pragma warning(push, 0)
#include "dr_defines.h"
#include "dr_config.h"
#pragma warning(pop)
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>
#include <memory>

namespace Detourist
{
std::vector<BYTE> WindowSyscallStackBytes()
{
    // The installed kernel image publishes the stack-byte count for each win32u service.
    wchar_t system[MAX_PATH]{};
    auto length = GetSystemDirectoryW(system, static_cast<UINT>(std::size(system)));
    if (!length || length >= std::size(system)) return {};
    auto path = std::wstring(system) + L"\\win32k.sys";
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr));
    Handle mapping(file ? CreateFileMappingW(file.get(), nullptr,
        PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr) : nullptr);
    std::unique_ptr<const BYTE, decltype(&UnmapViewOfFile)> image(
        mapping ? static_cast<const BYTE*>(MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0)) :
            nullptr, &UnmapViewOfFile);
    if (!image) return {};
    auto base = image.get();
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 4096)
        return {};
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return {};
    auto size = nt->OptionalHeader.SizeOfImage;
    auto within = [size](DWORD rva, size_t bytes)
    {
        return rva < size && bytes <= size - rva;
    };
    const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!within(directory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY))) return {};
    auto exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + directory.VirtualAddress);
    if (!within(exports->AddressOfNames, size_t{exports->NumberOfNames} * sizeof(DWORD)) ||
        !within(exports->AddressOfNameOrdinals, size_t{exports->NumberOfNames} * sizeof(WORD)) ||
        !within(exports->AddressOfFunctions, size_t{exports->NumberOfFunctions} * sizeof(DWORD)))
        return {};
    auto names = reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
    auto ordinals = reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
    auto functions = reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);
    DWORD limitRva = 0, tableRva = 0;
    for (DWORD index = 0; index < exports->NumberOfNames; ++index)
    {
        auto rva = names[index];
        if (!within(rva, sizeof("W32pArgumentTable")) ||
            ordinals[index] >= exports->NumberOfFunctions) continue;
        auto symbol = reinterpret_cast<const char*>(base + rva);
        if (!strcmp(symbol, "W32pServiceLimit")) limitRva = functions[ordinals[index]];
        if (!strcmp(symbol, "W32pArgumentTable")) tableRva = functions[ordinals[index]];
    }
    if (!within(limitRva, sizeof(DWORD))) return {};
    DWORD limit = 0;
    memcpy(&limit, base + limitRva, sizeof(limit));
    if (!limit || limit > 4096 || !within(tableRva, limit)) return {};
    return {base + tableRva, base + tableRva + limit};
}

void StartInstructionEngine(DWORD pid, uint64_t mapping, SharedHeader& header, bool launched,
    HANDLE startupToken)
{
    const auto root = ModuleDirectory() + L"\\instruction";
    auto configuration =
        LoadLibraryExW((root + L"\\bin" + std::to_wstring(sizeof(void*) * 8) + L"\\drconfiglib.dll").c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    using Library = std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)>;
    Library configurationOwner(configuration, &FreeLibrary);
    if (!configuration) throw std::runtime_error("The instruction engine is missing.");
    auto registerProcess = reinterpret_cast<decltype(&dr_register_process)>(
        GetProcAddress(configuration, "dr_register_process"));
    auto unregisterProcess = reinterpret_cast<decltype(&dr_unregister_process)>(
        GetProcAddress(configuration, "dr_unregister_process"));
    auto registerClient = reinterpret_cast<decltype(&dr_register_client)>(
        GetProcAddress(configuration, "dr_register_client"));
    if (!registerProcess || !unregisterProcess || !registerClient)
        throw std::runtime_error("The instruction engine could not be loaded.");

    // Resolve system call numbers from this machine's clean exports instead of using OS-version assumptions.
    struct Number
    {
        std::string name;
        DWORD service;
        bool window;
    };
    std::vector<Number> numbers;
    for (const auto library : {L"ntdll.dll", L"win32u.dll"})
    {
        Library module(LoadLibraryExW(library, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32), &FreeLibrary);
        if (!module) continue;
        const auto loaded = reinterpret_cast<const std::byte*>(module.get());
        const auto loadedDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(loaded);
        const auto loadedNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(loaded + loadedDos->e_lfanew);

        // Prefer the installed image when it matches the loaded build, bypassing in-process inline hooks.
        wchar_t path[ExtendedPathCapacity]{};
        auto length = GetModuleFileNameW(module.get(), path, static_cast<DWORD>(std::size(path)));
        Handle imageFile(length && length < std::size(path) ? CreateFileW(path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr) : INVALID_HANDLE_VALUE);
        Handle imageMapping(imageFile ? CreateFileMappingW(imageFile.get(), nullptr,
            PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr) : nullptr);
        std::unique_ptr<const std::byte, decltype(&UnmapViewOfFile)> image(
            imageMapping ? static_cast<const std::byte*>(MapViewOfFile(imageMapping.get(), FILE_MAP_READ, 0, 0, 0)) :
                nullptr, &UnmapViewOfFile);
        const auto mappedDos = image ? reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get()) : nullptr;
        const auto mappedNt = mappedDos && mappedDos->e_magic == IMAGE_DOS_SIGNATURE && mappedDos->e_lfanew > 0 ?
            reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get() + mappedDos->e_lfanew) : nullptr;
        const auto base = mappedNt && mappedNt->Signature == IMAGE_NT_SIGNATURE &&
            mappedNt->FileHeader.TimeDateStamp == loadedNt->FileHeader.TimeDateStamp &&
            mappedNt->OptionalHeader.SizeOfImage == loadedNt->OptionalHeader.SizeOfImage ? image.get() : loaded;
        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        const auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!directory.VirtualAddress || directory.VirtualAddress + directory.Size >
            nt->OptionalHeader.SizeOfImage) continue;
        const auto exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + directory.VirtualAddress);
        const auto names = reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
        const auto ordinals = reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
        const auto functions = reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);

        // Keep each signature search inside its export instead of borrowing a following service's code.
        std::vector<DWORD> starts;
        starts.reserve(exports->NumberOfFunctions);
        for (DWORD index = 0; index < exports->NumberOfFunctions; ++index)
        {
            auto address = functions[index];
            if (address < nt->OptionalHeader.SizeOfImage &&
                !(address >= directory.VirtualAddress && address < directory.VirtualAddress + directory.Size))
                starts.push_back(address);
        }
        std::sort(starts.begin(), starts.end());
        starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
        for (DWORD index = 0; index < exports->NumberOfNames; ++index)
        {
            auto name = reinterpret_cast<const char*>(base + names[index]);
            if (name[0] != 'N' || name[1] != 't') continue;
            if (ordinals[index] >= exports->NumberOfFunctions) continue;
            auto address = functions[ordinals[index]];
            if (address >= directory.VirtualAddress && address < directory.VirtualAddress + directory.Size ||
                address >= nt->OptionalHeader.SizeOfImage) continue;
            auto following = std::upper_bound(starts.begin(), starts.end(), address);
            auto available = (following == starts.end() ? nt->OptionalHeader.SizeOfImage : *following) - address;
            auto limit = std::min<DWORD>(32, available);
            auto code = reinterpret_cast<const BYTE*>(base + address);
            for (uint32_t offset = 0; offset + 7 < limit; ++offset)
            {
                if (code[offset] != 0xB8) continue;
                DWORD number = 0;
                memcpy(&number, code + offset + 1, sizeof(number));
                bool syscall = false;
                for (uint32_t next = offset + 5; next + 1 < limit; ++next)
                    if ((code[next] == 0x0F &&
                            (code[next + 1] == 0x05 || sizeof(void*) == 4 && code[next + 1] == 0x34)) ||
                        sizeof(void*) == 4 &&
                            (code[next] == 0xFF && (code[next + 1] == 0xD2 || code[next + 1] == 0x12) ||
                                next + 6 < limit && code[next] == 0x64 && code[next + 1] == 0xFF &&
                                    code[next + 2] == 0x15))
                    {
                        syscall = true;
                        break;
                    }
                if (syscall && (sizeof(void*) == 4 ? number & 0xFFFF : number) < 8192)
                    numbers.push_back({name, number, !wcscmp(library, L"win32u.dll")});
                break;
            }
        }
    }
    auto discriminator = std::find_if(numbers.begin(), numbers.end(), [](const auto& value)
    {
        return value.name == "NtGetContextThread";
    });
    if (discriminator == numbers.end()) throw std::runtime_error("Cannot resolve this system's syscall numbers.");
    wchar_t temporary[MAX_PATH];
    Check(GetTempPathW(MAX_PATH, temporary) != 0, "Locate syscall metadata cache");
    auto suffix = std::to_wstring(pid) + L"." + std::to_wstring(header.captureIdentity);
    auto numberPath = std::wstring(temporary) + L"Detourist.Syscalls." + suffix + L".txt";
    std::ofstream file{std::filesystem::path(numberPath)};
    file << "DrSyscall Number File\n1\nNtGetContextThread\nSTART=0x" << std::hex << discriminator->service << "\n";
    auto stackBytes = sizeof(void*) == 8 ? WindowSyscallStackBytes() : std::vector<BYTE>{};
    for (const auto& entry : numbers)
    {
        file << entry.name << "=0x" << entry.service;
        auto index = entry.service - 0x1000;
        if (entry.window && index < stackBytes.size() && stackBytes[index] % 4 == 0 &&
            stackBytes[index] <= (MaximumArguments - 4) * 4)
            file << "|stack=" << std::dec << static_cast<unsigned>(stackBytes[index]) << std::hex;
        file << "\n";
    }
    file << "=END\n";
    file.close();
    if (!file) throw std::runtime_error("Cannot write the syscall metadata cache.");

    Handle process(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | SYNCHRONIZE, FALSE, pid));
    Check(static_cast<bool>(process), "Open instruction target");
    wchar_t application[ExtendedPathCapacity];
    DWORD characters = static_cast<DWORD>(std::size(application));
    Check(QueryFullProcessImageNameW(process.get(), 0, application, &characters) != FALSE,
        "Locate instruction target");
    // Load the native window-system provider before registering its syscall table.
    RemoteInvoke(process.get(), RemoteSystemProcedure(pid, reinterpret_cast<void*>(&LoadLibraryW)),
        L"win32u.dll", nullptr, startupToken);
    bool registered = false;
    auto processName = Utf8(std::filesystem::path(application).filename().wstring());
    try
    {
        auto engineRoot = Utf8(root);
        auto client = Utf8(ModuleDirectory() + L"\\DetouristInstructions.dll");
        auto arguments = std::to_string(mapping) + " " + std::to_string(header.captureIdentity) +
            " \"" + Utf8(numberPath) + "\"";
        // Keep modern CLR callbacks at their original addresses while observing legacy runtime exports.
        std::string runtimeOptions = "-no_follow_children -no_hide -stderr_mask 14 -msgbox_mask 0 "
            "-native_exec_list clr.dll;coreclr.dll;clrjit.dll;mscorjit.dll;hostfxr.dll;hostpolicy.dll;"
            "DetouristProfiler.dll -native_exec_retakeover -no_native_exec_managed_code -skip_terminating_threads";

        // Preserve active CLR frames when joining an existing process.
        if (!launched) runtimeOptions += " -no_native_exec_guess_calls";
        Check(registerProcess(processName.c_str(), pid, false, engineRoot.c_str(), DR_MODE_CODE_MANIPULATION,
            false, (sizeof(void*) == 8 ? DR_PLATFORM_64BIT : DR_PLATFORM_32BIT), runtimeOptions.c_str()) == DR_SUCCESS,
            "Configure instruction capture");
        registered = true;
        Check(registerClient(processName.c_str(), pid, false,
                  (sizeof(void*) == 8 ? DR_PLATFORM_64BIT : DR_PLATFORM_32BIT), 0, 0, client.c_str(),
                  arguments.c_str()) == DR_SUCCESS,
            "Configure instruction observer");
        auto runtimePath = root + L"\\lib" + std::to_wstring(sizeof(void*) * 8) + L"\\release\\dynamorio.dll";
        auto agentPath = ModuleDirectory() + L"\\DetouristAgent.dll";
        Library localAgent(LoadLibraryExW(agentPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES), &FreeLibrary);
        Check(static_cast<bool>(localAgent), "Inspect instruction bootstrap");
        auto start = GetProcAddress(localAgent.get(), "DetouristStartInstructions");
        if (!start) throw std::runtime_error("The instruction bootstrap export is missing.");
        auto offset = reinterpret_cast<uintptr_t>(start) - reinterpret_cast<uintptr_t>(localAgent.get());
        auto agent = LoadCaptureAgent(process.get(), pid, agentPath, nullptr, startupToken);
        header.instructionState = static_cast<LONG>(InstructionState::Starting);
        auto startupText = runtimePath + L"|" + std::to_wstring(mapping) + L"|" +
            std::to_wstring(header.captureIdentity);
        auto bytes = (startupText.size() + 1) * sizeof(wchar_t);
        auto memory = VirtualAllocEx(process.get(), nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Check(memory != nullptr, "Allocate instruction startup data");
        Check(WriteProcessMemory(process.get(), memory, startupText.c_str(), bytes, nullptr) != FALSE,
            "Write instruction startup data");
        auto startup = CreateThreadWithToken(process.get(), reinterpret_cast<LPTHREAD_START_ROUTINE>(agent + offset),
            memory, startupToken);
        Check(static_cast<bool>(startup), "Start instruction capture");
        constexpr ULONGLONG InstructionTimeoutMs = 10000;
        constexpr DWORD InstructionPollMs = 10;
        auto deadline = GetTickCount64() + InstructionTimeoutMs;
        while (header.instructionState != static_cast<LONG>(InstructionState::Active) &&
            header.instructionState != static_cast<LONG>(InstructionState::Failed) && GetTickCount64() < deadline)
            Sleep(InstructionPollMs);
        if (header.instructionState != static_cast<LONG>(InstructionState::Active))
        {
            DWORD startupResult = STILL_ACTIVE;
            GetExitCodeThread(startup.get(), &startupResult);
            throw std::runtime_error(startupResult == STILL_ACTIVE ?
                "Instruction capture startup timed out." :
                "Instruction capture startup failed: " + Utf8(ErrorText(startupResult)));
        }
        VirtualFreeEx(process.get(), memory, 0, MEM_RELEASE);
        unregisterProcess(
            processName.c_str(), pid, false, (sizeof(void*) == 8 ? DR_PLATFORM_64BIT : DR_PLATFORM_32BIT));
    }
    catch (...)
    {
        header.instructionState = static_cast<LONG>(InstructionState::Failed);
        if (registered)
            unregisterProcess(
                processName.c_str(), pid, false, (sizeof(void*) == 8 ? DR_PLATFORM_64BIT : DR_PLATFORM_32BIT));
        throw;
    }
}

void StopInstructionEngine(DWORD pid, SharedHeader& header)
{
    constexpr ULONGLONG InstructionTimeoutMs = 10000;
    constexpr DWORD InstructionPollMs = 10;
    Handle process(OpenProcess(SYNCHRONIZE, FALSE, pid));
    auto deadline = GetTickCount64() + InstructionTimeoutMs;
    InterlockedCompareExchange(&header.stop, TransportStopping, 0);
    while ((header.instructionState == static_cast<LONG>(InstructionState::Active) ||
            header.instructionState == static_cast<LONG>(InstructionState::Stopping)) &&
        GetTickCount64() < deadline && process &&
        WaitForSingleObject(process.get(), InstructionPollMs) == WAIT_TIMEOUT) {}
    if ((header.instructionState == static_cast<LONG>(InstructionState::Active) ||
            header.instructionState == static_cast<LONG>(InstructionState::Stopping)) && process &&
        WaitForSingleObject(process.get(), 0) == WAIT_TIMEOUT)
        throw std::runtime_error("The instruction engine could not detach from this process.");

}
}

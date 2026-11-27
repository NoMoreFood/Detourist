#include "Session.h"
#include "ImageIdentity.h"
#include "ApiCatalog.h"
#include "InstructionEngine.h"
#ifdef DETOURIST_BUILD_PROFILER
#include "ManagedAttach.h"
#endif
#include <tlhelp32.h>
#include <objbase.h>
#include <psapi.h>
#include <algorithm>
#include <filesystem>
#include <map>
#include <memory>
#include <type_traits>

namespace Detourist
{
constexpr int ModuleSnapshotRetries = 20;
constexpr uint32_t ModuleEnumRetries = 3;
constexpr DWORD StartupTimeoutMs = 15000;
constexpr ULONGLONG CrossArchBootstrapTimeoutMs = 30000;
constexpr ULONGLONG StopDrainTimeoutMs = 5000;
constexpr ULONGLONG ManagedProbeIntervalMs = 1000;
constexpr uint32_t MaxModuleIntervalMs = 1000;
constexpr ULONGLONG StatusPublishIntervalMs = 100;
constexpr ULONGLONG FlushIntervalMs = 20;
constexpr DWORD PollIntervalMs = 10;
constexpr DWORD IdleWaitMs = 2;
constexpr DWORD BootstrapWaitMs = 1;
constexpr size_t TransportBatchSize = 2048;

uintptr_t FindModule(DWORD pid, const std::wstring& module)
{
    bool fullPath = std::filesystem::path(module).is_absolute();
    Handle snapshot;
    for (int attempt = 0; attempt < ModuleSnapshotRetries; ++attempt)
    {
        snapshot.reset(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (snapshot || GetLastError() != ERROR_BAD_LENGTH) break;
        Sleep(PollIntervalMs);
    }
    Handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    MODULEENTRY32W entry{sizeof(entry)};
    if (snapshot && Module32FirstW(snapshot.get(), &entry))
    {
        do
        {
            if (!_wcsicmp(fullPath ? entry.szExePath : entry.szModule, module.c_str()))
                return reinterpret_cast<uintptr_t>(entry.modBaseAddr);
            wchar_t path[ExtendedPathCapacity];
            if (fullPath && process &&
                GetModuleFileNameExW(process.get(), entry.hModule, path, static_cast<DWORD>(std::size(path))) &&
                !_wcsicmp(path, module.c_str())) return reinterpret_cast<uintptr_t>(entry.modBaseAddr);
        } while (Module32NextW(snapshot.get(), &entry));
    }
    // A suspended new process has mapped images before its loader list is initialized.
    MEMORY_BASIC_INFORMATION region{};
    uintptr_t address = 0;
    while (!fullPath && process &&
        VirtualQueryEx(process.get(), reinterpret_cast<void*>(address), &region, sizeof(region)))
    {
        if (region.Type == MEM_IMAGE && region.BaseAddress == region.AllocationBase)
        {
            wchar_t path[ExtendedPathCapacity];
            if (GetMappedFileNameW(process.get(), region.AllocationBase, path, static_cast<DWORD>(std::size(path))) &&
                !_wcsicmp(std::filesystem::path(path).filename().c_str(), module.c_str()))
                return reinterpret_cast<uintptr_t>(region.AllocationBase);
        }
        auto next = reinterpret_cast<uintptr_t>(region.BaseAddress) + region.RegionSize;
        if (next <= address) break;
        address = next;
    }
    throw std::runtime_error("Required module is not present in the target: " + Utf8(module));
}

uintptr_t RemoteSystemProcedure(DWORD pid, void* procedure)
{
    HMODULE owner = nullptr;
    Check(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(procedure), &owner) != FALSE, "Locate system procedure");
    wchar_t path[MAX_PATH];
    Check(GetModuleFileNameW(owner, path, MAX_PATH) != 0, "Locate system module");
    return FindModule(pid, std::filesystem::path(path).filename().wstring()) +
        reinterpret_cast<uintptr_t>(procedure) - reinterpret_cast<uintptr_t>(owner);
}

DWORD RemoteInvokeData(HANDLE process, uintptr_t procedure, const void* data, size_t bytes, HANDLE cancellation,
    HANDLE startupToken, const TransportHandles* transferredHandles = nullptr)
{
    bool transferred = false;
    auto closeUnclaimed = [&](const TransportHandles* handles)
    {
        if (!transferred) Transport::CloseRemote(process, *handles);
    };
    std::unique_ptr<const TransportHandles, decltype(closeUnclaimed)> ownership(transferredHandles, closeUnclaimed);
    auto memory = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Check(memory != nullptr, "Allocate agent startup data");
    bool running = false;
    try
    {
        Check(WriteProcessMemory(process, memory, data, bytes, nullptr) != FALSE, "Write agent startup data");
        auto thread = CreateThreadWithToken(process, reinterpret_cast<LPTHREAD_START_ROUTINE>(procedure),
            memory, startupToken);
        Check(static_cast<bool>(thread), "Start capture agent");
        running = true;
        transferred = true;
        HANDLE events[]{thread.get(), cancellation};
        if (WaitForMultipleObjects(cancellation ? 2 : 1, events, FALSE, StartupTimeoutMs) != WAIT_OBJECT_0)
            throw std::runtime_error("The target did not complete agent startup within 15 seconds.");
        if (transferredHandles)
        {
            LONG owned = 0;
            Check(ReadProcessMemory(process, static_cast<const BYTE*>(memory) + offsetof(TransportStartup, owned),
                &owned, sizeof(owned), nullptr) != FALSE, "Read agent transport ownership");
            transferred = owned != 0;
        }
        running = false;
        DWORD result;
        Check(GetExitCodeThread(thread.get(), &result) != FALSE, "Read agent startup result");
        VirtualFreeEx(process, memory, 0, MEM_RELEASE);
        return result;
    }
    catch (...)
    {
        // Pending or unreadable startup ownership retains both payload and handles for the target's lifetime;
        // closing remote values while a callee can adopt them risks closing a later, reused handle.
        if (!running) VirtualFreeEx(process, memory, 0, MEM_RELEASE);
        throw;
    }
}

DWORD RemoteInvoke(HANDLE process, uintptr_t procedure, const std::wstring& text, HANDLE cancellation,
    HANDLE startupToken)
{
    return RemoteInvokeData(process, procedure, text.c_str(), (text.size() + 1) * sizeof(wchar_t),
        cancellation, startupToken);
}

uintptr_t LoadCaptureAgent(HANDLE process, DWORD pid, const std::wstring& path, HANDLE cancellation,
    HANDLE startupToken)
{
    // Reject the incompatible trust policy before the loader can block in a hard-error prompt.
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature{};
    Check(GetProcessMitigationPolicy(process, ProcessSignaturePolicy, &signature, sizeof(signature)) != FALSE,
        "Inspect target image-signing policy");
    if (signature.MicrosoftSignedOnly || signature.StoreSignedOnly || signature.MitigationOptIn)
        throw std::runtime_error("Capture agent injection is blocked by the target's image-signing policy.");
    RemoteInvoke(process, RemoteSystemProcedure(pid, reinterpret_cast<void*>(&LoadLibraryW)),
        path, cancellation, startupToken);
    return FindModule(pid, path);
}

void InitializeLoader(HANDLE process, DWORD pid, HANDLE primaryThread = nullptr, HANDLE cancellation = nullptr,
    SharedHeader* header = nullptr, HANDLE releaseEvent = nullptr, const std::function<void(bool)>& progress = {})
{
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (primaryThread)
    {
        // Hold startup outside the loader lock until capture is ready, without consuming a caller's suspension.
        using ApcRoutine = void (NTAPI*)(void*, void*, void*);
        using QueueApc = LONG (NTAPI*)(HANDLE, ApcRoutine, void*, void*, void*);
        auto queue = reinterpret_cast<QueueApc>(GetProcAddress(ntdll, "NtQueueApcThread"));
        auto signal = GetProcAddress(ntdll, "NtSetEvent");
        auto wait = GetProcAddress(ntdll, "NtWaitForMultipleObjects");
        auto close = GetProcAddress(ntdll, "NtClose");
        Check(queue && signal && wait && close, "Locate startup bootstrap");
        Handle ready(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        Handle localRelease(releaseEvent ? nullptr : CreateEventW(nullptr, TRUE, FALSE, nullptr));
        auto release = releaseEvent ? releaseEvent : localRelease.get();
        Handle controller(OpenProcess(SYNCHRONIZE, FALSE, header ? header->controllerId : GetCurrentProcessId()));
        Check(ready && release && controller, "Create startup bootstrap events");
        auto closeRemote = [process](void* handle)
        {
            DuplicateHandle(process, handle, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
        };
        auto duplicate = [&](HANDLE event)
        {
            HANDLE remote = nullptr;
            Check(DuplicateHandle(GetCurrentProcess(), event, process, &remote, 0, FALSE, DUPLICATE_SAME_ACCESS),
                "Share startup bootstrap event");
            return std::unique_ptr<void, decltype(closeRemote)>(remote, closeRemote);
        };
        auto remoteReady = duplicate(ready.get()), remoteRelease = duplicate(release);
        auto remoteController = duplicate(controller.get());

        // A manual-reset gate cannot lose a wakeup; collector death also releases a child resumed after capture ends.
        constexpr size_t contextOffset = 128;
        BYTE code[contextOffset + 6 * sizeof(uintptr_t)]{
#ifdef _WIN64
            0x53, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x4B, 0x18, 0x33, 0xD2, 0xFF, 0x13,
            0xB9, 0x02, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x53, 0x20, 0x41, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x45,
            0x33, 0xC9, 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x53, 0x08, 0x48, 0x8B,
            0x4B, 0x18, 0xFF, 0x53, 0x10, 0x48, 0x8B, 0x4B, 0x20, 0xFF, 0x53, 0x10, 0x48, 0x8B, 0x4B, 0x28,
            0xFF, 0x53, 0x10, 0x48, 0x83, 0xC4, 0x30, 0x5B, 0xC3
#else
            0x53, 0x8B, 0x5C, 0x24, 0x08, 0x6A, 0x00, 0xFF, 0x73, 0x0C, 0xFF, 0x13, 0x8D, 0x43, 0x10, 0x6A,
            0x00, 0x6A, 0x00, 0x6A, 0x01, 0x50, 0x6A, 0x02, 0xFF, 0x53, 0x04, 0xFF, 0x73, 0x0C, 0xFF, 0x53,
            0x08, 0xFF, 0x73, 0x10, 0xFF, 0x53, 0x08, 0xFF, 0x73, 0x14, 0xFF, 0x53, 0x08, 0x5B, 0xC2, 0x0C, 0x00
#endif
        };
        uintptr_t context[]{RemoteSystemProcedure(pid, reinterpret_cast<void*>(signal)),
            RemoteSystemProcedure(pid, reinterpret_cast<void*>(wait)),
            RemoteSystemProcedure(pid, reinterpret_cast<void*>(close)), reinterpret_cast<uintptr_t>(remoteReady.get()),
            reinterpret_cast<uintptr_t>(remoteRelease.get()), reinterpret_cast<uintptr_t>(remoteController.get())};
        memcpy(code + contextOffset, context, sizeof(context));
        auto freeRemote = [process](void* memory) { VirtualFreeEx(process, memory, 0, MEM_RELEASE); };
        std::unique_ptr<void, decltype(freeRemote)> bootstrap(
            VirtualAllocEx(process, nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), freeRemote);
        DWORD protection = 0;
        if (!bootstrap || !WriteProcessMemory(process, bootstrap.get(), code, sizeof(code), nullptr) ||
            !VirtualProtectEx(process, bootstrap.get(), sizeof(code), PAGE_EXECUTE_READ, &protection) ||
            !FlushInstructionCache(process, bootstrap.get(), sizeof(code)))
        {
            throw std::runtime_error("Could not prepare the target's primary thread.");
        }
        if (queue(primaryThread, reinterpret_cast<ApcRoutine>(bootstrap.get()),
            static_cast<BYTE*>(bootstrap.get()) + contextOffset, nullptr, nullptr) < 0)
            throw std::runtime_error("Could not initialize the target's primary thread.");

        // Queued APCs own their event handles and retain their code for the target's lifetime.
        bootstrap.release();
        remoteReady.release();
        remoteRelease.release();
        remoteController.release();
        const bool deferred = header && header->bootstrapDeferred;
        if (header) InterlockedExchange(&header->bootstrapState, static_cast<LONG>(BootstrapState::ApcQueued));
        bool suspended = false;
        try
        {
            if (deferred && progress) progress(false);
            if (!deferred && ResumeThread(primaryThread) == DWORD(-1))
                throw std::runtime_error("Could not initialize the target's primary thread.");
            HANDLE waits[]{ready.get(), primaryThread, controller.get(), cancellation};
            if (WaitForMultipleObjects(cancellation ? 4 : 3, waits, FALSE,
                deferred ? INFINITE : StartupTimeoutMs) != WAIT_OBJECT_0)
                throw std::runtime_error("Target loader initialization did not complete.");
            if (header) InterlockedExchange(&header->bootstrapState, static_cast<LONG>(BootstrapState::LoaderReady));
            if (deferred)
            {
                if (progress) progress(true);
                else
                {
                    // The session collector grants a bootstrap slot to its architecture-matched helper.
                    while (header->bootstrapState != static_cast<LONG>(BootstrapState::Permitted) && !header->stop &&
                        WaitForSingleObject(controller.get(), BootstrapWaitMs) == WAIT_TIMEOUT) {}
                    if (header->stop || WaitForSingleObject(controller.get(), 0) != WAIT_TIMEOUT)
                        throw std::runtime_error("Capture stopped.");
                }
                InterlockedExchange(&header->bootstrapState, static_cast<LONG>(BootstrapState::Permitted));
                return;
            }
            if (SuspendThread(primaryThread) == DWORD(-1))
                throw std::runtime_error("Could not pause the target's primary thread.");
            suspended = true;
            CONTEXT threadContext{};
            threadContext.ContextFlags = CONTEXT_CONTROL;
            Check(GetThreadContext(primaryThread, &threadContext) && SetEvent(release), "Pause initialized target");
        }
        catch (...)
        {
            SetEvent(release);
            if (suspended) ResumeThread(primaryThread);
            throw;
        }
        return;
    }

    // Existing processes only need to finish any loader initialization already in progress.
    auto exitThread = GetProcAddress(ntdll, "RtlExitUserThread");
    Check(exitThread != nullptr, "Locate startup bootstrap");
    auto remote = RemoteSystemProcedure(pid, reinterpret_cast<void*>(exitThread));
    Handle bootstrap(CreateRemoteThread(process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remote), nullptr, 0, nullptr));
    Check(static_cast<bool>(bootstrap), "Initialize target loader");
    if (WaitForSingleObject(bootstrap.get(), StartupTimeoutMs) != WAIT_OBJECT_0)
        throw std::runtime_error("Target loader initialization timed out.");
}

Session::Session(const std::wstring& database, const CaptureOptions& options, uint32_t attachPid,
    std::wstring executable, std::wstring arguments)
    : databasePath_(database), options_(options), filters_(CaptureFilters(options.apiMask, options.categoryMask)),
      entryBreaks_(options.entryBreaks),
      exitBreaks_(options.exitBreaks), entryApi_(options.entryApi), exitApi_(options.exitApi)
{
    SetExcludedApis(options_.excludedApis);
    worker_ = std::jthread([this, attachPid, executable = std::move(executable), arguments = std::move(arguments)]()
    {
        Run(attachPid, executable, arguments);
    });
}

Session::~Session()
{
    forceStop_ = true;
    Stop();
    if (worker_.joinable()) worker_.join();
}
SessionStatus Session::Status() const { std::lock_guard lock(mutex_); return status_; }
void Session::Stop() { stop_ = true; SetEvent(cancelAttach_.get()); }
void Session::Pause(bool paused)
{
    // Publish admission changes before acknowledging the control request.
    std::lock_guard lock(mutex_);
    paused_ = paused;
    for (const auto& target : targets_)
        InterlockedExchange(&target->transport.Header()->capturePaused, paused ? 1 : 0);
}
void Session::SetFilters(uint64_t mask, uint64_t categories)
{
    std::lock_guard lock(mutex_);
    filters_ = CaptureFilters(mask, categories);
    for (const auto& target : targets_)
        InterlockedExchange64(&target->transport.Header()->enabledFilters, static_cast<LONGLONG>(filters_.load()));
}
void Session::SetExcludedApis(const std::vector<std::string>& names)
{
    if (names.size() > MaximumExcludedApis) throw std::runtime_error("API exclusion limit exceeded.");
    std::vector<uint64_t> hashes;
    hashes.reserve(names.size());
    for (const auto& name : names)
    {
        if (name.empty() || name.size() >= sizeof(DynamicApiMetadata::name))
            throw std::runtime_error("Select a valid API name to exclude.");
        hashes.push_back(ApiNameHash(name));
    }
    std::sort(hashes.begin(), hashes.end());
    hashes.erase(std::unique(hashes.begin(), hashes.end()), hashes.end());
    std::lock_guard lock(mutex_);
    excludedApis_ = std::move(hashes);
    ++exclusionGeneration_;
}

void Session::ApplyExclusions(Target& target)
{
    if (target.exclusionGeneration == exclusionGeneration_.load()) return;
    std::vector<uint64_t> hashes;
    {
        std::lock_guard lock(mutex_);
        hashes = excludedApis_;
        target.exclusionGeneration = exclusionGeneration_.load();
    }
    auto header = target.transport.Header();

    // Tombstones preserve concurrent probes while individual entries are added or removed atomically.
    if (!hashes.empty()) InterlockedExchange(&header->excludedApiCount, static_cast<LONG>(hashes.size()));
    for (auto& entry : header->excludedApis)
    {
        const auto hash = static_cast<uint64_t>(entry);
        if (hash > 1 && !std::binary_search(hashes.begin(), hashes.end(), hash)) InterlockedExchange64(&entry, 1);
    }
    for (auto hash : hashes)
    {
        auto slot = static_cast<uint32_t>(hash) & (ApiExclusionSlots - 1);
        uint32_t vacant = ApiExclusionSlots;
        for (uint32_t probe = 0; probe < ApiExclusionSlots; ++probe)
        {
            const auto entry = static_cast<uint64_t>(header->excludedApis[slot]);
            if (entry == hash) { vacant = ApiExclusionSlots; break; }
            if (entry <= 1 && vacant == ApiExclusionSlots) vacant = slot;
            if (!entry) break;
            slot = (slot + 1) & (ApiExclusionSlots - 1);
        }
        if (vacant < ApiExclusionSlots)
            InterlockedExchange64(&header->excludedApis[vacant], static_cast<LONGLONG>(hash));
    }
    InterlockedExchange(&header->excludedApiCount, static_cast<LONG>(hashes.size()));
}

void Session::SetBreaks(uint64_t entry, uint64_t exit) { entryBreaks_ = entry; exitBreaks_ = exit; }
void Session::SetApiBreaks(int32_t entry, int32_t exit) { entryApi_ = entry; exitApi_ = exit; }
void Session::Continue(const Event& editedCall, bool skip)
{
    std::lock_guard lock(mutex_);
    if (!status_.breakpoint || editedCall.callId != status_.stoppedCall.callId ||
        editedCall.processId != status_.stoppedCall.processId ||
        editedCall.threadId != status_.stoppedCall.threadId) return;
    if (skip && (status_.stoppedCall.flags & KernelDispatcher))
        throw std::runtime_error("A kernel dispatcher cannot be skipped.");
    editedCall_ = editedCall;
    skipCall_ = skip;
    resumeRequested_ = true;
}

bool Session::WriteMemory(uint64_t address, const void* bytes, size_t length, std::wstring& error)
{
    // Keep the process suspended until the debugger's memory operation completes.
    std::lock_guard lock(mutex_);
    if (!status_.breakpoint || resumeRequested_)
    {
        error = L"The process must be stopped at an API breakpoint.";
        return false;
    }
    if (!length || length > options_.bufferLimit)
    {
        error = L"Memory data exceeds the configured buffer limit.";
        return false;
    }
    Handle process(OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, status_.stoppedCall.processId));
    SIZE_T written = 0;
    if (!process || !WriteProcessMemory(process.get(), reinterpret_cast<void*>(address), bytes, length, &written) ||
        written != length)
    {
        error = ErrorText(GetLastError());
        return false;
    }
    return true;
}

bool Session::ReadMemory(uint64_t address, size_t length, std::vector<uint8_t>& bytes, std::wstring& error)
{
    // Live inspection shares the capture limit and cannot race a breakpoint resume.
    std::lock_guard lock(mutex_);
    if (!status_.breakpoint || resumeRequested_ || !length || length > options_.bufferLimit)
    {
        error = L"Stop at an API breakpoint and select a length within the configured buffer limit.";
        return false;
    }
    Handle process(OpenProcess(PROCESS_VM_READ, FALSE, status_.stoppedCall.processId));
    bytes.resize(length);
    SIZE_T read = 0;
    if (!process || (!ReadProcessMemory(process.get(), reinterpret_cast<const void*>(address), bytes.data(),
        length, &read) && !read))
    {
        bytes.clear();
        error = ErrorText(GetLastError());
        return false;
    }
    bytes.resize(read);
    return true;
}

void BootstrapTarget(DWORD pid, DWORD primaryThreadId, bool initializeLoader, [[maybe_unused]] bool launched,
    bool instructionEngine, Transport& transport, HANDLE cancellation,
    const std::function<void(bool)>& progress)
{
    auto header = transport.Header();
    Handle releaseEvent(OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE,
        (transport.Name() + L".bootstrap-release").c_str()));
    Check(static_cast<bool>(releaseEvent), "Open capture startup release event");
    try
    {
        Handle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE |
            PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | SYNCHRONIZE, FALSE, pid));
        Check(static_cast<bool>(process), "Open target process");
        const auto machine = ProcessMachine(process.get());
        Check(machine != IMAGE_FILE_MACHINE_UNKNOWN, "Inspect target architecture");
        const auto expected = sizeof(void*) == 8 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
        if (machine != expected)
            throw std::runtime_error("Use a capture collector that matches the target's x86 or x64 architecture.");

        // New children initialize on their primary thread; existing targets can still be starting their loader.
        Handle primaryThread(primaryThreadId ? OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT |
            THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, primaryThreadId) : nullptr);
        if (primaryThreadId) Check(static_cast<bool>(primaryThread), "Open child startup thread");
        if (initializeLoader)
            InitializeLoader(process.get(), pid, primaryThread.get(), cancellation, header, releaseEvent.get(), progress);
        if (cancellation && WaitForSingleObject(cancellation, 0) == WAIT_OBJECT_0)
            throw std::runtime_error("Capture stopped.");

        // The creator assigns startup impersonation before resuming its child into the bootstrap gate.
        Handle startupToken;
        if (primaryThread)
        {
            HANDLE token = nullptr;
            if (OpenThreadToken(primaryThread.get(), TOKEN_IMPERSONATE, TRUE, &token)) startupToken.reset(token);
            else Check(GetLastError() == ERROR_NO_TOKEN, "Open child startup security context");
        }

        // Load the architecture-matched observer, then initialize it outside loader callbacks.
        auto agentPath = ModuleDirectory() + L"\\DetouristAgent.dll";
        Check(GetFileAttributesW(agentPath.c_str()) != INVALID_FILE_ATTRIBUTES, "Locate capture agent");
        auto localAgent = LoadLibraryExW(agentPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        Check(localAgent != nullptr, "Inspect capture agent");
        auto start = GetProcAddress(localAgent, "DetouristStart");
        auto offset = reinterpret_cast<uintptr_t>(start) - reinterpret_cast<uintptr_t>(localAgent);
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(localAgent);
        auto localHeaders = *reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const std::byte*>(localAgent) + dos->e_lfanew);
        auto headerOffset = dos->e_lfanew;
        FreeLibrary(localAgent);
        if (!start) throw std::runtime_error("Capture agent startup export is missing.");
        auto module = LoadCaptureAgent(process.get(), pid, agentPath, cancellation, startupToken.get());

        // A pinned observer from another build must never be called using a new export offset.
        IMAGE_NT_HEADERS remoteHeaders{};
        if (!ReadProcessMemory(process.get(), reinterpret_cast<void*>(module + headerOffset),
            &remoteHeaders, sizeof(remoteHeaders), nullptr) ||
            remoteHeaders.Signature != IMAGE_NT_SIGNATURE ||
            remoteHeaders.FileHeader.TimeDateStamp != localHeaders.FileHeader.TimeDateStamp ||
            remoteHeaders.OptionalHeader.SizeOfImage != localHeaders.OptionalHeader.SizeOfImage)
            throw std::runtime_error(
                "A different capture agent is already loaded. Restart the target to use this build.");

        // Snapshot initial modules when bootstrapping across architectures so an x86 collector receives 64-bit bases.
        if (!cancellation)
        {
            std::vector<HMODULE> modules(1024);
            DWORD moduleBytes = 0;
            if (EnumProcessModulesEx(process.get(), modules.data(),
                static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &moduleBytes, LIST_MODULES_ALL))
            {
                auto count = std::min<size_t>(moduleBytes / sizeof(HMODULE), modules.size());
                for (size_t index = 0; index < count; ++index)
                {
                    MODULEINFO information{};
                    wchar_t path[MAX_PATH * 2];
                    if (!GetModuleInformation(process.get(), modules[index], &information, sizeof(information)))
                        continue;
                    auto length = GetModuleFileNameExW(process.get(), modules[index], path,
                        static_cast<DWORD>(std::size(path)));
                    if (!length) continue;
                    auto write = InterlockedCompareExchange64(&header->moduleChangeWrite, 0, 0);
                    auto read = InterlockedCompareExchange64(&header->moduleChangeRead, 0, 0);
                    if (write - read >= ModuleHistoryCapacity / 2) break;
                    auto& change = header->moduleChanges[static_cast<uint64_t>(write) & (ModuleHistoryCapacity - 1)];
                    change = {};
                    change.base = reinterpret_cast<uint64_t>(modules[index]);
                    change.size = information.SizeOfImage;
                    change.reason = static_cast<uint32_t>(ModuleChangeReason::Load);
                    change.characters = std::min<uint32_t>(length, MaximumModulePath);
                    memcpy(change.path, path, change.characters * sizeof(wchar_t));
                    ReadImageIdentity(change.base, change.size, change.identity,
                        [&](uint64_t address, void* output, size_t bytes)
                    {
                        SIZE_T readBytes = 0;
                        return ReadProcessMemory(process.get(), reinterpret_cast<void*>(address), output, bytes,
                            &readBytes) && readBytes == bytes;
                    });
                    InterlockedExchange64(&header->moduleChangeWrite, write + 1);
                }
            }
        }
        TransportStartup agentStartup{transport.DuplicateTo(process.get(), primaryThread.get()),
            header->captureIdentity, 0, 0};
        DWORD error = RemoteInvokeData(process.get(), module + offset, &agentStartup, sizeof(agentStartup),
            cancellation, startupToken.get(), &agentStartup.handles);
        if (error) throw std::runtime_error("Agent initialization failed: " + Utf8(ErrorText(error)));
        HANDLE ready[]{transport.ReadyEvent(), cancellation};
        auto deadline = GetTickCount64() + StartupTimeoutMs;
        for (uint32_t poll = 0;; ++poll)
        {
            transport.ServiceThreadIds(process.get(), pid);
            auto waited = WaitForMultipleObjects(cancellation ? 2 : 1, ready, FALSE, poll < 50 ? 1 : PollIntervalMs);
            if (waited == WAIT_OBJECT_0) break;
            if (waited == WAIT_TIMEOUT && GetTickCount64() < deadline) continue;
            InterlockedExchange(&header->stop, TransportStopping);
            throw std::runtime_error("Capture hooks did not become ready.");
        }
        if (header->state != static_cast<LONG>(AgentState::Active))
            throw std::runtime_error("Capture hook installation failed: " + Utf8(ErrorText(header->error)));
#ifdef DETOURIST_INSTRUCTION_ENGINE
        if (instructionEngine)
            StartInstructionEngine(pid, agentStartup.handles.mapping, *header, launched, startupToken.get(), module);
#else
        if (instructionEngine) throw std::runtime_error("The instruction engine is unavailable in this build.");
#endif
    }
    catch (const std::exception& failure)
    {
        if (!cancellation)
        {
            auto text = failure.what();
            auto length = std::min(strlen(text), sizeof(header->unknownNativeExports) - 1);
            memcpy(header->unknownNativeExports, text, length);
            header->unknownNativeExports[length] = 0;
        }
        throw;
    }
}

void BootstrapTarget(DWORD pid, DWORD primaryThreadId, bool initializeLoader, bool launched,
    bool instructionEngine, const std::wstring& mappingName, HANDLE cancellation,
    const std::function<void(bool)>& progress)
{
    // Architecture helpers open their own channel; in-process startup reuses the target's retained view.
    Transport transport;
    Check(transport.Open(mappingName, pid, false), "Open capture transport");
    BootstrapTarget(pid, primaryThreadId, initializeLoader, launched, instructionEngine,
        transport, cancellation, progress);
}

std::unique_ptr<Session::Target> Session::PrepareTarget(DWORD pid, int64_t parent, bool launched, DWORD primaryThreadId,
    bool suspended, std::shared_ptr<std::atomic<LONG>> progress)
{
    if (pid == GetCurrentProcessId()) throw std::runtime_error("Select another process to monitor.");
    if (stop_) throw std::runtime_error("Capture stopped.");

    // Deferred children release bootstrap capacity while their creator configures and resumes them.
    bool ownsSlot = false;
    auto releaseSlot = [&](Session*)
    {
        if (std::exchange(ownsSlot, false)) attachmentSlots_.release();
    };
    auto acquireSlot = [&]
    {
        for (;;)
        {
            if (stop_) throw std::runtime_error("Capture stopped.");
            if (!attachmentSlots_.try_acquire_for(std::chrono::milliseconds(PollIntervalMs))) continue;
            ownsSlot = true;
            break;
        }
    };
    std::unique_ptr<Session, decltype(releaseSlot)> slot(this, releaseSlot);
    if (parent) acquireSlot();
    auto reportProgress = [&](bool ready)
    {
        if (!progress) return;
        if (ready)
        {
            acquireSlot();
            progress->store(static_cast<LONG>(AttachmentProgress::LoaderReady));
        }
        else
        {
            progress->store(static_cast<LONG>(AttachmentProgress::ApcQueued));
            releaseSlot(this);
        }
    };
    auto target = std::make_unique<Target>();
    target->pid = pid;
    target->probeManaged = !profilerLaunch_;
    target->process.reset(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | SYNCHRONIZE, FALSE, pid));
    Check(static_cast<bool>(target->process), "Open target process");
    const auto machine = ProcessMachine(target->process.get());
    Check(machine != IMAGE_FILE_MACHINE_UNKNOWN, "Inspect target architecture");
    const auto expected = sizeof(void*) == 8 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    if ((machine != IMAGE_FILE_MACHINE_AMD64 && machine != IMAGE_FILE_MACHINE_I386) || (!parent && machine != expected))
        throw std::runtime_error("Use a capture collector that matches the target's x86 or x64 architecture.");
    target->pointerSize = machine == IMAGE_FILE_MACHINE_AMD64 ? 8 : 4;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy{};
    if (GetProcessMitigationPolicy(target->process.get(), ProcessDynamicCodePolicy, &policy, sizeof(policy)) &&
        policy.ProhibitDynamicCode)
        throw std::runtime_error("ProcessDynamicCodePolicy prohibits executable patches required for capture. "
            "For Chromium/Electron renderer capture in an isolated test session, launch the application with "
            "--no-sandbox and Follow child processes enabled. This disables the application's sandbox; "
            "use only trusted test content.");
    wchar_t image[ExtendedPathCapacity];
    DWORD characters = static_cast<DWORD>(std::size(image));
    Check(QueryFullProcessImageNameW(target->process.get(), 0, image, &characters) != FALSE, "Read target image");
    target->image.assign(image, characters);
    target->parent = parent;
    GUID guid;
    if (FAILED(CoCreateGuid(&guid))) throw std::runtime_error("Cannot create session identity.");
    wchar_t identity[64];
    StringFromGUID2(guid, identity, static_cast<int>(std::size(identity)));
    auto name = L"Local\\Detourist." + std::wstring(identity);
    target->transport.Create(name, pid, options_.bufferLimit, options_.stackDepth,
        filters_.load() & AllApis, options_.followChildren, CaptureCatalogName(target->pointerSize));
    ApplyExclusions(*target);
    target->transport.Header()->enabledFilters = static_cast<LONGLONG>(filters_.load());
    target->transport.Header()->bootstrapDeferred = suspended;

    // Arm requested breakpoints before any application thread resumes.
    SyncBreaks(target->transport.Header());
    if (options_.instructionEngine)
    {
        target->transport.Header()->capturePaused = 1;
        target->transport.Header()->instructionState = static_cast<LONG>(InstructionState::Starting);
    }

    // Dispatch cross-architecture child targets through the sibling collector into this session's transport.
    if (target->pointerSize == sizeof(void*))
    {
        BootstrapTarget(pid, parent ? primaryThreadId : 0, parent || !launched, launched,
            options_.instructionEngine, target->transport, cancelAttach_.get(), reportProgress);
    }
    else
    {
        auto collectorPath = ArchitectureDirectory(target->pointerSize) + L"\\DetouristCollector.exe";
        Check(GetFileAttributesW(collectorPath.c_str()) != INVALID_FILE_ATTRIBUTES,
            "Locate cross-architecture capture collector");
        auto command = L"\"" + collectorPath + L"\" --bootstrap " + std::to_wstring(pid) + L" " +
            std::to_wstring(parent ? primaryThreadId : 0) + L" " + (parent || !launched ? L"1 " : L"0 ") +
            (launched ? L"1 " : L"0 ") + (options_.instructionEngine ? L"1 \"" : L"0 \"") + name + L"\"";
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION bootstrap{};
        Check(CreateProcessW(collectorPath.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &bootstrap) != FALSE, "Start cross-architecture capture bootstrap");
        Handle bootstrapProcess(bootstrap.hProcess), bootstrapThread(bootstrap.hThread);
        auto header = target->transport.Header();
        try
        {
            HANDLE waits[]{bootstrapProcess.get(), cancelAttach_.get()};
            auto deadline = GetTickCount64() + CrossArchBootstrapTimeoutMs;
            bool queued = false, ready = false;
            for (;;)
            {
                auto state = InterlockedCompareExchange(&header->bootstrapState, 0, 0);
                if (suspended && state >= static_cast<LONG>(BootstrapState::ApcQueued) && !queued)
                {
                    reportProgress(false);
                    queued = true;
                }
                if (suspended && state >= static_cast<LONG>(BootstrapState::LoaderReady) && !ready)
                {
                    reportProgress(true);
                    InterlockedExchange(&header->bootstrapState, static_cast<LONG>(BootstrapState::Permitted));
                    ready = true;
                    deadline = GetTickCount64() + CrossArchBootstrapTimeoutMs;
                }
                auto waited = WaitForMultipleObjects(2, waits, FALSE, PollIntervalMs);
                if (waited == WAIT_OBJECT_0) break;
                if (waited != WAIT_TIMEOUT || stop_) throw std::runtime_error("Capture stopped.");
                if ((!queued || ready) && GetTickCount64() >= deadline)
                    throw std::runtime_error("Child capture bootstrap timed out.");
            }
        }
        catch (...)
        {
            target->transport.Stop();
            TerminateProcess(bootstrapProcess.get(), ERROR_CANCELLED);
            throw;
        }
        DWORD exitCode = 1;
        Check(GetExitCodeProcess(bootstrapProcess.get(), &exitCode) != FALSE, "Read bootstrap result");
        if (exitCode != 0 || header->state != static_cast<LONG>(AgentState::Active))
        {
            target->transport.Stop();
            header->unknownNativeExports[sizeof(header->unknownNativeExports) - 1] = 0;
            throw std::runtime_error(
                header->unknownNativeExports[0] ? header->unknownNativeExports : "Child capture bootstrap failed.");
        }
    }
    if (stop_) throw std::runtime_error("Capture stopped.");
    return target;
}

void Session::SyncBreaks(SharedHeader* header) const
{
    header->entryBreaks = static_cast<LONGLONG>(entryBreaks_.load());
    header->exitBreaks = static_cast<LONGLONG>(exitBreaks_.load());
    header->entryApi = entryApi_;
    header->exitApi = exitApi_;
    header->debuggerActive = (entryBreaks_ || exitBreaks_ || entryApi_ >= 0 || exitApi_ >= 0) ?
        CooperativeDebugger : 0;
}

void Session::RegisterTarget(std::unique_ptr<Target> target)
{
    // Only the drain worker writes trace state or publishes a fully prepared transport to controls.
    ApplyExclusions(*target);
    auto header = target->transport.Header();
    target->id = store_->AddTarget(target->pid, target->image, target->parent,
        static_cast<uint64_t>(header->installedApis), target->pointerSize);
    store_->AddCoverage(target->id, header->installedNativeCount, header->availableNativeCount,
        header->nativeExportCount, header->unknownNativeExports);
    store_->UpdateCoverage(target->id, *header);

    // Register transports under the same lock used to publish pause and filter changes.
    std::lock_guard lock(mutex_);
    header->enabledFilters = static_cast<LONGLONG>(filters_.load());
    header->capturePaused = paused_ ? 1 : 0;
    SyncBreaks(header);
    ++totalProcesses_;
    auto release = target->transport.BootstrapReleaseEvent();
    targets_.push_back(std::move(target));
    SetEvent(release);
}

void Session::RecordSkippedChild(int64_t parent, DWORD pid, const std::wstring& reason)
{
    if (stop_) return;
    store_->Diagnostic(parent, L"Child " + std::to_wstring(pid) + L": " + reason);
    std::lock_guard lock(mutex_);
    ++skippedChildren_;
    status_.partial = true;
    status_.skippedChildren = skippedChildren_;
}

void Session::CompleteAttachments(bool wait)
{
    for (size_t index = 0; index < attachments_.size();)
    {
        auto& attachment = attachments_[index];
        if (attachment.request && attachment.progress->load() >= static_cast<LONG>(AttachmentProgress::ApcQueued))
        {
            // An armed APC outlives its request slot and waits for the application's own resume operation.
            if (InterlockedCompareExchange(&attachment.request->state,
                static_cast<LONG>(ChildRequestState::Complete),
                static_cast<LONG>(ChildRequestState::Attaching)) == static_cast<LONG>(ChildRequestState::Abandoned))
                InterlockedExchange(&attachment.request->state, static_cast<LONG>(ChildRequestState::Idle));
            attachment.request = nullptr;
        }
        if (!wait && attachment.result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
        {
            ++index;
            continue;
        }
        auto request = attachment.request;
        auto parent = attachment.parent;
        auto childPid = attachment.pid;
        std::wstring error;
        try
        {
            auto target = attachment.result.get();
            if (!stop_) RegisterTarget(std::move(target));
        }
        catch (const std::exception& failure)
        {
            if (request) request->error = ERROR_NOT_SUPPORTED;
            error = Wide(failure.what());
        }

        // Release the creator only after bootstrap and transport ownership have settled.
        if (request && InterlockedCompareExchange(&request->state,
            static_cast<LONG>(ChildRequestState::Complete),
            static_cast<LONG>(ChildRequestState::Attaching)) == static_cast<LONG>(ChildRequestState::Abandoned))
            InterlockedExchange(&request->state, static_cast<LONG>(ChildRequestState::Idle));
        attachments_.erase(attachments_.begin() + index);
        if (!error.empty()) RecordSkippedChild(parent, childPid, error);
    }
}

void Session::RecordModules(Target& target)
{
    if (target.pointerSize > sizeof(void*)) return;

    // Loaded images attribute recorded return addresses to modules; a busy loader is read on a later pass.
    std::vector<HMODULE> modules(1024);
    DWORD bytes = 0;
    const DWORD filter = target.pointerSize < sizeof(void*) ? LIST_MODULES_32BIT : LIST_MODULES_ALL;
    for (uint32_t attempt = 0; attempt < ModuleEnumRetries; ++attempt)
    {
        if (!EnumProcessModulesEx(target.process.get(), modules.data(),
            static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &bytes, filter)) return;
        if (bytes <= modules.size() * sizeof(HMODULE)) break;
        if (attempt == ModuleEnumRetries - 1) return;
        modules.resize(bytes / sizeof(HMODULE) + 64);
    }
    auto count = std::min<size_t>(bytes / sizeof(HMODULE), modules.size());
    for (size_t index = 0; index < count; ++index)
    {
        MODULEINFO information{};
        wchar_t path[MAX_PATH * 2];
        auto base = reinterpret_cast<uint64_t>(modules[index]);
        if (target.modules.contains(base) || !GetModuleInformation(target.process.get(), modules[index],
            &information, sizeof(information))) continue;
        auto length = GetModuleFileNameExW(target.process.get(), modules[index], path,
            static_cast<DWORD>(std::size(path)));
        if (!length) continue;
        ModuleIdentity identity{};
        ReadImageIdentity(base, information.SizeOfImage, identity, [&](uint64_t address, void* output, size_t bytes)
        {
            SIZE_T read = 0;
            return ReadProcessMemory(target.process.get(), reinterpret_cast<void*>(address), output, bytes, &read) &&
                read == bytes;
        });
        store_->AddModule(target.id, base, information.SizeOfImage, std::wstring(path, length), 0, true, identity);
        target.modules.insert(base);
    }
}

void Session::RecordModuleChanges(Target& target)
{
    // Loader publications remain readable after process exit and never depend on the target's worker draining a queue.
    auto header = target.transport.Header();
    auto read = InterlockedCompareExchange64(&header->moduleChangeRead, 0, 0);
    auto write = InterlockedCompareExchange64(&header->moduleChangeWrite, 0, 0);
    if (write < read || write - read > ModuleHistoryCapacity)
        throw std::runtime_error("Invalid module history queue.");
    while (read < write)
    {
        const auto& change = header->moduleChanges[static_cast<uint64_t>(read) & (ModuleHistoryCapacity - 1)];
        const auto reason = static_cast<ModuleChangeReason>(change.reason);
        if ((reason != ModuleChangeReason::Load && reason != ModuleChangeReason::Unload) ||
            change.characters > MaximumModulePath)
            throw std::runtime_error("Invalid module history record.");
        if (!change.epoch && reason == ModuleChangeReason::Load)
        {
            store_->AddModule(target.id, change.base, change.size,
                std::wstring(change.path, change.characters), 0, true, change.identity);
            target.modules.insert(change.base);
            InterlockedExchange64(&header->moduleChangeRead, ++read);
            continue;
        }
        Record record;
        record.event = {};
        record.event.kind = reason == ModuleChangeReason::Load ? EventKind::ModuleLoad : EventKind::ModuleUnload;
        record.event.moduleEpoch = change.epoch;
        record.event.timestamp = Clock();
        record.event.arguments[0] = change.base;
        record.event.arguments[1] = change.size;
        auto bytes = reinterpret_cast<const std::byte*>(change.path);
        record.payload.resize(sizeof(ModuleIdentity) + change.characters * sizeof(wchar_t));
        memcpy(record.payload.data(), &change.identity, sizeof(change.identity));
        memcpy(record.payload.data() + sizeof(ModuleIdentity), bytes, change.characters * sizeof(wchar_t));
        store_->Add(target.id, record);
        InterlockedExchange64(&header->moduleChangeRead, ++read);
    }
}

void Session::PublishStatus(const std::wstring& message)
{
    std::lock_guard lock(mutex_);
    status_.calls = store_ ? store_->Count() : 0;
    status_.records = retiredRecords_;
    status_.queued = 0;
    status_.blockedMilliseconds = retiredBlockedMilliseconds_;
    status_.processes = totalProcesses_;
    status_.attaching = static_cast<uint32_t>(attachments_.size());
    status_.partial = skippedChildren_ != 0;
    status_.skippedChildren = skippedChildren_;
    for (const auto& target : targets_)
    {
        auto header = target->transport.Header();
        status_.records += static_cast<uint64_t>(header->dequeue);
        status_.queued += static_cast<uint64_t>(header->enqueue - header->dequeue);
        status_.blockedMilliseconds += static_cast<double>(header->waitTicks) * 1000 /
            static_cast<double>(header->frequency);
    }
    if (!message.empty()) status_.message = message;
    else if (!status_.breakpoint && status_.capturing && skippedChildren_)
        status_.message = L"Partial capture: " + std::to_wstring(skippedChildren_) +
            (skippedChildren_ == 1 ? L" child process was not attached." : L" child processes were not attached.");
}

Handle SuspendCapturedProcess(DWORD pid)
{
    // Closing the state-change handle releases the freeze, including when the collector terminates unexpectedly.
    using Create = LONG (NTAPI*)(HANDLE*, ACCESS_MASK, void*, HANDLE, ULONG);
    using Change = LONG (NTAPI*)(HANDLE, HANDLE, ULONG, void*, SIZE_T, ULONG);
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto create = reinterpret_cast<Create>(GetProcAddress(ntdll, "NtCreateProcessStateChange"));
    auto change = reinterpret_cast<Change>(GetProcAddress(ntdll, "NtChangeProcessState"));

    // The WOW64 state-change path also requires query and read access to the target.
    Handle process(OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION |
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    HANDLE state = nullptr;
    constexpr ACCESS_MASK StateChangeSetAttributes = 1;
    constexpr ULONG ProcessStateChangeSuspend = 0;
    if (!create || !change || !process ||
        create(&state, StateChangeSetAttributes, nullptr, process.get(), 0) < 0) return {};
    Handle suspension(state);
    if (change(suspension.get(), process.get(), ProcessStateChangeSuspend, nullptr, 0, 0) < 0) return {};
    return suspension;
}

void Session::PumpDebugger()
{
    // The controller suspends all threads while observers wait on the shared breakpoint signal.
    for (auto& target : targets_)
    {
        auto header = target->transport.Header();
        SyncBreaks(header);
        if (target->breakpointSuspension && (resumeRequested_ || stop_))
        {
            {
                std::lock_guard lock(mutex_);
                if (!stop_ && (editedCall_.processId != target->pid ||
                    editedCall_.callId != header->breakpoint.event.callId)) continue;
                if (!stop_)
                {
                    header->breakpoint.event = editedCall_;
                    header->breakpoint.action = static_cast<LONG>(
                        skipCall_ ? BreakpointAction::Skip : BreakpointAction::Continue);
                }
                status_.breakpoint = false;
                resumeRequested_ = false;
            }
            target->breakpointSuspension.reset();
            SetEvent(target->transport.ResumeEvent());
        }
        if (!target->breakpointSuspension && !stop_ && header->breakpoint.waiting &&
            WaitForSingleObject(target->transport.BreakEvent(), 0) == WAIT_OBJECT_0)
        {
            // Drain the definition before suspending other producers or presenting a dynamic breakpoint.
            if (!store_->HasDefinition(target->id, header->breakpoint.event.api))
            {
                SetEvent(target->transport.BreakEvent());
                continue;
            }
            store_->Flush();
            target->breakpointSuspension = SuspendCapturedProcess(target->pid);
            if (!target->breakpointSuspension)
            {
                store_->Diagnostic(target->id, L"Cannot suspend the process for its API breakpoint.");
                SetEvent(target->transport.ResumeEvent());
            }
        }
    }

    // Present held processes in order without hiding an earlier pending breakpoint.
    std::lock_guard lock(mutex_);
    if (status_.breakpoint) return;
    for (const auto& target : targets_)
    {
        if (!target->breakpointSuspension) continue;
        auto header = target->transport.Header();
        status_.breakpoint = true;
        status_.stoppedCall = header->breakpoint.event;
        status_.stoppedTarget = target->id;
        status_.stoppedPointerSize = target->pointerSize;
        status_.leaving = header->breakpoint.phase == static_cast<LONG>(BreakpointPhase::Leave);
        const auto definition = TraceStore::ReadApi(databasePath_, target->pid, status_.stoppedCall.api,
            status_.stoppedDefinition);
        status_.message = L"Paused at " + Wide(definition.name);
        break;
    }
}

class ProfilingRegistration
{
public:
    ProfilingRegistration() = default;
    ProfilingRegistration(const ProfilingRegistration&) = delete;
    ProfilingRegistration& operator=(const ProfilingRegistration&) = delete;
    ~ProfilingRegistration()
    {
        if (key_.empty()) return;
        for (const auto view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY})
        {
            RegDeleteKeyExW(HKEY_CURRENT_USER, server_.c_str(), view, 0);
            RegDeleteKeyExW(HKEY_CURRENT_USER, key_.c_str(), view, 0);
        }
    }

    void Create()
    {
        // CLR 2 resolves the profiler through COM; each capture owns an independent per-user class.
        auto path = ModuleDirectory() + L"\\DetouristProfiler.dll";
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
            throw std::runtime_error("DetouristProfiler.dll is missing from the portable application folder.");
        GUID identifier{};
        wchar_t text[40]{};
        Check(SUCCEEDED(CoCreateGuid(&identifier)) && StringFromGUID2(identifier, text, std::size(text)),
            "Create profiler identity");
        classId_ = text;
        auto keyName = L"Software\\Classes\\CLSID\\" + classId_;
        auto registerView = [&](REGSAM view, const std::wstring& profilerPath, bool requireNew)
        {
            HKEY raw = nullptr;
            DWORD disposition = 0;
            auto result = RegCreateKeyExW(HKEY_CURRENT_USER, keyName.c_str(), 0, nullptr, 0,
                KEY_WRITE | view, nullptr, &raw, &disposition);
            if (result != ERROR_SUCCESS)
                throw std::runtime_error("Create profiler activation: " + Utf8(ErrorText(result)));
            std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> classKey(raw, &RegCloseKey);
            if (requireNew && disposition != REG_CREATED_NEW_KEY)
                throw std::runtime_error("The capture's profiler identity already exists.");
            result = RegCreateKeyExW(classKey.get(), L"InprocServer32", 0, nullptr, 0,
                KEY_WRITE | view, nullptr, &raw, nullptr);
            if (result != ERROR_SUCCESS)
                throw std::runtime_error("Create profiler activation: " + Utf8(ErrorText(result)));
            std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> serverKey(raw, &RegCloseKey);
            result = RegSetValueExW(serverKey.get(), nullptr, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(profilerPath.c_str()),
                static_cast<DWORD>((profilerPath.size() + 1) * sizeof(wchar_t)));
            if (result == ERROR_SUCCESS)
            {
                constexpr wchar_t threading[] = L"Both";
                result = RegSetValueExW(serverKey.get(), L"ThreadingModel", 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(threading), sizeof(threading));
            }
            if (result != ERROR_SUCCESS)
                throw std::runtime_error("Configure profiler activation: " + Utf8(ErrorText(result)));
        };
        registerView(RegistryView, path, true);
        key_ = keyName;
        server_ = key_ + L"\\InprocServer32";
        auto siblingPath = ArchitectureDirectory(sizeof(void*) == 8 ? 4 : 8) + L"\\DetouristProfiler.dll";
        if (GetFileAttributesW(siblingPath.c_str()) != INVALID_FILE_ATTRIBUTES)
            registerView(sizeof(void*) == 8 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY, siblingPath, false);
    }
    const std::wstring& ClassId() const { return classId_; }

private:
    static constexpr REGSAM RegistryView = sizeof(void*) == 8 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
    std::wstring classId_, key_, server_;
};

std::vector<wchar_t> ProfilingEnvironment(const std::wstring& classId)
{
    auto compare = [](const std::wstring& left, const std::wstring& right)
    {
        return _wcsicmp(left.c_str(), right.c_str()) < 0;
    };
    std::map<std::wstring, std::wstring, decltype(compare)> values(compare);
    auto inherited = GetEnvironmentStringsW();
    Check(inherited != nullptr, "Read launch environment");
    for (auto entry = inherited; *entry; entry += wcslen(entry) + 1)
    {
        auto separator = wcschr(entry + 1, L'=');
        if (separator) values.emplace(std::wstring(entry, separator), separator + 1);
    }
    FreeEnvironmentStringsW(inherited);
    auto path = ModuleDirectory() + L"\\DetouristProfiler.dll";
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
        throw std::runtime_error("DetouristProfiler.dll is missing from the portable application folder.");
    auto siblingPath = ArchitectureDirectory(sizeof(void*) == 8 ? 4 : 8) + L"\\DetouristProfiler.dll";
    bool hasSibling = GetFileAttributesW(siblingPath.c_str()) != INVALID_FILE_ATTRIBUTES;
    for (const auto prefix : {L"COR_", L"CORECLR_"})
    {
        auto name = std::wstring(prefix);
        values[name + L"ENABLE_PROFILING"] = L"1";
        values[name + L"PROFILER"] = classId;
        values[name + L"PROFILER_PATH"] = path;
        values[name + (sizeof(void*) == 8 ? L"PROFILER_PATH_64" : L"PROFILER_PATH_32")] = path;
        if (hasSibling)
            values[name + (sizeof(void*) == 8 ? L"PROFILER_PATH_32" : L"PROFILER_PATH_64")] = siblingPath;
    }
    values[L"COMPlus_ReadyToRun"] = L"0";
    values[L"DOTNET_ReadyToRun"] = L"0";
    std::vector<wchar_t> environment;
    for (const auto& [name, value] : values)
    {
        auto entry = name + L"=" + value;
        environment.insert(environment.end(), entry.begin(), entry.end());
        environment.push_back(0);
    }
    environment.push_back(0);
    return environment;
}

void Session::Run(uint32_t attachPid, std::wstring executable, std::wstring arguments)
{
    Handle ownedProcess, primaryThread;
    ProfilingRegistration profiling;
    try
    {
        store_ = std::make_unique<TraceStore>(databasePath_);
#ifdef DETOURIST_BUILD_PROFILER
        profilerLaunch_ = !attachPid && (options_.apiMask & ManagedApis);
        if (!attachPid && options_.instructionEngine) profilerLaunch_ = true;
#endif
        if (!attachPid)
        {
            executable = std::filesystem::absolute(executable).wstring();
            auto workingDirectory = options_.workingDirectory.empty() ?
                std::filesystem::path(executable).parent_path().wstring() :
                std::filesystem::absolute(options_.workingDirectory).wstring();
            std::wstring command = L"\"" + executable + L"\"";
            if (!arguments.empty()) command += L" " + arguments;
            STARTUPINFOW startup{sizeof(startup)};
            if (options_.startMinimized)
            {
                startup.dwFlags = STARTF_USESHOWWINDOW;
                startup.wShowWindow = SW_SHOWMINNOACTIVE;
            }
            PROCESS_INFORMATION process{};
            if (profilerLaunch_) profiling.Create();
            auto environment = profiling.ClassId().empty() ? std::vector<wchar_t>{} :
                ProfilingEnvironment(profiling.ClassId());

            // Console targets need an interactive console independent of the collector's redirected I/O.
            Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
                environment.empty() ? nullptr : environment.data(), workingDirectory.c_str(), &startup, &process) != FALSE,
                "Launch target");
            ownedProcess.reset(process.hProcess);
            primaryThread.reset(process.hThread);
            attachPid = process.dwProcessId;
            InitializeLoader(ownedProcess.get(), attachPid, primaryThread.get(), cancelAttach_.get());
        }
        RegisterTarget(PrepareTarget(attachPid, 0, static_cast<bool>(primaryThread)));
        PumpDebugger();
        if (primaryThread) { ResumeThread(primaryThread.get()); primaryThread.reset(); }
        ownedProcess.reset();
        {
            std::lock_guard lock(mutex_);
            status_.capturing = true;
        }
        PublishStatus(L"Capturing");
        auto stopStarted = uint64_t{};
        auto nextFlush = GetTickCount64() + FlushIntervalMs;
        auto nextStatus = GetTickCount64();
        uint32_t failedTargets = 0;
        bool traceLimitReached = false;
        const auto traceStopBytes = static_cast<uint64_t>(options_.traceStopMiB) << 20;
        const auto walPath = traceStopBytes ? std::filesystem::path(databasePath_ + L"-wal") :
            std::filesystem::path{};

        // Bound each polling pass so child control and debugger commands keep making progress.
        for (;;)
        {
            bool alive = false;
            bool work = false;
            if (stop_ && !stopStarted) stopStarted = GetTickCount64();
            CompleteAttachments();
            PumpDebugger();
            for (size_t index = 0; index < targets_.size();)
            {
                auto& target = *targets_[index];
                auto header = target.transport.Header();
                target.transport.ServiceThreadIds(target.process.get(), target.pid);
                RecordModuleChanges(target);
#ifdef DETOURIST_BUILD_PROFILER
                if (target.managedAttach.valid() &&
                    target.managedAttach.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)
                {
                    auto attachment = target.managedAttach.get();
                    auto result = attachment.result;
                    target.managedDebugger = std::move(attachment.debugger);
                    target.probeManaged = result == S_FALSE;
                    target.nextManagedProbe = GetTickCount64() + ManagedProbeIntervalMs;
                    if (FAILED(result))
                    {
                        header->managedState = static_cast<LONG>(ManagedState::Failed);
                        wchar_t code[24];
                        swprintf_s(code, L"0x%08X", static_cast<uint32_t>(result));
                        store_->Diagnostic(target.id, result == E_NOTIMPL ?
                            L"This managed runtime requires tracing from launch." :
                            L"Managed profiler attachment failed: " + std::wstring(code));
                    }
                }
                if (!stop_ && target.phase == TargetPhase::Recording && (filters_.load() & ManagedApis) &&
                    target.probeManaged && !target.managedAttach.valid() &&
                    GetTickCount64() >= target.nextManagedProbe)
                {
                    if (header->managedState != static_cast<LONG>(ManagedState::Inactive)) target.probeManaged = false;
                    else target.managedAttach = std::async(std::launch::async,
                        [&target]()
                    {
                        return AttachManagedProfiler(target.pid, target.transport, target.pointerSize);
                    });
                }
#endif
                ApplyExclusions(target);
                bool preparingChild = std::any_of(attachments_.begin(), attachments_.end(),
                    [&target](const Attachment& attachment)
                    {
                        return attachment.request && attachment.parent == target.id;
                    });
                if (stop_)
                {
                    target.phase = TargetPhase::Draining;
                    InterlockedExchange(&header->capturePaused, 1);
                    if (!preparingChild) InterlockedCompareExchange(&header->stop, TransportStopping, 0);
                }
                if (!preparingChild &&
                    (forceStop_ || (stopStarted && GetTickCount64() - stopStarted > StopDrainTimeoutMs)))
                    target.transport.Stop();
                auto received = target.transport.ReadBatch(TransportBatchSize, [&](const RecordView& record)
                {
                    store_->Add(target.id, record);
                });
                work |= received != 0;
                for (auto& child : header->children)
                {
                    // Caller-suspended children retain a target slot while releasing active bootstrap capacity.
                    if (!stop_ && std::count_if(attachments_.begin(), attachments_.end(),
                        [](const Attachment& attachment)
                        {
                            return attachment.progress->load() != static_cast<LONG>(AttachmentProgress::ApcQueued);
                        }) >= MaxConcurrentAttachments) break;
                    if (InterlockedCompareExchange(&child.state,
                        static_cast<LONG>(ChildRequestState::Attaching),
                        static_cast<LONG>(ChildRequestState::Pending)) != static_cast<LONG>(ChildRequestState::Pending))
                        continue;
                    try
                    {
                        if (!stop_ && targets_.size() + attachments_.size() < MAXIMUM_WAIT_OBJECTS)
                        {
                            auto pid = child.processId, tid = child.threadId;
                            auto parent = target.id;
                            bool suspended = child.suspended != 0;
                            auto progress = std::make_shared<std::atomic<LONG>>(
                                static_cast<LONG>(AttachmentProgress::Starting));
                            attachments_.push_back({&child, parent, pid, progress, std::async(std::launch::async,
                                [this, pid, tid, parent, suspended, progress]
                                {
                                    return PrepareTarget(pid, parent, true, tid, suspended, progress);
                                })});
                            preparingChild = true;
                            continue;
                        }
                        else throw std::runtime_error("Child capture stopped or process limit reached.");
                    }
                    catch (const std::exception& error)
                    {
                        child.error = ERROR_NOT_SUPPORTED;
                        RecordSkippedChild(target.id, child.processId, Wide(error.what()));
                    }
                    if (InterlockedCompareExchange(&child.state,
                        static_cast<LONG>(ChildRequestState::Complete),
                        static_cast<LONG>(ChildRequestState::Attaching)) ==
                        static_cast<LONG>(ChildRequestState::Abandoned))
                        InterlockedExchange(&child.state, static_cast<LONG>(ChildRequestState::Idle));
                }
                bool unclaimedChild = !stop_ && std::any_of(std::begin(header->children), std::end(header->children),
                    [](ChildRequest& child)
                    {
                        return InterlockedCompareExchange(&child.state, 0, 0) ==
                            static_cast<LONG>(ChildRequestState::Pending);
                    });
                bool exited = WaitForSingleObject(target.process.get(), 0) == WAIT_OBJECT_0;
                bool stopped = header->state == static_cast<LONG>(AgentState::Stopped);
                if (exited || stopped) RecordModuleChanges(target);
                bool drained = header->dequeue == header->enqueue;
                if ((exited || stopped) && (drained || !work) && !preparingChild && !unclaimedChild)
                {
                    target.phase = TargetPhase::Draining;
                    if (target.managedAttach.valid()) { alive = true; ++index; continue; }
                    if (!target.detaching.valid())
                    {
                        target.detaching = std::async(std::launch::async, [&target, exited, header]
                        {
                            auto result = target.managedDebugger ? target.managedDebugger->Shutdown() : S_OK;
                            target.managedDebugger.reset();
#ifdef DETOURIST_INSTRUCTION_ENGINE
                            if (!exited && (header->instructionState == static_cast<LONG>(InstructionState::Active) ||
                                header->instructionState == static_cast<LONG>(InstructionState::Stopping)))
                                StopInstructionEngine(target.pid, *header);
#endif
                            return result;
                        });
                    }
                    if (target.detaching.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                    { alive = true; ++index; continue; }
                    if (FAILED(target.detaching.get()) && !exited)
                        store_->Diagnostic(target.id, L"Managed debugger detachment failed.");

                    // Detaching publishes the returns that the managed debugger and instruction engine still held.
                    while (target.transport.ReadBatch(TransportBatchSize, [&](const RecordView& record)
                    {
                        store_->Add(target.id, record);
                    })) {}
                    drained = header->dequeue == header->enqueue;
                    std::wstring targetState = exited ? L"Exited" : L"Detached";
                    DWORD exitCode = 0;
                    if (exited && GetExitCodeProcess(target.process.get(), &exitCode) && exitCode)
                    {
                        wchar_t code[24];
                        swprintf_s(code, L"0x%08lX", exitCode);
                        targetState += L" (" + std::wstring(code) + L")";
                        if (std::find(options_.expectedExitCodes.begin(), options_.expectedExitCodes.end(), exitCode) ==
                            options_.expectedExitCodes.end())
                        {
                            store_->Diagnostic(target.id, L"Target exited with code " + std::wstring(code));
                            ++failedTargets;
                        }
                    }
                    store_->UpdateCoverage(target.id, *header);
                    store_->TargetState(target.id, targetState, exited);
                    if (header->asyncUntracked)
                        store_->Diagnostic(target.id, std::to_wstring(header->asyncUntracked) +
                                                          L" asynchronous submissions lost completion tracking because "
                                                          L"controls were reused, capacity was exhausted, or the "
                                                          L"registry was busy.");
                    if (header->asyncCallbackErrors)
                        store_->Diagnostic(target.id, std::to_wstring(header->asyncCallbackErrors) +
                            L" asynchronous callbacks could not be observed before application dispatch.");
                    if (!drained)
                        store_->Diagnostic(target.id, L"Capture ended with uncommitted records.");
                    else if (store_->HasUnfinishedCalls(target.id))
                        store_->Diagnostic(target.id, L"Capture ended before all calls returned.");

                    // Retire the drained target so its transport mapping and kernel handles are released immediately.
                    std::unique_ptr<Target> retired;
                    {
                        std::lock_guard lock(mutex_);
                        retiredRecords_ += static_cast<uint64_t>(header->dequeue);
                        retiredBlockedMilliseconds_ += static_cast<double>(header->waitTicks) * 1000 /
                            static_cast<double>(header->frequency);
                        if (status_.breakpoint && status_.stoppedTarget == target.id)
                        {
                            status_.breakpoint = false;
                            status_.stoppedCall = {};
                            status_.stoppedDefinition = {};
                            status_.stoppedTarget = 0;
                            status_.stoppedPointerSize = 0;
                            status_.leaving = false;
                            resumeRequested_ = false;
                        }
                        retired = std::move(targets_[index]);
                        targets_.erase(targets_.begin() + index);
                    }
                    continue;
                }
                alive = true;
                ++index;
            }
            auto now = GetTickCount64();
            if (now >= nextFlush)
            {
                store_->Flush();
                nextFlush = now + FlushIntervalMs;

                // Measure the live database and WAL before switching to the ordinary stop and drain path.
                if (traceStopBytes && !stop_ && alive)
                {
                    std::error_code error;
                    auto walBytes = std::filesystem::file_size(walPath, error);
                    if (error && error != std::errc::no_such_file_or_directory)
                        throw std::filesystem::filesystem_error("Measure trace journal", walPath, error);
                    if (std::filesystem::file_size(databasePath_) + (error ? 0 : walBytes) >= traceStopBytes)
                    {
                        traceLimitReached = true;
                        store_->Diagnostic(0, L"Capture reached the configured trace size threshold.");
                        Stop();
                    }
                }
            }
            for (auto& target : targets_)
            {
                // Images load fastest at startup, so early passes run closer together.
                if (target->phase != TargetPhase::Recording || now < target->nextModules) continue;
                RecordModules(*target);
                target->nextModules = now + target->moduleInterval;
                target->moduleInterval = std::min<uint32_t>(target->moduleInterval * 2, MaxModuleIntervalMs);
            }
            if (now >= nextStatus)
            {
                for (auto& target : targets_) store_->UpdateCoverage(target->id, *target->transport.Header());
                PublishStatus();
                nextStatus = now + StatusPublishIntervalMs;
            }

            // Children attached in this pass remain active even when every previously visited parent has exited.
            if (!alive && attachments_.empty() && targets_.empty()) break;
            if (!work)
            {
                // Published records wake an idle collector without waiting for the polling timer.
                HANDLE events[MAXIMUM_WAIT_OBJECTS];
                DWORD count = 0;
                for (const auto& target : targets_)
                    if (count < MAXIMUM_WAIT_OBJECTS)
                        events[count++] = target->transport.DataEvent();
                if (count) WaitForMultipleObjects(count, events, FALSE, IdleWaitMs);
                else Sleep(IdleWaitMs);
            }
        }
        store_->Finish();
        std::wstring summary = traceLimitReached ? L"Capture reached the configured trace size threshold." :
            skippedChildren_ ?
            L"Partial capture finished: " + std::to_wstring(skippedChildren_) +
                (skippedChildren_ == 1 ? L" child process was not attached." : L" child processes were not attached.") :
            L"Capture finished.";
        if (failedTargets)
            summary += L" " + std::to_wstring(failedTargets) +
                (failedTargets == 1 ? L" target exited" : L" targets exited") + L" with a nonzero exit code.";
        else summary += L" Recorded calls remain available in the database.";
        PublishStatus(summary);
    }
    catch (const std::exception& error)
    {
        Stop();
        // Startup only owns processes created by this session; attached targets always survive cleanup.
        if (ownedProcess) TerminateProcess(ownedProcess.get(), ERROR_CANCELLED);
        for (auto& target : targets_) target->breakpointSuspension.reset();
        CompleteAttachments(true);
        for (auto& target : targets_)
        {
            target->transport.Stop();
            target->breakpointSuspension.reset();
        }
        try
        {
            if (store_) { store_->Diagnostic(0, Wide(error.what())); store_->Finish(); }
        }
        catch (...) {}
        PublishStatus(L"Capture stopped: " + Wide(error.what()));
    }
    std::lock_guard lock(mutex_);
    status_.capturing = false;
    status_.finished = true;
    status_.breakpoint = false;
}
}

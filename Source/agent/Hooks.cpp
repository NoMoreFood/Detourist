#include "Agent.h"
#include "DetoursAllocation.h"
#include <memory>
#include <system_error>
#include <detours.h>
#include <intrin.h>
#include <vector>
#include <stdexcept>
#include <utility>
#include <atomic>

extern "C"
{
__declspec(dllexport) volatile LONG64 DetouristNativeHookAddresses[Detourist::NativeHookCapacity]{};
__declspec(dllexport) volatile LONG DetouristNativeHookApis[Detourist::NativeHookCapacity]{};
__declspec(dllexport) volatile LONG64 DetouristInternalCallerRanges[Detourist::InternalNativeImageCount * 2]{};
}

namespace Detourist
{
constexpr DWORD ChildPollMs = 1;
constexpr uint32_t MaxForwarderDepth = 8;
constexpr size_t DetourPatchBytes = 5;
constexpr size_t MaxX86InstructionBytes = 15;
constexpr size_t MaxLifetimeHooks = 65536;

bool BroadHooks = false;
uint32_t InstalledNativeCount = 0;
uint32_t AvailableNativeCount = 0;
#define CORE_API(name, failure) decltype(&::name) Original##name = &::name;
#include "CoreCatalog.inc"
#undef CORE_API

template<class T> T Return(Call& call, T result, DWORD error)
{
    call.Finish(Bits(result), error);
    SetLastError(call.event.error);
    if constexpr (std::is_pointer_v<T>) return reinterpret_cast<T>(call.event.result);
    else return static_cast<T>(call.event.result);
}

template<Api Id, auto& Original, class Function = std::remove_reference_t<decltype(Original)>> struct CoreHook;

template<Api Id, auto& Original, class Result, class... Args>
struct CoreHook<Id, Original, Result (WINAPI*)(Args...)>
{
    template<size_t... Indices> static Result InvokeOriginal(Call& call, std::index_sequence<Indices...>)
    {
        return call.Invoke([&]
        {
            return call.skipped ? Result{} : Original(Argument<Args>(call, Indices)...);
        });
    }

    static Result WINAPI Invoke(Args... arguments)
    {
        Call call(Id, {Bits(arguments)...}, _ReturnAddress());
        std::index_sequence_for<Args...> indices;

        // Child capture owns the initial thread until the collector has observed the creation.
        if constexpr (Id == Api::CreateProcessW)
        {
            ChildLaunch child(call);
            auto result = InvokeOriginal(call, indices);
            child.Complete(result != FALSE);
            return Return(call, result, GetLastError());
        }
        else
        {
            auto result = InvokeOriginal(call, indices);
            return Return(call, result, GetLastError());
        }
    }
};

ChildLaunch::ChildLaunch(Call& call) : call_(call)
{
    // A single creation boundary owns the request even when Win32 calls another creation API internally.
    if (!call.transport || !call.transport->Header()->followChildren || call.skipped || FollowingChild) return;
    auto observing = std::exchange(ObserverActive, true);
    auto error = GetLastError(), status = NativeThreadStatus();
    auto header = call.transport->Header();
    int64_t waitStarted = 0;

    // Claim a request before creation so the child's initial thread starts suspended.
    while (!header->stop && call.transport->CollectorAlive())
    {
        for (auto& candidate : header->children)
            if (InterlockedCompareExchange(&candidate.state, static_cast<LONG>(ChildRequestState::Claimed),
                static_cast<LONG>(ChildRequestState::Idle)) == static_cast<LONG>(ChildRequestState::Idle))
            {
                request_ = &candidate;
                break;
            }
        if (request_) break;
        if (!waitStarted) waitStarted = Clock();
        Sleep(ChildPollMs);
    }
    if (waitStarted) InterlockedAdd64(&header->waitTicks, Clock() - waitStarted);
    if (request_)
    {
        native_ = call.event.api == Api::NtCreateUserProcess;
        flagIndex_ = ChildFlagsArgument(call.event.api);
        flags_ = static_cast<uint32_t>(call.event.arguments[flagIndex_]);
        call.event.arguments[flagIndex_] = flags_ | (native_ ? 1u : CREATE_SUSPENDED);
        FollowingChild = true;
    }
    SetLastError(error);
    RestoreNativeThreadStatus(status);
    ObserverActive = observing;
}

void ChildLaunch::Complete(bool success)
{
    if (!request_) return;
    auto observing = std::exchange(ObserverActive, true);
    auto error = GetLastError(), status = NativeThreadStatus();
    auto header = call_.transport->Header();
    call_.event.arguments[flagIndex_] = flags_;
    FollowingChild = false;
    PROCESS_INFORMATION information{};
    if (success && native_)
    {
        ReadCaptureMemory(reinterpret_cast<void*>(call_.event.arguments[0]), &information.hProcess, sizeof(HANDLE));
        ReadCaptureMemory(reinterpret_cast<void*>(call_.event.arguments[1]), &information.hThread, sizeof(HANDLE));
        information.dwProcessId = GetProcessId(information.hProcess);
        information.dwThreadId = GetThreadId(information.hThread);
        success = information.dwProcessId && information.dwThreadId;
    }
    else if (success)
        success = ReadCaptureMemory(reinterpret_cast<void*>(
            call_.event.arguments[ChildOutputArgument(call_.event.api)]), &information, sizeof(information));
    if (success)
    {
        request_->processId = information.dwProcessId;
        request_->threadId = information.dwThreadId;
        request_->error = 0;
        request_->suspended = (flags_ & (native_ ? 1u : CREATE_SUSPENDED)) != 0;
        InterlockedExchange(&request_->state, static_cast<LONG>(ChildRequestState::Pending));
        SetEvent(call_.transport->DataEvent());
        auto started = Clock();
        while (request_->state != static_cast<LONG>(ChildRequestState::Complete) &&
            !header->stop && call_.transport->CollectorAlive()) Sleep(ChildPollMs);
        InterlockedAdd64(&header->waitTicks, Clock() - started);
    }
    if (information.hThread && !(flags_ & (native_ ? 1u : CREATE_SUSPENDED))) ResumeThread(information.hThread);

    // A canceled request cannot be reused while the collector still owns it.
    for (;;)
    {
        auto state = request_->state;
        const auto next = static_cast<LONG>(state == static_cast<LONG>(ChildRequestState::Attaching) ?
            ChildRequestState::Abandoned : ChildRequestState::Idle);
        if (InterlockedCompareExchange(&request_->state, next, state) == state) break;
    }
    request_ = nullptr;
    SetLastError(error);
    RestoreNativeThreadStatus(status);
    ObserverActive = observing;
}

struct InstalledHook
{
    HookDefinition hook;
    void* address;
    void* entry;
    HMODULE owner;
    HMODULE privateProvider;
    bool attached;
};
std::vector<InstalledHook> HookRegistry;
uint32_t LifetimeHooks = 0;
using HookModule = std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)>;
thread_local std::vector<HookModule>* HookModuleReferences = nullptr;
std::atomic<void*> NativeHookOriginals[NativeHookCapacity]{};

void PublishNativeHookAddress(void* address, Api api, void* original, bool installed)
{
    auto value = reinterpret_cast<LONG64>(address);
    auto bucket = (static_cast<uint64_t>(value) >> 4) % std::size(DetouristNativeHookAddresses);
    for (size_t step = 0; step < std::size(DetouristNativeHookAddresses); ++step)
    {
        auto index = (bucket + step) % std::size(DetouristNativeHookAddresses);
        auto& slot = DetouristNativeHookAddresses[index];
        auto current = slot;
        if (installed && (current == 0 || current == 1))
        {
            NativeHookOriginals[index].store(original, std::memory_order_release);
            InterlockedExchange(&DetouristNativeHookApis[index], static_cast<LONG>(api));
            InterlockedExchange64(&slot, value);
            return;
        }
        if (current == value)
        {
            if (!installed) InterlockedExchange64(&slot, 1);
            return;
        }
        if (!installed && !current) return;
    }
    throw std::runtime_error("Capture hook address limit reached.");
}

FARPROC NativeInteropTarget(FARPROC function)
{
    auto address = reinterpret_cast<void*>(function);
    for (uint32_t depth = 0; depth < MaxForwarderDepth; ++depth)
    {
        auto original = ExportInteropTarget(reinterpret_cast<FARPROC>(address));
        if (original != reinterpret_cast<FARPROC>(address)) return original;
        if (BroadHooks)
        {
            auto observer = Win32uInteropObserver(reinterpret_cast<FARPROC>(address));
            if (observer != reinterpret_cast<FARPROC>(address)) return observer;
        }
        auto value = reinterpret_cast<LONG64>(address);
        auto bucket = (static_cast<uint64_t>(value) >> 4) % NativeHookCapacity;
        for (uint32_t step = 0; step < NativeHookCapacity; ++step)
        {
            auto index = (bucket + step) % NativeHookCapacity;
            auto current = DetouristNativeHookAddresses[index];
            if (current == value)
                return reinterpret_cast<FARPROC>(NativeHookOriginals[index].load(std::memory_order_acquire));
            if (!current) break;
        }

        // Alias observers call the unmodified implementation without entering a differently named observer.
        BYTE code[7]{};
        if (!ReadCaptureMemory(address, code, sizeof(code))) break;
        auto start = static_cast<const BYTE*>(address);
        int32_t displacement = 0;
        auto prefix = sizeof(void*) == 8 && code[0] == 0x48 ? 1 : 0;
        if (code[prefix] == 0xFF && code[prefix + 1] == 0x25)
        {
            memcpy(&displacement, code + prefix + 2, sizeof(displacement));
#ifdef _WIN64
            auto slot = start + prefix + 6 + displacement;
#else
            auto slot = reinterpret_cast<const BYTE*>(static_cast<uint32_t>(displacement));
#endif
            if (!ReadCaptureMemory(slot, &address, sizeof(address))) break;
        }
        else if (code[0] == 0xE9)
        {
            memcpy(&displacement, code + 1, sizeof(displacement));
            address = const_cast<BYTE*>(start + 5 + displacement);
        }
        else if (code[0] == 0xEB) address = const_cast<BYTE*>(start + 2 + static_cast<int8_t>(code[1]));
        else break;
    }
    return function;
}

void CountInstalledHooks()
{
    InstalledNativeCount = AvailableNativeCount = InstalledWin32Count = AvailableWin32Count = InstalledComCount = 0;
    InstalledExportCount = 0;
    for (const auto& item : HookRegistry)
    {
        if (IsNativeApi(item.hook.api))
        {
            ++AvailableNativeCount;
            if (item.attached) ++InstalledNativeCount;
        }
        else if (IsWin32Api(item.hook.api) || IsWin32uApi(item.hook.api) ||
            static_cast<uint32_t>(item.hook.api) < NativeApiStart)
        {
            ++AvailableWin32Count;
            if (item.attached) ++InstalledWin32Count;
        }
        else if (IsComApi(item.hook.api) && item.attached) ++InstalledComCount;
        else if (IsExportApi(item.hook.api) && item.attached) ++InstalledExportCount;
    }
}

void AddUnpatchedWin32Hooks(std::vector<HookDefinition>& hooks)
{
    // Imports retain typed observers when the function's entry instructions cannot be relocated safely.
    for (const auto& item : HookRegistry)
        if (!item.attached && IsWin32Api(item.hook.api)) hooks.push_back(item.hook);
}

HMODULE ResolveHookModule(const wchar_t* name)
{
    HMODULE module = nullptr;
    if (!HookModuleReferences || !GetModuleHandleExW(0, name, &module)) return nullptr;
    HookModule reference(module, &FreeLibrary);
    HookModuleReferences->push_back(std::move(reference));
    return module;
}

bool RelocatesCall(void* address)
{
    // Relocated calls can leave an exception return address without Windows unwind metadata.
    auto start = static_cast<const BYTE*>(address);
    auto instruction = start;
    while (instruction - start < DetourPatchBytes)
    {
        auto next = static_cast<const BYTE*>(DetourCopyInstruction(nullptr, nullptr,
            const_cast<BYTE*>(instruction), nullptr, nullptr));
        if (!next || next <= instruction || next - instruction > MaxX86InstructionBytes) return true;
        auto opcode = instruction;
        while (opcode < next && ((*opcode >= 0x40 && *opcode <= 0x4F) || *opcode == 0x66 ||
            *opcode == 0x67 || *opcode == 0xF2 || *opcode == 0xF3 || *opcode == 0x2E || *opcode == 0x3E ||
            *opcode == 0x26 || *opcode == 0x36 || *opcode == 0x64 || *opcode == 0x65)) ++opcode;
        if (opcode < next && (*opcode == 0xE8 || (*opcode == 0xFF && opcode + 1 < next &&
            ((opcode[1] >> 3) & 7) == 2))) return true;
        instruction = next;
    }
    return false;
}

std::pair<HMODULE, bool> HookTargetModule(void* address, DWORD flags)
{
    // Sandbox exports can forward through private executable stubs into their owning image.
    for (unsigned depth = 0; depth < MaxForwarderDepth; ++depth)
    {
        HMODULE module = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | flags,
            reinterpret_cast<LPCWSTR>(address), &module)) return {module, depth != 0};
        MEMORY_BASIC_INFORMATION region{};
        BYTE code[sizeof(void*) == 8 ? 12 : 7]{};
        if (!VirtualQuery(address, &region, sizeof(region)) || region.Type != MEM_PRIVATE ||
            region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD) ||
            !(region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
            !ReadCaptureMemory(address, code, sizeof(code))) break;
        uintptr_t destination = 0;
        if constexpr (sizeof(void*) == 8)
        {
            if (code[0] != 0x48 || code[1] != 0xB8 || code[10] != 0xFF || code[11] != 0xE0) break;
            memcpy(&destination, code + 2, sizeof(destination));
        }
        else
        {
            if (code[0] != 0xB8 || code[5] != 0xFF || code[6] != 0xE0) break;
            memcpy(&destination, code + 1, sizeof(destination));
        }
        address = reinterpret_cast<void*>(destination);
    }
    SetLastError(ERROR_MOD_NOT_FOUND);
    return {nullptr, false};
}

uint64_t CommitHooks(std::vector<HookDefinition>& hooks, Transport* transport)
{
    if (BroadHooks)
    {
        // The agent owns native waits because dispatcher transfer is unsafe during CLR startup.
        auto native = GetModuleHandleW(L"ntdll.dll"), graphical = GetModuleHandleW(L"win32u.dll");
        std::erase_if(hooks, [&](const auto& hook)
        {
            if (hook.api == Api::NtWaitForSingleObject || IsStackHook(hook.observer)) return false;
            auto address = DetourCodeFromPointer(*hook.original, nullptr);
            auto module = HookTargetModule(address, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT).first;
            return module && (module == native || (graphical && module == graphical));
        });
    }
    if (hooks.empty()) return 0;
    if (LifetimeHooks + hooks.size() > MaxLifetimeHooks)
        throw std::runtime_error("Capture hook generation limit reached.");
    std::vector<InstalledHook> pending;
    std::vector<HookModule> owners;
    pending.reserve(hooks.size());
    owners.reserve(hooks.size());
    HookRegistry.reserve(HookRegistry.size() + hooks.size());
    for (const auto& hook : hooks)
    {
        auto address = DetourCodeFromPointer(*hook.original, nullptr);
        auto [module, privateForwarder] = HookTargetModule(address, 0);
        if (!module)
            throw std::system_error(GetLastError(), std::system_category(), "Cannot retain a capture hook module.");
        owners.emplace_back(module, &FreeLibrary);

        // Private export entries expire with their declared provider as well as their implementation image.
        HMODULE privateProvider = nullptr;
        if (privateForwarder && IsWin32Api(hook.api))
        {
            privateProvider = GetModuleHandleA(Definition(hook.api).module);
            if (!privateProvider)
                throw std::system_error(GetLastError(), std::system_category(), "Cannot retain a capture hook provider.");
        }
        pending.push_back({hook, address, *hook.original, module, privateProvider, false});
    }

    DetourSetIgnoreTooSmall(TRUE);
    LONG error = DetourTransactionBegin();
    if (error) throw std::system_error(error, std::system_category(), "Cannot start hook transaction.");
    uint64_t mask = 0;

    // Prepare trampolines before suspending threads to keep the stop interval short.
    for (auto& item : pending)
    {
        const auto& hook = item.hook;
        if (error) break;
        if (RelocatesCall(item.address) || (IsWin32Api(hook.api) && !ExportEntryPatchable(item.address))) continue;
        error = DetourAttach(hook.original, hook.observer);
        if (error == ERROR_INVALID_BLOCK) { error = NO_ERROR; continue; }
        if (!error)
        {
            item.attached = true;
            mask |= ApiMask(hook.api);
        }
    }
    if (error)
    {
        DetourTransactionAbort();
        throw std::system_error(error, std::system_category(), "Cannot install capture hooks.");
    }

    // Bind collector discovery to this transaction's retained channel before any peer is suspended.
    DetouristTransactionThreads::EnumerationContext = transport;
    DetouristTransactionThreads::StartupThread = transport ? transport->StartupThread() : nullptr;
    DetouristTransactionThreads::Enumerate = transport ?
        +[](void* context, DWORD* ids, DWORD capacity, DWORD* count) -> LONG
        {
            return static_cast<Transport*>(context)->RequestThreadIds(ids, capacity, count);
        } : nullptr;
    error = DetourTransactionCommit();
    DetouristTransactionThreads::Enumerate = nullptr;
    DetouristTransactionThreads::EnumerationContext = nullptr;
    DetouristTransactionThreads::StartupThread = nullptr;
    if (error)
        throw std::system_error(error, std::system_category(), "Cannot commit capture hooks.");
    mask = 0;
    for (auto& item : pending)
    {
        item.attached = item.attached && *item.hook.original != item.entry;
        if (item.attached)
        {
            mask |= ApiMask(item.hook.api);
            if (item.hook.api < Api::Count)
                PublishNativeHookAddress(item.address, item.hook.api, *item.hook.original, true);
        }
    }
    LifetimeHooks += static_cast<uint32_t>(pending.size());
    HookRegistry.insert(HookRegistry.end(), pending.begin(), pending.end());
    CountInstalledHooks();
    return mask;
}

void InvalidateHooks(HMODULE module, size_t size)
{
    auto base = reinterpret_cast<uintptr_t>(module);
    std::erase_if(HookRegistry, [&](const auto& item)
    {
        auto address = reinterpret_cast<uintptr_t>(item.address);
        if (item.owner != module && item.privateProvider != module && (address < base || address - base >= size))
            return false;
        if (item.attached && item.hook.api < Api::Count)
            PublishNativeHookAddress(item.address, item.hook.api, nullptr, false);
        *item.hook.original = nullptr;
        return true;
    });
    CountInstalledHooks();
    ForgetComModule(module, size);
    ForgetExportModule(module, size);
}

uint64_t RefreshHooks(Transport* transport, bool includeNative)
{
    const auto catalog = transport ? &transport->Catalog() : nullptr;

    // Temporary references protect mapped code throughout export inspection and patching.
    std::vector<HookModule> modules;
    std::vector<HookDefinition> hooks;
    hooks.reserve(HookRegistry.size() + static_cast<size_t>(Api::Count));
    for (auto& installed : HookRegistry)
        hooks.push_back({installed.hook.api, &installed.address, installed.hook.observer});
    auto existing = hooks.size();
    HookModuleReferences = &modules;
    try
    {
        if (includeNative && !BroadHooks)
        {
            // A capture can require native and loader hooks omitted by another capture mode.
            AddNativeHooks(hooks);
            AddModuleHooks(hooks);
        }
        if (!BroadHooks) AddWin32uHooks(hooks);
        AddWin32Hooks(hooks);
        if (!BroadHooks)
        {
            AddComHooks(hooks, ResolveHookModule(L"ole32.dll"));
            AddComHooks(hooks, ResolveHookModule(L"combase.dll"));
            if (catalog) AddExportHooks(hooks, *catalog);
        }
        hooks.erase(hooks.begin(), hooks.begin() + existing);
        existing = 0;
        auto result = CommitHooks(hooks, transport);

        // Committed trampolines remain valid if named import binding cannot finish.
        hooks.clear();
        ActivateExportHooks();
        HookModuleReferences = nullptr;
        return result;
    }
    catch (...)
    {
        HookModuleReferences = nullptr;
        for (size_t index = existing; index < hooks.size(); ++index) *hooks[index].original = nullptr;
        throw;
    }
}

uint64_t InstallHooks(Transport& transport)
{
    StartModuleNotifications();
#define CORE_API(name, failure) \
    {Api::name, reinterpret_cast<void**>(&Original##name), \
        reinterpret_cast<void*>(&CoreHook<Api::name, Original##name>::Invoke)},
    std::vector<HookDefinition> hooks =
    {
#include "CoreCatalog.inc"
    };
#undef CORE_API
    AddNativeHooks(hooks);
    AddModuleHooks(hooks);
    AddStackHooks(hooks);
    auto mask = CommitHooks(hooks, &transport);
    mask |= RefreshHooks(&transport);
    return mask;
}
}

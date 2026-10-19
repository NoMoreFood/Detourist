#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "Agent.h"
#include <array>
#include <atomic>
#include <memory>
#include <utility>

namespace Detourist
{
extern SRWLOCK ModuleChangeLock;
void ReportModuleError(DWORD error);
bool __cdecl ManagedCodeAddress(const void* address);

struct NativeGatewayRuntime
{
    BOOL (*running)() = nullptr;
    void (__fastcall* enter)(void*) = nullptr;
};
NativeGatewayRuntime GatewayRuntime;
constexpr uint64_t GatewayEnabled = uint64_t{1} << 63;
constexpr size_t NativeGatewayCodeBytes = 384;
constexpr size_t NativeGatewayCapacity = 4096;
constexpr size_t GatewayPageBytes = 4096;
constexpr DWORD GatewayDrainPollMs = 1;
constexpr size_t TebWow32ReservedOffset = 0xC0;
constexpr uintptr_t SharedUserDataSystemCall = 0x7FFE0300;
std::atomic<uint64_t> GatewayReaders = 0;
size_t NativeGatewayCount = 0;
struct NativeGateway { std::array<BYTE, NativeGatewayCodeBytes> code; };

NativeGatewayRuntime* AcquireNativeGateway()
{
    if (!NativeThreadReady() || ObserverActive) return nullptr;
    auto state = GatewayReaders.load(std::memory_order_acquire);
    while (state & GatewayEnabled)
        if (GatewayReaders.compare_exchange_weak(state, state + 1, std::memory_order_acquire))
            return &GatewayRuntime;
    return nullptr;
}
void ReleaseNativeGateway() { GatewayReaders.fetch_sub(1, std::memory_order_release); }

bool EnableNativeGateways(HMODULE runtime)
{
    GatewayRuntime.running = reinterpret_cast<BOOL (*)()>(GetProcAddress(runtime, "dr_app_running_under_dynamorio"));
    GatewayRuntime.enter = reinterpret_cast<void (__fastcall*)(void*)>(GetProcAddress(runtime, "dr_app_retakeover"));
    auto nativeCode = reinterpret_cast<void (*)(bool (__cdecl*)(const void*))>(
        GetProcAddress(runtime, "dr_app_native_code_query"));
    if (!GatewayRuntime.running || !GatewayRuntime.enter || !nativeCode) return false;
    nativeCode(&ManagedCodeAddress);
    GatewayReaders.store(GatewayEnabled, std::memory_order_release);
    return true;
}

void DisableNativeGateways()
{
    GatewayReaders.fetch_and(~GatewayEnabled, std::memory_order_acq_rel);
    while (GatewayReaders.load(std::memory_order_acquire)) Sleep(GatewayDrainPollMs);
    GatewayRuntime = {};
}

bool PrivateSyscallTarget(void* address, uint64_t& original, uint32_t& returned)
{
    MEMORY_BASIC_INFORMATION region{};
    std::array<BYTE, 16> code{};
    if (reinterpret_cast<uintptr_t>(address) % sizeof(uint64_t) ||
        !VirtualQuery(address, &region, sizeof(region)) || region.State != MEM_COMMIT ||
        region.Type != MEM_PRIVATE || region.Protect & PAGE_GUARD ||
        !(region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
        !ReadCaptureMemory(address, code.data(), code.size()) || code[0] != 0xB8) return false;

    // Recognize native and WOW64 service gates without treating arbitrary CLR thunks as syscall wrappers.
    if (code[5] == 0xBA && code[10] == 0xFF && (code[11] == 0xD2 || code[11] == 0x12))
    {
        uintptr_t entry = 0, transition = 0;
        memcpy(&entry, code.data() + 6, sizeof(entry));
        auto gate = entry;
        if (code[11] == 0x12 && !ReadCaptureMemory(reinterpret_cast<void*>(gate), &gate, sizeof(gate)))
            return false;
        if (!ReadCaptureMemory(reinterpret_cast<BYTE*>(NtCurrentTeb()) + TebWow32ReservedOffset,
            &transition, sizeof(transition)))
            return false;
        if (transition && gate != transition)
        {
            std::array<BYTE, 6> thunk{};
            if (!ReadCaptureMemory(reinterpret_cast<void*>(gate), thunk.data(), thunk.size()) ||
                thunk[0] != 0xFF || thunk[1] != 0x25) return false;
            memcpy(&gate, thunk.data() + 2, sizeof(gate));
            if (!ReadCaptureMemory(reinterpret_cast<void*>(gate), &gate, sizeof(gate)) || gate != transition)
                return false;
        }
        else if (!transition && (code[11] != 0x12 || entry != SharedUserDataSystemCall)) return false;
        returned = 12;
    }
    else if (code[5] == 0x64 && code[6] == 0xFF && code[7] == 0x15 && code[8] == 0xC0 &&
        !code[9] && !code[10] && !code[11]) returned = 12;
    else if (code[5] == 0x8B && code[6] == 0xD4 && code[7] == 0x0F && code[8] == 0x34) returned = 9;
    else return false;
    if (code[returned] != 0xC3 && code[returned] != 0xC2) return false;
    memcpy(&original, code.data(), sizeof(original));
    return true;
}

void WINAPI ObserveNativeDelegate(uintptr_t address)
{
    if (!address || !BroadHooks || !(GatewayReaders.load(std::memory_order_acquire) & GatewayEnabled)) return;
    const auto error = GetLastError();
    const auto status = NativeThreadStatus();
    const auto observing = std::exchange(ObserverActive, true);
    try
    {
        [&]()
        {
            auto target = reinterpret_cast<void*>(address);
            uint64_t original = 0;
            uint32_t returned = 0;
            if (!PrivateSyscallTarget(target, original, returned)) return;
            AcquireSRWLockExclusive(&ModuleChangeLock);
            std::unique_ptr<SRWLOCK, decltype(&ReleaseSRWLockExclusive)> lock(
                &ModuleChangeLock, &ReleaseSRWLockExclusive);
            if (!PrivateSyscallTarget(target, original, returned)) return;
            if (NativeGatewayCount >= NativeGatewayCapacity) { ReportModuleError(ERROR_NOT_ENOUGH_MEMORY); return; }
            auto release = [](NativeGateway* value) { if (value) VirtualFree(value, 0, MEM_RELEASE); };
            std::unique_ptr<NativeGateway, decltype(release)> allocation(static_cast<NativeGateway*>(
                VirtualAlloc(nullptr, GatewayPageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)), release);
            if (!allocation) { ReportModuleError(GetLastError()); return; }
            auto gate = allocation.get();
            size_t length = 0;
            auto emit = [&](std::initializer_list<BYTE> bytes)
            {
                if (bytes.size() > gate->code.size() - length) throw std::length_error("Native gateway overflow.");
                for (auto byte : bytes) gate->code[length++] = byte;
            };
            auto data = [&]<class T>(T value)
            {
                if (sizeof(value) > gate->code.size() - length) throw std::length_error("Native gateway overflow.");
                memcpy(gate->code.data() + length, &value, sizeof(value));
                length += sizeof(value);
            };
            auto branch = [&]() { auto offset = length; data(int32_t{}); return offset; };
            auto patch = [&](size_t offset)
            {
                auto distance = static_cast<int32_t>(length - offset - sizeof(int32_t));
                memcpy(gate->code.data() + offset, &distance, sizeof(distance));
            };

            // Keep stack arguments, integer registers, x87/SSE state and native error state across admission.
            emit({0x9C, 0x60, 0x8B, 0xEC, 0x81, 0xEC}); data(uint32_t{0x220});
            emit({0x83, 0xE4, 0xF0, 0x0F, 0xAE, 0x04, 0x24});
            for (auto offset : {offsetof(TEB, LastErrorValue), offsetof(TEB, LastStatusValue)})
            {
                emit({0x64, 0xA1}); data(static_cast<uint32_t>(offset));
                emit({0x89, 0x45, static_cast<BYTE>(offset == offsetof(TEB, LastErrorValue) ? 0xF8 : 0xF4)});
            }
            emit({0xB8}); data(reinterpret_cast<uintptr_t>(&AcquireNativeGateway));
            emit({0xFF, 0xD0, 0x85, 0xC0, 0x0F, 0x84}); auto restore = branch();
            emit({0x89, 0x45, 0xFC, 0xFF, 0x10, 0x85, 0xC0, 0x0F, 0x85}); auto leave = branch();
            emit({0xB9}); data(address + returned);
            emit({0x8B, 0x45, 0xFC, 0xFF, 0x50, 0x04});
            patch(leave);
            emit({0xB8}); data(reinterpret_cast<uintptr_t>(&ReleaseNativeGateway));
            emit({0xFF, 0xD0});
            patch(restore);
            for (auto offset : {offsetof(TEB, LastErrorValue), offsetof(TEB, LastStatusValue)})
            {
                emit({0x8B, 0x45, static_cast<BYTE>(offset == offsetof(TEB, LastErrorValue) ? 0xF8 : 0xF4)});
                emit({0x64, 0xA3}); data(static_cast<uint32_t>(offset));
            }
            emit({0x0F, 0xAE, 0x0C, 0x24, 0x8B, 0xE5, 0x61, 0x9D, 0xB8});
            data(static_cast<uint32_t>(original >> 8));
            emit({0xE9}); data(static_cast<uint32_t>(address + 5 -
                reinterpret_cast<uintptr_t>(gate->code.data() + length + sizeof(uint32_t))));
            DWORD protection = 0;
            if (!VirtualProtect(gate, GatewayPageBytes, PAGE_EXECUTE_READ, &protection) ||
                !FlushInstructionCache(GetCurrentProcess(), gate, length))
            { ReportModuleError(GetLastError()); return; }

            // Only the complete first instruction changes; concurrent instruction boundaries remain valid.
            auto distance = reinterpret_cast<uintptr_t>(gate) - (address + 5);
            auto patched = (original & UINT64_C(0xffffff0000000000)) | uint64_t{0xE9} | (uint64_t{distance} << 8);
            if (!VirtualProtect(target, sizeof(original), PAGE_EXECUTE_READWRITE, &protection))
            { ReportModuleError(GetLastError()); return; }
            bool published = static_cast<uint64_t>(InterlockedCompareExchange64(static_cast<volatile LONG64*>(target),
                static_cast<LONG64>(patched), static_cast<LONG64>(original))) == original;
            DWORD ignored = 0;
            if (!VirtualProtect(target, sizeof(original), protection, &ignored)) ReportModuleError(GetLastError());
            if (!published) return;
            ++NativeGatewayCount;
            allocation.release();
            if (!FlushInstructionCache(GetCurrentProcess(), target, sizeof(original)))
                ReportModuleError(GetLastError());
        }();
    }
    catch (...) { ReportModuleError(ERROR_NOT_ENOUGH_MEMORY); }
    ObserverActive = observing;
    RestoreNativeThreadStatus(status);
    SetLastError(error);
}
}

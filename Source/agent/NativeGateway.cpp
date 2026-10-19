#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "Agent.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <memory>
#include <stdexcept>
#include <utility>

namespace Detourist
{
extern SRWLOCK ModuleChangeLock;
void ReportModuleError(DWORD error);

struct NativeGatewayRuntime
{
    BOOL (*running)() = nullptr;
    void (*enter)(void*) = nullptr;
};
NativeGatewayRuntime GatewayRuntime;
constexpr uint64_t GatewayEnabled = uint64_t{1} << 63;
constexpr size_t NativeGatewayCodeBytes = 384;
constexpr size_t NativeGatewayCapacity = 4096;
constexpr size_t GatewayPageBytes = 4096;
constexpr DWORD GatewayDrainPollMs = 1;
std::atomic<uint64_t> GatewayReaders = 0;
size_t NativeGatewayCount = 0;

struct NativeGateway
{
    std::array<BYTE, NativeGatewayCodeBytes> code;
    void* target;
    RUNTIME_FUNCTION function;
    std::array<BYTE, 8> unwind;
};

NativeGatewayRuntime* AcquireNativeGateway()
{
    if (!NativeThreadReady() || ObserverActive) return nullptr;
    auto state = GatewayReaders.load(std::memory_order_acquire);
    while (state & GatewayEnabled)
        if (GatewayReaders.compare_exchange_weak(state, state + 1, std::memory_order_acquire))
            return &GatewayRuntime;
    return nullptr;
}

void ReleaseNativeGateway()
{
    GatewayReaders.fetch_sub(1, std::memory_order_release);
}

bool EnableNativeGateways(HMODULE runtime)
{
    GatewayRuntime.running = reinterpret_cast<BOOL (*)()>(GetProcAddress(runtime, "dr_app_running_under_dynamorio"));
    GatewayRuntime.enter = reinterpret_cast<void (*)(void*)>(GetProcAddress(runtime, "dr_app_retakeover"));
    if (!GatewayRuntime.running || !GatewayRuntime.enter) return false;
    GatewayReaders.store(GatewayEnabled, std::memory_order_release);
    return true;
}

void DisableNativeGateways()
{
    // Close admission before waiting for entries that can still call into the session's runtime.
    GatewayReaders.fetch_and(~GatewayEnabled, std::memory_order_acq_rel);
    while (GatewayReaders.load(std::memory_order_acquire)) Sleep(GatewayDrainPollMs);
    GatewayRuntime = {};
}

bool PrivateSyscallTarget(void* address, uint64_t& original)
{
    MEMORY_BASIC_INFORMATION region{};
    std::array<BYTE, 11> code{};
    if (reinterpret_cast<uintptr_t>(address) % sizeof(uint64_t)) return false;
    if (!(VirtualQuery(address, &region, sizeof(region)) && region.State == MEM_COMMIT &&
        region.Type == MEM_PRIVATE && !(region.Protect & PAGE_GUARD) &&
        (region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
        ReadCaptureMemory(address, code.data(), code.size()) &&
        code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8 &&
        code[8] == 0x0F && code[9] == 0x05 && code[10] == 0xC3)) return false;
    memcpy(&original, code.data(), sizeof(original));
    return true;
}

void WINAPI ObserveNativeDelegate(uintptr_t address)
{
    if (!address || !BroadHooks || !(GatewayReaders.load(std::memory_order_acquire) & GatewayEnabled)) return;
    auto error = GetLastError();
    auto status = NativeThreadStatus();
    auto observing = std::exchange(ObserverActive, true);
    try
    {
        [&]()
        {
            // CLR callback thunks also occupy private executable memory; only patch direct syscall stubs.
            auto target = reinterpret_cast<void*>(address);
            uint64_t original = 0;
            if (!PrivateSyscallTarget(target, original)) return;
            AcquireSRWLockExclusive(&ModuleChangeLock);
            std::unique_ptr<SRWLOCK, decltype(&ReleaseSRWLockExclusive)> lock(
                &ModuleChangeLock, &ReleaseSRWLockExclusive);
            if (!PrivateSyscallTarget(target, original)) return;
            if (NativeGatewayCount >= NativeGatewayCapacity) { ReportModuleError(ERROR_NOT_ENOUGH_MEMORY); return; }
            bool registered = false;
            auto release = [&](NativeGateway* gate)
            {
                if (!gate) return;
                if (registered) RtlDeleteFunctionTable(&gate->function);
                VirtualFree(gate, 0, MEM_RELEASE);
            };
            auto allocate = reinterpret_cast<decltype(&VirtualAlloc2)>(
                GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "VirtualAlloc2"));
            if (!allocate) { ReportModuleError(ERROR_PROC_NOT_FOUND); return; }
            SYSTEM_INFO system{};
            GetSystemInfo(&system);
            auto origin = address + sizeof(uint64_t);
            auto alignment = uintptr_t{system.dwAllocationGranularity} - 1;
            auto lower = origin > INT32_MAX ? origin - INT32_MAX : 0;
            auto upper = std::min(origin + INT32_MAX, reinterpret_cast<uintptr_t>(system.lpMaximumApplicationAddress));
            MEM_ADDRESS_REQUIREMENTS requirements{
                reinterpret_cast<void*>((lower + alignment) & ~alignment),
                reinterpret_cast<void*>(((upper + 1) & ~alignment) - 1), 0};
            MEM_EXTENDED_PARAMETER parameter{};
            parameter.Type = MemExtendedParameterAddressRequirements;
            parameter.Pointer = &requirements;
            std::unique_ptr<NativeGateway, decltype(release)> allocation(static_cast<NativeGateway*>(
                allocate(GetCurrentProcess(), nullptr, GatewayPageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE,
                    &parameter, 1)), release);
            if (!allocation) { ReportModuleError(GetLastError()); return; }
            auto gate = allocation.get();
            gate->target = reinterpret_cast<void*>(origin);
            size_t length = 0;
            auto emit = [&](std::initializer_list<BYTE> bytes)
            {
                if (bytes.size() > gate->code.size() - length) throw std::length_error("Native gateway overflow.");
                for (auto value : bytes) gate->code[length++] = value;
            };
            auto data = [&]<class T>(T value)
            {
                if (sizeof(value) > gate->code.size() - length) throw std::length_error("Native gateway overflow.");
                memcpy(gate->code.data() + length, &value, sizeof(value));
                length += sizeof(value);
            };
            auto jump = [&]()
            {
                auto operand = length;
                data(int32_t{});
                return operand;
            };
            auto patch = [&](size_t operand)
            {
                auto distance = static_cast<int32_t>(length - operand - sizeof(int32_t));
                memcpy(gate->code.data() + operand, &distance, sizeof(distance));
            };

            // Preserve the Windows x64 argument registers, vector arguments and native error state.
            emit({0x48, 0x81, 0xEC}); data(uint32_t{0xD8});
            constexpr BYTE registers[]{0, 1, 2, 8, 9, 10, 11};
            for (size_t index = 0; index < std::size(registers); ++index)
                emit({static_cast<BYTE>(registers[index] < 8 ? 0x48 : 0x4C), 0x89,
                    static_cast<BYTE>(0x44 | (registers[index] & 7) << 3), 0x24,
                    static_cast<BYTE>(0x20 + index * 8)});
            for (BYTE index = 0; index < 6; ++index)
            {
                emit({0xF3, 0x0F, 0x7F, static_cast<BYTE>(0x84 | index << 3), 0x24});
                data(uint32_t{0x60} + index * 16);
            }
            for (auto offset : {offsetof(TEB, LastErrorValue), offsetof(TEB, LastStatusValue)})
            {
                emit({0x65, 0x8B, 0x04, 0x25}); data(static_cast<uint32_t>(offset));
                emit({0x89, 0x84, 0x24});
                data(uint32_t{offset == offsetof(TEB, LastErrorValue) ? 0xC0u : 0xC4u});
            }
            emit({0x48, 0xB8}); data(reinterpret_cast<uintptr_t>(&AcquireNativeGateway));
            emit({0xFF, 0xD0, 0x48, 0x85, 0xC0, 0x0F, 0x84}); auto restore = jump();
            emit({0x48, 0x89, 0x44, 0x24, 0x58, 0xFF, 0x10, 0x85, 0xC0, 0x0F, 0x85}); auto leave = jump();
            emit({0x48, 0xB9}); data(address + 10);
            emit({0x48, 0x8B, 0x44, 0x24, 0x58, 0xFF, 0x50, 0x08});
            patch(leave);
            emit({0x48, 0xB8}); data(reinterpret_cast<uintptr_t>(&ReleaseNativeGateway));
            emit({0xFF, 0xD0});
            patch(restore);
            for (auto offset : {offsetof(TEB, LastErrorValue), offsetof(TEB, LastStatusValue)})
            {
                emit({0x8B, 0x84, 0x24});
                data(uint32_t{offset == offsetof(TEB, LastErrorValue) ? 0xC0u : 0xC4u});
                emit({0x65, 0x89, 0x04, 0x25}); data(static_cast<uint32_t>(offset));
            }
            for (BYTE index = 0; index < 6; ++index)
            {
                emit({0xF3, 0x0F, 0x6F, static_cast<BYTE>(0x84 | index << 3), 0x24});
                data(uint32_t{0x60} + index * 16);
            }
            for (size_t index = 0; index < std::size(registers); ++index)
                emit({static_cast<BYTE>(registers[index] < 8 ? 0x48 : 0x4C), 0x8B,
                    static_cast<BYTE>(0x44 | (registers[index] & 7) << 3), 0x24,
                    static_cast<BYTE>(0x20 + index * 8)});
            emit({0xB8}); data(static_cast<uint32_t>(original >> 32));
            emit({0x48, 0x81, 0xC4}); data(uint32_t{0xD8});
            emit({0xFF, 0x25}); data(static_cast<int32_t>(offsetof(NativeGateway, target) - length - 4));
            gate->function = {0, static_cast<DWORD>(length), offsetof(NativeGateway, unwind)};
            gate->unwind = {1, 7, 2, 0, 7, 1, 0x1B, 0};
            DWORD protection = 0;
            if (!VirtualProtect(gate, GatewayPageBytes, PAGE_EXECUTE_READ, &protection) ||
                !FlushInstructionCache(GetCurrentProcess(), gate, length) ||
                !RtlAddFunctionTable(&gate->function, 1, reinterpret_cast<DWORD64>(gate)))
            {
                ReportModuleError(ERROR_NOT_SUPPORTED);
                return;
            }
            registered = true;

            // Replace one instruction atomically while retaining both entry instruction boundaries.
            auto distance = reinterpret_cast<uintptr_t>(gate) - origin;
            auto patched = uint64_t{0xE9D18B4C} | (uint64_t{static_cast<uint32_t>(distance)} << 32);
            if (!VirtualProtect(target, sizeof(original), PAGE_EXECUTE_READWRITE, &protection))
            {
                ReportModuleError(GetLastError());
                return;
            }
            bool published = static_cast<uint64_t>(InterlockedCompareExchange64(static_cast<volatile LONG64*>(target),
                static_cast<LONG64>(patched), static_cast<LONG64>(original))) == original;
            DWORD ignored = 0;
            if (!VirtualProtect(target, sizeof(original), protection, &ignored)) ReportModuleError(GetLastError());
            if (!published) return;

            // Cached delegates outlive capture sessions; the pinned agent retains each published gateway.
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

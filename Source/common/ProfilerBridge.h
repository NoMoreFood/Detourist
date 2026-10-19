#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace Detourist
{
constexpr uint32_t ProfilerBridgeVersion = 7;
inline constexpr wchar_t ProfilerClassId[] = L"{E79AF24A-CE8C-4D81-9F4D-A794BB3F4B15}";
inline constexpr GUID ProfilerGuid = {0xE79AF24A, 0xCE8C, 0x4D81, {0x9F, 0x4D, 0xA7, 0x94, 0xBB, 0x3F, 0x4B, 0x15}};
constexpr size_t ManagedCallStateBytes = 1024;

// Opaque invocation storage keeps the agent's C++ implementation out of the profiler ABI.
struct alignas(16) ManagedCallState
{
    std::byte storage[ManagedCallStateBytes];
};

struct DynamicApiMetadata;
struct CaptureClock;

struct ProfilerBridge
{
    uint32_t version;
    uint32_t bytes;
    BOOL (WINAPI* guard)(BOOL suppress);
    uint32_t (WINAPI* registerApi)(const DynamicApiMetadata* metadata, const char* layout, uint32_t layoutBytes);
    uint32_t (WINAPI* bufferLimit)(uint32_t api);
    BOOL (WINAPI* begin)(ManagedCallState* state, uint32_t api, const uint64_t* arguments, uint32_t argumentCount,
        const std::byte* payload, uint32_t payloadBytes);
    void (WINAPI* end)(ManagedCallState* state, uint64_t result, uint32_t flags,
        const std::byte* payload, uint32_t payloadBytes);
    void (WINAPI* status)(uint32_t state);
    BOOL (WINAPI* updateLayout)(uint32_t api, const char* layout, uint32_t bytes);
    void (WINAPI* nativeDelegate)(uintptr_t address);
    void (WINAPI* nativeCode)(uintptr_t address, size_t bytes, BOOL added);
    CaptureClock* (WINAPI* captureClock)();
};

using GetProfilerBridge = BOOL (WINAPI*)(uint32_t version, ProfilerBridge* bridge);
}

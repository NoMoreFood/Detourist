#pragma once
#include <cstdint>

namespace Detourist
{
struct CaptureClock;
inline constexpr uint32_t NativeHookCapacity = 16384;
inline constexpr uint32_t InternalNativeImageCount = 7;
enum ObserverFlags : uint32_t { ObserverRecording = 1, ObserverFollowingChild = 2, ObserverNativeReady = 4 };
struct ObserverContext
{
    uint64_t captureIdentity;
    uint64_t parentId;
    uint32_t depth;
    uint32_t flags;
    uint32_t api = UINT32_MAX;
    CaptureClock* clock = nullptr;
};
}

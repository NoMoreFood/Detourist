#pragma once
#include <atomic>
#include <cstdint>

namespace Detourist
{
struct CaptureClock;
struct Slot;
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
struct ObserverThreadPointers
{
    std::atomic<uint64_t>* slotGeneration = nullptr;
    uint64_t expectedGeneration = 0;
    uint64_t* captureIdentity = nullptr;
    uint64_t* parentId = nullptr;
    uint32_t* depth = nullptr;
    uint32_t* api = nullptr;
    bool* active = nullptr;
    bool* followingChild = nullptr;
    CaptureClock* clock = nullptr;
    volatile LONG* processShuttingDown = nullptr;
    Slot** pendingSlot = nullptr;
    void** pendingTransport = nullptr;
};
}

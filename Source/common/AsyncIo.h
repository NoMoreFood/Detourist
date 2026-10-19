#pragma once
#include "CaptureValues.h"

namespace Detourist
{
struct AsyncIoSink
{
    SharedHeader* header;
    void* context;
    Slot* (*acquire)(void*);
    void (*publish)(void*, Slot*);
};

template<class Channel> AsyncIoSink AsyncSink(Channel& channel)
{
    return {channel.Header(), &channel,
        [](void* context) { return static_cast<Channel*>(context)->Acquire(); },
        [](void* context, Slot* slot) { static_cast<Channel*>(context)->Publish(slot); }};
}

// DynamoRIO can stall an application thread that holds a session lock until an engine callback returns, so engine
// acquisitions stop waiting instead of deadlocking.
constexpr uint32_t EngineLockSpinLimit = 1u << 16;

[[nodiscard]] inline bool LockSession(volatile LONG& lock) noexcept
{
#ifdef DETOURIST_INSTRUCTION_CLIENT
    for (uint32_t spin = 0; InterlockedCompareExchange(&lock, 1, 0); ++spin)
    {
        if (spin == EngineLockSpinLimit) return false;
        YieldProcessor();
    }
#else
    while (InterlockedCompareExchange(&lock, 1, 0)) YieldProcessor();
#endif
    return true;
}

AsyncIoRole AsyncRole(const char* module, const char* name);
inline bool AsyncObserver(AsyncIoRole role) { return role >= AsyncIoRole::OverlappedResult; }
uint32_t AsyncCallbackParameter(AsyncIoRole role, AsyncCallbackKind& kind);
void BeginAsyncIo(SharedHeader* header, const Event& event, AsyncIoRole role);
void FinishAsyncIo(const AsyncIoSink& sink, Event& event, AsyncIoRole role);
void CompleteAsyncIo(const AsyncIoSink& sink, uint64_t control, uint64_t bytes, uint32_t status,
    AsyncIoDomain domain, AsyncIoSource source, uint64_t observer, uint32_t thread, uint32_t ioFlags = 0,
    uint64_t expectedCall = 0);
}

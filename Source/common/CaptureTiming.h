#pragma once
#include "Protocol.h"

namespace Detourist
{
// Application time advances through nested calls and pauses during observation on this thread.
struct CaptureClock
{
    int64_t overhead = 0;
    int64_t observed = 0;
    uint32_t depth = 0;

    int64_t ApplicationTime(int64_t now) const
    {
        return now - overhead - (depth ? now - observed : 0);
    }

    void Enter(int64_t now)
    {
        if (!depth++) observed = now;
    }

    void Leave(int64_t now)
    {
        if (!--depth) overhead += now - observed;
    }
};

struct CaptureObservation
{
    CaptureClock* clock = nullptr;
    bool active = false;

    CaptureObservation() = default;
    explicit CaptureObservation(CaptureClock* value, int64_t now) : clock(value), active(value != nullptr)
    {
        if (active) clock->Enter(now);
    }
    CaptureObservation(const CaptureObservation&) = delete;
    CaptureObservation& operator=(const CaptureObservation&) = delete;
    ~CaptureObservation() { Reset(); }

    int64_t ApplicationTime() const { return clock->observed - clock->overhead; }

    void Reset()
    {
        if (active) clock->Leave(Clock());
        active = false;
        clock = nullptr;
    }
    void Pause(int64_t now)
    {
        if (active) clock->Leave(now);
        active = false;
    }
    void Resume(int64_t now)
    {
        if (clock && !active) clock->Enter(now);
        active = clock != nullptr;
    }
};
}

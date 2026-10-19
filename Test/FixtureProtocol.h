#pragma once
#include "WinSupport.h"
#include "Protocol.h"

namespace Detourist
{
struct FixtureMetrics
{
    volatile LONG heartbeat;
    LONG exceptionsHandled;
    int64_t elapsedTicks;
    uint64_t cpuTicks;
    uint64_t peakWorkingSet;
    uint64_t privateBytes;
    uint32_t iterations;
    uint32_t errors;
};
}

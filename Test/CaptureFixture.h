#pragma once
#include "Transport.h"
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace Detourist::Tests
{
inline void Require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

inline int RunChecks(void (*checks)())
{
    try
    {
        checks();
        return 0;
    }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}

struct Snapshot
{
    Value value;
    std::vector<std::byte> bytes;
};

template<uint32_t Capacity = 4096>
struct CaptureFrame
{
    std::unique_ptr<SharedHeader> header = std::make_unique<SharedHeader>();
    CaptureFrame* const transport = this;
    Event event{};

    explicit CaptureFrame(uint32_t limit)
    {
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        header->pageBytes = system.dwPageSize;
        header->bufferLimit = limit;
        header->payloadCapacity = Capacity;
    }
    CaptureFrame(const CaptureFrame&) = delete;
    CaptureFrame& operator=(const CaptureFrame&) = delete;
    SharedHeader* Header() const { return header.get(); }
    Slot* ResetSlot()
    {
        storage.slot.event = {};
        return &storage.slot;
    }

    std::vector<Snapshot> Snapshots() const
    {
        // A malformed length must fail the test before the reader can leave the fixture allocation.
        Require(storage.slot.event.payloadBytes <= Capacity, "Capture exceeded the test slot");
        auto payload = std::span(storage.payload).first(storage.slot.event.payloadBytes);
        std::vector<Snapshot> values;
        while (!payload.empty())
        {
            Require(payload.size() >= sizeof(Value), "Incomplete capture header");
            Value value;
            memcpy(&value, payload.data(), sizeof(value));
            payload = payload.subspan(sizeof(value));
            Require(value.capturedBytes <= payload.size(), "Incomplete captured value");
            auto bytes = payload.first(value.capturedBytes);
            values.push_back({value, {bytes.begin(), bytes.end()}});
            payload = payload.subspan(bytes.size());
        }
        return values;
    }

private:
    struct SlotStorage
    {
        Slot slot;
        std::byte payload[Capacity];
    } storage{};
    static_assert(offsetof(SlotStorage, payload) == sizeof(Slot));
};
}

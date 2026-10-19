#pragma once
#include "Transport.h"

namespace Detourist
{
bool ReadCaptureMemory(const void* source, void* destination, size_t bytes);
bool ReadGuardedCaptureMemory(const void* source, void* destination, size_t bytes);
DWORD SafeDword(uint64_t pointer);
inline uint64_t Win32ByteCount(uint64_t count, size_t elementSize)
{
    return count > UINT64_MAX / elementSize ? UINT64_MAX : count * elementSize;
}

struct ValueCopyOptions
{
    bool terminated = false, multiString = false, guarded = false, unknownExtent = false;
    uint32_t flags = 0;
};

struct CountedString
{
    uint16_t length, maximumLength;
    uintptr_t buffer;
};

struct HStringHeader
{
    uint32_t flags, length, reserved[2];
    uintptr_t data;
};

uint32_t CopyValue(Slot* slot, SharedHeader* header, uint32_t parameter, ValueKind kind,
    uint64_t address, uint64_t length, ValueCopyOptions options = {});
void CaptureCoreOutputs(Api api, const Event& event, uint32_t requestedBytes, uint64_t readCapacity,
    Slot* slot, SharedHeader* header);
void CaptureStringMember(Slot* slot, SharedHeader* header, uint32_t parameter, uint32_t pointerOffset, bool wide);
void CaptureSoundValue(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint32_t flags, bool wide);

enum class MruMode : uint8_t { Unknown, Utf16, Binary };
struct MruCaptureState
{
    uint64_t generation = 0;
    MruMode mode = MruMode::Unknown;
};
void ResetMruCapture(uint64_t identity);
void ObserveMruCall(Api api, uint64_t identity, const Event& event, bool leaving, MruCaptureState& state);
bool CaptureMruValues(Api api, const Event& event, const MruCaptureState& state,
    Slot* slot, SharedHeader* header, bool leaving);

template<class State>
void CaptureReturnedSpan(State& call, Slot* slot, bool leaving, uint32_t parameter)
{
    // A completed marshaler returns the first byte after the consumed or produced wire representation.
    if (!leaving || call.event.flags & (Failed | Skipped | Unwound)) return;
    auto address = call.event.arguments[parameter];
    if (address && call.event.result >= address)
        CopyValue(slot, call.transport->Header(), parameter, ValueKind::Bytes, address, call.event.result - address);
}
}

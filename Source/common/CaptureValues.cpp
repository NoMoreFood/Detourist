#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "CaptureValues.h"
#include "TransportPool.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <playsoundapi.h>
#ifdef DETOURIST_INSTRUCTION_CLIENT
#pragma warning(push, 0)
#include "dr_api.h"
#pragma warning(pop)
#endif

namespace Detourist
{
std::atomic_flag MruCaptureGate = ATOMIC_FLAG_INIT;
uint64_t MruCaptureIdentity = 0;
struct MruListInfo
{
    uint32_t size, maximum, flags;
    HKEY key;
    const wchar_t* subKey;
    void* compare;
};
struct MruListState
{
    uint64_t handle;
    MruCaptureState state;
    MruListState* next;
};
MruListState* MruLists[64]{};

void ReleaseMruListState(MruListState* entry)
{
#ifdef DETOURIST_INSTRUCTION_CLIENT
    dr_global_free(entry, sizeof(*entry));
#else
    HeapFree(GetProcessHeap(), 0, entry);
#endif
}

void ResetMruCapture(uint64_t identity)
{
    // A new session cannot infer the mode of lists whose creation it did not observe.
    while (MruCaptureGate.test_and_set(std::memory_order_acquire)) YieldProcessor();
    for (auto& bucket : MruLists)
        while (bucket)
        {
            auto next = bucket->next;
            ReleaseMruListState(bucket);
            bucket = next;
        }
    MruCaptureIdentity = identity;
    MruCaptureGate.clear(std::memory_order_release);
}

void ObserveMruCall(Api api, uint64_t identity, const Event& event, bool leaving, MruCaptureState& state)
{
    if (api != Api::CreateMRUListW && api != Api::FreeMRUList &&
        api != Api::AddMRUStringW && api != Api::EnumMRUListW) return;
    if (event.flags & (Skipped | Unwound) || leaving && (event.flags & Failed)) return;
    if (api == Api::CreateMRUListW && !leaving)
    {
        // Sample the declared mode before the provider can invoke comparison callbacks or release input storage.
        uint32_t info[3]{};
        if (event.arguments[0] && ReadCaptureMemory(reinterpret_cast<void*>(event.arguments[0]), info, sizeof(info)) &&
            info[0] == sizeof(MruListInfo))
            state = {event.callId, info[2] & 1 ? MruMode::Binary : MruMode::Utf16};
        return;
    }
    if (leaving && api != Api::CreateMRUListW && api != Api::FreeMRUList) return;
    while (MruCaptureGate.test_and_set(std::memory_order_acquire)) YieldProcessor();
    auto release = [](std::atomic_flag* gate) { gate->clear(std::memory_order_release); };
    std::unique_ptr<std::atomic_flag, decltype(release)> lock(&MruCaptureGate, release);
    if (identity != MruCaptureIdentity) return;
    auto handle = api == Api::CreateMRUListW ? event.result : event.arguments[0];
    auto entry = &MruLists[(handle >> 4) % std::size(MruLists)];
    while (*entry && (*entry)->handle != handle) entry = &(*entry)->next;
    if (api == Api::CreateMRUListW)
    {
        // Failed bookkeeping leaves the handle untyped instead of guessing a buffer extent.
        if (!handle || state.mode == MruMode::Unknown) return;
        if (!*entry)
        {
#ifdef DETOURIST_INSTRUCTION_CLIENT
            *entry = static_cast<MruListState*>(dr_global_alloc(sizeof(MruListState)));
#else
            *entry = static_cast<MruListState*>(HeapAlloc(GetProcessHeap(), 0, sizeof(MruListState)));
#endif
            if (!*entry) return;
            **entry = {handle, state, nullptr};
        }
        else (*entry)->state = state;
        return;
    }
    if (!*entry) return;
    if (!leaving) state = (*entry)->state;
    else if ((*entry)->state.generation == state.generation)
    {
        auto removed = *entry;
        *entry = removed->next;
        ReleaseMruListState(removed);
    }
}

bool CaptureMruValues(Api api, const Event& event, const MruCaptureState& state,
    Slot* slot, SharedHeader* header, bool leaving)
{
    if (api != Api::CreateMRUListW && api != Api::FreeMRUList &&
        api != Api::AddMRUStringW && api != Api::EnumMRUListW) return false;
    if (event.flags & Unwound || leaving && (event.flags & (Failed | Skipped))) return true;
    const auto& args = event.arguments;
    if (api == Api::CreateMRUListW && !leaving)
    {
        CopyValue(slot, header, 0, ValueKind::Bytes, args[0], sizeof(MruListInfo));
        CaptureStringMember(slot, header, 0, offsetof(MruListInfo, subKey), true);
    }
    else if (api == Api::AddMRUStringW && !leaving && args[1])
    {
        // Binary inputs carry a DWORD payload size; text inputs are bounded, terminated UTF-16.
        if (state.mode == MruMode::Utf16)
            CopyValue(slot, header, 1, ValueKind::Utf16, args[1], header->bufferLimit, {.terminated = true});
        else if (state.mode == MruMode::Binary)
        {
            uint32_t bytes = 0;
            if (ReadCaptureMemory(reinterpret_cast<void*>(args[1]), &bytes, sizeof(bytes)))
                CopyValue(slot, header, 1, ValueKind::Bytes, args[1], uint64_t{bytes} + sizeof(bytes));
        }
    }
    else if (api == Api::EnumMRUListW && leaving && static_cast<int32_t>(args[1]) >= 0 && args[2] && args[3])
    {
        // Count queries produce no output; enumeration capacities use characters for text and bytes for binary data.
        auto capacity = static_cast<uint32_t>(args[3]);
        if (state.mode == MruMode::Utf16)
            CopyValue(slot, header, 2, ValueKind::Utf16, args[2], uint64_t{capacity} * sizeof(wchar_t),
                {.terminated = true});
        else if (state.mode == MruMode::Binary)
            CopyValue(slot, header, 2, ValueKind::Bytes, args[2],
                std::min(capacity, static_cast<uint32_t>(event.result)));
    }
    return true;
}

bool ReadCaptureMemory(const void* source, void* destination, size_t bytes)
{
#ifndef _WIN64
    // Keep WOW64 memory probes outside the application's exception dispatch.
    SIZE_T copied = 0;
    const auto status = NtReadVirtualMemory(NtCurrentProcess(), const_cast<void*>(source), destination, bytes, &copied);
    return status >= 0 && copied == bytes;
#elif defined(DETOURIST_INSTRUCTION_CLIENT)
    return dr_safe_read(source, bytes, destination, nullptr);
#else
    __try { memcpy(destination, source, bytes); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
#endif
}

bool ReadGuardedCaptureMemory(const void* source, void* destination, size_t bytes)
{
    auto cursor = reinterpret_cast<uintptr_t>(source);
    if (!cursor || bytes > UINTPTR_MAX - cursor) return false;
    const auto end = cursor + bytes;

    // Probing a guard page would consume the application's exception before its own reader reaches it.
    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION region{};
        if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(cursor), MemoryBasicInformation,
            &region, sizeof(region), nullptr) < 0 || region.State != MEM_COMMIT ||
            region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        const auto base = reinterpret_cast<uintptr_t>(region.BaseAddress);
        if (region.RegionSize > UINTPTR_MAX - base || base + region.RegionSize <= cursor) return false;
        cursor = std::min<uintptr_t>(end, base + region.RegionSize);
    }
    return ReadCaptureMemory(source, destination, bytes);
}

void CaptureSoundValue(Slot* slot, SharedHeader* header, uint32_t parameter, uint64_t address,
    uint32_t flags, bool wide)
{
    // Resource identifiers and predefined aliases are integer values, even though the API declares a string.
    auto resource = (flags & SND_RESOURCE) == SND_RESOURCE;
    if (!address || (flags & SND_ALIAS_ID) == SND_ALIAS_ID || resource && address <= UINT16_MAX) return;
    if (resource || !(flags & SND_MEMORY))
    {
        auto length = std::min(header->bufferLimit, 256u * (wide ? 2u : 1u));
        CopyValue(slot, header, parameter, wide ? ValueKind::Utf16 : ValueKind::Bytes, address, length,
            {.terminated = true});
        return;
    }

    // A RIFF WAVE header bounds in-memory audio independently of string terminators and the capture limit.
    constexpr uint32_t RiffSignature = 0x46464952;
    constexpr uint32_t WaveSignature = 0x45564157;
    uint32_t wave[3]{};
    uint64_t length = sizeof(wave);
    if (ReadCaptureMemory(reinterpret_cast<void*>(address), wave, sizeof(wave)) &&
        wave[0] == RiffSignature && wave[2] == WaveSignature && wave[1] >= 4) length = uint64_t{wave[1]} + 8;
    CopyValue(slot, header, parameter, ValueKind::Bytes, address, length);
}

DWORD SafeDword(uint64_t pointer)
{
    DWORD value = 0;
    if (pointer) ReadCaptureMemory(reinterpret_cast<const void*>(pointer), &value, sizeof(value));
    return value;
}

uint32_t CopyValue(Slot* slot, SharedHeader* header, uint32_t parameter, ValueKind kind,
    uint64_t address, uint64_t length, ValueCopyOptions options)
{
    if (!address) return 0;
    uint32_t limit = kind == ValueKind::Stack ? MaximumStack * sizeof(uint64_t) : header->bufferLimit;
    uint32_t desired = static_cast<uint32_t>(std::min<uint64_t>(length, limit));
    auto available = EnsureSlotPayload(slot, header, static_cast<uint32_t>(sizeof(Value)) + desired);
    if (available < sizeof(Value)) return 0;
    auto output = Transport::Payload(slot) + slot->event.payloadBytes;
    Value value{parameter, kind, options.flags, 0, length};
    uint32_t count = std::min(desired, available - static_cast<uint32_t>(sizeof(Value)));

    // Read only the requested bounded memory while it belongs to this invocation.
    if (options.terminated)
    {
        auto width = kind == ValueKind::Utf16 ? uint32_t{sizeof(wchar_t)} : uint32_t{sizeof(char)};
        auto source = reinterpret_cast<const uint8_t*>(address);
        auto destination = output + sizeof(Value);
        const auto pageBytes = std::max(header->pageBytes, width);
        count -= count % width;
        bool complete = false, previousNull = false;
        while (value.capturedBytes < count)
        {
            // Read within one page so a terminator never causes a probe of the following guard page.
            uint8_t characters[64];
            auto position = value.capturedBytes;
            auto bytes = std::min(count - position, uint32_t{sizeof(characters)});
            bytes = std::min(bytes, pageBytes - static_cast<uint32_t>((address + position) % pageBytes));
            bytes = std::max(width, bytes - bytes % width);
            const bool read = options.guarded || options.multiString ?
                ReadGuardedCaptureMemory(source + position, characters, bytes) :
                ReadCaptureMemory(source + position, characters, bytes);
            if (!read)
            {
                value.flags |= Unreadable;
                value.capturedBytes = 0;
                break;
            }
            for (uint32_t index = 0; index < bytes; index += width)
            {
                uint16_t character = 0;
                memcpy(&character, characters + index, width);
                if (!character && (!options.multiString || previousNull))
                {
                    bytes = index + width;
                    complete = true;
                    break;
                }
                previousNull = !character;
            }
            memcpy(destination + position, characters, bytes);
            value.capturedBytes += bytes;
            if (complete) break;
        }
        if (!complete) value.flags |= Truncated;
        value.originalBytes = complete ? value.capturedBytes : 0;
    }
    else if (options.guarded ?
            ReadGuardedCaptureMemory(reinterpret_cast<const void*>(address), output + sizeof(Value), count) :
            ReadCaptureMemory(reinterpret_cast<const void*>(address), output + sizeof(Value), count))
    {
        value.capturedBytes = count;
        if (count < length) value.flags |= Truncated;
    }
    else
    {
        value.flags |= Unreadable;
        value.capturedBytes = 0;
    }
    if (options.unknownExtent) value.originalBytes = 0;
    memcpy(output, &value, sizeof(value));
    slot->event.payloadBytes += static_cast<uint32_t>(sizeof(value)) + value.capturedBytes;
    return value.capturedBytes;
}

void CaptureCoreOutputs(Api api, const Event& event, uint32_t requestedBytes, uint64_t readCapacity,
    Slot* slot, SharedHeader* header)
{
    const auto& args = event.arguments;
    const bool success = !(event.flags & Failed);
    auto bytes = [&](uint32_t index, uint64_t size, ValueKind kind = ValueKind::Bytes)
    {
        CopyValue(slot, header, index, kind, args[index], size);
    };

    // Core API outputs use the same snapshot shapes in both capture engines.
    switch (api)
    {
    case Api::ReadFile:
        if (success && !(event.flags & AsyncPending))
            bytes(1, std::min<uint64_t>(SafeDword(args[3]), readCapacity));
        if (!(event.flags & AsyncPending)) bytes(3, sizeof(DWORD), ValueKind::Scalar);
        break;
    case Api::WriteFile:
        if (!(event.flags & AsyncPending)) bytes(3, sizeof(DWORD), ValueKind::Scalar);
        break;
    case Api::FindFirstFileExW:
        if (success) bytes(2, sizeof(WIN32_FIND_DATAW), ValueKind::FindData); break;
    case Api::FindNextFileW:
        if (success) bytes(1, sizeof(WIN32_FIND_DATAW), ValueKind::FindData); break;
    case Api::RegOpenKeyExW:
        if (success) bytes(4, sizeof(HKEY), ValueKind::Scalar); break;
    case Api::RegCreateKeyExW:
        if (success) { bytes(7, sizeof(HKEY), ValueKind::Scalar); bytes(8, sizeof(DWORD), ValueKind::Scalar); }
        break;
    case Api::RegQueryValueExW:
        bytes(5, sizeof(DWORD), ValueKind::Scalar);
        if (success)
        {
            bytes(3, sizeof(DWORD), ValueKind::Scalar);
            bytes(4, std::min<uint32_t>(requestedBytes, SafeDword(args[5])));
        }
        break;
    case Api::CreateProcessW:
        if (success) bytes(9, sizeof(PROCESS_INFORMATION), ValueKind::ProcessInformation); break;
    default: break;
    }
}

void CaptureStringMember(Slot* slot, SharedHeader* header, uint32_t parameter, uint32_t pointerOffset, bool wide)
{
    // Follow only complete pointer fields retained in the owning structure's bounded snapshot.
    for (uint32_t offset = 0; offset + sizeof(Value) <= slot->event.payloadBytes;)
    {
        Value parent{};
        memcpy(&parent, Transport::Payload(slot) + offset, sizeof(parent));
        auto data = Transport::Payload(slot) + offset + sizeof(parent);
        offset += static_cast<uint32_t>(sizeof(parent)) + parent.capturedBytes;
        if (parent.parameter != parameter || parent.kind != ValueKind::Bytes ||
            parent.capturedBytes < uint64_t{pointerOffset} + sizeof(uintptr_t)) continue;
        uintptr_t pointer = 0;
        memcpy(&pointer, data + pointerOffset, sizeof(pointer));
        CopyValue(slot, header, PackMemberParameter(parameter, pointerOffset),
            wide ? ValueKind::Utf16 : ValueKind::Bytes, pointer, header->bufferLimit,
            {.terminated = true, .guarded = true, .flags = MemberData | ReferencedData});
        return;
    }
}

}

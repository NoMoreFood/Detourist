#include "AsyncIo.h"
#include "CaptureFixture.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

using namespace Detourist;
using namespace Detourist::Tests;

void CaptureStrings()
{
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto header = std::make_unique<SharedHeader>();
    header->pageBytes = system.dwPageSize;
    header->bufferLimit = 1024;
    header->payloadCapacity = 2048;
    auto storage = std::make_unique<std::byte[]>(sizeof(Slot) + header->payloadCapacity);
    auto slot = reinterpret_cast<Slot*>(storage.get());
    auto memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, system.dwPageSize * 2,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Require(memory != nullptr, "Allocate string pages");
    auto release = [](uint8_t* address) { VirtualFree(address, 0, MEM_RELEASE); };
    std::unique_ptr<uint8_t, decltype(release)> pages(memory, release);
    auto boundary = memory + system.dwPageSize;
    auto capture = [&](const void* address, bool wide, uint32_t limit = 1024)
    {
        header->bufferLimit = limit;
        slot->event.payloadBytes = 0;
        CopyValue(slot, header.get(), 0, wide ? ValueKind::Utf16 : ValueKind::Bytes,
            reinterpret_cast<uintptr_t>(address), 1024, {.terminated = true});
        Value value{};
        memcpy(&value, Transport::Payload(slot), sizeof(value));
        return value;
    };

    // Terminators at the end of a readable page must leave the neighboring guard page untouched.
    DWORD previous = 0;
    Require(VirtualProtect(boundary, system.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &previous) != FALSE,
        "Protect the neighboring string page");
    for (bool wide : {false, true})
    {
        const auto width = wide ? 2u : 1u;
        for (uint32_t length : {0u, 1u, 31u, 32u, 63u, 64u, 255u})
        {
            auto start = boundary - (length + 1) * width;
            memset(start, 0, (length + 1) * width);
            for (uint32_t index = 0; index < length; ++index) start[index * width] = 'A';
            auto value = capture(start, wide);
            Require(!value.flags && value.capturedBytes == (length + 1) * width &&
                value.originalBytes == value.capturedBytes, "A boundary string changed length or flags");
            Require(!memcmp(Transport::Payload(slot) + sizeof(Value), start, value.capturedBytes),
                "A boundary string changed its contents");
        }
    }
    MEMORY_BASIC_INFORMATION region{};
    Require(VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
        "String capture consumed the neighboring guard page");

    // Page crossings, unaligned UTF-16, unreadable strings and odd capture limits retain their boundaries.
    Require(VirtualProtect(boundary, system.dwPageSize, PAGE_READWRITE, &previous) != FALSE,
        "Make the neighboring string page readable");
    uint16_t text[]{'A', 'B', 'C', 0};
    memcpy(boundary - 3, text, sizeof(text));
    auto value = capture(boundary - 3, true);
    Require(!value.flags && value.capturedBytes == sizeof(text), "An unaligned crossing string was truncated");
    value = capture(boundary - 3, true, 5);
    Require(value.flags == Truncated && value.capturedBytes == 4 && !value.originalBytes,
        "An odd UTF-16 limit captured a partial character");
    Require(VirtualProtect(boundary, system.dwPageSize, PAGE_NOACCESS, &previous) != FALSE,
        "Make the neighboring string page unreadable");
    memset(boundary - 64, 'A', 64);
    value = capture(boundary - 64, false);
    Require(value.flags == (Unreadable | Truncated) && !value.capturedBytes && !value.originalBytes,
        "An unreadable string exposed a partial snapshot");
    value = capture(boundary - 64, false, 64);
    Require(value.flags == Truncated && value.capturedBytes == 64,
        "A capped string probed beyond its capture limit");
    Require(VirtualProtect(boundary, system.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &previous) != FALSE,
        "Guard the string's first page");
    value = capture(boundary, false);
    Require(value.flags == (Unreadable | Truncated) && !value.capturedBytes,
        "A failed guarded read was retried as readable memory");

    // Native MRU inputs at a page boundary must not expose bytes beyond their architecture's structure.
    struct MruInfo
    {
        DWORD size, maximum, flags;
        HKEY key;
        const wchar_t* subKey;
        void* compare;
    } info{sizeof(MruInfo), 10, 0, HKEY_CURRENT_USER, L"Software\\Detourist", nullptr};
    Require(VirtualProtect(boundary, system.dwPageSize, PAGE_NOACCESS, &previous) != FALSE,
        "Protect the neighboring MRU page");
    auto input = boundary - sizeof(info);
    memcpy(input, &info, sizeof(info));
    Event event{};
    event.arguments[0] = reinterpret_cast<uintptr_t>(input);
    header->bufferLimit = 1024;
    slot->event.payloadBytes = 0;
    Require(CaptureMruValues(Api::CreateMRUListW, event, {}, slot, header.get(), false),
        "MRU factory input was not handled");
    memcpy(&value, Transport::Payload(slot), sizeof(value));
    Require(!value.flags && value.capturedBytes == sizeof(info) &&
        !memcmp(Transport::Payload(slot) + sizeof(Value), &info, sizeof(info)),
        "MRU input capture crossed its native structure boundary");
    auto offset = static_cast<uint32_t>(sizeof(Value)) + value.capturedBytes;
    Require(slot->event.payloadBytes >= offset + sizeof(Value), "MRU subkey snapshot is missing");
    memcpy(&value, Transport::Payload(slot) + offset, sizeof(value));
    const auto textBytes = (wcslen(info.subKey) + 1) * sizeof(wchar_t);
    Require(value.kind == ValueKind::Utf16 && value.flags == (MemberData | ReferencedData) &&
        value.parameter == ((offsetof(MruInfo, subKey) + 1u) << 8) && value.capturedBytes == textBytes &&
        !memcmp(Transport::Payload(slot) + offset + sizeof(Value), info.subKey, textBytes),
        "MRU subkey snapshot used the wrong native pointer offset");
}

void ObserveWaits()
{
    auto header = std::make_unique<SharedHeader>();
    header->bufferLimit = 64;
    header->payloadCapacity = 4096;
    header->asyncFree = 1;
    for (uint32_t index = 0; index < AsyncIoCapacity; ++index)
        header->asyncIo[index].next = index + 1 < AsyncIoCapacity ? index + 2 : 0;
    struct State
    {
        SharedHeader* header;
        std::unique_ptr<std::byte[]> slot;
        std::vector<uint64_t> calls;
    } state{header.get(), std::make_unique<std::byte[]>(sizeof(Slot) + header->payloadCapacity)};
    AsyncIoSink sink{header.get(), &state,
        [](void* context) { return reinterpret_cast<Slot*>(static_cast<State*>(context)->slot.get()); },
        [](void* context, Slot* slot)
        {
            auto& state = *static_cast<State*>(context);
            Require(!state.header->asyncLock, "Publishing a completion held the I/O lock");
            Require(slot->event.flags == AsyncCompleted, "An observed completion changed status");
            state.calls.push_back(slot->event.callId);
        }};
    std::vector<OVERLAPPED> controls(3840);
    for (uint32_t index = 0; index < controls.size(); ++index)
    {
        controls[index].hEvent = reinterpret_cast<HANDLE>(uintptr_t{index % 3 + 1} * 4);
        controls[index].Internal = index == 0 ? 0x103 : 0;
        Event submit{};
        submit.api = Api::ReadFile;
        submit.callId = index + 1;
        submit.arguments[4] = reinterpret_cast<uintptr_t>(&controls[index]);
        BeginAsyncIo(header.get(), submit, AsyncIoRole::ReadFile);
    }
    Require(static_cast<size_t>(header->asyncPending) == controls.size(),
        "Submissions were lost before observing waits");
    Event waited{};
    waited.api = Api::WaitForSingleObject;
    waited.arguments[0] = 4;
    waited.result = WAIT_TIMEOUT;
    FinishAsyncIo(sink, waited, AsyncIoRole::WaitSingle);
    Require(state.calls.empty(), "A timed-out wait completed pending I/O");
    waited.result = 0;
    FinishAsyncIo(sink, waited, AsyncIoRole::WaitSingle);
    Require(state.calls.size() == 1279 && header->asyncPending == 2561,
        "A successful wait lost requests or completed unrelated events");
    controls[0].Internal = 0;
    FinishAsyncIo(sink, waited, AsyncIoRole::WaitSingle);
    Require(state.calls.size() == 1280, "A request pending during the earlier wait was skipped");

    // Wait-any observes only its returned handle; wait-all drains the remaining matching requests.
    uintptr_t handles[]{8, 12};
    waited.api = Api::WaitForMultipleObjects;
    waited.arguments[0] = 2;
    waited.arguments[1] = reinterpret_cast<uintptr_t>(handles);
    waited.arguments[2] = FALSE;
    waited.result = 1;
    FinishAsyncIo(sink, waited, AsyncIoRole::WaitMultiple);
    Require(state.calls.size() == 2560 && header->asyncPending == 1280, "Wait-any completed the wrong handle");
    waited.arguments[2] = TRUE;
    waited.result = 0;
    FinishAsyncIo(sink, waited, AsyncIoRole::WaitMultiple);
    std::sort(state.calls.begin(), state.calls.end());
    Require(state.calls.size() == controls.size() && !header->asyncPending,
        "Wait-all left matching requests unobserved");
    for (uint32_t index = 0; index < controls.size(); ++index)
        Require(state.calls[index] == index + 1, "A completion was duplicated or attributed to the wrong call");
}

void ObserveReusedControl()
{
    auto header = std::make_unique<SharedHeader>();
    header->bufferLimit = 64;
    header->payloadCapacity = 4096;
    header->asyncFree = 1;
    for (uint32_t index = 0; index < AsyncIoCapacity; ++index)
        header->asyncIo[index].next = index + 1 < AsyncIoCapacity ? index + 2 : 0;
    alignas(512) OVERLAPPED controls[2]{};
    struct State
    {
        SharedHeader* header;
        OVERLAPPED* controls;
        std::unique_ptr<std::byte[]> slot;
        std::vector<uint64_t> calls;
    } state{header.get(), controls, std::make_unique<std::byte[]>(sizeof(Slot) + header->payloadCapacity)};
    AsyncIoSink sink{header.get(), &state,
        [](void* context) { return reinterpret_cast<Slot*>(static_cast<State*>(context)->slot.get()); },
        [](void* context, Slot* slot)
        {
            auto& state = *static_cast<State*>(context);
            state.calls.push_back(slot->event.callId);
            if (state.calls.size() != 1) return;

            // Reuse the other completed request while its old identity remains in the observer's batch.
            Event submit{};
            submit.api = Api::ReadFile;
            submit.callId = 3;
            submit.threadId = 2;
            submit.arguments[4] = reinterpret_cast<uintptr_t>(state.controls + (slot->event.callId == 1 ? 1 : 0));
            BeginAsyncIo(state.header, submit, AsyncIoRole::ReadFile);
        }};
    for (uint32_t index = 0; index < std::size(controls); ++index)
    {
        controls[index].hEvent = reinterpret_cast<HANDLE>(uintptr_t{4});
        Event submit{};
        submit.api = Api::ReadFile;
        submit.callId = index + 1;
        submit.threadId = 1;
        submit.arguments[4] = reinterpret_cast<uintptr_t>(&controls[index]);
        BeginAsyncIo(header.get(), submit, AsyncIoRole::ReadFile);
        submit.error = ERROR_IO_PENDING;
        FinishAsyncIo(sink, submit, AsyncIoRole::ReadFile);
    }
    Event waited{};
    waited.api = Api::WaitForSingleObject;
    waited.arguments[0] = 4;
    FinishAsyncIo(sink, waited, AsyncIoRole::WaitSingle);
    Require(state.calls.size() == 1 && header->asyncPending == 1 && header->asyncUntracked == 1,
        "An old wait snapshot completed a reused control block");
    FinishAsyncIo(sink, waited, AsyncIoRole::WaitSingle);
    Require(state.calls.size() == 2 && state.calls.back() == 3 && !header->asyncPending,
        "A reused control block was not observed by a later wait");
}

int main()
{
    return RunChecks([]
    {
        CaptureStrings();
        ObserveWaits();
        ObserveReusedControl();
        std::puts("PASS: bounded string memory and batched I/O wait observation");
    });
}

#include "RtmCaptureValues.h"
#include "CaptureFixture.h"
#include "GuardedPages.h"
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

using namespace Detourist;
using namespace Detourist::Tests;

struct Frame : CaptureFrame<2048>
{
    Frame() : CaptureFrame(128) {}

    std::vector<Value> Capture(uint32_t index, const ExportParameter& parameter, bool leaving)
    {
        auto slot = ResetSlot();
        CaptureRtmBuffer(event, slot, header.get(), leaving, index, parameter);
        std::vector<Value> values;
        for (uint32_t offset = 0; offset < slot->event.payloadBytes;)
        {
            Value value{};
            memcpy(&value, Transport::Payload(slot) + offset, sizeof(value));
            values.push_back(value);
            offset += static_cast<uint32_t>(sizeof(value)) + value.capturedBytes;
        }
        return values;
    }
};

ExportParameter Parameter(RtmBuffer mode, uint8_t flags)
{
    ExportParameter parameter{};
    parameter.bytes = static_cast<uint32_t>(mode);
    parameter.flags = flags;
    parameter.multiplier = 1;
    if (mode == RtmBuffer::Criteria) parameter.actualIndex = 2;
    return parameter;
}

void DirectBuffers()
{
    Frame call;
    auto pages = Detourist::Tests::GuardedPages(call.header->pageBytes, PAGE_NOACCESS);
    auto boundary = pages.get() + call.header->pageBytes;
    DWORD previous = 0;

    // Exact IP/IPX route and network allocations end at an inaccessible page on both architectures.
    for (uint64_t family : {0ull, 1ull})
    {
        const uint32_t bytes = family ? 92u : 52u;
        call.event.arguments[0] = family;
        call.event.arguments[2] = reinterpret_cast<uintptr_t>(boundary - bytes);
        for (bool leaving : {false, true})
        {
            auto values = call.Capture(2, Parameter(RtmBuffer::Route, 3), leaving);
            Require(values.size() == 1 && values[0].capturedBytes == bytes && !values[0].flags,
                "Family-specific route crossed its bound");
        }
        const uint32_t network = family ? 8u : 4u;
        call.event.arguments[1] = reinterpret_cast<uintptr_t>(boundary - network);
        auto values = call.Capture(1, Parameter(RtmBuffer::Network, 1), false);
        Require(values.size() == 1 && values[0].capturedBytes == network && !values[0].flags,
            "Network input used a route size");
        Require(call.Capture(1, Parameter(RtmBuffer::Network, 1), true).empty(), "Input network read on return");
        Require(call.Capture(2, Parameter(RtmBuffer::BestRoute, 2), true).empty(), "False IsRoute exposed output");
        call.event.result = TRUE;
        values = call.Capture(2, Parameter(RtmBuffer::BestRoute, 2), true);
        Require(values.size() == 1 && values[0].capturedBytes == bytes, "IsRoute lost valid output");
        Require(call.Capture(2, Parameter(RtmBuffer::BestRoute, 2), false).empty(), "IsRoute read unfilled output");
        call.event.result = NO_ERROR;
    }

    // Unknown selectors and null pointers remain opaque before any memory read.
    for (uint64_t family : {2ull, 99ull, UINT64_MAX})
    {
        call.event.arguments[0] = family;
        call.event.arguments[2] = 9;
        Require(call.Capture(2, Parameter(RtmBuffer::Route, 3), false).empty(), "Unknown family probed a pointer");
    }
    call.event.arguments[0] = 1;
    call.event.arguments[2] = 0;
    Require(call.Capture(2, Parameter(RtmBuffer::Route, 3), false).empty(), "Null route produced data");
    call.event.arguments[2] = reinterpret_cast<uintptr_t>(boundary - 92);
    call.event.arguments[0] = UINT64_C(0xFEDCBA9800000001);
    Require(call.Capture(2, Parameter(RtmBuffer::Route, 3), false).size() == 1,
        "The upper bits of a DWORD changed the protocol family");
    call.event.arguments[0] = 1;
    call.header->bufferLimit = 13;
    auto values = call.Capture(2, Parameter(RtmBuffer::Route, 3), true);
    Require(values.size() == 1 && values[0].capturedBytes == 13 && values[0].originalBytes == 92 &&
        (values[0].flags & Truncated), "Route capture exceeded its global limit");
    call.event.arguments[2] = reinterpret_cast<uintptr_t>(boundary);
    values = call.Capture(2, Parameter(RtmBuffer::Route, 3), true);
    Require(values.size() == 1 && !values[0].capturedBytes && (values[0].flags & Unreadable),
        "Unreadable route was captured as readable");
    Require(VirtualProtect(boundary, call.header->pageBytes, PAGE_READWRITE | PAGE_GUARD, &previous) != FALSE,
        "Cannot guard route storage");
    values = call.Capture(2, Parameter(RtmBuffer::Route, 3), true);
    MEMORY_BASIC_INFORMATION region{};
    Require(values.size() == 1 && (values[0].flags & Unreadable) &&
        VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
        "Route capture consumed an application guard page");
    call.event.arguments[1] = reinterpret_cast<uintptr_t>(boundary);
    values = call.Capture(1, Parameter(RtmBuffer::Network, 1), false);
    Require(values.size() == 1 && (values[0].flags & Unreadable) &&
        VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
        "Network capture consumed an application guard page");
}

void CriteriaAndFailures()
{
    Frame call;
    BYTE route[92]{};
    call.event.arguments[0] = 1;
    call.event.arguments[2] = reinterpret_cast<uintptr_t>(route);

    // CreateEnumeration/GetFirst ignore criteria with no selected fields; GetNext still consumes its route.
    for (uint64_t flags : {0ull, 8ull, 16ull, 17ull, UINT64_MAX})
    {
        call.event.arguments[1] = flags;
        for (uint8_t direction : {uint8_t{1}, uint8_t{3}})
            Require(call.Capture(2, Parameter(RtmBuffer::Criteria, direction), false).empty(),
                "Ignored or invalid criteria were read");
    }
    for (uint64_t flags : {1ull, 2ull, 4ull, 7ull, 9ull, 15ull})
    {
        call.event.arguments[1] = flags;
        for (uint8_t direction : {uint8_t{1}, uint8_t{3}})
            Require(call.Capture(2, Parameter(RtmBuffer::Criteria, direction), false).size() == 1,
                "Verified criterion was lost");
    }
    call.event.arguments[1] = UINT64_C(0xFEDCBA9800000001);
    Require(call.Capture(2, Parameter(RtmBuffer::Criteria, 3), false).size() == 1,
        "The upper bits of a DWORD changed the route selector");
    call.event.arguments[1] = 0;
    Require(call.Capture(2, Parameter(RtmBuffer::Route, 3), false).size() == 1, "GetNext lost its route input");
    Require(call.Capture(2, Parameter(RtmBuffer::Criteria, 3), true).size() == 1,
        "GetFirst lost output from an unfiltered scan");
    Require(call.Capture(2, Parameter(RtmBuffer::Criteria, 1), true).empty(), "CreateEnumeration exposed output");
    for (uint64_t result : {uint64_t{ERROR_INVALID_PARAMETER}, uint64_t{ERROR_MORE_DATA}, UINT64_MAX})
    {
        call.event.result = result;
        Require(call.Capture(2, Parameter(RtmBuffer::Route, 3), true).empty(), "Failed getter exposed output");
        Require(call.Capture(2, Parameter(RtmBuffer::Criteria, 3), true).empty(), "Failed first route exposed output");
    }
    for (uint32_t flags : {Failed, Skipped, Unwound, AsyncPending})
    {
        call.event.flags = flags;
        call.event.result = NO_ERROR;
        Require(call.Capture(2, Parameter(RtmBuffer::Route, 3), true).empty(), "Incomplete getter exposed output");
        call.event.result = TRUE;
        Require(call.Capture(2, Parameter(RtmBuffer::BestRoute, 2), true).empty(), "Incomplete lookup exposed output");
    }
}

void CommonRouteFields()
{
    Frame call;
    auto pages = Detourist::Tests::GuardedPages(call.header->pageBytes, PAGE_NOACCESS);
    auto boundary = pages.get() + call.header->pageBytes;
    auto route = boundary - 36;
    memset(route, 0x6a, 36);
    call.event.arguments[0] = 0xdeadbeef;
    call.event.arguments[1] = reinterpret_cast<uintptr_t>(route);
    auto parameter = Parameter(RtmBuffer::AddInput, 1);
    parameter.extentIndex = -1;
    auto values = call.Capture(1, parameter, false);
    Require(values.size() == 3 && values[0].parameter == ((12 + 1) << 8 | 1) &&
        values[1].parameter == ((16 + 1) << 8 | 1) && values[2].parameter == ((32 + 1) << 8 | 1) &&
        values[0].capturedBytes == 4 && values[1].capturedBytes == 16 && values[2].capturedBytes == 4 &&
        (values[0].flags & MemberData), "AddRoute lost a documented common field");
    Require(call.Capture(1, parameter, true).empty(), "An input route was read on return");
    parameter = Parameter(RtmBuffer::DeleteInput, 1);
    parameter.extentIndex = -1;
    values = call.Capture(1, parameter, false);
    Require(values.size() == 2 && values[0].parameter == ((12 + 1) << 8 | 1) &&
        values[1].parameter == ((32 + 1) << 8 | 1), "DeleteRoute read fields outside its contract");

    // Only selected criteria are read, including when storage ends at a page boundary.
    parameter = Parameter(RtmBuffer::BlockInput, 1);
    parameter.extentIndex = 1;
    call.event.arguments[2] = reinterpret_cast<uintptr_t>(route);
    for (uint32_t selector : {0u, 8u, 16u, 17u})
    {
        call.event.arguments[1] = selector;
        Require(call.Capture(2, parameter, false).empty(), "Ignored criteria established a field");
    }
    call.event.arguments[1] = 7;
    values = call.Capture(2, parameter, false);
    Require(values.size() == 3 && values[0].parameter == ((8 + 1) << 8 | 2) &&
        values[1].parameter == ((12 + 1) << 8 | 2) && values[2].parameter == ((32 + 1) << 8 | 2),
        "Criteria flags did not select their common fields");
    call.event.arguments[1] = UINT64_C(0xFFFFFFFF00000001);
    values = call.Capture(2, parameter, false);
    Require(values.size() == 1 && values[0].parameter == ((32 + 1) << 8 | 2),
        "Upper argument bits changed a DWORD criteria flag");

    // A returned enumeration record is complete only on NO_ERROR.
    parameter = Parameter(RtmBuffer::Enumerated, 2);
    parameter.extentIndex = -1;
    call.event.arguments[1] = reinterpret_cast<uintptr_t>(route);
    call.event.result = NO_ERROR;
    values = call.Capture(1, parameter, true);
    Require(values.size() == 1 && values[0].capturedBytes == 36 && !values[0].flags,
        "Enumeration lost the common family-independent prefix");
    call.event.result = ERROR_NO_MORE_ITEMS;
    Require(call.Capture(1, parameter, true).empty(), "A failed enumeration exposed its output");
}

void CommonRouteResults()
{
    Frame call;
    BYTE route[52]{};
    DWORD flags = 0;
    call.event.arguments[0] = 0xdeadbeef;
    call.event.arguments[3] = reinterpret_cast<uintptr_t>(&flags);
    call.event.arguments[4] = call.event.arguments[5] = reinterpret_cast<uintptr_t>(route);
    auto current = Parameter(RtmBuffer::AddCurrent, 2);
    current.extentIndex = 3;
    auto previous = Parameter(RtmBuffer::AddPrevious, 2);
    previous.extentIndex = 3;
    for (DWORD state : {0u, 1u, 2u, 3u, 4u})
    {
        flags = state;
        auto now = call.Capture(4, current, true);
        auto prior = call.Capture(5, previous, true);
        Require(now.size() == (state == 1 || state == 3 ? 1u : 0u) &&
            prior.size() == (state == 3 ? 1u : 0u), "AddRoute used an invalid change flag");
        if (!now.empty()) Require(now[0].capturedBytes == 36, "Current route exceeded the common prefix");
    }
    auto deleted = Parameter(RtmBuffer::DeleteCurrent, 2);
    deleted.extentIndex = 2;
    call.event.arguments[2] = reinterpret_cast<uintptr_t>(&flags);
    call.event.arguments[3] = reinterpret_cast<uintptr_t>(route);
    for (DWORD state : {0u, 1u, 2u, 3u, 4u})
    {
        flags = state;
        Require(call.Capture(3, deleted, true).size() == (state == 3 ? 1u : 0u),
            "DeleteRoute used an invalid change flag");
    }
    auto messageNow = Parameter(RtmBuffer::MessageCurrent, 2);
    auto messageBefore = Parameter(RtmBuffer::MessagePrevious, 2);
    messageNow.extentIndex = messageBefore.extentIndex = 1;
    call.event.arguments[1] = reinterpret_cast<uintptr_t>(&flags);
    call.event.arguments[2] = call.event.arguments[3] = reinterpret_cast<uintptr_t>(route);
    for (uint32_t result : {uint32_t{NO_ERROR}, uint32_t{ERROR_MORE_DATA}})
    {
        call.event.result = result;
        for (DWORD state : {0u, 1u, 2u, 3u, 4u})
        {
            flags = state;
            Require(call.Capture(2, messageNow, true).size() == (state == 1 || state == 3 ? 1u : 0u) &&
                call.Capture(3, messageBefore, true).size() == (state == 2 || state == 3 ? 1u : 0u),
                "Route message used an invalid status or change flag");
        }
    }
    flags = 3;
    for (uint32_t result : {uint32_t{ERROR_INVALID_HANDLE}, uint32_t{ERROR_NO_MORE_ITEMS}})
    {
        call.event.result = result;
        Require(call.Capture(2, messageNow, true).empty(), "A failed route message exposed output");
    }
    call.event.result = NO_ERROR;
    for (uint32_t state : {Failed, Skipped, Unwound, AsyncPending})
    {
        call.event.flags = state;
        Require(call.Capture(3, messageBefore, true).empty(), "An incomplete route message exposed output");
    }
    call.event.flags = 0;
    call.event.arguments[1] = 9;
    Require(call.Capture(2, messageNow, true).empty(), "An unreadable change flag established output");

    // A guarded change flag is never consumed while checking output validity.
    auto release = [](void* value) { if (value) VirtualFree(value, 0, MEM_RELEASE); };
    auto memory = VirtualAlloc(nullptr, call.header->pageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    std::unique_ptr<void, decltype(release)> allocation(memory, release);
    Require(allocation != nullptr, "Cannot allocate a route flag guard page");
    DWORD protection = 0;
    Require(VirtualProtect(memory, call.header->pageBytes, PAGE_READWRITE | PAGE_GUARD, &protection) != FALSE,
        "Cannot guard route flag storage");
    call.event.arguments[1] = reinterpret_cast<uintptr_t>(memory);
    MEMORY_BASIC_INFORMATION region{};
    Require(call.Capture(2, messageNow, true).empty() &&
        VirtualQuery(memory, &region, sizeof(region)) == sizeof(region) && (region.Protect & PAGE_GUARD),
        "A guarded route-change flag was consumed");
}

void InvalidContracts()
{
    Frame call;
    call.event.arguments[0] = 1;
    call.event.arguments[1] = call.event.arguments[2] = 9;
    auto parameter = Parameter(RtmBuffer::Route, 3);
    parameter.extentIndex = 1;
    Require(call.Capture(2, parameter, false).empty(), "Non-family selector was accepted");
    parameter = Parameter(RtmBuffer::Route, 1);
    Require(call.Capture(2, parameter, false).empty(), "Handle-derived input contract was accepted");
    parameter = Parameter(RtmBuffer::Route, 2);
    Require(call.Capture(2, parameter, true).empty(), "Handle-derived output contract was accepted");
    parameter = Parameter(RtmBuffer::Route, 3);
    parameter.bytes = UINT32_MAX;
    Require(call.Capture(2, parameter, false).empty(), "Unknown mode was accepted");
    parameter = Parameter(RtmBuffer::Route, 3);
    Require(call.Capture(1, parameter, false).empty(), "Wrong route ordinal was accepted");
    Require(call.Capture(MaximumArguments, parameter, false).empty(), "Out-of-range argument was indexed");
    parameter.actualIndex = 4;
    Require(call.Capture(2, parameter, false).empty(), "Route-change flags contract was accepted");
    parameter = Parameter(RtmBuffer::Criteria, 3);
    parameter.actualIndex = 0;
    Require(call.Capture(2, parameter, false).empty(), "Missing criteria selector was accepted");
}

int wmain()
{
    return RunChecks([]
    {
        DirectBuffers();
        CriteriaAndFailures();
        CommonRouteFields();
        CommonRouteResults();
        InvalidContracts();
        std::puts("PASS: stateless RTMv1 selectors, bounded buffers, failure gates and passive reads.");
    });
}

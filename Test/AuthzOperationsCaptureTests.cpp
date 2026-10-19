#include "AuthzOperationsCapture.h"
#include "CaptureFixture.h"
#include "GuardedPages.h"
#include <array>
#include <cstdio>
#include <memory>

using namespace Detourist;
using namespace Detourist::Tests;

void CheckOperations()
{
    CaptureFrame<256> call(64);
    auto slot = call.ResetSlot();
    ExportParameter parameter{4, -1, 0, 1, 1, ExportValueKind::Bytes};
    parameter.actualIndirectBytes = 4;
    auto capture = [&](uint32_t index, const void* operations, const void* context, uint16_t countOffset,
        bool leaving = false, uint32_t limit = 64)
    {
        slot->event.payloadBytes = 0;
        call.header->bufferLimit = limit;
        parameter.actualIndex = static_cast<uint8_t>(index);
        parameter.actualOffset = countOffset;
        call.event.arguments[index] = reinterpret_cast<uintptr_t>(operations);
        call.event.arguments[index - 1] = reinterpret_cast<uintptr_t>(context);
        CaptureAuthzOperations(call, slot, leaving, index, parameter);
        Value value{};
        if (slot->event.payloadBytes >= sizeof(value))
            memcpy(&value, Transport::Payload(slot), sizeof(value));
        return value;
    };
    auto check = [&](const Value& value, uint64_t original, uint32_t captured, uint32_t flags = 0)
    {
        Require(value.kind == ValueKind::Bytes && value.originalBytes == original &&
            value.capturedBytes == captured && value.flags == flags &&
            slot->event.payloadBytes == sizeof(Value) + captured, "Authz operation snapshot shape changed");
    };
    std::array<uint32_t, 4> operations{AUTHZ_SID_OPERATION_ADD, AUTHZ_SID_OPERATION_DELETE,
        AUTHZ_SID_OPERATION_NONE, AUTHZ_SID_OPERATION_ADD};

    // Both group fields and claim fields supply counts for all four catalog argument positions.
    for (uint32_t index : {7u, 9u, 11u, 13u})
    {
        auto countOffset = static_cast<uint16_t>(index < 10 ? 0 : 4);
        for (uint32_t count : {0u, 1u, 4u})
        {
            std::array<uint32_t, 2> context{0xFFFF0001u, count};
            if (!countOffset) context[0] = count;
            auto value = capture(index, operations.data(), context.data(), countOffset);
            check(value, count * 4, count * 4);
            Require(value.parameter == index, "Authz operation argument identity changed");
            Require(!memcmp(Transport::Payload(slot) + sizeof(Value), operations.data(), value.capturedBytes),
                "Authz operation contents changed");
        }
    }
    auto value = capture(7, operations.data(), nullptr, 0);
    check(value, 4, 4);
    value = capture(7, nullptr, nullptr, 0);
    Require(!slot->event.payloadBytes, "A null optional operation array was sampled");
    capture(7, operations.data(), nullptr, 0, true);
    Require(!slot->event.payloadBytes, "Authz operations were captured on return");

    // Guarded contexts and single-enum arrays expose accidental traversal beyond the selected extent.
    auto pages = Detourist::Tests::GuardedPages(call.header->pageBytes, PAGE_READWRITE | PAGE_GUARD);
    auto boundary = pages.get() + call.header->pageBytes;
    DWORD previous = 0;
    uint32_t replaceAll = AUTHZ_SID_OPERATION_REPLACE_ALL;
    memcpy(boundary - 4, &replaceAll, 4);
    value = capture(11, boundary - 4, boundary, 4);
    check(value, 4, 4);
    MEMORY_BASIC_INFORMATION region{};
    Require(VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
        "REPLACE_ALL probed the guarded context");
    memcpy(boundary - 4, operations.data(), 4);
    value = capture(7, boundary - 4, nullptr, 0);
    check(value, 4, 4);
    Require(VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
        "A null context probed beyond one operation");
    value = capture(7, boundary - 4, boundary, 0);
    check(value, 4, 4);
    Require(VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
        "An unreadable context consumed the application's guard page");
    value = capture(7, boundary, nullptr, 0);
    check(value, 4, 0, Unreadable);
    Require(VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
        "An unreadable operation consumed the application's guard page");
    Require(VirtualProtect(boundary, call.header->pageBytes, PAGE_NOACCESS, &previous) != FALSE,
        "Protect operation context");
    value = capture(7, boundary - 4, boundary, 0);
    check(value, 4, 4);
    value = capture(11, boundary - 4, boundary - 4, 4);
    check(value, 4, 4);
    value = capture(7, boundary, nullptr, 0);
    check(value, 4, 0, Unreadable);
    value = capture(7, boundary - 2, nullptr, 0);
    check(value, 4, 0, Unreadable);
    uint32_t many = 4;
    value = capture(7, boundary - 4, &many, 0, false, 4);
    check(value, 16, 4, Truncated);
    Require(VirtualProtect(boundary, call.header->pageBytes, PAGE_READWRITE | PAGE_GUARD, &previous) != FALSE,
        "Guard operation sample");
    value = capture(7, boundary, &many, 0);
    check(value, 4, 0, Unreadable);

    // Payload budgets and extreme counts cannot expand reads or wrap native addresses.
    value = capture(7, operations.data(), &many, 0, false, 5);
    check(value, 16, 5, Truncated);
    value = capture(7, operations.data(), &many, 0, false, 2);
    check(value, 4, 2, Truncated);
    uint32_t huge = UINT32_MAX;
    value = capture(7, operations.data(), &huge, 0, false, 8);
    check(value, uint64_t{UINT32_MAX} * 4, 8, Truncated);
    value = capture(11, operations.data(), reinterpret_cast<void*>(UINTPTR_MAX - 2), 4);
    check(value, 4, 4);
    value = capture(7, reinterpret_cast<void*>(UINTPTR_MAX - 2), nullptr, 0);
    check(value, 4, 0, Unreadable);
    call.header->payloadCapacity = sizeof(Value) + 6;
    value = capture(7, operations.data(), &many, 0);
    check(value, 16, 6, Truncated);
    call.header->payloadCapacity = sizeof(Value) - 1;
    capture(7, operations.data(), nullptr, 0);
    Require(!slot->event.payloadBytes, "Authz operations exceeded the remaining payload");
}

int main()
{
    return RunChecks([]
    {
        CheckOperations();
        std::puts("Authz operation captures passed.");
    });
}

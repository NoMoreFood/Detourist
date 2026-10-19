#include "CatalogCaptureValues.h"
#include "CaptureFixture.h"
#include "GuardedPages.h"
#include <array>
#include <cstdio>
#include <memory>
#include <vector>

using namespace Detourist;
using namespace Detourist::Tests;

struct EapCapture : CaptureFrame<>
{
    uint64_t captureLimits[MaximumArguments]{};
    uint32_t initializedOutputs = 0;
    EAP_ERROR* output = nullptr;
    ExportParameter parameter{sizeof(EAP_ERROR), -1, 0, 1, 2, ExportValueKind::Bytes};

    EapCapture() : CaptureFrame(256)
    {
        event.arguments[7] = reinterpret_cast<uintptr_t>(&output);
    }

    std::vector<Snapshot> Capture(bool leaving)
    {
        auto slot = ResetSlot();
        CaptureEapError(*this, slot, leaving, 7, parameter);
        return Snapshots();
    }
};

EAP_ERROR Error(wchar_t* cause, wchar_t* repair)
{
    EAP_ERROR error{};
    error.dwWinError = ERROR_CANCELLED;
    error.dwReasonCode = 91;
    error.pRootCauseString = cause;
    error.pRepairString = repair;
    return error;
}

void ChangedOutputs()
{
    EapCapture call;
    wchar_t cause[] = L"configuration cancelled";
    wchar_t repair[] = L"retry configuration";
    auto error = Error(cause, repair);
    Require(call.Capture(false).empty() && (call.initializedOutputs & (1u << 7)) && !call.captureLimits[7],
        "Entry emitted output or failed to sample the initial pointer");
    call.output = &error;
    call.event.flags = Failed;
    call.event.result = ERROR_CANCELLED;
    auto values = call.Capture(true);
    Require(values.size() == 4 && values[0].value.kind == ValueKind::Scalar &&
        values[0].value.parameter == 7 && values[0].bytes.size() == sizeof(uintptr_t),
        "Changed failure output did not retain its native pointer");
    Require(values[1].value.parameter == 7 && values[1].value.kind == ValueKind::Bytes &&
        values[1].bytes.size() == sizeof(error) && (values[1].value.flags & ReferencedData) &&
        !memcmp(values[1].bytes.data(), &error, sizeof(error)), "The EAP error record changed");
    for (size_t index = 0; index < 2; ++index)
    {
        auto offset = index ? offsetof(EAP_ERROR, pRepairString) : offsetof(EAP_ERROR, pRootCauseString);
        auto bytes = index ? sizeof(repair) : sizeof(cause);
        auto text = index ? repair : cause;
        auto& value = values[index + 2];
        Require(value.value.parameter == (((offset + 1u) << 8) | 7u) &&
            value.value.kind == ValueKind::Utf16 && value.bytes.size() == bytes &&
            value.value.flags == (MemberData | ReferencedData) && !memcmp(value.bytes.data(), text, bytes),
            "An EAP error string lost its member identity or contents");
    }

    // Success and incomplete calls never expose the failure-only output, even with stale event state.
    for (uint32_t flags : {0u, Failed | Skipped, Failed | Unwound, Failed | AsyncPending})
    {
        call.event.flags = flags;
        Require(call.Capture(true).empty(), "A successful or incomplete call captured an EAP error");
    }
    call.event.flags = Failed;
    call.event.result = ERROR_SUCCESS;
    Require(call.Capture(true).empty(), "A zero result was treated as an actual failure");
    call.event.result = ERROR_CANCELLED;
    Require(call.Capture(false).empty() && call.captureLimits[7] == reinterpret_cast<uintptr_t>(&error),
        "Entry did not replace a stale output-pointer sample");
    Require(call.Capture(true).empty(), "An unchanged error pointer was followed after failure");
    call.output = nullptr;
    Require(call.Capture(true).empty(), "A null returned error pointer established a record");
    call.initializedOutputs = 0;
    call.output = &error;
    Require(call.Capture(true).empty(), "An unsampled pointer established a failure output");
    call.parameter.flags = 0;
    Require(call.Capture(false).empty() && !call.initializedOutputs && !call.captureLimits[7],
        "A disabled output retained an old initialization sample");
}

void CaptureLimits()
{
    EapCapture call;
    std::array<wchar_t, 160> cause{};
    cause.fill(L'x');
    cause.back() = 0;
    wchar_t repair[] = L"repair";
    auto error = Error(cause.data(), repair);
    call.Capture(false);
    call.output = &error;
    call.event.flags = Failed;
    call.event.result = ERROR_INVALID_DATA;

    // A partial root can establish only those native pointer fields entirely retained in the snapshot.
    call.header->bufferLimit = static_cast<uint32_t>(offsetof(EAP_ERROR, pRootCauseString) + sizeof(uintptr_t) - 1);
    auto values = call.Capture(true);
    Require(values.size() == 2 && values[1].bytes.size() == call.header->bufferLimit &&
        (values[1].value.flags & Truncated), "A partial pointer field established referenced strings");
    call.header->bufferLimit += 1;
    values = call.Capture(true);
    Require(values.size() == 3 && values[2].value.parameter ==
        (((offsetof(EAP_ERROR, pRootCauseString) + 1u) << 8) | 7u) &&
        values[2].bytes.size() == call.header->bufferLimit && (values[2].value.flags & Truncated),
        "A complete first string field was lost or an absent second field was followed");
    call.header->bufferLimit = sizeof(EAP_ERROR);
    values = call.Capture(true);
    Require(values.size() == 4 && values[2].bytes.size() == sizeof(EAP_ERROR) &&
        (values[2].value.flags & Truncated) && values[2].value.originalBytes == 0,
        "A bounded unterminated string lost its truncation state");
    call.header->bufferLimit = static_cast<uint32_t>(sizeof(uintptr_t) - 1);
    Require(call.Capture(true).empty(), "An incomplete native pointer established an EAP error");
    call.header->bufferLimit = 256;
    call.header->payloadCapacity = sizeof(Value) + sizeof(uintptr_t);
    values = call.Capture(true);
    Require(values.size() == 1, "The error record exceeded the remaining payload budget");
    call.header->payloadCapacity = sizeof(Value) + sizeof(uintptr_t) + sizeof(Value) +
        static_cast<uint32_t>(offsetof(EAP_ERROR, pRootCauseString));
    values = call.Capture(true);
    Require(values.size() == 2 && values[1].bytes.size() == offsetof(EAP_ERROR, pRootCauseString),
        "A payload-limited record established missing strings");
    call.header->payloadCapacity = sizeof(Value) - 1;
    Require(call.Capture(true).empty(), "EAP errors exceeded a payload shorter than a value header");
}

void GuardedOutputs()
{
    EapCapture call;
    auto pages = Detourist::Tests::GuardedPages(call.header->pageBytes, PAGE_READWRITE | PAGE_GUARD);
    auto boundary = pages.get() + call.header->pageBytes;
    DWORD previous = 0;
    auto guarded = [&]
    {
        MEMORY_BASIC_INFORMATION region{};
        Require(VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
            "EAP capture consumed an application's guard page");
    };
    wchar_t text[] = L"readable";
    auto error = Error(text, text);

    // Unreadable entry storage cannot prove initialization, even if readable storage appears on return.
    call.event.arguments[7] = reinterpret_cast<uintptr_t>(boundary);
    call.initializedOutputs = 1u << 7;
    call.captureLimits[7] = 42;
    Require(call.Capture(false).empty() && !call.initializedOutputs && !call.captureLimits[7],
        "Unreadable entry storage retained a stale pointer sample");
    guarded();
    call.event.arguments[7] = reinterpret_cast<uintptr_t>(&call.output);
    call.output = &error;
    call.event.flags = Failed;
    call.event.result = ERROR_CANCELLED;
    Require(call.Capture(true).empty(), "A missing entry sample established error data");
    call.output = reinterpret_cast<EAP_ERROR*>(boundary);
    Require(call.Capture(false).empty(), "Entry followed the original error pointer");
    Require(call.Capture(true).empty(), "An unchanged guarded pointer was followed");
    guarded();
    call.output = &error;
    Require(call.Capture(true).size() == 4, "A changed pointer retained an unrelated guarded entry target");

    // Each referenced region is guarded independently; a readable sibling string remains capturable.
    call.output = nullptr;
    call.Capture(false);
    call.output = reinterpret_cast<EAP_ERROR*>(boundary);
    auto values = call.Capture(true);
    Require(values.size() == 2 && values[1].bytes.empty() &&
        (values[1].value.flags & Unreadable), "An unreadable error established string fields");
    guarded();
    error.pRootCauseString = reinterpret_cast<wchar_t*>(boundary);
    call.output = &error;
    values = call.Capture(true);
    Require(values.size() == 4 && values[2].bytes.empty() &&
        (values[2].value.flags & Unreadable) && values[3].bytes.size() == sizeof(text),
        "An unreadable string lost its marker or prevented a readable sibling");
    guarded();
    wchar_t terminated[] = L"ok";
    memcpy(boundary - sizeof(terminated), terminated, sizeof(terminated));
    error.pRootCauseString = reinterpret_cast<wchar_t*>(boundary - sizeof(terminated));
    error.pRepairString = nullptr;
    values = call.Capture(true);
    Require(values.size() == 3 && values[2].bytes.size() == sizeof(terminated) &&
        !(values[2].value.flags & (Unreadable | Truncated)), "A terminator before a guard page was lost");
    guarded();

    // Pointer slots and record spans crossing protected pages cannot trigger speculative traversal.
    error.pRootCauseString = text;
    call.event.arguments[7] = reinterpret_cast<uintptr_t>(boundary - sizeof(uintptr_t));
    uintptr_t pointer = 0;
    memcpy(boundary - sizeof(pointer), &pointer, sizeof(pointer));
    call.Capture(false);
    pointer = reinterpret_cast<uintptr_t>(&error);
    memcpy(boundary - sizeof(pointer), &pointer, sizeof(pointer));
    Require(call.Capture(true).size() == 3, "A boundary-aligned native pointer was not captured");
    call.event.arguments[7] = reinterpret_cast<uintptr_t>(boundary - sizeof(uintptr_t) + 1);
    Require(call.Capture(true).empty(), "A pointer crossing a guard page established an error");
    guarded();
    call.event.arguments[7] = reinterpret_cast<uintptr_t>(&call.output);
    call.output = reinterpret_cast<EAP_ERROR*>(UINTPTR_MAX - 1);
    values = call.Capture(true);
    Require(values.size() == 2 && (values[1].value.flags & Unreadable),
        "An overflowing record address established readable data");
    call.event.arguments[7] = UINTPTR_MAX - 1;
    Require(call.Capture(false).empty() && !call.initializedOutputs && call.Capture(true).empty(),
        "An overflowing pointer slot established initialization");
    Require(VirtualProtect(boundary, call.header->pageBytes, PAGE_NOACCESS, &previous) != FALSE,
        "Cannot protect the EAP boundary");
    call.event.arguments[7] = reinterpret_cast<uintptr_t>(boundary);
    Require(call.Capture(false).empty() && !call.initializedOutputs && call.Capture(true).empty(),
        "An unreadable pointer slot established an error");
}

void CatalogDispatch()
{
    EapCapture call;
    std::array<ExportParameter, 8> parameters{};
    parameters[7] = {sizeof(EAP_ERROR), -1, 0, 1, 2, ExportValueKind::FailureEapError};
    auto slot = call.ResetSlot();
    CaptureCatalogValues(call, slot, false, parameters, {});
    Require(!slot->event.payloadBytes && (call.initializedOutputs & (1u << 7)),
        "The catalog did not initialize failure-only capture");
    wchar_t text[] = L"failure";
    auto error = Error(text, nullptr);
    call.output = &error;
    call.event.flags = Failed;
    call.event.result = ERROR_INVALID_DATA;
    CaptureCatalogValues(call, slot, true, parameters, {});
    Require(slot->event.payloadBytes > sizeof(Value) + sizeof(uintptr_t),
        "The catalog did not dispatch the failed EAP output");
}

int main()
{
    return RunChecks([]
    {
        static_assert(sizeof(EAP_ERROR) == (sizeof(uintptr_t) == 8 ? 88 : 80));
        ChangedOutputs();
        CaptureLimits();
        GuardedOutputs();
        CatalogDispatch();
        std::puts("PASS: failure-only EAP errors preserve changed pointers, bounded records, strings and guard pages.");
    });
}

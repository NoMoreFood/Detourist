#include "PrintDocumentCapture.h"
#include "CaptureFixture.h"
#include "GuardedPages.h"
#include <WinSpool.h>
#include <winddiui.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

using namespace Detourist;
using namespace Detourist::Tests;

struct PrintCapture : CaptureFrame<>
{
    uint64_t captureLimits[MaximumArguments]{};
    int32_t result = 1;

    PrintCapture() : CaptureFrame(512)
    {
        event.arguments[8] = reinterpret_cast<uintptr_t>(&result);
    }

    std::vector<Snapshot> Capture(bool leaving, bool output)
    {
        const uint32_t index = output ? 7u : 5u;
        ExportParameter parameter{};
        parameter.extentIndex = 3;
        parameter.actualIndex = output ? 7 : 5;
        parameter.prefixBytes = 9;
        parameter.flags = output ? 3 : 1;
        parameter.multiplier = 1;
        auto slot = ResetSlot();
        CapturePrintDocumentEvent(*this, slot, leaving, index, parameter);
        return Snapshots();
    }

    std::vector<Snapshot> CapturePayload(bool leaving, PrinterPayload mode)
    {
        const auto index = mode == PrinterPayload::JobAttributes ? 4u : 3u;
        ExportParameter parameter{};
        parameter.bytes = static_cast<uint32_t>(mode);
        parameter.extentIndex = mode == PrinterPayload::DriverInformation ? 2 :
            mode == PrinterPayload::JobAttributes ? 3 : -1;
        parameter.multiplier = 1;
        parameter.flags = mode == PrinterPayload::JobAttributes ? 3 : 1;
        auto slot = ResetSlot();
        CapturePrinterPayload(event, slot, header.get(), leaving, index, parameter);
        return Snapshots();
    }

};

void InputEvents()
{
    PrintCapture call;
    std::array<std::byte, 32> input{};
    input.fill(std::byte{0x5a});
    call.event.arguments[4] = input.size();
    call.event.arguments[5] = reinterpret_cast<uintptr_t>(input.data());

    // Only documented input events expose the supplied buffer; high-word spool flags preserve the selector.
    for (uint32_t event : {1u, 2u, 3u, 4u, 5u, 11u, 13u, 14u})
    {
        call.event.arguments[3] = event | 0x10000;
        auto values = call.Capture(false, false);
        Require(values.size() == 1 && values[0].value.parameter == 5 &&
            values[0].bytes == std::vector(input.begin(), input.end()), "Input event bytes differ");
        Require(call.Capture(true, false).empty(), "Input event was sampled after the callback");
    }
    for (uint32_t event : {0u, 6u, 7u, 8u, 9u, 10u, 12u, 15u, 0xffffu})
    {
        call.event.arguments[3] = event;
        call.event.arguments[5] = 9;
        call.event.arguments[4] = UINT32_MAX;
        Require(call.Capture(false, false).empty(), "An ignored input event probed a poison pointer");
    }
    call.event.arguments[3] = 1;
    call.event.arguments[4] = input.size();
    auto values = call.Capture(false, false);
    Require(values.size() == 1 && (values[0].value.flags & Unreadable), "Unreadable input was not retained");
    call.event.arguments[5] = reinterpret_cast<uintptr_t>(input.data());
    call.header->bufferLimit = 7;
    values = call.Capture(false, false);
    Require(values.size() == 1 && values[0].bytes.size() == 7 && values[0].value.originalBytes == input.size() &&
        (values[0].value.flags & Truncated), "Input capture exceeded its global limit");
}

void OutputEvents()
{
    PrintCapture call;
    std::array<std::byte, 64> output{};
    call.event.arguments[7] = reinterpret_cast<uintptr_t>(output.data());
    call.event.arguments[6] = 16;

    // ESCAPE is output-only; QUERYFILTER retains the initialized input and clamps subsequent growth.
    call.event.arguments[3] = 11;
    Require(call.Capture(false, true).empty(), "ESCAPE sampled uninitialized output");
    output.fill(std::byte{0x42});
    call.event.arguments[6] = output.size();
    auto values = call.Capture(true, true);
    Require(values.size() == 1 && values[0].bytes.size() == 16 && values[0].bytes[0] == std::byte{0x42},
        "ESCAPE lost its entry capacity");
    call.event.arguments[3] = 14 | 0x10000;
    call.event.arguments[6] = 32;
    values = call.Capture(false, true);
    Require(values.size() == 1 && values[0].bytes.size() == 32, "QUERYFILTER input was not captured");
    call.event.arguments[6] = 8;
    values = call.Capture(true, true);
    Require(values.size() == 1 && values[0].bytes.size() == 8, "QUERYFILTER output ignored the smaller capacity");
    for (uint32_t flags : {Failed, Skipped, Unwound})
    {
        call.event.flags = flags;
        Require(call.Capture(true, true).empty(), "An incomplete call captured output");
    }
    call.event.flags = 0;
    call.event.result = static_cast<uint32_t>(E_FAIL);
    Require(call.Capture(true, true).empty(), "A failed HRESULT captured output");
    call.event.result = S_OK;
    for (int32_t result : {-1, 0, 2})
    {
        call.result = result;
        Require(call.Capture(true, true).empty(), "A failed callback result captured output");
    }
    call.result = 1;
    call.event.arguments[8] = 9;
    Require(call.Capture(true, true).empty(), "Unreadable piResult established initialized output");
    call.event.arguments[3] = 7;
    call.event.arguments[7] = 9;
    call.captureLimits[7] = 512;
    Require(call.Capture(false, true).empty() && !call.captureLimits[7] && call.Capture(true, true).empty(),
        "An ignored output event retained stale capacity or touched a poison pointer");
}

void DeviceModeResults()
{
    PrintCapture call;
    auto pages = Detourist::Tests::GuardedPages(call.header->pageBytes, PAGE_NOACCESS);
    auto memory = pages.get();
    auto boundary = memory + call.header->pageBytes;
    auto pointerSlot = boundary - sizeof(uintptr_t);
    uintptr_t pointer = reinterpret_cast<uintptr_t>(memory);
    memcpy(pointerSlot, &pointer, sizeof(pointer));
    DEVMODEW mode{};
    mode.dmSize = static_cast<WORD>(sizeof(mode));
    mode.dmDriverExtra = 16;
    memcpy(memory, &mode, sizeof(mode));
    memset(memory + sizeof(mode), 0xa5, mode.dmDriverExtra);
    call.event.arguments[7] = reinterpret_cast<uintptr_t>(pointerSlot);
    call.event.arguments[6] = UINT32_MAX;

    // A native pointer exactly at a page boundary verifies the x86 and x64 pointer-slot widths.
    for (uint32_t event : {1u, 3u})
    {
        call.event.arguments[3] = event;
        Require(call.Capture(false, true).empty() && call.captureLimits[7] == sizeof(uintptr_t),
            "A DEVMODE result read cbOut or uninitialized pointer storage");
        auto values = call.Capture(true, true);
        Require(values.size() == 2 && values[0].value.kind == ValueKind::Scalar &&
            values[0].bytes.size() == sizeof(uintptr_t) && values[1].bytes.size() == sizeof(mode) + 16 &&
            values[1].bytes.back() == std::byte{0xa5} && (values[1].value.flags & ReferencedData),
            "DEVMODE pointer, private bytes or referenced-data identity differ");
    }
    call.header->bufferLimit = 32;
    auto values = call.Capture(true, true);
    Require(values.size() == 2 && values[1].bytes.size() == 32 &&
        values[1].value.originalBytes == sizeof(mode) + 16 && (values[1].value.flags & Truncated),
        "A DEVMODE allocation exceeded its capture bound");
    call.header->bufferLimit = static_cast<uint32_t>(sizeof(uintptr_t) - 1);
    values = call.Capture(true, true);
    Require(values.size() == 1 && values[0].bytes.size() == sizeof(uintptr_t) - 1,
        "An incomplete pointer established a referenced DEVMODE");
    call.header->bufferLimit = 512;
    for (uint16_t size : {uint16_t{0}, uint16_t{71}})
    {
        memcpy(memory + offsetof(DEVMODEW, dmSize), &size, sizeof(size));
        Require(call.Capture(true, true).size() == 1, "An invalid DEVMODE header was followed");
    }
    pointer = 9;
    memcpy(pointerSlot, &pointer, sizeof(pointer));
    Require(call.Capture(true, true).size() == 1, "An unreadable DEVMODE header was followed");
    pointer = 0;
    memcpy(pointerSlot, &pointer, sizeof(pointer));
    Require(call.Capture(true, true).size() == 1, "A null DEVMODE pointer was followed");
    call.event.arguments[7] = reinterpret_cast<uintptr_t>(boundary);
    values = call.Capture(true, true);
    Require(values.size() == 1 && (values[0].value.flags & Unreadable) && values[0].bytes.empty(),
        "An unreadable pointer slot established a DEVMODE");
}

void DriverAndJobRecords()
{
    static_assert(sizeof(DRIVER_INFO_1W) == sizeof(uintptr_t));
    static_assert(sizeof(DRIVER_INFO_2W) == 6 * sizeof(uintptr_t));
    static_assert(sizeof(DRIVER_INFO_3W) == 10 * sizeof(uintptr_t));
    static_assert(sizeof(ATTRIBUTE_INFO_1) == 28 && sizeof(ATTRIBUTE_INFO_2) == 32);
    static_assert(sizeof(ATTRIBUTE_INFO_3) == 36 && sizeof(ATTRIBUTE_INFO_4) == 56);
    PrintCapture call;
    auto pages = Detourist::Tests::GuardedPages(call.header->pageBytes, PAGE_NOACCESS);
    auto boundary = pages.get() + call.header->pageBytes;

    // Every documented level ends immediately before an inaccessible page.
    for (uint32_t level = 1; level <= 3; ++level)
    {
        const uint32_t bytes = level == 1 ? sizeof(DRIVER_INFO_1W) :
            level == 2 ? sizeof(DRIVER_INFO_2W) : sizeof(DRIVER_INFO_3W);
        memset(boundary - bytes, 0xa5, bytes);
        call.event.arguments[2] = level;
        call.event.arguments[3] = reinterpret_cast<uintptr_t>(boundary - bytes);
        auto values = call.CapturePayload(false, PrinterPayload::DriverInformation);
        Require(values.size() == 1 && values[0].bytes.size() == bytes &&
            values[0].bytes.back() == std::byte{0xa5}, "Driver information exceeded its selected level");
        Require(call.CapturePayload(true, PrinterPayload::DriverInformation).empty(),
            "Driver information was sampled after return");
    }
    call.event.arguments[2] = UINT32_MAX;
    call.event.arguments[3] = reinterpret_cast<uintptr_t>(boundary);
    Require(call.CapturePayload(false, PrinterPayload::DriverInformation).empty(),
        "Unknown driver level touched an invalid pointer");

    const uint32_t sizes[] = {sizeof(ATTRIBUTE_INFO_1), sizeof(ATTRIBUTE_INFO_2),
        sizeof(ATTRIBUTE_INFO_3), sizeof(ATTRIBUTE_INFO_4)};
    for (uint32_t level = 1; level <= 4; ++level)
    {
        auto bytes = sizes[level - 1];
        memset(boundary - bytes, 0x6b, bytes);
        call.event.arguments[3] = level;
        call.event.arguments[4] = reinterpret_cast<uintptr_t>(boundary - bytes);
        for (bool leaving : {false, true})
        {
            auto values = call.CapturePayload(leaving, PrinterPayload::JobAttributes);
            Require(values.size() == 1 && values[0].bytes.size() == bytes &&
                values[0].bytes.back() == std::byte{0x6b}, "Job attributes exceeded their selected level");
        }
    }
    for (uint32_t flags : {Failed, Skipped, Unwound, AsyncPending})
    {
        call.event.flags = flags;
        Require(call.CapturePayload(true, PrinterPayload::JobAttributes).empty(),
            "An incomplete job callback exposed an output record");
    }
    call.event.flags = 0;
    call.event.result = static_cast<uint32_t>(E_FAIL);
    Require(call.CapturePayload(true, PrinterPayload::JobAttributes).empty(),
        "A failed job callback exposed an output record");
    call.event.result = 0;
    call.event.arguments[3] = 5;
    call.event.arguments[4] = reinterpret_cast<uintptr_t>(boundary);
    Require(call.CapturePayload(false, PrinterPayload::JobAttributes).empty(),
        "Unknown job level touched an invalid pointer");
}

void PrinterNotifications()
{
    constexpr uint32_t arrayOffset = sizeof(uintptr_t) == 8 ? 16 : 12;
    constexpr uint32_t stride = sizeof(uintptr_t) == 8 ? 32 : 20;
    static_assert(offsetof(PRINTER_NOTIFY_INFO, aData) == arrayOffset);
    static_assert(sizeof(PRINTER_NOTIFY_INFO_DATA) == stride);
    static_assert(offsetof(PRINTER_NOTIFY_INFO_DATA, NotifyData) == (sizeof(uintptr_t) == 8 ? 16 : 12));
    PRINTER_NOTIFY_INFO_DATA layout{};
    Require(reinterpret_cast<std::byte*>(&layout.NotifyData.Data.pBuf) - reinterpret_cast<std::byte*>(&layout) ==
        (sizeof(uintptr_t) == 8 ? 24 : 16), "Printer notification pointer layout differs from the SDK");
    PrintCapture call;
    const wchar_t name[] = L"Printer";
    SYSTEMTIME submitted{};
    std::array<std::byte, arrayOffset + 3 * stride> notification{};
    const uint32_t count = 3;
    memcpy(notification.data() + 8, &count, sizeof(count));
    PRINTER_NOTIFY_INFO_DATA entry{};
    entry.Type = PRINTER_NOTIFY_TYPE;
    entry.Field = PRINTER_NOTIFY_FIELD_PRINTER_NAME;
    entry.NotifyData.Data.cbBuf = sizeof(name);
    entry.NotifyData.Data.pBuf = const_cast<wchar_t*>(name);
    memcpy(notification.data() + arrayOffset, &entry, sizeof(entry));
    entry = {};
    entry.Type = JOB_NOTIFY_TYPE;
    entry.Field = JOB_NOTIFY_FIELD_SUBMITTED;
    entry.NotifyData.Data.cbBuf = sizeof(submitted);
    entry.NotifyData.Data.pBuf = &submitted;
    memcpy(notification.data() + arrayOffset + stride, &entry, sizeof(entry));
    entry = {};
    entry.Type = PRINTER_NOTIFY_TYPE;
    entry.Field = PRINTER_NOTIFY_FIELD_ATTRIBUTES;
    entry.NotifyData.Data.cbBuf = UINT32_MAX;
    entry.NotifyData.Data.pBuf = reinterpret_cast<void*>(9);
    memcpy(notification.data() + arrayOffset + 2 * stride, &entry, sizeof(entry));
    call.event.arguments[3] = reinterpret_cast<uintptr_t>(notification.data());

    // Scalar union fields never establish pointers, even when their bytes resemble one.
    auto values = call.CapturePayload(false, PrinterPayload::Notification);
    Require(values.size() == 3 && values[0].bytes.size() == notification.size() &&
        values[1].bytes.size() == sizeof(name) && values[2].bytes.size() == sizeof(submitted) &&
        (values[1].value.flags & (MemberData | ReferencedData)) == (MemberData | ReferencedData),
        "Notification entries or their bounded references were not retained");
    Require(call.CapturePayload(true, PrinterPayload::Notification).empty(),
        "Input-only notification was sampled on return");
    call.header->bufferLimit = arrayOffset + stride - 1;
    values = call.CapturePayload(false, PrinterPayload::Notification);
    Require(values.size() == 1 && (values[0].value.flags & Truncated),
        "An incomplete notification entry established a referenced buffer");
    call.header->bufferLimit = arrayOffset + stride;
    values = call.CapturePayload(false, PrinterPayload::Notification);
    Require(values.size() == 2 && values[1].bytes.size() == sizeof(name),
        "The first complete notification entry was not retained");
    call.header->bufferLimit = 512;
    entry.Type = 999;
    entry.Field = 1;
    memcpy(notification.data() + arrayOffset, &entry, sizeof(entry));
    entry.Field = 0xffff;
    memcpy(notification.data() + arrayOffset + stride, &entry, sizeof(entry));
    Require(call.CapturePayload(false, PrinterPayload::Notification).size() == 1,
        "Unknown notification fields established referenced buffers");

    // A guarded notification or referenced buffer is never read or consumed by capture.
    auto pages = Detourist::Tests::GuardedPages(call.header->pageBytes, PAGE_READWRITE | PAGE_GUARD);
    auto boundary = pages.get() + call.header->pageBytes;
    entry = {};
    entry.Type = PRINTER_NOTIFY_TYPE;
    entry.Field = PRINTER_NOTIFY_FIELD_PRINTER_NAME;
    entry.NotifyData.Data.cbBuf = 2;
    entry.NotifyData.Data.pBuf = boundary;
    memcpy(notification.data() + arrayOffset, &entry, sizeof(entry));
    values = call.CapturePayload(false, PrinterPayload::Notification);
    MEMORY_BASIC_INFORMATION region{};
    Require(values.size() == 2 && (values[1].value.flags & Unreadable) &&
        VirtualQuery(boundary, &region, sizeof(region)) == sizeof(region) && (region.Protect & PAGE_GUARD),
        "A guarded notification buffer was consumed");
    call.event.arguments[3] = reinterpret_cast<uintptr_t>(boundary - 8);
    values = call.CapturePayload(false, PrinterPayload::Notification);
    Require(values.size() == 1 && (values[0].value.flags & Unreadable) &&
        VirtualQuery(boundary, &region, sizeof(region)) == sizeof(region) && (region.Protect & PAGE_GUARD),
        "A guarded notification header was consumed");
    call.event.flags = Skipped;
    Require(call.CapturePayload(false, PrinterPayload::Notification).empty(),
        "A skipped notification touched caller memory");
}

int wmain()
{
    return RunChecks([]
    {
        InputEvents();
        OutputEvents();
        DeviceModeResults();
        DriverAndJobRecords();
        PrinterNotifications();
        std::puts("PASS: Printer selectors, bounded records, callback results and referenced buffers.");
    });
}

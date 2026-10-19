#include "CatalogCaptureValues.h"
#include "CaptureFixture.h"
#include "GuardedPages.h"
#include <array>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

using namespace Detourist;
using namespace Detourist::Tests;

struct Capture : CaptureFrame<>
{
    uint64_t captureLimits[MaximumArguments]{};
    uint32_t initializedOutputs = 0;

    Capture() : CaptureFrame(128) {}

    std::vector<Snapshot> Read(std::span<const ExportParameter> parameters, bool leaving = false,
        std::span<const ExportMember> members = {})
    {
        auto slot = ResetSlot();
        CaptureCatalogValues(*this, slot, leaving, parameters, members);
        return Snapshots();
    }
};

int main()
{
    return RunChecks([]
    {
        Capture capture;
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        auto pages = Detourist::Tests::GuardedPages(system.dwPageSize, PAGE_NOACCESS);
        auto boundary = pages.get() + system.dwPageSize;
        DWORD previous = 0;

        // Multi-string termination crosses embedded NULs and stops before the next inaccessible page.
        const wchar_t environment[]{L'A', L'=', L'1', 0, L'B', L'=', L'2', 0, 0};
        auto guarded = boundary - sizeof(environment);
        memcpy(guarded, environment, sizeof(environment));
        ExportParameter parameter{UINT32_MAX, -1, 0, 1, 9, ExportValueKind::Utf16MultiString};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(guarded);
        auto values = capture.Read(std::span{&parameter, 1});
        Require(values.size() == 1 && values[0].bytes.size() == sizeof(environment) &&
            !memcmp(values[0].bytes.data(), environment, sizeof(environment)) && !values[0].value.flags,
            "Multi-string capture lost an entry or touched the guard page");
        capture.header->bufferLimit = sizeof(environment) - sizeof(wchar_t);
        values = capture.Read(std::span{&parameter, 1});
        Require(values.size() == 1 && values[0].bytes.size() == capture.header->bufferLimit &&
            (values[0].value.flags & Truncated), "An incomplete multi-string was not marked truncated");
        capture.header->bufferLimit = 128;
        wchar_t* returnedEnvironment = const_cast<wchar_t*>(environment);
        parameter.flags = 42;
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(&returnedEnvironment);
        Require(capture.Read(std::span{&parameter, 1}).empty(), "Returned multi-string was read on entry");
        values = capture.Read(std::span{&parameter, 1}, true);
        Require(values.size() == 2 && values[1].bytes.size() == sizeof(environment) &&
            (values[1].value.flags & ReferencedData) &&
            !memcmp(values[1].bytes.data(), environment, sizeof(environment)),
            "Returned multi-string lost an entry or its final terminator");

        // Counted records can place their DWORD size after other header fields.
        struct Counted { uint32_t fields[3], size; uint8_t data[16]; } counted{{1, 2, 3}, sizeof(Counted), {}};
        parameter = {sizeof(uint32_t) * 4, -1, 0, 1, 1, ExportValueKind::CountedBytes};
        parameter.actualOffset = 12;
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(&counted);
        values = capture.Read(std::span{&parameter, 1});
        Require(values.size() == 1 && values[0].bytes.size() == sizeof(counted), "Counted offset was ignored");
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(boundary - 12);
        values = capture.Read(std::span{&parameter, 1});
        Require(values.empty(), "An unreadable size fabricated data");

        // A returned pointer array is followed only after its output count and array are initialized.
        wchar_t first[]{L"alpha"}, second[]{L"beta"};
        wchar_t* strings[]{first, second};
        wchar_t** returned = strings;
        DWORD count = 2;
        std::array<ExportParameter, 2> array{};
        array[0] = {0, 1, 4, sizeof(uintptr_t), 34, ExportValueKind::Utf16StringArray};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(&returned);
        capture.event.arguments[1] = reinterpret_cast<uintptr_t>(boundary);
        Require(capture.Read(array).empty(), "An output-only count was sampled before the call");
        capture.event.arguments[1] = reinterpret_cast<uintptr_t>(&count);
        values = capture.Read(array, true);
        Require(values.size() == 4 && values[0].bytes.size() == sizeof(uintptr_t) &&
            values[1].bytes.size() == sizeof(strings) && values[2].bytes.size() == sizeof(first) &&
            values[3].bytes.size() == sizeof(second) && (values[2].value.flags & StringArrayElement) &&
            !memcmp(values[2].bytes.data(), first, sizeof(first)) &&
            !memcmp(values[3].bytes.data(), second, sizeof(second)), "Returned strings were not resolved");
        capture.event.flags = Skipped;
        Require(capture.Read(array, true).empty(), "A skipped call exposed an uninitialized returned array");
        capture.event.flags = 0;
        capture.header->bufferLimit = sizeof(uintptr_t);
        capture.Read(array);
        values = capture.Read(array, true);
        Require(values.size() == 3 && values[1].bytes.size() == sizeof(uintptr_t) &&
            (values[1].value.flags & Truncated), "A partial pointer array established an uncaptured string");
        capture.header->bufferLimit = 128;
        Require(VirtualProtect(boundary, system.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &previous),
            "Guard returned text");
        strings[1] = reinterpret_cast<wchar_t*>(boundary);
        capture.Read(array);
        values = capture.Read(array, true);
        MEMORY_BASIC_INFORMATION region{};
        Require(values.size() == 4 && (values[3].value.flags & Unreadable) &&
            VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
            "An unreadable returned string consumed a guard page");
        Require(VirtualProtect(boundary, system.dwPageSize, PAGE_NOACCESS, &previous), "Protect returned text");

        // Direct pointer arrays and returned record arrays both resolve their complete string fields.
        strings[1] = second;
        array[0] = {0, 1, 0, sizeof(uintptr_t), 1, ExportValueKind::Utf16StringArray};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(strings);
        capture.event.arguments[1] = 2;
        values = capture.Read(array);
        Require(values.size() == 3 && values[0].bytes.size() == sizeof(strings) &&
            !memcmp(values[1].bytes.data(), first, sizeof(first)) &&
            !memcmp(values[2].bytes.data(), second, sizeof(second)), "Input string array was not resolved");

        // Caller-owned output arrays never exceed their entry capacity or use an unreadable completed count.
        std::array<ExportParameter, 3> enumerated{};
        enumerated[0] = {0, 1, 0, sizeof(uintptr_t), 2, ExportValueKind::Utf16StringArray, 3, 4};
        capture.event = {};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(strings);
        capture.event.arguments[1] = 2;
        capture.event.arguments[2] = reinterpret_cast<uintptr_t>(boundary);
        Require(capture.Read(enumerated).empty(), "An output string array was read on entry");
        Require(VirtualProtect(boundary, system.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &previous),
            "Guard the completed count");
        Require(capture.Read(enumerated, true).empty(), "An unreadable completed count exposed string elements");
        Require(VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
            "An unreadable completed count consumed a guard page");
        Require(VirtualProtect(boundary, system.dwPageSize, PAGE_NOACCESS, &previous), "Protect the completed count");
        count = 1;
        capture.event.arguments[2] = reinterpret_cast<uintptr_t>(&count);
        values = capture.Read(enumerated, true);
        Require(values.size() == 2 && values[0].bytes.size() == sizeof(uintptr_t) &&
            !memcmp(values[1].bytes.data(), first, sizeof(first)), "The completed string count was ignored");
        count = 3;
        values = capture.Read(enumerated, true);
        Require(values.size() == 3 && values[0].bytes.size() == sizeof(strings),
            "A completed string count exceeded the entry capacity");
        capture.event.flags = Failed;
        Require(capture.Read(enumerated, true).empty(), "A failed call exposed string elements");
        capture.event.flags = 0;
        enumerated[0] = {0, 1, 4, sizeof(uintptr_t), 2, ExportValueKind::Utf16StringArray};
        count = 2;
        capture.event.arguments[1] = reinterpret_cast<uintptr_t>(&count);
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(boundary);
        Require(capture.Read(enumerated).empty(), "An output pointer array was probed on entry");
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(strings);
        count = 3;
        values = capture.Read(enumerated, true);
        Require(values.size() == 3 && values[0].bytes.size() == sizeof(strings),
            "An in/out count expanded the caller-owned array");

        struct Message { DWORD severity, id; const wchar_t* text; } messages[]{{1, 2, first}, {3, 4, second}};
        Message* returnedMessages = messages;
        count = 2;
        array[0] = {0, 1, 4, sizeof(Message), 34, ExportValueKind::Utf16StringArray};
        array[0].actualOffset = offsetof(Message, text);
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(&returnedMessages);
        capture.event.arguments[1] = reinterpret_cast<uintptr_t>(&count);
        capture.Read(array);
        values = capture.Read(array, true);
        Require(values.size() == 4 && values[1].bytes.size() == sizeof(messages) &&
            !memcmp(values[2].bytes.data(), first, sizeof(first)) &&
            !memcmp(values[3].bytes.data(), second, sizeof(second)), "Returned message text was not resolved");
        struct Qualifier { const wchar_t* name; const wchar_t* value; } qualifier{first, second};
        Qualifier* returnedQualifier = &qualifier;
        count = 1;
        array[0] = {0, 1, 4, sizeof(Qualifier), 34, ExportValueKind::Utf16StringPairs};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(&returnedQualifier);
        Require(capture.Read(array).empty(), "An output qualifier was read before the call");
        values = capture.Read(array, true);
        Require(values.size() == 4 && values[1].bytes.size() == sizeof(qualifier) &&
            !memcmp(values[2].bytes.data(), first, sizeof(first)) &&
            !memcmp(values[3].bytes.data(), second, sizeof(second)), "Returned qualifier fields were not resolved");

        parameter = {UINT32_MAX, -1, 0, 1, 43, ExportValueKind::Utf16};
        wchar_t* inoutText = first;
        capture.event = {};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(&inoutText);
        values = capture.Read(std::span{&parameter, 1});
        Require(values.size() == 2 && values[1].bytes.size() == sizeof(first) &&
            (values[1].value.flags & ReferencedData), "In/out text lost its entry value");
        capture.event.flags = Failed;
        Require(capture.Read(std::span{&parameter, 1}, true).empty(), "A failed call exposed returned text");

        // A BOOL API exposes its required SIZE_T on insufficient-buffer failure only.
        SIZE_T required = 1234;
        parameter = {sizeof(SIZE_T), -1, 0, 1, 2, ExportValueKind::RequiredSizeLastError};
        capture.event = {};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(&required);
        capture.Read(std::span{&parameter, 1});
        capture.event.flags = Failed;
        capture.event.error = ERROR_INSUFFICIENT_BUFFER;
        values = capture.Read(std::span{&parameter, 1}, true);
        Require(values.size() == 1 && values[0].bytes.size() == sizeof(required) &&
            !memcmp(values[0].bytes.data(), &required, sizeof(required)), "The required size was lost");
        capture.event.error = ERROR_ACCESS_DENIED;
        Require(capture.Read(std::span{&parameter, 1}, true).empty(), "An unrelated failure exposed output");

        // Products use an initialized indirect count and never exceed entry capacity on output.
        float audio[9]{};
        DWORD channels = 2;
        std::array<ExportParameter, 3> product{};
        product[0] = {0, 2, 4, sizeof(float), 2, ExportValueKind::Bytes};
        product[0].productIndex = 2;
        capture.event = {};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(audio);
        capture.event.arguments[1] = 3;
        capture.event.arguments[2] = reinterpret_cast<uintptr_t>(&channels);
        Require(capture.Read(product).empty(), "Output audio was read before the call");
        channels = 3;
        values = capture.Read(product, true);
        Require(values.size() == 1 && values[0].bytes.size() == 6 * sizeof(float),
            "An output product exceeded its entry capacity");

        // Returned record pointers authorize nested data only when the parent fields were captured completely.
        struct Record { DWORD size; const uint8_t* data; } record{4, reinterpret_cast<const uint8_t*>(first)};
        Record* result = &record;
        parameter = {sizeof(record), -1, 0, 1, 2 | ExportReturnedBuffer, ExportValueKind::IndirectBytes};
        ExportMember indirect{0, offsetof(Record, data), offsetof(Record, size), 1, 4,
            2 | ExportReturnedBuffer | ExportIndirectRecord};
        capture.event = {};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(&result);
        Require(capture.Read(std::span{&parameter, 1}, false, std::span{&indirect, 1}).empty(),
            "An output-only record pointer was followed before the call");
        values = capture.Read(std::span{&parameter, 1}, true, std::span{&indirect, 1});
        Require(values.size() == 3 && values[1].bytes.size() == sizeof(record) && values[2].bytes.size() == 4 &&
            (values[2].value.flags & MemberData), "A returned record lost its referenced buffer");
        parameter.flags = 3;
        indirect.flags = 3 | ExportReturnedBuffer | ExportIndirectRecord;
        capture.Read(std::span{&parameter, 1}, false, std::span{&indirect, 1});
        capture.event.flags = Failed;
        values = capture.Read(std::span{&parameter, 1}, true, std::span{&indirect, 1});
        Require(std::none_of(values.begin(), values.end(), [](const auto& sample)
            { return (sample.value.flags & MemberData) != 0; }),
            "A failed in/out record established returned nested data");
        parameter.flags = 2 | ExportReturnedBuffer;
        indirect.flags = 2 | ExportReturnedBuffer | ExportIndirectRecord;
        capture.event.flags = 0;
        capture.header->bufferLimit = sizeof(uintptr_t);
        capture.Read(std::span{&parameter, 1}, false, std::span{&indirect, 1});
        values = capture.Read(std::span{&parameter, 1}, true, std::span{&indirect, 1});
        Require(values.size() == 2 && (values[1].value.flags & Truncated),
            "An incomplete returned record established a nested buffer");
        capture.header->bufferLimit = 128;

        // A returned resource payload is valid only for its output type.
        DWORD selector = 3;
        std::array<ExportParameter, 2> selected{};
        selected[0] = {sizeof(record), -1, 0, 1, 2, ExportValueKind::Bytes};
        ExportMember selectedMember{0, offsetof(Record, data), offsetof(Record, size), 1, 4,
            2 | ExportReturnedBuffer | ExportIndirectSelector, 0, 0, 2, 0, 3};
        capture.event = {};
        capture.event.arguments[0] = reinterpret_cast<uintptr_t>(&record);
        capture.event.arguments[1] = reinterpret_cast<uintptr_t>(&selector);
        Require(capture.Read(selected, false, std::span{&selectedMember, 1}).empty(),
            "An uninitialized output selector was read");
        values = capture.Read(selected, true, std::span{&selectedMember, 1});
        Require(values.size() == 2 && values[1].bytes.size() == 4 && (values[1].value.flags & MemberData),
            "A matching resource type lost its payload");
        selector = 1;
        values = capture.Read(selected, true, std::span{&selectedMember, 1});
        Require(values.size() == 1, "A string resource was interpreted as embedded data");
        capture.event.arguments[1] = reinterpret_cast<uintptr_t>(boundary);
        values = capture.Read(selected, true, std::span{&selectedMember, 1});
        Require(values.size() == 1, "An unreadable selector established a payload");
        selector = 3;
        capture.event.arguments[1] = reinterpret_cast<uintptr_t>(&selector);
        capture.header->bufferLimit = sizeof(DWORD);
        capture.Read(selected, false, std::span{&selectedMember, 1});
        values = capture.Read(selected, true, std::span{&selectedMember, 1});
        Require(values.size() == 1 && (values[0].value.flags & Truncated),
            "An incomplete direct record established a nested payload");
        capture.header->bufferLimit = 128;

        // Routing structures use the family declared by the same call, not inferred handle state.
        BYTE route[92]{};
        std::array<ExportParameter, 3> routing{};
        routing[2] = {3, 0, 0, 1, 2, ExportValueKind::RtmBuffer};
        capture.event = {};
        capture.event.arguments[0] = 1;
        capture.event.arguments[2] = reinterpret_cast<uintptr_t>(route);
        Require(capture.Read(routing).empty(), "A route output was read before its call");
        capture.event.result = TRUE;
        values = capture.Read(routing, true);
        Require(values.size() == 1 && values[0].bytes.size() == sizeof(route), "Route dispatch lost its family size");
        capture.event.result = FALSE;
        Require(capture.Read(routing, true).empty(), "A missing route exposed an output buffer");

        // Handle-derived route input emits only the documented family-independent fields.
        std::array<ExportParameter, 2> commonRoute{};
        commonRoute[1] = {4, -1, 0, 1, 1, ExportValueKind::RtmBuffer};
        capture.event = {};
        capture.event.arguments[0] = 0x12345678;
        capture.event.arguments[1] = reinterpret_cast<uintptr_t>(route);
        values = capture.Read(commonRoute);
        Require(values.size() == 3 && values[0].value.parameter == ((12 + 1) << 8 | 1) &&
            (values[0].value.flags & MemberData), "Common route fields were not dispatched");

        // Printer job attributes use the caller's level at both entry and successful return.
        std::array<ExportParameter, 5> printer{};
        printer[4] = {1, 3, 0, 1, 3, ExportValueKind::PrinterPayload};
        std::array<std::byte, 56> job{};
        capture.event = {};
        capture.event.arguments[3] = 4;
        capture.event.arguments[4] = reinterpret_cast<uintptr_t>(job.data());
        values = capture.Read(printer);
        Require(values.size() == 1 && values[0].bytes.size() == job.size(), "Printer dispatch lost job attributes");
        values = capture.Read(printer, true);
        Require(values.size() == 1 && values[0].bytes.size() == job.size(), "Printer dispatch lost returned changes");
        capture.event.arguments[3] = 5;
        capture.event.arguments[4] = reinterpret_cast<uintptr_t>(boundary);
        Require(capture.Read(printer).empty(), "Unknown printer level touched caller memory");

#ifndef _WIN64
        // An eight-byte by-value record retains its nested buffer even though its fields are inline.
        struct Inline { uint32_t size; const uint8_t* data; } value{4, reinterpret_cast<const uint8_t*>(first)};
        static_assert(sizeof(value) == sizeof(uint64_t));
        capture.event = {};
        memcpy(&capture.event.arguments[0], &value, sizeof(value));
        parameter = {0, -1, 0, 1, 0, ExportValueKind::Bytes};
        ExportMember member{0, offsetof(Inline, data), offsetof(Inline, size), 1, 4,
            1 | ExportInlineRecord};
        values = capture.Read(std::span{&parameter, 1}, false, std::span{&member, 1});
        Require(values.size() == 1 && values[0].bytes.size() == 4 && (values[0].value.flags & MemberData),
            "An inline record lost its referenced buffer");
#endif
        std::cout << "PASS: bounded counted, product, string-array, multi-string and inline buffers.\n";
    });
}

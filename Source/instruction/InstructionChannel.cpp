#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#include "dr_api.h"
#pragma warning(pop)
#include "InstructionCapture.h"
#include "TransportPool.h"
#include <intrin.h>

namespace Detourist
{
int64_t Clock()
{
    LARGE_INTEGER value{};
    RtlQueryPerformanceCounter(&value);
    return value.QuadPart;
}

bool InstructionChannel::Open(uint64_t mapping, uint64_t captureIdentity)
{
    if (!captureIdentity || !mapping || mapping > UINTPTR_MAX) return false;
    auto duplicate = [](uint64_t source, HANDLE& destination)
    {
        return source && source <= UINTPTR_MAX && NtDuplicateObject(NtCurrentProcess(),
            reinterpret_cast<HANDLE>(static_cast<uintptr_t>(source)), NtCurrentProcess(), &destination,
            0, 0, DUPLICATE_SAME_ACCESS) >= 0;
    };
    SIZE_T bytes = 0;
    if (!duplicate(mapping, section) ||
        NtMapViewOfSection(section, NtCurrentProcess(), reinterpret_cast<void**>(&header), 0, 0,
            nullptr, &bytes, ViewShare, 0, PAGE_READWRITE) < 0) return false;
    if (!ValidPoolHeader(header, bytes, dr_get_process_id(), captureIdentity)) return false;
    // Each observer owns duplicates of the resident agent's already granted handles.
    auto handles = header->targetHandles;
    if (handles.mapping != mapping || !duplicate(handles.controller, controller) ||
        !duplicate(handles.data, data) || !duplicate(handles.space, space) ||
        !duplicate(handles.resume, resume) || !duplicate(handles.breakpoint, breakpoint)) return false;

    // Metadata is supplied by the controller as a read-only section, independent of the target's loader.
    bytes = 0;
    if (!duplicate(handles.catalog, catalogSection) ||
        NtMapViewOfSection(catalogSection, NtCurrentProcess(), &catalogMemory, 0, 0,
            nullptr, &bytes, ViewUnmap, 0, PAGE_READONLY) < 0 || !catalog.Open(catalogMemory, bytes) ||
        !BindApiDefinitions(catalog)) return false;
    return true;
}

void InstructionChannel::Close()
{
    if (header) NtUnmapViewOfSection(NtCurrentProcess(), header);
    if (catalogMemory) NtUnmapViewOfSection(NtCurrentProcess(), catalogMemory);
    for (const auto handle : {section, data, space, controller, resume, breakpoint, catalogSection})
        if (handle) NtClose(handle);
    header = nullptr;
    section = data = space = controller = nullptr;
    resume = breakpoint = nullptr;
    catalogMemory = nullptr;
    catalogSection = nullptr;
}

bool InstructionChannel::CollectorAlive() const
{
    LARGE_INTEGER timeout{};
    return controller && NtWaitForSingleObject(controller, FALSE, &timeout) == STATUS_TIMEOUT;
}

Slot* InstructionChannel::Acquire()
{
    return AcquireSlot(header, [&]
    {
        if (!CollectorAlive()) return false;
        LARGE_INTEGER timeout{};
        timeout.QuadPart = NtRelativeMilliseconds(10);
        NtWaitForSingleObject(space, FALSE, &timeout);
        return true;
    });
}

void InstructionChannel::Publish(Slot* slot)
{
    if (PublishSlot(header, slot)) NtSetEvent(data, nullptr);
}
}

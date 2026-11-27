#include "Agent.h"
#include "ProfilerBridge.h"
#include "TransportPool.h"
#include <algorithm>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <utility>
#include <atomic>

namespace Detourist
{
struct ManagedDefinition
{
    DynamicApiMetadata metadata{};
    std::string extendedLayout;
    uint64_t categoryMask = 0;
    uint64_t nameHash = 0;
    std::atomic<uint64_t> publishedSession = 0;
    uint64_t countedSession = 0;
};

constexpr size_t ManagedDefinitionCapacity = 65536;
constexpr size_t BoundObserverSlotCapacity = 4096;
constexpr size_t DetachedThreadTableCapacity = 4096;
constexpr DWORD DetachedThreadTombstone = 1;
constexpr unsigned ManagedPageShift = 12;
constexpr size_t ManagedCodePageCount = size_t{1} << (32 - ManagedPageShift);

SRWLOCK ManagedDefinitionsLock = SRWLOCK_INIT;
std::array<std::atomic<ManagedDefinition*>, ManagedDefinitionCapacity> ManagedDefinitions{};
std::array<std::atomic<uint64_t>, BoundObserverSlotCapacity> BoundObserverGenerations{};
std::array<std::atomic<DWORD>, DetachedThreadTableCapacity> DetachedObserverThreads{};
std::atomic<uint64_t> NextBoundObserverGeneration = 1;
[[msvc::no_tls_guard]] constinit thread_local uint32_t BoundObserverSlot = 0;
[[msvc::no_tls_guard]] constinit thread_local uint64_t BoundObserverGeneration = 0;
uint32_t ManagedDefinitionCount = 0;
volatile LONG ManagedProfilerState = static_cast<LONG>(ManagedState::Inactive);
void WINAPI ManagedStatus(uint32_t state);

bool IsObserverThreadDetached() noexcept
{
    const auto tid = CurrentObserverThreadId();
    if (tid <= DetachedThreadTombstone) return false;
    const auto start = static_cast<size_t>(tid * 2654435761u) & (DetachedThreadTableCapacity - 1);
    for (size_t step = 0; step < DetachedThreadTableCapacity; ++step)
    {
        const auto value = DetachedObserverThreads[(start + step) & (DetachedThreadTableCapacity - 1)]
            .load(std::memory_order_acquire);
        if (!value) return false;
        if (value == tid) return true;
    }
    return false;
}

void AttachObserverThread() noexcept
{
    const auto tid = CurrentObserverThreadId();
    if (tid <= DetachedThreadTombstone) return;
    const auto start = static_cast<size_t>(tid * 2654435761u) & (DetachedThreadTableCapacity - 1);
    for (size_t step = 0; step < DetachedThreadTableCapacity; ++step)
    {
        auto& slot = DetachedObserverThreads[(start + step) & (DetachedThreadTableCapacity - 1)];
        auto value = slot.load(std::memory_order_acquire);
        if (!value) return;
        if (value == tid) slot.compare_exchange_strong(value, DetachedThreadTombstone, std::memory_order_acq_rel);
    }
}

void DetachObserverThread() noexcept
{
    if (NativeThreadReady())
    {
        FlushPendingEntrySlot();
        if (BoundObserverSlot)
        {
            auto expected = BoundObserverGeneration;
            BoundObserverGenerations[BoundObserverSlot - 1].compare_exchange_strong(expected, 0,
                std::memory_order_acq_rel);
            BoundObserverSlot = 0;
            BoundObserverGeneration = 0;
        }
    }
    const auto tid = CurrentObserverThreadId();
    if (tid <= DetachedThreadTombstone) return;
    const auto start = static_cast<size_t>(tid * 2654435761u) & (DetachedThreadTableCapacity - 1);
    size_t tombstoneIndex = DetachedThreadTableCapacity;
    for (size_t step = 0; step < DetachedThreadTableCapacity; ++step)
    {
        const auto index = (start + step) & (DetachedThreadTableCapacity - 1);
        auto value = DetachedObserverThreads[index].load(std::memory_order_acquire);
        if (value == tid) return;
        if (value == DetachedThreadTombstone && tombstoneIndex == DetachedThreadTableCapacity) tombstoneIndex = index;
        if (!value)
        {
            const auto target = tombstoneIndex < DetachedThreadTableCapacity ? tombstoneIndex : index;
            DWORD expected = tombstoneIndex < DetachedThreadTableCapacity ? DetachedThreadTombstone : 0;
            if (DetachedObserverThreads[target].compare_exchange_strong(expected, tid, std::memory_order_acq_rel))
                return;
        }
    }
    if (tombstoneIndex < DetachedThreadTableCapacity)
        DetachedObserverThreads[tombstoneIndex].store(tid, std::memory_order_release);
}

#if defined(_M_IX86)
// Plain zero-initialized storage avoids expanding a million atomic constructors during compilation.
std::array<uint32_t, ManagedCodePageCount> ManagedCodePages{};
static_assert(std::atomic_ref<uint32_t>::required_alignment <= alignof(uint32_t));

bool __cdecl ManagedCodeAddress(const void* address)
{
    return std::atomic_ref(ManagedCodePages[reinterpret_cast<uintptr_t>(address) >> ManagedPageShift])
        .load(std::memory_order_acquire) != 0;
}
#endif

void WINAPI ManagedNativeCode(uintptr_t address, size_t bytes, BOOL added)
{
#if defined(_M_IX86)
    if (!bytes || bytes - 1 > UINTPTR_MAX - address) return;

    // CLR methods can share executable pages; retain each page until its final method unloads.
    const auto last = (address + bytes - 1) >> ManagedPageShift;
    for (auto page = address >> ManagedPageShift; page <= last; ++page)
    {
        if (added) std::atomic_ref(ManagedCodePages[page]).fetch_add(1, std::memory_order_release);
        else std::atomic_ref(ManagedCodePages[page]).fetch_sub(1, std::memory_order_release);
    }
#else
    (void)address;
    (void)bytes;
    (void)added;
#endif
}

BOOL WINAPI ManagedGuard(BOOL suppress)
{
    return std::exchange(ObserverActive, suppress != FALSE) ? TRUE : FALSE;
}

CaptureClock* WINAPI ManagedCaptureClock() { return &CaptureTime; }

uint32_t WINAPI RegisterManagedApi(const DynamicApiMetadata* metadata, const char* layout, uint32_t layoutBytes)
{
    if (!metadata || metadata->argumentCount > MaximumArguments || (layoutBytes && !layout)) return 0;
    auto savedError = GetLastError();
    auto previous = ManagedGuard(TRUE);
    uint32_t id = 0;
    std::unique_ptr<ManagedDefinition> definition;
    try
    {
        definition = std::make_unique<ManagedDefinition>();
        definition->metadata = *metadata;
        definition->metadata.module[std::size(definition->metadata.module) - 1] = 0;
        definition->metadata.name[std::size(definition->metadata.name) - 1] = 0;
        definition->metadata.parameters[std::size(definition->metadata.parameters) - 1] = 0;
        definition->metadata.layout[std::size(definition->metadata.layout) - 1] = 0;
        if (layoutBytes)
        {
            if (layoutBytes < sizeof(definition->metadata.layout))
            {
                memcpy(definition->metadata.layout, layout, layoutBytes);
                definition->metadata.layout[layoutBytes] = 0;
            }
            else
            {
                definition->metadata.layout[0] = 0;
                definition->extendedLayout.assign(layout, layoutBytes);
            }
        }
        definition->metadata.category = ClassifyApi(definition->metadata.module, definition->metadata.name);
        definition->categoryMask = CategoryMask(definition->metadata.category);
        definition->nameHash = ApiNameHash(definition->metadata.name);
        AcquireSRWLockExclusive(&ManagedDefinitionsLock);
        if (ManagedDefinitionCount < ManagedDefinitions.size())
        {
            auto index = ManagedDefinitionCount++;
            id = ManagedApiStart + index;
            ManagedDefinitions[index].store(definition.release(), std::memory_order_release);
        }
        else InterlockedExchange(&ManagedProfilerState, static_cast<LONG>(ManagedState::Failed));
        ReleaseSRWLockExclusive(&ManagedDefinitionsLock);
    }
    catch (...)
    {
        id = 0;
        InterlockedExchange(&ManagedProfilerState, static_cast<LONG>(ManagedState::Failed));
    }
    if (!id) ManagedStatus(static_cast<uint32_t>(ManagedState::Failed));
    ManagedGuard(previous);
    SetLastError(savedError);
    return id;
}

BOOL WINAPI UpdateManagedApiLayout(uint32_t api, const char* layout, uint32_t bytes)
{
    const auto index = api - ManagedApiStart;
    if (!layout || !bytes || index >= ManagedDefinitions.size()) return FALSE;
    auto definition = ManagedDefinitions[index].load(std::memory_order_acquire);
    if (!definition) return FALSE;
    auto savedError = GetLastError();
    auto previous = ManagedGuard(TRUE);

    // Prepare larger descriptors before locking, then publish one immutable layout for each API definition.
    BOOL updated = TRUE;
    try
    {
        std::string extended;
        if (bytes >= sizeof(definition->metadata.layout)) extended.assign(layout, bytes);
        AcquireSRWLockExclusive(&ManagedDefinitionsLock);
        if (!definition->metadata.layout[0] && definition->extendedLayout.empty())
        {
            if (extended.empty())
            {
                memcpy(definition->metadata.layout, layout, bytes);
                definition->metadata.layout[bytes] = 0;
            }
            else definition->extendedLayout.swap(extended);
            definition->publishedSession.store(0, std::memory_order_release);
        }
        ReleaseSRWLockExclusive(&ManagedDefinitionsLock);
    }
    catch (...) { updated = FALSE; ManagedStatus(static_cast<uint32_t>(ManagedState::Failed)); }
    ManagedGuard(previous);
    SetLastError(savedError);
    return updated;
}

uint64_t ManagedApiCategoryMask(Api api)
{
    const auto index = static_cast<uint32_t>(api) - ManagedApiStart;
    auto definition = index < ManagedDefinitions.size() ?
        ManagedDefinitions[index].load(std::memory_order_acquire) : nullptr;
    return definition ? definition->categoryMask : CategoryMask(ApiCategory::Unclassified);
}

void RefreshManagedApiCategories()
{
    // Reattached captures apply their current policy to methods already instrumented by the profiler.
    AcquireSRWLockExclusive(&ManagedDefinitionsLock);
    for (uint32_t index = 0; index < ManagedDefinitionCount; ++index)
    {
        auto definition = ManagedDefinitions[index].load(std::memory_order_acquire);
        definition->metadata.category = ClassifyApi(definition->metadata.module, definition->metadata.name);
        definition->categoryMask = CategoryMask(definition->metadata.category);
    }
    ReleaseSRWLockExclusive(&ManagedDefinitionsLock);
}

uint64_t ManagedApiNameHash(Api api)
{
    const auto index = static_cast<uint32_t>(api) - ManagedApiStart;
    auto definition = index < ManagedDefinitions.size() ?
        ManagedDefinitions[index].load(std::memory_order_acquire) : nullptr;
    return definition ? definition->nameHash : 0;
}

bool PublishManagedApiMetadata(Api api, Transport* transport)
{
    const auto index = static_cast<uint32_t>(api) - ManagedApiStart;
    auto definition = index < ManagedDefinitions.size() ?
        ManagedDefinitions[index].load(std::memory_order_acquire) : nullptr;
    if (!definition) return false;
    auto header = transport->Header();
    if (definition->publishedSession.load(std::memory_order_acquire) == header->captureIdentity) return true;
    bool published = false;
    AcquireSRWLockExclusive(&ManagedDefinitionsLock);
    if (header->payloadCapacity >= sizeof(DynamicApiMetadata))
    {
        if (definition->publishedSession.load(std::memory_order_relaxed) == header->captureIdentity) published = true;
        else if (auto slot = transport->Acquire())
        {
            // Metadata precedes the first call in each capture, including a reattached session.
            slot->event = {};
            slot->event.kind = EventKind::ApiMetadata;
            slot->event.api = api;
            slot->event.timestamp = Clock();
            slot->event.processId = GetCurrentProcessId();
            slot->event.threadId = GetCurrentThreadId();
            slot->event.payloadBytes = sizeof(DynamicApiMetadata);
            memcpy(Transport::Payload(slot), &definition->metadata, sizeof(DynamicApiMetadata));
            transport->Publish(slot);

            // Layout fragments remain ordered under the definition lock and precede the first recorded call.
            published = true;
            const auto& layout = definition->extendedLayout;
            for (uint32_t offset = 0; offset < layout.size();)
            {
                auto part = transport->Acquire();
                if (!part) { published = false; break; }
                auto desired = static_cast<uint32_t>(std::min<size_t>(layout.size() - offset,
                    header->payloadCapacity - sizeof(ApiLayoutFragment)));
                auto available = EnsureSlotPayload(part, header,
                    static_cast<uint32_t>(sizeof(ApiLayoutFragment)) + desired);
                auto bytes = std::min(desired, available - static_cast<uint32_t>(sizeof(ApiLayoutFragment)));
                ApiLayoutFragment fragment{offset, static_cast<uint32_t>(layout.size())};
                part->event = {};
                part->event.kind = EventKind::ApiLayout;
                part->event.api = api;
                part->event.timestamp = Clock();
                part->event.processId = GetCurrentProcessId();
                part->event.threadId = GetCurrentThreadId();
                part->event.payloadBytes = static_cast<uint32_t>(sizeof(fragment)) + bytes;
                memcpy(Transport::Payload(part), &fragment, sizeof(fragment));
                memcpy(Transport::Payload(part) + sizeof(fragment), layout.data() + offset, bytes);
                transport->Publish(part);
                offset += bytes;
            }
            if (published)
            {
                definition->publishedSession.store(header->captureIdentity, std::memory_order_release);
                if (definition->countedSession != header->captureIdentity)
                {
                    definition->countedSession = header->captureIdentity;
                    ++header->managedApiCount;
                }
            }
        }
    }
    header->managedState = InterlockedCompareExchange(&ManagedProfilerState, 0, 0);
    ReleaseSRWLockExclusive(&ManagedDefinitionsLock);
    return published;
}

uint32_t WINAPI ManagedBufferLimit(uint32_t api)
{
    uint32_t result = 0;
    AcquireSRWLockShared(&CaptureLock);
    if (auto transport = ActiveTransport)
    {
        auto header = transport->Header();
        if (!header->stop && !header->capturePaused && FilterEnabled(header->enabledFilters,
            ManagedApis, ManagedApiCategoryMask(static_cast<Api>(api))))
            result = header->bufferLimit;
    }
    ReleaseSRWLockShared(&CaptureLock);
    return result;
}

BOOL WINAPI ManagedBegin(ManagedCallState* state, uint32_t api, const uint64_t* arguments, uint32_t argumentCount,
    const std::byte* payload, uint32_t payloadBytes)
{
    static_assert(sizeof(Call) <= sizeof(ManagedCallState));
    static_assert(alignof(Call) <= alignof(ManagedCallState));
    if (!state || api < ManagedApiStart || argumentCount > MaximumArguments) return FALSE;
    auto savedError = GetLastError();
    auto previous = ManagedGuard(FALSE);
    auto call = new (state->storage) Call(static_cast<Api>(api), std::span(arguments, argumentCount), nullptr,
        std::span(payload, payloadBytes));
    call->BeginInvocation();
    ManagedGuard(previous);
    SetLastError(savedError);
    return TRUE;
}

void WINAPI ManagedEnd(ManagedCallState* state, uint64_t result, uint32_t flags,
    const std::byte* payload, uint32_t payloadBytes)
{
    auto savedError = GetLastError();
    auto previous = ManagedGuard(TRUE);
    auto call = std::launder(reinterpret_cast<Call*>(state->storage));
    call->EndInvocation();
    call->event.flags |= flags;
    call->Finish(result, 0, std::span(payload, payloadBytes));
    call->~Call();
    ManagedGuard(previous);
    SetLastError(savedError);
}

void WINAPI ManagedStatus(uint32_t state)
{
    InterlockedExchange(&ManagedProfilerState, static_cast<LONG>(state));
    AcquireSRWLockShared(&CaptureLock);
    if (auto transport = ActiveTransport) transport->Header()->managedState = static_cast<LONG>(state);
    ReleaseSRWLockShared(&CaptureLock);
}
}

extern "C" __declspec(dllexport) BOOL WINAPI DetouristGetProfilerBridge(uint32_t version,
    Detourist::ProfilerBridge* bridge)
{
    if (version != Detourist::ProfilerBridgeVersion || !bridge) return FALSE;
    *bridge = {Detourist::ProfilerBridgeVersion, sizeof(Detourist::ProfilerBridge), &Detourist::ManagedGuard,
        &Detourist::RegisterManagedApi, &Detourist::ManagedBufferLimit, &Detourist::ManagedBegin,
        &Detourist::ManagedEnd, &Detourist::ManagedStatus, &Detourist::UpdateManagedApiLayout,
        &Detourist::ObserveNativeDelegate, &Detourist::ManagedNativeCode, &Detourist::ManagedCaptureClock};
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL WINAPI DetouristGetObserverContext(Detourist::ObserverContext* context)
{
    using namespace Detourist;
    if (!context || !NativeThreadReady()) return FALSE;
    *context = {CallIdentity, ParentCall, CallDepth,
        ObserverNativeReady | (ObserverActive ? ObserverRecording : 0u) |
        (FollowingChild ? ObserverFollowingChild : 0u), static_cast<uint32_t>(CallApi), &CaptureTime};
    return TRUE;
}

extern "C" __declspec(dllexport) void WINAPI DetouristSetObserverContext(const Detourist::ObserverContext* context)
{
    using namespace Detourist;
    if (!context || !NativeThreadReady()) return;
    // Observer ancestry can outlive a detached session while an application call remains blocked.
    CallIdentity = context->captureIdentity;
    ParentCall = context->parentId;
    CallDepth = context->depth;
    CallApi = static_cast<Api>(context->api);
}

extern "C" __declspec(dllexport) BOOL WINAPI DetouristBindObserverThread(Detourist::ObserverThreadPointers* pointers)
{
    using namespace Detourist;
    static_assert(sizeof(Api) == sizeof(uint32_t));
    if (!pointers || !NativeThreadReady()) return FALSE;

    // Guard bound TLS pointers with a pinned slot generation cleared before loader thread-detach frees TLS memory.
    if (BoundObserverSlot &&
        BoundObserverGenerations[BoundObserverSlot - 1].load(std::memory_order_acquire) != BoundObserverGeneration)
    {
        BoundObserverSlot = 0;
        BoundObserverGeneration = 0;
    }
    if (!BoundObserverSlot)
    {
        const auto generation = NextBoundObserverGeneration.fetch_add(1, std::memory_order_relaxed);
        const auto start = static_cast<size_t>(GetCurrentThreadId()) % BoundObserverSlotCapacity;
        for (size_t step = 0; step < BoundObserverSlotCapacity; ++step)
        {
            const auto index = (start + step) % BoundObserverSlotCapacity;
            uint64_t expected = 0;
            if (BoundObserverGenerations[index].compare_exchange_strong(expected, generation,
                std::memory_order_acq_rel))
            {
                BoundObserverSlot = static_cast<uint32_t>(index + 1);
                BoundObserverGeneration = generation;
                break;
            }
        }
        if (!BoundObserverSlot) return FALSE;
    }
    *pointers = {&BoundObserverGenerations[BoundObserverSlot - 1], BoundObserverGeneration,
        &CallIdentity, &ParentCall, &CallDepth, reinterpret_cast<uint32_t*>(&CallApi),
        &ObserverActive, &FollowingChild, &CaptureTime, &ProcessShuttingDown,
        &PendingEntrySlot, reinterpret_cast<void**>(&PendingEntryTransport)};
    return TRUE;
}


#include "Transport.h"
#include "TransportPool.h"
#include "CatalogView.h"
#include <tlhelp32.h>
#include <algorithm>
#include <cstring>
#include <memory>

namespace Detourist
{
constexpr uint64_t ThreadIdTimeoutMs = 5000;
constexpr DWORD ThreadIdPollMs = 1;
constexpr DWORD AcquireSpaceTimeoutMs = 10;
constexpr uint32_t ReadBatchMaximum = 32;

Transport::Transport(TransportStartup& startup) noexcept
    : mapping_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.mapping))),
      data_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.data))),
      space_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.space))),
      ready_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.ready))),
      resume_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.resume))),
      break_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.breakpoint))),
      controller_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.controller))),
      catalogMapping_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.catalog))),
      startupThread_(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.startupThread)))
{
    // Acknowledge only after every supplied handle has an owner, including failed or busy starts.
    InterlockedExchange(&startup.owned, 1);
}

Transport::~Transport()
{
    if (bootstrapRelease_) SetEvent(bootstrapRelease_.get());
    if (header_) UnmapViewOfFile(header_);
    if (catalogView_) UnmapViewOfFile(catalogView_);
}

bool Transport::BindEvents(bool create)
{
    struct Signal { Handle& handle; const wchar_t* suffix; BOOL manualReset; };
    const Signal signals[] = {{data_, L".data", FALSE}, {space_, L".space", FALSE}, {ready_, L".ready", TRUE},
        {resume_, L".resume", TRUE}, {break_, L".break", FALSE}};
    for (const auto& signal : signals)
    {
        auto name = name_ + signal.suffix;
        signal.handle.reset(create ? CreateEventW(nullptr, signal.manualReset, FALSE, name.c_str()) :
            OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name.c_str()));
        if (!signal.handle) return false;
    }
    return true;
}

void Transport::Create(const std::wstring& name, uint32_t processId, uint32_t bufferLimit, uint32_t stackDepth,
    uint64_t captureMask, bool followChildren, const std::wstring& catalogName)
{
    name_ = name;
    // Allocate a fixed memory budget independent of trace length.
    bufferLimit = std::clamp(bufferLimit, MinimumBufferLimit, MaximumBufferLimit);
    uint32_t payload = (bufferLimit + sizeof(Value)) * 2 * MaximumArguments + MaximumStack * sizeof(uint64_t);
    uint32_t stride = Align64(static_cast<uint32_t>(sizeof(Slot)) + payload);
    uint32_t capacity = 2;
    while ((capacity * 2ull * stride + sizeof(SharedHeader)) <= TransportBudget) capacity *= 2;
    uint32_t bytes = static_cast<uint32_t>(sizeof(SharedHeader)) + capacity * stride;
    mapping_.reset(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, bytes, name.c_str()));
    Check(static_cast<bool>(mapping_), "Create capture buffer");
    if (GetLastError() == ERROR_ALREADY_EXISTS) throw std::runtime_error("Capture buffer already exists.");
    header_ = static_cast<SharedHeader*>(MapViewOfFile(mapping_.get(), FILE_MAP_ALL_ACCESS, 0, 0, bytes));
    Check(header_ != nullptr, "Map capture buffer");
    header_->magic = ProtocolMagic;
    header_->version = ProtocolVersion;
    header_->processId = processId;
    header_->controllerId = GetCurrentProcessId();
    if (catalogName.size() >= std::size(header_->catalogMapping))
        throw std::runtime_error("API catalog mapping name exceeds the protocol limit.");
    std::copy(catalogName.begin(), catalogName.end(), header_->catalogMapping);
    header_->capacity = capacity;
    header_->stride = stride;
    header_->payloadCapacity = payload;
    header_->bufferLimit = bufferLimit;
    header_->mappingBytes = bytes;
    header_->stackDepth = std::min(stackDepth, MaximumStack);
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    header_->pageBytes = system.dwPageSize;
    header_->followChildren = followChildren;
    header_->enabledFilters = static_cast<LONGLONG>(CaptureFilters(captureMask, AllCategories));
    header_->entryApi = -1;
    header_->exitApi = -1;
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    header_->frequency = frequency.QuadPart;
    header_->captureIdentity = static_cast<uint64_t>(Clock());
    header_->freeSlots = 1;
    header_->asyncFree = 1;
    for (uint32_t index = 0; index < AsyncIoCapacity; ++index)
        header_->asyncIo[index].next = index + 1 < AsyncIoCapacity ? index + 2 : 0;
    for (uint32_t index = 0; index < capacity; ++index)
    {
        auto slot = PoolSlot(header_, index);
        slot->index = index + 1;
        slot->next = index + 1 < capacity ? index + 2 : 0;
    }

    // Keep wakeups and debugger control independent of record storage.
    Check(BindEvents(true), "Create capture signals");
    bootstrapRelease_.reset(CreateEventW(nullptr, TRUE, FALSE, (name + L".bootstrap-release").c_str()));
    controller_.reset(OpenProcess(SYNCHRONIZE, FALSE, header_->controllerId));
    Check(controller_ && bootstrapRelease_, "Create capture signals");
    if (!catalogName.empty())
    {
        catalogMapping_.reset(OpenFileMappingW(FILE_MAP_READ, FALSE, catalogName.c_str()));
        Check(static_cast<bool>(catalogMapping_), "Open API catalog handle");
    }
}

bool Transport::Open(const std::wstring& name, uint32_t processId, bool bindCatalog)
{
    name_ = name;
    if (!processId) processId = GetCurrentProcessId();
    mapping_.reset(OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name.c_str()));
    if (!mapping_) return false;
    if (!Map(processId)) return false;

    // Named opens belong to unrestricted controller helpers; targets receive already granted handles.
    if (!BindEvents(false)) return false;
    controller_.reset(OpenProcess(SYNCHRONIZE, FALSE, header_->controllerId));
    if (!controller_) return false;
    if (header_->catalogMapping[0])
    {
        catalogMapping_.reset(OpenFileMappingW(FILE_MAP_READ, FALSE, header_->catalogMapping));
        if (!catalogMapping_) return false;
    }
    return MapCatalog(bindCatalog);
}

bool Transport::Map(uint32_t processId, uint64_t captureIdentity)
{
    header_ = static_cast<SharedHeader*>(MapViewOfFile(mapping_.get(), FILE_MAP_ALL_ACCESS, 0, 0, 0));
    // Validate the mapped extent before reading its header or accepting advertised slot boundaries.
    MEMORY_BASIC_INFORMATION mapped{};
    if (!header_ || !VirtualQuery(header_, &mapped, sizeof(mapped))) return false;
    if (!ValidPoolHeader(header_, mapped.RegionSize, processId, captureIdentity))
    {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    return true;
}

bool Transport::MapCatalog(bool bindCatalog)
{
    if (header_->catalogMapping[0])
    {
        if (!catalogMapping_) { SetLastError(ERROR_INVALID_HANDLE); return false; }
        // Bootstrap consumers pass the catalog handle without reserving another metadata view.
        if (!bindCatalog) return true;
        catalogView_ = MapViewOfFile(catalogMapping_.get(), FILE_MAP_READ, 0, 0, 0);
        MEMORY_BASIC_INFORMATION region{};
        if (!catalogView_ || !VirtualQuery(catalogView_, &region, sizeof(region))) return false;
        if (!catalog_.Open(catalogView_, region.RegionSize) || !BindApiDefinitions(catalog_))
        {
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }
    }
    return true;
}

bool Transport::Open(uint64_t captureIdentity, bool bindCatalog)
{
    if (!captureIdentity) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
    if (!Map(GetCurrentProcessId(), captureIdentity)) return false;
    if (!data_ || !space_ || !ready_ || !resume_ || !break_ || !controller_)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }
    if (startupThread_.get())
    {
        auto owner = GetProcessIdOfThread(startupThread_.get());
        if (!owner) return false;
        if (owner != header_->processId) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
    }
    if (!MapCatalog(bindCatalog)) return false;

    // The resident agent owns these sources; instruction observers retain independent local duplicates.
    header_->targetHandles = {reinterpret_cast<uint64_t>(mapping_.get()), reinterpret_cast<uint64_t>(data_.get()),
        reinterpret_cast<uint64_t>(space_.get()), reinterpret_cast<uint64_t>(ready_.get()),
        reinterpret_cast<uint64_t>(resume_.get()), reinterpret_cast<uint64_t>(break_.get()),
        reinterpret_cast<uint64_t>(controller_.get()), reinterpret_cast<uint64_t>(catalogMapping_.get()),
        reinterpret_cast<uint64_t>(startupThread_.get())};
    return true;
}

bool Transport::Open(HANDLE mapping, uint64_t captureIdentity, bool bindCatalog)
{
    if (!captureIdentity) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
    auto duplicate = [](uint64_t source, Handle& owner)
    {
        if (!source || source > UINTPTR_MAX) { SetLastError(ERROR_INVALID_HANDLE); return false; }
        HANDLE handle = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), reinterpret_cast<HANDLE>(static_cast<uintptr_t>(source)),
            GetCurrentProcess(), &handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) return false;
        owner.reset(handle);
        return true;
    };
    if (!duplicate(reinterpret_cast<uint64_t>(mapping), mapping_) ||
        !Map(GetCurrentProcessId(), captureIdentity)) return false;
    auto handles = header_->targetHandles;
    if (handles.mapping != reinterpret_cast<uint64_t>(mapping))
    {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    if (!duplicate(handles.data, data_) || !duplicate(handles.space, space_) || !duplicate(handles.ready, ready_) ||
        !duplicate(handles.resume, resume_) || !duplicate(handles.breakpoint, break_) ||
        !duplicate(handles.controller, controller_) ||
        (header_->catalogMapping[0] && !duplicate(handles.catalog, catalogMapping_))) return false;
    return MapCatalog(bindCatalog);
}

TransportHandles Transport::DuplicateTo(HANDLE process, HANDLE startupThread) const
{
    // A granted startup capability must belong to the process receiving the channel.
    if (startupThread)
    {
        auto target = GetProcessId(process);
        Check(target != 0, "Inspect startup target");
        auto owner = GetProcessIdOfThread(startupThread);
        Check(owner != 0, "Inspect startup thread");
        if (owner != target)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            Check(false, "Validate startup thread owner");
        }
    }
    TransportHandles result{};
    struct Item { HANDLE source; uint64_t* destination; DWORD access; };
    const Item items[]{
        {mapping_.get(), &result.mapping, FILE_MAP_READ | FILE_MAP_WRITE},
        {data_.get(), &result.data, EVENT_MODIFY_STATE | SYNCHRONIZE},
        {space_.get(), &result.space, EVENT_MODIFY_STATE | SYNCHRONIZE},
        {ready_.get(), &result.ready, EVENT_MODIFY_STATE | SYNCHRONIZE},
        {resume_.get(), &result.resume, EVENT_MODIFY_STATE | SYNCHRONIZE},
        {break_.get(), &result.breakpoint, EVENT_MODIFY_STATE | SYNCHRONIZE},
        {controller_.get(), &result.controller, SYNCHRONIZE},
        {catalogMapping_.get(), &result.catalog, FILE_MAP_READ},
        {startupThread, &result.startupThread,
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION}};
    try
    {
        for (const auto& item : items)
        {
            if (!item.source) continue;
            HANDLE handle = nullptr;
            Check(DuplicateHandle(GetCurrentProcess(), item.source, process, &handle, item.access, FALSE, 0) != FALSE,
                "Share capture transport handle");
            *item.destination = reinterpret_cast<uint64_t>(handle);
        }
    }
    catch (...)
    {
        CloseRemote(process, result);
        throw;
    }
    return result;
}

void Transport::CloseRemote(HANDLE process, const TransportHandles& handles)
{
    // Only the sender's private, unclaimed handle list is eligible for remote cleanup.
    const auto error = GetLastError();
    for (auto value : {handles.mapping, handles.data, handles.space, handles.ready, handles.resume,
        handles.breakpoint, handles.controller, handles.catalog, handles.startupThread})
        if (value) DuplicateHandle(process, reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value)),
            nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    SetLastError(error);
}

bool Transport::CollectorAlive() const
{
    return controller_ && WaitForSingleObject(controller_.get(), 0) == WAIT_TIMEOUT;
}

LONG Transport::RequestThreadIds(DWORD* ids, DWORD capacity, DWORD* count) noexcept
{
    if (count) *count = 0;
    if (!header_ || !ids || !capacity || !count) return ERROR_INVALID_PARAMETER;
    if (header_->stop || !CollectorAlive()) return ERROR_CANCELLED;
    auto& request = header_->threadIds;

    // A timed-out collector retains its response slot until it finishes writing.
    constexpr auto idle = static_cast<LONG>(ThreadIdState::Idle);
    constexpr auto pending = static_cast<LONG>(ThreadIdState::Pending);
    constexpr auto processing = static_cast<LONG>(ThreadIdState::Processing);
    constexpr auto ready = static_cast<LONG>(ThreadIdState::Ready);
    InterlockedCompareExchange(&request.state, idle, ready);
    if (InterlockedCompareExchange(&request.state, pending, idle) != idle) return ERROR_BUSY;
    auto deadline = GetTickCount64() + ThreadIdTimeoutMs;
    for (;;)
    {
        LONG failure = ERROR_SUCCESS;
        if (header_->stop || !CollectorAlive()) failure = ERROR_CANCELLED;
        else if (GetTickCount64() >= deadline) failure = ERROR_TIMEOUT;
        if (failure)
        {
            InterlockedCompareExchange(&request.state, idle, pending);
            return failure;
        }
        auto state = InterlockedCompareExchange(&request.state, idle, idle);
        if (state == ready)
        {
            auto error = request.error;
            auto received = request.count;
            if (error > static_cast<DWORD>(MAXLONG) || received > ThreadIdCapacity || (error && received))
                failure = ERROR_INVALID_DATA;
            else if (error) failure = static_cast<LONG>(error);
            else if (!received || std::find(request.ids, request.ids + received, DWORD{0}) != request.ids + received)
                failure = ERROR_INVALID_DATA;
            else if (received > capacity) failure = ERROR_INSUFFICIENT_BUFFER;
            else
            {
                memcpy(ids, request.ids, static_cast<size_t>(received) * sizeof(DWORD));
                *count = received;
            }
            InterlockedExchange(&request.state, idle);
            return failure;
        }
        if (state != pending && state != processing) return ERROR_INVALID_DATA;
        Sleep(ThreadIdPollMs);
    }
}

void Transport::ServiceThreadIds(HANDLE process, DWORD pid) noexcept
{
    constexpr auto pending = static_cast<LONG>(ThreadIdState::Pending);
    constexpr auto processing = static_cast<LONG>(ThreadIdState::Processing);
    if (!header_ || InterlockedCompareExchange(&header_->threadIds.state, processing, pending) != pending) return;
    auto& request = header_->threadIds;
    DWORD count = 0;
    auto failed = []() noexcept
    {
        auto error = GetLastError();
        return error ? error : ERROR_GEN_FAILURE;
    };
    auto enumerate = [&]() noexcept -> DWORD
    {
        if (!process || !pid || header_->processId != pid) return ERROR_INVALID_PARAMETER;
        if (header_->stop || !CollectorAlive()) return ERROR_CANCELLED;
        auto owner = GetProcessId(process);
        if (!owner) return failed();
        if (owner != pid) return ERROR_INVALID_PARAMETER;
        auto waited = WaitForSingleObject(process, 0);
        if (waited != WAIT_TIMEOUT) return waited == WAIT_OBJECT_0 ? ERROR_PROCESS_ABORTED : failed();
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (!snapshot) return failed();
        THREADENTRY32 entry{sizeof(entry)};
        if (!Thread32First(snapshot.get(), &entry)) return failed();
        do
        {
            if (entry.dwSize < offsetof(THREADENTRY32, th32OwnerProcessID) + sizeof(entry.th32OwnerProcessID))
                return ERROR_BAD_LENGTH;
            if (entry.th32OwnerProcessID == pid)
            {
                if (!entry.th32ThreadID) return ERROR_INVALID_DATA;
                if (count == ThreadIdCapacity) return ERROR_INSUFFICIENT_BUFFER;
                request.ids[count++] = entry.th32ThreadID;
            }
            entry.dwSize = sizeof(entry);
        } while (Thread32Next(snapshot.get(), &entry));
        auto error = GetLastError();
        if (error != ERROR_NO_MORE_FILES) return error ? error : ERROR_GEN_FAILURE;
        if (header_->stop || !CollectorAlive()) return ERROR_CANCELLED;
        waited = WaitForSingleObject(process, 0);
        if (waited != WAIT_TIMEOUT) return waited == WAIT_OBJECT_0 ? ERROR_PROCESS_ABORTED : failed();
        return count ? ERROR_SUCCESS : ERROR_NOT_FOUND;
    };

    // Only IDs cross the channel; target threads still open peers under their own security context.
    request.error = enumerate();
    request.count = request.error ? 0 : count;
    InterlockedExchange(&request.state, static_cast<LONG>(ThreadIdState::Ready));
}

Slot* Transport::Acquire()
{
    return AcquireSlot(header_, [&]
    {
        if (!CollectorAlive()) return false;
        WaitForSingleObject(space_.get(), AcquireSpaceTimeoutMs);
        return true;
    });
}

void Transport::Publish(Slot* slot)
{
    if (PublishSlot(header_, slot)) SetEvent(data_.get());
}

bool Transport::Read(Record& record)
{
    return ReadBatch(1, [&](const RecordView& view)
    {
        record.event = view.event;
        record.payload.assign(view.payload.begin(), view.payload.end());
    }) != 0;
}

uint32_t Transport::ReadBatch(uint32_t limit, const void* context,
    void (*consume)(const void*, const RecordView&))
{
    // Return consumed slots together without withholding a small queue's working capacity.
    const auto batchLimit = std::min(ReadBatchMaximum, std::max(1u, header_->capacity / 4));
    Slot* freeHead = nullptr;
    Slot* freeTail = nullptr;
    uint32_t count = 0, received = 0;
    auto release = [&](Transport*)
    {
        if (!freeHead) return;
        auto head = ReadShared64(header_->freeSlots);
        for (;;)
        {
            freeTail->next = PoolIndex(head);
            auto observed = InterlockedCompareExchange64(&header_->freeSlots,
                NextPoolHead(head, freeHead->index), head);
            if (observed == head) break;
            head = observed;
        }
        InterlockedAdd64(&header_->dequeue, count);
        if (header_->waiters) SetEvent(space_.get());
        freeHead = freeTail = nullptr;
        count = 0;
    };
    std::unique_ptr<Transport, decltype(release)> batch(this, release);
    while (received < limit)
    {
        // Detach completed records and restore their publication order before borrowing their payloads.
        if (!readHead_)
        {
            auto head = ReadShared64(header_->readySlots);
            while (PoolIndex(head))
            {
                auto observed = InterlockedCompareExchange64(&header_->readySlots, NextPoolHead(head, 0), head);
                if (observed == head) break;
                head = observed;
            }
            auto index = PoolIndex(head);
            if (!index) break;
            while (index)
            {
                auto completed = PoolSlot(header_, index - 1);
                auto next = static_cast<uint32_t>(completed->next);
                completed->next = readHead_;
                readHead_ = index;
                index = next;
            }
        }
        auto slot = PoolSlot(header_, readHead_ - 1);
        if (slot->event.payloadBytes > header_->payloadCapacity) throw std::runtime_error("Invalid capture record.");
        consume(context, {slot->event, {Payload(slot), slot->event.payloadBytes}});
        readHead_ = static_cast<uint32_t>(slot->next);
        slot->next = freeHead ? freeHead->index : 0;
        if (!freeHead) freeTail = slot;
        freeHead = slot;
        ++received;
        if (++count == batchLimit) release(this);
    }
    return received;
}

void Transport::Stop()
{
    if (!header_) return;
    InterlockedExchange(&header_->stop, TransportStopped);
    SetEvent(space_.get());
    SetEvent(resume_.get());
    if (bootstrapRelease_) SetEvent(bootstrapRelease_.get());
}
}

#pragma once
#include <windows.h>
#include <winternl.h>
#include <algorithm>
#include <cstddef>
#include <memory>

// The owning transaction thread allocates without heaps that suspended target threads may hold.
struct DetouristTransactionAllocation
{
    struct Block
    {
        Block* next;
        std::size_t used;
    };
    inline static Block* blocks = nullptr;
    inline static std::size_t outstanding = 0;

    static void* Allocate(Block*& head, std::size_t& count, std::size_t size) noexcept
    {
        // Transaction nodes share pages until the last node is released on commit or abort.
        constexpr std::size_t capacity = 65536, alignment = alignof(std::max_align_t);
        size = (size + alignment - 1) & ~(alignment - 1);
        if (size > capacity - sizeof(Block)) return nullptr;
        if (!head || size > capacity - head->used)
        {
            auto block = static_cast<Block*>(VirtualAlloc(nullptr, capacity,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!block) return nullptr;
            block->next = head;
            block->used = (sizeof(Block) + alignment - 1) & ~(alignment - 1);
            head = block;
        }
        auto memory = reinterpret_cast<std::byte*>(head) + head->used;
        head->used += size;
        ++count;
        return memory;
    }
    static void Free(Block*& head, std::size_t& count, void* memory) noexcept
    {
        if (!memory || --count) return;
        while (head)
        {
            auto next = head->next;
            VirtualFree(head, 0, MEM_RELEASE);
            head = next;
        }
    }
    static void* operator new(std::size_t size) noexcept { return Allocate(blocks, outstanding, size); }
    static void operator delete(void* memory) noexcept { Free(blocks, outstanding, memory); }
};

class DetouristTransactionThreads
{
    struct Entry
    {
        Entry* next = nullptr;
        HANDLE handle = nullptr;
        DWORD id = 0;
    };
    Entry* entries_ = nullptr;
    DetouristTransactionAllocation::Block* blocks_ = nullptr;
    std::size_t count_ = 0;

public:
    inline static thread_local LONG (*Enumerate)(void*, DWORD*, DWORD, DWORD*) = nullptr;
    inline static thread_local void* EnumerationContext = nullptr;
    inline static thread_local HANDLE StartupThread = nullptr;
    DetouristTransactionThreads() = default;
    DetouristTransactionThreads(const DetouristTransactionThreads&) = delete;
    DetouristTransactionThreads& operator=(const DetouristTransactionThreads&) = delete;

    static constexpr ULONG ThreadIsTerminated = 20;
    static constexpr LONG NtStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004);
    static constexpr ULONG InitialSnapshotBytes = 65536;
    static constexpr ULONG SnapshotGrowthPadding = 65536;
    static constexpr unsigned MaxSuspendPasses = 256;
    static constexpr unsigned MaxSnapshotAttempts = 16;

    static bool Terminated(HANDLE thread)
    {
        // Termination can prohibit suspension before the thread handle becomes signaled.
        ULONG terminated = 0;
        return NtQueryInformationThread(thread, static_cast<THREADINFOCLASS>(ThreadIsTerminated), &terminated,
            sizeof(terminated), nullptr) >= 0 && terminated != 0;
    }

    ~DetouristTransactionThreads()
    {
        // Resumed peers can start another transaction while this private arena closes its handles.
        while (entries_)
        {
            auto entry = entries_;
            entries_ = entry->next;
            if (entry->handle) CloseHandle(entry->handle);
            DetouristTransactionAllocation::Free(blocks_, count_, entry);
        }
    }

    LONG Suspend(LONG (WINAPI* update)(HANDLE))
    {
        auto release = [](void* memory) { if (memory) VirtualFree(memory, 0, MEM_RELEASE); };
        std::unique_ptr<void, decltype(release)> snapshot(nullptr, release);
        ULONG capacity = 0, required = InitialSnapshotBytes;
        auto processId = GetCurrentProcessId(), currentThread = GetCurrentThreadId();
        constexpr DWORD access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
            THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION;

        // Repeat suspension until no running peer can create another thread between enumeration and patching.
        for (unsigned pass = 0; pass < MaxSuspendPasses; ++pass)
        {
            ULONG bytes = 0;
            LONG status = NtStatusInfoLengthMismatch;
            for (unsigned attempt = 0; status == NtStatusInfoLengthMismatch; ++attempt)
            {
                if (attempt == MaxSnapshotAttempts || required > MAXDWORD / 2) return ERROR_NOT_ENOUGH_MEMORY;
                if (required > capacity)
                {
                    snapshot.reset(VirtualAlloc(nullptr, required, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
                    if (!snapshot) return ERROR_NOT_ENOUGH_MEMORY;
                    capacity = required;
                }
                status = NtQuerySystemInformation(SystemProcessInformation, snapshot.get(), capacity, &bytes);
                if (status == NtStatusInfoLengthMismatch)
                {
                    if (bytes > MAXDWORD - SnapshotGrowthPadding) return ERROR_NOT_ENOUGH_MEMORY;
                    required = (std::max)(capacity * 2, bytes + SnapshotGrowthPadding);
                }
            }
            if (status < 0) return static_cast<LONG>(RtlNtStatusToDosError(status));
            if (bytes < sizeof(SYSTEM_PROCESS_INFORMATION) || bytes > capacity) return ERROR_BAD_LENGTH;

            // Snapshot IDs expose inaccessible peers instead of silently omitting them from the transaction.
            auto process = static_cast<SYSTEM_PROCESS_INFORMATION*>(snapshot.get());
            for (;;)
            {
                auto offset = reinterpret_cast<BYTE*>(process) - static_cast<BYTE*>(snapshot.get());
                auto remaining = bytes - offset;
                if (remaining < sizeof(*process)) return ERROR_BAD_LENGTH;
                auto recordBytes = process->NextEntryOffset ? process->NextEntryOffset : remaining;
                if (recordBytes < sizeof(*process) || recordBytes > remaining || process->NumberOfThreads >
                    (recordBytes - sizeof(*process)) / sizeof(SYSTEM_THREAD_INFORMATION))
                    return ERROR_BAD_LENGTH;
                if (reinterpret_cast<ULONG_PTR>(process->UniqueProcessId) == processId)
                    break;
                if (!process->NextEntryOffset)
                {
                    process = nullptr;
                    break;
                }
                process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
                    reinterpret_cast<BYTE*>(process) + process->NextEntryOffset);
            }

            // Restricted snapshots can omit this process; the collector supplies IDs without granting thread access.
            auto ids = static_cast<DWORD*>(snapshot.get());
            DWORD threadCount = process ? process->NumberOfThreads : 0;
            if (process)
            {
                auto threads = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(process + 1);
                for (DWORD index = 0; index < threadCount; ++index)
                    ids[index] = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(threads[index].ClientId.UniqueThread));
            }
            else
            {
                if (!Enumerate) return ERROR_NOT_FOUND;
                auto idCapacity = capacity / static_cast<DWORD>(sizeof(DWORD));
                auto error = Enumerate(EnumerationContext, ids, idCapacity, &threadCount);
                if (error) return error;
                if (threadCount > idCapacity) return ERROR_BAD_LENGTH;
            }
            if (std::find(ids, ids + threadCount, currentThread) == ids + threadCount) return ERROR_NOT_FOUND;
            bool changed = false;
            for (DWORD index = 0; index < threadCount; ++index)
            {
                auto id = ids[index];
                if (id == currentThread) continue;
                auto known = entries_;
                while (known && known->id != id) known = known->next;
                if (known) continue;
                changed = true;
                auto memory = DetouristTransactionAllocation::Allocate(blocks_, count_, sizeof(Entry));
                if (!memory) return ERROR_NOT_ENOUGH_MEMORY;
                auto entry = new(memory) Entry;
                entry->next = entries_;
                entries_ = entry;
                entry->handle = OpenThread(access, FALSE, id);
                if (!entry->handle)
                {
                    auto error = GetLastError();
                    if (error == ERROR_INVALID_PARAMETER) continue;

                    // The creator can grant its startup thread even when a restricted observer cannot reopen it.
                    if (error != ERROR_ACCESS_DENIED || !StartupThread || GetThreadId(StartupThread) != id)
                        return static_cast<LONG>(error);
                    if (!DuplicateHandle(GetCurrentProcess(), StartupThread, GetCurrentProcess(), &entry->handle,
                        access, FALSE, 0)) return static_cast<LONG>(GetLastError());
                }

                // Retain handles through commit so recycled IDs cannot identify a different suspended peer.
                auto owner = GetProcessIdOfThread(entry->handle);
                if (owner != processId)
                {
                    auto error = GetLastError();
                    if (owner || Terminated(entry->handle)) continue;
                    return static_cast<LONG>(error);
                }
                entry->id = id;
                auto error = update(entry->handle);
                if (error) return error;

                // Suspension is asynchronous; retrieving context waits until this peer has actually stopped.
                CONTEXT context{};
                context.ContextFlags = CONTEXT_CONTROL;
                if (!GetThreadContext(entry->handle, &context))
                {
                    error = GetLastError();
                    if (!Terminated(entry->handle)) return error;
                }
            }
            if (!changed) return NO_ERROR;
        }
        return ERROR_RETRY;
    }
};

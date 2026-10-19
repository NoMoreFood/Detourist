#include "AsyncIo.h"
#include "RpcCapture.h"
#include <algorithm>
#include <cstring>
#include <memory>
#include <intrin.h>

namespace Detourist
{
constexpr uint32_t AsyncPublicCallback = 1u << 31;
constexpr uint32_t NtStatusPending = 0x103;
constexpr uint32_t NtStatusCancelled = 0xC0000120;

AsyncIoRole AsyncRole(const char* module, const char* name)
{
    // Only system providers establish these contracts; application exports can reuse their names.
    const bool native = !_stricmp(module, "ntdll.dll");
    const bool win32 = !_stricmp(module, "kernel32.dll") || !_stricmp(module, "kernelbase.dll") ||
        !_strnicmp(module, "api-ms-win-core-", 16);
    const bool winsock = !_stricmp(module, "ws2_32.dll") || !_stricmp(module, "mswsock.dll") ||
        !strcmp(module, "$winsock-extension");
    if (!_stricmp(module, "rpcrt4.dll"))
    {
        if (!strcmp(name, "RpcAsyncCompleteCall")) return AsyncIoRole::RpcComplete;
        if (!strcmp(name, "RpcAsyncInitializeHandle")) return AsyncIoRole::RpcInitialize;
    }
    if (!native && !win32 && !winsock) return AsyncIoRole::None;
    struct Contract { const char* name; AsyncIoRole role; };
    constexpr Contract contracts[]{
        {"ReadFile", AsyncIoRole::ReadFile}, {"WriteFile", AsyncIoRole::WriteFile},
        {"ReadFileEx", AsyncIoRole::ReadFileEx}, {"WriteFileEx", AsyncIoRole::WriteFileEx},
        {"ReadFileScatter", AsyncIoRole::ReadScatter}, {"WriteFileGather", AsyncIoRole::WriteGather},
        {"DeviceIoControl", AsyncIoRole::DeviceControl}, {"LockFileEx", AsyncIoRole::LockFile},
        {"ReadDirectoryChangesW", AsyncIoRole::DirectoryChanges},
        {"ReadDirectoryChangesExW", AsyncIoRole::DirectoryChanges},
        {"NtReadFile", AsyncIoRole::NtRead}, {"NtWriteFile", AsyncIoRole::NtWrite},
        {"NtReadFileScatter", AsyncIoRole::NtReadScatter}, {"NtWriteFileGather", AsyncIoRole::NtWriteGather},
        {"NtDeviceIoControlFile", AsyncIoRole::NtControl}, {"NtFsControlFile", AsyncIoRole::NtControl},
        {"NtQueryDirectoryFile", AsyncIoRole::NtDirectory},
        {"NtQueryDirectoryFileEx", AsyncIoRole::NtDirectory},
        {"NtNotifyChangeDirectoryFile", AsyncIoRole::NtDirectory},
        {"NtNotifyChangeDirectoryFileEx", AsyncIoRole::NtDirectory},
        {"WSARecv", AsyncIoRole::WsaRecv}, {"WSASend", AsyncIoRole::WsaSend},
        {"WSARecvFrom", AsyncIoRole::WsaRecvFrom}, {"WSASendTo", AsyncIoRole::WsaSendTo},
        {"WSAIoctl", AsyncIoRole::WsaControl}, {"AcceptEx", AsyncIoRole::Accept},
        {"ConnectEx", AsyncIoRole::Connect}, {"DisconnectEx", AsyncIoRole::Disconnect},
        {"TransmitFile", AsyncIoRole::Transmit},
        {"GetOverlappedResult", AsyncIoRole::OverlappedResult},
        {"GetOverlappedResultEx", AsyncIoRole::OverlappedResult},
        {"WSAGetOverlappedResult", AsyncIoRole::WsaResult},
        {"GetQueuedCompletionStatus", AsyncIoRole::Dequeue},
        {"GetQueuedCompletionStatusEx", AsyncIoRole::DequeueBatch},
        {"NtRemoveIoCompletion", AsyncIoRole::NtDequeue},
        {"NtRemoveIoCompletionEx", AsyncIoRole::NtDequeueBatch},
        {"WaitForSingleObject", AsyncIoRole::WaitSingle}, {"WaitForSingleObjectEx", AsyncIoRole::WaitSingle},
        {"NtWaitForSingleObject", AsyncIoRole::WaitSingle},
        {"WaitForMultipleObjects", AsyncIoRole::WaitMultiple},
        {"WaitForMultipleObjectsEx", AsyncIoRole::WaitMultiple},
        {"NtWaitForMultipleObjects", AsyncIoRole::WaitMultiple}};
    for (const auto& contract : contracts)
        if (*name == *contract.name && !strcmp(name, contract.name)) return contract.role;
    return AsyncIoRole::None;
}

uint32_t AsyncCallbackParameter(AsyncIoRole role, AsyncCallbackKind& kind)
{
    kind = AsyncCallbackKind::None;
    if (role >= AsyncIoRole::NtRead && role <= AsyncIoRole::NtDirectory)
    {
        kind = AsyncCallbackKind::Native;
        return 2;
    }
    if (role == AsyncIoRole::ReadFileEx || role == AsyncIoRole::WriteFileEx ||
        role == AsyncIoRole::DirectoryChanges)
    {
        kind = AsyncCallbackKind::Win32;
        return role == AsyncIoRole::DirectoryChanges ? 7u : 4u;
    }
    if (role >= AsyncIoRole::WsaRecv && role <= AsyncIoRole::WsaControl)
    {
        kind = AsyncCallbackKind::Winsock;
        return role == AsyncIoRole::WsaRecv || role == AsyncIoRole::WsaSend ? 6u : 8u;
    }
    return UINT32_MAX;
}

constexpr auto UnlockAsyncIo = [](SharedHeader* header) noexcept { InterlockedExchange(&header->asyncLock, 0); };
using AsyncIoLock = std::unique_ptr<SharedHeader, decltype(UnlockAsyncIo)>;
uint32_t AsyncBucket(uint64_t control) noexcept
{
    return static_cast<uint32_t>((control >> 4) ^ (control >> 16)) % AsyncIoBuckets;
}

uint32_t AsyncControlParameter(AsyncIoRole role) noexcept
{
    if (role >= AsyncIoRole::NtRead && role <= AsyncIoRole::NtDirectory) return 4;
    if (role >= AsyncIoRole::WsaRecv && role <= AsyncIoRole::WsaSendTo)
        return role == AsyncIoRole::WsaRecv || role == AsyncIoRole::WsaSend ? 5u : 7u;
    switch (role)
    {
    case AsyncIoRole::ReadFileEx: case AsyncIoRole::WriteFileEx: return 3;
    case AsyncIoRole::DeviceControl: case AsyncIoRole::WsaControl: case AsyncIoRole::Accept: return 7;
    case AsyncIoRole::DirectoryChanges: case AsyncIoRole::Connect: return 6;
    case AsyncIoRole::LockFile: return 5;
    case AsyncIoRole::Disconnect: return 1;
    default: return 4;
    }
}

void BeginAsyncIo(SharedHeader* header, const Event& event, AsyncIoRole role)
{
    if (role == AsyncIoRole::None || AsyncObserver(role) || event.flags & (Skipped | Unwound)) return;
    PendingIo pending{};
    pending.callId = pending.group = event.callId;
    pending.api = static_cast<uint32_t>(event.api);
    pending.thread = event.threadId;
    pending.role = role;
    pending.submitting = true;
    const auto& args = event.arguments;
    pending.file = args[0];
    auto buffer = [&](uint32_t parameter, uint64_t address, uint64_t bytes, uint32_t index = UINT32_MAX)
    {
        if (pending.bufferCount == MaximumArguments) { pending.flags |= Truncated; return; }
        pending.buffers[pending.bufferCount++] = {address, bytes, parameter, index};
    };
    auto flat = [&](uint32_t parameter, uint32_t count)
    {
        buffer(parameter, args[parameter], static_cast<uint32_t>(args[count]));
    };
    auto vector = [&](uint32_t parameter, uint32_t count, bool pages)
    {
        struct SocketBuffer { uint32_t bytes; uintptr_t address; };
        const auto extent = static_cast<uint32_t>(args[count]);
        const auto total = pages ? (uint64_t{extent} + header->pageBytes - 1) / header->pageBytes : extent;
        for (uint64_t index = 0; index < std::min<uint64_t>(total, MaximumArguments); ++index)
        {
            uint64_t address = 0, bytes = 0;
            if (pages)
            {
                if (!ReadCaptureMemory(reinterpret_cast<void*>(args[parameter] + index * 8), &address, 8))
                { pending.flags |= Unreadable; break; }
                bytes = std::min<uint64_t>(header->pageBytes, extent - index * header->pageBytes);
            }
            else
            {
                SocketBuffer value{};
                if (!ReadCaptureMemory(reinterpret_cast<void*>(args[parameter] + index * sizeof(value)),
                    &value, sizeof(value))) { pending.flags |= Unreadable; break; }
                address = value.address;
                bytes = value.bytes;
            }
            buffer(parameter, address, bytes, static_cast<uint32_t>(index));
        }
        if (total > MaximumArguments) pending.flags |= Truncated;
    };

    // Copy scatter/gather descriptors now; Winsock permits the descriptor array itself to live on the stack.
    if (role >= AsyncIoRole::NtRead && role <= AsyncIoRole::NtDirectory)
    {
        pending.event = args[1];
        if (role == AsyncIoRole::NtControl) flat(8, 9);
        else if (role == AsyncIoRole::NtReadScatter || role == AsyncIoRole::NtWriteGather) vector(5, 6, true);
        else flat(5, 6);
    }
    else if (role >= AsyncIoRole::WsaRecv && role <= AsyncIoRole::WsaSendTo)
        vector(1, 2, false);
    else switch (role)
    {
    case AsyncIoRole::ReadFile: case AsyncIoRole::WriteFile:
    case AsyncIoRole::ReadFileEx: case AsyncIoRole::WriteFileEx: case AsyncIoRole::DirectoryChanges:
        flat(1, 2); break;
    case AsyncIoRole::ReadScatter: case AsyncIoRole::WriteGather: vector(1, 2, true); break;
    case AsyncIoRole::DeviceControl: case AsyncIoRole::WsaControl: flat(4, 5); break;
    case AsyncIoRole::Accept:
        buffer(2, args[2], static_cast<uint32_t>(args[3]), 0);
        buffer(2, args[2] + static_cast<uint32_t>(args[3]), static_cast<uint32_t>(args[4]), 1);
        buffer(2, args[2] + static_cast<uint32_t>(args[3]) + static_cast<uint32_t>(args[4]),
            static_cast<uint32_t>(args[5]), 2);
        break;
    case AsyncIoRole::Connect: flat(3, 4); break;
    case AsyncIoRole::LockFile: case AsyncIoRole::Disconnect: case AsyncIoRole::Transmit: break;
    default: return;
    }
    pending.controlParameter = AsyncControlParameter(role);
    pending.control = args[pending.controlParameter];
    if (!pending.control) return;
    AsyncCallbackKind callbackKind;
    const auto callback = AsyncCallbackParameter(role, callbackKind);
    if (callback != UINT32_MAX && args[callback] && callbackKind != AsyncCallbackKind::Native)
        pending.flags |= AsyncPublicCallback;
    if (role < AsyncIoRole::NtRead || role > AsyncIoRole::NtDirectory)
    {
        uintptr_t handle = 0;
        if (ReadCaptureMemory(reinterpret_cast<void*>(pending.control + offsetof(OVERLAPPED, hEvent)),
            &handle, sizeof(handle))) pending.event = handle & ~uintptr_t{1};
    }
    if (!LockSession(header->asyncLock)) { InterlockedIncrement64(&header->asyncUntracked); return; }
    AsyncIoLock lock(header, UnlockAsyncIo);

    // Completion observers return claimed slots without the registry lock.
    for (auto released = static_cast<uint32_t>(InterlockedExchange(&header->asyncReleased, 0)); released;)
    {
        auto& slot = header->asyncIo[released - 1];
        auto next = slot.next;
        slot.next = header->asyncFree;
        header->asyncFree = released;
        released = next;
    }
    auto& bucket = header->asyncBuckets[AsyncBucket(pending.control)];
    for (auto link = &bucket; *link;)
    {
        auto& current = header->asyncIo[*link - 1];
        if (current.control != pending.control) { link = &current.next; continue; }
        if (current.submitting && current.thread == pending.thread)
        {
            pending.group = current.group;
            link = &current.next;
            continue;
        }

        // Reusing an unobserved control block invalidates its old buffers; never attribute new bytes to that request.
        auto removed = *link;
        *link = current.next;
        current.next = header->asyncFree;
        header->asyncFree = removed;
        InterlockedDecrement(&header->asyncPending);
        InterlockedIncrement64(&header->asyncUntracked);
    }
    if (!header->asyncFree) { InterlockedIncrement64(&header->asyncUntracked); return; }
    auto index = header->asyncFree;
    header->asyncFree = header->asyncIo[index - 1].next;
    pending.next = bucket;
    header->asyncIo[index - 1] = pending;
    bucket = index;
    InterlockedIncrement(&header->asyncPending);
}

void CompleteAsyncIo(const AsyncIoSink& sink, uint64_t control, uint64_t bytes, uint32_t status,
    AsyncIoDomain domain, AsyncIoSource source, uint64_t observer, uint32_t thread, uint32_t ioFlags,
    uint64_t expectedCall)
{
    auto header = sink.header;
    if (!control || !header->asyncPending || domain == AsyncIoDomain::NtStatus && status == NtStatusPending) return;
    if (source == AsyncIoSource::CompletionPort || source == AsyncIoSource::Result)
    {
        uintptr_t current = 0;
        if (ReadCaptureMemory(reinterpret_cast<void*>(control), &current, sizeof(current)) &&
            static_cast<uint32_t>(current) == NtStatusPending) return;
    }
    uint32_t claimed = 0;

    // Claim each request once, then release the registry before snapshotting or waiting for transport space.
    {
        if (!LockSession(header->asyncLock)) return;
        AsyncIoLock lock(header, UnlockAsyncIo);
        auto link = &header->asyncBuckets[AsyncBucket(control)];

        // A control block can be reused after an observer releases the registry lock.
        if (expectedCall)
        {
            auto matching = *link;
            while (matching && (header->asyncIo[matching - 1].control != control ||
                header->asyncIo[matching - 1].callId != expectedCall)) matching = header->asyncIo[matching - 1].next;
            if (!matching) return;
        }

        // Public callbacks expose provider translations and Winsock flags after their internal native APC.
        if (source == AsyncIoSource::Apc && domain == AsyncIoDomain::NtStatus)
            for (auto index = *link; index; index = header->asyncIo[index - 1].next)
            {
                const auto& pending = header->asyncIo[index - 1];
                if (pending.control == control && pending.flags & AsyncPublicCallback) return;
            }
        while (*link)
        {
            auto& pending = header->asyncIo[*link - 1];
            if (pending.control != control) { link = &pending.next; continue; }
            auto index = *link;
            *link = pending.next;
            pending.next = claimed;
            claimed = index;
            InterlockedDecrement(&header->asyncPending);
        }
    }
    const auto observed = Clock();
    while (claimed)
    {
        auto& pending = header->asyncIo[claimed - 1];
        const auto next = pending.next;
        if (auto slot = sink.acquire(sink.context))
        {
            slot->event = {};
            auto& completed = slot->event;
            completed.kind = EventKind::AsyncCompletion;
            completed.api = static_cast<Api>(pending.api);
            completed.callId = pending.callId;
            completed.timestamp = observed;
            completed.threadId = thread;
            completed.arguments[0] = control;
            completed.arguments[1] = observer;
            completed.arguments[2] = bytes;
            completed.arguments[3] = status;
            completed.arguments[4] = static_cast<uint32_t>(domain);
            completed.arguments[5] = static_cast<uint32_t>(source);
            completed.arguments[6] = pending.bufferCount;
            completed.arguments[7] = pending.flags & (Truncated | Unreadable);
            completed.arguments[8] = ioFlags;
            completed.flags = AsyncCompleted;
            if (domain == AsyncIoDomain::NtStatus ? static_cast<int32_t>(status) < 0 : status != 0)
                completed.flags |= Failed;
            if ((domain == AsyncIoDomain::NtStatus && status == NtStatusCancelled) ||
                (domain != AsyncIoDomain::NtStatus && status == ERROR_OPERATION_ABORTED))
                completed.flags |= AsyncCancelled;
            auto remaining = bytes;
            for (uint32_t index = 0; index < pending.bufferCount; ++index)
            {
                const auto& buffer = pending.buffers[index];
                const bool address = pending.role == AsyncIoRole::Accept && index != 0 && !(completed.flags & Failed);
                auto transferred = address ? buffer.bytes : std::min(remaining, buffer.bytes);
                AsyncIoBufferSnapshot snapshot{buffer.address, buffer.bytes, transferred,
                    buffer.parameter, buffer.index};
                memcpy(Transport::Payload(slot) + index * sizeof(snapshot), &snapshot, sizeof(snapshot));
                if (!address) remaining -= transferred;
            }
            completed.payloadBytes = pending.bufferCount * sizeof(AsyncIoBufferSnapshot);
            for (uint32_t index = 0; index < pending.bufferCount; ++index)
            {
                const auto& buffer = pending.buffers[index];
                AsyncIoBufferSnapshot snapshot;
                memcpy(&snapshot, Transport::Payload(slot) + index * sizeof(snapshot), sizeof(snapshot));
                CopyValue(slot, header, buffer.parameter, ValueKind::Bytes, buffer.address, snapshot.completed,
                    {.flags = buffer.index != UINT32_MAX ? ReferencedData | (buffer.index << ValueDetailShift) : 0u});
            }
            const bool native = pending.role >= AsyncIoRole::NtRead && pending.role <= AsyncIoRole::NtDirectory;
            CopyValue(slot, header, pending.controlParameter, native ? ValueKind::IoStatus : ValueKind::Bytes,
                control, native ? sizeof(uintptr_t) * 2 : sizeof(OVERLAPPED));
            sink.publish(sink.context, slot);
        }

        // Release the slot without the registry lock; the next submission returns it to the free list.
        for (auto head = header->asyncReleased;;)
        {
            pending.next = static_cast<uint32_t>(head);
            auto current = InterlockedCompareExchange(&header->asyncReleased, static_cast<LONG>(claimed), head);
            if (current == head) break;
            head = current;
        }
        claimed = next;
    }
}

void FinishAsyncIo(const AsyncIoSink& sink, Event& event, AsyncIoRole role)
{
    struct IoStatusBlock { uintptr_t status, bytes; };
    auto header = sink.header;
    if (header->rpcPending && (role == AsyncIoRole::RpcComplete || role == AsyncIoRole::RpcInitialize ||
        event.flags & Unwound)) FinishRpcAsync(sink, event, role);
    if (role >= AsyncIoRole::RpcComplete || role == AsyncIoRole::None || !header->asyncPending) return;
    const auto& args = event.arguments;
    if (!AsyncObserver(role))
    {
        const bool native = role >= AsyncIoRole::NtRead && role <= AsyncIoRole::NtDirectory;
        const bool wsa = role >= AsyncIoRole::WsaRecv && role <= AsyncIoRole::WsaControl;
        AsyncCallbackKind kind;
        const auto callbackParameter = AsyncCallbackParameter(role, kind);
        const bool callback = callbackParameter != UINT32_MAX && args[callbackParameter] &&
            kind != AsyncCallbackKind::Native;
        const bool pending = native ? event.result == NtStatusPending || args[2] && event.result == 0 :
            wsa ? (static_cast<int32_t>(event.result) == -1 && event.error == ERROR_IO_PENDING) ||
                (callback && event.result == 0) : callback ? event.result != 0 :
                !event.result && event.error == ERROR_IO_PENDING;
        const bool failed = event.flags & (Skipped | Unwound) ||
            (native ? static_cast<int32_t>(event.result) < 0 : wsa ?
                static_cast<int32_t>(event.result) == -1 && !pending : !event.result && !pending);
        const bool synchronous = native && !pending && !args[1] && !args[2];
        uint64_t control = 0;
        if (LockSession(header->asyncLock))
        {
            AsyncIoLock lock(header, UnlockAsyncIo);
            auto& bucket = header->asyncBuckets[AsyncBucket(args[AsyncControlParameter(role)])];
            for (auto link = &bucket; *link;)
            {
                auto& current = header->asyncIo[*link - 1];
                if (current.callId != event.callId) { link = &current.next; continue; }
                current.submitting = false;
                control = current.control;
                if (failed || synchronous)
                {
                    auto index = *link;
                    *link = current.next;
                    current.next = header->asyncFree;
                    header->asyncFree = index;
                    InterlockedDecrement(&header->asyncPending);
                }
                break;
            }
        }
        if (pending && !failed) { event.flags = (event.flags & ~Failed) | AsyncPending; return; }
        if (!control || failed || synchronous) return;
        IoStatusBlock completed{};
        if (ReadCaptureMemory(reinterpret_cast<void*>(control), &completed, sizeof(completed)) &&
            static_cast<uint32_t>(completed.status) != NtStatusPending)
            CompleteAsyncIo(sink, control, completed.bytes, static_cast<uint32_t>(completed.status),
                AsyncIoDomain::NtStatus, AsyncIoSource::Return, event.callId, event.threadId, 0, event.callId);
        return;
    }
    if (event.flags & (Skipped | Unwound)) return;
    auto complete = [&](uint64_t control, uint64_t bytes, uint32_t status, AsyncIoDomain domain,
        AsyncIoSource source = AsyncIoSource::CompletionPort, uint64_t expectedCall = 0)
    {
        CompleteAsyncIo(sink, control, bytes, status, domain, source, event.callId, event.threadId,
            role == AsyncIoRole::WsaResult ? SafeDword(args[4]) : 0, expectedCall);
    };
    auto pointer = [](uint64_t address)
    {
        uintptr_t value = 0;
        if (address) ReadCaptureMemory(reinterpret_cast<void*>(address), &value, sizeof(value));
        return static_cast<uint64_t>(value);
    };
    if (role == AsyncIoRole::OverlappedResult || role == AsyncIoRole::WsaResult)
    {
        if (!event.result && (event.error == ERROR_IO_INCOMPLETE || event.error == WAIT_TIMEOUT ||
            event.error == ERROR_IO_PENDING || event.error == WAIT_IO_COMPLETION)) return;
        complete(args[1], event.result ? SafeDword(args[2]) : pointer(args[1] + sizeof(uintptr_t)),
            event.result ? 0 : event.error,
            role == AsyncIoRole::WsaResult ? AsyncIoDomain::Winsock : AsyncIoDomain::Win32, AsyncIoSource::Result);
    }
    else if (role == AsyncIoRole::Dequeue)
        complete(pointer(args[3]), SafeDword(args[1]), event.result ? 0 : event.error, AsyncIoDomain::Win32);
    else if (role == AsyncIoRole::DequeueBatch && event.result)
    {
        struct Entry { uintptr_t key, control, status; uint32_t bytes; };
        for (uint32_t index = 0, count = std::min<uint32_t>(SafeDword(args[3]), static_cast<uint32_t>(args[2]));
            index < count; ++index)
        {
            Entry entry{};
            if (!ReadCaptureMemory(reinterpret_cast<void*>(args[1] + uint64_t{index} * sizeof(entry)),
                &entry, sizeof(entry))) break;
            uintptr_t status = NtStatusPending;
            if (ReadCaptureMemory(reinterpret_cast<void*>(entry.control), &status, sizeof(status)))
                complete(entry.control, entry.bytes, static_cast<uint32_t>(status), AsyncIoDomain::NtStatus);
        }
    }
    else if (role == AsyncIoRole::NtDequeue && !event.result)
    {
        IoStatusBlock status{};
        if (ReadCaptureMemory(reinterpret_cast<void*>(args[3]), &status, sizeof(status)))
            complete(pointer(args[2]), status.bytes, static_cast<uint32_t>(status.status), AsyncIoDomain::NtStatus);
    }
    else if (role == AsyncIoRole::NtDequeueBatch && !event.result)
    {
        struct Entry { uintptr_t key, control, status, bytes; };
        for (uint32_t index = 0, count = std::min<uint32_t>(SafeDword(args[3]), static_cast<uint32_t>(args[2]));
            index < count; ++index)
        {
            Entry entry{};
            if (!ReadCaptureMemory(reinterpret_cast<void*>(args[1] + uint64_t{index} * sizeof(entry)),
                &entry, sizeof(entry))) break;
            complete(entry.control, entry.bytes, static_cast<uint32_t>(entry.status), AsyncIoDomain::NtStatus);
        }
    }
    else if (role == AsyncIoRole::WaitSingle || role == AsyncIoRole::WaitMultiple)
    {
        uintptr_t handles[MAXIMUM_WAIT_OBJECTS]{};
        auto count = role == AsyncIoRole::WaitSingle ? 1u : static_cast<uint32_t>(args[0]);
        if (count > MAXIMUM_WAIT_OBJECTS || event.result >= count) return;
        if (role == AsyncIoRole::WaitSingle) handles[0] = static_cast<uintptr_t>(args[0]);
        else if (!ReadCaptureMemory(reinterpret_cast<void*>(args[1]), handles, count * sizeof(uintptr_t))) return;
        const bool waitAll = role == AsyncIoRole::WaitMultiple &&
            (NativeReturnsStatus(event.api) || event.flags & Syscall ? args[2] == 0 : args[2] != 0);
        struct Request { uint64_t call, control; };
        Request controls[MaximumArguments];

        // Batch bucket inspection while keeping application-memory reads outside the shared lock.
        constexpr uint32_t bucketsPerBatch = 32;
        for (uint32_t first = 0; first < AsyncIoBuckets; first += bucketsPerBatch)
        {
            uint64_t after = 0;
            bool more;
            do
            {
                uint32_t found = 0, candidates = 0;
                {
                    if (!LockSession(header->asyncLock)) return;
                    AsyncIoLock lock(header, UnlockAsyncIo);
                    for (uint32_t bucket = first; bucket < std::min(first + bucketsPerBatch, AsyncIoBuckets); ++bucket)
                        for (auto index = header->asyncBuckets[bucket]; index; index = header->asyncIo[index - 1].next)
                        {
                            const auto& pending = header->asyncIo[index - 1];
                            if (pending.callId <= after || !pending.event) continue;
                            bool matches = false;
                            for (uint32_t handle = 0; handle < count; ++handle)
                                if ((waitAll || handle == event.result) && handles[handle] == pending.event)
                                { matches = true; break; }
                            if (!matches) continue;
                            ++candidates;
                            auto position = found;
                            if (found < MaximumArguments) ++found;
                            else
                            {
                                position = 0;
                                for (uint32_t item = 1; item < found; ++item)
                                    if (controls[item].call > controls[position].call) position = item;
                                if (pending.callId >= controls[position].call) continue;
                            }
                            controls[position] = {pending.callId, pending.control};
                        }
                }
                more = candidates > found;
                for (uint32_t index = 0; index < found; ++index)
                {
                    after = std::max(after, controls[index].call);
                    IoStatusBlock status{};
                    if (ReadCaptureMemory(reinterpret_cast<void*>(controls[index].control), &status, sizeof(status)))
                        complete(controls[index].control, status.bytes, static_cast<uint32_t>(status.status),
                            AsyncIoDomain::NtStatus, AsyncIoSource::Event, controls[index].call);
                }
            } while (more);
        }
    }
}
}

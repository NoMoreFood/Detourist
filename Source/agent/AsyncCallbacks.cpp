#pragma warning(push, 0)
#include <winsock2.h>
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "Agent.h"
#include "AsyncIo.h"

namespace Detourist
{
constexpr size_t AsyncCallbackCodeBytes = 32;

struct alignas(16) AsyncCallback
{
    uint64_t identity, original;
    AsyncCallback* next;
    AsyncCallbackKind kind;
    uint32_t reserved;
    uint64_t typeHash, padding;
    unsigned char code[AsyncCallbackCodeBytes];
};
SRWLOCK AsyncCallbackLock = SRWLOCK_INIT;
AsyncCallback* AsyncCallbacks = nullptr;
uint32_t AsyncCallbackCount = 0;
extern "C" void AsyncCallbackGateway();

extern "C" __declspec(dllexport) uint64_t WINAPI DetouristAsyncCallback(uint64_t identity,
    uint64_t callback, uint32_t callbackKind, uint64_t* original)
{
    if (!callback || !identity || !original) return callback;
    ObserverScope observer;
    AcquireSRWLockExclusive(&AsyncCallbackLock);
    const auto kind = static_cast<AsyncCallbackKind>(callbackKind);

    // A callback can cross typed, export and syscall boundaries; retain its logical application address.
    for (auto entry = AsyncCallbacks; entry; entry = entry->next)
        if (callback == reinterpret_cast<uint64_t>(entry->code)) { callback = entry->original; break; }
    *original = callback;
    auto result = callback;
    if (kind >= AsyncCallbackKind::Win32 && kind <= AsyncCallbackKind::Winsock)
    {
        auto entry = AsyncCallbacks;
        while (entry && (entry->identity != identity || entry->original != callback || entry->kind != kind))
            entry = entry->next;
        if (entry) result = reinterpret_cast<uint64_t>(entry->code);
        else if (auto created = AsyncCallbackCount < AsyncIoCapacity ?
            static_cast<AsyncCallback*>(VirtualAlloc(nullptr, sizeof(AsyncCallback),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) : nullptr)
        {
            *created = {};
            created->identity = identity;
            created->original = callback;
            created->kind = kind;
            created->next = AsyncCallbacks;
            ReadCaptureMemory(reinterpret_cast<void*>(callback - 8), &created->padding, sizeof(uint64_t));
#ifdef _WIN64
            const unsigned char code[]{0x49, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,
                0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
            memcpy(created->code, code, sizeof(code));
            auto descriptor = reinterpret_cast<uint64_t>(created);
            auto gateway = reinterpret_cast<uint64_t>(&AsyncCallbackGateway);
            memcpy(created->code + 2, &descriptor, sizeof(descriptor));
            memcpy(created->code + 12, &gateway, sizeof(gateway));
#else
            const unsigned char code[]{0xB8, 0, 0, 0, 0, 0xBA, 0, 0, 0, 0, 0xFF, 0xE2};
            memcpy(created->code, code, sizeof(code));
            auto descriptor = reinterpret_cast<uintptr_t>(created);
            auto gateway = reinterpret_cast<uintptr_t>(&AsyncCallbackGateway);
            memcpy(created->code + 1, &descriptor, sizeof(descriptor));
            memcpy(created->code + 6, &gateway, sizeof(gateway));
#endif
            DWORD protection = 0;
            if (VirtualProtect(created, sizeof(*created), PAGE_EXECUTE_READ, &protection))
            {
                FlushInstructionCache(GetCurrentProcess(), created->code, sizeof(created->code));
                AsyncCallbacks = created;
                ++AsyncCallbackCount;
                result = reinterpret_cast<uint64_t>(created->code);
            }
            else VirtualFree(created, 0, MEM_RELEASE);
        }
    }
    ReleaseSRWLockExclusive(&AsyncCallbackLock);
    return result;
}

extern "C" void AsyncCallbackDispatch(uint64_t first, uint64_t second, uint64_t third, uint64_t fourth,
    const AsyncCallback* callback)
{
    const auto savedError = GetLastError();
    const auto savedStatus = NativeThreadStatus();
    const auto observing = ObserverActive;
    ObserverActive = true;
    CaptureObservation capture(&CaptureTime, Clock());
    Transport* transport = nullptr;
    if (!ProcessShuttingDown)
    {
        AcquireSRWLockShared(&CaptureLock);
        if (ActiveTransport && !ActiveTransport->Header()->stop &&
            ActiveTransport->Header()->captureIdentity == callback->identity)
        {
            transport = ActiveTransport;
            InterlockedIncrement64(&transport->Header()->activeCalls);
            InterlockedIncrement64(&transport->Header()->recordingCalls);
        }
        ReleaseSRWLockShared(&CaptureLock);
    }
    if (transport)
    {
        if (callback->kind == AsyncCallbackKind::Native)
        {
            struct Status { uintptr_t status, bytes; } completed{};
            if (ReadCaptureMemory(reinterpret_cast<void*>(second), &completed, sizeof(completed)))
                CompleteAsyncIo(AsyncSink(*transport), second, completed.bytes,
                    static_cast<uint32_t>(completed.status), AsyncIoDomain::NtStatus, AsyncIoSource::Apc,
                    0, GetCurrentThreadId());
        }
        else
            CompleteAsyncIo(AsyncSink(*transport), third, static_cast<uint32_t>(second), static_cast<uint32_t>(first),
                callback->kind == AsyncCallbackKind::Winsock ? AsyncIoDomain::Winsock : AsyncIoDomain::Win32,
                AsyncIoSource::Apc, 0, GetCurrentThreadId(),
                callback->kind == AsyncCallbackKind::Winsock ? static_cast<uint32_t>(fourth) : 0);
        InterlockedDecrement64(&transport->Header()->recordingCalls);
        InterlockedDecrement64(&transport->Header()->activeCalls);
    }
    capture.Reset();
    ObserverActive = observing;
    SetLastError(savedError);
    RestoreNativeThreadStatus(savedStatus);

    // Persistent gateways also forward outstanding callbacks after capture detaches, preserving the original context.
    if (callback->kind == AsyncCallbackKind::Native)
        reinterpret_cast<PIO_APC_ROUTINE>(callback->original)(reinterpret_cast<void*>(first),
            reinterpret_cast<PIO_STATUS_BLOCK>(second), static_cast<ULONG>(third));
    else if (callback->kind == AsyncCallbackKind::Winsock)
        reinterpret_cast<LPWSAOVERLAPPED_COMPLETION_ROUTINE>(callback->original)(static_cast<DWORD>(first),
            static_cast<DWORD>(second), reinterpret_cast<LPWSAOVERLAPPED>(third), static_cast<DWORD>(fourth));
    else
        reinterpret_cast<LPOVERLAPPED_COMPLETION_ROUTINE>(callback->original)(static_cast<DWORD>(first),
            static_cast<DWORD>(second), reinterpret_cast<LPOVERLAPPED>(third));
}
}

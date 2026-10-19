#include "SpyProtocol.h"
#include "ProfilerBridge.h"
#include <atomic>
#include <iterator>

using namespace Detourist;

SRWLOCK MappingLock = SRWLOCK_INIT;
HANDLE Mapping = nullptr;
std::atomic<SpyBuffer*> Buffer = nullptr;
volatile LONG InitialDrops = 0;
std::atomic<BOOL (WINAPI*)(BOOL)> CaptureGuard = nullptr;

void RecordMessage(SpyMessageKind kind, HWND window, UINT message, WPARAM wparam, LPARAM lparam, LRESULT result)
{
    // Reuse the agent's observer guard so inspecting messages does not record the logger's own API calls.
    auto guard = CaptureGuard.load(std::memory_order_acquire);
    if (!guard)
    {
        const auto error = GetLastError();
        auto agent = GetModuleHandleW(L"DetouristAgent.dll");
        auto query = agent ? reinterpret_cast<GetProfilerBridge>(GetProcAddress(agent,
            "DetouristGetProfilerBridge")) : nullptr;
        ProfilerBridge bridge{};
        if (query && query(ProfilerBridgeVersion, &bridge))
            CaptureGuard.store(guard = bridge.guard, std::memory_order_release);
        SetLastError(error);
    }
    const auto observing = guard ? guard(TRUE) : FALSE;

    // Hook callbacks never wait on the viewer or dereference application-owned message parameters.
    const auto error = GetLastError();
    auto buffer = Buffer.load(std::memory_order_acquire);
    if (!buffer)
    {
        if (!TryAcquireSRWLockExclusive(&MappingLock))
        {
            InterlockedIncrement(&InitialDrops);
            SetLastError(error);
            if (guard) guard(observing);
            return;
        }
        buffer = Buffer.load(std::memory_order_acquire);
        if (!buffer)
        {
            wchar_t name[SpyObjectNameCapacity];
            SpyName(name, GetCurrentProcessId(), L"buffer");
            Mapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name);
            if (Mapping)
                buffer = static_cast<SpyBuffer*>(MapViewOfFile(Mapping, FILE_MAP_READ | FILE_MAP_WRITE,
                    0, 0, sizeof(SpyBuffer)));
            if (!buffer && Mapping) { CloseHandle(Mapping); Mapping = nullptr; }
            Buffer.store(buffer, std::memory_order_release);
        }
        ReleaseSRWLockExclusive(&MappingLock);
    }
    if (buffer && buffer->signature == SpySignature && InterlockedCompareExchange(&buffer->active, 0, 0))
    {
        if (InitialDrops) InterlockedExchangeAdd(&buffer->dropped, InterlockedExchange(&InitialDrops, 0));
        if (InterlockedCompareExchange(&buffer->lock, 1, 0)) InterlockedIncrement(&buffer->dropped);
        else
        {
            const auto target = reinterpret_cast<HWND>(static_cast<uintptr_t>(buffer->window));
            if (buffer->active && (!target || target == window || buffer->children && IsChild(target, window)))
            {
                if (buffer->write - buffer->read >= SpyCapacity) InterlockedIncrement(&buffer->dropped);
                else
                {
                    LARGE_INTEGER clock;
                    QueryPerformanceCounter(&clock);
                    auto& record = buffer->messages[buffer->write % SpyCapacity];
                    record = {clock.QuadPart,
                        reinterpret_cast<uintptr_t>(window), wparam, static_cast<uintptr_t>(lparam),
                        static_cast<uintptr_t>(result), GetCurrentThreadId(), message, static_cast<uint32_t>(kind),
                        0, {}};
                    if (window) GetClassNameW(window, record.className, static_cast<int>(std::size(record.className)));
                    ++buffer->write;
                }
                if (target == window && message == WM_NCDESTROY && kind == SpyMessageKind::Returned)
                {
                    InterlockedExchange(&buffer->finished, 1);
                    InterlockedExchange(&buffer->active, 0);
                }
            }
            InterlockedExchange(&buffer->lock, 0);
        }
    }
    SetLastError(error);
    if (guard) guard(observing);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK SpySent(int code, WPARAM wparam, LPARAM lparam)
{
    if (code >= 0)
    {
        auto message = reinterpret_cast<const CWPSTRUCT*>(lparam);
        RecordMessage(SpyMessageKind::Sent, message->hwnd, message->message, message->wParam, message->lParam, 0);
    }
    return CallNextHookEx(nullptr, code, wparam, lparam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK SpyReturned(int code, WPARAM wparam, LPARAM lparam)
{
    if (code >= 0)
    {
        auto message = reinterpret_cast<const CWPRETSTRUCT*>(lparam);
        RecordMessage(SpyMessageKind::Returned, message->hwnd, message->message, message->wParam, message->lParam,
            message->lResult);
    }
    return CallNextHookEx(nullptr, code, wparam, lparam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK SpyPosted(int code, WPARAM wparam, LPARAM lparam)
{
    if (code >= 0)
    {
        auto message = reinterpret_cast<const MSG*>(lparam);
        RecordMessage(wparam == PM_REMOVE ? SpyMessageKind::PostedRemoved : SpyMessageKind::PostedPeeked,
            message->hwnd, message->message, message->wParam, message->lParam, 0);
    }
    return CallNextHookEx(nullptr, code, wparam, lparam);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_DETACH)
    {
        if (auto buffer = Buffer.load(std::memory_order_acquire)) UnmapViewOfFile(buffer);
        if (Mapping) CloseHandle(Mapping);
    }
    return TRUE;
}

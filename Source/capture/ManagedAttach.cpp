#include "ManagedAttach.h"
#include "ApiCatalog.h"
#include "ProfilerBridge.h"
#include <objbase.h>
#include <tlhelp32.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace Detourist
{
constexpr DWORD ManagedAttachTimeoutMs = 15000;
constexpr DWORD PipeBusyWaitMs = 100;
constexpr uint32_t ProfilerAttachTimeoutMs = 12000;
constexpr size_t DotnetIpcHeaderBytes = 20;
constexpr size_t DotnetIpcSizeOffset = 14;
constexpr size_t DotnetIpcCommandSetOffset = 16;
constexpr size_t DotnetIpcCommandIdOffset = 17;
constexpr BYTE DotnetIpcProfilerCommandSet = 3;
constexpr BYTE DotnetIpcAttachProfilerCommand = 1;
constexpr BYTE DotnetIpcServerCommandSet = 0xFF;
constexpr BYTE DotnetIpcOkResponse = 0;
constexpr BYTE DotnetIpcErrorResponse = 0xFF;
constexpr size_t DotnetIpcTimeoutOffset = 20;
constexpr size_t DotnetIpcClsidOffset = 24;
constexpr size_t DotnetIpcPathLengthOffset = 40;
constexpr size_t DotnetIpcPathOffset = 44;

#ifdef DETOURIST_BUILD_MANAGED_DEBUGGER
class RemoteManagedDebugger final : public ManagedDebugger
{
public:
    RemoteManagedDebugger(Transport& transport, Handle process, Handle stop) : transport_(transport),
        process_(std::move(process)), stop_(std::move(stop)) {}
    ~RemoteManagedDebugger() override { Shutdown(); }
    HRESULT Shutdown() override
    {
        if (!process_) return result_;
        SetEvent(stop_.get());
        SetEvent(transport_.ResumeEvent());
        if (WaitForSingleObject(process_.get(), ManagedAttachTimeoutMs) == WAIT_TIMEOUT)
        {
            transport_.Stop();
            if (WaitForSingleObject(process_.get(), ManagedAttachTimeoutMs) == WAIT_TIMEOUT)
                return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        }
        DWORD code = 0;
        result_ = GetExitCodeProcess(process_.get(), &code) ? FAILED(static_cast<HRESULT>(code)) ?
            static_cast<HRESULT>(code) : HRESULT_FROM_WIN32(code) : HRESULT_FROM_WIN32(GetLastError());
        process_.reset();
        return result_;
    }
private:
    Transport& transport_;
    Handle process_, stop_;
    HRESULT result_ = S_OK;
};

std::unique_ptr<ManagedDebugger> StartManagedDebugger(DWORD processId, Transport& transport,
    const std::wstring& runtime, bool legacy, uint32_t pointerSize, HRESULT& result)
{
    // Each runtime observer owns its debugger and publishes through the target's shared queue.
    auto name = transport.Name();
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, (name + L".managed.ready").c_str()));
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, (name + L".managed.stop").c_str()));
    if (!ready || !stop) { result = HRESULT_FROM_WIN32(GetLastError()); return nullptr; }
    auto executable = ArchitectureDirectory(pointerSize) + L"\\DetouristManagedDebugger.exe";
    auto command = L"\"" + executable + L"\" " + std::to_wstring(processId) + L" \"" + name + L"\" \"" +
        runtime + L"\" " + (legacy ? L"legacy" : L"desktop");
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION information{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &information))
    {
        result = HRESULT_FROM_WIN32(GetLastError());
        return nullptr;
    }
    Handle process(information.hProcess), thread(information.hThread);
    HANDLE events[]{process.get(), ready.get()};
    auto waited = WaitForMultipleObjects(2, events, FALSE, ManagedAttachTimeoutMs);
    if (waited != WAIT_OBJECT_0 + 1)
    {
        SetEvent(stop.get());
        DWORD code = 0;
        result = waited == WAIT_OBJECT_0 && GetExitCodeProcess(process.get(), &code) && code ?
            FAILED(static_cast<HRESULT>(code)) ? static_cast<HRESULT>(code) : HRESULT_FROM_WIN32(code) :
            HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        return nullptr;
    }
    result = S_OK;
    return std::make_unique<RemoteManagedDebugger>(transport, std::move(process), std::move(stop));
}
#endif

HRESULT ProfilerPipeTransfer(HANDLE pipe, void* buffer, DWORD bytes, bool write, uint64_t deadline)
{
    Handle completed(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!completed) return HRESULT_FROM_WIN32(GetLastError());
    auto data = static_cast<BYTE*>(buffer);
    while (bytes)
    {
        OVERLAPPED operation{};
        operation.hEvent = completed.get();
        ResetEvent(completed.get());
        DWORD transferred = 0;
        auto success = write ? WriteFile(pipe, data, bytes, &transferred, &operation) :
            ReadFile(pipe, data, bytes, &transferred, &operation);
        if (!success && GetLastError() == ERROR_IO_PENDING)
        {
            auto now = GetTickCount64();
            auto remaining = static_cast<DWORD>(now < deadline ? deadline - now : 0);
            if (WaitForSingleObject(completed.get(), remaining) != WAIT_OBJECT_0)
            {
                CancelIoEx(pipe, &operation);
                GetOverlappedResult(pipe, &operation, &transferred, TRUE);
                return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
            }
            success = GetOverlappedResult(pipe, &operation, &transferred, FALSE);
        }
        if (!success || !transferred) return HRESULT_FROM_WIN32(success ? ERROR_BROKEN_PIPE : GetLastError());
        data += transferred;
        bytes -= transferred;
    }
    return S_OK;
}

HRESULT AttachCoreProfiler(DWORD processId, const GUID& profiler, const std::wstring& path)
{
    auto name = L"\\\\.\\pipe\\dotnet-diagnostic-" + std::to_wstring(processId);
    auto deadline = GetTickCount64() + ManagedAttachTimeoutMs;
    Handle pipe;
    while (GetTickCount64() < deadline)
    {
        pipe.reset(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED, nullptr));
        if (pipe) break;
        auto error = GetLastError();
        if (error != ERROR_PIPE_BUSY) return HRESULT_FROM_WIN32(error);
        WaitNamedPipeW(name.c_str(), PipeBusyWaitMs);
    }
    if (!pipe) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);

    // A single diagnostics connection carries one attach request and its HRESULT response.
    constexpr char magic[14] = "DOTNET_IPC_V1";
    auto size = DotnetIpcHeaderBytes + sizeof(uint32_t) + sizeof(GUID) + sizeof(uint32_t) +
        (path.size() + 1) * sizeof(wchar_t) + sizeof(uint32_t);
    if (size > UINT16_MAX) return E_INVALIDARG;
    std::vector<BYTE> message(size, 0);
    memcpy(message.data(), magic, sizeof(magic));
    auto encodedSize = static_cast<uint16_t>(size);
    memcpy(message.data() + DotnetIpcSizeOffset, &encodedSize, sizeof(encodedSize));
    message[DotnetIpcCommandSetOffset] = DotnetIpcProfilerCommandSet;
    message[DotnetIpcCommandIdOffset] = DotnetIpcAttachProfilerCommand;
    uint32_t timeout = ProfilerAttachTimeoutMs, length = static_cast<uint32_t>(path.size() + 1);
    memcpy(message.data() + DotnetIpcTimeoutOffset, &timeout, sizeof(timeout));
    memcpy(message.data() + DotnetIpcClsidOffset, &profiler, sizeof(profiler));
    memcpy(message.data() + DotnetIpcPathLengthOffset, &length, sizeof(length));
    memcpy(message.data() + DotnetIpcPathOffset, path.c_str(), length * sizeof(wchar_t));
    auto result = ProfilerPipeTransfer(pipe.get(), message.data(), static_cast<DWORD>(message.size()), true, deadline);
    if (FAILED(result)) return result;
    std::array<BYTE, DotnetIpcHeaderBytes> header{};
    result = ProfilerPipeTransfer(pipe.get(), header.data(), static_cast<DWORD>(header.size()), false, deadline);
    if (FAILED(result)) return result;
    uint16_t responseSize = 0;
    memcpy(&responseSize, header.data() + DotnetIpcSizeOffset, sizeof(responseSize));
    if (memcmp(header.data(), magic, sizeof(magic)) ||
        header[DotnetIpcCommandSetOffset] != DotnetIpcServerCommandSet ||
        (header[DotnetIpcCommandIdOffset] != DotnetIpcOkResponse &&
            header[DotnetIpcCommandIdOffset] != DotnetIpcErrorResponse) ||
        responseSize < header.size() + sizeof(HRESULT))
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    std::vector<BYTE> response(responseSize - header.size());
    result = ProfilerPipeTransfer(pipe.get(), response.data(), static_cast<DWORD>(response.size()), false, deadline);
    if (FAILED(result)) return result;
    memcpy(&result, response.data(), sizeof(result));
    return result;
}

ManagedAttachment AttachManagedProfiler(DWORD processId, Transport& transport, uint32_t pointerSize)
{
    ManagedAttachment attachment;
    if (pointerSize > sizeof(void*)) return attachment;
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId));
    if (!snapshot) { attachment.result = HRESULT_FROM_WIN32(GetLastError()); return attachment; }
    MODULEENTRY32W module{sizeof(module)};
    bool core = false, desktop = false, legacy = false;
    std::wstring runtime;
    if (!Module32FirstW(snapshot.get(), &module)) return attachment;
    do
    {
        core |= !_wcsicmp(module.szModule, L"coreclr.dll");
        desktop |= !_wcsicmp(module.szModule, L"clr.dll");
        legacy |= !_wcsicmp(module.szModule, L"mscorwks.dll");
        if (!_wcsicmp(module.szModule, L"clr.dll") || !_wcsicmp(module.szModule, L"mscorwks.dll"))
            runtime = module.szExePath;
    } while (Module32NextW(snapshot.get(), &module));
    if (!core && !desktop && !legacy) return attachment;
    GUID profiler{};
    if (FAILED(CLSIDFromString(ProfilerClassId, &profiler))) { attachment.result = E_FAIL; return attachment; }
    auto path = ArchitectureDirectory(pointerSize) + L"\\DetouristProfiler.dll";
    HRESULT result = S_OK;
    if (core) result = AttachCoreProfiler(processId, profiler, path);
    if ((desktop || legacy) && SUCCEEDED(result))
#ifdef DETOURIST_BUILD_MANAGED_DEBUGGER
        attachment.debugger = StartManagedDebugger(processId, transport, runtime, legacy, pointerSize, result);
#else
        result = E_NOTIMPL;
    static_cast<void>(transport);
#endif
    attachment.result = result;
    return attachment;
}
}

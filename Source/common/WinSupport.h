#pragma once
#include <windows.h>
#include <string>
#include <stdexcept>
#include <utility>

namespace Detourist
{
constexpr size_t ExtendedPathCapacity = 32768;
constexpr size_t ErrorTextCapacity = 512;

class Handle
{
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.release()) {}
    Handle& operator=(Handle&& other) noexcept
    {
        if (this != &other) reset(other.release());
        return *this;
    }
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
    HANDLE release() { return std::exchange(value_, nullptr); }
    void reset(HANDLE value = nullptr)
    {
        if (*this) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_ = nullptr;
};

inline Handle CreateThreadWithToken(HANDLE process, LPTHREAD_START_ROUTINE procedure, void* argument, HANDLE token)
{
    Handle thread(CreateRemoteThread(process, nullptr, 0, procedure, argument, token ? CREATE_SUSPENDED : 0, nullptr));
    if (!thread || !token) return thread;

    // Assign the creator's startup context before any loader callbacks or observer code can run.
    auto handle = thread.get();
    if (SetThreadToken(&handle, token) && ResumeThread(handle) != DWORD(-1)) return thread;
    auto error = GetLastError();

    // This thread has never run user code or acquired application locks.
    TerminateThread(handle, ERROR_CANCELLED);
    thread.reset();
    SetLastError(error);
    return {};
}

inline std::wstring Wide(const std::string& text)
{
    if (text.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring value(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), value.data(), size);
    return value;
}
inline std::string Utf8(const std::wstring& text)
{
    if (text.empty()) return {};
    int size =
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string value(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), value.data(), size, nullptr, nullptr);
    return value;
}
inline std::wstring ErrorText(DWORD code)
{
    wchar_t buffer[ErrorTextCapacity]{};
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
        buffer, static_cast<DWORD>(std::size(buffer)), nullptr);
    return std::wstring(buffer) + L" (" + std::to_wstring(code) + L")";
}
inline void Check(bool success, const char* operation)
{
    if (!success) throw std::runtime_error(std::string(operation) + ": " + Utf8(ErrorText(GetLastError())));
}
inline USHORT ProcessMachine(HANDLE process)
{
    USHORT machine, native;
    if (!IsWow64Process2(process, &machine, &native)) return IMAGE_FILE_MACHINE_UNKNOWN;
    return machine == IMAGE_FILE_MACHINE_UNKNOWN ? native : machine;
}

inline std::wstring ModuleDirectory()
{
    std::wstring path(ExtendedPathCapacity, L'\0');
    auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    path.resize(size);
    return path.substr(0, path.find_last_of(L"\\/"));
}
}

#pragma once
#include "WinSupport.h"
#include "../spy/SpyProtocol.h"
#include <nlohmann/json.hpp>
#include <array>
#include <map>
#include <memory>
#include <type_traits>

namespace Detourist
{
std::string Hex(uint64_t value);
nlohmann::json ProcessList();
nlohmann::json SpySnapshot();
nlohmann::json SpyWindowInfo(HWND window);
nlohmann::json SpyProperties(DWORD pid, DWORD tid, HWND window);
nlohmann::json SpyPick();

class WindowSpy
{
public:
    WindowSpy() = default;
    ~WindowSpy();
    WindowSpy(const WindowSpy&) = delete;
    WindowSpy& operator=(const WindowSpy&) = delete;
    void Start(DWORD pid, DWORD tid, HWND window, bool children);
    nlohmann::json Poll(bool stop = false);
    void Stop();
private:
    struct ThreadHooks
    {
        Handle thread;
        using Hook = std::unique_ptr<std::remove_pointer_t<HHOOK>,
            decltype([](HHOOK hook) { UnhookWindowsHookEx(hook); })>;
        std::array<Hook, SpyHookCount> hooks;
    };
    void RefreshThreads();
    Handle process_;
    Handle owner_;
    Handle mapping_;
    SpyBuffer* buffer_ = nullptr;
    HMODULE module_ = nullptr;
    std::map<DWORD, ThreadHooks> threads_;
    DWORD pid_ = 0;
    DWORD tid_ = 0;
    DWORD hookError_ = 0;
    uint64_t refresh_ = 0;
    int64_t started_ = 0;
    int64_t frequency_ = 0;
};
}

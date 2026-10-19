#pragma once
#include <windows.h>
#include <cstdint>
#include <cstdio>

namespace Detourist
{
constexpr uint32_t SpyCapacity = 8192;
constexpr uint32_t SpySignature = 0x44535059;
constexpr size_t SpyClassNameCapacity = 64;
constexpr size_t SpyObjectNameCapacity = 96;
constexpr size_t SpyHookCount = 3;
enum class SpyMessageKind : uint32_t { Sent, Returned, PostedRemoved, PostedPeeked };

struct SpyMessage
{
    int64_t clock;
    uint64_t window;
    uint64_t wparam;
    uint64_t lparam;
    uint64_t result;
    uint32_t thread;
    uint32_t message;
    uint32_t kind;
    uint32_t reserved;
    wchar_t className[SpyClassNameCapacity];
};

struct SpyBuffer
{
    uint32_t signature;
    volatile LONG active;
    volatile LONG lock;
    volatile LONG dropped;
    uint32_t read;
    uint32_t write;
    uint64_t window;
    uint32_t children;
    volatile LONG finished;
    SpyMessage messages[SpyCapacity];
};

inline void SpyName(wchar_t (&name)[SpyObjectNameCapacity], DWORD pid, const wchar_t* suffix)
{
    swprintf_s(name, L"Local\\Detourist.WindowSpy.%lu.%s", pid, suffix);
}
}

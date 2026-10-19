#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "SystemHooks.h"
#include <intrin.h>
#include <atomic>

namespace Detourist
{
#define WIN32U_API(name, failure, ...) using Type##name = __VA_ARGS__;
#define WIN32U_UNSUPPORTED(name)
#include "Win32uCatalog.inc"
#undef WIN32U_UNSUPPORTED
#undef WIN32U_API

template<Api Id, class Function> struct Win32uInterop;
template<Api Id, class Result, class... Arguments> struct Win32uInterop<Id, Result (NTAPI*)(Arguments...)>
{
    using Function = Result (NTAPI*)(Arguments...);
    inline static std::atomic<Function> original = nullptr;

    template<class T> static uint64_t Raw(T value)
    {
        if constexpr (std::is_enum_v<T>) return static_cast<uint64_t>(value);
        else
        {
            static_assert(sizeof(T) <= sizeof(uint64_t) && std::is_trivially_copyable_v<T>);
            uint64_t bits = 0;
            memcpy(&bits, &value, sizeof(value));
            return bits;
        }
    }

    template<class T> static T Value(uint64_t bits)
    {
        if constexpr (std::is_enum_v<T>) return static_cast<T>(bits);
        else
        {
            T value{};
            memcpy(&value, &bits, sizeof(value));
            return value;
        }
    }

    template<size_t... Indices> static Result InvokeOriginal(Function function, Call& call,
        std::index_sequence<Indices...>)
    {
        return call.Invoke([&]()
        {
            return function(Value<Arguments>(call.event.arguments[Indices])...);
        });
    }

    static Result NTAPI Invoke(Arguments... arguments)
    {
        auto function = original.load(std::memory_order_acquire);
        if (!NativeThreadReady() || ObserverActive) return function(arguments...);
        Call call(Id, {Raw(arguments)...}, _ReturnAddress());
        if constexpr (std::is_void_v<Result>)
        {
            if (!call.skipped) InvokeOriginal(function, call, std::index_sequence_for<Arguments...>{});
            call.Finish(0, GetLastError());
            SetLastError(call.event.error);
        }
        else
        {
            auto result = call.skipped ? Result{} :
                InvokeOriginal(function, call, std::index_sequence_for<Arguments...>{});
            call.Finish(Raw(result), GetLastError());
            SetLastError(call.event.error);
            return Value<Result>(call.event.result);
        }
    }

    static FARPROC Bind(FARPROC function)
    {
        original.store(reinterpret_cast<Function>(function), std::memory_order_release);
        return reinterpret_cast<FARPROC>(&Invoke);
    }
};

FARPROC Win32uInteropObserver(FARPROC function)
{
    // Resolved CLR pointers retain a native entry without changing system stubs or waiting for module hooks.
    auto module = GetModuleHandleW(L"win32u.dll");
    HMODULE owner = nullptr;
    if (!module || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCWSTR>(function), &owner) ||
        owner != module) return function;
    struct Entry { const char* name; FARPROC (*bind)(FARPROC); };
#define WIN32U_API(name, ...) {#name, &Win32uInterop<Api::name, Type##name>::Bind},
    static constexpr Entry entries[] =
    {
#define WIN32U_UNSUPPORTED(name)
#include "Win32uCatalog.inc"
#undef WIN32U_UNSUPPORTED
    };
#undef WIN32U_API
    for (const auto& entry : entries)
        if (GetProcAddress(module, entry.name) == function) return entry.bind(function);
    return function;
}

bool IsWin32uFailure(Api api, uint64_t result)
{
    constexpr uint32_t Win32uRuleMask = 0xFFu;
    constexpr uint32_t Win32uWidthShift = 8;
    constexpr uint32_t DefaultResultBytes = 8;
    switch (api)
    {
#define WIN32U_API(name, failure, ...) \
    case Api::name: return ExportResultFailed(static_cast<ExportResultRule>(failure & Win32uRuleMask), \
        (failure >> Win32uWidthShift) ? (failure >> Win32uWidthShift) : DefaultResultBytes, result);
#define WIN32U_UNSUPPORTED(name)
#include "Win32uCatalog.inc"
#undef WIN32U_UNSUPPORTED
#undef WIN32U_API
    default: return false;
    }
}

void EmitWin32u(Call& call, Slot* slot, bool leaving)
{
    CaptureBuiltinParameters(call, slot, leaving);
}

void AddWin32uHooks(std::vector<HookDefinition>& hooks)
{
    auto module = ResolveHookModule(L"win32u.dll");
    if (!module) return;

    // Resolve only the already loaded module; graphical dependencies remain under target control.
#define WIN32U_API(name, ...) \
    if (!SystemHook<Api::name, Type##name, false>::original) \
    { \
        auto& original = SystemHook<Api::name, Type##name, false>::original; \
        original = reinterpret_cast<Type##name>(GetProcAddress(module, #name)); \
        if (original) hooks.push_back({Api::name, reinterpret_cast<void**>(&original), \
            reinterpret_cast<void*>(&SystemHook<Api::name, Type##name, false>::Invoke)}); \
    }
#define WIN32U_UNSUPPORTED(name)
#include "Win32uCatalog.inc"
#undef WIN32U_UNSUPPORTED
#undef WIN32U_API
}
}

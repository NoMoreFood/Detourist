#pragma once
#include "Agent.h"
#include <atomic>
#include <intrin.h>

namespace Detourist
{
void PrepareNativeTermination(HANDLE process);

class NativeInvocation
{
public:
    explicit NativeInvocation(const Call& call) : previous_(ObserverActive),
        suppressed_(BroadHooks && !(call.event.flags & Continuation) &&
            (!(ApiDefinitions[static_cast<uint32_t>(call.event.api)].hookFlags & HookWait) || call.internalRuntime))
    {
        if (suppressed_) ObserverActive = true;
    }
    ~NativeInvocation() { if (suppressed_) ObserverActive = previous_; }
private:
    bool previous_, suppressed_;
};

template<class Type> Type SystemValue(uint64_t bits)
{
    static_assert(sizeof(Type) <= sizeof(bits));
    // Forward-declared native enums retain their ABI storage without requiring a complete declaration.
    if constexpr (!std::is_enum_v<Type>) static_assert(std::is_trivially_copyable_v<Type>);
    Type value{};
    memcpy(&value, &bits, sizeof(value));
    return value;
}

template<Api Id, class Function, bool Native> struct SystemHook;
template<Api Id, class Result, class... Arguments, bool Native>
struct SystemHook<Id, Result (WINAPI*)(Arguments...), Native>
{
    using Function = Result (WINAPI*)(Arguments...);
    inline static Function original = nullptr;
    static constexpr bool InvalidatesStackRegions = Id == Api::NtProtectVirtualMemory ||
        Id == Api::NtFreeVirtualMemory || Id == Api::NtUnmapViewOfSection || Id == Api::NtUnmapViewOfSectionEx;

    template<size_t... Indices> static Result InvokeOriginal(Call& call, std::index_sequence<Indices...>)
    {
        if constexpr (Native)
        {
            // The native observer owns the invocation while the instruction engine sees its original entry.
            NativeInvocation invocation(call);
            if constexpr (Id == Api::NtCreateUserProcess)
            {
                ChildLaunch child(call);
                auto result = call.Invoke([&]()
                {
                    return original(SystemValue<Arguments>(call.InvocationArgument(static_cast<uint32_t>(Indices)))...);
                });
                child.Complete(result >= 0);
                return result;
            }
            else return call.Invoke([&]()
            {
                return original(SystemValue<Arguments>(call.InvocationArgument(static_cast<uint32_t>(Indices)))...);
            });
        }
        else return call.Invoke([&]()
        {
            return original(SystemValue<Arguments>(call.event.arguments[Indices])...);
        });
    }

    static Result WINAPI Invoke(Arguments... arguments)
    {
        if (!NativeThreadReady()) return original(arguments...);
        auto policy = ApiDefinitions[static_cast<uint32_t>(Id)].hookFlags;
        if (ObserverActive)
        {
            if constexpr (sizeof...(Arguments))
                if (policy & HookProcessTermination)
                {
                    const uint64_t values[]{Bits(arguments)...};
                    PrepareNativeTermination(reinterpret_cast<HANDLE>(values[0]));
                }
            if constexpr (InvalidatesStackRegions)
            {
                auto result = original(arguments...);
                InvalidateStackImageCache();
                return result;
            }
            else return original(arguments...);
        }
        Call call(Id, {Bits(arguments)...}, _ReturnAddress());

        // Catalog policies release transport ownership before nonreturning context and teardown transfers.
        if (policy & HookContinuation) call.ReleaseForContinuation();
        if constexpr (sizeof...(Arguments))
            if (!call.skipped && (policy & HookProcessTermination))
                PrepareNativeTermination(reinterpret_cast<HANDLE>(call.event.arguments[0]));
        if constexpr (std::is_void_v<Result>)
        {
            if (!call.skipped) InvokeOriginal(call, std::index_sequence_for<Arguments...>{});
            if constexpr (InvalidatesStackRegions) InvalidateStackImageCache();
            call.Finish(0, GetLastError());
            SetLastError(call.event.error);
        }
        else
        {
            auto result = call.skipped ? Result{} : InvokeOriginal(call, std::index_sequence_for<Arguments...>{});
            if constexpr (InvalidatesStackRegions) InvalidateStackImageCache();
            call.Finish(Bits(result), GetLastError());
            SetLastError(call.event.error);
            return SystemValue<Result>(call.event.result);
        }
    }
};
}

#pragma once
#include "CatalogView.h"
#include <unknwn.h>
#include <algorithm>
#include <tuple>
#include <type_traits>

namespace Detourist
{
constexpr uint32_t ExportStackBytes(const ExportSignature& signature, uint32_t count)
{
    uint32_t bytes = 0;
    for (uint32_t index = 0; index < count; ++index)
    {
        if (signature.callingConvention == ExportCallingConvention::Fastcall && index < 2) continue;
        bytes += (std::max(4u, uint32_t{signature.argumentBytes[index]}) + 3u) & ~3u;
    }
    return bytes;
}

template<class Type> constexpr uint8_t ExportValueBytes()
{
    if constexpr (std::is_void_v<Type>) return 0;
    else if constexpr (std::is_reference_v<Type>) return sizeof(void*);
#ifdef _M_IX86
    else if constexpr (sizeof(Type) > UINT8_MAX) return UINT8_MAX;
#else
    else if constexpr (sizeof(Type) > sizeof(uint64_t)) return sizeof(uint64_t);
#endif
    else return sizeof(Type);
}

template<class Function> struct ExportFunction;
template<class Type> consteval bool ExportInterfaceInput()
{
    if constexpr (!std::is_pointer_v<Type>) return false;
    else
    {
        using Interface = std::remove_cv_t<std::remove_pointer_t<Type>>;
        if constexpr (requires { sizeof(Interface); }) return std::is_base_of_v<IUnknown, Interface>;
        else return false;
    }
}

template<class Type> consteval bool ExportInterfaceOutput()
{
    if constexpr (!std::is_pointer_v<Type>) return false;
    else if constexpr (!std::is_pointer_v<std::remove_pointer_t<Type>>) return false;
    else
    {
        using Interface = std::remove_pointer_t<std::remove_pointer_t<Type>>;
        if constexpr (requires { sizeof(Interface); }) return std::is_base_of_v<IUnknown, Interface>;
        else return false;
    }
}

template<class Result, class... Arguments> struct ExportFunction<Result (WINAPI*)(Arguments...)>
{
    using Parameters = std::tuple<Arguments...>;

    static consteval uint32_t InputInterfaces()
    {
        uint32_t mask = 0;
        [[maybe_unused]] uint32_t index = 0;
        ((mask |= ExportInterfaceInput<Arguments>() && index < MaximumArguments ? uint32_t{1} << index : 0,
            ++index), ...);
        return mask;
    }

    static const GUID* InputInterface([[maybe_unused]] uint32_t parameter)
    {
        const GUID* identity = nullptr;
        [[maybe_unused]] uint32_t index = 0;
        ([&]()
        {
            if constexpr (ExportInterfaceInput<Arguments>())
                if (index == parameter) identity = &__uuidof(std::remove_cv_t<std::remove_pointer_t<Arguments>>);
            ++index;
        }(), ...);
        return identity;
    }

    static consteval ExportSignature Signature()
    {
        ExportSignature signature{{ExportValueBytes<Arguments>()...}, 0, ExportValueBytes<Result>(),
            std::is_floating_point_v<Result>, true};
#ifdef _M_IX86
        signature.callingConvention = ExportCallingConvention::Stdcall;
#endif
        [[maybe_unused]] uint32_t index = 0;
        ((signature.floatingArguments |= static_cast<uint8_t>(
            std::is_floating_point_v<Arguments> && index < 4 ? 1u << index : 0), ++index), ...);
        index = 0;
        bool fixedInterface = false;
        ([&]()
        {
            if constexpr (std::is_reference_v<Arguments> &&
                std::is_same_v<std::remove_cvref_t<Arguments>, GUID>)
                signature.interfaceIdIndex = static_cast<uint8_t>(index + 1);
            if constexpr (std::is_same_v<Arguments, void**> || ExportInterfaceOutput<Arguments>())
            {
                signature.interfaceOutputIndex = static_cast<uint8_t>(index + 1);
                using Interface = std::remove_cv_t<std::remove_pointer_t<std::remove_pointer_t<Arguments>>>;
                fixedInterface = ExportInterfaceOutput<Arguments>() && !std::is_same_v<Interface, IUnknown>;
            }
            ++index;
        }(), ...);
        if (fixedInterface) signature.interfaceIdIndex = 0;
        return signature;
    }

    static consteval uint32_t OutputInterfaces()
    {
        uint32_t mask = 0;
        [[maybe_unused]] uint32_t index = 0;
        ((mask |= ExportInterfaceOutput<Arguments>() && index < MaximumArguments ? uint32_t{1} << index : 0,
            ++index), ...);
        return mask;
    }

    static const GUID* OutputInterface([[maybe_unused]] uint32_t parameter)
    {
        const GUID* identity = nullptr;
        [[maybe_unused]] uint32_t index = 0;
        ([&]()
        {
            if constexpr (ExportInterfaceOutput<Arguments>())
                if (index == parameter)
                    identity = &__uuidof(std::remove_pointer_t<std::remove_pointer_t<Arguments>>);
            ++index;
        }(), ...);
        return identity;
    }
};
template<class Result, class... Arguments> struct ExportFunction<Result (__cdecl*)(Arguments..., ...)>
    : ExportFunction<Result (WINAPI*)(Arguments...)>
{
    static consteval ExportSignature Signature()
    {
        auto signature = ExportFunction<Result (WINAPI*)(Arguments...)>::Signature();
#ifdef _M_IX86
        signature.callingConvention = ExportCallingConvention::Cdecl;
#endif
        return signature;
    }
};

#ifdef _M_IX86
template<class Result, class... Arguments> struct ExportFunction<Result (__cdecl*)(Arguments...)>
    : ExportFunction<Result (WINAPI*)(Arguments...)>
{
    static consteval ExportSignature Signature()
    {
        auto signature = ExportFunction<Result (WINAPI*)(Arguments...)>::Signature();
        signature.callingConvention = ExportCallingConvention::Cdecl;
        return signature;
    }
};
template<class Result, class... Arguments> struct ExportFunction<Result (__cdecl*)(Arguments...) noexcept>
    : ExportFunction<Result (__cdecl*)(Arguments...)>
{
};
#endif

template<class Result, class... Arguments> struct ExportFunction<Result (WINAPI*)(Arguments...) noexcept>
    : ExportFunction<Result (WINAPI*)(Arguments...)>
{
};
template<class Owner, class Result, class... Arguments>
struct ExportFunction<Result (STDMETHODCALLTYPE Owner::*)(Arguments...)>
    : ExportFunction<Result (WINAPI*)(Owner*, Arguments...)>
{
};
}


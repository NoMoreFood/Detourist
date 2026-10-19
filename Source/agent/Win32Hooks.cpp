#pragma warning(push)
#pragma warning(disable: 4995 4996)
#include "Win32Headers.inc"
#include "Agent.h"
#include "AuthzArguments.h"
#include "InvokeArguments.h"
#include <detours.h>
#include <intrin.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cstdarg>
#include <delayimp.h>
#include <tuple>
#include <map>
#include <unordered_set>

namespace Detourist
{
constexpr uint64_t MinCallerAddress = 65542;
constexpr LONG MaxDosHeaderOffset = 1024 * 1024;
constexpr uint32_t MaxImportDescriptors = 4096;
constexpr size_t MaxImportThunks = 8192;
constexpr size_t ImportAliasNameCapacity = 64;
constexpr uintptr_t MaxOrdinalValue = 0xFFFF;

bool SharedWin32Export(HMODULE module, FARPROC function)
{
    HMODULE implementation = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(function), &implementation)) return false;
    module = implementation;
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS image{};
    auto base = reinterpret_cast<const BYTE*>(module);
    if (!ReadCaptureMemory(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        !ReadCaptureMemory(base + dos.e_lfanew, &image, sizeof(image)) || image.Signature != IMAGE_NT_SIGNATURE)
        return false;
    auto offset = reinterpret_cast<uintptr_t>(function) - reinterpret_cast<uintptr_t>(base);
    auto extent = image.OptionalHeader.SizeOfImage;
    const auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY exports{};
    if (offset >= extent || !directory.VirtualAddress ||
        uint64_t{directory.VirtualAddress} + sizeof(exports) > extent ||
        !ReadCaptureMemory(base + directory.VirtualAddress, &exports, sizeof(exports)) ||
        uint64_t{exports.AddressOfFunctions} + uint64_t{exports.NumberOfFunctions} * sizeof(DWORD) > extent)
        return false;

    // Late DLLs need separate observers only when multiple exported identities share the same code.
    auto addresses = reinterpret_cast<const DWORD*>(base + exports.AddressOfFunctions);
    bool matched = false;
    for (DWORD index = 0; index < exports.NumberOfFunctions; ++index)
    {
        DWORD address = 0;
        if (!ReadCaptureMemory(addresses + index, &address, sizeof(address))) return false;
        if (address != offset) continue;
        if (matched) return true;
        matched = true;
    }
    return false;
}

template<class T, bool Argument = false> constexpr bool Win32ValueSupported()
{
    if constexpr (std::is_void_v<T> || std::is_reference_v<T>) return true;
    else if constexpr (Argument && std::is_same_v<T, VARIANT>) return true;
    else return sizeof(T) <= sizeof(uint64_t) && std::is_trivially_copyable_v<T>;
}

template<class Type> consteval bool Win32InterfaceOutput()
{
    if constexpr (!std::is_pointer_v<Type> || !std::is_pointer_v<std::remove_pointer_t<Type>>) return false;
    else
    {
        using Interface = std::remove_cv_t<std::remove_pointer_t<std::remove_pointer_t<Type>>>;
        if constexpr (requires { sizeof(Interface); }) return std::is_base_of_v<IUnknown, Interface>;
        else return false;
    }
}

template<class T> uint64_t Win32Bits(const std::type_identity_t<T>& value)
{
    if constexpr (std::is_reference_v<T>) return reinterpret_cast<uint64_t>(&value);
    else if constexpr (std::is_pointer_v<T>) return reinterpret_cast<uint64_t>(value);
    else if constexpr (std::is_same_v<T, VARIANT>) return reinterpret_cast<uint64_t>(&value);
    else
    {
        uint64_t bits = 0;
        memcpy(&bits, &value, sizeof(value));
        return bits;
    }
}

template<class T> T Win32Argument(uint64_t bits)
{
    if constexpr (std::is_reference_v<T>) return *reinterpret_cast<std::remove_reference_t<T>*>(bits);
    else if constexpr (std::is_pointer_v<T>) return reinterpret_cast<T>(bits);
    else if constexpr (std::is_same_v<T, VARIANT>)
    {
        T value{};
        ReadCaptureMemory(reinterpret_cast<const void*>(bits), &value, sizeof(value));
        return value;
    }
    else
    {
        T value{};
        memcpy(&value, &bits, sizeof(value));
        return value;
    }
}

template<Api Id, class Function> struct Win32Hook;
template<Api Id, class Prototype, class Result, class... Arguments> struct Win32HookImplementation
{
    static_assert(sizeof...(Arguments) <= MaximumArguments);
    using Function = Prototype;
    static constexpr bool InterfaceFactory = std::is_same_v<Result, HRESULT> &&
        ((std::is_same_v<Arguments, void**> || std::is_same_v<Arguments, MULTI_QI*>) || ...);
    static constexpr bool TypedInterfaceFactory = std::is_same_v<Result, HRESULT> &&
        (Win32InterfaceOutput<Arguments>() || ...);
    inline static Function original = nullptr;
    inline static std::atomic<Function> interop = nullptr;
    inline static bool availableAtStartup = false;

    static void DiscoverTypedOutputs(uint64_t result, const uint64_t* values)
    {
        [[maybe_unused]] uint32_t index = 0;
        ([&]()
        {
            if constexpr (Win32InterfaceOutput<Arguments>())
            {
                using Interface = std::remove_cv_t<std::remove_pointer_t<std::remove_pointer_t<Arguments>>>;
                DiscoverComOutput(static_cast<HRESULT>(result), values[index], &__uuidof(Interface));
            }
            ++index;
        }(), ...);
    }

    template<size_t... Indices> static Result InvokeOriginal(Call& call, Function function,
        std::index_sequence<Indices...>)
    {
        if constexpr (CreatesChild(Id))
        {
            ChildLaunch child(call);
            auto result = call.Invoke([&]()
            {
                return function(Win32Argument<Arguments>(call.InvocationArgument(static_cast<uint32_t>(Indices)))...);
            });
            child.Complete(result != FALSE);
            return result;
        }
        else
        {
            if constexpr (RpcSerializationApi(Id)) BeginRpcSerialization(Id, call.event.arguments);
            return call.Invoke([&]()
            {
                return function(Win32Argument<Arguments>(call.InvocationArgument(static_cast<uint32_t>(Indices)))...);
            });
        }
    }

    static Result InvokeTarget(Function function, void* caller, Arguments... arguments)
    {
        if (!NativeThreadReady() || ObserverActive)
        {
            if constexpr (RpcSerializationApi(Id)) InvalidateRpcSerialization();
            return function(arguments...);
        }
        Call call(Id, {Win32Bits<Arguments>(arguments)...}, caller);
        if (!call.transport)
        {
            if constexpr (RpcSerializationApi(Id))
            {
                const uint64_t values[]{Win32Bits<Arguments>(arguments)...};
                BeginRpcSerialization(Id, values);
            }
            if constexpr (std::is_void_v<Result>) return function(arguments...);
            else
            {
                auto result = function(arguments...);
                if constexpr (InterfaceFactory || TypedInterfaceFactory || RpcSerializationApi(Id))
                {
                    const uint64_t values[]{Win32Bits<Arguments>(arguments)...};
                    if constexpr (InterfaceFactory) DiscoverWin32ComOutput(Id, Win32Bits<Result>(result), values);
                    if constexpr (TypedInterfaceFactory) DiscoverTypedOutputs(Win32Bits<Result>(result), values);
                    if constexpr (RpcSerializationApi(Id))
                        ObserveRpcSerialization(Id, values, Win32Bits<Result>(result));
                }
                return result;
            }
        }
        DiscoverCatalogInterfaces(call, 0, false);
        if constexpr (std::is_void_v<Result>)
        {
            if (!call.skipped) InvokeOriginal(call, function, std::index_sequence_for<Arguments...>{});
            DiscoverCatalogInterfaces(call, 0, true);
            call.Finish(0, GetLastError());
            SetLastError(call.event.error);
        }
        else
        {
            auto result = call.skipped ? Result{} : InvokeOriginal(call, function,
                std::index_sequence_for<Arguments...>{});
            if constexpr (RpcSerializationApi(Id))
                if (!call.skipped) ObserveRpcSerialization(Id, call.event.arguments, Win32Bits<Result>(result));
            DiscoverCatalogInterfaces(call, Win32Bits<Result>(result), true);
            call.Finish(Win32Bits<Result>(result), GetLastError());
            if constexpr (InterfaceFactory)
                if (!call.skipped) DiscoverWin32ComOutput(Id, call.event.result, call.event.arguments);
            if constexpr (TypedInterfaceFactory)
                if (!call.skipped) DiscoverTypedOutputs(call.event.result, call.event.arguments);
            SetLastError(call.event.error);
            return Win32Argument<Result>(call.event.result);
        }
    }

    static Result WINAPI Invoke(Arguments... arguments)
    {
        return InvokeTarget(original, _ReturnAddress(), arguments...);
    }

    static Result WINAPI InvokeInterop(Arguments... arguments)
    {
        return InvokeTarget(interop.load(std::memory_order_acquire), _ReturnAddress(), arguments...);
    }

    static void Add(std::vector<HookDefinition>& hooks, std::unordered_set<void*>& addresses,
        HMODULE module, const char* name, std::nullptr_t = nullptr)
    {
        if constexpr (Win32ValueSupported<Result>() && (Win32ValueSupported<Arguments, true>() && ...))
        {
            availableAtStartup = module != nullptr;
            if (original || !module) return;
            auto address = GetProcAddress(module, name);
            if (!address) return;
            auto implementation = DetourCodeFromPointer(reinterpret_cast<void*>(address), nullptr);

            // Forwarded exports can share an implementation with an already scheduled hook.
            if (!addresses.insert(implementation).second) return;
            original = reinterpret_cast<Function>(address);
            hooks.push_back(
                {Id, reinterpret_cast<void**>(&original), reinterpret_cast<void*>(&Win32Hook<Id, Function>::Invoke)});
        }
    }

    static FARPROC ResolveInterop(HMODULE module, FARPROC function, bool aliasesOnly)
    {
        if constexpr (Win32ValueSupported<Result>() && (Win32ValueSupported<Arguments, true>() && ...))
        {
            // A skipped direct patch can still be observed through a resolved function pointer.
            if (function == reinterpret_cast<FARPROC>(&Win32Hook<Id, Function>::InvokeInterop) ||
                (original && original != reinterpret_cast<Function>(function))) return function;
            if (aliasesOnly && !availableAtStartup && !SharedWin32Export(module, function)) return function;
            interop.store(reinterpret_cast<Function>(NativeInteropTarget(function)), std::memory_order_release);
            return reinterpret_cast<FARPROC>(&Win32Hook<Id, Function>::InvokeInterop);
        }
        else return function;
    }

    static void Add(std::vector<HookDefinition>& hooks, std::unordered_set<void*>& addresses,
        HMODULE module, const char* name,
        const char* nativeName)
    {
        if (!nativeName || !*nativeName) { Add(hooks, addresses, module, name); return; }
        availableAtStartup = module != nullptr;
        if (!module) return;
        auto address = GetProcAddress(module, name);
        auto native = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), nativeName);

        // A void Win32 facade can share code with an NTSTATUS API used by native Windows callers.
        if (address && native && DetourCodeFromPointer(reinterpret_cast<void*>(address), nullptr) ==
            DetourCodeFromPointer(reinterpret_cast<void*>(native), nullptr))
        {
            using NativeFunction = std::conditional_t<std::is_same_v<Function, Result (WINAPI*)(Arguments...)>,
                LONG (WINAPI*)(Arguments...), LONG (__cdecl*)(Arguments...)>;
            Win32Hook<Id, NativeFunction>::Add(hooks, addresses, module, name);
        }
        else Add(hooks, addresses, module, name);
    }
};
template<Api Id, class Result, class... Arguments> struct Win32Hook<Id, Result (WINAPI*)(Arguments...)>
    : Win32HookImplementation<Id, Result (WINAPI*)(Arguments...), Result, Arguments...>
{
};

#ifdef _M_IX86
template<Api Id, class Result, class... Arguments> struct Win32Hook<Id, Result (__cdecl*)(Arguments...)>
    : Win32HookImplementation<Id, Result (__cdecl*)(Arguments...), Result, Arguments...>
{
    using Base = Win32HookImplementation<Id, Result (__cdecl*)(Arguments...), Result, Arguments...>;
    static Result __cdecl Invoke(Arguments... arguments)
    {
        return Base::InvokeTarget(Base::original, _ReturnAddress(), arguments...);
    }
    static Result __cdecl InvokeInterop(Arguments... arguments)
    {
        return Base::InvokeTarget(Base::interop.load(std::memory_order_acquire), _ReturnAddress(), arguments...);
    }
};
template<Api Id, class Result, class... Arguments> struct Win32Hook<Id, Result (__cdecl*)(Arguments...) noexcept>
    : Win32Hook<Id, Result (__cdecl*)(Arguments...)>
{
};
#endif

template<Api Id, class Result, class... Arguments> struct Win32Hook<Id, Result (WINAPI*)(Arguments...) noexcept>
    : Win32Hook<Id, Result (WINAPI*)(Arguments...)>
{
};

template<> struct Win32Hook<Api::AuthzReportSecurityEvent, decltype(&::AuthzReportSecurityEvent)>
    : Win32Hook<Api::AuthzReportSecurityEvent, BOOL (WINAPI*)(DWORD, AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE,
        DWORD, PSID, DWORD)>
{
    using Base = Win32Hook<Api::AuthzReportSecurityEvent, BOOL (WINAPI*)(DWORD,
        AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE, DWORD, PSID, DWORD)>;

    static BOOL InvokeTarget(Function function, void* caller, DWORD flags,
        AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE provider, DWORD auditId, PSID sid, DWORD count, va_list tail)
    {
        auto error = GetLastError();
        auto status = NativeThreadStatus();
        Event arguments{};
        arguments.arguments[0] = flags;
        arguments.arguments[1] = reinterpret_cast<uint64_t>(provider);
        arguments.arguments[2] = auditId;
        arguments.arguments[3] = reinterpret_cast<uint64_t>(sid);
        arguments.arguments[4] = count;
        auto first = reinterpret_cast<uintptr_t>(tail);
        auto end = reinterpret_cast<uintptr_t>(reinterpret_cast<const NT_TIB*>(NtCurrentTeb())->StackBase);
        auto total = ReadAuditArguments(arguments, end > first ? 5 + (end - first) / sizeof(void*) : 5,
            [&](uint64_t index, uint32_t bytes, uint64_t& value)
        {
            return ReadCaptureMemory(tail + (index - 5) * sizeof(void*), &value, bytes);
        });
        auto captured = static_cast<size_t>(std::min(total, uint64_t{MaximumArguments}));
        SetLastError(error);
        RestoreNativeThreadStatus(status);

        // Only the recorded prefix is editable; all remaining supplied values retain their original ABI slots.
        Call call(Api::AuthzReportSecurityEvent, {arguments.arguments, captured}, caller, {}, arguments.flags);
        auto result = call.Invoke([&]()
        {
            return call.skipped ? 0 : InvokeIntegerArguments(reinterpret_cast<void*>(function),
                call.event.arguments, captured,
                reinterpret_cast<const uint64_t*>(tail + (captured - 5) * sizeof(void*)),
                static_cast<size_t>(total) - captured);
        });
        call.Finish(static_cast<uint32_t>(result), GetLastError());
        SetLastError(call.event.error);
        return static_cast<BOOL>(call.event.result);
    }

    static BOOL __cdecl Invoke(DWORD flags, AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE provider,
        DWORD auditId, PSID sid, DWORD count, ...)
    {
        va_list tail;
        va_start(tail, count);
        auto result = InvokeTarget(original, _ReturnAddress(), flags, provider, auditId, sid, count, tail);
        va_end(tail);
        return result;
    }

    static BOOL __cdecl InvokeInterop(DWORD flags, AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE provider,
        DWORD auditId, PSID sid, DWORD count, ...)
    {
        va_list tail;
        va_start(tail, count);
        auto result = InvokeTarget(interop.load(std::memory_order_acquire), _ReturnAddress(),
            flags, provider, auditId, sid, count, tail);
        va_end(tail);
        return result;
    }

    static void Add(std::vector<HookDefinition>& hooks, std::unordered_set<void*>& addresses,
        HMODULE module, const char* name, const char*)
    {
        auto count = hooks.size();
        Base::Add(hooks, addresses, module, name);
        if (hooks.size() != count) hooks.back().observer = reinterpret_cast<void*>(&Invoke);
    }

    static FARPROC ResolveInterop(HMODULE module, FARPROC function, bool aliasesOnly)
    {
        if (function == reinterpret_cast<FARPROC>(&InvokeInterop)) return function;
        auto resolved = Base::ResolveInterop(module, function, aliasesOnly);
        return resolved == reinterpret_cast<FARPROC>(&Base::InvokeInterop) ?
            reinterpret_cast<FARPROC>(&InvokeInterop) : resolved;
    }
};

Api ImportedWin32Api(Api fallback, void* caller, std::span<const Api> aliases)
{
    if (ObserverActive || !NativeThreadReady()) return fallback;
    ObserverScope observer;
    auto returning = reinterpret_cast<uint64_t>(caller);
    if (returning < MinCallerAddress) return fallback;
    BYTE instruction[6]{};
    int32_t displacement = 0;
    uint64_t slot = 0, thunk = 0;
    if (ReadCaptureMemory(reinterpret_cast<void*>(returning - 6), instruction, 6) &&
        instruction[0] == 0xff && instruction[1] == 0x15)
    {
        memcpy(&displacement, instruction + 2, sizeof(displacement));
        slot = sizeof(void*) == 8 ? returning + displacement : static_cast<uint32_t>(displacement);
    }
    else if (ReadCaptureMemory(reinterpret_cast<void*>(returning - 5), instruction + 1, 5) &&
        instruction[1] == 0xe8)
    {
        memcpy(&displacement, instruction + 2, sizeof(displacement));
        thunk = returning + displacement;
        if (ReadCaptureMemory(reinterpret_cast<void*>(thunk), instruction, 6) &&
            instruction[0] == 0xff && instruction[1] == 0x25)
        {
            memcpy(&displacement, instruction + 2, sizeof(displacement));
            slot = sizeof(void*) == 8 ? thunk + 6 + displacement : static_cast<uint32_t>(displacement);
        }
    }
    MEMORY_BASIC_INFORMATION region{};
    if (!slot || !VirtualQuery(caller, &region, sizeof(region)) || region.Type != MEM_IMAGE) return fallback;
    auto base = reinterpret_cast<uint64_t>(region.AllocationBase);
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS image{};
    if (!ReadCaptureMemory(reinterpret_cast<void*>(base), &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || dos.e_lfanew > MaxDosHeaderOffset ||
        !ReadCaptureMemory(reinterpret_cast<void*>(base + dos.e_lfanew), &image, sizeof(image)) ||
        image.Signature != IMAGE_NT_SIGNATURE || image.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return fallback;
    auto bytes = image.OptionalHeader.SizeOfImage;
    auto read = [&](uint64_t rva, void* destination, size_t count)
    {
        return rva <= bytes && count <= bytes - rva &&
            ReadCaptureMemory(reinterpret_cast<void*>(base + rva), destination, count);
    };
    void* target = nullptr;
    if (returning - 6 < base || returning > base + bytes ||
        thunk && (thunk < base || thunk > base + bytes - 6) ||
        slot < base || !read(slot - base, &target, sizeof(target))) return fallback;

    // An immutable import name and its current target must agree before attributing a shared implementation.
    for (bool delayed : {false, true})
    {
        auto directoryIndex = delayed ? IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT : IMAGE_DIRECTORY_ENTRY_IMPORT;
        if (image.OptionalHeader.NumberOfRvaAndSizes <= static_cast<DWORD>(directoryIndex)) continue;
        auto directory = image.OptionalHeader.DataDirectory[directoryIndex];
        auto stride = delayed ? sizeof(ImgDelayDescr) : sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!directory.VirtualAddress || directory.Size / stride > MaxImportDescriptors) continue;
        for (uint32_t index = 0; index < directory.Size / stride; ++index)
        {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            auto rva = uint64_t{directory.VirtualAddress} + index * stride;
            if (delayed)
            {
                ImgDelayDescr delay{};
                if (!read(rva, &delay, sizeof(delay)) || !delay.rvaDLLName) break;
                if (delay.grAttrs != static_cast<DWORD>(dlattrRva)) continue;
                descriptor.Name = delay.rvaDLLName;
                descriptor.FirstThunk = delay.rvaIAT;
                descriptor.OriginalFirstThunk = delay.rvaINT;
            }
            else if (!read(rva, &descriptor, sizeof(descriptor)) || !descriptor.Name) break;
            auto first = base + descriptor.FirstThunk;
            if (!descriptor.FirstThunk || !descriptor.OriginalFirstThunk ||
                slot < first || (slot - first) % sizeof(void*) ||
                (slot - first) / sizeof(void*) >= MaxImportThunks) continue;
            auto selected = (slot - first) / sizeof(void*);
            IMAGE_THUNK_DATA entry{};
            uint64_t position = 0;
            for (; position <= selected; ++position)
                if (!read(uint64_t{descriptor.OriginalFirstThunk} + position * sizeof(entry), &entry,
                        sizeof(entry)) ||
                    !entry.u1.AddressOfData)
                    break;
            if (position <= selected || IMAGE_SNAP_BY_ORDINAL(entry.u1.Ordinal)) continue;
            for (auto alias : aliases)
            {
                const auto& definition = ApiDefinitions[static_cast<uint32_t>(alias)];
                char name[ImportAliasNameCapacity]{}, library[ImportAliasNameCapacity]{};
                auto nameBytes = strlen(definition.name) + 1, libraryBytes = strlen(definition.module) + 1;
                if (nameBytes > sizeof(name) || libraryBytes > sizeof(library) ||
                    !read(descriptor.Name, library, libraryBytes) || library[libraryBytes - 1] ||
                    _stricmp(library, definition.module) ||
                    !read(entry.u1.AddressOfData + offsetof(IMAGE_IMPORT_BY_NAME, Name), name, nameBytes) ||
                    name[nameBytes - 1] || strcmp(name, definition.name)) continue;
                if (reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA(definition.module), name)) == target)
                    return alias;
            }
        }
    }
    return fallback;
}

template<Api Id, class Character>
    requires (Id == Api::AVISave || Id == Api::AVISaveA || Id == Api::AVISaveW)
struct Win32Hook<Id, HRESULT (__cdecl*)(const Character*, CLSID*, AVISAVECALLBACK, int,
    PAVISTREAM, LPAVICOMPRESSOPTIONS, ...)>
    : Win32Hook<Id, HRESULT (WINAPI*)(const Character*, CLSID*, AVISAVECALLBACK, int,
        PAVISTREAM, LPAVICOMPRESSOPTIONS)>
{
    using Base = Win32Hook<Id, HRESULT (WINAPI*)(const Character*, CLSID*, AVISAVECALLBACK, int,
        PAVISTREAM, LPAVICOMPRESSOPTIONS)>;
    using typename Base::Function;

    static HRESULT InvokeTarget(Function function, Api api, void* caller, const Character* filename,
        CLSID* handler, AVISAVECALLBACK callback, int streams, PAVISTREAM firstStream,
        LPAVICOMPRESSOPTIONS firstOptions, va_list tail)
    {
        auto error = GetLastError();
        auto status = NativeThreadStatus();
        uint64_t arguments[MaximumArguments]{reinterpret_cast<uint64_t>(filename), reinterpret_cast<uint64_t>(handler),
            reinterpret_cast<uint64_t>(callback), static_cast<uint32_t>(streams),
            reinterpret_cast<uint64_t>(firstStream), reinterpret_cast<uint64_t>(firstOptions)};
        auto total = 4 + 2 * static_cast<uint64_t>(std::max(streams, 1));
        auto first = reinterpret_cast<uintptr_t>(tail);
        auto end = reinterpret_cast<uintptr_t>(reinterpret_cast<const NT_TIB*>(NtCurrentTeb())->StackBase);
        total = std::min<uint64_t>(total, end > first ? 6 + (end - first) / sizeof(void*) : 6);
        auto captured = static_cast<uint32_t>(std::min(total, uint64_t{MaximumArguments}));
        for (uint32_t index = 6; index < captured; ++index)
            ReadCaptureMemory(tail + (index - 6) * sizeof(void*), arguments + index, sizeof(void*));
        SetLastError(error);
        RestoreNativeThreadStatus(status);

        // Forward all stream pairs while retaining a bounded, editable prefix for the inspector.
        Call call(api, {arguments, captured}, caller, {}, RawArguments | FormattedArguments |
            (captured << FormattedArgumentShift));
        auto result = call.Invoke([&]()
        {
            return call.skipped ? 0 : InvokeIntegerArguments(reinterpret_cast<void*>(function),
                call.event.arguments, captured,
                reinterpret_cast<const uint64_t*>(tail + (captured - 6) * sizeof(void*)),
                static_cast<size_t>(total) - captured);
        });
        call.Finish(static_cast<uint32_t>(result), GetLastError());
        SetLastError(call.event.error);
        return static_cast<HRESULT>(call.event.result);
    }

    static HRESULT __cdecl Invoke(const Character* filename, CLSID* handler, AVISAVECALLBACK callback,
        int streams, PAVISTREAM firstStream, LPAVICOMPRESSOPTIONS firstOptions, ...)
    {
        va_list tail;
        va_start(tail, firstOptions);
        auto api = Id;
        if constexpr (Id == Api::AVISave)
        {
            constexpr Api aliases[]{Api::AVISave, Api::AVISaveA};
            api = ImportedWin32Api(Id, _ReturnAddress(), aliases);
        }
        auto result = InvokeTarget(Base::original, api, _ReturnAddress(), filename, handler, callback,
            streams, firstStream, firstOptions, tail);
        va_end(tail);
        return result;
    }

    static HRESULT __cdecl InvokeInterop(const Character* filename, CLSID* handler, AVISAVECALLBACK callback,
        int streams, PAVISTREAM firstStream, LPAVICOMPRESSOPTIONS firstOptions, ...)
    {
        va_list tail;
        va_start(tail, firstOptions);
        auto result = InvokeTarget(Base::interop.load(std::memory_order_acquire), Id, _ReturnAddress(),
            filename, handler, callback, streams, firstStream, firstOptions, tail);
        va_end(tail);
        return result;
    }

    static void Add(std::vector<HookDefinition>& hooks, std::unordered_set<void*>& addresses,
        HMODULE module, const char* name, const char*)
    {
        auto count = hooks.size();
        Base::Add(hooks, addresses, module, name);
        if (hooks.size() != count) hooks.back().observer = reinterpret_cast<void*>(&Invoke);
    }

    static FARPROC ResolveInterop(HMODULE module, FARPROC function, bool aliasesOnly)
    {
        if (function == reinterpret_cast<FARPROC>(&InvokeInterop)) return function;
        auto resolved = Base::ResolveInterop(module, function, aliasesOnly);
        return resolved == reinterpret_cast<FARPROC>(&Base::InvokeInterop) ?
            reinterpret_cast<FARPROC>(&InvokeInterop) : resolved;
    }
};

FARPROC Win32InteropObserver(HMODULE module, LPCSTR name, FARPROC function, bool aliasesOnly)
{
    if (reinterpret_cast<uintptr_t>(name) <= MaxOrdinalValue) return function;
    struct Entry
    {
        const char* name;
        Api api;
        FARPROC (*resolve)(HMODULE, FARPROC, bool);
    };
#define WIN32_BINDING(name) \
    {#name, Api::name, &Win32Hook<Api::name, decltype(ResolveWin32Prototype(&::name))>::ResolveInterop},
    static constexpr Entry entries[] =
    {
#include "Win32Bindings.h"
    };
#undef WIN32_BINDING
    auto found = std::lower_bound(std::begin(entries), std::end(entries), name,
        [](const auto& entry, const char* value) { return strcmp(entry.name, value) < 0; });
    if (found == std::end(entries) || strcmp(found->name, name) ||
        module != GetModuleHandleA(ApiDefinitions[static_cast<uint32_t>(found->api)].module)) return function;

    // Shared implementations and late-loaded DLLs retain the name used to resolve each export.
    return found->resolve(module, function, aliasesOnly);
}

void AddWin32Hooks(std::vector<HookDefinition>& hooks)
{
    struct Entry
    {
        Api api;
        void (*add)(std::vector<HookDefinition>&, std::unordered_set<void*>&, HMODULE, const char*, const char*);
    };
#define WIN32_BINDING(name) \
    {Api::name, &Win32Hook<Api::name, decltype(ResolveWin32Prototype(&::name))>::Add},
    static constexpr Entry entries[] =
    {
#include "Win32Bindings.h"
    };
#undef WIN32_BINDING

    // Resolve each scheduled implementation once when deduplicating forwarded exports.
    std::unordered_set<void*> addresses;
    addresses.reserve(hooks.size() + std::size(entries));
    for (const auto& hook : hooks) addresses.insert(DetourCodeFromPointer(*hook.original, nullptr));

    // Resolve catalog DLLs once; bindings contain only the C++ types required by their adapters.
    std::map<std::string, std::vector<const Entry*>> modules;
    for (const auto& entry : entries)
        modules[ApiDefinitions[static_cast<uint32_t>(entry.api)].module].push_back(&entry);
    for (const auto& [name, bindings] : modules)
    {
        auto module = ResolveHookModule(Wide(name).c_str());
        for (auto entry : bindings)
        {
            const auto& definition = ApiDefinitions[static_cast<uint32_t>(entry->api)];
            entry->add(hooks, addresses, module, definition.name, definition.nativeName);
        }
    }
}
}
#pragma warning(pop)

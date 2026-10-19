#include "Agent.h"
#include "ComCaptureValues.h"
#include "ExportFunction.h"
#include "InvokeArguments.h"
#include <objbase.h>
#include <oaidl.h>
#include <roapi.h>
#include <winstring.h>
#include <intrin.h>
#include <atomic>
#include <algorithm>
#include <cstdio>
#include <memory>

namespace Detourist
{
constexpr uint64_t MaxMultiQiInterfaces = 65536;
constexpr DWORD MaxCoCreateMultiQi = 1024;
constexpr uint32_t IUnknownSlotCount = 3;
constexpr size_t MaxBuiltinComSlots = 7;
constexpr size_t GuidStringCapacity = 40;
constexpr size_t GuidStringChars = 38;
constexpr size_t VariantDescriptionCapacity = 96;

#define COM_EXPORT(name) decltype(&::name) Original##name = nullptr;
#define COM_METHOD(id, owner, slot, ...)
#include "ComCatalog.inc"
#undef COM_EXPORT
#undef COM_METHOD
std::atomic<decltype(&::WindowsGetStringRawBuffer)> OriginalWindowsGetStringRawBuffer = nullptr;

template<class T> bool ComValue(uint64_t address, T& output)
{
    __try
    {
        if (!address) return false;
        output = *reinterpret_cast<const T*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

struct ComMethodInvocation;
[[msvc::no_tls_guard]] constinit thread_local ComMethodInvocation* CurrentComInvocation = nullptr;
struct ComMethodInvocation
{
    void* original;
    uint32_t slot;
    uint64_t caller;
    ComMethodInvocation* previous = CurrentComInvocation;
    ~ComMethodInvocation() { CurrentComInvocation = previous; }
};

void InvokeComMethodObserver(const ComMethodObserver& observer, void* original, uint32_t slot, uint64_t caller,
    const uint64_t* arguments, NativeCallResult* result, uint32_t argumentSlots)
{
    // A cached entry and an invocation already in progress retain their original implementation.
    ComMethodInvocation invocation{original, slot, caller};
    CurrentComInvocation = &invocation;
    InvokeNativeArguments(observer.entry, arguments, argumentSlots ? argumentSlots :
        std::max(observer.argumentCount, 4u), result, observer.signature.floatingResult ?
            observer.signature.resultBytes : 0);
}

void* OriginalComMethod(uint32_t index)
{
    return CurrentComInvocation && CurrentComInvocation->slot == index ? CurrentComInvocation->original : nullptr;
}

template<class R, class... Args, size_t... Indices>
R InvokeComMethod(Call& call, uint32_t slot, std::index_sequence<Indices...>)
{
    auto instance = Argument<void*>(call, 0);
    auto method = reinterpret_cast<R (STDMETHODCALLTYPE*)(void*, Args...)>(OriginalComMethod(slot));
    auto result = call.Invoke([&]()
    {
        return call.skipped ? R{} : method ? method(instance, Argument<Args>(call, Indices + 1)...) :
            static_cast<R>(E_UNEXPECTED);
    });
    auto error = GetLastError();
    call.Finish(Bits(result), error);
    SetLastError(call.event.error);
    return static_cast<R>(call.event.result);
}

void DiscoverComInterface(void* instance, const IID& iid);
void DiscoverComOutput(HRESULT result, uint64_t output, const IID* iid);
void DiscoverAutomation(uint64_t address, bool input, uint32_t count = 0);

template<class R = HRESULT, class... Args>
R RecordComMethod(Api api, uint32_t slot, void* instance, void* caller, Args... args)
{
    if (!NativeThreadReady() || ObserverActive)
    {
        auto original = reinterpret_cast<R (STDMETHODCALLTYPE*)(void*, Args...)>(OriginalComMethod(slot));
        return original ? original(instance, args...) : static_cast<R>(E_UNEXPECTED);
    }
    if (CurrentComInvocation) caller = reinterpret_cast<void*>(CurrentComInvocation->caller);
    Call call(api, {Bits(instance), Bits(args)...}, caller);
    if (api == Api::ComInvoke && !call.skipped) DiscoverAutomation(call.event.arguments[5], true);
    auto result = InvokeComMethod<R, Args...>(call, slot, std::index_sequence_for<Args...>{});
    if constexpr (std::is_same_v<R, HRESULT>)
    {
        if (call.skipped) return result;
        switch (api)
        {
        case Api::ComQueryInterface:
            DiscoverComOutput(result, call.event.arguments[2], Argument<const IID*>(call, 1)); break;
        case Api::ComCreateInstance:
            DiscoverComOutput(result, call.event.arguments[3], Argument<const IID*>(call, 2)); break;
        case Api::ComGetTypeInfo:
            DiscoverComOutput(result, call.event.arguments[3], &__uuidof(ITypeInfo)); break;
        case Api::ComActivateInstance:
            DiscoverComOutput(result, call.event.arguments[1], &__uuidof(IInspectable)); break;
        case Api::ComEnumVariantClone:
            DiscoverComOutput(result, call.event.arguments[1], &__uuidof(IEnumVARIANT)); break;
        case Api::ComEnumVariantNext:
        {
            auto count = AutomationFetched(call.event.arguments[1], call.event.arguments[3], call.event.result);
            if (count) DiscoverAutomation(call.event.arguments[2], false, count);
            break;
        }
        case Api::ComInvoke:
        {
            if (SUCCEEDED(result)) DiscoverAutomation(call.event.arguments[6], false);
            break;
        }
        default: break;
        }
    }
    return result;
}

void DiscoverAutomation(uint64_t address, bool input, uint32_t count)
{
    if (!NativeThreadReady() || ObserverActive) return;
    ObserverScope observer;
    AcquireSRWLockShared(&CaptureLock);
    bool active = ActiveTransport && !ActiveTransport->Header()->stop &&
        (ActiveTransport->Header()->enabledFilters & ComApis);
    ReleaseSRWLockShared(&CaptureLock);
    if (active)
    {
        auto observe = [](void* instance, const GUID& iid) { DiscoverComInterface(instance, iid); };
        if (count) ForEachAutomationElement(address, count, observe);
        else if (input) ForEachAutomationInput(address, observe);
        else ForEachAutomationInterface(address, observe);
    }
}

void DiscoverComOutput(HRESULT result, uint64_t output, const IID* iid)
{
    if (FAILED(result) || !NativeThreadReady() || ObserverActive) return;
    ObserverScope observer;
    AcquireSRWLockShared(&CaptureLock);
    bool active = ActiveTransport && !ActiveTransport->Header()->stop;
    ReleaseSRWLockShared(&CaptureLock);

    // Discovery follows returned references without adding calls or changing object identity.
    void* instance = nullptr;
    IID identity{};
    if (active && ComValue(output, instance) && instance && ComValue(Bits(iid), identity))
        DiscoverComInterface(instance, identity);
}

void DiscoverWin32ComOutput(Api api, uint64_t result, const uint64_t* arguments)
{
    if (FAILED(static_cast<HRESULT>(result))) return;
    uint64_t count = 0, address = 0;
    switch (api)
    {
    case Api::OleCreateFontIndirect:
        DiscoverComOutput(static_cast<HRESULT>(result), arguments[2],
            reinterpret_cast<const IID*>(arguments[1]));
        return;
    case Api::OleCreatePictureIndirect: case Api::OleLoad:
        DiscoverComOutput(static_cast<HRESULT>(result), arguments[3],
            reinterpret_cast<const IID*>(arguments[1]));
        return;
    case Api::OleCreateDefaultHandler:
        DiscoverComOutput(static_cast<HRESULT>(result), arguments[3],
            reinterpret_cast<const IID*>(arguments[2]));
        return;
    case Api::OleLoadPicture:
        DiscoverComOutput(static_cast<HRESULT>(result), arguments[4],
            reinterpret_cast<const IID*>(arguments[3]));
        return;
    case Api::OleLoadPictureEx:
        DiscoverComOutput(static_cast<HRESULT>(result), arguments[7],
            reinterpret_cast<const IID*>(arguments[3]));
        return;
    case Api::OleLoadPicturePath:
        DiscoverComOutput(static_cast<HRESULT>(result), arguments[5],
            reinterpret_cast<const IID*>(arguments[4]));
        return;
    case Api::DXGIGetDebugInterface1:
        DiscoverComOutput(static_cast<HRESULT>(result), arguments[2],
            reinterpret_cast<const IID*>(arguments[1]));
        return;
    case Api::CoGetObject:
        DiscoverComOutput(static_cast<HRESULT>(result), arguments[3],
            reinterpret_cast<const IID*>(arguments[2]));
        return;
    case Api::CoGetObjectContext:
        DiscoverComOutput(static_cast<HRESULT>(result), arguments[1],
            reinterpret_cast<const IID*>(arguments[0]));
        return;
    case Api::CoCreateInstanceFromApp: count = arguments[4]; address = arguments[5]; break;
    case Api::CoGetInstanceFromFile: count = arguments[6]; address = arguments[7]; break;
    case Api::CoGetInstanceFromIStorage: count = arguments[5]; address = arguments[6]; break;
    default: return;
    }
    count = std::min<uint64_t>(count, MaxMultiQiInterfaces);
    if (!address || address > UINT64_MAX - count * sizeof(MULTI_QI) ||
        !NativeThreadReady() || ObserverActive) return;
    ObserverScope observer;
    AcquireSRWLockShared(&CaptureLock);
    bool active = ActiveTransport && !ActiveTransport->Header()->stop;
    ReleaseSRWLockShared(&CaptureLock);
    if (!active) return;

    // Follow each successful result without reentering the public hook or changing caller error state.
    for (uint64_t index = 0; index < count; ++index)
    {
        MULTI_QI requested{};
        if (!ComValue(address + index * sizeof(MULTI_QI), requested)) break;
        if (SUCCEEDED(requested.hr) && requested.pItf)
        {
            IID iid{};
            if (ComValue(Bits(requested.pIID), iid)) DiscoverComInterface(requested.pItf, iid);
        }
    }
}

template<class T>
using ComArgument = std::conditional_t<std::is_reference_v<T>, std::add_pointer_t<std::remove_reference_t<T>>, T>;

template<Api api, uint32_t slot, class Method> struct ComMethodThunk;
template<Api api, uint32_t slot, class Owner, class R, class... Args>
struct ComMethodThunk<api, slot, R (STDMETHODCALLTYPE Owner::*)(Args...)>
{
    static R STDMETHODCALLTYPE Invoke(void* instance, ComArgument<Args>... args)
    {
        return RecordComMethod<R>(api, slot, instance, _ReturnAddress(), args...);
    }
};

void DiscoverComInterface(void* instance, const IID& iid)
{
    void** table = nullptr;
    if (!ComValue(Bits(instance), table) || !table) return;
    const ComMethodObserver* observers[MaxBuiltinComSlots]{};
    uint32_t count = IUnknownSlotCount;
    struct Entry { const GUID* owner; uint32_t slot; ComMethodObserver observer; };
    static const Entry methods[] =
    {
#define COM_EXPORT(name)
#define COM_METHOD(id, owner, slot, ...) {&__uuidof(owner), slot, {Api::id, \
    reinterpret_cast<void*>(&ComMethodThunk<Api::id, slot, __VA_ARGS__>::Invoke), \
    ExportFunction<decltype(&ComMethodThunk<Api::id, slot, __VA_ARGS__>::Invoke)>::Signature(), \
    static_cast<uint32_t>(std::tuple_size_v<ExportFunction<__VA_ARGS__>::Parameters>)}},
#include "ComCatalog.inc"
#undef COM_EXPORT
#undef COM_METHOD
    };

    // Select declared slots while retaining the inherited IUnknown and IInspectable prefixes.
    for (const auto& method : methods)
    {
        if (method.slot < IUnknownSlotCount || iid == *method.owner ||
            (iid == __uuidof(IActivationFactory) && *method.owner == __uuidof(IInspectable)))
        {
            observers[method.slot] = &method.observer;
            count = std::max(count, method.slot + 1);
        }
    }

    // Declared tails share catalog capture rules; callback interfaces retain their own first slots.
    AcquireSRWLockShared(&CaptureLock);
    std::unique_ptr<SRWLOCK, decltype(&ReleaseSRWLockShared)> lock(&CaptureLock, &ReleaseSRWLockShared);
    if (!ActiveTransport || ActiveTransport->Header()->stop || BroadHooks) return;
    const auto& catalog = ActiveTransport->Catalog();
    auto end = catalog.Interfaces() + catalog.Header()->interfaceCount;
    auto contract = std::lower_bound(catalog.Interfaces(), end, iid, [](const auto& candidate, const GUID& identity)
    {
        return memcmp(&candidate.iid, &identity, sizeof(GUID)) < 0;
    });
    if (contract == end || contract->iid != iid) contract = nullptr;
    if (contract)
    {
        const char* prefix[]{"QueryInterface", "AddRef", "Release"};
        bool unknown = contract->slotCount >= std::size(prefix);
        for (uint32_t slot = 0; unknown && slot < std::size(prefix); ++slot)
        {
            auto plan = catalog.Slots()[contract->firstSlot + slot];
            unknown = plan < catalog.Header()->planCount &&
                !strcmp(catalog.Text(catalog.Plans()[plan].name), prefix[slot]);
        }
        if (!unknown) count = 0;
    }
    AddComMethodHooks(table, iid, catalog, contract, {observers, count});
}

void ForgetComModule(HMODULE module, size_t size)
{
    auto first = reinterpret_cast<uintptr_t>(module);
    auto last = first + size;

    auto stringReader = reinterpret_cast<uintptr_t>(OriginalWindowsGetStringRawBuffer.load(std::memory_order_acquire));
    if (stringReader >= first && stringReader < last)
        OriginalWindowsGetStringRawBuffer.store(nullptr, std::memory_order_release);
    ForgetComMethodModule(module, size);
}

template<class T> T ComResult(Call& call, T result)
{
    auto error = GetLastError();
    call.Finish(Bits(result), error);
    SetLastError(call.event.error);
    return static_cast<T>(call.event.result);
}

#define COM_ARG(type, index) Argument<type>(call, index)
HRESULT WINAPI HookCoCreateInstance(REFCLSID classId, IUnknown* outer, DWORD context, REFIID iid, void** output)
{
    if (!NativeThreadReady() || ObserverActive) return OriginalCoCreateInstance(classId, outer, context, iid, output);
    Call call(Api::CoCreateInstance, {Bits(&classId), Bits(outer), context, Bits(&iid), Bits(output)},
        _ReturnAddress());
    auto result = call.Invoke([&]()
    {
        return call.skipped ? S_OK : OriginalCoCreateInstance(*COM_ARG(const CLSID*, 0),
            COM_ARG(IUnknown*, 1), COM_ARG(DWORD, 2), *COM_ARG(const IID*, 3), COM_ARG(void**, 4));
    });
    if (!call.skipped) DiscoverComOutput(result, call.event.arguments[4], COM_ARG(const IID*, 3));
    return ComResult(call, result);
}

HRESULT WINAPI HookCoCreateInstanceEx(REFCLSID classId, IUnknown* outer, DWORD context,
    COSERVERINFO* server, DWORD count, MULTI_QI* results)
{
    if (!NativeThreadReady() || ObserverActive)
        return OriginalCoCreateInstanceEx(classId, outer, context, server, count, results);
    Call call(Api::CoCreateInstanceEx, {Bits(&classId), Bits(outer), context, Bits(server), count, Bits(results)},
        _ReturnAddress());
    auto result = call.Invoke([&]()
    {
        return call.skipped ? S_OK : OriginalCoCreateInstanceEx(*COM_ARG(const CLSID*, 0),
            COM_ARG(IUnknown*, 1), COM_ARG(DWORD, 2), COM_ARG(COSERVERINFO*, 3),
            COM_ARG(DWORD, 4), COM_ARG(MULTI_QI*, 5));
    });
    if (!call.skipped && SUCCEEDED(result))
    {
        auto values = COM_ARG(MULTI_QI*, 5);
        for (uint32_t index = 0; index < std::min<DWORD>(COM_ARG(DWORD, 4), MaxCoCreateMultiQi); ++index)
        {
            MULTI_QI value{};
            if (!ComValue(Bits(values + index), value)) break;
            DiscoverComOutput(value.hr, Bits(&value.pItf), value.pIID);
        }
    }
    return ComResult(call, result);
}

HRESULT WINAPI HookCoGetClassObject(REFCLSID classId, DWORD context, LPVOID reserved, REFIID iid, void** output)
{
    if (!NativeThreadReady() || ObserverActive)
        return OriginalCoGetClassObject(classId, context, reserved, iid, output);
    Call call(Api::CoGetClassObject, {Bits(&classId), context, Bits(reserved), Bits(&iid), Bits(output)},
        _ReturnAddress());
    auto result = call.Invoke([&]()
    {
        return call.skipped ? S_OK : OriginalCoGetClassObject(*COM_ARG(const CLSID*, 0),
            COM_ARG(DWORD, 1), COM_ARG(LPVOID, 2), *COM_ARG(const IID*, 3), COM_ARG(void**, 4));
    });
    if (!call.skipped) DiscoverComOutput(result, call.event.arguments[4], COM_ARG(const IID*, 3));
    return ComResult(call, result);
}

HRESULT WINAPI HookRoGetActivationFactory(HSTRING name, REFIID iid, void** output)
{
    if (!NativeThreadReady() || ObserverActive) return OriginalRoGetActivationFactory(name, iid, output);
    Call call(Api::RoGetActivationFactory, {Bits(name), Bits(&iid), Bits(output)}, _ReturnAddress());
    auto result = call.Invoke([&]()
    {
        return call.skipped ? S_OK : OriginalRoGetActivationFactory(COM_ARG(HSTRING, 0),
            *COM_ARG(const IID*, 1), COM_ARG(void**, 2));
    });
    if (!call.skipped) DiscoverComOutput(result, call.event.arguments[2], COM_ARG(const IID*, 1));
    return ComResult(call, result);
}

HRESULT WINAPI HookRoActivateInstance(HSTRING name, IInspectable** output)
{
    if (!NativeThreadReady() || ObserverActive) return OriginalRoActivateInstance(name, output);
    Call call(Api::RoActivateInstance, {Bits(name), Bits(output)}, _ReturnAddress());
    auto result = call.Invoke([&]()
    {
        return call.skipped ? S_OK : OriginalRoActivateInstance(COM_ARG(HSTRING, 0), COM_ARG(IInspectable**, 1));
    });
    if (!call.skipped) DiscoverComOutput(result, call.event.arguments[1], &__uuidof(IInspectable));
    return ComResult(call, result);
}
#undef COM_ARG

void CaptureComGuid(Call& call, Slot* slot, uint32_t index, uint64_t address)
{
    GUID id{};
    if (!ComValue(address, id))
    {
        CopyValue(slot, call.transport->Header(), index, ValueKind::Bytes, address, sizeof(GUID));
        return;
    }
    wchar_t text[GuidStringCapacity]{};
    swprintf_s(text, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", id.Data1, id.Data2, id.Data3,
        id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3], id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
    CopyValue(slot, call.transport->Header(), index, ValueKind::Utf16, Bits(text), GuidStringChars * sizeof(wchar_t));
}

void CaptureComString(Call& call, Slot* slot, uint32_t index, HSTRING value)
{
    auto read = OriginalWindowsGetStringRawBuffer.load(std::memory_order_acquire);
    if (!read || !value) return;
    __try
    {
        UINT32 length = 0;
        auto data = read(value, &length);
        CopyValue(slot, call.transport->Header(), index, ValueKind::Utf16, Bits(data), uint64_t{length} * 2);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

void CaptureComVariant(Call& call, Slot* slot, uint32_t index, uint64_t address)
{
    auto header = call.transport->Header();
    CopyValue(slot, header, index, ValueKind::Bytes, address, sizeof(VARIANT));
    VARIANT value{};
    if (!ComValue(address, value)) return;
    if (value.vt & VT_ARRAY || value.vt == (VT_VARIANT | VT_BYREF))
        CaptureAutomationArrays(slot, header, index, address);
    wchar_t description[VariantDescriptionCapacity]{};
    switch (value.vt)
    {
    case VT_EMPTY: swprintf_s(description, L"VT_EMPTY"); break;
    case VT_NULL: swprintf_s(description, L"VT_NULL"); break;
    case VT_I1: swprintf_s(description, L"VT_I1: %d", value.cVal); break;
    case VT_UI1: swprintf_s(description, L"VT_UI1: %u", value.bVal); break;
    case VT_I2: swprintf_s(description, L"VT_I2: %d", value.iVal); break;
    case VT_UI2: swprintf_s(description, L"VT_UI2: %u", value.uiVal); break;
    case VT_I4: case VT_INT: swprintf_s(description, L"VT_I4: %ld", value.lVal); break;
    case VT_UI4: case VT_UINT: swprintf_s(description, L"VT_UI4: %lu", value.ulVal); break;
    case VT_I8: swprintf_s(description, L"VT_I8: %lld", value.llVal); break;
    case VT_UI8: swprintf_s(description, L"VT_UI8: %llu", value.ullVal); break;
    case VT_R4: swprintf_s(description, L"VT_R4: %.9g", static_cast<double>(value.fltVal)); break;
    case VT_R8: swprintf_s(description, L"VT_R8: %.17g", value.dblVal); break;
    case VT_BOOL: swprintf_s(description, L"VT_BOOL: %ls", value.boolVal ? L"true" : L"false"); break;
    case VT_ERROR: swprintf_s(description, L"VT_ERROR: 0x%08lX", static_cast<ULONG>(value.scode)); break;
    default: break;
    }
    if (description[0]) CopyValue(slot, header, index, ValueKind::Utf16, Bits(description),
        wcslen(description) * sizeof(wchar_t));
    CaptureComVariantReference(slot, header, index, value);
}

void EmitCom(Call& call, Slot* slot, bool leaving)
{
    CaptureComValues(call, slot, call.event.api, leaving, call.event.arguments[1]);
}

void AddComHooks(std::vector<HookDefinition>& hooks, HMODULE module)
{
    if (!module) return;
#define COM_EXPORT(name) \
    if (!Original##name) \
    { \
        Original##name = reinterpret_cast<decltype(Original##name)>(GetProcAddress(module, #name)); \
        if (Original##name) hooks.push_back({Api::name, reinterpret_cast<void**>(&Original##name), \
            reinterpret_cast<void*>(&Hook##name)}); \
    }
#define COM_METHOD(id, owner, slot, ...)
#include "ComCatalog.inc"
#undef COM_EXPORT
#undef COM_METHOD
    if (!OriginalWindowsGetStringRawBuffer.load(std::memory_order_acquire))
        OriginalWindowsGetStringRawBuffer.store(reinterpret_cast<decltype(&::WindowsGetStringRawBuffer)>(
            GetProcAddress(module, "WindowsGetStringRawBuffer")), std::memory_order_release);
}
}

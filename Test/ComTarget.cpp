#include <windows.h>
#include <objbase.h>
#include <oaidl.h>
#include <roapi.h>
#include <winstring.h>
#include <windows.foundation.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.Numerics.h>
#include <d2d1.h>
#include <d3d11.h>
#include <d3d12.h>
#include <dxgi1_4.h>
#include <dwrite.h>
#include <wrl/client.h>
#include <shobjidl.h>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <thread>
#include <vector>
#include <cstdio>

class PrivateSequentialStream final : public ISequentialStream
{
public:
    __declspec(noinline) HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == __uuidof(IUnknown) || iid == __uuidof(ISequentialStream) ? this : nullptr;
        return *output ? S_OK : E_NOINTERFACE;
    }
    __declspec(noinline) ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    __declspec(noinline) ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE Read(void* buffer, ULONG bytes, ULONG* read) override
    {
        if (!buffer || bytes < sizeof(uint32_t) || !read) return E_INVALIDARG;
        uint32_t value = 0x51A17E01;
        memcpy(buffer, &value, sizeof(value));
        *read = sizeof(value);
        return S_OK;
    }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE Write(const void* buffer, ULONG bytes, ULONG* written) override
    {
        uint32_t value = 0;
        if (!buffer || bytes != sizeof(value) || !written) return E_INVALIDARG;
        memcpy(&value, buffer, sizeof(value));
        *written = bytes;
        return value == 0xDEADBEEF ? S_OK : E_FAIL;
    }
private:
    ULONG references_ = 1;
};

class OpaqueMenuContext final : public IContextMenu
{
public:
    __declspec(noinline) HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == __uuidof(IUnknown) || iid == __uuidof(IContextMenu) ?
            static_cast<IContextMenu*>(this) : nullptr;
        if (*output) AddRef();
        return *output ? S_OK : E_NOINTERFACE;
    }
    __declspec(noinline) ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    __declspec(noinline) ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE QueryContextMenu(HMENU menu, UINT index, UINT first,
        UINT last, UINT flags) override
    {
        return IsMenu(menu) && !index && first == 1 && last == 2 && !flags ? HRESULT{1} : E_INVALIDARG;
    }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE InvokeCommand(LPCMINVOKECOMMANDINFO) override
    {
        return E_NOTIMPL;
    }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE GetCommandString(UINT_PTR, UINT, UINT*, LPSTR, UINT) override
    {
        return E_NOTIMPL;
    }
private:
    ULONG references_ = 1;
};

bool OpaqueMenuWorkload()
{
    // A real SDK interface call passes a menu handle without granting access to its address as memory.
    OpaqueMenuContext object;
    IContextMenu* context = nullptr;
    if (FAILED(object.QueryInterface(__uuidof(IContextMenu), reinterpret_cast<void**>(&context)))) return false;
    auto menu = CreatePopupMenu();
    auto result = menu ? context->QueryContextMenu(menu, 0, 1, 2, 0) : E_FAIL;
    if (menu) DestroyMenu(menu);
    context->Release();
    return result == HRESULT{1};
}

bool PrivateInterfaceWorkload()
{
    // This object reaches no factory or SDK input boundary before its first interface method executes.
    PrivateSequentialStream object;
    ISequentialStream* stream = &object;
    uint32_t output = 0, input = 0xDEADBEEF;
    ULONG read = 0, written = 0;
    return SUCCEEDED(stream->Read(&output, sizeof(output), &read)) && output == 0x51A17E01 && read == sizeof(output) &&
        SUCCEEDED(stream->Write(&input, sizeof(input), &written)) && written == sizeof(input) &&
        stream->AddRef() == 2 && stream->Release() == 1;
}

class NonComPrimary
{
public:
    __declspec(noinline) virtual ULONG Marker() { return 0x12345678; }
};

class VirtualSequentialStream final : public NonComPrimary, public virtual ISequentialStream, public virtual IPersist
{
public:
    __declspec(noinline) HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid == __uuidof(IUnknown) || iid == __uuidof(ISequentialStream))
            *output = static_cast<ISequentialStream*>(this);
        else if (iid == __uuidof(IPersist)) *output = static_cast<IPersist*>(this);
        return *output ? S_OK : E_NOINTERFACE;
    }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE GetClassID(CLSID* value) override
    {
        if (!value) return E_POINTER;
        *value = __uuidof(ISequentialStream);
        return S_OK;
    }
    __declspec(noinline) ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    __declspec(noinline) ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE Read(void* buffer, ULONG bytes, ULONG* read) override
    {
        if (!buffer || bytes < sizeof(uint32_t) || !read) return E_INVALIDARG;
        uint32_t value = 0x73A17E02;
        memcpy(buffer, &value, sizeof(value));
        *read = sizeof(value);
        return S_OK;
    }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE Write(const void* buffer, ULONG bytes, ULONG* written) override
    {
        uint32_t value = 0;
        if (!buffer || bytes != sizeof(value) || !written) return E_INVALIDARG;
        memcpy(&value, buffer, sizeof(value));
        *written = bytes;
        return value == 0xC0FFEE12 ? S_OK : E_FAIL;
    }
private:
    ULONG references_ = 1;
};

bool PrivateVirtualWorkload()
{
    // An unrelated primary vtable must not be mistaken for the virtual COM subobject.
    VirtualSequentialStream object;
    ISequentialStream* stream = &object;
    NonComPrimary* primary = &object;
    IPersist* persist = &object;
    CLSID identity{};
    uint32_t output = 0, input = 0xC0FFEE12;
    ULONG read = 0, written = 0;
    return SUCCEEDED(persist->GetClassID(&identity)) && identity == __uuidof(ISequentialStream) &&
        primary->Marker() == 0x12345678 &&
        SUCCEEDED(stream->Read(&output, sizeof(output), &read)) && output == 0x73A17E02 && read == sizeof(output) &&
        SUCCEEDED(stream->Write(&input, sizeof(input), &written)) && written == sizeof(input) &&
        stream->AddRef() == 2 && stream->Release() == 1;
}

class ProjectedStringable : public NonComPrimary,
    public winrt::implements<ProjectedStringable, winrt::Windows::Foundation::IStringable>
{
public:
    __declspec(noinline) winrt::hstring ToString() { return L"Private projected WinRT capture"; }
};

__declspec(noinline) bool InvokeProjectedStringable(const winrt::Windows::Foundation::IStringable& object)
{
    return object.ToString() == L"Private projected WinRT capture";
}

bool PrivateProjectedWorkload()
{
    // A local projected implementation reaches its first ABI call without activation or interface queries.
    auto object = winrt::make<ProjectedStringable>();
    auto implementation = winrt::get_self<ProjectedStringable>(object);
    NonComPrimary* primary = implementation;
    return primary->Marker() == 0x12345678 && InvokeProjectedStringable(object);
}

template<class Type> class ProjectedReference : public NonComPrimary,
    public winrt::implements<ProjectedReference<Type>, winrt::Windows::Foundation::IReference<Type>>
{
public:
    explicit ProjectedReference(Type value) : value_(std::move(value)) {}
    __declspec(noinline) Type Value() { return value_; }
private:
    Type value_;
};

class ProjectedVectorView : public NonComPrimary,
    public winrt::implements<ProjectedVectorView,
        winrt::Windows::Foundation::Collections::IVectorView<int32_t>>
{
public:
    __declspec(noinline) int32_t GetAt(uint32_t index) { return 0x31415900 + index; }
    __declspec(noinline) uint32_t Size() { return 32; }
    __declspec(noinline) bool IndexOf(int32_t value, uint32_t& index)
    {
        index = value - 0x31415900;
        return index < 32;
    }
    __declspec(noinline) uint32_t GetMany(uint32_t start, winrt::array_view<int32_t> values)
    {
        auto count = std::min<uint32_t>(32 - start, static_cast<uint32_t>(values.size()));
        for (uint32_t index = 0; index < count; ++index) values[index] = GetAt(start + index);
        return count;
    }
};

__declspec(noinline) bool InvokeParameterizedInterfaces(
    const winrt::Windows::Foundation::IReference<int32_t>& integer,
    const winrt::Windows::Foundation::IReference<winrt::hstring>& text,
    const winrt::Windows::Foundation::IReference<winrt::guid>& guid,
    const winrt::Windows::Foundation::Collections::IVectorView<int32_t>& vector)
{
    // First ABI calls occur before activation or interface queries, including a counted output array.
    std::vector<int32_t> values(32);
    uint32_t index = 0;
    return integer.Value() == 0x51A17E01 && text.Value() == L"Parameterized WinRT capture" &&
        guid.Value() == winrt::guid{0x12345678, 0x4321, 0xABCD, {1, 2, 3, 4, 5, 6, 7, 8}} &&
        vector.GetAt(3) == 0x31415903 && vector.Size() == 32 &&
        vector.IndexOf(0x31415907, index) && index == 7 && vector.GetMany(0, values) == 32 &&
        values.front() == 0x31415900 && values.back() == 0x3141591F;
}

bool PrivateParameterizedWorkload()
{
    auto integer = winrt::make<ProjectedReference<int32_t>>(0x51A17E01);
    auto text = winrt::make<ProjectedReference<winrt::hstring>>(L"Parameterized WinRT capture");
    auto guid = winrt::make<ProjectedReference<winrt::guid>>(
        winrt::guid{0x12345678, 0x4321, 0xABCD, {1, 2, 3, 4, 5, 6, 7, 8}});
    auto vector = winrt::make<ProjectedVectorView>();
    return InvokeParameterizedInterfaces(integer, text, guid, vector);
}

__declspec(noinline) bool InvokeParameterizedCollections(
    const winrt::Windows::Foundation::Collections::IVector<float>& vector)
{
    // Exercise returned interface pointers, floating input registers and iterator output extents.
    vector.Append(1.25f);
    vector.Append(2.5f);
    vector.InsertAt(1, 3.75f);
    vector.SetAt(0, 0.625f);
    uint32_t index = 0;
    if (vector.Size() != 3 || !vector.IndexOf(3.75f, index) || index != 1) return false;
    auto view = vector.GetView();
    if (view.GetAt(0) != 0.625f) return false;
    auto iterator = vector.First();
    if (!iterator.HasCurrent() || iterator.Current() != 0.625f || !iterator.MoveNext()) return false;
    std::vector<float> values(32);
    if (iterator.GetMany(values) != 2 || values[0] != 3.75f || values[1] != 2.5f) return false;
    if (vector.GetMany(0, values) != 3 || values[0] != 0.625f) return false;
    vector.RemoveAt(0);
    vector.RemoveAtEnd();
    vector.Clear();
    vector.ReplaceAll(std::vector<float>{0.125f, 0.25f, 0.5f, 1.0f, 2.0f, 4.0f});
    return vector.Size() == 6 && vector.GetAt(5) == 4.0f;
}

bool ParameterizedCollectionWorkload()
{
    auto vector = winrt::single_threaded_vector<float>();
    return InvokeParameterizedCollections(vector);
}

template<class Type> class ProjectedReferenceArray : public NonComPrimary,
    public winrt::implements<ProjectedReferenceArray<Type>, winrt::Windows::Foundation::IReferenceArray<Type>>
{
public:
    explicit ProjectedReferenceArray(std::vector<Type> values) : values_(std::move(values)) {}
    __declspec(noinline) winrt::com_array<Type> Value() { return {values_.begin(), values_.end()}; }
private:
    std::vector<Type> values_;
};

__declspec(noinline) bool InvokeReferenceArrays(
    const winrt::Windows::Foundation::IReferenceArray<int32_t>& integers,
    const winrt::Windows::Foundation::IReferenceArray<winrt::guid>& identifiers)
{
    // Allocate returned arrays through their real ABI before the application inspects or frees them.
    auto values = integers.Value();
    auto guids = identifiers.Value();
    return values.size() == 32 && values[0] == 0x41525200 && values[31] == 0x4152521F &&
        guids.size() == 9 && guids[0].Data1 == 0x12345678 && guids[8].Data1 == 0x12345680;
}

bool ReferenceArrayWorkload()
{
    std::vector<int32_t> values(32);
    std::vector<winrt::guid> identifiers(9);
    for (uint32_t index = 0; index < values.size(); ++index) values[index] = 0x41525200 + index;
    for (uint32_t index = 0; index < identifiers.size(); ++index)
        identifiers[index] = {0x12345678 + index, 0x4321, 0xABCD, {1, 2, 3, 4, 5, 6, 7, 8}};
    auto integers = winrt::make<ProjectedReferenceArray<int32_t>>(std::move(values));
    auto guids = winrt::make<ProjectedReferenceArray<winrt::guid>>(std::move(identifiers));
    return InvokeReferenceArrays(integers, guids);
}

__declspec(noinline) bool InvokeStructuredReferences(
    const winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>& point,
    const winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>& rectangle,
    const winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>& date,
    const winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>& span,
    const winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>& vector,
    const winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float4x4>& matrix,
    const winrt::Windows::Foundation::IReferenceArray<winrt::Windows::Foundation::Rect>& rectangles)
{
    // These structure and allocated-array calls precede every factory and interface-query boundary.
    auto p = point.Value();
    auto r = rectangle.Value();
    auto v = vector.Value();
    auto m = matrix.Value();
    auto values = rectangles.Value();
    return p.X == 1.25f && p.Y == -2.5f && r.X == 1.25f && r.Y == -2.5f &&
        r.Width == 32 && r.Height == 64 && date.Value().time_since_epoch().count() == 11223344556677 &&
        span.Value().count() == -11223344556677 && v.x == 1.25f && v.y == -2.5f && v.z == 3.75f &&
        m.m11 == 1 && m.m44 == 16 && values.size() == 8 && values.front().X == 0.25f && values.back().X == 7.25f;
}

__declspec(noinline) bool InvokeNestedCollections(
    const winrt::Windows::Foundation::Collections::IVector<
        winrt::Windows::Foundation::Collections::IVectorView<int32_t>>& outer,
    const winrt::Windows::Foundation::Collections::IVectorView<int32_t>& inner)
{
    // Input, returned-object and counted-array boundaries retain the nested interface's closed identity.
    outer.Append(inner);
    if (outer.Size() != 1 || outer.GetAt(0).GetAt(3) != 0x31415903) return false;
    auto iterator = outer.First();
    if (!iterator.HasCurrent() || iterator.Current().GetAt(4) != 0x31415904) return false;
    std::vector<winrt::Windows::Foundation::Collections::IVectorView<int32_t>> values(3);
    return outer.GetMany(0, values) == 1 && values[0].GetAt(5) == 0x31415905;
}

bool StructuredGenericWorkload()
{
    using namespace winrt::Windows::Foundation;
    using namespace winrt::Windows::Foundation::Collections;
    using namespace winrt::Windows::Foundation::Numerics;
    auto point = winrt::make<ProjectedReference<Point>>(Point{1.25f, -2.5f});
    auto rectangle = winrt::make<ProjectedReference<Rect>>(Rect{1.25f, -2.5f, 32, 64});
    auto date = winrt::make<ProjectedReference<DateTime>>(DateTime{TimeSpan{11223344556677}});
    auto span = winrt::make<ProjectedReference<TimeSpan>>(TimeSpan{-11223344556677});
    auto vector = winrt::make<ProjectedReference<float3>>(float3{1.25f, -2.5f, 3.75f});
    auto matrix = winrt::make<ProjectedReference<float4x4>>(float4x4{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    std::vector<Rect> values(8);
    for (uint32_t index = 0; index < values.size(); ++index) values[index] = {index + 0.25f, -2.5f, 32, 64};
    auto rectangles = winrt::make<ProjectedReferenceArray<Rect>>(std::move(values));
    auto inner = winrt::make<ProjectedVectorView>();
    auto outer = winrt::single_threaded_vector<IVectorView<int32_t>>();
    return InvokeStructuredReferences(point, rectangle, date, span, vector, matrix, rectangles) &&
        InvokeNestedCollections(outer, inner);
}

__declspec(noinline) bool InvokeParameterizedMaps(
    const winrt::Windows::Foundation::Collections::IMap<winrt::hstring, double>& numbers,
    const winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::hstring>& identifiers)
{
    // Native map contracts retain string and structure inputs, floating registers and nested interface outputs.
    auto key = winrt::hstring(std::wstring(96, L'K'));
    if (numbers.Insert(key, 3.125) || !numbers.Insert(key, 6.25) || numbers.Size() != 1 ||
        numbers.Lookup(key) != 6.25 || !numbers.HasKey(key) || numbers.HasKey(L"missing")) return false;
    numbers.Insert(L"second", 12.5);
    auto view = numbers.GetView();
    if (view.Size() != 2 || view.Lookup(key) != 6.25 || !view.HasKey(L"second")) return false;
    decltype(view) first{nullptr}, second{nullptr};
    view.Split(first, second);
    auto iterator = numbers.First();
    if (!iterator.HasCurrent()) return false;
    auto pair = iterator.Current();
    if (!numbers.HasKey(pair.Key()) || numbers.Lookup(pair.Key()) != pair.Value()) return false;
    std::vector<decltype(pair)> pairs(4);
    if (iterator.GetMany(pairs) != 2 || !pairs[0] || !pairs[1] || iterator.MoveNext()) return false;
    bool missing = false;
    try { view.Lookup(L"missing"); }
    catch (const winrt::hresult_out_of_bounds&) { missing = true; }
    numbers.Remove(L"second");
    numbers.Clear();
    winrt::guid identity{0x12345678, 0x4321, 0xABCD, {1, 2, 3, 4, 5, 6, 7, 8}};
    auto text = winrt::hstring(std::wstring(96, L'V'));
    return missing && numbers.Size() == 0 && !identifiers.Insert(identity, text) &&
        identifiers.Lookup(identity) == text && identifiers.HasKey(identity);
}

bool ParameterizedMapWorkload()
{
    auto numbers = winrt::single_threaded_map<winrt::hstring, double>();
    auto identifiers = winrt::single_threaded_map<winrt::guid, winrt::hstring>();
    return InvokeParameterizedMaps(numbers, identifiers);
}

namespace PrivateInterfaces
{
struct __declspec(uuid("7E381203-9F22-4BCD-8270-946930041327")) IProbe : IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE Copy(const BYTE* input, ULONG size, BYTE* output, ULONG* written) = 0;
    virtual uint64_t STDMETHODCALLTYPE Scalar(uint64_t value) = 0;
};

class Probe final : public IProbe
{
public:
    __declspec(noinline) HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == __uuidof(IUnknown) || iid == __uuidof(IProbe) ? this : nullptr;
        if (!*output) return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }
    __declspec(noinline) ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    __declspec(noinline) ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE Copy(const BYTE* input, ULONG size, BYTE* output,
        ULONG* written) override
    {
        for (ULONG index = 0; index < size; ++index) output[index] = input[index] ^ 0xA5;
        *written = size;
        return S_OK;
    }
    __declspec(noinline) uint64_t STDMETHODCALLTYPE Scalar(uint64_t value) override
    {
        return value ^ 0x0123456789ABCDEF;
    }
private:
    ULONG references_ = 1;
};

class VirtualProbe final : public NonComPrimary, public virtual IProbe
{
public:
    __declspec(noinline) HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == __uuidof(IUnknown) || iid == __uuidof(IProbe) ? static_cast<IProbe*>(this) : nullptr;
        if (!*output) return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }
    __declspec(noinline) ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    __declspec(noinline) ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE Copy(const BYTE* input, ULONG size, BYTE* output,
        ULONG* written) override
    {
        for (ULONG index = 0; index < size; ++index) output[index] = input[index] ^ 0xA5;
        *written = size;
        return S_OK;
    }
    __declspec(noinline) uint64_t STDMETHODCALLTYPE Scalar(uint64_t value) override
    {
        return value ^ 0x0123456789ABCDEF;
    }
private:
    ULONG references_ = 1;
};

class Stringable final : public ABI::Windows::Foundation::IStringable
{
public:
    __declspec(noinline) HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == __uuidof(IUnknown) || iid == __uuidof(IInspectable) ||
            iid == __uuidof(ABI::Windows::Foundation::IStringable) ? this : nullptr;
        if (!*output) return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }
    __declspec(noinline) ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    __declspec(noinline) ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    HRESULT STDMETHODCALLTYPE GetIids(ULONG* count, IID** identities) override
    {
        if (!count || !identities) return E_POINTER;
        *count = 0;
        *identities = nullptr;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetRuntimeClassName(HSTRING* name) override
    {
        constexpr wchar_t text[] = L"PrivateInterfaces.Stringable";
        return WindowsCreateString(text, std::size(text) - 1, name);
    }
    HRESULT STDMETHODCALLTYPE GetTrustLevel(TrustLevel* level) override
    {
        if (!level) return E_POINTER;
        *level = BaseTrust;
        return S_OK;
    }
    __declspec(noinline) HRESULT STDMETHODCALLTYPE ToString(HSTRING* value) override
    {
        constexpr wchar_t text[] = L"Private namespaced WinRT capture";
        return WindowsCreateString(text, std::size(text) - 1, value);
    }
private:
    ULONG references_ = 1;
};
}

bool PrivateUnknownWorkload(bool edited = false)
{
    // Unknown private methods execute before a query can supply their real interface identity.
    PrivateInterfaces::Probe object;
    PrivateInterfaces::IProbe* instance = &object;
    BYTE input[128]{}, output[128]{};
    for (uint32_t index = 0; index < std::size(input); ++index) input[index] = static_cast<BYTE>(index);
    ULONG written = 0;
    if (FAILED(instance->Copy(input, sizeof(input), output, &written)) || written != sizeof(output) ||
        instance->Scalar(0x113322557799BBDD) != (edited ? 0x1122334455667788 :
            (0x113322557799BBDD ^ 0x0123456789ABCDEF))) return false;
    for (uint32_t index = 0; index < std::size(output); ++index)
        if (output[index] != (input[index] ^ 0xA5)) return false;
    PrivateInterfaces::IProbe* queried = nullptr;
    return SUCCEEDED(instance->QueryInterface(IID_PPV_ARGS(&queried))) && queried == instance &&
        queried->Scalar(0x2233445566778899) == (0x2233445566778899 ^ 0x0123456789ABCDEF) &&
        queried->Release() == 1;
}

bool PrivateVirtualUnknownWorkload()
{
    // Unknown private methods execute before a query can supply their real interface identity.
    PrivateInterfaces::VirtualProbe object;
    PrivateInterfaces::IProbe* instance = &object;
    BYTE input[128]{}, output[128]{};
    for (uint32_t index = 0; index < std::size(input); ++index) input[index] = static_cast<BYTE>(index);
    ULONG written = 0;
    if (FAILED(instance->Copy(input, sizeof(input), output, &written)) || written != sizeof(output) ||
        instance->Scalar(0x113322557799BBDD) != (0x113322557799BBDD ^ 0x0123456789ABCDEF)) return false;
    for (uint32_t index = 0; index < std::size(output); ++index)
        if (output[index] != (input[index] ^ 0xA5)) return false;
    PrivateInterfaces::IProbe* queried = nullptr;
    return SUCCEEDED(instance->QueryInterface(IID_PPV_ARGS(&queried))) && queried == instance &&
        queried->Scalar(0x2233445566778899) == (0x2233445566778899 ^ 0x0123456789ABCDEF) &&
        queried->Release() == 1;
}

bool PrivateStringableWorkload()
{
    // A namespaced SDK contract identifies typed WinRT output without activation or interface queries.
    PrivateInterfaces::Stringable object;
    ABI::Windows::Foundation::IStringable* instance = &object;
    HSTRING value = nullptr;
    if (FAILED(instance->ToString(&value))) return false;
    auto valid = !wcscmp(WindowsGetStringRawBuffer(value, nullptr), L"Private namespaced WinRT capture");
    WindowsDeleteString(value);
    return valid;
}

bool SystemInterfaceWorkload()
{
    // SDK factories with fixed interface outputs discover allocation and stream methods without a requested IID.
    Microsoft::WRL::ComPtr<IMalloc> allocator;
    if (FAILED(CoGetMalloc(1, &allocator))) return false;
    auto memory = allocator->Alloc(256);
    if (!memory) return false;
    bool valid = allocator->GetSize(memory) >= 256 && allocator->DidAlloc(memory) == 1;
    allocator->Free(memory);
    Microsoft::WRL::ComPtr<IStream> stream, clone;
    if (FAILED(CreateStreamOnHGlobal(nullptr, TRUE, &stream))) return false;
    char input[] = "Detourist system interface capture", output[sizeof(input)]{};
    ULONG written = 0, read = 0;
    STATSTG status{};
    valid &= SUCCEEDED(stream->Write(input, sizeof(input), &written)) && written == sizeof(input);
    valid &= SUCCEEDED(stream->Seek({}, STREAM_SEEK_SET, nullptr));
    valid &= SUCCEEDED(stream->Read(output, sizeof(output), &read)) && read == sizeof(input) &&
        !memcmp(input, output, sizeof(input));
    valid &= SUCCEEDED(stream->Stat(&status, STATFLAG_NONAME)) && status.cbSize.QuadPart == sizeof(input);
    valid &= SUCCEEDED(stream->Commit(STGC_DEFAULT)) && SUCCEEDED(stream->Clone(&clone));

    // Shell path parsing discovers already-executed interfaces while system worker threads are running.
    Microsoft::WRL::ComPtr<IShellLinkW> link;
    wchar_t executable[MAX_PATH]{}, returned[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, executable, MAX_PATH) ||
        FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)))) return false;
    valid &= SUCCEEDED(link->SetPath(executable));
    valid &= SUCCEEDED(link->GetPath(returned, MAX_PATH, nullptr, 0)) && !_wcsicmp(executable, returned);
    return valid;
}

bool DispatchWorkload()
{
    CLSID classId{};
    if (FAILED(CLSIDFromProgID(L"Scripting.Dictionary", &classId))) return false;
    IClassFactory* factory = nullptr;
    if (FAILED(CoGetClassObject(classId, CLSCTX_INPROC_SERVER, nullptr, IID_PPV_ARGS(&factory)))) return false;
    IDispatch* dictionary = nullptr;
    auto result = factory->CreateInstance(nullptr, IID_PPV_ARGS(&dictionary));
    factory->LockServer(TRUE);
    factory->LockServer(FALSE);
    factory->Release();
    if (FAILED(result)) return false;
    bool valid = true;

    // Exercise real automation dispatch, including nested BSTR input and scalar output.
    IUnknown* identity = nullptr;
    if (FAILED(dictionary->QueryInterface(IID_PPV_ARGS(&identity)))) valid = false;
    if (identity)
    {
        identity->AddRef();
        identity->Release();
        identity->Release();
    }
    UINT informationCount = 0;
    if (FAILED(dictionary->GetTypeInfoCount(&informationCount)) || !informationCount) valid = false;
    ITypeInfo* information = nullptr;
    if (FAILED(dictionary->GetTypeInfo(0, LOCALE_USER_DEFAULT, &information))) valid = false;
    if (information)
    {
        TYPEATTR* attributes = nullptr;
        valid &= SUCCEEDED(information->GetTypeAttr(&attributes)) && attributes && attributes->cFuncs > 0;
        if (attributes) information->ReleaseTypeAttr(attributes);
        BSTR name = nullptr;
        valid &= SUCCEEDED(information->GetDocumentation(MEMBERID_NIL, &name, nullptr, nullptr, nullptr)) && name;
        SysFreeString(name);
        information->Release();
    }
    wchar_t addName[] = L"Add";
    LPOLESTR names[] = {addName};
    DISPID add = 0;
    if (FAILED(dictionary->GetIDsOfNames(IID_NULL, names, 1, LOCALE_USER_DEFAULT, &add))) valid = false;
    VARIANT arguments[2]{};
    arguments[0].vt = VT_I4;
    arguments[0].lVal = 42;
    arguments[1].vt = VT_BSTR;
    arguments[1].bstrVal = SysAllocString(L"Detourist automation key");
    DISPPARAMS parameters{arguments, nullptr, 2, 0};
    if (FAILED(dictionary->Invoke(add, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
        &parameters, nullptr, nullptr, nullptr))) valid = false;
    SysFreeString(arguments[1].bstrVal);
    wchar_t countName[] = L"Count";
    names[0] = countName;
    DISPID count = 0;
    if (FAILED(dictionary->GetIDsOfNames(IID_NULL, names, 1, LOCALE_USER_DEFAULT, &count))) valid = false;
    DISPPARAMS empty{};
    VARIANT output{};
    if (FAILED(dictionary->Invoke(count, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET,
        &empty, &output, nullptr, nullptr)) || output.vt != VT_I4 || output.lVal != 1) valid = false;
    VariantClear(&output);
    if (dictionary->Invoke(0x7FFFFFFF, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
        &empty, nullptr, nullptr, nullptr) != DISP_E_MEMBERNOTFOUND) valid = false;
    dictionary->Release();

    // Activation APIs return the same interface identities that callers subsequently use.
    if (FAILED(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dictionary)))) valid = false;
    else dictionary->Release();
    MULTI_QI requested{&__uuidof(IDispatch), nullptr, S_OK};
    if (FAILED(CoCreateInstanceEx(classId, nullptr, CLSCTX_INPROC_SERVER, nullptr, 1, &requested)) ||
        FAILED(requested.hr)) valid = false;
    if (requested.pItf) requested.pItf->Release();
    return valid;
}

bool PrepareFactoryFile(const wchar_t* path)
{
    Microsoft::WRL::ComPtr<IShellLinkW> link;
    Microsoft::WRL::ComPtr<IPersistFile> persistence;
    wchar_t executable[MAX_PATH]{};
    return GetModuleFileNameW(nullptr, executable, MAX_PATH) &&
        SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&link))) &&
        SUCCEEDED(link->SetPath(executable)) &&
        SUCCEEDED(link.As(&persistence)) &&
        SUCCEEDED(persistence->Save(path, TRUE));
}

bool UseFactoryFile(const wchar_t* path)
{
    // A multi-interface file activation is the only source of this object's vtable in this process.
    MULTI_QI requested{&__uuidof(IShellLinkW), nullptr, E_NOINTERFACE};
    CLSID classId = CLSID_ShellLink;
    auto result = CoGetInstanceFromFile(nullptr, &classId, nullptr,
        CLSCTX_INPROC_SERVER, STGM_READ, const_cast<wchar_t*>(path), 1, &requested);
    if (FAILED(result) || FAILED(requested.hr) || !requested.pItf) return false;
    auto link = reinterpret_cast<IShellLinkW*>(requested.pItf);
    wchar_t pathFromLink[MAX_PATH]{}, executable[MAX_PATH]{};
    bool valid = SUCCEEDED(link->GetPath(pathFromLink, MAX_PATH, nullptr, 0)) &&
        GetModuleFileNameW(nullptr, executable, MAX_PATH) && !_wcsicmp(pathFromLink, executable);
    link->Release();
    return valid;
}

bool TypedFactoryWorkload()
{
    IMalloc* allocator = nullptr;
    if (FAILED(CoGetMalloc(1, &allocator)) || !allocator) return false;
    auto memory = allocator->Alloc(16);
    if (memory) allocator->Free(memory);
    allocator->Release();
    return memory != nullptr;
}

bool InspectableWorkload()
{
    HSTRING name = nullptr;
    constexpr wchar_t className[] = L"Windows.Foundation.Collections.PropertySet";
    if (FAILED(WindowsCreateString(className, static_cast<UINT32>(std::size(className) - 1), &name))) return false;
    IInspectable* object = nullptr;
    bool valid = SUCCEEDED(RoActivateInstance(name, &object));
    if (object)
    {
        HSTRING runtimeName = nullptr;
        if (FAILED(object->GetRuntimeClassName(&runtimeName))) valid = false;
        else
        {
            UINT32 length = 0;
            auto text = WindowsGetStringRawBuffer(runtimeName, &length);
            if (!text || length != std::size(className) - 1 || wcscmp(text, className)) valid = false;
            WindowsDeleteString(runtimeName);
        }
        ULONG count = 0;
        IID* identifiers = nullptr;
        if (FAILED(object->GetIids(&count, &identifiers)) || !count || !identifiers) valid = false;
        CoTaskMemFree(identifiers);
        TrustLevel trust{};
        if (FAILED(object->GetTrustLevel(&trust))) valid = false;
        IInspectable* same = nullptr;
        if (FAILED(object->QueryInterface(IID_PPV_ARGS(&same)))) valid = false;
        if (same) same->Release();
        object->Release();
    }
    IActivationFactory* factory = nullptr;
    if (FAILED(RoGetActivationFactory(name, IID_PPV_ARGS(&factory)))) valid = false;
    if (factory)
    {
        object = nullptr;
        if (FAILED(factory->ActivateInstance(&object))) valid = false;
        if (object) object->Release();
        factory->Release();
    }
    WindowsDeleteString(name);
    return valid;
}

struct __declspec(uuid("F2C7F242-11B5-4C65-9D14-424434414343")) ICustomCapture : IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE Transform(const BYTE* input, ULONG size, BYTE* output, ULONG* written) = 0;
    virtual ULONG STDMETHODCALLTYPE Scalar(ULONG value) = 0;
};

class CustomCapture final : public ICustomCapture
{
public:
    explicit CustomCapture(bool generated)
    {
        if (!generated) return;
        auto original = *reinterpret_cast<void***>(this);
        auto code = static_cast<BYTE*>(VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!code) return;

        // Runtime-generated vtable thunks preserve the native ABI while living outside every loaded image.
        for (uint32_t index = 0; index < 2; ++index)
        {
            auto entry = code + index * 16;
            constexpr BYTE jump[]{0xFF, 0x25, 0, 0, 0, 0};
            memcpy(entry, jump, sizeof(jump));
            memcpy(entry + sizeof(jump), original + index + 3, sizeof(void*));
        }
        DWORD protection = 0;
        if (!VirtualProtect(code, 64, PAGE_EXECUTE_READ, &protection))
        {
            VirtualFree(code, 0, MEM_RELEASE);
            return;
        }
        FlushInstructionCache(GetCurrentProcess(), code, 64);
        std::copy_n(original, 5, generatedTable);
        generatedTable[0] = reinterpret_cast<void*>(&GeneratedQueryInterface);
        generatedTable[1] = reinterpret_cast<void*>(&GeneratedAddRef);
        generatedTable[2] = reinterpret_cast<void*>(&GeneratedRelease);
        generatedTable[3] = code;
        generatedTable[4] = code + 16;
        generatedCode = code;
        *reinterpret_cast<void***>(this) = generatedTable;
    }
    ~CustomCapture() { if (generatedCode) VirtualFree(generatedCode, 0, MEM_RELEASE); }
    bool HasGeneratedCode() const { return generatedCode != nullptr; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(ICustomCapture)) return E_NOINTERFACE;
        *output = static_cast<ICustomCapture*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        auto remaining = --references;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE Transform(const BYTE* input, ULONG size, BYTE* output, ULONG* written) override
    {
        for (ULONG index = 0; index < size; ++index) output[index] = input[index] ^ 0x5A;
        *written = size;
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE Scalar(ULONG value) override { return value ^ 0xBAADF00D; }
private:
    static HRESULT STDMETHODCALLTYPE GeneratedQueryInterface(CustomCapture* instance, REFIID iid, void** output)
    {
        return instance->CustomCapture::QueryInterface(iid, output);
    }
    static ULONG STDMETHODCALLTYPE GeneratedAddRef(CustomCapture* instance)
    {
        return instance->CustomCapture::AddRef();
    }
    static ULONG STDMETHODCALLTYPE GeneratedRelease(CustomCapture* instance)
    {
        return instance->CustomCapture::Release();
    }
    std::atomic<ULONG> references = 1;
    void* generatedTable[6]{};
    void* generatedCode = nullptr;
};

class CaptureBrush final : public ID2D1SolidColorBrush
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(ID2D1Brush) &&
            iid != __uuidof(ID2D1SolidColorBrush)) return E_NOINTERFACE;
        *output = static_cast<ID2D1Brush*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        auto count = --references_;
        if (!count) delete this;
        return count;
    }
    void STDMETHODCALLTYPE GetFactory(ID2D1Factory** factory) const override { *factory = nullptr; }
    void STDMETHODCALLTYPE SetOpacity(FLOAT opacity) override { opacity_ = opacity; }
    FLOAT STDMETHODCALLTYPE GetOpacity() const override { return opacity_; }
    void STDMETHODCALLTYPE SetTransform(const D2D1_MATRIX_3X2_F* transform) override { transform_ = *transform; }
    void STDMETHODCALLTYPE GetTransform(D2D1_MATRIX_3X2_F* transform) const override { *transform = transform_; }
    void STDMETHODCALLTYPE SetColor(const D2D1_COLOR_F* color) override { color_ = *color; }
    D2D1_COLOR_F STDMETHODCALLTYPE GetColor() const override { return color_; }
private:
    std::atomic<ULONG> references_ = 1;
    FLOAT opacity_ = 1;
    D2D1_MATRIX_3X2_F transform_{};
    D2D1_COLOR_F color_{};
};

class CaptureLayer final : public ID2D1Layer
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(ID2D1Resource) &&
            iid != __uuidof(ID2D1Layer)) return E_NOINTERFACE;
        *output = static_cast<ID2D1Layer*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        auto count = --references_;
        if (!count) delete this;
        return count;
    }
    void STDMETHODCALLTYPE GetFactory(ID2D1Factory** factory) const override { *factory = nullptr; }
    D2D1_SIZE_F STDMETHODCALLTYPE GetSize() const override { return {128.5f, 257.25f}; }
private:
    std::atomic<ULONG> references_ = 1;
};

class CaptureProgram final : public ID3D12StateObjectProperties1
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(ID3D12StateObjectProperties) &&
            iid != __uuidof(ID3D12StateObjectProperties1)) return E_NOINTERFACE;
        *output = static_cast<ID3D12StateObjectProperties1*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        auto count = --references_;
        if (!count) delete this;
        return count;
    }
    void* STDMETHODCALLTYPE GetShaderIdentifier(LPCWSTR) override { return nullptr; }
    UINT64 STDMETHODCALLTYPE GetShaderStackSize(LPCWSTR) override { return 0; }
    UINT64 STDMETHODCALLTYPE GetPipelineStackSize() override { return 0; }
    void STDMETHODCALLTYPE SetPipelineStackSize(UINT64) override {}
    D3D12_PROGRAM_IDENTIFIER STDMETHODCALLTYPE GetProgramIdentifier(LPCWSTR name) override
    {
        if (name && !wcscmp(name, L"Modified")) return {{0xDEADBEEF, 2, 3, 4}};
        if (!name || wcscmp(name, L"Capture program")) return {};
        return {{0x3141592653589793, 0x2384626433832795, 0x0288419716939937, 0x5105820974944592}};
    }
private:
    std::atomic<ULONG> references_ = 1;
};

class CustomFactory final : public IClassFactory
{
public:
    explicit CustomFactory(bool generated) : generated_(generated) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE;
        *output = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override { return --references; }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** output) override
    {
        if (outer) return CLASS_E_NOAGGREGATION;
        if (iid == IID_IStream) return CreateStreamOnHGlobal(nullptr, TRUE, reinterpret_cast<IStream**>(output));
        if (iid == __uuidof(ID2D1Brush))
        {
            *output = static_cast<ID2D1Brush*>(new CaptureBrush());
            return S_OK;
        }
        if (iid == __uuidof(ID2D1SolidColorBrush))
        {
            *output = static_cast<ID2D1SolidColorBrush*>(new CaptureBrush());
            return S_OK;
        }
        if (iid == __uuidof(ID2D1Layer))
        {
            *output = static_cast<ID2D1Layer*>(new CaptureLayer());
            return S_OK;
        }
        if (iid == __uuidof(ID3D12StateObjectProperties1))
        {
            *output = static_cast<ID3D12StateObjectProperties1*>(new CaptureProgram());
            return S_OK;
        }
        if (iid == __uuidof(ID3D11DeviceContext))
        {
            Microsoft::WRL::ComPtr<ID3D11Device> device;
            return D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, nullptr, 0,
                D3D11_SDK_VERSION, &device, nullptr, reinterpret_cast<ID3D11DeviceContext**>(output));
        }
        if (iid == __uuidof(IDWriteFactory))
            return DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, iid, reinterpret_cast<IUnknown**>(output));
        auto instance = new CustomCapture(generated_);
        if (generated_ && !instance->HasGeneratedCode()) { instance->Release(); return E_OUTOFMEMORY; }
        auto result = instance->QueryInterface(iid, output);
        instance->Release();
        return result;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL) override { return S_OK; }
private:
    std::atomic<ULONG> references = 1;
    bool generated_;
};

bool TypedWorkload(REFCLSID classId)
{
    // Real streams expose inherited slots, partial outputs and another interface returned by Clone.
    IStream* stream = nullptr;
    if (FAILED(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&stream)))) return false;
    BYTE bytes[256]{}, read[256]{};
    for (ULONG index = 0; index < sizeof(bytes); ++index) bytes[index] = static_cast<BYTE>(index);
    ULONG count = 0;
    bool valid = SUCCEEDED(stream->Write(bytes, sizeof(bytes), &count)) && count == sizeof(bytes);
    ULARGE_INTEGER size{}, position{};
    size.QuadPart = 37;
    LARGE_INTEGER offset{};
    valid &= SUCCEEDED(stream->SetSize(size));
    valid &= SUCCEEDED(stream->Seek(offset, STREAM_SEEK_SET, &position)) && position.QuadPart == 0;
    valid &= SUCCEEDED(stream->Read(read, sizeof(read), &count)) && count == 37;
    valid &= !memcmp(bytes, read, count);
    STATSTG status{};
    valid &= SUCCEEDED(stream->Stat(&status, STATFLAG_NONAME)) && status.cbSize.QuadPart == 37;
    IStream* clone = nullptr;
    valid &= SUCCEEDED(stream->Clone(&clone)) && clone;
    if (clone)
    {
        valid &= SUCCEEDED(clone->Seek(offset, STREAM_SEEK_SET, nullptr));
        valid &= SUCCEEDED(clone->Read(read, 13, &count)) && count == 13 && !memcmp(bytes, read, count);
        clone->Release();
    }
    if (!valid) std::fprintf(stderr, "Stream fixture failed: count=%lu size=%llu\n", count, status.cbSize.QuadPart);
    stream->Release();

    // A custom implementation of a public graphics interface exercises floating registers and structure pointers.
    ID2D1Brush* brush = nullptr;
    if (FAILED(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&brush)))) return false;
    brush->SetOpacity(0.375f);
    valid &= brush->GetOpacity() == 0.375f;
    D2D1_MATRIX_3X2_F transform{1, 2, 3, 4, 5, 6}, returned{};
    brush->SetTransform(&transform);
    brush->GetTransform(&returned);
    valid &= !memcmp(&transform, &returned, sizeof(transform));
    if (!valid) std::fprintf(stderr, "Typed COM fixture failed: opacity=%g\n", brush->GetOpacity());
    brush->Release();

    // Both small and large structure returns use a hidden buffer, including methods with declared arguments.
    Microsoft::WRL::ComPtr<ID2D1SolidColorBrush> solid;
    Microsoft::WRL::ComPtr<ID2D1Layer> layer;
    Microsoft::WRL::ComPtr<ID3D12StateObjectProperties1> program;
    if (FAILED(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&solid))) ||
        FAILED(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&layer))) ||
        FAILED(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&program)))) return false;
    D2D1_COLOR_F color{0.125f, 0.25f, 0.5f, 1.0f};
    solid->SetColor(&color);
    auto returnedColor = solid->GetColor();
    auto returnedSize = layer->GetSize();
    auto identifier = program->GetProgramIdentifier(L"Capture program");
    valid &= !memcmp(&color, &returnedColor, sizeof(color));
    valid &= returnedSize.width == 128.5f && returnedSize.height == 257.25f;
    valid &= identifier.OpaqueData[0] == 0x3141592653589793 && identifier.OpaqueData[3] == 0x5105820974944592;

    // Real graphics methods take fixed arrays as pointers and write all four output elements.
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> graphics;
    if (FAILED(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&graphics)))) return false;
    FLOAT factors[]{0.125f, 0.25f, 0.5f, 1.0f}, returnedFactors[4]{};
    UINT mask = 0;
    graphics->OMSetBlendState(nullptr, factors, 0xABCDEF01);
    graphics->OMGetBlendState(nullptr, returnedFactors, &mask);
    valid &= !memcmp(factors, returnedFactors, sizeof(factors)) && mask == 0xABCDEF01;

    // A real text analyzer exposes outputs beyond the twentieth argument slot.
    Microsoft::WRL::ComPtr<IDWriteFactory> writing;
    Microsoft::WRL::ComPtr<IDWriteFontCollection> fonts;
    Microsoft::WRL::ComPtr<IDWriteFontFamily> family;
    Microsoft::WRL::ComPtr<IDWriteFont> font;
    Microsoft::WRL::ComPtr<IDWriteFontFace> face;
    Microsoft::WRL::ComPtr<IDWriteTextAnalyzer> analyzer;
    if (FAILED(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&writing))) ||
        FAILED(writing->GetSystemFontCollection(&fonts)) || FAILED(fonts->GetFontFamily(0, &family)) ||
        FAILED(family->GetFirstMatchingFont(DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
            DWRITE_FONT_STYLE_NORMAL, &font)) || FAILED(font->CreateFontFace(&face)) ||
        FAILED(writing->CreateTextAnalyzer(&analyzer))) return false;
    DWRITE_SCRIPT_ANALYSIS script{};
    UINT16 clusters[1]{}, glyphs[16]{};
    DWRITE_SHAPING_TEXT_PROPERTIES textProperties[1]{};
    DWRITE_SHAPING_GLYPH_PROPERTIES glyphProperties[16]{};
    UINT32 glyphCount = 0;
    auto shaped = analyzer->GetGlyphs(L"A", 1, face.Get(), FALSE, FALSE, &script, L"en-us", nullptr,
        nullptr, nullptr, 0, 16, clusters, textProperties, glyphs, glyphProperties, &glyphCount);
    FLOAT advances[16]{};
    DWRITE_GLYPH_OFFSET offsets[16]{};
    auto placed = SUCCEEDED(shaped) ? analyzer->GetGdiCompatibleGlyphPlacements(L"A", clusters,
        textProperties, 1, glyphs, glyphProperties, glyphCount, face.Get(), 16.0f, 1.0f, nullptr,
        FALSE, FALSE, FALSE, &script, L"en-us", nullptr, nullptr, 0, advances, offsets) : shaped;
    valid &= SUCCEEDED(placed) && glyphCount == 1 && advances[0] > 0;
    if (!valid) std::fprintf(stderr, "COM ABI fixture failed: shape=%08lX placement=%08lX glyphs=%u\n",
        shaped, placed, glyphCount);
    return valid;
}

bool CustomWorkload(bool generated = false)
{
    CustomFactory factory(generated);
    constexpr CLSID classId{0x3AD70B10, 0xE49C, 0x4DBC, {0x9F, 0x71, 0x2B, 0x17, 0x18, 0x21, 0x10, 0x52}};
    DWORD registration = 0;
    auto registered = CoRegisterClassObject(classId, &factory, CLSCTX_INPROC_SERVER, REGCLS_MULTIPLEUSE,
        &registration);
    if (FAILED(registered))
    {
        std::fprintf(stderr, "Custom registration: %08lX\n", registered);
        return false;
    }
    ICustomCapture* instance = nullptr;
    auto created = CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&instance));
    bool valid = SUCCEEDED(created);
    if (!valid) std::fprintf(stderr, "Custom activation: %08lX\n", created);
    if (instance)
    {
        BYTE input[256]{}, output[256]{};
        for (ULONG index = 0; index < sizeof(input); ++index) input[index] = static_cast<BYTE>(index);
        ULONG written = 0;
        valid = SUCCEEDED(instance->Transform(input, sizeof(input), output, &written)) && written == sizeof(input);
        for (ULONG index = 0; index < sizeof(input); ++index) valid &= output[index] == (input[index] ^ 0x5A);
        valid &= instance->Scalar(0x31415926) == (0x31415926 ^ 0xBAADF00D);
        ICustomCapture* same = nullptr;
        valid &= SUCCEEDED(instance->QueryInterface(IID_PPV_ARGS(&same))) && same == instance;
        if (same) same->Release();
        instance->Release();
    }
    if (!generated) valid &= TypedWorkload(classId);
    CoRevokeClassObject(registration);
    return valid;
}

bool ProgramBreakpointWorkload(LPCWSTR gateName)
{
    // A named gate lets the controller set an exact breakpoint after this interface has been discovered.
    CustomFactory factory(false);
    constexpr CLSID classId{0x3AD70B10, 0xE49C, 0x4DBC, {0x9F, 0x71, 0x2B, 0x17, 0x18, 0x21, 0x10, 0x52}};
    DWORD registration = 0;
    if (FAILED(CoRegisterClassObject(classId, &factory, CLSCTX_INPROC_SERVER, REGCLS_MULTIPLEUSE,
        &registration))) return false;
    Microsoft::WRL::ComPtr<ID3D12StateObjectProperties1> program;
    bool valid = SUCCEEDED(CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&program)));
    HANDLE gate = CreateEventW(nullptr, TRUE, FALSE, gateName);
    if (valid && gate)
    {
        wchar_t alternate[] = L"Modified";
        program->GetShaderIdentifier(alternate);
        auto first = program->GetProgramIdentifier(L"Capture program");
        valid &= first.OpaqueData[0] == 0x3141592653589793;
        valid &= WaitForSingleObject(gate, 30000) == WAIT_OBJECT_0;
        if (valid)
        {
            auto edited = program->GetProgramIdentifier(L"Capture program");
            valid &= edited.OpaqueData[0] == 0xFEEDFACE && edited.OpaqueData[1] == 2 &&
                edited.OpaqueData[2] == 3 && edited.OpaqueData[3] == 4;
        }
    }
    else valid = false;
    if (gate) CloseHandle(gate);
    CoRevokeClassObject(registration);
    return valid;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && !wcscmp(argv[1], L"--graphics-factory"))
    {
        // Exercise two distinct COM interfaces returned by one SDK factory call.
        Microsoft::WRL::ComPtr<ID3D11Device> device;
        Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
        auto result = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, nullptr, 0,
            D3D11_SDK_VERSION, &device, nullptr, &context);
        if (FAILED(result) || !device || !context) return 1;
        auto feature = device->GetFeatureLevel();
        auto type = context->GetType();
        return feature >= D3D_FEATURE_LEVEL_10_0 && type == D3D11_DEVICE_CONTEXT_IMMEDIATE ? 0 : 1;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--dwrite-factory"))
    {
        // The requested IID, rather than the generic output pointer type, identifies the returned factory.
        Microsoft::WRL::ComPtr<IDWriteFactory> factory;
        auto result = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
            reinterpret_cast<IUnknown**>(factory.GetAddressOf()));
        if (FAILED(result) || !factory) return 1;
        Microsoft::WRL::ComPtr<IDWriteFontCollection> fonts;
        return SUCCEEDED(factory->GetSystemFontCollection(&fonts)) && fonts ? 0 : 1;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--d2d-factory"))
    {
        // Create a factory and invoke its interface without a window or display adapter.
        Microsoft::WRL::ComPtr<ID2D1Factory> factory;
        auto result = D2D1CreateFactory(D2D1_FACTORY_TYPE_MULTI_THREADED, __uuidof(ID2D1Factory), nullptr,
            reinterpret_cast<void**>(factory.GetAddressOf()));
        if (FAILED(result) || !factory) return 1;
        FLOAT x = 0, y = 0;
        auto refreshed = factory->ReloadSystemMetrics();
        factory->GetDesktopDpi(&x, &y);
        return SUCCEEDED(refreshed) && x > 0 && y > 0 ? 0 : 1;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--d3d12-factory"))
    {
        // WARP exercises the device factory without requiring a physical display adapter.
        Microsoft::WRL::ComPtr<IDXGIFactory4> factory;
        if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory)))) return 1;
        Microsoft::WRL::ComPtr<IDXGIAdapter> adapter;
        if (FAILED(factory->EnumWarpAdapter(IID_PPV_ARGS(&adapter)))) return 1;
        Microsoft::WRL::ComPtr<ID3D12Device> device;
        if (FAILED(D3D12CreateDevice(adapter.Get(), D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device)))) return 1;
        return device && device->GetNodeCount() ? 0 : 1;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--private-virtual-threaded"))
    {
        std::atomic<uint32_t> failures = 0;
        std::vector<std::jthread> workers;
        for (uint32_t index = 0; index < 4; ++index)
            workers.emplace_back([&]()
            {
                for (uint32_t call = 0; call < 8; ++call)
                    if (!PrivateVirtualWorkload()) ++failures;
            });
        workers.clear();
        return failures ? 1 : 0;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--private-virtual-unknown"))
        return PrivateVirtualUnknownWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--private-virtual")) return PrivateVirtualWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--private-only")) return PrivateInterfaceWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--private-unknown")) return PrivateUnknownWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--private-edit")) return PrivateUnknownWorkload(true) ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--private-stringable")) return PrivateStringableWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--private-projected")) return PrivateProjectedWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--private-generic")) return PrivateParameterizedWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--generic-collections")) return ParameterizedCollectionWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--generic-maps")) return ParameterizedMapWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--reference-arrays")) return ReferenceArrayWorkload() ? 0 : 1;
    if (argc == 2 && !wcscmp(argv[1], L"--generic-structures")) return StructuredGenericWorkload() ? 0 : 1;
    if (argc == 3 && (!wcscmp(argv[1], L"--prepare-factory") || !wcscmp(argv[1], L"--use-factory")))
    {
        if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 2;
        auto valid = !wcscmp(argv[1], L"--prepare-factory") ?
            PrepareFactoryFile(argv[2]) : UseFactoryFile(argv[2]);
        CoUninitialize();
        return valid ? 0 : 1;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--typed-factory"))
    {
        if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 2;
        auto valid = TypedFactoryWorkload();
        CoUninitialize();
        return valid ? 0 : 1;
    }
    if (FAILED(RoInitialize(RO_INIT_MULTITHREADED))) return 2;
    if (argc == 3 && !wcscmp(argv[1], L"--abi-breakpoints"))
    {
        auto valid = ProgramBreakpointWorkload(argv[2]);
        RoUninitialize();
        return valid ? 0 : 1;
    }
    if (argc == 2 && !wcscmp(argv[1], L"--abi-only"))
    {
        auto valid = CustomWorkload();
        RoUninitialize();
        return valid ? 0 : 1;
    }
    bool system = SystemInterfaceWorkload();
    bool dispatch = DispatchWorkload();
    bool inspectable = InspectableWorkload();
    bool custom = CustomWorkload();
    bool generated = CustomWorkload(true);
    bool opaque = OpaqueMenuWorkload();
    bool valid = system && dispatch && inspectable && custom && generated && opaque;
    if (!valid) std::fprintf(stderr,
        "COM fixture failed: system=%d dispatch=%d inspectable=%d custom=%d generated=%d opaque=%d\n",
        system, dispatch, inspectable, custom, generated, opaque);
    std::atomic<uint32_t> failures = 0;
    std::vector<std::jthread> threads;
    for (uint32_t worker = 0; worker < 4; ++worker)
    {
        threads.emplace_back([&]()
        {
            if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) { ++failures; return; }
            for (uint32_t index = 0; index < 8; ++index)
                if (!DispatchWorkload()) ++failures;
            CoUninitialize();
        });
    }
    threads.clear();
    RoUninitialize();
    return valid && !failures ? 0 : 1;
}

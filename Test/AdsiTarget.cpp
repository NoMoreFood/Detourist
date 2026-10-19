#include <windows.h>
#include <objbase.h>
#include <Activeds.h>
#include <AdsHlp.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>

constexpr wchar_t ObjectName[] = L"Detourist\0ADSI directory object";
constexpr wchar_t PropertyName[] = L"ObjectName\0Typed";
constexpr uint64_t PropertyValue = 0x1122334455667788;

// The private implementation exposes an SDK interface without a factory or interface-query boundary.
class DirectoryObject final : public IADs
{
public:
    explicit DirectoryObject(bool arrays = false) : arrays_(arrays) {}
    bool FailArray = false;
    bool UnreadableArray = false;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IUnknown) || iid == __uuidof(IDispatch) || iid == __uuidof(IADs) ? this : nullptr;
        return *value ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR*, UINT, LCID, DISPID*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE get_Name(BSTR* value) override
    {
        if (!value) return E_POINTER;
        *value = SysAllocStringLen(ObjectName, static_cast<UINT>(std::size(ObjectName) - 1));
        return *value ? S_OK : E_OUTOFMEMORY;
    }
    HRESULT STDMETHODCALLTYPE get_Class(BSTR*) override { return E_FAIL; }
    HRESULT STDMETHODCALLTYPE get_GUID(BSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_ADsPath(BSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Parent(BSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE get_Schema(BSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetInfo() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetInfo() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Get(BSTR name, VARIANT* value) override
    {
        if (!ValidName(name) || !value) return E_INVALIDARG;
        VariantInit(value);
        value->vt = VT_UI8;
        value->ullVal = PropertyValue;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Put(BSTR name, VARIANT value) override
    {
        if (!ValidName(name)) return E_INVALIDARG;
        if (value.vt == VT_UI8) return value.ullVal == PropertyValue ? S_OK : E_INVALIDARG;
        if (value.vt != VT_BSTR && value.vt != (VT_BSTR | VT_BYREF)) return E_INVALIDARG;
        BSTR text = value.vt & VT_BYREF ? *value.pbstrVal : value.bstrVal;
        return !text || SysStringLen(text) == std::size(ObjectName) - 1 &&
            !memcmp(text, ObjectName, sizeof(ObjectName) - sizeof(wchar_t)) ? S_OK : E_INVALIDARG;
    }
    HRESULT STDMETHODCALLTYPE GetEx(BSTR name, VARIANT* value) override
    {
        if (!ValidName(name) || !value) return E_INVALIDARG;
        if (arrays_)
        {
            if (FailArray) return E_FAIL;
            VariantInit(value);
            value->vt = VT_ARRAY | VT_VARIANT;
            value->parray = UnreadableArray ? reinterpret_cast<SAFEARRAY*>(0x12345678) : MakeArray(true);
            return value->parray ? S_OK : E_OUTOFMEMORY;
        }
        VariantInit(value);
        value->vt = VT_BSTR;
        value->bstrVal = SysAllocStringLen(ObjectName, static_cast<UINT>(std::size(ObjectName) - 1));
        return value->bstrVal ? S_OK : E_OUTOFMEMORY;
    }
    HRESULT STDMETHODCALLTYPE PutEx(long, BSTR, VARIANT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetInfoEx(VARIANT value, long reserved) override
    {
        if (!arrays_ || reserved) return E_INVALIDARG;
        if (value.vt == (VT_VARIANT | VT_BYREF)) return value.pvarVal ? S_OK : E_INVALIDARG;
        if (!(value.vt & VT_ARRAY)) return E_INVALIDARG;
        auto array = value.vt & VT_BYREF ? *value.pparray : value.parray;
        return array ? S_OK : E_INVALIDARG;
    }
    static SAFEARRAY* MakeArray(bool variants)
    {
        SAFEARRAYBOUND bounds{3, -5};
        auto array = SafeArrayCreate(variants ? VT_VARIANT : VT_BSTR, 1, &bounds);
        if (!array) return nullptr;
        void* memory = nullptr;
        if (SafeArrayAccessData(array, &memory) != S_OK) { SafeArrayDestroy(array); return nullptr; }
        constexpr wchar_t second[] = L"tail\0";
        auto first = SysAllocStringLen(ObjectName, static_cast<UINT>(std::size(ObjectName) - 1));
        auto last = SysAllocStringLen(second, static_cast<UINT>(std::size(second) - 1));
        if (variants)
        {
            auto values = static_cast<VARIANT*>(memory);
            values[0].vt = values[1].vt = values[2].vt = VT_BSTR;
            values[0].bstrVal = first;
            values[1].bstrVal = last;
        }
        else
        {
            auto values = static_cast<BSTR*>(memory);
            values[0] = first;
            values[1] = last;
        }
        SafeArrayUnaccessData(array);
        if (!first || !last) { SafeArrayDestroy(array); return nullptr; }
        return array;
    }
private:
    bool arrays_ = false;
    bool ValidName(BSTR name)
    {
        return name && SysStringLen(name) == std::size(PropertyName) - 1 &&
            !memcmp(name, PropertyName, sizeof(PropertyName) - sizeof(wchar_t));
    }
};

__declspec(noinline) bool InspectArrays(IADs* object)
{
    // Ordinary typed methods expose direct and indirect arrays without an IDispatch invocation.
    for (bool variants : {false, true})
    {
        auto array = DirectoryObject::MakeArray(variants);
        if (!array) return false;
        for (bool byref : {false, true})
        {
            VARIANT value{};
            value.vt = VT_ARRAY | (variants ? VT_VARIANT : VT_BSTR) | (byref ? VT_BYREF : 0);
            if (byref) value.pparray = &array;
            else value.parray = array;
            if (object->GetInfoEx(value, 0) != S_OK) { SafeArrayDestroy(array); return false; }
        }
        SafeArrayDestroy(array);
    }
    VARIANT cyclic{};
    cyclic.vt = VT_VARIANT | VT_BYREF;
    cyclic.pvarVal = &cyclic;
    if (object->GetInfoEx(cyclic, 0) != S_OK) return false;
    auto name = SysAllocStringLen(PropertyName, static_cast<UINT>(std::size(PropertyName) - 1));
    if (!name) return false;
    VARIANT returned{};
    auto result = object->GetEx(name, &returned);
    bool passed = result == S_OK && returned.vt == (VT_ARRAY | VT_VARIANT) && returned.parray;
    VariantClear(&returned);
    SysFreeString(name);
    return passed;
}

__declspec(noinline) bool InspectArrayFailure(IADs* object, bool failed)
{
    auto name = SysAllocStringLen(PropertyName, static_cast<UINT>(std::size(PropertyName) - 1));
    if (!name) return false;
    VARIANT value{};
    value.vt = VT_UI8;
    value.ullVal = PropertyValue;
    auto result = object->GetEx(name, &value);
    bool passed = failed ? result == E_FAIL && value.vt == VT_UI8 && value.ullVal == PropertyValue :
        result == S_OK && value.vt == (VT_ARRAY | VT_VARIANT) &&
            value.parray == reinterpret_cast<SAFEARRAY*>(0x12345678);
    SysFreeString(name);
    return passed;
}

__declspec(noinline) bool Inspect(IADs* object)
{
    // Exercise outputs, embedded-null strings, by-value structures and a failed untouched output.
    BSTR name = nullptr;
    bool passed = object->get_Name(&name) == S_OK && name &&
        SysStringLen(name) == std::size(ObjectName) - 1 &&
        !memcmp(name, ObjectName, sizeof(ObjectName) - sizeof(wchar_t));
    SysFreeString(name);
    BSTR failed = reinterpret_cast<BSTR>(0x12345678);
    passed &= object->get_Class(&failed) == E_FAIL && failed == reinterpret_cast<BSTR>(0x12345678);
    auto property = SysAllocStringLen(PropertyName, static_cast<UINT>(std::size(PropertyName) - 1));
    if (!property) return false;
    VARIANT value{};
    passed &= object->Get(property, &value) == S_OK && value.vt == VT_UI8 && value.ullVal == PropertyValue;
    passed &= object->Put(property, value) == S_OK;

    // By-value variants can reference a counted string directly, through a pointer, or as an empty value.
    auto text = SysAllocStringLen(ObjectName, static_cast<UINT>(std::size(ObjectName) - 1));
    if (!text) return false;
    value.vt = VT_BSTR;
    value.bstrVal = text;
    passed &= object->Put(property, value) == S_OK;
    value.vt = VT_BSTR | VT_BYREF;
    value.pbstrVal = &text;
    passed &= object->Put(property, value) == S_OK;
    value.vt = VT_BSTR;
    value.bstrVal = nullptr;
    passed &= object->Put(property, value) == S_OK;
    SysFreeString(text);
    passed &= object->GetInfo() == S_OK;
    VariantClear(&value);
    passed &= object->GetEx(property, &value) == S_OK && value.vt == VT_BSTR && value.bstrVal &&
        SysStringLen(value.bstrVal) == std::size(ObjectName) - 1;
    VariantClear(&value);
    SysFreeString(property);
    return passed;
}

// Native pointer outputs and nested SDK values preserve their actual x64 field layout.
class DirectoryInformation final : public IDirectoryObject
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void**) override { return E_NOINTERFACE; }
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE GetObjectInformation(PADS_OBJECT_INFO* value) override
    {
        if (!value) return E_POINTER;
        *value = &information_;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetObjectAttributes(LPWSTR*, DWORD, PADS_ATTR_INFO*, DWORD*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE SetObjectAttributes(PADS_ATTR_INFO values, DWORD count, DWORD* modified) override
    {
        if (!values || count != 1 || !modified || values->dwControlCode != ADS_ATTR_UPDATE ||
            values->dwADsType != ADSTYPE_LARGE_INTEGER || values->dwNumValues != 1) return E_INVALIDARG;
        *modified = 1;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateDSObject(LPWSTR, PADS_ATTR_INFO, DWORD, IDispatch**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DeleteDSObject(LPWSTR) override { return E_NOTIMPL; }
private:
    ADS_OBJECT_INFO information_{const_cast<LPWSTR>(L"CN=Fixture"), const_cast<LPWSTR>(L"CN=Fixture,DC=example"),
        const_cast<LPWSTR>(L"DC=example"), const_cast<LPWSTR>(L"CN=Schema,DC=example"),
        const_cast<LPWSTR>(L"computer")};
};

class DirectorySearch final : public IDirectorySearch
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void**) override { return E_NOINTERFACE; }
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE SetSearchPreference(PADS_SEARCHPREF_INFO values, DWORD count) override
    {
        return values && count == 1 && values->dwSearchPref == ADS_SEARCHPREF_PAGESIZE &&
            values->vValue.dwType == ADSTYPE_INTEGER && values->vValue.Integer == 312 ? S_OK : E_INVALIDARG;
    }
    HRESULT STDMETHODCALLTYPE ExecuteSearch(LPWSTR, LPWSTR*, DWORD, PADS_SEARCH_HANDLE) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE AbandonSearch(ADS_SEARCH_HANDLE) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetFirstRow(ADS_SEARCH_HANDLE) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetNextRow(ADS_SEARCH_HANDLE) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPreviousRow(ADS_SEARCH_HANDLE) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetNextColumnName(ADS_SEARCH_HANDLE, LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetColumn(ADS_SEARCH_HANDLE, LPWSTR, PADS_SEARCH_COLUMN) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE FreeColumn(PADS_SEARCH_COLUMN) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CloseSearchHandle(ADS_SEARCH_HANDLE) override { return E_NOTIMPL; }
};

void ReportRegion(std::FILE* report, const char* name, const void* source, size_t bytes)
{
    std::fprintf(report, "%s,", name);
    for (size_t index = 0; index < bytes; ++index)
        std::fprintf(report, "%02x", static_cast<const BYTE*>(source)[index]);
    std::fprintf(report, "\n");
}

__declspec(noinline) bool InspectStructures(IDirectoryObject* object, IDirectorySearch* search, std::FILE* report)
{
    PADS_OBJECT_INFO information = nullptr;
    if (object->GetObjectInformation(&information) != S_OK || !information) return false;
    ReportRegion(report, "information", information, sizeof(*information));
    ADSVALUE value{};
    value.dwType = ADSTYPE_LARGE_INTEGER;
    value.LargeInteger.QuadPart = 0x1122334455667788;
    ADS_ATTR_INFO attribute{const_cast<LPWSTR>(L"accountExpires"), ADS_ATTR_UPDATE, ADSTYPE_LARGE_INTEGER, &value, 1};
    DWORD modified = 0;
    if (object->SetObjectAttributes(&attribute, 1, &modified) != S_OK || modified != 1) return false;
    ReportRegion(report, "attribute", &attribute, sizeof(attribute));
    ADS_SEARCHPREF_INFO preference{};
    preference.dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    preference.vValue.dwType = ADSTYPE_INTEGER;
    preference.vValue.Integer = 312;
    if (search->SetSearchPreference(&preference, 1) != S_OK) return false;
    ReportRegion(report, "preference", &preference, sizeof(preference));
    return true;
}

int wmain(int count, wchar_t** arguments)
{
    if (count == 2 && !wcscmp(arguments[1], L"--exports"))
    {
        // Exercise real ADSI helper exports without requiring a directory server.
        auto module = LoadLibraryExW(L"activeds.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module) return 3;
        auto allocate = reinterpret_cast<decltype(&AllocADsMem)>(GetProcAddress(module, "AllocADsMem"));
        auto release = reinterpret_cast<decltype(&FreeADsMem)>(GetProcAddress(module, "FreeADsMem"));
        auto allocateString = reinterpret_cast<decltype(&AllocADsStr)>(GetProcAddress(module, "AllocADsStr"));
        auto releaseString = reinterpret_cast<decltype(&FreeADsStr)>(GetProcAddress(module, "FreeADsStr"));
        auto buildArray = reinterpret_cast<decltype(&ADsBuildVarArrayInt)>(
            GetProcAddress(module, "ADsBuildVarArrayInt"));
        if (!allocate || !release || !allocateString || !releaseString || !buildArray)
        {
            FreeLibrary(module);
            return 4;
        }
        auto memory = allocate(64);
        auto string = allocateString(L"LDAP://Detourist");
        DWORD numbers[] = {3, 5, 8};
        VARIANT values{};
        auto built = buildArray(numbers, static_cast<DWORD>(std::size(numbers)), &values);
        bool valid = memory && string && SUCCEEDED(built) && (values.vt & VT_ARRAY);
        if (memory) valid &= release(memory) != FALSE;
        if (string) valid &= releaseString(string) != FALSE;
        VariantClear(&values);
        FreeLibrary(module);
        return valid ? 0 : 5;
    }
    if (count == 2 && !wcscmp(arguments[1], L"--arrays"))
    {
        DirectoryObject object(true);
        IADs* observed = &object;
        bool passed = InspectArrays(observed);
        object.FailArray = true;
        passed &= InspectArrayFailure(observed, true);
        object.FailArray = false;
        object.UnreadableArray = true;
        passed &= InspectArrayFailure(observed, false);
        return passed ? 0 : 1;
    }
    if (count == 3 && !wcscmp(arguments[1], L"--structures"))
    {
        std::FILE* report = nullptr;
        if (_wfopen_s(&report, arguments[2], L"w")) return 2;
        DirectoryInformation object;
        DirectorySearch search;
        bool passed = InspectStructures(&object, &search, report);
        std::fclose(report);
        return passed ? 0 : 1;
    }
    DirectoryObject object;
    return Inspect(&object) ? 0 : 1;
}

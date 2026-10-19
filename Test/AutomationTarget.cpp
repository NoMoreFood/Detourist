#include <windows.h>
#include <oaidl.h>
#include <inspectable.h>
#include <oleauto.h>
#include <array>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <string>

// Unique marker methods keep private vtables distinct without RTTI or interface queries on returned objects.
template<DISPID Identity> class AutomationLeaf final : public IDispatch
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == IID_IUnknown || iid == IID_IDispatch ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override
    {
        if (!count) return E_POINTER;
        *count = 0;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR*, UINT count, LCID, DISPID* identifiers) override
    {
        if (count != 1 || !identifiers) return E_INVALIDARG;
        *identifiers = Identity;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID member, REFIID, LCID, WORD, DISPPARAMS*, VARIANT* value,
        EXCEPINFO*, UINT*) override
    {
        if (member != Identity || !value) return DISP_E_MEMBERNOTFOUND;
        VariantInit(value);
        value->vt = VT_UI4;
        value->ulVal = Identity;
        return S_OK;
    }
private:
    std::atomic<ULONG> references_ = 1;
};

class AutomationRecordInfo final : public IRecordInfo
{
public:
    ULONG queries = 0, guidCalls = 0, fieldCalls = 0, references = 1;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        ++queries;
        if (!value) return E_POINTER;
        *value = iid == IID_IUnknown || iid == __uuidof(IRecordInfo) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override { return --references; }
    HRESULT STDMETHODCALLTYPE RecordInit(PVOID) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RecordClear(PVOID) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RecordCopy(PVOID, PVOID) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetGuid(GUID* value) override
    {
        ++guidCalls;
        if (!value) return E_POINTER;
        *value = {0x12345678, 0x9ABC, 0xDEF0, {1, 2, 3, 4, 5, 6, 7, 8}};
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetName(BSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetSize(ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(ITypeInfo**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetField(PVOID data, LPCOLESTR name, VARIANT* value) override
    {
        ++fieldCalls;
        if (!data || !name || !value) return E_POINTER;
        VariantInit(value);
        value->vt = VT_DISPATCH;
        value->pdispVal = *static_cast<IDispatch**>(data);
        value->pdispVal->AddRef();
        return !wcscmp(name, L"Failed") ? E_FAIL : S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetFieldNoCopy(PVOID data, LPCOLESTR name, VARIANT* value, PVOID* output) override
    {
        if (output) *output = nullptr;
        return GetField(data, name, value);
    }
    HRESULT STDMETHODCALLTYPE PutField(ULONG, PVOID, LPCOLESTR, VARIANT*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE PutFieldNoCopy(ULONG, PVOID, LPCOLESTR, VARIANT*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetFieldNames(ULONG*, BSTR*) override { return E_NOTIMPL; }
    BOOL STDMETHODCALLTYPE IsMatchingType(IRecordInfo* value) override { return value == this; }
    PVOID STDMETHODCALLTYPE RecordCreate() override { return nullptr; }
    HRESULT STDMETHODCALLTYPE RecordCreateCopy(PVOID, PVOID*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RecordDestroy(PVOID) override { return E_NOTIMPL; }
};

class AutomationRoot final : public IDispatch
{
public:
    AutomationRoot(std::array<IDispatch*, 3> leaves, const wchar_t* mode) : leaves_(leaves), mode_(mode)
    {
        if (!wcsncmp(mode, L"record-array", 12))
        {
            // A private descriptor bypasses SDK construction calls that would reveal its provider earlier.
            recordStorage_.info = &record_;
            recordArray_ = &recordStorage_.array;
            recordArray_->cDims = 2;
            recordArray_->fFeatures = FADF_RECORD | FADF_STATIC | FADF_AUTO;
            recordArray_->cbElements = sizeof(recordStorage_.data[0]);
            recordArray_->pvData = recordStorage_.data.data();
            recordArray_->rgsabound[0] = {2, -7};
            recordStorage_.lastBound = {2, 5};
            recordStorage_.data[0].object = leaves_[0];
            IRecordInfo* prefix = nullptr;
            memcpy(&prefix, reinterpret_cast<const BYTE*>(recordArray_) - sizeof(prefix), sizeof(prefix));
            layoutValid_ = prefix == &record_ && recordArray_->fFeatures & FADF_RECORD;
            if (!wcscmp(mode, L"record-array-invalid")) recordArray_->fFeatures &= ~FADF_RECORD;
        }
        cycle_.vt = VT_VARIANT | VT_BYREF;
        cycle_.pvarVal = &cycle_;
        SAFEARRAYBOUND bounds[2]{{2, 7}, {2, -3}};
        bool unknown = !wcscmp(mode, L"unknown") || !wcscmp(mode, L"base-tail");
        array_ = SafeArrayCreate(unknown ? VT_UNKNOWN : VT_DISPATCH, 2, bounds);
        if (!array_) return;
        void** data = nullptr;
        if (FAILED(SafeArrayAccessData(array_, reinterpret_cast<void**>(&data)))) return;
        for (size_t index = 0; index < leaves_.size(); ++index)
        {
            leaves_[index]->AddRef();
            data[index] = leaves_[index];
        }
        data[3] = nullptr;
        SafeArrayUnaccessData(array_);
        value_.vt = VT_ARRAY | (unknown ? VT_UNKNOWN : VT_DISPATCH);
        value_.parray = array_;
        single_ = leaves_[0];
        if (!wcscmp(mode, L"nested"))
        {
            SAFEARRAYBOUND extent{3, -5};
            outer_ = SafeArrayCreate(VT_VARIANT, 1, &extent);
            VARIANT* values = nullptr;
            if (!outer_ || FAILED(SafeArrayAccessData(outer_, reinterpret_cast<void**>(&values)))) return;
            values[0] = value_;
            values[1].vt = VT_VARIANT | VT_BYREF;
            values[1].pvarVal = &cycle_;
            values[2].vt = VT_EMPTY;
            SafeArrayUnaccessData(outer_);
            value_.vt = VT_ARRAY | VT_VARIANT;
            value_.parray = outer_;
        }
    }
    ~AutomationRoot()
    {
        if (outer_) SafeArrayDestroy(outer_);
        else if (array_) SafeArrayDestroy(array_);
    }
    bool Ready() const
    {
        return array_ && (wcsncmp(mode_, L"record-array", 12) || recordArray_ && layoutValid_) &&
            (wcscmp(mode_, L"nested") || outer_);
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == IID_IUnknown || iid == IID_IDispatch ? this : nullptr;
        return *value ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override { *count = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR*, UINT, LCID, DISPID*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS* arguments, VARIANT* value,
        EXCEPINFO*, UINT*) override
    {
        if (!value) return E_POINTER;
        if (!wcsncmp(mode_, L"record", 6))
        {
            if (!wcscmp(mode_, L"record-input"))
            {
                if (!arguments || arguments->cArgs != 1 || arguments->rgvarg->vt != VT_RECORD) return E_INVALIDARG;
                GUID guid{};
                value->vt = VT_EMPTY;
                return arguments->rgvarg->pRecInfo->GetGuid(&guid);
            }
            if (!wcsncmp(mode_, L"record-array", 12))
            {
                value->vt = VT_ARRAY | VT_RECORD;
                value->parray = recordArray_;
                if (!wcscmp(mode_, L"record-array-byref"))
                {
                    value->vt |= VT_BYREF;
                    value->pparray = &recordArray_;
                }
                if (!wcscmp(mode_, L"record-array-nested"))
                {
                    recordValue_ = *value;
                    value->vt = VT_VARIANT | VT_BYREF;
                    value->pvarVal = &recordValue_;
                }
                return !wcscmp(mode_, L"record-array-failed") ? E_FAIL : S_OK;
            }
            value->vt = VT_RECORD | (!wcscmp(mode_, L"record-byref") ? VT_BYREF : 0);
            value->pvRecord = leaves_.data();
            value->pRecInfo = &record_;
            if (!wcscmp(mode_, L"record-nested"))
            {
                recordValue_ = *value;
                value->vt = VT_VARIANT | VT_BYREF;
                value->pvarVal = &recordValue_;
            }
            return !wcscmp(mode_, L"record-failed") ? E_FAIL : S_OK;
        }
        *value = value_;
        if (!wcscmp(mode_, L"byref-array"))
        {
            value->vt |= VT_BYREF;
            value->pparray = &array_;
        }
        else if (!wcscmp(mode_, L"byref"))
        {
            value->vt = VT_DISPATCH | VT_BYREF;
            value->ppdispVal = &single_;
        }
        else if (!wcscmp(mode_, L"cycle"))
        {
            value->vt = VT_VARIANT | VT_BYREF;
            value->pvarVal = &cycle_;
        }
        return !wcscmp(mode_, L"failed") ? E_FAIL : S_OK;
    }
public:
    AutomationRecordInfo record_;
private:
    VARIANT recordValue_{};
    std::array<IDispatch*, 3> leaves_;
    const wchar_t* mode_;
    SAFEARRAY* array_ = nullptr;
    SAFEARRAY* outer_ = nullptr;
    struct RecordStorage
    {
        IRecordInfo* info = nullptr;
        SAFEARRAY array{};
        SAFEARRAYBOUND lastBound{};
        struct RecordCell { IDispatch* object; ULONGLONG marker; };
        std::array<RecordCell, 4> data{};
    } recordStorage_;
    static_assert(offsetof(RecordStorage, array) == sizeof(IRecordInfo*));
    SAFEARRAY* recordArray_ = nullptr;
    bool layoutValid_ = false;
    VARIANT value_{}, cycle_{};
    IDispatch* single_ = nullptr;
};

__declspec(noinline) HRESULT Query(IUnknown* object, REFIID iid, void** value)
{
    return object->QueryInterface(iid, value);
}

__declspec(noinline) bool Touch(IDispatch* object, DISPID identity)
{
    UINT count = 1;
    if (object->GetTypeInfoCount(&count) != S_OK || count != 0) return false;
    DISPPARAMS parameters{};
    VARIANT value{};
    return object->Invoke(identity, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
        &parameters, &value, nullptr, nullptr) == S_OK && value.vt == VT_UI4 && value.ulVal == identity;
}



struct InspectionProbe : IInspectable
{
    virtual ULONGLONG STDMETHODCALLTYPE InspectValue(ULONGLONG value, GUID* output) = 0;
};

template<ULONG Identity> class InspectionLeaf final : public InspectionProbe
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == __uuidof(IInspectable) ? this : nullptr;
        return *output ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return Identity + 1; }
    ULONG STDMETHODCALLTYPE Release() override { return Identity; }
    HRESULT STDMETHODCALLTYPE GetIids(ULONG* count, IID** output) override
    {
        if (!count || !output) return E_POINTER;
        *count = 0;
        *output = nullptr;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetRuntimeClassName(HSTRING* output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetTrustLevel(TrustLevel* output) override
    {
        if (!output) return E_POINTER;
        *output = BaseTrust;
        return S_OK;
    }
    ULONGLONG STDMETHODCALLTYPE InspectValue(ULONGLONG value, GUID* output) override
    {
        if (output) *output = GUID{Identity, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};
        return value ^ Identity;
    }
};

__declspec(noinline) ULONGLONG InspectValue(InspectionProbe* instance, GUID* output)
{
    return instance->InspectValue(0x1122334455667788ull, output);
}

ULONGLONG STDMETHODCALLTYPE ChangedInspectionValue(InspectionProbe*, ULONGLONG value, GUID* output)
{
    if (output) *output = GUID{2, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};
    return value ^ 2;
}

bool InspectableTail(bool changing = false)
{
    InspectionLeaf<1> selected;
    InspectionLeaf<99> control;
    std::array<void*, 7> writable{};
    auto table = *reinterpret_cast<void***>(&selected);
    if (changing)
    {
        memcpy(writable.data(), table, sizeof(writable));
        *reinterpret_cast<void***>(&selected) = writable.data();
    }
    void* queried = nullptr;
    if (Query(&selected, __uuidof(IInspectable), &queried) != S_OK) return false;
    auto instance = static_cast<IInspectable*>(queried);
    ULONG count = 99;
    IID* identities = reinterpret_cast<IID*>(1);
    if (instance->GetIids(&count, &identities) != S_OK || count || identities) return false;
    GUID output{};
    bool passed = InspectValue(static_cast<InspectionProbe*>(instance), &output) == 0x1122334455667789ull &&
        output.Data1 == 1 && InspectValue(&control, nullptr) == (0x1122334455667788ull ^ 99);
    if (changing)
    {
        // A discovered table can change a derived method without issuing another interface query.
        writable[6] = reinterpret_cast<void*>(&ChangedInspectionValue);
        passed = passed && InspectValue(static_cast<InspectionProbe*>(instance), &output) ==
            (0x1122334455667788ull ^ 2) && output.Data1 == 2;

        // Reuse the same storage for an unobserved table whose base methods establish a different identity.
        auto unobserved = *reinterpret_cast<void***>(&control);
        memcpy(writable.data(), unobserved, sizeof(writable));
        *reinterpret_cast<void***>(&control) = writable.data();
        passed = passed && InspectValue(&control, nullptr) == (0x1122334455667788ull ^ 99);
        writable[6] = reinterpret_cast<void*>(&ChangedInspectionValue);
        passed = passed && InspectValue(&control, nullptr) == (0x1122334455667788ull ^ 2);

        // A real interface query admits the replacement table as a new lifetime before its next call.
        void* replacement = nullptr;
        passed = passed && Query(&control, __uuidof(IInspectable), &replacement) == S_OK &&
            InspectValue(static_cast<InspectionProbe*>(static_cast<IInspectable*>(replacement)), nullptr) ==
                (0x1122334455667788ull ^ 2);
        *reinterpret_cast<void***>(&control) = unobserved;
        *reinterpret_cast<void***>(&selected) = table;
    }
    return passed;
}

struct InspectionTask
{
    InspectionProbe* instance;
    HANDLE go;
    volatile LONG ready = 0;
};

DWORD WINAPI InspectWorker(void* argument)
{
    auto& task = *static_cast<InspectionTask*>(argument);
    InterlockedIncrement(&task.ready);
    if (WaitForSingleObject(task.go, 15000) != WAIT_OBJECT_0) return 1;
    return InspectValue(task.instance, nullptr) == (0x1122334455667788ull ^ 55) ? 0 : 1;
}

bool ConcurrentInspection()
{
    InspectionLeaf<55> selected;
    void* queried = nullptr;
    if (Query(&selected, __uuidof(IInspectable), &queried) != S_OK) return false;
    HANDLE go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!go) return false;
    InspectionTask task{&selected, go};
    std::array<HANDLE, 8> workers{};
    LONG created = 0;
    bool passed = true;
    for (auto& worker : workers)
    {
        worker = CreateThread(nullptr, 0, &InspectWorker, &task, CREATE_SUSPENDED, nullptr);
        if (!worker) passed = false;
        else ++created;
    }
    for (auto worker : workers) if (worker) ResumeThread(worker);
    auto deadline = GetTickCount64() + 10000;
    while (InterlockedCompareExchange(&task.ready, 0, 0) != created && GetTickCount64() < deadline) Sleep(1);
    passed = passed && task.ready == created;
    SetEvent(go);
    for (auto worker : workers)
    {
        if (!worker) continue;
        DWORD result = 1;
        passed = WaitForSingleObject(worker, 15000) == WAIT_OBJECT_0 &&
            GetExitCodeThread(worker, &result) && !result && passed;
        CloseHandle(worker);
    }
    CloseHandle(go);
    return passed;
}


bool InspectionGate(const std::wstring& path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    CloseHandle(file);
    return true;
}

bool AttachedInspection(const wchar_t* root)
{
    InspectionLeaf<1> selected;
    void* output = nullptr;
    if (Query(&selected, __uuidof(IInspectable), &output) != S_OK) return false;
    if (InspectValue(static_cast<InspectionProbe*>(static_cast<IInspectable*>(output)), nullptr) !=
        0x1122334455667789ull) return false;
    for (unsigned phase = 0; phase < 3; ++phase)
    {
        auto prefix = std::wstring(root) + L"\\" + std::to_wstring(phase);
        if (!InspectionGate(prefix + L".ready")) return false;
        auto deadline = GetTickCount64() + 60000;
        auto go = prefix + L".go";
        while (GetFileAttributesW(go.c_str()) == INVALID_FILE_ATTRIBUTES && GetTickCount64() < deadline) Sleep(10);
        if (GetFileAttributesW(go.c_str()) == INVALID_FILE_ATTRIBUTES) return false;

        // A real query reestablishes the interface boundary before its first call in this capture session.
        if (Query(&selected, __uuidof(IInspectable), &output) != S_OK ||
            InspectValue(static_cast<InspectionProbe*>(static_cast<IInspectable*>(output)), nullptr) !=
                0x1122334455667789ull || !InspectionGate(prefix + L".done")) return false;
        auto released = prefix + L".release";
        deadline = GetTickCount64() + 60000;
        while (GetFileAttributesW(released.c_str()) == INVALID_FILE_ATTRIBUTES && GetTickCount64() < deadline)
            Sleep(10);
        if (GetFileAttributesW(released.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    }
    return true;
}

template<ULONG Identity> class AutomationEnumerator final : public IEnumVARIANT
{
public:
    AutomationEnumerator(std::array<IDispatch*, 3> leaves) : leaves_(leaves) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == IID_IEnumVARIANT ? this : nullptr;
        return *output ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return Identity + 1; }
    ULONG STDMETHODCALLTYPE Release() override { return Identity; }
    HRESULT STDMETHODCALLTYPE Next(ULONG capacity, VARIANT* values, ULONG* fetched) override
    {
        if (!values || (!fetched && capacity != 1)) return E_INVALIDARG;
        if (capacity == 99) return E_FAIL;
        ULONG count = 0;
        while (position_ < leaves_.size() && count < capacity)
        {
            VariantInit(values + count);
            values[count].vt = position_ == 1 ? VT_UNKNOWN : VT_DISPATCH;
            values[count].pdispVal = leaves_[position_++];
            values[count].pdispVal->AddRef();
            ++count;
        }
        if (fetched) *fetched = count;
        return count == capacity ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG count) override
    {
        auto skipped = static_cast<ULONG>(std::min<size_t>(count, leaves_.size() - position_));
        position_ += skipped;
        return skipped == count ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Reset() override { position_ = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumVARIANT** output) override
    {
        if (!output) return E_POINTER;
        *output = clone_;
        return clone_ ? S_OK : E_NOTIMPL;
    }
    void SetClone(IEnumVARIANT* clone) { clone_ = clone; }
private:
    std::array<IDispatch*, 3> leaves_;
    size_t position_ = 0;
    IEnumVARIANT* clone_ = nullptr;
};

class EnumerationRoot final : public IDispatch
{
public:
    explicit EnumerationRoot(IEnumVARIANT* enumerator) : enumerator_(enumerator) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == IID_IDispatch ? this : nullptr;
        return *output ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override { *count = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR*, UINT, LCID, DISPID*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT* output,
        EXCEPINFO*, UINT*) override
    {
        if (!output) return E_POINTER;
        VariantInit(output);
        output->vt = VT_UNKNOWN;
        output->punkVal = enumerator_;
        return S_OK;
    }
private:
    IEnumVARIANT* enumerator_;
};

bool EnumeratedInterfaces(std::array<IDispatch*, 3> leaves, IDispatch* control)
{
    // A real Automation input discovers a private factory without RTTI in either capture engine.
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return false;
    AutomationEnumerator<21> source(leaves);
    AutomationEnumerator<22> clone(leaves);
    source.SetClone(&clone);
    EnumerationRoot root(&source);
    CLSID identifier{};
    IDispatch* dictionary = nullptr;
    bool passed = SUCCEEDED(CLSIDFromProgID(L"Scripting.Dictionary", &identifier)) &&
        SUCCEEDED(CoCreateInstance(identifier, nullptr, CLSCTX_INPROC_SERVER, IID_IDispatch,
            reinterpret_cast<void**>(&dictionary)));
    DISPID add = 0;
    LPOLESTR name = const_cast<LPOLESTR>(L"Add");
    if (passed) passed = dictionary->GetIDsOfNames(IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &add) == S_OK;
    if (passed)
    {
        VARIANT arguments[2]{};
        arguments[0].vt = VT_DISPATCH;
        arguments[0].pdispVal = &root;
        arguments[1].vt = VT_I4;
        DISPPARAMS parameters{arguments, nullptr, 2, 0};
        passed = dictionary->Invoke(add, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
            &parameters, nullptr, nullptr, nullptr) == S_OK;
    }
    DISPPARAMS parameters{};
    VARIANT returned{};
    IDispatch* factory = &root;
    passed = passed && factory->Invoke(DISPID_NEWENUM, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET,
        &parameters, &returned, nullptr, nullptr) == S_OK;
    IEnumVARIANT* enumerator = nullptr;
    passed = passed && returned.punkVal->QueryInterface(IID_IEnumVARIANT,
        reinterpret_cast<void**>(&enumerator)) == S_OK;
    VARIANT values[4]{};
    for (auto& value : values) { value.vt = VT_DISPATCH; value.pdispVal = control; }
    ULONG fetched = 99;
    passed = passed && enumerator->Next(4, values, &fetched) == S_FALSE && fetched == 3;
    void* dispatch = nullptr;
    passed = passed && values[1].punkVal->QueryInterface(IID_IDispatch, &dispatch) == S_OK;
    for (size_t index = 0; passed && index < leaves.size(); ++index)
        passed = Touch(leaves[index], static_cast<DISPID>(index + 1));
    for (auto& value : values) { value.vt = VT_DISPATCH; value.pdispVal = control; }
    passed = passed && enumerator->Next(4, values, &fetched) == S_FALSE && fetched == 0;
    fetched = 4;
    passed = passed && enumerator->Next(99, values, &fetched) == E_FAIL;
    passed = passed && enumerator->Reset() == S_OK && enumerator->Skip(1) == S_OK &&
        enumerator->Next(1, values, nullptr) == S_OK && Touch(leaves[1], 2);
    IEnumVARIANT* copied = nullptr;
    passed = passed && enumerator->Clone(&copied) == S_OK && copied != enumerator;
    passed = passed && copied->Next(3, values, &fetched) == S_OK && fetched == 3;
    for (size_t index = 0; passed && index < leaves.size(); ++index)
        passed = Touch(leaves[index], static_cast<DISPID>(index + 1));
    passed = passed && Touch(control, 99);
    if (dictionary) dictionary->Release();
    CoUninitialize();
    return passed;
}

bool DictionaryInputs(std::array<IDispatch*, 3> leaves)
{
    auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return false;
    CLSID identifier{};
    IDispatch* dictionary = nullptr;
    bool passed = SUCCEEDED(CLSIDFromProgID(L"Scripting.Dictionary", &identifier)) &&
        SUCCEEDED(CoCreateInstance(identifier, nullptr, CLSCTX_INPROC_SERVER, IID_IDispatch,
            reinterpret_cast<void**>(&dictionary)));
    if (passed)
    {
        LPOLESTR name = const_cast<LPOLESTR>(L"Add");
        DISPID add = 0;
        passed = dictionary->GetIDsOfNames(IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &add) == S_OK;
        for (size_t index = 0; passed && index < leaves.size(); ++index)
        {
            VARIANT arguments[2]{};
            arguments[0].vt = VT_DISPATCH;
            arguments[0].pdispVal = leaves[index];
            arguments[1].vt = VT_I4;
            arguments[1].lVal = static_cast<LONG>(index);
            DISPPARAMS parameters{arguments, nullptr, 2, 0};
            passed = dictionary->Invoke(add, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
                &parameters, nullptr, nullptr, nullptr) == S_OK;
        }
        for (size_t index = 0; passed && index < leaves.size(); ++index)
            passed = Touch(leaves[index], static_cast<DISPID>(index + 1));
    }
    if (dictionary) dictionary->Release();
    CoUninitialize();
    return passed;
}

bool DictionaryStrings(bool byref)
{
    // A real Automation server copies direct strings and retains by-reference variant contracts.
    auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return false;
    CLSID identifier{};
    IDispatch* dictionary = nullptr;
    bool passed = SUCCEEDED(CLSIDFromProgID(L"Scripting.Dictionary", &identifier)) &&
        SUCCEEDED(CoCreateInstance(identifier, nullptr, CLSCTX_INPROC_SERVER, IID_IDispatch,
            reinterpret_cast<void**>(&dictionary)));
    DISPID add = 0;
    LPOLESTR name = const_cast<LPOLESTR>(L"Add");
    if (passed) passed = dictionary->GetIDsOfNames(IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &add) == S_OK;
    constexpr wchar_t first[] = L"alpha\0omega";
    constexpr wchar_t second[] = L"tail\0";
    for (LONG index = 0; passed && index < 2; ++index)
    {
        SAFEARRAYBOUND bounds{3, -5};
        auto array = SafeArrayCreate(index ? VT_VARIANT : VT_BSTR, 1, &bounds);
        if (!array) { passed = false; break; }
        BSTR indirect = SysAllocStringLen(second, static_cast<UINT>(std::size(second) - 1));
        VARIANT nested{};
        nested.vt = VT_BSTR;
        nested.bstrVal = indirect;
        void* memory = nullptr;
        passed = indirect && SafeArrayAccessData(array, &memory) == S_OK;
        if (passed)
        {
            BSTR owned = SysAllocStringLen(first, static_cast<UINT>(std::size(first) - 1));
            passed = owned != nullptr;
            if (!index)
            {
                auto values = static_cast<BSTR*>(memory);
                values[0] = owned;
                values[1] = SysAllocStringLen(second, static_cast<UINT>(std::size(second) - 1));
                values[2] = nullptr;
                passed = passed && values[1];
            }
            else
            {
                auto values = static_cast<VARIANT*>(memory);
                values[0].vt = VT_BSTR;
                values[0].bstrVal = owned;
                values[1].vt = VT_BSTR | VT_BYREF;
                values[1].pbstrVal = &indirect;
                values[2].vt = VT_VARIANT | VT_BYREF;
                values[2].pvarVal = &nested;
            }
            SafeArrayUnaccessData(array);
            VARIANT arguments[2]{};
            arguments[0].vt = VT_ARRAY | (index ? VT_VARIANT : VT_BSTR) | (byref ? VT_BYREF : 0);
            if (byref) arguments[0].pparray = &array;
            else arguments[0].parray = array;
            arguments[1].vt = VT_I4;
            arguments[1].lVal = index;
            DISPPARAMS parameters{arguments, nullptr, 2, 0};
            passed = passed && dictionary->Invoke(add, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
                &parameters, nullptr, nullptr, nullptr) == S_OK;
            DISPPARAMS key{arguments + 1, nullptr, 1, 0};
            VARIANT result{};
            passed = passed && dictionary->Invoke(DISPID_VALUE, IID_NULL, LOCALE_USER_DEFAULT,
                DISPATCH_PROPERTYGET, &key, &result, nullptr, nullptr) == S_OK &&
                result.vt == (VT_ARRAY | (index ? VT_VARIANT : VT_BSTR));
            if (passed)
            {
                void* returned = nullptr;
                passed = SafeArrayAccessData(result.parray, &returned) == S_OK;
                if (passed)
                {
                    BSTR actual = index ? static_cast<VARIANT*>(returned)[0].bstrVal :
                        static_cast<BSTR*>(returned)[0];
                    passed = actual && SysStringByteLen(actual) == (std::size(first) - 1) * sizeof(wchar_t) &&
                        !memcmp(actual, first, (std::size(first) - 1) * sizeof(wchar_t));
                    SafeArrayUnaccessData(result.parray);
                }
            }
            VariantClear(&result);
        }
        SafeArrayDestroy(array);
        SysFreeString(indirect);
    }
    if (dictionary) dictionary->Release();
    CoUninitialize();
    return passed;
}

bool DictionaryArrays(bool byref)
{
    auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return false;
    CLSID identifier{};
    IDispatch* dictionary = nullptr;
    bool passed = SUCCEEDED(CLSIDFromProgID(L"Scripting.Dictionary", &identifier)) &&
        SUCCEEDED(CoCreateInstance(identifier, nullptr, CLSCTX_INPROC_SERVER, IID_IDispatch,
            reinterpret_cast<void**>(&dictionary)));
    DISPID add = 0;
    LPOLESTR name = const_cast<LPOLESTR>(L"Add");
    if (passed) passed = dictionary->GetIDsOfNames(IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &add) == S_OK;
    constexpr VARTYPE types[]{VT_I4, VT_R8, VT_BOOL, VT_VARIANT, VT_I4};
    for (size_t index = 0; passed && index < std::size(types); ++index)
    {
        SAFEARRAYBOUND bounds[2]{{3, -4}, {2, 5}};
        if (index) bounds[0] = {index == 2 ? 4u : index == 4 ? 0u : 3u, -2};
        auto array = SafeArrayCreate(types[index], index ? 1 : 2, bounds);
        if (!array) { passed = false; break; }
        void* memory = nullptr;
        passed = SafeArrayAccessData(array, &memory) == S_OK;
        LONG integers[]{-7, 0, 42, LONG_MIN, LONG_MAX, 123456};
        double floats[]{-3.25, 0.5, 1.125};
        VARIANT_BOOL booleans[]{VARIANT_TRUE, VARIANT_FALSE, VARIANT_TRUE, VARIANT_FALSE};
        VARIANT variants[3]{};
        variants[0].vt = VT_I4;
        variants[0].lVal = -99;
        variants[1].vt = VT_R8;
        variants[1].dblVal = 3.5;
        variants[2].vt = VT_UI4;
        variants[2].ulVal = 0xDEADBEEF;
        const void* expected = index == 0 ? static_cast<void*>(integers) : index == 1 ?
            static_cast<void*>(floats) : index == 2 ? static_cast<void*>(booleans) :
            static_cast<void*>(variants);
        size_t bytes = index == 0 ? sizeof(integers) : index == 1 ? sizeof(floats) :
            index == 2 ? sizeof(booleans) : index == 3 ? sizeof(variants) : 0;
        if (passed)
        {
            if (bytes) memcpy(memory, expected, bytes);
            SafeArrayUnaccessData(array);
            VARIANT arguments[2]{};
            arguments[0].vt = VT_ARRAY | types[index] | (byref ? VT_BYREF : 0);
            if (byref) arguments[0].pparray = &array;
            else arguments[0].parray = array;
            arguments[1].vt = VT_I4;
            arguments[1].lVal = static_cast<LONG>(index);
            DISPPARAMS parameters{arguments, nullptr, 2, 0};
            passed = dictionary->Invoke(add, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
                &parameters, nullptr, nullptr, nullptr) == S_OK;
            DISPPARAMS key{arguments + 1, nullptr, 1, 0};
            VARIANT result{};
            passed = passed && dictionary->Invoke(DISPID_VALUE, IID_NULL, LOCALE_USER_DEFAULT,
                DISPATCH_PROPERTYGET, &key, &result, nullptr, nullptr) == S_OK &&
                result.vt == (VT_ARRAY | types[index]);
            if (passed)
            {
                void* returned = nullptr;
                passed = SafeArrayAccessData(result.parray, &returned) == S_OK;
                if (passed)
                {
                    passed = !bytes || !memcmp(returned, expected, bytes);
                    SafeArrayUnaccessData(result.parray);
                }
            }
            VariantClear(&result);
        }
        SafeArrayDestroy(array);
    }
    if (dictionary) dictionary->Release();
    CoUninitialize();
    return passed;
}

int wmain(int argc, wchar_t** argv)
{
    auto mode = argc > 1 ? argv[1] : L"array";
    if (!wcscmp(mode, L"attach-tail") && argc == 3) return AttachedInspection(argv[2]) ? 0 : 14;
    if (!wcscmp(mode, L"strings") || !wcscmp(mode, L"byref-strings"))
        return DictionaryStrings(!wcscmp(mode, L"byref-strings")) ? 0 : 9;
    if (!wcscmp(mode, L"values") || !wcscmp(mode, L"byref-values"))
        return DictionaryArrays(!wcscmp(mode, L"byref-values")) ? 0 : 8;
    if (!wcscmp(mode, L"inspect-tail")) return InspectableTail() ? 0 : 11;
    if (!wcscmp(mode, L"changing-tail")) return InspectableTail(true) ? 0 : 12;
    if (!wcscmp(mode, L"concurrent-tail")) return ConcurrentInspection() ? 0 : 13;
    AutomationLeaf<1> first;
    AutomationLeaf<2> second;
    AutomationLeaf<3> third;
    AutomationLeaf<99> control;
    std::array<IDispatch*, 3> leaves{&first, &second, &third};
    if (!wcscmp(mode, L"enumerate"))
        return EnumeratedInterfaces(leaves, &control) ? 0 : 10;
    if (!wcscmp(mode, L"input"))
        return DictionaryInputs(leaves) && Touch(&control, 99) ? 0 : 1;
    AutomationRoot root(leaves, mode);
    if (!root.Ready()) return 2;
    void* selected = nullptr;
    if (FAILED(Query(&root, IID_IDispatch, &selected))) return 3;
    auto dispatch = static_cast<IDispatch*>(selected);
    DISPPARAMS parameters{};
    VARIANT supplied{};
    if (!wcscmp(mode, L"record-input"))
    {
        supplied.vt = VT_RECORD;
        supplied.pvRecord = leaves.data();
        supplied.pRecInfo = &root.record_;
        parameters.rgvarg = &supplied;
        parameters.cArgs = 1;
    }
    VARIANT result{};
    auto invoked = dispatch->Invoke(1, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
        &parameters, &result, nullptr, nullptr);
    if (invoked != (!wcscmp(mode, L"failed") || !wcscmp(mode, L"record-failed") ||
        !wcscmp(mode, L"record-array-failed") ? E_FAIL : S_OK)) return 4;
    if (!wcsncmp(mode, L"record", 6))
    {
        // Record metadata and completed field values expose private interfaces without querying those objects.
        auto record = !wcscmp(mode, L"record-input") ? &supplied :
            result.vt == (VT_VARIANT | VT_BYREF) ? result.pvarVal : &result;
        auto info = record->pRecInfo;
        auto data = record->pvRecord;
        if (!wcsncmp(mode, L"record-array", 12))
        {
            auto array = record->vt & VT_BYREF ? *record->pparray : record->parray;
            memcpy(&info, reinterpret_cast<const BYTE*>(array) - sizeof(info), sizeof(info));
            data = array->pvData;
        }
        info->AddRef();
        info->Release();
        GUID guid{};
        if (wcscmp(mode, L"record-input") &&
            (info->GetGuid(&guid) != S_OK || guid.Data1 != 0x12345678)) return 15;
        VARIANT field{};
        if (info->GetField(data, L"Leaf", &field) != S_OK || field.pdispVal != &first ||
            !Touch(field.pdispVal, 1)) return 16;
        field.pdispVal->Release();
        VARIANT failed{};
        auto other = leaves.data() + 1;
        if (info->GetField(other, L"Failed", &failed) != E_FAIL || !Touch(&second, 2)) return 17;
        failed.pdispVal->Release();
        printf("record_queries=%lu guid_calls=%lu field_calls=%lu\n", root.record_.queries,
            root.record_.guidCalls, root.record_.fieldCalls);
        return root.record_.queries == 0 && root.record_.guidCalls == 1 && root.record_.fieldCalls == 2 &&
            root.record_.references == 1 && Touch(&control, 99) ? 0 : 18;
    }
    auto count = !wcscmp(mode, L"byref") ? 1u : 3u;
    if (!wcscmp(mode, L"unknown"))
    {
        // The array exposes IUnknown first; its initial reference calls must be visible before any query.
        for (auto leaf : leaves) { leaf->AddRef(); leaf->Release(); }
        for (auto leaf : leaves)
        {
            void* value = nullptr;
            if (FAILED(Query(leaf, IID_IDispatch, &value))) return 5;
            static_cast<IDispatch*>(value)->Release();
        }
    }
    for (size_t index = 0; index < count; ++index)
        if (!Touch(leaves[index], static_cast<DISPID>(index + 1))) return 6;
    return Touch(&control, 99) ? 0 : 7;
}

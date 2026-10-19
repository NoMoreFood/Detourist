#include "TestSupport.h"
#include <mswmdm.h>

using namespace Detourist::Tests;
// Each private object has a distinct vtable and no RTTI or interface-query boundary.
template<ULONG Identity> class ArrayItem final : public FixedUnknown<IShellItem>
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void** value) override
    {
        if (value) *value = nullptr;
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE BindToHandler(IBindCtx*, REFGUID, REFIID, void**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetParent(IShellItem**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetDisplayName(SIGDN, PWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetAttributes(SFGAOF mask, SFGAOF* value) override
    {
        if (!value) return E_POINTER;
        *value = Identity & mask;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Compare(IShellItem*, SICHINTF, int*) override { return E_NOTIMPL; }
};


template<ULONG Identity> class ArrayStream final : public FixedUnknown<ISequentialStream>
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void** value) override
    {
        if (value) *value = nullptr;
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Read(void* value, ULONG bytes, ULONG* count) override
    {
        memset(value, Identity, bytes);
        if (count) *count = bytes;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Write(const void*, ULONG bytes, ULONG* count) override
    {
        if (count) *count = bytes;
        return S_OK;
    }
};

struct __declspec(uuid("2f5e21e4-549a-4db3-af03-1c7780d12b9a")) IArrayProbe : public IUnknown
{
    virtual ULONG STDMETHODCALLTYPE Transform(ULONG value) = 0;
};

template<ULONG Identity> class ArrayProbe final : public FixedUnknown<IArrayProbe>
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void** value) override
    {
        if (value) *value = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE Transform(ULONG value) override { return value ^ Identity; }
};

class ItemEnumerator final : public FixedUnknown<IEnumShellItems>
{
public:
    ItemEnumerator(std::array<IShellItem*, 3> items, ULONG completed, HRESULT result)
        : items_(items), completed_(completed), result_(result) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IEnumShellItems) ? this : nullptr;
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG capacity, IShellItem** items, ULONG* count) override
    {
        auto completed = std::min(capacity, completed_);
        for (ULONG index = 0; index < completed; ++index) items[index] = items_[index];
        if (count) *count = completed;
        return result_;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumShellItems**) override { return E_NOTIMPL; }
private:
    std::array<IShellItem*, 3> items_;
    ULONG completed_;
    HRESULT result_;
};

class ObjectEnumerator final : public FixedUnknown<IEnumObjects>
{
public:
    ObjectEnumerator(std::array<IUnknown*, 3> streams, REFIID iid) : streams_(streams), iid_(iid) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IEnumObjects) ? this : nullptr;
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG capacity, REFIID iid, void** items, ULONG* count) override
    {
        if (iid != iid_) return E_NOINTERFACE;
        auto completed = std::min<ULONG>(capacity, static_cast<ULONG>(streams_.size()));
        for (ULONG index = 0; index < completed; ++index) items[index] = streams_[index];
        if (count) *count = completed;
        return completed == capacity ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumObjects**) override { return E_NOTIMPL; }
private:
    std::array<IUnknown*, 3> streams_;
    GUID iid_;
};

// The input policies implement the SDK ABI without exposing RTTI or a query on the policies themselves.
class PolicyDefaults : public FixedUnknown<IMFOutputPolicy>
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void** value) override
    {
        if (value) *value = nullptr;
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE GetItem(const GUID & guidKey, PROPVARIANT * pValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetItemType(
        const GUID & guidKey, MF_ATTRIBUTE_TYPE * pType) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE CompareItem(
        const GUID & guidKey, const PROPVARIANT & Value, BOOL * pbResult) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE Compare(
        IMFAttributes * pTheirs, MF_ATTRIBUTES_MATCH_TYPE MatchType, BOOL * pbResult) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetUINT32(const GUID & guidKey, UINT32 * punValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetUINT64(const GUID & guidKey, UINT64 * punValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetDouble(const GUID & guidKey, double * pfValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetGUID(const GUID & guidKey, GUID * pguidValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetStringLength(const GUID & guidKey, UINT32 * pcchLength) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetString(
        const GUID & guidKey, LPWSTR pwszValue, UINT32 cchBufSize, UINT32 * pcchLength) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetAllocatedString(
        const GUID & guidKey, LPWSTR * ppwszValue, UINT32 * pcchLength) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetBlobSize(const GUID & guidKey, UINT32 * pcbBlobSize) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetBlob(
        const GUID & guidKey, UINT8 * pBuf, UINT32 cbBufSize, UINT32 * pcbBlobSize) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetAllocatedBlob(
        const GUID & guidKey, UINT8 ** ppBuf, UINT32 * pcbSize) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetUnknown(
        const GUID & guidKey, const IID & riid, LPVOID * ppv) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE SetItem(const GUID & guidKey, const PROPVARIANT & Value) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DeleteItem(const GUID & guidKey) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DeleteAllItems() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetUINT32(const GUID & guidKey, UINT32 unValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetUINT64(const GUID & guidKey, UINT64 unValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetDouble(const GUID & guidKey, double fValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetGUID(const GUID & guidKey, const GUID & guidValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetString(const GUID & guidKey, LPCWSTR wszValue) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetBlob(
        const GUID & guidKey, const UINT8 * pBuf, UINT32 cbBufSize) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE SetUnknown(const GUID & guidKey, IUnknown * pUnknown) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE LockStore() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE UnlockStore() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCount(UINT32 * pcItems) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetItemByIndex(
        UINT32 unIndex, GUID * pguidKey, PROPVARIANT * pValue) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE CopyAllItems(IMFAttributes * pDest) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GenerateRequiredSchemas(DWORD, GUID, GUID*, DWORD, IMFCollection**) override
    {
        return E_NOTIMPL;
    }
};

template<ULONG Identity> class ArrayPolicy final : public PolicyDefaults
{
public:
    HRESULT STDMETHODCALLTYPE GetOriginatorID(GUID* value) override
    {
        if (!value) return E_POINTER;
        *value = {Identity, 0x1234, 0x5678, {1, 2, 3, 4, 5, 6, 7, 8}};
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetMinimumGRLVersion(DWORD* value) override
    {
        if (!value) return E_POINTER;
        *value = Identity;
        return S_OK;
    }
};

class PolicyAuthority final : public FixedUnknown<IMFOutputTrustAuthority>
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IMFOutputTrustAuthority) ? this : nullptr;
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE GetAction(MFPOLICYMANAGER_ACTION*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetPolicy(IMFOutputPolicy** policies, DWORD count, BYTE** ticket, DWORD* bytes) override
    {
        for (DWORD index = 0; index < count; ++index)
        {
            GUID identity{};
            if (policies[index]->GetOriginatorID(&identity) != S_OK || identity.Data1 != index + 1)
                return E_UNEXPECTED;
        }
        if (ticket) *ticket = nullptr;
        if (bytes) *bytes = 0;
        return S_OK;
    }
};

__declspec(noinline) HRESULT Query(IUnknown* value, REFIID iid, void** result)
{
    return value->QueryInterface(iid, result);
}

__declspec(noinline) bool TouchItem(IShellItem* item, ULONG identity)
{
    SFGAOF value = 0;
    return item->GetAttributes(0xFFFF, &value) == S_OK && value == identity;
}

__declspec(noinline) bool TouchProbe(IArrayProbe* item, ULONG identity)
{
    return item->Transform(0xA5A50000) == (0xA5A50000 ^ identity);
}

__declspec(noinline) bool TouchStream(ISequentialStream* stream, BYTE identity)
{
    std::array<BYTE, 256> input{}, output{};
    input.fill(identity);
    ULONG count = 0;
    return stream->Write(input.data(), static_cast<ULONG>(input.size()), &count) == S_OK &&
        count == input.size() && stream->Read(output.data(), static_cast<ULONG>(output.size()), &count) == S_OK &&
        count == output.size() && input == output;
}

class AllocatedDevice final : public IMDSPDevice
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        ++queries;
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IUnknown) || iid == __uuidof(IMDSPDevice) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { ++added; return 2; }
    ULONG STDMETHODCALLTYPE Release() override { ++released; return 1; }
    HRESULT STDMETHODCALLTYPE GetName(LPWSTR, UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetManufacturer(LPWSTR, UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetVersion(DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetType(DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetSerialNumber(PWMDMID, BYTE[8]) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPowerSource(DWORD*, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetStatus(DWORD* value) override
    {
        if (!value) return E_POINTER;
        *value = 0x31415926;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDeviceIcon(ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EnumStorage(IMDSPEnumStorage**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetFormatSupport(_WAVEFORMATEX**, UINT*, LPWSTR**, UINT*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE SendOpaqueCommand(OPAQUECOMMAND*) override { return E_NOTIMPL; }
    ULONG queries = 0, added = 0, released = 0;
};

class AdjacentVirtual
{
public:
    virtual ULONG Slot0() { return marker + 0; }
    virtual ULONG Slot1() { return marker + 1; }
    virtual ULONG Slot2() { return marker + 2; }
    virtual ULONG Slot3() { return marker + 3; }
    virtual ULONG Slot4() { return marker + 4; }
    virtual ULONG Slot5() { return marker + 5; }
    virtual ULONG Slot6() { return marker + 6; }
    virtual ULONG Slot7() { return marker + 7; }
    virtual ULONG Slot8() { return marker + 8; }

    // Slot nine uses the C++ receiver register on x86, unlike IMDSPDevice::GetStatus.
    virtual ULONG Transform(ULONG first, ULONG second) { return marker ^ first ^ second; }
    virtual ULONG Slot10() { return marker + 10; }
    virtual ULONG Slot11() { return marker + 11; }
    virtual ULONG Slot12() { return marker + 12; }
    virtual ULONG Slot13() { return marker + 13; }
    ULONG marker = 0x13579BDF;
};

class AllocatedDeviceProvider final : public FixedUnknown<IMDServiceProvider2, IClassFactory>
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = nullptr;
        if (iid == __uuidof(IClassFactory)) *value = static_cast<IClassFactory*>(this);
        else if (iid == __uuidof(IUnknown) || iid == __uuidof(IMDServiceProvider) ||
            iid == __uuidof(IMDServiceProvider2)) *value = static_cast<IMDServiceProvider2*>(this);
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** value) override
    {
        return outer ? CLASS_E_NOAGGREGATION : QueryInterface(iid, value);
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetDeviceCount(DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EnumDevices(IMDSPEnumDevice**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CreateDevice(LPCWSTR, DWORD* count, IMDSPDevice*** devices) override
    {
        if (!count || !devices) return E_POINTER;
        *count = 0;
        *devices = static_cast<IMDSPDevice**>(CoTaskMemAlloc(2 * sizeof(void*)));
        if (!*devices) return E_OUTOFMEMORY;

        // The readable allocation tail is not part of the returned interface array.
        (*devices)[0] = &device;
        (*devices)[1] = reinterpret_cast<IMDSPDevice*>(&adjacent);
        device.AddRef();
        *count = 1;
        return S_OK;
    }
    AllocatedDevice device;
    AdjacentVirtual adjacent;
};

__declspec(noinline) bool TouchAdjacent(AdjacentVirtual* instance)
{
    return instance->Transform(0x2468ACE0, 0x10203040) == (0x13579BDF ^ 0x2468ACE0 ^ 0x10203040);
}

int AllocatedComWorkload()
{
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return 18;
    AllocatedDeviceProvider factory;
    std::array<void*, 14> original;
    auto table = *reinterpret_cast<void***>(&factory.adjacent);
    std::copy_n(table, original.size(), original.begin());
    constexpr CLSID identity{0xA2D83E06, 0x3402, 0x4EA5, {0xAB, 0x1C, 0x37, 0xC3, 0x2F, 0x1D, 0x0B, 0x96}};
    DWORD registration = 0;
    auto result = CoRegisterClassObject(identity, static_cast<IClassFactory*>(&factory), CLSCTX_INPROC_SERVER,
        REGCLS_MULTIPLEUSE, &registration);
    IMDServiceProvider2* provider = nullptr;
    if (SUCCEEDED(result)) result = CoCreateInstance(identity, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&provider));
    DWORD count = 0;
    IMDSPDevice** devices = nullptr;
    if (SUCCEEDED(result)) result = provider->CreateDevice(L"Allocated device", &count, &devices);
    bool valid = SUCCEEDED(result) && count == 1 && devices && devices[0] == &factory.device;

    // Reject false table mutations before invoking an ordinary virtual method through its native ABI.
    valid &= std::equal(original.begin(), original.end(), table);
    if (valid)
    {
        DWORD status = 0;
        valid = devices[0]->GetStatus(&status) == S_OK && status == 0x31415926 && TouchAdjacent(&factory.adjacent);
    }
    if (devices)
    {
        devices[0]->Release();
        CoTaskMemFree(devices);
    }
    valid &= !factory.device.queries && factory.device.added == 1 && factory.device.released == 1;
    if (provider) provider->Release();
    if (registration) CoRevokeClassObject(registration);
    CoUninitialize();
    return valid ? 0 : 19;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc > 1 && !wcscmp(argv[1], L"--allocated")) return AllocatedComWorkload();

    // Capacity tails contain a real undisclosed object and an invalid pointer to expose overreads.
    ArrayItem<1> first;
    ArrayItem<2> second;
    ArrayItem<3> third;
    ArrayItem<99> undisclosed;
    if (argc > 1 && (!wcscmp(argv[1], L"--single") || !wcscmp(argv[1], L"--single-empty")))
    {
        bool empty = !wcscmp(argv[1], L"--single-empty");
        ItemEnumerator source({&first, &second, &third}, empty ? 0 : 1, empty ? S_FALSE : S_OK);
        void* selected = nullptr;
        if (FAILED(Query(&source, __uuidof(IEnumShellItems), &selected))) return 15;
        IShellItem* item = &undisclosed;
        auto enumerator = static_cast<IEnumShellItems*>(selected);
        if (enumerator->Next(1, &item, nullptr) != (empty ? S_FALSE : S_OK)) return 16;
        return TouchItem(item, empty ? 99 : 1) ? 0 : 17;
    }
    if (argc > 1 && !wcscmp(argv[1], L"--input"))
    {
        ArrayPolicy<1> one;
        ArrayPolicy<2> two;
        ArrayPolicy<3> three;
        ArrayPolicy<99> extra;
        PolicyAuthority source;
        void* selected = nullptr;
        if (FAILED(Query(&source, __uuidof(IMFOutputTrustAuthority), &selected))) return 8;
        std::array<IMFOutputPolicy*, 4> policies{&one, &two, &three, &extra};
        auto authority = static_cast<IMFOutputTrustAuthority*>(selected);
        if (authority->SetPolicy(policies.data(), 3, nullptr, nullptr) != S_OK) return 9;
        GUID control{};
        IMFOutputPolicy* hidden = &extra;
        return hidden->GetOriginatorID(&control) == S_OK && control.Data1 == 99 ? 0 : 10;
    }
    bool customFull = argc > 1 && !wcscmp(argv[1], L"--custom-full");
    if (customFull || argc > 1 && !wcscmp(argv[1], L"--custom"))
    {
        ArrayProbe<1> one;
        ArrayProbe<2> two;
        ArrayProbe<3> three;
        ArrayProbe<99> extra;
        ObjectEnumerator source({&one, &two, &three}, __uuidof(IArrayProbe));
        void* selected = nullptr;
        if (FAILED(Query(&source, __uuidof(IEnumObjects), &selected))) return 11;
        std::array<void*, 6> items{nullptr, nullptr, nullptr, &extra, reinterpret_cast<void*>(1), nullptr};
        ULONG count = 0;
        auto enumerator = static_cast<IEnumObjects*>(selected);
        if (customFull)
        {
            if (enumerator->Next(3, __uuidof(IArrayProbe), items.data(), nullptr) != S_OK) return 12;
            count = 3;
        }
        else if (enumerator->Next(6, __uuidof(IArrayProbe), items.data(), &count) != S_FALSE || count != 3) return 12;
        for (ULONG index = 0; index < count; ++index)
            if (!TouchProbe(static_cast<IArrayProbe*>(items[index]), index + 1)) return 13;
        return TouchProbe(&extra, 99) ? 0 : 14;
    }
    bool queried = argc > 1 && !wcscmp(argv[1], L"--iid");
    bool full = argc > 1 && !wcscmp(argv[1], L"--iid-full");
    bool unknownCount = argc > 1 && !wcscmp(argv[1], L"--iid-unknown-count");
    if (queried || full || unknownCount)
    {
        ArrayStream<1> one;
        ArrayStream<2> two;
        ArrayStream<3> three;
        ArrayStream<99> extra;
        ObjectEnumerator source({&one, &two, &three}, __uuidof(ISequentialStream));
        void* selected = nullptr;
        if (FAILED(Query(&source, __uuidof(IEnumObjects), &selected))) return 1;
        std::array<void*, 6> items{nullptr, nullptr, nullptr, &extra, reinterpret_cast<void*>(1), nullptr};
        ULONG count = 0;
        auto enumerator = static_cast<IEnumObjects*>(selected);
        if (full || unknownCount)
        {
            if (enumerator->Next(full ? 3 : 6, __uuidof(ISequentialStream), items.data(), nullptr) !=
                (full ? S_OK : S_FALSE)) return 2;
            count = 3;
        }
        else if (enumerator->Next(6, __uuidof(ISequentialStream), items.data(), &count) != S_FALSE || count != 3)
            return 2;
        for (ULONG index = 0; index < count; ++index)
            if (!TouchStream(static_cast<ISequentialStream*>(items[index]), static_cast<BYTE>(index + 1))) return 3;
        return TouchStream(&extra, 99) ? 0 : 4;
    }
    bool failed = argc > 1 && !wcscmp(argv[1], L"--fail");
    bool empty = argc > 1 && !wcscmp(argv[1], L"--zero");
    auto expected = failed ? E_FAIL : S_FALSE;
    ItemEnumerator source({&first, &second, &third}, empty ? 0 : 3, expected);
    void* selected = nullptr;
    if (FAILED(Query(&source, __uuidof(IEnumShellItems), &selected))) return 5;
    std::array<IShellItem*, 6> items{&first, &second, &third, &undisclosed,
        reinterpret_cast<IShellItem*>(1), nullptr};
    ULONG count = 0;
    auto enumerator = static_cast<IEnumShellItems*>(selected);
    if (enumerator->Next(6, items.data(), &count) != expected || count != (empty ? 0u : 3u)) return 6;
    return TouchItem(&first, 1) && TouchItem(&second, 2) && TouchItem(&third, 3) &&
        TouchItem(&undisclosed, 99) ? 0 : 7;
}

void ComArrayBreakpoints(const Context& context)
{
    // Stop on the producer's return and the returned interface's first entry.
    Collector collector(context.collector, context.directory);
    auto hello = collector.Call("hello");
    auto database = context.directory / L"breakpoints.sqlite";
    collector.Call("launch", {{"database", Text(database)},
                              {"executable", Text(context.target)},
                              {"arguments", TargetArguments(context)},
                              {"apiMask", hello["comMask"]},
                              {"entryMask", hello["comMask"]},
                              {"bufferLimit", 16},
                              {"followChildren", false},
                              {"instructionEngine", true}});
    auto stopped = [&]
    {
        return collector.Wait([](const Json& state)
        { return state["breakpoint"] == true || state["finished"] == true; });
    };
    auto state = stopped();
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        Require(state["breakpoint"] == true, "Enumerator entry breakpoint missing", state);
        if (state["stoppedCall"]["name"] == "IEnumShellItems::Next") break;
        collector.Call("continue");
        state = stopped();
    }
    auto next = state["stoppedCall"];
    Require(next["name"] == "IEnumShellItems::Next" && state["leaving"] == false, "Enumerator entry differs", state);
    collector.Call("breaks", {{"entryMask", 0}, {"exitMask", 0}});
    collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", next["api"]}});
    collector.Call("continue");
    state = stopped();
    if (state["breakpoint"] == true && state["leaving"] == false)
        state = collector.Wait([&](const Json& value)
        {
            return value["finished"] == true || (value["breakpoint"] == true && value["leaving"] == true &&
                                                 value["stoppedCall"]["id"] == next["id"]);
        });
    Require(state["breakpoint"] == true && state["leaving"] == true && state["stoppedCall"]["id"] == next["id"],
            "Enumerator return breakpoint differs", state);
    collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
    collector.Call("breaks", {{"entryMask", hello["comMask"]}, {"exitMask", 0}});
    collector.Call("continue");
    state = stopped();
    if (state["breakpoint"] == true && state["leaving"] == true)
        state = collector.Wait([](const Json& value)
        {
            return value["finished"] == true || (value["breakpoint"] == true && value["leaving"] == false &&
                                                 value["stoppedCall"]["name"] == "IShellItem::GetAttributes");
        });
    Require(state["breakpoint"] == true && state["leaving"] == false &&
                state["stoppedCall"]["name"] == "IShellItem::GetAttributes" &&
                state["stoppedCall"]["arguments"].size() == 3,
            "First returned interface breakpoint differs", state);
    collector.Call("breaks", {{"entryMask", 0}, {"exitMask", 0}});
    collector.Call("continue");
    collector.Wait([](const Json& value) { return value["finished"] == true; }, 45);
    for (const auto& target : collector.Call("page", {{"database", Text(database)}, {"limit", 1}})["targets"])
        Require(target["state"] == "Exited", "COM array breakpoint target is still running", target);
    collector.Close();
}

void ComArray(const Context& context)
{
    if (context.Has(L"--allocated-only"))
    {
        RunTarget(context, L"--allocated");
        Capture::Run(context, {.arguments = L"--allocated", .instructions = false, .comOnly = true},
            [](Capture& capture)
        {
            capture.CheckDiagnostics();
            auto created = Named(capture.Calls(), "IMDServiceProvider2::CreateDevice");
            auto devices = Named(capture.Calls(), "IMDSPDevice::GetStatus");
            Require(created.size() == 1 && devices.size() == 1, "Allocated COM interface discovery differs");
            auto receiver = Prefix(Data(devices[0]["arguments"]), sizeof(void*));
            Require(Regions(created[0]["output"], {.parameter = 3, .kind = 0}) ==
                        std::vector<Value>{{3, 0, 0, sizeof(void*), receiver}},
                    "Allocated COM array included its capacity tail", created[0]);
            Require(Snapshots(created[0]["output"], 2, 2) == std::vector<Bytes>{Integer(1, 4)} &&
                        Snapshots(devices[0]["output"], 1, 2) == std::vector<Bytes>{Integer(0x31415926, 4)},
                    "Allocated COM device output differs");
        }, 45);
        return;
    }
    Json results = Json::array();
    bool baseline = context.Has(L"--baseline");
    for (std::string mode : {"iid-full", "custom-full", "iid-unknown-count", "single", "single-empty", "partial", "iid",
                             "zero", "fail", "input", "custom"})
    {
        auto arguments = mode == "partial" ? L"" : L"--" + Detourist::Wide(mode);
        RunTarget(context, arguments);
        for (uint32_t limit : baseline ? std::vector{16u} : std::vector{16u, 64u})
        {
            Capture::Run(context, {.arguments = arguments, .limit = limit, .comOnly = true}, [&](Capture& capture)
            {
                const auto& rows = capture.Calls();
                std::array names{"ISequentialStream::Read", "ISequentialStream::Write", "IShellItem::GetAttributes",
                                 "IMFOutputPolicy::GetOriginatorID"};
                std::array<Json, 4> observed;
                Json counts = Json::object();
                for (size_t index = 0; index < names.size(); ++index)
                {
                    observed[index] = Named(rows, names[index]);
                    counts[names[index]] = observed[index].size();
                }
                results.push_back({{"mode", mode}, {"limit", limit}, {"methods", counts}});
                if (baseline) return;
                capture.CheckDiagnostics();
                Require(Query(capture.database, "SELECT id FROM calls WHERE ended IS NULL").empty(),
                        "COM array calls are incomplete");
                auto first = [&](const char* name)
                {
                    auto calls = Named(rows, name);
                    Require(calls.size() == 1, "COM array producer count differs", calls);
                    return calls[0];
                };
                auto pointers = [](const Json& calls)
                {
                    Bytes result;
                    for (const auto& row : calls)
                    {
                        auto receiver = Prefix(Data(row["arguments"]), 8);
                        result.insert(result.end(), receiver.begin(), receiver.end());
                    }
                    return result;
                };
                auto exact = [&](const Json& payload, uint32_t parameter, uint32_t kind, uint32_t flags,
                                 uint64_t original, const Bytes& data)
                {
                    Require(Regions(payload, {.parameter = parameter, .kind = kind}) ==
                                std::vector<Value>{{parameter, kind, flags, original, data}},
                            "COM array snapshot differs");
                };
                if (mode == "single" || mode == "single-empty")
                {
                    Require(observed[2].size() == (mode == "single" ? 1 : 0), "Single COM item discovery differs",
                            counts);
                    auto next = first("IEnumShellItems::Next");
                    auto bytes = pointers(observed[2]);
                    exact(next["output"], 2, 0, 0, bytes.size(), bytes);
                    Require(Regions(next["output"], {.parameter = 3, .kind = 2}).empty(),
                            "Null enumerator completion count was captured", next);
                    return;
                }
                if (mode == "iid-unknown-count")
                {
                    for (const auto& calls : observed)
                        Require(calls.empty(), "Unknown completion count discovered items");
                    Require(Regions(first("IEnumObjects::Next")["output"], {.parameter = 3, .kind = 0}).empty(),
                            "Unknown completion count captured capacity tails");
                    return;
                }
                Json expected = Json::object();
                if (mode == "iid" || mode == "iid-full")
                    expected = {{names[0], 3}, {names[1], 3}};
                else if (mode == "partial")
                    expected = {{names[2], 3}};
                else if (mode == "input")
                    expected = {{names[3], 3}};
                for (size_t index = 0; index < names.size(); ++index)
                    Require(observed[index].size() == expected.value(names[index], 0u), "COM item discovery differs",
                            counts);
                if (mode == "custom" || mode == "custom-full")
                {
                    auto raw = Named(rows, "{2f5e21e4-549a-4db3-af03-1c7780d12b9a}::slot 3");
                    Require(raw.size() == 3, "Custom COM interface count differs", raw);
                    std::set<uint64_t> results;
                    for (const auto& row : raw)
                    {
                        Require((row["flags"].get<uint32_t>() & 256) &&
                                    Read<uint64_t>(row["arguments"], 8) == 0xa5a50000,
                                "Custom COM call differs", row);
                        results.insert(Number(row["result"]));
                    }
                    Require(results == std::set<uint64_t>{0xa5a50001, 0xa5a50002, 0xa5a50003},
                            "Custom COM results differ");
                    exact(first("IEnumObjects::Next")["output"], 3, 0, limit < 24, 24, Prefix(pointers(raw), limit));
                    return;
                }
                for (const auto& row : rows)
                    Require(!(row["flags"].get<uint32_t>() & 256), "Typed COM array call is raw", row);
                if (mode == "input")
                {
                    auto call = first("IMFOutputTrustAuthority::SetPolicy");
                    Require(!(call["flags"].get<uint32_t>() & 1), "Input COM array producer failed", call);
                    exact(call["input"], 1, 0, limit < 24, 24, Prefix(pointers(observed[3]), limit));
                    for (size_t index = 0; index < observed[3].size(); ++index)
                    {
                        auto guid = Integer(index + 1, 4), suffix = Unhex("341278560102030405060708");
                        guid.insert(guid.end(), suffix.begin(), suffix.end());
                        exact(observed[3][index]["output"], 1, 0, 0, 16, guid);
                    }
                    return;
                }
                bool iid = mode == "iid" || mode == "iid-full";
                auto next = first(iid ? "IEnumObjects::Next" : "IEnumShellItems::Next");
                Require(bool(next["flags"].get<uint32_t>() & 1) == (mode == "fail") &&
                            Regions(next["input"], {.parameter = iid ? 3u : 2u, .kind = 0}).empty(),
                        "COM enumerator input or failure differs", next);
                if (mode == "partial" || iid)
                {
                    exact(next["output"], iid ? 3 : 2, 0, limit < 24, 24,
                          Prefix(pointers(observed[iid ? 0 : 2]), limit));
                    auto count = Snapshots(next["output"], iid ? 4 : 3, 2);
                    Require(count == (mode == "iid-full" ? std::vector<Bytes>{} : std::vector<Bytes>{Integer(3, 4)}),
                            "COM enumerator completed count differs", next);
                }
                if (mode == "zero")
                {
                    exact(next["output"], 2, 0, 0, 0, {});
                    exact(next["output"], 3, 2, 0, 4, Bytes(4));
                }
                if (mode == "fail")
                    Require(Regions(next["output"], {.parameter = 2, .kind = 0}).empty(),
                            "Failed COM enumeration captured items", next);
                if (mode == "partial")
                {
                    std::set<Bytes> attributes;
                    for (const auto& row : observed[2])
                    {
                        auto values = Snapshots(row["output"], 2, 2);
                        Require(!values.empty(), "Shell item attributes missing", row);
                        attributes.insert(values[0]);
                    }
                    Require(attributes == std::set<Bytes>{Integer(1, 4), Integer(2, 4), Integer(3, 4)},
                            "Shell item attributes differ");
                }
                if (iid)
                    for (size_t direction = 0; direction < 2; ++direction)
                        for (size_t index = 0; index < observed[direction].size(); ++index)
                        {
                            auto row = observed[direction][index];
                            if (!direction)
                                Require(row["parameters"].get<std::string>().contains("pv") &&
                                            row["parameters"].get<std::string>().contains("cb"),
                                        "Stream parameter names missing", row);
                            exact(row[direction ? "input" : "output"], 1, 0, 1, 256,
                                  Bytes(limit, static_cast<uint8_t>(index + 1)));
                        }
            }, 45);
        }
    }
    if (!baseline)
    {
        Capture::Run(context, {.limit = 16, .comOnly = true, .excludedApis = {"IEnumShellItems::Next"}},
                     [](Capture& capture)
        {
            Require(Named(capture.Calls(), "IEnumShellItems::Next").empty() &&
                        Named(capture.Calls(), "IShellItem::GetAttributes").size() == 3,
                    "Filtered enumerator failed to discover returned interfaces", capture.Calls());
        }, 45);
        ComArrayBreakpoints(context);
    }
    WriteJson(context.directory / L"results.json", results);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ComArray); }

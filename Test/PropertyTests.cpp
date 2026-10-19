#include "TestSupport.h"

#if defined(DETOURIST_TEST_DetouristPropertyStoreTests)

using namespace Detourist::Tests;
using Microsoft::WRL::ComPtr;

constexpr GUID PropertyIdentity{0x9dc27815, 0x4381, 0x4b81, {0x93, 0x24, 0x76, 0x11, 0x8c, 0x59, 0x3d, 0x72}};
constexpr wchar_t CountedText[] = L"counted property text";
PCWSTR PropertyStrings[]{L"first allocated property", L"second \u0394 property", L"", L"last property"};

struct PropertyValue
{
    PROPVARIANT value{};
    ~PropertyValue() { PropVariantClear(&value); }
};

bool PropertyData(PROPVARIANT& value, unsigned index)
{
    if (index == 1) return SUCCEEDED(InitPropVariantFromStringVector(PropertyStrings,
        static_cast<ULONG>(std::size(PropertyStrings)), &value));
    if (index == 3) return SUCCEEDED(InitPropVariantFromCLSID(PropertyIdentity, &value));
    if (index == 2)
    {
        value.vt = VT_BLOB;
        value.blob.cbSize = 96;
        value.blob.pBlobData = static_cast<BYTE*>(CoTaskMemAlloc(value.blob.cbSize));
        if (!value.blob.pBlobData) return false;
        for (ULONG byte = 0; byte < value.blob.cbSize; ++byte)
            value.blob.pBlobData[byte] = static_cast<BYTE>(byte ^ 0x53);
        return true;
    }
    value.vt = VT_VECTOR | VT_BSTR;
    value.cabstr.cElems = 3;
    value.cabstr.pElems = static_cast<BSTR*>(CoTaskMemAlloc(3 * sizeof(BSTR)));
    if (!value.cabstr.pElems) return false;
    memset(value.cabstr.pElems, 0, 3 * sizeof(BSTR));
    value.cabstr.pElems[0] = SysAllocStringLen(CountedText, static_cast<UINT>(std::size(CountedText) - 1));
    value.cabstr.pElems[1] = SysAllocString(L"");
    value.cabstr.pElems[2] = SysAllocString(L"final counted property");
    return value.cabstr.pElems[0] && value.cabstr.pElems[1] && value.cabstr.pElems[2];
}

bool VerifyProperty(const PROPVARIANT& value, unsigned index)
{
    if (index == 1)
    {
        if (value.vt != (VT_VECTOR | VT_LPWSTR) || value.calpwstr.cElems != std::size(PropertyStrings)) return false;
        for (ULONG item = 0; item < value.calpwstr.cElems; ++item)
            if (wcscmp(value.calpwstr.pElems[item], PropertyStrings[item])) return false;
        return true;
    }
    if (index == 3) return value.vt == VT_CLSID && value.puuid && *value.puuid == PropertyIdentity;
    if (index == 2)
    {
        if (value.vt != VT_BLOB || value.blob.cbSize != 96 || !value.blob.pBlobData) return false;
        for (ULONG byte = 0; byte < value.blob.cbSize; ++byte)
            if (value.blob.pBlobData[byte] != static_cast<BYTE>(byte ^ 0x53)) return false;
        return true;
    }
    return value.vt == (VT_VECTOR | VT_BSTR) && value.cabstr.cElems == 3 &&
        SysStringLen(value.cabstr.pElems[0]) == std::size(CountedText) - 1 &&
        !memcmp(value.cabstr.pElems[0], CountedText, sizeof(CountedText) - sizeof(wchar_t)) &&
        !SysStringLen(value.cabstr.pElems[1]) && !wcscmp(value.cabstr.pElems[2], L"final counted property");
}

bool PropertyStores(const wchar_t* mode)
{
    // Real stores own deep copies of text, counted strings, binary values and GUIDs.
    ComPtr<IPropertyStore> first, second, selected;
    if (FAILED(PSCreateMemoryPropertyStore(IID_PPV_ARGS(&first))) ||
        FAILED(PSCreateMemoryPropertyStore(IID_PPV_ARGS(&second)))) return false;
    auto multiplex = !wcscmp(mode, L"multiplex");
    for (unsigned index = 1; index <= 4; ++index)
    {
        PropertyValue value;
        PROPERTYKEY key{PropertyIdentity, index};
        auto store = multiplex && index > 2 ? second.Get() : first.Get();
        if (!PropertyData(value.value, index) || FAILED(store->SetValue(key, value.value))) return false;
    }
    if (FAILED(first->Commit()) || FAILED(second->Commit())) return false;
    if (multiplex)
    {
        IUnknown* sources[]{first.Get(), second.Get()};
        if (FAILED(PSCreateMultiplexPropertyStore(sources, 2, IID_PPV_ARGS(&selected)))) return false;
    }
    else if (!wcscmp(mode, L"serialized"))
    {
        ComPtr<IPersistSerializedPropStorage> source, destination;
        if (FAILED(first.As(&source)) || FAILED(second.As(&destination))) return false;
        SERIALIZEDPROPSTORAGE* raw = nullptr;
        DWORD bytes = 0;
        auto result = source->GetPropertyStorage(&raw, &bytes);
        std::unique_ptr<SERIALIZEDPROPSTORAGE, decltype(&CoTaskMemFree)> storage(raw, &CoTaskMemFree);
        if (FAILED(result) || !storage || !bytes || FAILED(destination->SetPropertyStorage(storage.get(), bytes)))
            return false;
        selected = second;
    }
    else selected = first;

    // Returned allocations remain valid after the input variants and serialized buffer have been freed.
    DWORD count = 0;
    if (FAILED(selected->GetCount(&count)) || count != 4) return false;
    for (DWORD position = 0; position < count; ++position)
    {
        PROPERTYKEY key{};
        PropertyValue value;
        if (FAILED(selected->GetAt(position, &key)) || key.fmtid != PropertyIdentity ||
            FAILED(selected->GetValue(key, &value.value)) || !VerifyProperty(value.value, key.pid)) return false;
    }
    PropertyValue missing;
    PROPERTYKEY unknown{PropertyIdentity, 99};
    return SUCCEEDED(selected->GetValue(unknown, &missing.value)) && missing.value.vt == VT_EMPTY;
}

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 2 || FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return 1;
    auto success = PropertyStores(arguments[1]);
    CoUninitialize();
    std::puts(success ? "PASS: property stores and allocated values." : "FAIL: property stores.");
    return success ? 0 : 2;
}

void PropertyStore(const Context& context)
{
    // Real memory, serialized and multiplex stores retain scalar allocations, blobs and string vectors.
    Json details = Json::array();
    for (auto mode : {"memory", "serialized", "multiplex"})
    {
        RunTarget(context, Detourist::Wide(mode), 30000);
        for (auto [limit, comOnly] : {std::pair{16u, false}, {64u, false}, {16u, true}})
        {
            Capture::Run(context,
                         {.arguments = Detourist::Wide(mode),
                          .limit = limit,
                          .instructions = context.Has(L"--instructions"),
                          .comOnly = comOnly},
                         [&](Capture& capture)
            {
                auto rows = TargetCalls(context, capture.database);
                auto getters = Named(rows, "IPropertyStore::GetValue"),
                     setters = Named(rows, "IPropertyStore::SetValue");
                Require(getters.size() == 5 && setters.size() == 4, "Property store call count differs", rows);
                for (auto phase : {"output", "input"})
                    for (const auto& row : std::string(phase) == "output" ? getters : setters)
                    {
                        Require(!(row["flags"].get<uint32_t>() & (1 | 4 | 256)), "Property store call failed", row);
                        auto values = Values(row[phase]);
                        auto headers = Regions(values, {.parameter = 2, .excluded = 8});
                        Require(!headers.empty(), "Property header missing", row);
                        auto tag = Read<uint16_t>(headers[0].data);
                        auto references = Regions(values, {.parameter = 2, .required = 8, .parameterMask = 255});
                        if (tag == 72)
                            Require(references.size() == 1 && references[0].original == 16 &&
                                        references[0].data == Unhex("1578c29d8143814b932476118c593d72"),
                                    "Property GUID differs", row);
                        else if (tag == 65)
                        {
                            Bytes bytes(limit);
                            for (size_t index = 0; index < bytes.size(); ++index)
                                bytes[index] = uint8_t(index ^ 0x53);
                            Require(limit < 24 ? references.empty()
                                               : references.size() == 1 && references[0].original == 96 &&
                                                     references[0].data == bytes && (references[0].flags & 1),
                                    "Property blob differs", row);
                        }
                        else if (tag == 0x101f || tag == 0x1008)
                        {
                            std::vector<std::string> strings =
                                tag == 0x101f
                                    ? std::vector<std::string>{"first allocated property", "second \u0394 property", "",
                                                               "last property"}
                                    : std::vector<std::string>{"counted property text", "", "final counted property"};
                            Require(references.size() == std::min(strings.size(), size_t(limit / 8)),
                                    "Property string vector extent differs", row);
                            for (size_t index = 0; index < references.size(); ++index)
                            {
                                const auto& value = references[index];
                                auto text = Encode(strings[index], true, tag == 0x101f);
                                auto original = tag == 0x101f && text.size() > limit ? 0 : text.size();
                                Require(value.kind == 1 && (value.flags & 32) && (value.flags >> 16) == index &&
                                            value.original == original && value.data == Prefix(text, limit),
                                        "Property string differs", row);
                            }
                        }
                        else
                            Require(tag == 0 && references.empty(), "Unexpected property tag", row);
                        CheckLimit(row, limit);
                        details.push_back({{"mode", mode}, {"limit", limit}, {"call", capture.Details(row)}});
                    }
                if (std::string(mode) == "serialized")
                    for (auto method : {"GetPropertyStorage", "SetPropertyStorage"})
                        Require(!Named(rows, "IPersistSerializedPropStorage::" + std::string(method)).empty(),
                                "Serialized property method missing");
                bool memory = false;
                for (const auto& row : rows)
                    if (row["name"].get<std::string>().starts_with("PSCreate"))
                    {
                        Require(!comOnly, "COM-only capture included a property export", row);
                        memory |= row["name"] == "PSCreateMemoryPropertyStore";
                    }
                Require(comOnly || memory, "Property factory missing");
                capture.CheckDiagnostics(true);
            }, 60);
        }
    }
    Inspect(context, context.Option(L"--inspector"), "--property-stores", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, PropertyStore); }

#elif defined(DETOURIST_TEST_DetouristPropertyGraphTests)

using namespace Detourist::Tests;
class GraphStore final : public CountedUnknown<IPropertyStore>
{
public:
    PROPVARIANT value{};
    ULONG queries = 0, reads = 0;
    bool fail = false;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        ++queries;
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == __uuidof(IPropertyStore) ? this : nullptr;
        if (*output) AddRef();
        return *output ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE GetCount(DWORD* count) override { *count = 1; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetAt(DWORD, PROPERTYKEY*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY key, PROPVARIANT* output) override
    {
        ++reads;
        if (!output || key != PKEY_Title) return E_INVALIDARG;
        *output = value;
        return fail ? E_FAIL : S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetValue(REFPROPERTYKEY, REFPROPVARIANT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Commit() override { return S_OK; }
};

int TargetMain(int argc, wchar_t** argv)
{
    auto mode = argc > 1 ? argv[1] : L"graph";
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 1;
    GraphStore store;
    std::array<PROPVARIANT, 4> root{};
    std::array<PROPVARIANT, 6> nested{};
    std::array<BYTE, 96> blob{};
    for (size_t index = 0; index < blob.size(); ++index) blob[index] = static_cast<BYTE>(index ^ 0x53);
    GUID identifier{0x9DC27815, 0x4381, 0x4B81, {0x93, 0x24, 0x76, 0x11, 0x8C, 0x59, 0x3D, 0x72}};
    CLIPDATA clipboard{static_cast<ULONG>(blob.size() + sizeof(LONG)), CF_TEXT, blob.data()};
    std::array<CLIPDATA, 3> clipboardVector{clipboard, CLIPDATA{100, CF_TEXT, reinterpret_cast<BYTE*>(1)},
        CLIPDATA{sizeof(LONG), CF_TEXT, nullptr}};
    LONG integer = -78921;
    DOUBLE floating = -2.5;
    VARIANT_BOOL boolean = VARIANT_TRUE;
    DECIMAL decimal{};
    decimal.scale = 2;
    decimal.Lo32 = 1234;
    std::array<PROPVARIANT, 7> references{};
    std::array<LPWSTR, 3> strings{nullptr, const_cast<LPWSTR>(L"last sibling"), const_cast<LPWSTR>(L"\u0394 text")};
    constexpr wchar_t text[] = L"counted\0graph text";
    std::unique_ptr<wchar_t, decltype(&SysFreeString)> counted(
        SysAllocStringLen(text, static_cast<UINT>(std::size(text) - 1)), SysFreeString);
    std::unique_ptr<SAFEARRAY, decltype(&SafeArrayDestroy)> automation(
        SafeArrayCreateVector(VT_VARIANT, 0, 3), SafeArrayDestroy);
    if (!counted || !automation) return 2;

    // SDK allocations contain nested Automation arrays; property vectors borrow stable fixture-owned storage.
    VARIANT indirect{};
    indirect.vt = VT_BSTR;
    indirect.bstrVal = counted.get();
    auto variants = static_cast<VARIANT*>(automation->pvData);
    variants[0].vt = VT_BSTR;
    variants[0].bstrVal = SysAllocStringLen(text, static_cast<UINT>(std::size(text) - 1));
    variants[1].vt = VT_ARRAY | VT_I4;
    variants[1].parray = SafeArrayCreateVector(VT_I4, 0, 6);
    if (!variants[0].bstrVal || !variants[1].parray) return 2;
    constexpr LONG integers[]{-7, 0, 42, LONG_MIN, LONG_MAX, 123456};
    memcpy(variants[1].parray->pvData, integers, sizeof(integers));
    variants[2].vt = VT_VARIANT | VT_BYREF;
    variants[2].pvarVal = &indirect;
    root[0].vt = VT_LPWSTR;
    root[0].pwszVal = const_cast<LPWSTR>(L"outer property text");
    root[1].vt = VT_ARRAY | VT_VARIANT;
    root[1].parray = automation.get();
    root[2].vt = VT_VECTOR | VT_VARIANT;
    root[2].capropvar = {static_cast<ULONG>(nested.size()), nested.data()};
    root[3].vt = VT_VECTOR | VT_LPWSTR;
    root[3].calpwstr = {static_cast<ULONG>(strings.size()), strings.data()};
    nested[0].vt = VT_BLOB;
    nested[0].blob = {static_cast<ULONG>(blob.size()), blob.data()};
    nested[1].vt = VT_CLSID;
    nested[1].puuid = &identifier;
    nested[2].vt = VT_LPSTR;
    nested[2].pszVal = reinterpret_cast<LPSTR>(1);
    nested[3].vt = VT_VARIANT | VT_BYREF;
    nested[3].pvarVal = reinterpret_cast<PROPVARIANT*>(&indirect);
    nested[4].vt = VT_CF;
    nested[4].pclipdata = &clipboard;
    nested[5].vt = VT_VARIANT | VT_BYREF;
    nested[5].pvarVal = &root[2];
    store.value.vt = VT_VECTOR | VT_VARIANT;
    store.value.capropvar = {static_cast<ULONG>(root.size()), root.data()};
    store.fail = !wcscmp(mode, L"failed-graph");
    if (!wcscmp(mode, L"cycle-graph"))
    {
        store.value.vt = VT_VARIANT | VT_BYREF;
        store.value.pvarVal = &store.value;
    }
    if (!wcscmp(mode, L"referenced-scalars"))
    {
        references[0].vt = VT_I4 | VT_BYREF;
        references[0].plVal = &integer;
        references[1].vt = VT_R8 | VT_BYREF;
        references[1].pdblVal = &floating;
        references[2].vt = VT_BOOL | VT_BYREF;
        references[2].pboolVal = &boolean;
        references[3].vt = VT_DECIMAL | VT_BYREF;
        references[3].pdecVal = &decimal;
        references[4].vt = VT_I4 | VT_BYREF;
        references[4].plVal = reinterpret_cast<LONG*>(1);
        references[5].vt = VT_I4 | VT_BYREF;
        references[5].plVal = nullptr;
        references[6] = references[0];
        store.value.vt = VT_VECTOR | VT_VARIANT;
        store.value.capropvar = {static_cast<ULONG>(references.size()), references.data()};
    }
    if (wcsstr(mode, L"clipboard") == mode)
    {
        store.value.vt = VT_CF;
        store.value.pclipdata = &clipboard;
        if (!wcscmp(mode, L"clipboard-empty")) { clipboard.cbSize = sizeof(LONG); clipboard.pClipData = nullptr; }
        if (!wcscmp(mode, L"clipboard-null")) store.value.pclipdata = nullptr;
        if (!wcscmp(mode, L"clipboard-invalid")) clipboard.pClipData = reinterpret_cast<BYTE*>(1);
        if (!wcscmp(mode, L"clipboard-header")) store.value.pclipdata = reinterpret_cast<CLIPDATA*>(1);
        if (!wcscmp(mode, L"clipboard-size")) clipboard.cbSize = 2;
        if (!wcscmp(mode, L"clipboard-vector"))
        {
            store.value.vt = VT_VECTOR | VT_CF;
            store.value.caclipdata = {static_cast<ULONG>(clipboardVector.size()), clipboardVector.data()};
        }
    }

    // Property helpers exercise an allocated output and its later typed input boundary.
    PROPVARIANT initialized{};
    std::unique_ptr<PROPVARIANT, decltype(&PropVariantClear)> cleanup(&initialized, PropVariantClear);
    if (!wcscmp(mode, L"property-helpers"))
    {
        LONG element = 0;
        if (FAILED(InitPropVariantFromInt32Vector(integers, static_cast<ULONG>(std::size(integers)), &initialized)) ||
            FAILED(PropVariantGetInt32Elem(initialized, 2, &element)) || element != 42) return 3;
        store.value = initialized;
    }

    // The real propsys input boundary discovers the private store without RTTI or probing interface queries.
    IPropertyDescription* description = nullptr;
    auto result = PSGetPropertyDescription(PKEY_Title, IID_PPV_ARGS(&description));
    if (FAILED(result)) return 3;
    PROPVARIANT returned{};
    result = PSGetPropertyValue(&store, description, &returned);
    auto valid = result == (store.fail ? E_FAIL : S_OK) && store.reads == 1 &&
        store.queries == 0 && store.references == 1;
    description->Release();
    CoUninitialize();
    printf("mode=%ls result=0x%08lX reads=%lu queries=%lu references=%lu\n",
        mode, static_cast<ULONG>(result), store.reads, store.queries, store.references);
    return valid ? 0 : 4;
}

Bytes GraphIntegers() { return Unhex("f9ffffff000000002a00000000000080ffffff7f40e20100"); }

void CheckGraph(const Json& snapshots, uint32_t limit)
{
    // Descriptor parent links and reference identities preserve the mixed property graph's topology.
    std::map<unsigned, Json> descriptors, data;
    std::map<std::tuple<unsigned, unsigned, unsigned>, Json> references;
    for (const auto& value : snapshots)
    {
        auto kind = value["kind"].get<unsigned>();
        if (kind == 8 || kind == 10) descriptors[value["arrayIndex"]] = value;
        if (kind == 9 || kind == 11) data[value["arrayIndex"]] = value;
        if (value["flags"].get<uint32_t>() & 32) references[{value["arrayIndex"], value["elementIndex"], kind}] = value;
    }
    std::map<unsigned, std::tuple<unsigned, Json, Json>> expected{{0, {10, nullptr, nullptr}}};
    if (limit >= 40)
    {
        expected[1] = {8, 0, 1};
        expected[2] = {8, 1, 1};
    }
    if (limit >= 96)
    {
        expected[3] = {10, 0, 2};
        expected[4] = {10, 0, 3};
    }
    Require(descriptors.size() == expected.size(), "Property graph descriptor set differs");
    for (const auto& [index, item] : expected)
    {
        auto [kind, parent, element] = item;
        auto descriptor = descriptors.at(index), region = data.at(index);
        Require(descriptor["kind"] == kind && descriptor.value("parentArrayIndex", Json(nullptr)) == parent &&
                    descriptor.value("parentElementIndex", Json(nullptr)) == element &&
                    region.value("parentArrayIndex", Json(nullptr)) == parent &&
                    region.value("parentElementIndex", Json(nullptr)) == element,
                "Property graph parent differs", descriptor);
        if (index == 2)
            Require(Unhex(region["bytes"]) == Prefix(GraphIntegers(), limit), "Nested integer array differs");
    }
    using Key = std::tuple<unsigned, unsigned, unsigned>;
    std::map<Key, std::pair<unsigned, std::optional<Bytes>>> wanted{
        {{0, 0, 1}, {31, Encode("outer property text", true, true)}}};
    auto counted = Encode(std::string("counted\0graph text", 18), true);
    if (limit >= 40) wanted[{1, 0, 1}] = {8, counted};
    if (limit >= 64) wanted[{1, 2, 1}] = {8, counted};
    Bytes bytes(96);
    for (size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = uint8_t(index ^ 0x53);
    if (limit >= 96)
    {
        wanted[{3, 0, 0}] = {65, bytes};
        wanted[{3, 1, 0}] = {72, Unhex("1578c29d8143814b932476118c593d72")};
        wanted[{3, 2, 0}] = {30, Bytes{}};
        wanted[{3, 3, 1}] = {8, counted};
        wanted[{3, 4, 14}] = {71, std::nullopt};
        wanted[{3, 4, 0}] = {71, bytes};
        wanted[{4, 0, 1}] = {31, Bytes{}};
        wanted[{4, 1, 1}] = {31, Encode("last sibling", true, true)};
        wanted[{4, 2, 1}] = {31, Encode("\u0394 text", true, true)};
    }
    Require(references.size() == wanted.size(), "Property graph reference set differs");
    for (const auto& [key, item] : wanted)
    {
        auto [tag, bytesWanted] = item;
        auto value = references.at(key);
        auto flags = value["flags"].get<uint32_t>();
        bool unreadable = key == Key{3, 2, 0};
        Require((value["variantType"].get<uint32_t>() & 0xfff) == tag &&
                    (!bytesWanted || Unhex(value["bytes"]) == Prefix(*bytesWanted, limit)) &&
                    bool(flags & 2) == unreadable &&
                    (unreadable || bool(flags & 1) == bool(bytesWanted && bytesWanted->size() > limit)),
                "Property graph reference differs", value);
    }
}

void PropertyGraph(const Context& context)
{
    std::vector<std::pair<std::string, uint32_t>> cases;
    for (auto limit : {16u, 40u, 64u, 128u, 256u})
        cases.emplace_back("graph", limit);
    for (auto mode : {"cycle-graph", "failed-graph", "clipboard", "clipboard-empty", "clipboard-null",
                      "clipboard-invalid", "clipboard-header", "clipboard-size"})
        cases.emplace_back(mode, 64);
    cases.emplace_back("clipboard", 16);
    for (auto limit : {16u, 64u, 128u, 256u})
        cases.emplace_back("referenced-scalars", limit);
    for (auto limit : {16u, 20u, 64u})
        cases.emplace_back("clipboard-vector", limit);
    for (auto limit : {16u, 64u})
        cases.emplace_back("property-helpers", limit);
    Json details = Json::array();
    for (const auto& [mode, limit] : cases)
    {
        RunTarget(context, Detourist::Wide(mode));
        Capture::Run(context,
                     {.arguments = Detourist::Wide(mode),
                      .limit = limit,
                      .instructions = context.Has(L"--instructions"),
                      .comOnly = mode != "property-helpers"},
                     [&](Capture& capture)
        {
            auto rows = capture.Calls();
            auto getters = Named(rows, "IPropertyStore::GetValue");
            Require(getters.size() == 1 && !(getters[0]["flags"].get<uint32_t>() & (4 | 256)) &&
                        bool(getters[0]["flags"].get<uint32_t>() & 1) == (mode == "failed-graph"),
                    "Property graph getter differs", getters);
            if (mode == "property-helpers")
                for (auto [name, phase, parameter] : {std::tuple{"InitPropVariantFromInt32Vector", "output", 2u},
                                                      {"PropVariantGetInt32Elem", "input", 0u}})
                {
                    auto helpers = Named(rows, name);
                    Require(!helpers.empty(), "Property helper missing");
                    auto vectors =
                        Regions(Values(helpers[0][phase]), {.parameter = parameter, .kind = 11, .parameterMask = 255});
                    Require(!(helpers[0]["flags"].get<uint32_t>() & (1 | 4 | 256)) && vectors.size() == 1 &&
                                (vectors[0].flags >> 16) == 3 && vectors[0].data == Prefix(GraphIntegers(), limit),
                            "Property helper vector differs", helpers[0]);
                }
            for (const auto& row : rows)
                CheckLimit(row, limit);
            capture.CheckDiagnostics(true);
            auto detail = capture.Details(getters[0]);
            Json snapshots = Json::array();
            for (const auto& value : detail["output"])
            {
                Require(value["kind"] != 13, "Property graph contains an unsupported region", value);
                if (value["parameter"] == 2) snapshots.push_back(value);
            }
            if (mode == "graph")
                CheckGraph(snapshots, limit);
            else if (mode == "property-helpers")
            {
                size_t count = 0;
                for (const auto& value : snapshots)
                    if (value["kind"] == 11)
                    {
                        ++count;
                        Require((value["flags"].get<uint32_t>() >> 16) == 3, "Helper vector identity differs", value);
                    }
                Require(count == 1, "Helper vector missing");
            }
            else if (mode == "failed-graph")
                Require(snapshots.empty(), "Failed graph has output");
            else if (mode == "cycle-graph")
                Require(snapshots.size() == 1 && snapshots[0]["kind"] == 0, "Cyclic property graph was followed");
            else
            {
                Json references = Json::array(), descriptors = Json::array();
                bool vector = mode == "referenced-scalars" || mode == "clipboard-vector";
                for (const auto& value : snapshots)
                {
                    if (value["kind"] == 10) descriptors.push_back(value);
                    if (value["flags"].get<uint32_t>() & (vector ? 32 : 8)) references.push_back(value);
                }
                if (vector)
                    Require(descriptors.size() == 1 && descriptors[0]["arrayIndex"] == 0, "Vector descriptor differs");
                if (mode == "referenced-scalars")
                {
                    std::vector<Bytes> wanted{Integer(uint32_t(-78921), 4),
                                              Integer(std::bit_cast<uint64_t>(-2.5)),
                                              Integer(0xffff, 2),
                                              Unhex("0000020000000000d204000000000000"),
                                              {},
                                              {},
                                              Integer(uint32_t(-78921), 4)};
                    std::vector<unsigned> tags{3, 5, 11, 14, 3, 3, 3};
                    Require(references.size() == std::min(7u, (limit + 8) / 24), "Referenced scalar count differs");
                    for (size_t index = 0; index < references.size(); ++index)
                    {
                        const auto& value = references[index];
                        Require(value["arrayIndex"] == 0 && value["elementIndex"] == index &&
                                    value["variantType"] == (tags[index] | 0x4000) &&
                                    value["kind"] == (index == 3 ? 0 : 2) && Unhex(value["bytes"]) == wanted[index] &&
                                    bool(value["flags"].get<uint32_t>() & 2) == (index == 4 || index == 5),
                                "Referenced scalar differs", value);
                    }
                }
                else if (mode == "clipboard-vector")
                {
                    auto count = std::min(3u, limit / 16);
                    Require(references.size() == count * 2, "Clipboard vector reference count differs");
                    for (size_t index = 0; index < count; ++index)
                    {
                        auto header = references[index * 2], data = references[index * 2 + 1];
                        Bytes bytes(index == 0 ? limit : 0);
                        for (size_t position = 0; position < bytes.size(); ++position)
                            bytes[position] = uint8_t(position ^ 0x53);
                        Require(header["arrayIndex"] == 0 && data["arrayIndex"] == 0 &&
                                    header["elementIndex"] == index && data["elementIndex"] == index &&
                                    header["kind"] == 14 && Unhex(header["bytes"]).size() == 16 && data["kind"] == 0 &&
                                    data["variantType"] == 71 && Unhex(data["bytes"]) == bytes &&
                                    bool(data["flags"].get<uint32_t>() & 2) == (index == 1),
                                "Clipboard vector data differs", data);
                    }
                }
                else
                {
                    auto count = mode == "clipboard-null" ? 0u : mode == "clipboard-header" ? 1u : 2u;
                    Require(references.size() == count, "Clipboard reference count differs");
                    if (count)
                        Require(references[0]["kind"] == 14 && references[0]["originalBytes"] == 16 &&
                                    bool(references[0]["flags"].get<uint32_t>() & 2) == (mode == "clipboard-header"),
                                "Clipboard header differs", references[0]);
                    if (count == 2)
                    {
                        auto data = references[1];
                        Bytes bytes(mode == "clipboard" ? std::min(limit, 96u) : 0);
                        for (size_t index = 0; index < bytes.size(); ++index)
                            bytes[index] = uint8_t(index ^ 0x53);
                        Require(data["kind"] == 0 &&
                                    bool(data["flags"].get<uint32_t>() & 2) ==
                                        (mode == "clipboard-invalid" || mode == "clipboard-size") &&
                                    data["originalBytes"] ==
                                        (mode == "clipboard-empty" || mode == "clipboard-size" ? 0 : 96) &&
                                    Unhex(data["bytes"]) == bytes,
                                "Clipboard data differs", data);
                    }
                }
            }
            details.push_back({{"mode", mode}, {"limit", limit}, {"call", detail}});
        }, 45);
    }
    Inspect(context, context.Option(L"--inspector"), "--property-graphs", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, PropertyGraph); }

#else
#error Select a native test target.
#endif

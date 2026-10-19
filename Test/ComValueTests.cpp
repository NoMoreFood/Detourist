#include "TestSupport.h"

#if defined(DETOURIST_TEST_DetouristAllocatedVariantTests)

using namespace Detourist::Tests;
template<UINT Identity> class AllocatedLeaf final : public CountedUnknown<IDispatch>
{
public:
    ULONG queries = 0, calls = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void** output) override
    {
        ++queries;
        if (output) *output = nullptr;
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override
    {
        ++calls;
        if (count) *count = Identity;
        return count ? S_OK : E_POINTER;
    }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR*, UINT, LCID, DISPID*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*) override
    {
        return E_NOTIMPL;
    }
};

class AllocatedCodec final : public FixedUnknown<ICodecAPI>
{
public:
    std::array<VARIANT, 5> values{};
    ULONG count = 5;
    bool fail = false, invalid = false;
    VARIANT* invalidValues = reinterpret_cast<VARIANT*>(0x12345678);
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == __uuidof(ICodecAPI) ? this : nullptr;
        return *output ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE IsSupported(const GUID*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE IsModifiable(const GUID*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetParameterRange(const GUID*, VARIANT*, VARIANT*, VARIANT*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetParameterValues(const GUID*, VARIANT** output, ULONG* completed) override
    {
        if (fail) return E_FAIL;
        if (!output || !completed) return E_POINTER;
        *completed = count;
        *output = nullptr;
        if (invalid) { *output = invalidValues; return S_OK; }
        if (!count) return S_OK;
        *output = static_cast<VARIANT*>(CoTaskMemAlloc(count * sizeof(VARIANT)));
        if (!*output) return E_OUTOFMEMORY;
        std::copy_n(values.data(), count, *output);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDefaultValue(const GUID*, VARIANT*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetValue(const GUID*, VARIANT*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetValue(const GUID*, VARIANT*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RegisterForEvent(const GUID*, LONG_PTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE UnregisterForEvent(const GUID*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetAllDefaults() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetValueWithNotify(const GUID*, VARIANT*, GUID**, ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetAllDefaultsWithNotify(GUID**, ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetAllSettings(IStream*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetAllSettings(IStream*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetAllSettingsWithNotify(IStream*, GUID**, ULONG*) override { return E_NOTIMPL; }
};

class AllocatedFilter final : public FixedUnknown<IFilter>
{
public:
    PROPVARIANT value{};
    bool fail = false;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == __uuidof(IFilter) ? this : nullptr;
        return *output ? S_OK : E_NOINTERFACE;
    }
    SCODE STDMETHODCALLTYPE Init(ULONG, ULONG, const FULLPROPSPEC*, ULONG*) override { return E_NOTIMPL; }
    SCODE STDMETHODCALLTYPE GetChunk(STAT_CHUNK*) override { return E_NOTIMPL; }
    SCODE STDMETHODCALLTYPE GetText(ULONG*, WCHAR*) override { return E_NOTIMPL; }
    SCODE STDMETHODCALLTYPE GetValue(PROPVARIANT** output) override
    {
        if (fail) return E_FAIL;
        if (!output) return E_POINTER;
        *output = static_cast<PROPVARIANT*>(CoTaskMemAlloc(sizeof(PROPVARIANT)));
        if (!*output) return E_OUTOFMEMORY;
        **output = value;
        return S_OK;
    }
    SCODE STDMETHODCALLTYPE BindRegion(FILTERREGION, REFIID, void**) override { return E_NOTIMPL; }
};

__declspec(noinline) HRESULT Query(IUnknown* instance, REFIID iid, void** output)
{
    return instance->QueryInterface(iid, output);
}

__declspec(noinline) bool Touch(IDispatch* instance, UINT expected)
{
    UINT actual = 0;
    return instance->GetTypeInfoCount(&actual) == S_OK && actual == expected;
}

int TargetMain(int argc, wchar_t** argv)
{
    AllocatedLeaf<31> first;
    AllocatedLeaf<32> last;
    AllocatedLeaf<99> control;
    AllocatedLeaf<33> sibling;
    AllocatedCodec source;
    auto mode = argc > 2 ? argv[2] : L"";
    bool probe = *mode != 0;
    bool prefix = !wcscmp(mode, L"prefix"), nested = !wcscmp(mode, L"nested");
    bool propertyProbe = !wcscmp(mode, L"property");
    bool deep = !wcscmp(mode, L"deep");

    // A readable prefix ends at inaccessible storage while its first element references unavailable memory.
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto storage = static_cast<BYTE*>(VirtualAlloc(nullptr, 2ull * system.dwPageSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!storage) return 4;
    DWORD oldProtection = 0;
    if (!VirtualProtect(storage + system.dwPageSize, system.dwPageSize, PAGE_NOACCESS, &oldProtection)) return 5;
    auto guarded = reinterpret_cast<VARIANT*>(storage + system.dwPageSize - 2 * sizeof(VARIANT));
    guarded[0].vt = VT_VARIANT | VT_BYREF;
    guarded[0].pvarVal = reinterpret_cast<VARIANT*>(0x12345678);
    guarded[1].vt = VT_DISPATCH;
    guarded[1].pdispVal = &sibling;
    SAFEARRAY descriptor{};
    descriptor.cDims = 1;
    descriptor.cbElements = sizeof(VARIANT);
    descriptor.pvData = guarded;
    descriptor.rgsabound[0] = {MAXDWORD, 0};
    VARIANT container{};
    container.vt = VT_ARRAY | VT_VARIANT;
    container.parray = &descriptor;

    // An array at the traversal depth limit must not walk its declared element count.
    std::array<VARIANT, 32> chain{};
    for (size_t index = 0; index + 1 < chain.size(); ++index)
    {
        chain[index].vt = VT_VARIANT | VT_BYREF;
        chain[index].pvarVal = &chain[index + 1];
    }
    chain.back() = container;
    auto text = SysAllocStringLen(L"allocated\0variant", 17);
    if (!text) return 1;
    source.values[0].vt = VT_DISPATCH;
    source.values[0].pdispVal = &first;
    source.values[1].vt = VT_BSTR;
    source.values[1].bstrVal = text;
    source.values[2].vt = VT_I4;
    source.values[2].lVal = -42;
    source.values[3].vt = VT_VARIANT | VT_BYREF;
    source.values[3].pvarVal = &source.values[1];
    source.values[4].vt = VT_DISPATCH;
    source.values[4].pdispVal = &last;
    ICodecAPI* codec = nullptr;
    bool passed = Query(&source, __uuidof(ICodecAPI), reinterpret_cast<void**>(&codec)) == S_OK;
    VARIANT* returned = nullptr;
    ULONG count = 0;
    GUID property{};

    // Returned interfaces outside the captured byte extent must be discovered before their first calls.
    passed = passed && codec->GetParameterValues(&property, &returned, &count) == S_OK && count == 5 && returned;
    if (passed) passed = Touch(returned[0].pdispVal, 31) && Touch(returned[4].pdispVal, 32);
    CoTaskMemFree(returned);
    source.count = 0;
    passed = passed && codec->GetParameterValues(&property, &returned, &count) == S_OK && !count && !returned;
    source.values[0].pdispVal = &control;
    returned = source.values.data();
    count = 5;
    source.fail = true;
    passed = passed && codec->GetParameterValues(&property, &returned, &count) == E_FAIL && Touch(&control, 99);
    source.fail = false;
    source.invalid = true;
    source.count = probe && !propertyProbe ? MAXDWORD : 5;
    if (prefix) source.invalidValues = guarded;
    if (nested) { source.invalidValues = &container; source.count = 1; }
    if (deep) { source.invalidValues = chain.data(); source.count = 1; }
    passed = passed && codec->GetParameterValues(&property, &returned, &count) == S_OK;
    if (prefix || nested) passed = passed && Touch(&sibling, 33);

    // Property variants retain their allocated structure and vector without adopting Automation layout rules.
    AllocatedFilter filterSource;
    std::array<ULONG, 6> numbers{11, 22, 33, 44, 55, 66};
    filterSource.value.vt = VT_VECTOR | VT_UI4;
    filterSource.value.caul = {static_cast<ULONG>(numbers.size()), numbers.data()};
    if (propertyProbe)
    {
        filterSource.value.vt = VT_VECTOR | VT_VARIANT;
        filterSource.value.capropvar = {MAXDWORD, reinterpret_cast<PROPVARIANT*>(guarded)};
    }
    IFilter* filter = nullptr;
    PROPVARIANT* propertyValue = nullptr;
    passed = passed && Query(&filterSource, __uuidof(IFilter), reinterpret_cast<void**>(&filter)) == S_OK &&
        filter->GetValue(&propertyValue) == S_OK && propertyValue->caul.cElems == (propertyProbe ? MAXDWORD : 6);
    if (propertyProbe) passed = passed && Touch(&sibling, 33);
    CoTaskMemFree(propertyValue);
    filterSource.fail = true;
    propertyValue = &filterSource.value;
    passed = passed && filter->GetValue(&propertyValue) == E_FAIL;
    passed = passed && first.calls == 1 && last.calls == 1 && control.calls == 1 &&
        first.queries == 0 && last.queries == 0 && control.queries == 0 &&
        first.references == 1 && last.references == 1 && control.references == 1 &&
        sibling.queries == 0 && sibling.references == 1 &&
        sibling.calls == (prefix || nested || propertyProbe ? 1u : 0u);
    SysFreeString(text);
    VirtualFree(storage, 0, MEM_RELEASE);
    if (passed && argc >= 2)
    {
        auto result = CreateFileW(argv[1], GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (result == INVALID_HANDLE_VALUE) return 2;
        DWORD written = 0;
        passed = WriteFile(result, "complete", 8, &written, nullptr) && written == 8;
        CloseHandle(result);
    }
    return passed ? 0 : 3;
}

void AllocatedVariant(const Context& context)
{
    // Returned interfaces must be discovered beyond the byte cap and through excluded producers.
    RunTarget(context, L"", 15000);
    auto result = context.directory / L"complete.result";
    Json details = Json::array();
    for (auto [limit, filtered] : {std::pair{16u, false}, {64u, false}, {256u, false}, {16u, true}})
    {
        Capture::Run(
            context,
            {.arguments = Quote(result),
             .limit = limit,
             .comOnly = true,
             .excludedApis = filtered ? std::vector<std::string>{"ICodecAPI::GetParameterValues", "IFilter::GetValue"}
                                      : std::vector<std::string>{}},
            [&](Capture& capture)
        {
            Require(ReadLog(result) == "complete", "Allocated variant target did not finish");
            auto rows = capture.Calls();
            auto codecs = Named(rows, "ICodecAPI::GetParameterValues"), filters = Named(rows, "IFilter::GetValue");
            auto leaves = Named(rows, "IDispatch::GetTypeInfoCount");
            if (context.Has(L"--baseline")) return;
            Require(leaves.size() == 2 && codecs.size() == (filtered ? 0u : 4u) &&
                        filters.size() == (filtered ? 0u : 2u),
                    "Allocated variant discovery differs", rows);
            for (size_t index = 0; index < leaves.size(); ++index)
            {
                auto output = Regions(Values(leaves[index]["output"]), {.parameter = 1});
                Require(output.size() == 1 && output[0].data == Integer(31 + index, 4) &&
                            !(leaves[index]["flags"].get<uint32_t>() & 257),
                        "Returned interface identity differs", leaves[index]);
            }
            if (!filtered)
            {
                auto regions = Regions(Values(codecs[0]["output"]), {.parameter = 2});
                auto pointers = Regions(regions, {.kind = 2});
                auto data = Regions(regions, {.kind = 0});
                Require(pointers.size() == 1 && data.size() == 1 && Read<uint64_t>(pointers[0].data) &&
                            data[0].original == 120 && data[0].data.size() == std::min(120u, limit),
                        "Allocated array differs");
                auto strings = Regions(regions, {.required = 64});
                std::vector<uint32_t> indices;
                for (const auto& value : strings)
                {
                    indices.push_back(value.flags >> 16);
                    auto text = Encode(std::string("allocated\0variant", 17), true);
                    Require(value.data == Prefix(text, limit) && value.original == text.size(),
                            "Allocated BSTR differs");
                }
                Require(indices == (limit == 16   ? std::vector<uint32_t>{}
                                    : limit == 64 ? std::vector<uint32_t>{1}
                                                  : std::vector<uint32_t>{1, 3}),
                        "Allocated BSTR identities differ");
                for (const auto& value : Values(codecs[1]["output"]))
                    Require(value.kind == 2 || value.index != 2, "Empty allocated array exposed data");
                auto damaged = Regions(Values(codecs[3]["output"]), {.parameter = 2, .kind = 0});
                Require((codecs[2]["flags"].get<uint32_t>() & 1) && Data(codecs[2]["output"]).empty() &&
                            damaged.size() == 1 && (damaged[0].flags & 2) && damaged[0].data.empty(),
                        "Failed allocated output differs");
                auto prop = Regions(Values(filters[0]["output"]), {.parameter = 1, .parameterMask = 255});
                auto raw = Regions(prop, {.kind = 0});
                auto descriptors = Regions(prop, {.kind = 10});
                auto vector = Regions(prop, {.kind = 11});
                Require(raw.size() == 1 && descriptors.size() == 1 && vector.size() == 1 && raw[0].original == 24 &&
                            raw[0].data.size() == std::min(limit, 24u) && vector[0].original == 24 &&
                            vector[0].data ==
                                Prefix(Unhex("0b00000016000000210000002c0000003700000042000000"), limit) &&
                            (filters[1]["flags"].get<uint32_t>() & 1) && Data(filters[1]["output"]).empty(),
                        "Allocated property vector differs");
                for (const auto& row : {codecs[0], filters[0]})
                {
                    Require(!(row["flags"].get<uint32_t>() & 257), "Allocated producer failed", row);
                    details.push_back({{"limit", limit}, {"call", capture.Details(row)}});
                }
            }
            capture.CheckDiagnostics();
            for (const auto& row : rows)
                CheckLimit(row, limit);
        }, 45);
    }
    if (!context.Has(L"--baseline"))
    {
        FirstMethod(context, "IDispatch::GetTypeInfoCount", Json::array({"ICodecAPI::GetParameterValues"}),
                    Quote(result));
        Require(ReadLog(result) == "complete", "Allocated first-method target did not finish");
    }
    WriteJson(context.directory / L"details.json", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, AllocatedVariant); }

#elif defined(DETOURIST_TEST_DetouristVariantBufferTests)

using namespace Detourist::Tests;
class VariantSource final : public FixedUnknown<IEnumVARIANT, IPropertyBag2>
{
public:
    std::array<VARIANT, 8> values{};
    ULONG position = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == IID_IEnumVARIANT ?
            static_cast<void*>(static_cast<IEnumVARIANT*>(this)) :
            iid == IID_IPropertyBag2 ? static_cast<IPropertyBag2*>(this) : nullptr;
        return *output ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Next(ULONG count, VARIANT* output, ULONG* fetched) override
    {
        if (count == 99) return E_FAIL;
        auto completed = std::min<ULONG>(count, static_cast<ULONG>(values.size()) - position);
        std::copy_n(values.data() + position, completed, output);
        position += completed;
        if (fetched) *fetched = completed;
        return completed == count ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { position = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumVARIANT**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Read(ULONG count, PROPBAG2*, IErrorLog*, VARIANT* output, HRESULT* errors) override
    {
        if (count == 99) return E_FAIL;
        if (count > values.size()) return E_INVALIDARG;
        std::copy_n(values.data(), count, output);
        if (errors) std::fill_n(errors, count, S_OK);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Write(ULONG count, PROPBAG2*, VARIANT* input) override
    {
        return count == values.size() && input == values.data() ? S_OK : E_INVALIDARG;
    }
    HRESULT STDMETHODCALLTYPE CountProperties(ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPropertyInfo(ULONG, ULONG, PROPBAG2*, ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE LoadObject(LPCOLESTR, DWORD, IUnknown*, IErrorLog*) override { return E_NOTIMPL; }
};

__declspec(noinline) HRESULT Query(IUnknown* object, REFIID iid, void** output)
{
    return object->QueryInterface(iid, output);
}

int TargetMain()
{
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 1;
    BSTR first = SysAllocStringLen(L"alpha\0omega", 11);
    BSTR second = SysAllocStringLen(L"tail\0", 5);
    SAFEARRAYBOUND bound{3, -5};
    SAFEARRAY* array = SafeArrayCreate(VT_BSTR, 1, &bound);
    if (!first || !second || !array) return 2;
    BSTR* data = nullptr;
    if (FAILED(SafeArrayAccessData(array, reinterpret_cast<void**>(&data)))) return 3;
    data[0] = SysAllocStringLen(first, 11);
    data[1] = SysAllocStringLen(second, 5);
    data[2] = nullptr;
    SafeArrayUnaccessData(array);

    // Returned variants include indirect values, empty strings and malformed references in unused capacity tests.
    VariantSource source;
    auto& values = source.values;
    values[0].vt = VT_BSTR;
    values[0].bstrVal = first;
    values[1].vt = VT_BSTR | VT_BYREF;
    values[1].pbstrVal = &second;
    values[2].vt = VT_VARIANT | VT_BYREF;
    values[2].pvarVal = &values[1];
    values[3].vt = VT_BSTR;
    values[4].vt = VT_ARRAY | VT_BSTR;
    values[4].parray = array;
    values[5].vt = VT_VARIANT | VT_BYREF;
    values[5].pvarVal = &values[5];
    values[6].vt = VT_BSTR | VT_BYREF;
    values[6].pbstrVal = reinterpret_cast<BSTR*>(0x12345678);
    values[7].vt = VT_BSTR;
    values[7].bstrVal = reinterpret_cast<BSTR>(0x12345678);

    // A real Automation input establishes the private object's boundary for both capture engines.
    CLSID identifier{};
    IDispatch* dictionary = nullptr;
    bool passed = SUCCEEDED(CLSIDFromProgID(L"Scripting.Dictionary", &identifier)) &&
        SUCCEEDED(CoCreateInstance(identifier, nullptr, CLSCTX_INPROC_SERVER, IID_IDispatch,
            reinterpret_cast<void**>(&dictionary)));
    LPOLESTR addName = const_cast<LPOLESTR>(L"Add");
    DISPID add = 0;
    if (passed) passed = SUCCEEDED(dictionary->GetIDsOfNames(IID_NULL, &addName, 1, LOCALE_USER_DEFAULT, &add));
    VARIANT arguments[2]{};
    arguments[0].vt = VT_UNKNOWN;
    arguments[0].punkVal = static_cast<IEnumVARIANT*>(&source);
    arguments[1].vt = VT_I4;
    DISPPARAMS parameters{arguments, nullptr, 2, 0};
    if (passed) passed = SUCCEEDED(dictionary->Invoke(add, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
        &parameters, nullptr, nullptr, nullptr));
    IEnumVARIANT* enumerator = nullptr;
    IPropertyBag2* bag = nullptr;
    passed = passed && SUCCEEDED(Query(static_cast<IEnumVARIANT*>(&source), IID_IEnumVARIANT,
        reinterpret_cast<void**>(&enumerator))) &&
        SUCCEEDED(Query(static_cast<IEnumVARIANT*>(&source), IID_IPropertyBag2, reinterpret_cast<void**>(&bag)));
    std::array<VARIANT, 9> output{};
    std::array<PROPBAG2, 8> properties{};
    std::array<HRESULT, 8> errors{};
    ULONG fetched = 99;
    if (passed)
    {
        passed = bag->Write(8, properties.data(), values.data()) == S_OK &&
            bag->Read(8, properties.data(), nullptr, output.data(), errors.data()) == S_OK &&
            bag->Read(99, properties.data(), nullptr, output.data(), errors.data()) == E_FAIL &&
            enumerator->Next(9, output.data(), &fetched) == S_FALSE && fetched == 8 &&
            enumerator->Next(9, output.data(), &fetched) == S_FALSE && fetched == 0 &&
            enumerator->Next(99, output.data(), &fetched) == E_FAIL && enumerator->Reset() == S_OK &&
            enumerator->Next(1, output.data(), nullptr) == S_OK;
    }
    if (dictionary) dictionary->Release();
    SafeArrayDestroy(array);
    SysFreeString(second);
    SysFreeString(first);
    CoUninitialize();
    return passed ? 0 : 4;
}

void VariantBuffer(const Context& context)
{
    // VARIANT buffers preserve element identities, bounded BSTRs and nested SAFEARRAY strings.
    RunTarget(context, L"", 15000);
    std::vector<Bytes> expected{Encode(std::string("alpha\0omega", 11), true),
                                Encode(std::string("tail\0", 5), true),
                                Encode(std::string("tail\0", 5), true),
                                {}};
    Json details = Json::array();
    for (bool instructions : {false, true})
        for (uint32_t limit : {16u, 56u, 64u, 256u})
        {
            Capture::Run(context, {.limit = limit, .instructions = instructions, .comOnly = true}, [&](Capture& capture)
            {
                auto rows = capture.Calls();
                auto enumerated = Named(rows, "IEnumVARIANT::Next"), writes = Named(rows, "IPropertyBag2::Write");
                auto reads = Named(rows, "IPropertyBag2::Read");
                Require(enumerated.size() == 4, "Variant enumeration calls missing", rows);
                if (instructions || !writes.empty() || !reads.empty())
                    Require(writes.size() == 1 && reads.size() == 2, "Property bag calls missing", rows);
                std::vector<std::tuple<Json, std::string, uint32_t, uint32_t>> selected{
                    {enumerated[0], "output", 2, 8}, {enumerated[3], "output", 2, 1}};
                if (!writes.empty())
                {
                    selected.emplace_back(writes[0], "input", 3, 8);
                    selected.emplace_back(reads[0], "output", 4, 8);
                }
                for (const auto& [row, phase, parameter, count] : selected)
                {
                    auto regions = Regions(Values(row[phase]), {.parameter = parameter, .parameterMask = 255});
                    auto raw = Regions(regions, {.kind = 0});
                    Require(raw.size() == 1 && raw[0].original == count * 24 &&
                                raw[0].data.size() == std::min(limit, count * 24) &&
                                !(row["flags"].get<uint32_t>() & 257),
                            "Variant buffer extent differs", row);
                    if (context.Has(L"--baseline")) continue;
                    auto strings = Regions(regions, {.required = 64});
                    auto visible = std::min(count, (limit + 8) / 24);
                    size_t position = 0;
                    for (uint32_t index = 0; index < visible; ++index)
                    {
                        if (index == 4 || index == 5) continue;
                        Require(position < strings.size(), "Variant element string missing", row);
                        const auto& value = strings[position++];
                        auto bytes = index < 4 ? expected[index] : Bytes{};
                        Require((value.flags >> 16) == index && value.kind == 1 && (value.flags & 8) &&
                                    value.original == bytes.size() && value.data == Prefix(bytes, limit) &&
                                    (value.flags & 3) == (index >= 6 ? 2u : uint32_t(limit < bytes.size())),
                                "Variant element string differs", row);
                    }
                    Require(position == strings.size(), "Unexpected variant element string", row);
                    auto arrays = Regions(regions, {.kind = 8});
                    Require(arrays.size() == size_t(visible > 4), "Nested SAFEARRAY descriptor differs", row);
                    if (!arrays.empty())
                    {
                        auto data = Regions(regions, {.kind = 9});
                        auto strings = Regions(regions, {.required = 32});
                        Require(data.size() == 1 && data[0].original == 24 && data[0].data.size() == 24 &&
                                    strings.size() == 3 && strings[0].data == expected[0] &&
                                    strings[1].data == expected[1] && strings[2].data.empty(),
                                "Nested SAFEARRAY data differs", row);
                    }
                    details.push_back({{"limit", limit},
                                       {"phase", phase},
                                       {"parameter", parameter},
                                       {"count", count},
                                       {"call", capture.Details(row)}});
                }
                if (!context.Has(L"--baseline"))
                {
                    Require(enumerated[0]["result"] == 1 && enumerated[1]["result"] == 1 &&
                                (enumerated[2]["flags"].get<uint32_t>() & 1) && Data(enumerated[2]["output"]).empty(),
                            "Empty or failed enumeration differs");
                    for (const auto& value : Values(enumerated[1]["output"]))
                        Require(value.kind != 1 && value.kind != 8 && value.kind != 9,
                                "Empty enumeration exposed payload");
                    if (!reads.empty())
                    {
                        Require(reads[1]["flags"].get<uint32_t>() & 1, "Failed property read classification missing");
                        for (const auto& value : Values(reads[1]["output"]))
                            Require(value.index != 4, "Failed property read exposed values");
                    }
                    capture.CheckDiagnostics();
                    for (const auto& row : rows)
                        CheckLimit(row, limit);
                }
            }, 45);
        }
    WriteJson(context.directory / L"details.json", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, VariantBuffer); }

#elif defined(DETOURIST_TEST_DetouristPropertyVariantTests)

using namespace Detourist::Tests;
template<ULONG Identity> class PropertyDispatch final : public CountedUnknown<IDispatch>
{
public:
    ULONG queries = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        ++queries;
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == IID_IDispatch ? this : nullptr;
        if (*output) AddRef();
        return *output ? S_OK : E_NOINTERFACE;
    }
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
    HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*) override
    {
        return E_NOTIMPL;
    }
};

class PropertyStream final : public CountedUnknown<IStream>
{
public:
    ULONG queries = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        ++queries;
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == __uuidof(IStream) ? this : nullptr;
        if (*output) AddRef();
        return *output ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Read(void* buffer, ULONG bytes, ULONG* read) override
    {
        if (!buffer || !read) return E_POINTER;
        auto count = std::min<ULONG>(bytes, 128);
        for (ULONG index = 0; index < count; ++index)
            static_cast<BYTE*>(buffer)[index] = static_cast<BYTE>(index ^ 0x6D);
        *read = count;
        return count == bytes ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Write(const void*, ULONG, ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER, DWORD, ULARGE_INTEGER*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CopyTo(IStream*, ULARGE_INTEGER, ULARGE_INTEGER*, ULARGE_INTEGER*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE Commit(DWORD) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Revert() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Stat(STATSTG*, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Clone(IStream**) override { return E_NOTIMPL; }
};

class PropertyStorage final : public CountedUnknown<IStorage>
{
public:
    ULONG queries = 0;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        ++queries;
        if (!output) return E_POINTER;
        *output = iid == IID_IUnknown || iid == __uuidof(IStorage) ? this : nullptr;
        if (*output) AddRef();
        return *output ? S_OK : E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE CreateStream(const OLECHAR*, DWORD, DWORD, DWORD, IStream**) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE OpenStream(const OLECHAR*, void*, DWORD, DWORD, IStream**) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE CreateStorage(const OLECHAR*, DWORD, DWORD, DWORD, IStorage**) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE OpenStorage(const OLECHAR*, IStorage*, DWORD, SNB, DWORD, IStorage**) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE CopyTo(DWORD, const IID*, SNB, IStorage*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE MoveElementTo(const OLECHAR*, IStorage*, const OLECHAR*, DWORD) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE Commit(DWORD) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Revert() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE EnumElements(DWORD, void*, DWORD, IEnumSTATSTG**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DestroyElement(const OLECHAR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RenameElement(const OLECHAR*, const OLECHAR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetElementTimes(
        const OLECHAR*, const FILETIME*, const FILETIME*, const FILETIME*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE SetClass(REFCLSID) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetStateBits(DWORD, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Stat(STATSTG* output, DWORD) override
    {
        if (!output) return E_POINTER;
        *output = {};
        output->type = STGTY_STORAGE;
        output->cbSize.QuadPart = 0x12345678;
        return S_OK;
    }
};

class PropertyRoot final : public CountedUnknown<IPropertyStore>
{
public:
    PROPVARIANT value{};
    ULONG queries = 0, callbacks = 0;
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
    HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY, PROPVARIANT* output) override
    {
        if (!output) return E_POINTER;
        *output = value;
        return fail ? E_FAIL : S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetValue(REFPROPERTYKEY, REFPROPVARIANT input) override
    {
        if (input.vt != VT_DISPATCH || !input.pdispVal) return E_INVALIDARG;
        UINT count = 0;
        ++callbacks;
        return input.pdispVal->GetTypeInfoCount(&count) == S_OK && count == 0 ? S_OK : E_FAIL;
    }
    HRESULT STDMETHODCALLTYPE Commit() override { return S_OK; }
};

__declspec(noinline) HRESULT PropertyQuery(IUnknown* source, REFIID iid, void** output)
{
    return source->QueryInterface(iid, output);
}

__declspec(noinline) bool PropertyTouch(IDispatch* value, UINT identity)
{
    UINT count = 0;
    DISPID identifier = 0;
    LPOLESTR name = const_cast<LPOLESTR>(L"Value");
    return value->GetTypeInfoCount(&count) == S_OK && count == 0 &&
        value->GetIDsOfNames(IID_NULL, &name, 1, 0, &identifier) == S_OK && identifier == static_cast<DISPID>(identity);
}

int TargetMain(int argc, wchar_t** argv)
{
    // Private vtables have no RTTI; the caller's interface query establishes only the property-store boundary.
    auto mode = argc > 1 ? argv[1] : L"dispatch";
    PropertyRoot root;
    PropertyDispatch<41> first;
    PropertyDispatch<42> second;
    PropertyDispatch<99> control;
    PropertyStream stream;
    PropertyStorage storage;
    PROPVARIANT nested{};
    std::array<PROPVARIANT, 3> elements{};
    std::array<LONG, 6> integers{-7, 0, 42, LONG_MIN, LONG_MAX, 123456};
    std::array<DOUBLE, 3> floating{-3.25, 0.5, 1.125};
    std::array<VARIANT_BOOL, 4> boolean{VARIANT_TRUE, VARIANT_FALSE, VARIANT_TRUE, VARIANT_FALSE};
    std::array<GUID, 2> identifiers{{{0x11223344, 0x5566, 0x7788, {1, 2, 3, 4, 5, 6, 7, 8}},
        {0x99AABBCC, 0xDDEE, 0xFF00, {8, 7, 6, 5, 4, 3, 2, 1}}}};
    std::array<LPWSTR, 4> wideStrings{const_cast<LPWSTR>(L"vector property text"), nullptr,
        reinterpret_cast<LPWSTR>(1), const_cast<LPWSTR>(L"last vector text")};
    std::array<LPSTR, 4> ansiStrings{const_cast<LPSTR>("vector property text"), nullptr,
        reinterpret_cast<LPSTR>(1), const_cast<LPSTR>("last vector text")};
    std::array<BSTR, 4> countedStrings{};
    VERSIONEDSTREAM version{};
    IDispatch* indirect = &first;
    auto releasePages = [](void* value) { if (value) VirtualFree(value, 0, MEM_RELEASE); };
    std::unique_ptr<void, decltype(releasePages)> pages(nullptr, releasePages);
    std::unique_ptr<wchar_t, decltype(&SysFreeString)> counted(nullptr, SysFreeString);
    root.value.vt = VT_DISPATCH;
    root.value.pdispVal = &first;
    if (!wcscmp(mode, L"unknown"))
    {
        root.value.vt = VT_UNKNOWN;
        root.value.punkVal = &first;
    }
    else if (!wcscmp(mode, L"byref"))
    {
        root.value.vt |= VT_BYREF;
        root.value.ppdispVal = &indirect;
    }
    else if (!wcscmp(mode, L"vector") || !wcscmp(mode, L"nested") || !wcscmp(mode, L"cycle"))
    {
        elements[0].vt = VT_DISPATCH;
        elements[0].pdispVal = &first;
        elements[1].vt = VT_DISPATCH | VT_BYREF;
        elements[1].ppdispVal = &indirect;
        elements[2].vt = VT_DISPATCH;
        elements[2].pdispVal = &second;
        nested.vt = VT_VECTOR | VT_VARIANT;
        nested.capropvar = {static_cast<ULONG>(elements.size()), elements.data()};
        root.value = nested;
        if (!wcscmp(mode, L"nested"))
        {
            root.value.vt = VT_VARIANT | VT_BYREF;
            root.value.pvarVal = &nested;
        }
        if (!wcscmp(mode, L"cycle"))
        {
            root.value.vt = VT_VARIANT | VT_BYREF;
            root.value.pvarVal = &root.value;
        }
    }
    else if (!wcscmp(mode, L"stream") || !wcscmp(mode, L"streamed") || !wcscmp(mode, L"versioned"))
    {
        root.value.vt = static_cast<VARTYPE>(!wcscmp(mode, L"streamed") ? VT_STREAMED_OBJECT : VT_STREAM);
        root.value.pStream = &stream;
        if (!wcscmp(mode, L"versioned"))
        {
            version.pStream = &stream;
            root.value.vt = VT_VERSIONED_STREAM;
            root.value.pVersionedStream = &version;
        }
    }
    else if (!wcscmp(mode, L"storage") || !wcscmp(mode, L"stored"))
    {
        root.value.vt = static_cast<VARTYPE>(!wcscmp(mode, L"stored") ? VT_STORED_OBJECT : VT_STORAGE);
        root.value.pStorage = &storage;
    }
    else if (!wcscmp(mode, L"empty-vector") || !wcscmp(mode, L"invalid-vector"))
    {
        root.value.vt = VT_VECTOR | VT_VARIANT;
        root.value.capropvar = {!wcscmp(mode, L"empty-vector") ? 0ul : 3ul, reinterpret_cast<PROPVARIANT*>(1)};
    }
    else if (!wcscmp(mode, L"integer-vector"))
    {
        root.value.vt = VT_VECTOR | VT_I4;
        root.value.cal = {static_cast<ULONG>(integers.size()), integers.data()};
    }
    else if (!wcscmp(mode, L"float-vector"))
    {
        root.value.vt = VT_VECTOR | VT_R8;
        root.value.cadbl = {static_cast<ULONG>(floating.size()), floating.data()};
    }
    else if (!wcscmp(mode, L"bool-vector"))
    {
        root.value.vt = VT_VECTOR | VT_BOOL;
        root.value.cabool = {static_cast<ULONG>(boolean.size()), boolean.data()};
    }
    else if (!wcscmp(mode, L"guid-vector"))
    {
        root.value.vt = VT_VECTOR | VT_CLSID;
        root.value.cauuid = {static_cast<ULONG>(identifiers.size()), identifiers.data()};
    }
    else if (!wcscmp(mode, L"wide-string-vector"))
    {
        root.value.vt = VT_VECTOR | VT_LPWSTR;
        root.value.calpwstr = {static_cast<ULONG>(wideStrings.size()), wideStrings.data()};
    }
    else if (!wcscmp(mode, L"ansi-string-vector"))
    {
        root.value.vt = VT_VECTOR | VT_LPSTR;
        root.value.calpstr = {static_cast<ULONG>(ansiStrings.size()), ansiStrings.data()};
    }
    else if (!wcscmp(mode, L"bstr-string-vector"))
    {
        constexpr wchar_t text[] = L"counted\0vector text";
        counted.reset(SysAllocStringLen(text, static_cast<UINT>(std::size(text) - 1)));
        if (!counted) return 3;
        countedStrings = {counted.get(), nullptr, reinterpret_cast<BSTR>(1), counted.get()};
        root.value.vt = VT_VECTOR | VT_BSTR;
        root.value.cabstr = {static_cast<ULONG>(countedStrings.size()), countedStrings.data()};
    }
    else if (wcsstr(mode, L"-text"))
    {
        // Place terminated property text immediately before an inaccessible page to expose overreads.
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        pages.reset(VirtualAlloc(nullptr, static_cast<SIZE_T>(system.dwPageSize) * 2,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        DWORD previous = 0;
        if (!pages || !VirtualProtect(static_cast<BYTE*>(pages.get()) + system.dwPageSize,
            system.dwPageSize, PAGE_NOACCESS, &previous)) return 3;
        auto end = static_cast<BYTE*>(pages.get()) + system.dwPageSize;
        if (!wcscmp(mode, L"wide-text"))
        {
            constexpr wchar_t text[] = L"guarded property text";
            root.value.vt = VT_LPWSTR;
            root.value.pwszVal = reinterpret_cast<wchar_t*>(end - sizeof(text));
            memcpy(root.value.pwszVal, text, sizeof(text));
        }
        else if (!wcscmp(mode, L"bstr-text"))
        {
            constexpr wchar_t text[] = L"counted\0property text";
            counted.reset(SysAllocStringLen(text, static_cast<UINT>(std::size(text) - 1)));
            if (!counted) return 3;
            root.value.vt = VT_BSTR;
            root.value.bstrVal = counted.get();
        }
        else
        {
            constexpr char text[] = "guarded property text";
            root.value.vt = VT_LPSTR;
            root.value.pszVal = reinterpret_cast<char*>(end - sizeof(text));
            memcpy(root.value.pszVal, text, sizeof(text));
            if (!wcscmp(mode, L"unreadable-text")) root.value.pszVal = reinterpret_cast<char*>(end);
            if (!wcscmp(mode, L"null-text")) root.value.pszVal = nullptr;
        }
    }
    root.fail = !wcscmp(mode, L"failed") || !wcscmp(mode, L"failed-text");
    void* queried = nullptr;
    if (PropertyQuery(&root, __uuidof(IPropertyStore), &queried) != S_OK) return 1;
    auto store = static_cast<IPropertyStore*>(queried);
    PROPERTYKEY key{{0x11223344, 0x5566, 0x7788, {1, 2, 3, 4, 5, 6, 7, 8}}, 1};
    PROPVARIANT returned{};
    bool valid;
    if (!wcscmp(mode, L"input")) valid = store->SetValue(key, root.value) == S_OK;
    else
    {
        auto result = store->GetValue(key, &returned);
        valid = result == (root.fail ? E_FAIL : S_OK);
        if (returned.vt == VT_STREAM || returned.vt == VT_STREAMED_OBJECT || returned.vt == VT_VERSIONED_STREAM)
        {
            std::array<BYTE, 128> data{};
            ULONG read = 0;
            auto source = returned.vt == VT_VERSIONED_STREAM ? returned.pVersionedStream->pStream : returned.pStream;
            valid &= source->Read(data.data(), static_cast<ULONG>(data.size()), &read) == S_OK && read == data.size();
            for (size_t index = 0; index < data.size(); ++index)
                valid &= data[index] == static_cast<BYTE>(index ^ 0x6D);
        }
        else if (returned.vt == VT_STORAGE || returned.vt == VT_STORED_OBJECT)
        {
            STATSTG information{};
            valid &= returned.pStorage->Stat(&information, STATFLAG_NONAME) == S_OK &&
                information.type == STGTY_STORAGE && information.cbSize.QuadPart == 0x12345678;
        }
        else
        {
            if (!wcscmp(mode, L"unknown")) { first.AddRef(); first.Release(); }
            valid &= PropertyTouch(&first, 41);
            if (!wcscmp(mode, L"vector") || !wcscmp(mode, L"nested")) valid &= PropertyTouch(&second, 42);
        }
    }
    store->Release();
    valid &= PropertyTouch(&control, 99) && root.queries == 1 && root.references == 1 &&
        first.queries == 0 && second.queries == 0 && stream.queries == 0 && storage.queries == 0 &&
        first.references == 1 && second.references == 1 && stream.references == 1 && storage.references == 1;
    printf("mode=%ls root_queries=%lu leaf_queries=%lu references=%lu callbacks=%lu\n", mode,
        root.queries, first.queries + second.queries + stream.queries,
        first.references + second.references + stream.references, root.callbacks);
    return valid ? 0 : 2;
}

void PropertyVariant(const Context& context)
{
    // Discover passive interface references without adding queries or changing ownership.
    std::vector<std::string> modes{
        "dispatch", "byref",     "vector",    "nested",       "stream",          "streamed",  "versioned",
        "input",    "storage",   "stored",    "empty-vector", "invalid-vector",  "unknown",   "failed",
        "cycle",    "ansi-text", "wide-text", "bstr-text",    "unreadable-text", "null-text", "failed-text"};
    for (const auto& mode : modes)
    {
        auto baseline = RunTarget(context, Detourist::Wide(mode), 15000);
        Require(baseline.contains("root_queries=1 leaf_queries=0 references=3"),
                "Property reference ownership differs");
        for (uint32_t limit : context.Has(L"--baseline") ? std::vector<uint32_t>{16} : std::vector<uint32_t>{16, 64})
        {
            Capture::Run(context, {.arguments = Detourist::Wide(mode), .limit = limit, .comOnly = true},
                         [&](Capture& capture)
            {
                if (context.Has(L"--baseline")) return;
                auto rows = capture.Calls();
                auto leaves = Named(rows, "IDispatch::GetTypeInfoCount"), streams = Named(rows, "IStream::Read");
                auto storage = Named(rows, "IStorage::Stat");
                std::set<std::string> withoutLeaves{"unknown",   "failed",  "cycle",  "stream",       "streamed",
                                                    "versioned", "storage", "stored", "empty-vector", "invalid-vector"};
                auto expected = mode.ends_with("-text") || withoutLeaves.contains(mode) ? 0u
                                : mode == "vector" || mode == "nested"                  ? 2u
                                                                                        : 1u;
                Require(leaves.size() == expected &&
                            streams.size() == size_t(mode == "stream" || mode == "streamed" || mode == "versioned") &&
                            storage.size() == size_t(mode == "storage" || mode == "stored"),
                        "Property interface discovery differs", rows);
                for (const auto& row : leaves)
                    Require(!(row["flags"].get<uint32_t>() & 256) &&
                                Snapshots(row["output"], 1, 2) == std::vector<Bytes>{Integer(0, 4)},
                            "Property leaf output differs", row);
                for (const auto& row : streams)
                {
                    Bytes bytes(limit);
                    for (size_t index = 0; index < bytes.size(); ++index)
                        bytes[index] = uint8_t(index ^ 0x6d);
                    auto values = Values(row["output"]);
                    Require(!(row["flags"].get<uint32_t>() & 256) && std::ranges::any_of(values, [&](const Value& value)
                    { return value.index == 1 && value.original == 128 && value.data == bytes; }),
                            "Property stream differs", row);
                }
                for (const auto& row : storage)
                {
                    auto values = Values(row["output"]);
                    Require(!(row["flags"].get<uint32_t>() & 256) && std::ranges::any_of(values,
                                                                                         [&](const Value& value)
                    {
                        return value.index == 1 && value.original == 80 && value.data.size() == limit &&
                               Read<uint32_t>(value.data, 8) == 1;
                    }),
                            "Property storage differs", row);
                }
                auto producers = Named(rows, "IPropertyStore::GetValue");
                auto setters = Named(rows, "IPropertyStore::SetValue");
                for (const auto& row : setters)
                    producers.push_back(row);
                Require(producers.size() == 1, "Property producer count differs", producers);
                const auto& producer = producers[0];
                Require(!(producer["flags"].get<uint32_t>() & 256) && Data(producer["arguments"]).size() == 24,
                        "Property producer contract differs", producer);
                if (mode == "failed" || mode == "failed-text")
                    Require((producer["flags"].get<uint32_t>() & 1) && Data(producer["output"]).empty(),
                            "Failed property output differs", producer);
                else
                {
                    auto values = Values(producer[mode == "input" ? "input" : "output"]);
                    Require(std::ranges::any_of(values, [&](const Value& value)
                    { return value.index == 2 && value.original == 24 && value.data.size() == std::min(limit, 24u); }),
                            "Property variant header differs", producer);
                    if (mode.ends_with("-text"))
                    {
                        auto text = Regions(values, {.required = 8});
                        if (mode == "null-text")
                            Require(text.empty(), "Null property text was captured");
                        else if (mode == "unreadable-text")
                            Require(text.size() == 1 && (text[0].flags & 2) && text[0].data.empty(),
                                    "Unreadable text differs");
                        else
                        {
                            auto bytes = mode == "bstr-text"
                                             ? Encode(std::string("counted\0property text", 21), true)
                                             : Encode("guarded property text", mode != "ansi-text", true);
                            bool truncated = bytes.size() > limit;
                            Require(text ==
                                        std::vector<Value>{{2, mode == "ansi-text" ? 0u : 1u, 8u | uint32_t(truncated),
                                                            mode == "bstr-text" || !truncated ? bytes.size() : 0,
                                                            Prefix(bytes, limit)}},
                                    "Property text differs", producer);
                        }
                    }
                }
                if (mode == "input")
                    Require(producer["started"] <= leaves[0]["started"] && leaves[0]["started"] < leaves[0]["ended"] &&
                                leaves[0]["ended"] <= producer["ended"],
                            "Property input call nesting differs");
                if (mode == "unknown")
                    Require(std::ranges::any_of(Named(rows, "IUnknown::AddRef"),
                                                [&](const Json& row) { return row["started"] > producer["ended"]; }),
                            "Unknown property reference was lost");
                for (const auto& row : rows)
                    CheckLimit(row, limit);
                if (mode == "dispatch" && limit == 64)
                {
                    auto details = capture.Details(producer);
                    auto parameters = details["parameters"].get<std::string>();
                    Require(parameters.contains("PROPVARIANT") && parameters.contains("pv"),
                            "Property metadata differs");
                }
            }, 40);
        }
    }
    if (!context.Has(L"--baseline"))
    {
        auto database =
            FirstMethod(context, "IDispatch::GetTypeInfoCount", Json::array({"IPropertyStore::GetValue"}), L"dispatch");
        auto rows = Calls(database);
        Require(Named(rows, "IPropertyStore::GetValue").empty() && !Named(rows, "IDispatch::GetTypeInfoCount").empty(),
                "Filtered property producer discovery differs", rows);
    }
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, PropertyVariant); }

#else
#error Select a native test target.
#endif

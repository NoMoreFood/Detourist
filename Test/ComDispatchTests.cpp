#include "TestSupport.h"

#if defined(DETOURIST_TEST_DetouristNoRttiComTests) || \
    defined(DETOURIST_TEST_DetouristGuardedComTests) || \
    defined(DETOURIST_TEST_DetouristXfgComTests)

using namespace Detourist::Tests;

// Place workload guard dispatches in a distinct executable section.
#pragma code_seg(push, ".testapi")
struct __declspec(uuid("e45d8d21-25b7-4920-a530-31d9cd09f480")) IPrivateProbe : IUnknown
{
    virtual ULONG STDMETHODCALLTYPE Transform(ULONG value) = 0;
};

class PrivateStream final : public ISequentialStream, public IPrivateProbe
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid == __uuidof(IUnknown) || iid == __uuidof(ISequentialStream))
            *output = static_cast<ISequentialStream*>(this);
        else if (iid == __uuidof(IPrivateProbe)) *output = static_cast<IPrivateProbe*>(this);
        else return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override { return --references_; }

    HRESULT STDMETHODCALLTYPE Read(void* buffer, ULONG bytes, ULONG* read) override
    {
        auto count = std::min(bytes, static_cast<ULONG>(contents_.size()));
        memcpy(buffer, contents_.data(), count);
        if (read) *read = count;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Write(const void* buffer, ULONG bytes, ULONG* written) override
    {
        auto count = std::min(bytes, static_cast<ULONG>(contents_.size()));
        memcpy(contents_.data(), buffer, count);
        if (written) *written = count;
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE Transform(ULONG value) override { return value ^ 0x13579BDF; }

private:
    std::atomic<ULONG> references_ = 1;
    std::array<BYTE, 128> contents_{};
};

class OrdinaryVirtual
{
public:
    virtual HRESULT Query(REFIID iid, void** output)
    {
        *output = nullptr;
        return iid == __uuidof(IUnknown) ? E_NOINTERFACE : S_FALSE;
    }
    virtual ULONG Measure(ULONG value) { return value + 1; }
    virtual bool Ready() { return true; }
};

__declspec(noinline) HRESULT Query(IUnknown* instance, REFIID iid, void** output)
{
    auto result = instance->QueryInterface(iid, output);
    return SUCCEEDED(result) && !*output ? E_UNEXPECTED : result;
}

__declspec(noinline) HRESULT TailQuery(IUnknown* instance, REFIID iid, void** output)
{
    return instance->QueryInterface(iid, output);
}

__declspec(noinline) HRESULT OrdinaryQuery(OrdinaryVirtual* instance, REFIID iid, void** output)
{
    auto result = instance->Query(iid, output);
    return SUCCEEDED(result) && *output ? E_UNEXPECTED : result;
}

__declspec(noinline) bool Exercise(PrivateStream& instance)
{
    // No factory or SDK call exposes this stack object to the monitor.
    void* output = nullptr;
    auto base = static_cast<ISequentialStream*>(&instance);
    bool valid = SUCCEEDED(Query(base, __uuidof(IPrivateProbe), &output));
    if (output)
    {
        auto custom = static_cast<IPrivateProbe*>(output);
        valid &= custom->Transform(0x2468ACE0) == (0x2468ACE0 ^ 0x13579BDF);
        custom->Release();
    }
    output = nullptr;
    if (FAILED(TailQuery(base, __uuidof(ISequentialStream), &output))) return false;
    auto stream = static_cast<ISequentialStream*>(output);
    std::array<BYTE, 128> input{}, captured{};
    for (size_t index = 0; index < input.size(); ++index) input[index] = static_cast<BYTE>(index ^ 0x5A);
    ULONG written = 0, read = 0;
    valid &= SUCCEEDED(stream->Write(input.data(), static_cast<ULONG>(input.size()), &written)) &&
        written == input.size() && SUCCEEDED(stream->Read(captured.data(), 128, &read)) && read == 128 &&
        captured == input;
    stream->Release();
    output = reinterpret_cast<void*>(1);
    valid &= Query(base, __uuidof(IDispatch), &output) == E_NOINTERFACE && !output;
    return valid;
}

__declspec(noinline) uintptr_t PointerIdentity(void* first, void* second, void* third)
{
    return reinterpret_cast<uintptr_t>(first) ^ reinterpret_cast<uintptr_t>(second) ^
        reinterpret_cast<uintptr_t>(third);
}

int TargetMain([[maybe_unused]] int argc, [[maybe_unused]] wchar_t** argv)
{
#ifdef DETOURIST_TEST_GUARDED
    // Require the operating system's guard policy to remain active during monitored execution.
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy{};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &policy,
        sizeof(policy)) || !policy.EnableControlFlowGuard) return 3;
#ifdef DETOURIST_TEST_XFG
    // Report the operating system's enforcement state alongside the verified dispatch workload.
    FILE* result = nullptr;
    if (argc != 2 || _wfopen_s(&result, argv[1], L"wb") || !result) return 4;
    const auto written = fwrite(&policy.Flags, sizeof(policy.Flags), 1, result);
    if (fclose(result) || written != 1) return 5;
#endif
#endif
    // Ordinary register calls may carry guarded pointers without ever dereferencing them.
    auto release = [](void* value) { if (value) VirtualFree(value, 0, MEM_RELEASE); };
    std::unique_ptr<void, decltype(release)> memory(VirtualAlloc(nullptr, 8192,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), release);
    DWORD protection = 0;
    if (!memory || !VirtualProtect(static_cast<BYTE*>(memory.get()) + 4096, 4096,
        PAGE_READWRITE | PAGE_GUARD, &protection)) return 6;
    auto volatile dispatch = &PointerIdentity;
    void* second = &memory;
    void* third = &protection;
    for (auto offset : {4096u, 4096u - static_cast<unsigned>(sizeof(void*) / 2)})
    {
        auto first = static_cast<BYTE*>(memory.get()) + offset;
        if (dispatch(first, second, third) != PointerIdentity(first, second, third)) return 7;
    }
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(static_cast<BYTE*>(memory.get()) + 4096, &region, sizeof(region)) ||
        !(region.Protect & PAGE_GUARD)) return 8;

    OrdinaryVirtual ordinary;
    void* output = reinterpret_cast<void*>(1);
    if (OrdinaryQuery(&ordinary, __uuidof(IUnknown), &output) != E_NOINTERFACE || output) return 1;
    std::atomic<ULONG> failures = 0;
    std::vector<std::jthread> workers;
    for (ULONG worker = 0; worker < 4; ++worker)
    {
        workers.emplace_back([&]()
        {
            PrivateStream instance;
            for (ULONG iteration = 0; iteration < 8; ++iteration)
                if (!Exercise(instance)) ++failures;
        });
    }
    workers.clear();
    return failures ? 2 : 0;
}
#pragma code_seg(pop)

void NoRttiCom(const Context& context)
{
    // Require actual XFG call and tail-call sites through the configured dispatch slots.
    auto policy = context.directory / L"guard-policy.bin";
    if (context.Has(L"--xfg"))
    {
        Image image(context.target);
        auto directory = image.headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        auto config = image.Offset(directory.VirtualAddress);
        Require(directory.Size >= 304 && Read<uint32_t>(image.bytes, config) >= 304, "XFG load config missing");
        uint32_t calls = 0, tails = 0;
        auto first = Read<uint64_t>(image.bytes, config + 288);
        auto second = Read<uint64_t>(image.bytes, config + 296);
        for (const auto& section : image.sections)
        {
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                std::string_view(reinterpret_cast<const char*>(section.Name), sizeof(section.Name)) != ".testapi")
                continue;
            for (size_t offset = 0; offset + 6 < section.SizeOfRawData; ++offset)
            {
                auto position = section.PointerToRawData + offset;
                if (image.bytes[position] != 0xff ||
                    (image.bytes[position + 1] != 0x15 && image.bytes[position + 1] != 0x25))
                    continue;
                auto slot = image.headers.OptionalHeader.ImageBase + section.VirtualAddress + offset + 6 +
                            Read<int32_t>(image.bytes, position + 2);
                if (slot != first && slot != second) continue;
                (image.bytes[position + 1] == 0x15 ? calls : tails)++;
            }
        }
        Require(calls && tails, "Actual XFG calls or tail calls missing");
    }
    Collector hello(context.collector, context.directory);
    auto catalog = hello.Call("hello");
    hello.Close();
    Capture::Run(
        context,
        {.arguments = context.Has(L"--xfg") ? Quote(policy) : L"", .limit = 64, .apiMask = Number(catalog["comMask"])},
        [&](Capture& capture)
    {
        if (context.Has(L"--xfg"))
        {
            auto text = ReadLog(policy);
            Require(text.size() == 4 && (Read<uint32_t>(Bytes(text.begin(), text.end())) & 1),
                    "CFG enforcement disabled");
        }
        auto targets = capture.collector.Call("page", {{"database", Text(capture.database)}, {"limit", 1}})["targets"];
        for (const auto& target : targets)
            Require(target["state"] == "Exited", "COM target is still running");
        auto rows = capture.Calls();
        auto queries = Named(rows, "IUnknown::QueryInterface");
        Require(queries.size() == 96, "QueryInterface count differs", queries);
        size_t failed = 0;
        for (const auto& row : queries)
        {
            failed += bool(row["flags"].get<uint32_t>() & 1);
            Require(!Data(row["input"]).empty() && Data(row["arguments"]).size() == 24, "Query input missing", row);
        }
        Require(failed == 32 && Query(capture.database, "SELECT id FROM calls WHERE ended<started").empty(),
                "Failed query classification or timing differs");
        auto queryId = Named(catalog["catalog"], "IUnknown::QueryInterface")[0]["id"];
        auto counts = Query(capture.database, "SELECT tid,COUNT(*) count FROM calls WHERE api=? GROUP BY tid",
                            Json::array({queryId}));
        Require(counts.size() == 4, "Concurrent COM threads missing", counts);
        for (const auto& count : counts)
            Require(count["count"] == 24, "COM thread call count differs", counts);
        Bytes payload(64);
        for (size_t index = 0; index < payload.size(); ++index)
            payload[index] = static_cast<uint8_t>(index ^ 0x5a);
        for (auto [name, phase] :
             {std::pair{"ISequentialStream::Write", "input"}, {"ISequentialStream::Read", "output"}})
        {
            auto calls = Named(rows, name);
            Require(calls.size() == 32, "Concurrent stream call count differs", calls);
            for (const auto& row : calls)
            {
                auto parameters = row["parameters"].get<std::string>();
                Require(!(row["flags"].get<uint32_t>() & 256) && parameters.contains("pv") &&
                            parameters.contains("cb") && Read<uint64_t>(row["arguments"], 16) == 128,
                        "Stream contract differs", row);
                auto values = Values(row[phase]);
                Require(std::ranges::any_of(values, [&](const Value& value)
                { return value.index == 1 && (value.flags & 1) && value.original == 128 && value.data == payload; }),
                        "Concurrent stream bytes differ", row);
                if (std::string(phase) == "output")
                    Require(Snapshots(row["output"], 3, 2) == std::vector<Bytes>{Integer(128, 4)},
                            "Stream output count differs", row);
            }
        }
        auto custom = Named(rows, "{e45d8d21-25b7-4920-a530-31d9cd09f480}::slot 3");
        Require(custom.size() == 32, "Custom slot count differs", custom);
        for (const auto& row : custom)
            Require((row["flags"].get<uint32_t>() & 256) && Read<uint64_t>(row["arguments"], 8) == 0x2468ace0 &&
                        row["result"] == (0x2468ace0 ^ 0x13579bdf),
                    "Custom slot differs", row);
    }, 60);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, NoRttiCom); }

#elif defined(DETOURIST_TEST_DetouristContextComTests)

using namespace Detourist::Tests;
const GUID ContextIdentity{0x23456789, 0x1234, 0xABCD, {1, 2, 3, 4, 5, 6, 7, 8}};

// This private object supplies no RTTI; its actual interface query establishes the SDK contract.
class ContextInformation final : public IObjectContextInfo
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IUnknown) || iid == __uuidof(IObjectContextInfo) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    BOOL STDMETHODCALLTYPE IsInTransaction() override { return FALSE; }
    HRESULT STDMETHODCALLTYPE GetTransaction(IUnknown** value) override
    {
        if (value) *value = nullptr;
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetTransactionId(GUID*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetActivityId(GUID* value) override
    {
        if (!value) return E_POINTER;
        *value = ContextIdentity;
        ++value->Data1;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetContextId(GUID* value) override
    {
        if (!value) return E_POINTER;
        *value = ContextIdentity;
        return S_OK;
    }
private:
    std::atomic<ULONG> references_ = 1;
};

class ContextProperties final : public IEnumContextProps
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
    {
        if (!value) return E_POINTER;
        *value = iid == __uuidof(IUnknown) || iid == __uuidof(IEnumContextProps) ? this : nullptr;
        if (*value) AddRef();
        return *value ? S_OK : E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override { return --references_; }

    HRESULT STDMETHODCALLTYPE Next(ULONG count, ContextProperty* values, ULONG* fetched) override
    {
        if (!values || !fetched) return E_POINTER;
        if (count != 1) return E_INVALIDARG;
        memset(values, 0, sizeof(*values));
        values[0].policyId = ContextIdentity;
        values[0].flags = 7;
        *fetched = 1;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return S_FALSE; }
    HRESULT STDMETHODCALLTYPE Reset() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumContextProps**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Count(ULONG* count) override
    {
        if (!count) return E_POINTER;
        *count = 1;
        return S_OK;
    }

private:
    std::atomic<ULONG> references_ = 1;
};

__declspec(noinline) HRESULT Query(IUnknown* object, REFIID iid, void** value)
{
    return object->QueryInterface(iid, value);
}

HRESULT __stdcall ContextBody(ComCallData* parameters)
{
    if (!parameters || parameters->dwDispid != 0x2A || parameters->dwReserved != 0x12345678 ||
        !parameters->pUserDefined) return E_INVALIDARG;
    *static_cast<ULONG*>(parameters->pUserDefined) = 0xC01DC0DE;
    return S_OK;
}

int TargetMain()
{
    auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) return 1;

    // The operating system supplies a real context callback and executes the application's callback.
    IContextCallback* callback = nullptr;
    auto obtained = CoGetObjectContext(__uuidof(IContextCallback), reinterpret_cast<void**>(&callback));
    ULONG invoked = 0;
    ComCallData parameters{0x2A, 0x12345678, &invoked};
    bool passed = SUCCEEDED(obtained) && callback && callback->ContextCallback(&ContextBody, &parameters,
        IID_IUnknown, 3, nullptr) == S_OK && invoked == 0xC01DC0DE;
    if (callback) callback->Release();

    // A queried private implementation must retain named methods and bounded GUID outputs.
    ContextInformation instance;
    void* selected = nullptr;
    passed &= Query(&instance, __uuidof(IObjectContextInfo), &selected) == S_OK && selected;
    if (selected)
    {
        auto information = static_cast<IObjectContextInfo*>(selected);
        GUID identity{};
        passed &= !information->IsInTransaction() && information->GetContextId(&identity) == S_OK &&
            identity == ContextIdentity;
        passed &= information->GetActivityId(&identity) == S_OK && identity.Data1 == ContextIdentity.Data1 + 1;
        information->Release();
    }

    // A guarded SDK context interface returns one counted, expandable property item.
    ContextProperties properties;
    selected = nullptr;
    passed &= Query(&properties, __uuidof(IEnumContextProps), &selected) == S_OK && selected;
    if (selected)
    {
        auto enumeration = static_cast<IEnumContextProps*>(selected);
        ContextProperty item{};
        ULONG fetched = 0, count = 0;
        passed &= enumeration->Next(1, &item, &fetched) == S_OK && fetched == 1 &&
            item.policyId == ContextIdentity && item.flags == 7 && !item.pUnk;
        passed &= enumeration->Count(&count) == S_OK && count == 1;
        enumeration->Release();
    }
    CoUninitialize();
    return passed ? 0 : 2;
}

void ContextCom(const Context& context)
{
    // Context callbacks capture their data rather than the callback's executable bytes.
    RunTarget(context, L"", 15000);
    for (uint32_t limit : {16u, 64u})
    {
        Collector hello(context.collector, context.directory);
        auto mask = hello.Call("hello")["comMask"];
        hello.Close();
        Capture::Run(context, {.limit = limit, .apiMask = Number(mask)}, [&](Capture& capture)
        {
            auto targets =
                capture.collector.Call("page", {{"database", Text(capture.database)}, {"limit", 1}})["targets"];
            for (const auto& target : targets)
                Require(target["state"] == "Exited", "COM target is still running");
            auto rows = capture.Calls();
            for (auto name : {"IContextCallback::ContextCallback", "IObjectContextInfo::IsInTransaction",
                              "IObjectContextInfo::GetContextId", "IObjectContextInfo::GetActivityId",
                              "IEnumContextProps::Next", "IEnumContextProps::Count"})
            {
                auto calls = Named(rows, name);
                Require(!calls.empty(), "Context method missing: " + std::string(name));
                for (const auto& row : calls)
                    Require(!(row["flags"].get<uint32_t>() & 256), "Context method is raw", row);
            }
            auto callback = Named(rows, "IContextCallback::ContextCallback")[0];
            auto parameters = callback["parameters"].get<std::string>();
            Require(parameters.contains("pfnCallback") && parameters.contains("pParam") &&
                        Snapshots(callback["input"], 1, 0).empty() && Snapshots(callback["output"], 2, 0).empty(),
                    "Context callback directions differ", callback);
            auto data = Snapshots(callback["input"], 2, 0);
            Require(data.size() == 1 && data[0].size() == 16 && Read<uint32_t>(data[0]) == 0x2a &&
                        Read<uint32_t>(data[0], 4) == 0x12345678 && Read<uint64_t>(data[0], 8),
                    "Callback data differs");
            auto guid = Unhex("896745233412cdab0102030405060708");
            for (auto name : {"IObjectContextInfo::GetContextId", "IObjectContextInfo::GetActivityId"})
                for (const auto& row : Named(rows, name))
                {
                    auto expected = guid;
                    if (std::string(name).ends_with("GetActivityId")) expected[0] = 0x8a;
                    auto text = row["parameters"].get<std::string>();
                    Require((text.contains("pGuid") || text.contains("pGUID")) &&
                                Snapshots(row["output"], 1, 0) == std::vector<Bytes>{expected},
                            "Context GUID differs", row);
                }
            auto enumeration = Named(rows, "IEnumContextProps::Next")[0];
            auto property = guid;
            property.resize(32);
            property[16] = 7;
            Require(enumeration["parameters"].get<std::string>().contains("ContextProperty * pContextProperties") &&
                        Snapshots(enumeration["output"], 2, 0) == std::vector<Bytes>{Prefix(property, limit)} &&
                        Snapshots(enumeration["output"], 3, 2) == std::vector<Bytes>{Integer(1, 4)} &&
                        Snapshots(Named(rows, "IEnumContextProps::Count")[0]["output"], 1, 2) ==
                            std::vector<Bytes>{Integer(1, 4)},
                    "Context enumeration differs", enumeration);
            for (const auto& row : rows)
                CheckLimit(row, limit);
            Require(Query(capture.database, "SELECT message FROM diagnostics").empty(), "Capture diagnostics");
        }, 45);
    }
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ContextCom); }

#else
#error Select a native test target.
#endif

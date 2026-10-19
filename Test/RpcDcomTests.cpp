#include "TestSupport.h"
#include "RpcCapture.h"
#include "RpcObjectFixture.h"

extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID, REFIID, void**);
using namespace Detourist::Tests;
using Microsoft::WRL::ComPtr;

HANDLE DcomGate = nullptr;
class DcomProbe final : public IDetouristRpcProbe
{
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) override
    {
        *result = nullptr;
        if (iid != IID_IUnknown && iid != IID_IDetouristRpcProbe) return E_NOINTERFACE;
        *result = static_cast<IDetouristRpcProbe*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override { return --references_; }
    HRESULT STDMETHODCALLTYPE Value(long number, long* changed) override
    {
        if (WaitForSingleObject(DcomGate, 15000) != WAIT_OBJECT_0) return E_UNEXPECTED;
        if (number < 0) return E_ACCESSDENIED;
        *changed = number * 3;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Mix(double fraction, hyper wide, long first, long second, long third,
        const wchar_t* text, hyper* total) override
    {
        if (fraction != 3.25 || wide != 0x123456789LL || first != 5 || second != 7 || third != 11 ||
            wcscmp(text, L"async-com"))
            return E_INVALIDARG;
        *total = wide + first + second + third;
        return S_OK;
    }
private:
    std::atomic<ULONG> references_{1};
};

int DcomTarget(int, wchar_t**)
{
    // COM resolves async/sync IID associations through the interface registry, even for process-local proxies.
    // Some Windows releases read those associations only from machine registrations, so elevated runs register
    // there and other runs fall back to per-user keys.
    Detourist::Handle registryMutex(CreateMutexW(nullptr, FALSE, L"Local\\Detourist.RpcDcom.Registry"));
    const auto locked = registryMutex ? WaitForSingleObject(registryMutex.get(), 60000) : WAIT_FAILED;
    Require(locked == WAIT_OBJECT_0 || locked == WAIT_ABANDONED, "Lock COM fixture registration");
    const wchar_t* ids[]{L"{a01cfdea-4564-47dc-92d4-b604c8ffcc9f}", L"{b851663e-3d68-4133-9502-c7e494515ad4}"};
    std::wstring keys[2]{L"Software\\Classes\\Interface\\" + std::wstring(ids[0]),
        L"Software\\Classes\\Interface\\" + std::wstring(ids[1])};
    bool created[2]{};
    HKEY hive = HKEY_LOCAL_MACHINE;
    auto remove = [&](bool*)
    {
        for (uint32_t index = 0; index < 2; ++index)
            if (created[index])
            {
                RegDeleteTreeW(hive, keys[index].c_str());
                RegDeleteKeyW(hive, keys[index].c_str());
            }
        ReleaseMutex(registryMutex.get());
    };
    std::unique_ptr<bool, decltype(remove)> registration(created, remove);
    for (uint32_t index = 0; index < 2; ++index)
    {
        const auto name = index ? L"SynchronousInterface" : L"AsynchronousInterface";
        const auto value = ids[1 - index];
        HKEY key = nullptr;
        DWORD disposition = 0;
        auto status = RegCreateKeyExW(hive, keys[index].c_str(), 0, nullptr,
            REG_OPTION_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &key, &disposition);
        if (status == ERROR_ACCESS_DENIED && !index)
        {
            hive = HKEY_CURRENT_USER;
            status = RegCreateKeyExW(hive, keys[index].c_str(), 0, nullptr,
                REG_OPTION_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &key, &disposition);
        }
        bool owned = disposition == REG_CREATED_NEW_KEY;

        // Recover interrupted fixture registrations only when their complete shape and association match.
        if (status == ERROR_SUCCESS && !owned)
        {
            DWORD subkeys = 0, values = 0;
            HKEY association = nullptr;
            if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr,
                    &values, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS && subkeys == 1 && !values &&
                RegOpenKeyExW(key, name, 0, KEY_READ, &association) == ERROR_SUCCESS)
            {
                wchar_t registered[40]{};
                DWORD type = 0, bytes = sizeof(registered);
                owned = RegQueryInfoKeyW(association, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr,
                            &values, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS && !subkeys && values == 1 &&
                    RegQueryValueExW(association, nullptr, nullptr, &type,
                        reinterpret_cast<BYTE*>(registered), &bytes) == ERROR_SUCCESS && type == REG_SZ &&
                    bytes == (wcslen(value) + 1) * sizeof(wchar_t) && !memcmp(registered, value, bytes);
                RegCloseKey(association);
            }
        }
        if (key) RegCloseKey(key);
        Require(status == ERROR_SUCCESS && owned,
            "COM fixture interface registration already exists or is unavailable");
        created[index] = true;
        auto written = RegCreateKeyExW(hive, (keys[index] + L"\\" + name).c_str(), 0, nullptr,
            REG_OPTION_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);
        if (written == ERROR_SUCCESS)
        {
            written = RegSetValueExW(key, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(value),
                static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t)));
            RegCloseKey(key);
        }
        Require(written == ERROR_SUCCESS, "Register asynchronous interface association", {{"status", written}});
    }
    Require(SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED)), "Initialize COM client");
    ComPtr<IPSFactoryBuffer> factory;
    Require(DllGetClassObject(IID_AsyncIDetouristRpcProbe, IID_PPV_ARGS(&factory)) == S_OK,
        "Create generated proxy factory");
    DWORD cookie = 0;
    Require(CoRegisterClassObject(IID_AsyncIDetouristRpcProbe, factory.Get(), CLSCTX_INPROC_SERVER,
        REGCLS_MULTIPLEUSE, &cookie) == S_OK &&
        CoRegisterPSClsid(IID_IDetouristRpcProbe, IID_AsyncIDetouristRpcProbe) == S_OK &&
        CoRegisterPSClsid(IID_AsyncIDetouristRpcProbe, IID_AsyncIDetouristRpcProbe) == S_OK,
        "Register process-local proxies");
    Detourist::Handle ready(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Detourist::Handle done(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Detourist::Handle gate(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Require(ready && done && gate, "Create COM coordination events");
    DcomGate = gate.get();
    IStream* stream = nullptr;
    HRESULT serverStatus = E_UNEXPECTED;
    std::thread server([&]()
    {
        serverStatus = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (SUCCEEDED(serverStatus))
        {
            ComPtr<IPSFactoryBuffer> serverFactory;
            DWORD serverCookie = 0;
            serverStatus = DllGetClassObject(IID_AsyncIDetouristRpcProbe, IID_PPV_ARGS(&serverFactory));
            if (SUCCEEDED(serverStatus)) serverStatus = CoRegisterClassObject(IID_AsyncIDetouristRpcProbe,
                serverFactory.Get(), CLSCTX_INPROC_SERVER, REGCLS_MULTIPLEUSE, &serverCookie);
            if (SUCCEEDED(serverStatus)) serverStatus = CoRegisterPSClsid(IID_IDetouristRpcProbe,
                IID_AsyncIDetouristRpcProbe);
            if (SUCCEEDED(serverStatus)) serverStatus = CoRegisterPSClsid(IID_AsyncIDetouristRpcProbe,
                IID_AsyncIDetouristRpcProbe);
            DcomProbe object;
            if (SUCCEEDED(serverStatus)) serverStatus = CoMarshalInterThreadInterfaceInStream(
                IID_IDetouristRpcProbe, &object, &stream);
            SetEvent(ready.get());
            HANDLE stop = done.get();
            while (MsgWaitForMultipleObjects(1, &stop, FALSE, 30000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
            {
                MSG message{};
                while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) DispatchMessageW(&message);
            }
            if (serverCookie) CoRevokeClassObject(serverCookie);
            serverFactory.Reset();
            CoUninitialize();
        }
        else SetEvent(ready.get());
    });
    HRESULT result = E_UNEXPECTED;
    const char* stage = "server";
    if (WaitForSingleObject(ready.get(), 10000) == WAIT_OBJECT_0 && SUCCEEDED(serverStatus))
    {
        ComPtr<IDetouristRpcProbe> proxy;
        stage = "unmarshal";
        result = CoGetInterfaceAndReleaseStream(stream, IID_PPV_ARGS(&proxy));
        ComPtr<ICallFactory> calls;
        if (SUCCEEDED(result)) { stage = "call factory"; result = proxy.As(&calls); }
        ComPtr<AsyncIDetouristRpcProbe> call;
        if (SUCCEEDED(result))
        {
            stage = "create call";
            result = calls->CreateCall(IID_AsyncIDetouristRpcProbe, nullptr,
                IID_AsyncIDetouristRpcProbe, reinterpret_cast<IUnknown**>(call.GetAddressOf()));
        }
        ComPtr<ISynchronize> synchronize;
        if (SUCCEEDED(result)) { stage = "synchronize"; result = call.As(&synchronize); }
        for (long number : {14L, -1L, 19L})
        {
            if (FAILED(result)) break;
            ResetEvent(gate.get());
            result = call->Begin_Value(number);
            if (SUCCEEDED(result) && SUCCEEDED(call->Begin_Value(99))) result = E_UNEXPECTED;
            SetEvent(gate.get());
            if (SUCCEEDED(result)) result = synchronize->Wait(0, 15000);
            long changed = 0xBAD;
            HRESULT finished = E_UNEXPECTED;
            if (SUCCEEDED(result))
            {
                std::thread completion([&]()
                {
                    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
                    finished = call->Finish_Value(&changed);
                    CoUninitialize();
                });
                completion.join();
                if (finished != (number < 0 ? E_ACCESSDENIED : S_OK) || number >= 0 && changed != number * 3)
                    result = E_UNEXPECTED;
            }
            printf("number=%ld result=%08lX finished=%08lX value=%ld\n", number, result, finished, changed);
            changed = 0xBAD;
            if (SUCCEEDED(result) && SUCCEEDED(call->Finish_Value(&changed))) result = E_UNEXPECTED;
        }
        if (SUCCEEDED(result))
        {
            stage = "mixed argument call";
            hyper total = 0;
            result = call->Begin_Mix(3.25, 0x123456789LL, 5, 7, 11, L"async-com");
            if (SUCCEEDED(result)) result = synchronize->Wait(0, 15000);
            if (SUCCEEDED(result)) result = call->Finish_Mix(&total);
            if (SUCCEEDED(result) && total != 0x1234567A0LL) result = E_UNEXPECTED;
        }
    }
    SetEvent(gate.get());
    SetEvent(done.get());
    server.join();
    CoRevokeClassObject(cookie);
    factory.Reset();
    CoUninitialize();
    Require(SUCCEEDED(result), "Async COM workload failed",
        {{"status", result}, {"server", serverStatus}, {"stage", stage}});
    std::puts("PASS: live asynchronous COM calls across apartments and completion threads.");
    return 0;
}

void Dcom(const Context& context)
{
    Require(RunTarget(context).contains("PASS:"), "Async COM baseline failed");
    for (bool instructions : {false, true})
    {
        Collector collector(context.collector, context.directory);
        auto database = Launch(collector, context, {.instructions = instructions});
        auto ended = collector.Wait([](const Json& state) { return state["finished"] == true; });
        Require(!ended["message"].get<std::string>().contains("nonzero exit code"), "Captured async COM failed", ended);
        Json details = Json::array();
        uint32_t begins = 0, finishes = 0, rejectedBegins = 0, failedFinishes = 0;
        uint32_t beginThread = 0;
        std::string receiver;
        std::vector<int32_t> returned;
        for (const auto& call : Calls(database, "COALESCE(d.name,a.name) LIKE '{b851663e-%'"))
        {
            auto value = collector.Call("details", {{"database", Text(database)},
                {"target", call["target"]}, {"callId", call["id"]}});
            details.push_back(value);
            const auto& rpc = value["rpc"];
            const auto flags = call["flags"].get<uint32_t>();
            const bool failed = flags & Detourist::Failed;
            const auto procedure = rpc["procedure"].get<uint32_t>();
            Require(!value.contains("rawArguments") && rpc["prefix"] == 0 &&
                (rpc["flags"].get<uint32_t>() &
                (Detourist::RpcDescriptorValid | Detourist::RpcPartial | Detourist::RpcObjectProcedure)) ==
                (Detourist::RpcDescriptorValid | Detourist::RpcObjectProcedure) &&
                !(flags & (Detourist::Unwound | Detourist::Continuation)),
                "Live async COM descriptor or call boundary was lost", value);
            if (receiver.empty()) receiver = value["arguments"][0].get<std::string>();
            Require(receiver == value["arguments"][0].get<std::string>(),
                "Reused COM call object changed identity", value);
            auto nodes = [&](const char* side, uint32_t argument, uint32_t type)
            {
                return Select(value[side], [&](const Json& node)
                {
                    return node["kind"] == 16 && node["parameter"] == argument && node["typeId"] == type;
                });
            };
            if (procedure & 1)
            {
                beginThread = call["tid"].get<uint32_t>();
                Require(rpc["operation"] == "Begin" && rpc["outputsDeferred"] == !failed,
                    "COM Begin completion state differs", value);
                if (failed) ++rejectedBegins;
                else ++begins;
                if (procedure == 3)
                {
                    const auto input = Read<int32_t>(Unhex(Only(nodes("input", 1, 6))["bytes"]));
                    Require(failed ? input == 99 : input == 14 || input == -1 || input == 19,
                        "COM Begin input differs", value);
                }
                else
                {
                    Require(procedure == 5 && !failed &&
                        Read<double>(Unhex(Only(nodes("input", 1, 10))["bytes"])) == 3.25 &&
                        Read<int64_t>(Unhex(Only(nodes("input", sizeof(void*) == 8 ? 2 : 3, 8))["bytes"])) ==
                            0x123456789LL &&
                        Read<int32_t>(Unhex(Only(nodes("input", sizeof(void*) == 8 ? 5 : 7, 6))["bytes"])) == 11,
                        "COM floating, 64-bit or stack arguments differ", value);
                    Require(Unhex(Only(nodes("input", sizeof(void*) == 8 ? 6 : 8, 12))["bytes"]) ==
                        Encode("async-com", true, true), "COM string input differs", value);
                }
            }
            else
            {
                Require(rpc["operation"] == "Finish" && rpc["outputsDeferred"] == false &&
                    nodes("input", 1, procedure == 4 ? 6 : 8).empty(),
                    "COM Finish inspected an uninitialized output", value);
                const auto output = nodes("output", 1, procedure == 4 ? 6 : 8);
                if (failed)
                {
                    ++failedFinishes;
                    Require(output.empty(), "Failed COM Finish exposed stale output", value);
                }
                else
                {
                    ++finishes;
                    if (procedure == 4)
                    {
                        Require(call["tid"] != beginThread, "COM Finish did not run on the completion thread", value);
                        returned.push_back(Read<int32_t>(Unhex(Only(output)["bytes"])));
                    }
                    else Require(procedure == 6 && Read<int64_t>(Unhex(Only(output)["bytes"])) == 0x1234567A0LL,
                        "COM Finish lost its 64-bit output", value);
                }
            }
        }
        WriteJson(context.directory / (instructions ? "dcom-instructions.json" : "dcom-typed.json"), details);
        Require(begins == 4 && finishes == 3 && rejectedBegins == 3 && failedFinishes == 4 &&
            returned == std::vector<int32_t>{42, 57}, "Live async COM capture counts or outputs differ",
            {{"begins", begins}, {"finishes", finishes}, {"rejected", rejectedBegins}, {"failed", failedFinishes}});
        if (context.Has(L"--inspector")) Inspect(context, context.Option(L"--inspector"), "--rpc", details);
        collector.Close();
    }
}

int wmain(int argc, wchar_t** argv)
{
    try { return Run<DcomTarget>(argc, argv, Dcom); }
    catch (const std::exception& error) { fprintf(stderr, "%s\n", error.what()); return 1; }
}

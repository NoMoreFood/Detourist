#include "TestSupport.h"
#include "Protocol.h"
#include "RpcLegacyFixture.h"

using namespace Detourist;
using namespace Detourist::Tests;

extern "C" int DetouristSehProbe(int abnormal);
extern "C" int (__cdecl* DetouristAbnormalTermination)(void);
extern "C" void* DetouristExceptHandler3;

extern "C" void* __RPC_USER midl_user_allocate(size_t bytes) { return malloc(bytes); }
extern "C" void __RPC_USER midl_user_free(void* memory) { free(memory); }
extern "C" long Server_DetouristRpcLegacyValues(handle_t, long value, hyper wide, wchar_t* text,
    long* changed, long* output)
{
    if (value != 0x41 || wide != 0x123456789abcdef0 || wcscmp(text, L"legacy-rpc") || *changed != 7) return -1;
    *changed = 25;
    *output = -17;
    return 0x2468;
}

Json LegacyRpc()
{
    // Compiler-generated Oi stubs marshal a wide stack argument and independent input/output pointers.
    auto endpoint = L"Detourist.RpcLegacy." + std::to_wstring(GetCurrentProcessId());
    auto protocol = reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc"));
    auto name = reinterpret_cast<RPC_WSTR>(endpoint.data());
    Require(!RpcServerUseProtseqEpW(protocol, RPC_C_PROTSEQ_MAX_REQS_DEFAULT, name, nullptr) &&
        !RpcServerRegisterIfEx(Server_DetouristRpcLegacy_v1_0_s_ifspec, nullptr, nullptr,
            RPC_IF_AUTOLISTEN | RPC_IF_ALLOW_LOCAL_ONLY, RPC_C_LISTEN_MAX_CALLS_DEFAULT, nullptr),
        "Register legacy RPC fixture");
    RPC_WSTR text = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;
    Require(!RpcStringBindingComposeW(nullptr, protocol, nullptr, name, nullptr, &text) &&
        !RpcBindingFromStringBindingW(text, &binding), "Bind legacy RPC fixture");
    RpcStringFreeW(&text);
    wchar_t message[] = L"legacy-rpc";
    long changed = 7, output = 0xBAD;
    auto result = Client_DetouristRpcLegacyValues(binding, 0x41, 0x123456789abcdef0, message, &changed, &output);
    RpcBindingFree(&binding);
    RpcServerUnregisterIf(Server_DetouristRpcLegacy_v1_0_s_ifspec, nullptr, TRUE);
    Require(result == 0x2468 && changed == 25 && output == -17, "Preserve legacy RPC results");
    return {{"result", result}, {"changed", changed}, {"output", output}};
}

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 2) return 1;
    try
    {
        // Runtime results establish native stack widths, integer returns and output-only scalar capture.
        Json calls = Json::array();
        auto resolve = [](HMODULE module, const char* name)
        {
            auto address = GetProcAddress(module, name);
            Require(address != nullptr, "Resolve x86 catalog export: " + std::string(name));
            return address;
        };
        auto sample = [&](const char* module, const char* name, uint32_t parameters, uint64_t result,
            uint64_t mask = UINT64_MAX)
        {
            calls.push_back({{"module", module}, {"name", name}, {"count", parameters}, {"result", result},
                {"mask", mask}, {"output", Json::array()}, {"absentInput", Json::array()}});
        };
        auto output = [&](uint32_t parameter, const void* data, size_t bytes)
        {
            const auto begin = static_cast<const BYTE*>(data);
            calls.back()["output"].push_back({{"parameter", parameter}, {"bytes", Bytes(begin, begin + bytes)}});
            calls.back()["absentInput"].push_back(parameter);
        };
        auto native = GetModuleHandleW(L"ntdll.dll");
        LARGE_INTEGER first{}, second{};
        first.QuadPart = 0x123456789abcdef;
        second.QuadPart = 0x123456789;
        auto add = reinterpret_cast<LARGE_INTEGER(WINAPI*)(LARGE_INTEGER, LARGE_INTEGER)>(
            resolve(native, "RtlLargeIntegerAdd"));
        auto total = add(first, second);
        Require(total.QuadPart == first.QuadPart + second.QuadPart, "Add native x86 large integers");
        sample("ntdll.dll", "RtlLargeIntegerAdd", 2, total.QuadPart);
        auto divide = reinterpret_cast<LARGE_INTEGER(WINAPI*)(LARGE_INTEGER, ULONG, PULONG)>(
            resolve(native, "RtlExtendedLargeIntegerDivide"));
        ULONG remainder = 0;
        auto quotient = divide(first, 97, &remainder);
        Require(quotient.QuadPart == first.QuadPart / 97 && remainder == first.QuadPart % 97,
            "Divide native x86 large integers");
        sample("ntdll.dll", "RtlExtendedLargeIntegerDivide", 3, quotient.QuadPart);
        output(2, &remainder, sizeof(remainder));
        auto shift = reinterpret_cast<LARGE_INTEGER(WINAPI*)(LARGE_INTEGER, CCHAR)>(
            resolve(native, "RtlLargeIntegerShiftRight"));
        auto shifted = shift(first, 9);
        Require(shifted.QuadPart == first.QuadPart >> 9, "Shift native x86 large integers");
        sample("ntdll.dll", "RtlLargeIntegerShiftRight", 2, shifted.QuadPart);
        auto swap = reinterpret_cast<ULONGLONG(WINAPI*)(ULONGLONG)>(resolve(native, "RtlUlonglongByteSwap"));
        auto swapped = swap(0x123456789abcdef0);
        Require(swapped == 0xf0debc9a78563412, "Swap a native x86 large integer");
        sample("ntdll.dll", "RtlUlonglongByteSwap", 1, swapped);
        auto swapShort = reinterpret_cast<USHORT(__fastcall*)(USHORT)>(resolve(native, "RtlUshortByteSwap"));
        auto shortResult = swapShort(0x1234);
        Require(shortResult == 0x3412, "Swap a native x86 fastcall short");
        sample("ntdll.dll", "RtlUshortByteSwap", 1, shortResult, UINT16_MAX);
        calls.back()["arguments"] = Json::array({0x1234});
        auto swapLong = reinterpret_cast<ULONG(__fastcall*)(ULONG)>(resolve(native, "RtlUlongByteSwap"));
        auto longResult = swapLong(0x12345678);
        Require(longResult == 0x78563412, "Swap a native x86 fastcall integer");
        sample("ntdll.dll", "RtlUlongByteSwap", 1, longResult, UINT32_MAX);
        calls.back()["arguments"] = Json::array({0x12345678});
        auto fill = reinterpret_cast<void(WINAPI*)(PVOID, SIZE_T, ULONGLONG)>(
            resolve(native, "RtlFillMemoryUlonglong"));
        ULONGLONG buffer[3]{};
        fill(buffer, sizeof(buffer), 0x123456789abcdef0);
        Require(std::ranges::all_of(buffer, [](auto value) { return value == 0x123456789abcdef0; }),
            "Fill native x86 output bytes");
        sample("ntdll.dll", "RtlFillMemoryUlonglong", 3, 0, 0);
        output(0, buffer, sizeof(buffer));

        // The CRT query leaves floating-point control state intact and returns two independent outputs.
        auto runtime = LoadLibraryExW(L"ucrtbase.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        Require(runtime != nullptr, "Load x86 CRT provider");
        auto control = reinterpret_cast<int(__cdecl*)(unsigned int, unsigned int, unsigned int*, unsigned int*)>(
            resolve(runtime, "__control87_2"));
        unsigned int x87 = 0, sse = 0;
        auto controlled = control(0, 0, &x87, &sse);
        Require(x87 && sse, "Read native x86 floating-point control words");
        sample("ucrtbase.dll", "__control87_2", 4, static_cast<uint32_t>(controlled), UINT32_MAX);
        output(2, &x87, sizeof(x87));
        output(3, &sse, sizeof(sse));
        FreeLibrary(runtime);

        // The legacy CRT helpers must observe the application's original SEH registration and EBP.
        auto legacy = LoadLibraryExW(L"msvcrt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        Require(legacy != nullptr, "Load x86 SEH provider");
        DetouristAbnormalTermination = reinterpret_cast<int(__cdecl*)(void)>(resolve(legacy, "_abnormal_termination"));
        DetouristExceptHandler3 = reinterpret_cast<void*>(resolve(legacy, "_except_handler3"));
        auto normal = DetouristSehProbe(0), abnormal = DetouristSehProbe(1);
        Require(normal == 0 && abnormal == 1, "Preserve normal and abnormal x86 termination state");
        FreeLibrary(legacy);
        WriteJson(arguments[1], {{"calls", calls}, {"seh", {normal, abnormal}}, {"rpc", LegacyRpc()}});
        return 0;
    }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}

void NativeCatalog(const Context& context)
{
    auto report = context.directory / L"x86-catalog.json";
    auto arguments = Quote(report);
    RunTarget(context, arguments);
    auto baseline = Report(report);
    for (bool instructions : {true, false})
    {
        Capture::Run(context, {.arguments = arguments, .limit = 64, .instructions = instructions}, [&](Capture& capture)
        {
            auto expected = Report(report);
            CompareCalls(baseline, expected, {"module", "name", "count", "result", "output"});
            Require(baseline["seh"] == expected["seh"], "Native x86 SEH behavior differs", expected);
            Require(baseline["rpc"] == expected["rpc"], "Native legacy RPC behavior differs", expected);
            auto rows = TargetCalls(context, capture.database);
            if (instructions)
            {
                for (const auto& sample : expected["calls"])
                {
                    auto matches = Select(rows, [&](const Json& row)
                    { return row["name"] == sample["name"] && row["module"] == sample["module"]; });
                    Require(matches.size() == 1, "Expected one native x86 call: " + sample["name"].get<std::string>(),
                        matches);
                    const auto& row = matches[0];
                    auto mask = sample["mask"].get<uint64_t>();
                    Require(row["argument_count"] == sample["count"] &&
                        !(row["flags"].get<uint32_t>() &
                            (Detourist::Failed | Detourist::Unwound | Detourist::Skipped)) &&
                        (Number(row["result"]) & mask) == sample["result"], "Native x86 ABI differs", row);
                    CheckLimit(row, 64);
                    if (sample.contains("arguments"))
                        for (size_t index = 0; index < sample["arguments"].size(); ++index)
                            Require(Read<uint64_t>(row["arguments"], index * sizeof(uint64_t)) ==
                                sample["arguments"][index], "Capture x86 register argument", row);
                    for (const auto& value : sample["output"])
                    {
                        auto region = Only(Regions(row["output"], {.parameter = value["parameter"]}));
                        Require(!region.flags && region.data == value["bytes"].get<Bytes>(),
                            "Native x86 output bytes differ", row);
                    }
                    for (const auto& parameter : sample["absentInput"])
                        Require(Regions(row["input"], {.parameter = parameter}).empty(),
                            "Native x86 output pointer was captured on entry", row);
                }
                auto termination = Select(rows, [](const Json& row) { return row["name"] == "_abnormal_termination"; });
                Require(termination.size() == 2 && Number(termination[0]["result"]) == 0 &&
                    Number(termination[1]["result"]) == 1, "Capture real x86 termination state", termination);
                auto handlers = Select(Calls(capture.database), [](const Json& row)
                { return row["name"] == "_except_handler3"; });
                Require(!handlers.empty() && std::ranges::all_of(handlers, [](const Json& row)
                { return row["argument_count"] == 4 && !(row["flags"].get<uint32_t>() & RawArguments); }),
                    "Capture real x86 SEH dispatch", handlers);
            }
            auto rpc = Only(capture.Find("NdrClientCall", "rpcrt4.dll"));
            auto values = Values(rpc["input"]);
            auto descriptor = std::ranges::find_if(values, [](const auto& value)
            { return value.kind == static_cast<uint32_t>(ValueKind::RpcCall); });
            Require(descriptor != values.end() && descriptor->data.size() == sizeof(RpcCallInfo),
                "Capture legacy RPC descriptor", rpc);
            auto info = Read<RpcCallInfo>(descriptor->data);
            Require(info.flags == RpcDescriptorValid && info.argumentCount == 9 && info.prefix == 2 &&
                Number(rpc["result"]) == 0x2468, "Decode legacy RPC stack and return", rpc);
            auto details = capture.Details(rpc);
            auto nodes = [&](const char* side, uint32_t parameter, RpcValueType type)
            {
                return Select(details[side], [&](const Json& value)
                { return value["kind"] == static_cast<uint32_t>(ValueKind::RpcValue) &&
                    value["parameter"] == parameter && value["typeId"] == static_cast<uint32_t>(type); });
            };
            Require(Read<int64_t>(Unhex(Only(nodes("input", 4, RpcValueType::Int64))["bytes"])) ==
                0x123456789abcdef0 &&
                Unhex(Only(nodes("input", 6, RpcValueType::Utf16))["bytes"]) == Encode("legacy-rpc", true, true) &&
                Read<long>(Unhex(Only(nodes("output", 7, RpcValueType::Int32))["bytes"])) == 25 &&
                Read<long>(Unhex(Only(nodes("output", 8, RpcValueType::Int32))["bytes"])) == -17 &&
                nodes("input", 8, RpcValueType::Int32).empty(), "Capture legacy RPC directions and values", details);
        }, 90);
    }
}

int wmain(int argc, wchar_t** argv) { return Run(argc, argv, NativeCatalog, TargetMain); }

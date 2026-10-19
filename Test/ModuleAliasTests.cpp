#include "SqliteCatalog.h"
#include "TestSupport.h"
#include "Protocol.h"
#include <sqlite3.h>
#include <array>

using namespace Detourist::Tests;

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 2 && count != 3) return 1;
    if (count == 3)
    {
        // Hold the private export loaded until initial attachment has completed its hook transaction.
        auto module = LoadLibraryW((Path(arguments[1]) / arguments[2] / L"d3dcompiler_47.dll").c_str());
        if (!module) return 9;
        const auto name = L"Local\\Detourist.PrivateHook." + std::to_wstring(GetCurrentProcessId());
        Detourist::Handle ready(CreateEventW(nullptr, TRUE, FALSE, (name + L".Ready").c_str()));
        Detourist::Handle gate(CreateEventW(nullptr, TRUE, FALSE, (name + L".Gate").c_str()));
        if (!ready || !gate || !SetEvent(ready.get()) || WaitForSingleObject(gate.get(), 30000) != WAIT_OBJECT_0)
            return 10;
        using Compile = HRESULT(WINAPI*)(const void*, SIZE_T, const char*, const void*, void*,
            const char*, const char*, UINT, UINT, void**, void**);
        auto call = reinterpret_cast<Compile>(GetProcAddress(module, "D3DCompile"));
        if (!call || call(nullptr, 0, nullptr, nullptr, nullptr, nullptr, nullptr, 0, 0, nullptr, nullptr) != E_FAIL)
            return 11;
        return FreeLibrary(module) ? 0 : 12;
    }
    const std::array crypto{L"libcrypto-3.dll", L"libcrypto-3-x64.dll", L"libcrypto-1_1.dll",
        L"libcrypto-1_1-x64.dll", L"libcrypto-30.dll"};
    const std::array ssl{L"libssl-3.dll", L"libssl-3-x64.dll", L"libssl-1_1.dll", L"libssl-1_1-x64.dll"};
    std::vector<HMODULE> loaded;
    auto load = [&](const wchar_t* name)
    {
        auto module = LoadLibraryW((Path(arguments[1]) / name).c_str());
        if (module) loaded.push_back(module);
        return module;
    };

    // Canonical and alias filenames run the same fixture without loading a third-party library.
    int value = 1;
    for (auto name : crypto)
    {
        auto module = load(name);
        auto call = module ? reinterpret_cast<int(__cdecl*)(const void*, const void*, size_t)>(
            GetProcAddress(module, "CRYPTO_memcmp")) : nullptr;
        if (!call || call(&value, &value, 7) != 37) return 2;
    }
    for (auto name : ssl)
    {
        auto module = load(name);
        auto call = module ? reinterpret_cast<const char*(__cdecl*)(const void*)>(
            GetProcAddress(module, "SSL_get_version")) : nullptr;
        if (!call || !call(&value)) return 3;
    }
#ifdef _WIN64
    // Earlier X3DAudio releases use the shorter emitter structure.
    for (auto name : {L"x3daudio1_0.dll", L"x3daudio1_7.dll"})
    {
        auto module = load(name);
        auto call = module ? reinterpret_cast<void(WINAPI*)(const void*, const void*, const void*, UINT32, void*)>(
            GetProcAddress(module, "X3DAudioCalculate")) : nullptr;
        std::array<unsigned char, 128> field{};
        if (!call) return 4;
        call(field.data(), field.data(), field.data(), 0, field.data());
    }
#endif
    for (auto name : {L"d3dcompiler_40.dll", L"d3dcompiler_47.dll"})
    {
        const bool privateCode = !wcscmp(name, L"d3dcompiler_47.dll");
        for (uint32_t pass = 0; pass < (privateCode ? 4u : 1u); ++pass)
        {
            auto path = privateCode ? Path(pass < 2 ? L"hotpatch" : L"private-entry") / name : Path(name);
            auto module = load(path.c_str());
            using Compile = HRESULT(WINAPI*)(const void*, SIZE_T, const char*, const void*, void*,
                const char*, const char*, UINT, UINT, void**, void**);
            auto call = module ? reinterpret_cast<Compile>(GetProcAddress(module, "D3DCompile")) : nullptr;
            if (!call ||
                call(nullptr, 0, nullptr, nullptr, nullptr, nullptr, nullptr, 0, 0, nullptr, nullptr) != E_FAIL)
                return 5;
            if (!privateCode) continue;

            // Both an image hotpatch and a private export entry must release their provider before reloading it.
            if (!FreeLibrary(module)) return 7;
            loaded.pop_back();
            if (GetModuleHandleW(name)) return 8;
        }
    }
    for (auto name : {L"d3dcsx_42.dll", L"d3dcsx_47.dll"})
    {
        auto module = load(name);
        using Create = HRESULT(WINAPI*)(void*, const void*, UINT, void*, void**);
        auto call = module ? reinterpret_cast<Create>(GetProcAddress(module, "D3DX11CreateFFT")) : nullptr;
        std::array<unsigned char, 140> description{};
        std::array<unsigned char, 40> buffers{};
        void* output = nullptr;
        if (!call || call(nullptr, description.data(), 0, buffers.data(), &output) != S_OK) return 6;
    }
    for (auto module : loaded) FreeLibrary(module);
    return 0;
}

void ModuleAliases(const Context& context)
{
    auto directory = context.directory / L"alias-fixtures";
    std::filesystem::create_directory(directory);
    for (auto name : {L"libcrypto-3.dll", L"libcrypto-3-x64.dll", L"libcrypto-1_1.dll",
        L"libcrypto-1_1-x64.dll", L"libcrypto-30.dll", L"libssl-3.dll", L"libssl-3-x64.dll",
        L"libssl-1_1.dll", L"libssl-1_1-x64.dll", L"x3daudio1_0.dll", L"x3daudio1_7.dll",
        L"d3dcompiler_40.dll", L"d3dcompiler_47.dll", L"d3dcsx_42.dll", L"d3dcsx_47.dll"})
        std::filesystem::copy_file(context.Extra(0), directory / name);
    for (auto mode : {L"hotpatch", L"private-entry"})
    {
        std::filesystem::create_directory(directory / mode);
        std::filesystem::copy_file(context.Extra(2), directory / mode / L"d3dcompiler_47.dll");
    }
    auto arguments = Quote(directory);
    Require(RunTarget(context, arguments).empty(), "Alias fixture baseline failed");

    // A per-module plan must win over its canonical alias in both observers.
    auto catalog = context.directory / L"alias-catalog.sqlite";
    std::filesystem::copy_file(context.Extra(1), catalog);
    sqlite3* raw = nullptr;
    Require(sqlite3_open16(catalog.c_str(), &raw) == SQLITE_OK, "Open the private alias catalog");
    Require(Detourist::SelectCatalogArchitecture(raw, sizeof(void*), true) == SQLITE_OK,
        "Select the alias catalog architecture");
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> owner(raw, sqlite3_close);
    const char* overrideSql = R"sql(
        INSERT INTO functions(module,name,result,signature,summary,variant)
            SELECT 'libcrypto-3-x64.dll',name,result,signature,summary,variant FROM functions
            WHERE module='libcrypto-3.dll' AND name='CRYPTO_memcmp';
        INSERT INTO plans SELECT (SELECT id FROM functions WHERE module='libcrypto-3-x64.dll'
            AND name='CRYPTO_memcmp'),kind,argument_count,argument_bytes,floating_arguments,result_bytes,
            floating_result,supported,interface_id_index,interface_output_index,return_buffer_bytes,4,
            interface_parameters,counted_result_bytes,capture_rules FROM plans WHERE function_id=
            (SELECT id FROM functions WHERE module='libcrypto-3.dll' AND name='CRYPTO_memcmp');
    )sql";
    Require(sqlite3_exec(raw, overrideSql, nullptr, nullptr, nullptr) == SQLITE_OK, "Create an exact alias override");
#ifndef _WIN64
    Require(sqlite3_exec(raw, "INSERT INTO function_abis SELECT (SELECT id FROM functions WHERE "
        "module='libcrypto-3-x64.dll' AND name='CRYPTO_memcmp'),convention FROM function_abis WHERE function_id="
        "(SELECT id FROM functions WHERE module='libcrypto-3.dll' AND name='CRYPTO_memcmp')", nullptr, nullptr,
        nullptr) == SQLITE_OK, "Create the x86 alias convention");
#endif
    owner.reset();
    Require(SetEnvironmentVariableW(L"DETOURIST_API_CATALOG", catalog.c_str()) &&
        SetEnvironmentVariableW(L"DETOURIST_API_CATALOG_X86", catalog.c_str()), "Select the private alias catalog");
    const bool instructions = context.Has(L"--instructions");
    for (auto mode : {L"hotpatch", L"private-entry"})
    {
        TargetProcess target(context, arguments + L" " + mode);
        const auto name = L"Local\\Detourist.PrivateHook." + std::to_wstring(target.Pid());
        Detourist::Handle ready;
        const auto deadline = GetTickCount64() + 10000;
        while (!ready && GetTickCount64() < deadline && target.Running())
        {
            ready.reset(OpenEventW(SYNCHRONIZE, FALSE, (name + L".Ready").c_str()));
            if (!ready) Sleep(10);
        }
        Require(ready && WaitForSingleObject(ready.get(), 10000) == WAIT_OBJECT_0,
            "Private hook provider was not loaded before attachment");
        Detourist::Handle gate(OpenEventW(EVENT_MODIFY_STATE, FALSE, (name + L".Gate").c_str()));
        auto& collector = context.GetCollector();
        const auto database = context.directory / (std::wstring(mode) + L"-attached.sqlite");
        collector.Call("attach", {{"pid", target.Pid()}, {"database", Text(database)},
            {"instructionEngine", instructions}});
        auto state = collector.Wait([](const Json& value)
        { return value["capturing"] == true || value["finished"] == true; });
        Require(state["capturing"] == true, "Private hook provider failed initial hook installation", state);
        const auto targets = collector.Call("page", {{"database", Text(database)}, {"limit", 1}})["targets"];
        Require(targets.size() == 1 && targets[0]["moduleRefreshError"] == 0,
            "Private hook provider failed initial discovery", targets);
        Require(gate && SetEvent(gate.get()), "Release preloaded private hook provider");
        collector.Wait([](const Json& value) { return value["finished"] == true; });
        Require(target.Wait() == 0, "Attached private hook provider changed target behavior");
        auto call = Only(Calls(database, "COALESCE(d.name,a.name)='D3DCompile'"));
        Require(call["argument_count"] == 11 && call["result"] == 0x80004005u,
            "Attached private hook provider lost its call contract", call);
        Require(Query(database, "SELECT * FROM coverage WHERE module_error<>0").empty() &&
            Query(database, "SELECT * FROM diagnostics").empty(), "Private hook attachment reported a diagnostic");
    }
    Capture::Run(context, {.arguments = arguments, .instructions = instructions}, [&](Capture& capture)
    {
        // Exact aliases retain the physical module and the canonical argument contract.
        for (auto module : {"libcrypto-3.dll", "libcrypto-3-x64.dll", "libcrypto-1_1.dll",
            "libcrypto-1_1-x64.dll"})
        {
            auto call = Only(capture.Find("CRYPTO_memcmp", module));
            Require(call["argument_count"] == 3 && Read<uint64_t>(call["arguments"], 16) == 7 &&
                call["result"] == 37 && bool(call["flags"].get<uint32_t>() & 1) ==
                    (std::string_view(module) == "libcrypto-3-x64.dll"),
                "An exact crypto alias lost its call contract or override", call);
        }
        for (auto module : {"libssl-3.dll", "libssl-3-x64.dll", "libssl-1_1.dll", "libssl-1_1-x64.dll"})
        {
            auto call = Only(capture.Find("SSL_get_version", module));
            Require(call["argument_count"] == 1 && call["result"] != 0,
                "An exact SSL alias lost its call contract", call);
        }
        for (const auto& unrelated : capture.Find("CRYPTO_memcmp", "libcrypto-30.dll"))
            Require(instructions && (unrelated["flags"].get<uint32_t>() & Detourist::RawArguments),
                "An unrelated module matched an OpenSSL alias", unrelated);
#ifdef _WIN64
        for (const auto& [module, bytes] : {std::pair{"x3daudio1_0.dll", size_t{120}},
            std::pair{"x3daudio1_7.dll", size_t{128}}})
        {
            auto call = Only(capture.Find("X3DAudioCalculate", module));
            auto emitter = Only(Regions(call["input"], {.parameter = 2}));
            Require(emitter.data.size() == bytes, "The X3DAudio version override was not preserved", call);
        }
#endif
        for (auto module : {"d3dcompiler_40.dll", "d3dcompiler_47.dll"})
        {
            auto calls = capture.Find("D3DCompile", module);
            Require(calls.size() == (std::string_view(module) == "d3dcompiler_47.dll" ? 4u : 1u),
                "A private hook target lost calls across module lifetimes", calls);
            for (const auto& call : calls)
            {
                Require(call["argument_count"] == 11 && call["result"] == 0x80004005u && !call["ended"].is_null(),
                    "A versioned shader compiler call was not captured", call);
                for (uint32_t index = 0; index < 11; ++index)
                    Require(Read<uint64_t>(call["arguments"], index * sizeof(uint64_t)) == 0,
                        "A private hook target changed an argument", call);
            }
        }
        for (auto module : {"d3dcsx_42.dll", "d3dcsx_47.dll"})
        {
            auto call = Only(capture.Find("D3DX11CreateFFT", module));
            Require(call["argument_count"] == 5 && call["result"] == 0 &&
                Only(Regions(call["input"], {.parameter = 1})).data.size() == 140,
                "A versioned FFT call was not captured", call);
        }
        // Count loader publications independently of baseline polling snapshots.
        auto lifetimes = Query(capture.database, "SELECT path,loaded,count(*) count FROM modules "
            "WHERE epoch>0 AND path LIKE '%\\d3dcompiler_47.dll' GROUP BY path,loaded");
        Require(lifetimes.size() == 4, "Private hook providers lost a module lifetime", lifetimes);
        for (const auto& lifetime : lifetimes)
            Require(lifetime["count"] == 2, "A private hook provider did not unload and reload", lifetime);
        Require(Query(capture.database, "SELECT * FROM coverage WHERE module_error<>0").empty(),
            "Private executable hook targets caused incomplete module discovery");
        capture.CheckDiagnostics();
    });
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ModuleAliases); }

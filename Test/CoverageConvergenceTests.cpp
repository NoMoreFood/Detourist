#include "TestSupport.h"
#include "GuardedPages.h"

// ODBC and WAB declare unrelated bookmark types.
#define BOOKMARK OdbcBookmark
#include <sqlext.h>
#include <odbcinst.h>
#undef BOOKMARK
#include <Ratings.h>

using namespace Detourist;
using namespace Detourist::Tests;

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 2) return 1;
    try
    {
        // All fixture files live in the harness's isolated temporary directory.
        auto report = Path(arguments[1]), directory = report.parent_path();
        auto profile = directory / L"coverage-\u6f22\u5b57.dsn";
        std::wstring profileText = L"\ufeff[ODBC]\r\nFirst=Alpha-\u6f22\u5b57\r\nSecond=Beta\r\n";
        {
            std::ofstream file(profile, std::ios::binary);
            file.write(reinterpret_cast<const char*>(profileText.data()),
                static_cast<std::streamsize>(profileText.size() * sizeof(wchar_t)));
            Require(bool(file), "Create temporary Unicode profile");
        }
        Check(SetEnvironmentVariableW(L"COMPLUS_Version", L"v4.0.30319"), "Select local hashing runtime");
        using Library = std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)>;
        Library odbc(LoadLibraryExW(L"odbc32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32), FreeLibrary);
        Library installer(LoadLibraryExW(L"odbccp32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32), FreeLibrary);
        Library runtime(LoadLibraryExW(L"mscoree.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32), FreeLibrary);
        Require(odbc && installer && runtime, "Load coverage providers");
        auto resolve = [](HMODULE module, const char* name)
        {
            auto address = GetProcAddress(module, name);
            Require(address != nullptr, "Resolve coverage export: " + std::string(name));
            return address;
        };
        auto connect = reinterpret_cast<decltype(&SQLConnectA)>(resolve(odbc.get(), "SQLConnectA"));
        auto diagnostic = reinterpret_cast<decltype(&SQLGetDiagRecA)>(resolve(odbc.get(), "SQLGetDiagRecA"));
        auto drivers = reinterpret_cast<decltype(&SQLGetInstalledDriversW)>(
            resolve(installer.get(), "SQLGetInstalledDriversW"));
        auto readProfile = reinterpret_cast<decltype(&SQLGetPrivateProfileStringW)>(
            resolve(installer.get(), "SQLGetPrivateProfileStringW"));
        auto readDsn = reinterpret_cast<decltype(&SQLReadFileDSNW)>(resolve(installer.get(), "SQLReadFileDSNW"));
        auto installerError = reinterpret_cast<decltype(&SQLInstallerErrorW)>(
            resolve(installer.get(), "SQLInstallerErrorW"));

        // Output buffers end at an inaccessible page so incorrect byte extents become observable.
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        auto pages = GuardedPages(system.dwPageSize, PAGE_NOACCESS);
        auto end = reinterpret_cast<BYTE*>(pages.get()) + system.dwPageSize;
        auto output = [&](size_t bytes)
        {
            Require(bytes <= system.dwPageSize, "Fit bounded coverage buffer");
            memset(end - bytes, 0xcc, bytes);
            return end - bytes;
        };
        auto snapshot = [](uint32_t parameter, uint32_t kind, const void* data, size_t bytes, size_t minimum = 0)
        {
            auto first = static_cast<const BYTE*>(data);
            return Json{{"parameter", parameter}, {"kind", kind}, {"data", Bytes(first, first + bytes)},
                {"minimum", minimum ? minimum : bytes}};
        };
        auto wide = [&](uint32_t parameter, const wchar_t* text)
        {
            return snapshot(parameter, 1, text, (wcslen(text) + 1) * sizeof(wchar_t));
        };
        auto sample = [](const char* name, const char* names, const char* module, uint32_t parameters,
            uint32_t result, bool failed)
        {
            return Json{{"name", name}, {"names", names}, {"module", module}, {"count", parameters},
                {"result", result}, {"failed", failed}, {"input", Json::array()}, {"output", Json::array()},
                {"absentInput", Json::array()}, {"matchParameter", -1}};
        };
        Json calls = Json::array();

        // Null ODBC handles reject the calls before any driver, connection, or external service can be used.
        SQLCHAR server[] = "Convergence server", user[] = "Convergence user", authentication[] = "fixture";
        auto connected = connect(SQL_NULL_HDBC, server, sizeof(server) - 1, user, sizeof(user) - 1,
            authentication, sizeof(authentication) - 1);
        Require(connected == SQL_INVALID_HANDLE, "Reject an invalid ODBC connection handle");
        auto item = sample("SQLConnectA", "SQLConnectA?", "odbc32.dll", 7,
            static_cast<uint16_t>(connected), true);
        item["resultMask"] = 0xffff;
        item["input"] = {snapshot(1, 0, server, sizeof(server) - 1), snapshot(3, 0, user, sizeof(user) - 1),
            snapshot(5, 0, authentication, sizeof(authentication) - 1)};
        calls.push_back(std::move(item));
        SQLCHAR state[6]{}, message[32]{};
        SQLINTEGER nativeError = 0x12345678;
        SQLSMALLINT messageLength = 0x1234;
        auto diagnosed = diagnostic(SQL_HANDLE_DBC, SQL_NULL_HANDLE, 1, state, &nativeError, message,
            sizeof(message), &messageLength);
        Require(diagnosed == SQL_INVALID_HANDLE && nativeError == 0x12345678 && messageLength == 0x1234,
            "Preserve invalid-handle diagnostic buffers");
        item = sample("SQLGetDiagRecA", "SQLGetDiagRecA?", "odbc32.dll", 8,
            static_cast<uint16_t>(diagnosed), true);
        item["resultMask"] = 0xffff;
        item["absentInput"] = {3, 5, 7};
        calls.push_back(std::move(item));

        // SQL_NO_DATA clears the message without establishing a diagnostic record or output lengths.
        auto errorMessage = reinterpret_cast<wchar_t*>(output(8 * sizeof(wchar_t)));
        DWORD errorCode = 0x12345678;
        WORD errorLength = 0x1234;
        auto errorResult = installerError(USHRT_MAX, &errorCode, errorMessage, 8, &errorLength);
        Require(errorResult == SQL_NO_DATA && errorCode == 0x12345678 && errorLength == 0x1234 &&
            !errorMessage[0] && std::all_of(errorMessage + 1, errorMessage + 8,
                [](wchar_t value) { return value == 0xcccc; }), "Reject a missing installer diagnostic record");
        item = sample("SQLInstallerErrorW", "SQLInstallerErrorW", "odbccp32.dll", 5, errorResult, true);
        item["resultMask"] = 0xffff;
        item["matchParameter"] = 0;
        item["matchValue"] = USHRT_MAX;
        item["absentInput"] = {1, 2, 4};
        calls.push_back(std::move(item));

        // Installed driver names exercise bounded MULTISZ output without changing driver configuration.
        for (WORD capacity : {WORD{8}, WORD{1024}})
        {
            auto buffer = reinterpret_cast<wchar_t*>(output(capacity * sizeof(wchar_t)));
            WORD length = 0;
            auto result = drivers(buffer, capacity, &length);
            Require(result && length < capacity, "Enumerate installed ODBC drivers");
            item = sample("SQLGetInstalledDriversW", "SQLGetInstalledDriversW", "odbccp32.dll", 3, result, false);
            item["matchParameter"] = 1;
            item["matchValue"] = capacity;
            item["absentInput"] = {0, 2};
            item["output"] = {snapshot(0, 1, buffer, capacity * sizeof(wchar_t), (length + 1) * sizeof(wchar_t)),
                snapshot(2, 2, &length, sizeof(length))};
            calls.push_back(std::move(item));
        }

        // Unicode defaults and temporary file contents cover full and truncated UTF-16 reads.
        const wchar_t* section = L"Detourist coverage", *entry = L"Missing";
        const wchar_t* fallback = L"Convergence-\u6f22\u5b57-default";
        for (int capacity : {8, 64})
        {
            auto buffer = reinterpret_cast<wchar_t*>(output(capacity * sizeof(wchar_t)));
            auto result = readProfile(section, entry, fallback, buffer, capacity, profile.c_str());
            Require(result == std::min<int>(static_cast<int>(wcslen(fallback)), capacity - 1) &&
                std::wstring_view(buffer) == std::wstring_view(fallback).substr(0, result),
                "Read bounded Unicode profile default");
            item = sample("SQLGetPrivateProfileStringW", "SQLGetPrivateProfileStringW", "odbccp32.dll", 6,
                result, false);
            item["matchParameter"] = 4;
            item["matchValue"] = capacity;
            item["input"] = {wide(0, section), wide(1, entry), wide(2, fallback), wide(5, profile.c_str())};
            item["absentInput"] = {3};
            item["output"] = Json::array({snapshot(3, 1, buffer, capacity * sizeof(wchar_t),
                (result + 1) * sizeof(wchar_t))});
            calls.push_back(std::move(item));
        }
        for (WORD capacity : {WORD{8}, WORD{64}})
        {
            auto buffer = reinterpret_cast<wchar_t*>(output(capacity * sizeof(wchar_t)));
            WORD length = 0;
            auto result = readDsn(profile.c_str(), L"ODBC", L"First", buffer, capacity, &length);
            Require(bool(result) == (capacity == 64) && length == 8 &&
                std::wstring_view(buffer) == std::wstring_view(L"Alpha-\u6f22\u5b57").substr(0, capacity - 1),
                "Read bounded Unicode file DSN");
            item = sample("SQLReadFileDSNW", "SQLReadFileDSNW", "odbccp32.dll", 6, result, !result);
            item["matchParameter"] = 4;
            item["matchValue"] = capacity;
            item["input"] = {wide(0, profile.c_str()), wide(1, L"ODBC"), wide(2, L"First")};
            item["absentInput"] = {3, 5};
            if (result)
                item["output"] = {snapshot(3, 1, buffer, capacity * sizeof(wchar_t),
                    (length + 1) * sizeof(wchar_t)), snapshot(5, 2, &length, sizeof(length))};
            calls.push_back(std::move(item));
        }

        // Legacy hashing reads a temporary Unicode-path assembly and preserves native provider failures.
        wchar_t windows[MAX_PATH]{};
        Check(GetWindowsDirectoryW(windows, MAX_PATH) != 0, "Find managed hashing fixture");
        auto framework = Path(windows) / L"Microsoft.NET" /
            (sizeof(void*) == 8 ? L"Framework64" : L"Framework") / L"v4.0.30319" / L"mscorlib.dll";
        auto assembly = directory / L"assembly-\u6f22\u5b57.dll";
        std::filesystem::copy_file(framework, assembly, std::filesystem::copy_options::overwrite_existing);
        using Hash = HRESULT(WINAPI*)(LPCWSTR, unsigned int*, BYTE*, DWORD, DWORD*);
        for (auto name : {"GetHashFromFileW", "GetHashFromAssemblyFileW"})
        {
            auto hash = reinterpret_cast<Hash>(resolve(runtime.get(), name));
            auto buffer = output(64);
            unsigned int algorithm = 0;
            DWORD length = 0;
            auto result = hash(assembly.c_str(), &algorithm, buffer, 64, &length);
            Require(FAILED(result) || length > 0 && length <= 64, "Bound native hash output");
            item = sample(name, name, "mscoree.dll", 5, result, FAILED(result));
            unsigned int initialAlgorithm = 0;
            item["input"] = {wide(0, assembly.c_str()), snapshot(1, 2, &initialAlgorithm, sizeof(initialAlgorithm))};
            item["absentInput"] = {2, 4};

            // The initialized algorithm is in/out even when the provider cannot produce a hash.
            item["output"] = Json::array({snapshot(1, 2, &algorithm, sizeof(algorithm))});
            if (SUCCEEDED(result))
            {
                item["output"].push_back(snapshot(2, 0, buffer, length));
                item["output"].push_back(snapshot(4, 2, &length, sizeof(length)));
            }
            else
                std::printf("Native %s returned 0x%08lx.\n", name, static_cast<unsigned long>(result));
            calls.push_back(std::move(item));
        }

        // Explicit resolution of the environment alias retains its pointer result and zero-argument ABI.
        auto environment = reinterpret_cast<LPCH(WINAPI*)()>(
            resolve(GetModuleHandleW(L"kernel32.dll"), "GetEnvironmentStringsA"));
        auto block = environment();
        Require(block != nullptr, "Read process environment alias");
        item = sample("GetEnvironmentStringsA", "GetEnvironmentStringsA", "kernel32.dll", 0, 0, false);
        item["pointerResult"] = reinterpret_cast<uint64_t>(block);
        calls.push_back(std::move(item));
        Check(FreeEnvironmentStringsA(block), "Free process environment block");

#ifdef _WIN64
        // Named imports retain each API's Unicode contract at a shared failure stub.
        Library ratings(LoadLibraryExW(L"msrating.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32), FreeLibrary);
        Require(ratings != nullptr, "Load rating provider");
        wchar_t ratingsPath[MAX_PATH]{};
        Check(GetModuleFileNameW(ratings.get(), ratingsPath, MAX_PATH) != 0, "Locate rating provider");
        Image ratingsImage(ratingsPath);
        auto ratingsExports = ratingsImage.Exports();
        auto rating = [&](const char* name, uint32_t parameters, Json input, Json absent, auto invoke,
            Json outputs = Json::array())
        {
            auto rva = ratingsExports.at(name).at("rva").get<uint32_t>();
            const BYTE stub[]{0xb8, 0x01, 0x40, 0x00, 0x80, 0xc3};
            auto offset = ratingsImage.Offset(rva);
            if (offset + sizeof(stub) > ratingsImage.bytes.size() ||
                memcmp(ratingsImage.bytes.data() + offset, stub, sizeof(stub))) return;
            auto result = invoke();
            Require(result == E_NOTIMPL, "Preserve the rating provider's failure result");
            auto rated = sample(name, name, "msrating.dll", parameters, static_cast<uint32_t>(result), true);
            rated["input"] = std::move(input);
            rated["output"] = std::move(outputs);
            rated["absentInput"] = std::move(absent);
            calls.push_back(std::move(rated));
        };
        const wchar_t username[] = L"Rating user-\u6f22\u5b57", url[] = L"https://example.invalid/\u6f22\u5b57";
        const wchar_t content[] = L"Rating content-\u6f22\u5b57";
        BYTE data[]{0x51, 0x52, 0x53, 0x54};
        void* details = reinterpret_cast<void*>(0x1234);
        HANDLE query = reinterpret_cast<HANDLE>(0x5678);
        rating("RatingAccessDeniedDialogW", 4, {wide(1, username), wide(2, content)}, {3}, [&]
        {
            return RatingAccessDeniedDialogW(nullptr, username, content, &details);
        });
        rating("RatingAccessDeniedDialog2W", 3, Json::array({wide(1, username)}), {2}, [&]
        {
            return RatingAccessDeniedDialog2W(nullptr, username, &details);
        });
        rating("RatingCheckUserAccessW", 6,
            {wide(0, username), wide(1, url), wide(2, content), snapshot(3, 0, data, sizeof(data))}, {5}, [&]
        {
            return RatingCheckUserAccessW(username, url, content, data, sizeof(data), &details);
        });
        rating("RatingEnableW", 3, Json::array({wide(1, username)}), Json::array(), [&]
        {
            return RatingEnableW(nullptr, username, FALSE);
        });
        rating("RatingSetupUIW", 2, Json::array({wide(1, username)}), Json::array(), [&]
        {
            return RatingSetupUIW(nullptr, username);
        });
        rating("RatingObtainQueryW", 4, Json::array({wide(0, url)}), {3}, [&]
        {
            return RatingObtainQueryW(url, 0x12345678u, nullptr, &query);
        });
        rating("RatingAddToApprovedSites", 7, {snapshot(2, 0, data, sizeof(data)), wide(3, url)}, Json::array(), [&]
        {
            return RatingAddToApprovedSites(nullptr, sizeof(data), data, url, FALSE, FALSE, FALSE);
        }, Json::array({snapshot(2, 0, data, sizeof(data))}));
        rating("RatingInit", 0, Json::array(), Json::array(), [] { return RatingInit(); });
        Require(details == reinterpret_cast<void*>(0x1234) && query == reinterpret_cast<HANDLE>(0x5678),
            "Failed rating calls changed output pointers");
#endif
        WriteJson(report, {{"calls", calls}});
        return 0;
    }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}

void Convergence(const Context& context)
{
    // Compare real workload results with and without capture before validating serialized parameter values.
    auto report = context.directory / L"coverage.json";
    auto arguments = Quote(report);
    std::cout << RunTarget(context, arguments, 60000);
    auto baseline = Report(report);
    for (uint32_t limit : {16u, 512u})
    {
        Capture::Run(context, {.arguments = arguments, .limit = limit}, [&](Capture& capture)
        {
            auto expected = Report(report);
            CompareCalls(baseline, expected, {"name", "result", "failed", "input", "output"});
            auto rows = TargetCalls(context, capture.database);
            for (const auto& sample : expected["calls"])
            {
                auto matches = Matching(rows, sample["names"], sample["module"]);
                int parameter = sample["matchParameter"];
                if (parameter >= 0)
                    matches = Select(matches, [&](const Json& row)
                    {
                        return Read<uint64_t>(row["arguments"], parameter * 8) == sample["matchValue"];
                    });
                // Tail-forwarded aliases retain the caller address; validate the originating call once.
                auto forwarded = matches;
                matches = Select(matches, [&](const Json& row)
                {
                    return std::ranges::none_of(forwarded,
                        [&](const Json& other) { return other["id"] == row["parent"]; });
                });
                Require(matches.size() == 1, "Expected one typed coverage call: " + sample["name"].get<std::string>(),
                    matches);
                const auto& row = matches[0];
                Require(row["argument_count"] == sample["count"] &&
                    Data(row["arguments"]).size() == sample["count"].get<size_t>() * 8 &&
                    !(row["flags"].get<uint32_t>() & 256), "Coverage alias lost its callable contract", row);
                auto mask = sample.value("resultMask", UINT32_MAX);
                Require(sample.contains("pointerResult") ? Number(row["result"]) == sample["pointerResult"] :
                    (Number(row["result"]) & mask) == sample["result"], "Captured native result differs", row);
                Require(bool(row["flags"].get<uint32_t>() & 1) == sample["failed"],
                    "Coverage result failure classification differs", row);

                // Payloads must preserve encoding, direction, returned lengths, and both caller and capture limits.
                CheckLimit(row, limit);
                for (auto phase : {"input", "output"})
                {
                    for (const auto& value : sample[phase])
                    {
                        auto region = Only(Regions(row[phase], {.parameter = value["parameter"]}));
                        auto bytes = value["data"].get<Bytes>();
                        auto minimum = std::min<size_t>(value["minimum"].get<size_t>(), limit);
                        Require(region.kind == value["kind"] && !(region.flags & 2) &&
                            region.data.size() >= minimum &&
                            region.data.size() <= std::min<size_t>(bytes.size(), limit) &&
                            region.data == Prefix(bytes, region.data.size()),
                            "Coverage parameter bytes or bounds differ", row);
                        if (value["minimum"].get<size_t>() > limit)
                            Require(region.flags & 1, "Capped coverage parameter lacks truncation flag", row);
                    }
                }
                for (const auto& absent : sample["absentInput"])
                    Require(Regions(row["input"], {.parameter = absent}).empty(),
                        "Output-only coverage parameter was captured on entry", row);
                if (sample["failed"] == true)
                    Require(Values(row["output"]).size() == sample["output"].size(),
                        "Failed coverage call exposed undefined output values", row);
            }
        }, 90);
    }
}

int wmain(int argc, wchar_t** argv) { return Run(argc, argv, Convergence, TargetMain); }

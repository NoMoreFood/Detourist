#include "TestSupport.h"

#if defined(DETOURIST_TEST_DetouristProviderComTests)

using namespace Detourist::Tests;
using Microsoft::WRL::ComPtr;
using Module = std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)>;

bool CombaseWorkload(HMODULE module)
{
    auto context = reinterpret_cast<decltype(&CoGetObjectContext)>(GetProcAddress(module, "CoGetObjectContext"));
    auto token = reinterpret_cast<decltype(&CoGetContextToken)>(GetProcAddress(module, "CoGetContextToken"));
    auto apartment = reinterpret_cast<decltype(&CoGetApartmentType)>(GetProcAddress(module, "CoGetApartmentType"));
    auto guid = reinterpret_cast<decltype(&CoCreateGuid)>(GetProcAddress(module, "CoCreateGuid"));
    if (!context || !token || !apartment || !guid) return false;

    // Direct combase exports expose an apartment interface before its first derived method call.
    ComPtr<IComThreadingInfo> threading;
    ULONG_PTR value = 0;
    GUID identity{};
    APTTYPE type = APTTYPE_CURRENT;
    APTTYPEQUALIFIER qualifier = APTTYPEQUALIFIER_NONE;
    if (FAILED(context(IID_PPV_ARGS(&threading))) || !threading || FAILED(token(&value)) || !value ||
        FAILED(apartment(&type, &qualifier)) || type != APTTYPE_MTA || FAILED(guid(&identity)) ||
        identity == GUID{}) return false;
    THDTYPE thread = THDTYPE_PROCESSMESSAGES;
    return SUCCEEDED(threading->GetCurrentApartmentType(&type)) && type == APTTYPE_MTA &&
        SUCCEEDED(threading->GetCurrentThreadType(&thread)) && thread == THDTYPE_BLOCKMESSAGES;
}

bool CaptureEngineWorkload(HMODULE module)
{
    auto create = reinterpret_cast<HRESULT(WINAPI*)(IMFCaptureEngine**)>(
        GetProcAddress(module, "MFCreateCaptureEngine"));
    if (!create) return false;

    // Engines without selected devices exercise factory and source slots without initializing capture.
    ComPtr<IMFCaptureEngine> engine;
    ComPtr<IMFCaptureSource> source;
    auto result = create(&engine);
    std::printf("Create engine: %08lX\n", static_cast<unsigned long>(result));
    if (FAILED(result) || !engine) return false;
    auto sourceResult = engine->GetSource(&source);
    if (FAILED(sourceResult) || !source) return false;
    DWORD streams = 0xFFFFFFFF;
    result = source->GetDeviceStreamCount(&streams);
    std::printf("Streams: %08lX %lu\n", static_cast<unsigned long>(result), streams);
    if (SUCCEEDED(result) || streams != 0xFFFFFFFF) return false;
    ComPtr<IMFCaptureEngineClassFactory> factory;
    ComPtr<IMFCaptureEngine> created;
    result = CoCreateInstance(CLSID_MFCaptureEngineClassFactory, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&factory));
    std::printf("Create factory: %08lX\n", static_cast<unsigned long>(result));
    if (FAILED(result) || !factory) return false;
    result = factory->CreateInstance(CLSID_MFCaptureEngine, IID_PPV_ARGS(&created));
    std::printf("Create instance: %08lX\n", static_cast<unsigned long>(result));
    return SUCCEEDED(result) && created && SUCCEEDED(created->GetSource(source.ReleaseAndGetAddressOf())) && source;
}

bool AddressBookWorkload(HMODULE module)
{
    auto open = reinterpret_cast<LPWABOPEN>(GetProcAddress(module, "WABOpen"));
    auto extended = reinterpret_cast<LPWABOPENEX>(GetProcAddress(module, "WABOpenEx"));
    if (!open || !extended) return false;
    for (int mode = 0; mode < 2; ++mode)
    {
        WAB_PARAM options{};
        options.cbSize = sizeof(options);
        ComPtr<IAddrBook> book;
        ComPtr<IWABObject> object;
        auto result = mode ? extended(&book, &object, &options, 0, nullptr, nullptr, nullptr) :
            open(&book, &object, &options, 0);
        if (FAILED(result) || !book || !object) return false;

        // Allocations retain their parent ownership; no contacts or address-book settings are changed.
        void* allocation = nullptr;
        void* child = nullptr;
        if (FAILED(object->AllocateBuffer(32, &allocation)) || !allocation ||
            FAILED(object->AllocateMore(16, allocation, &child)) || !child) return false;
        memset(allocation, 0x5A, 32);
        memset(child, 0xA5, 16);
        if (FAILED(object->FreeBuffer(allocation))) return false;
        MAPIERROR* error = nullptr;
        result = object->GetLastError(E_INVALIDARG, 0, &error);
        std::printf("GetLastError: %08lX\n", static_cast<unsigned long>(result));
        if (error && FAILED(object->FreeBuffer(error))) return false;
    }
    return true;
}

bool ComputeWorkload(HMODULE module)
{
    auto scan = reinterpret_cast<decltype(&D3DX11CreateScan)>(GetProcAddress(module, "D3DX11CreateScan"));
    auto segmented = reinterpret_cast<decltype(&D3DX11CreateSegmentedScan)>(
        GetProcAddress(module, "D3DX11CreateSegmentedScan"));
    auto transform = reinterpret_cast<decltype(&D3DX11CreateFFT1DComplex)>(
        GetProcAddress(module, "D3DX11CreateFFT1DComplex"));
    if (!scan || !segmented || !transform) return false;

    // The software device makes scan and FFT factories independent of installed graphics hardware.
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0;
    if (FAILED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, &level, 1,
        D3D11_SDK_VERSION, &device, nullptr, &context))) return false;
    ComPtr<ID3DX11Scan> scanner;
    ComPtr<ID3DX11SegmentedScan> segments;
    ComPtr<ID3DX11FFT> fft;
    D3DX11_FFT_BUFFER_INFO buffers{};
    if (FAILED(scan(context.Get(), 32, 1, &scanner)) || !scanner ||
        FAILED(segmented(context.Get(), 32, &segments)) || !segments ||
        FAILED(transform(context.Get(), 16, D3DX11_FFT_CREATE_FLAG_NO_PRECOMPUTE_BUFFERS, &buffers, &fft)) ||
        !fft || !buffers.NumTempBufferSizes) return false;
    return SUCCEEDED(scanner->SetScanDirection(D3DX11_SCAN_DIRECTION_BACKWARD)) &&
        SUCCEEDED(segments->SetScanDirection(D3DX11_SCAN_DIRECTION_FORWARD)) &&
        SUCCEEDED(fft->SetForwardScale(0.25f)) && fft->GetForwardScale() == 0.25f &&
        SUCCEEDED(fft->SetInverseScale(0.5f)) && fft->GetInverseScale() == 0.5f;
}

#ifdef DETOURIST_TEST_D3DX
constexpr std::array<unsigned char, 64> CallbackData = []
{
    std::array<unsigned char, 64> value{};
    for (size_t index = 0; index < value.size(); ++index) value[index] = static_cast<unsigned char>(index + 1);
    return value;
}();

struct CallbackState
{
    std::atomic<unsigned> calls = 0;
    std::atomic<bool> worker = false;
    DWORD thread = GetCurrentThreadId();
    unsigned result = 0x13579BDF;
};

class WorkLoader final : public ID3DX11DataLoader
{
public:
    explicit WorkLoader(CallbackState& state) : state_(state) {}
    HRESULT STDMETHODCALLTYPE Load() override
    {
        state_.calls.fetch_or(1);
        if (GetCurrentThreadId() != state_.thread) state_.worker.store(true);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Decompress(void** data, SIZE_T* bytes) override
    {
        state_.calls.fetch_or(2);
        *data = const_cast<unsigned char*>(CallbackData.data());
        *bytes = CallbackData.size();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Destroy() override { state_.calls.fetch_or(4); return S_OK; }
private:
    CallbackState& state_;
};

class WorkProcessor final : public ID3DX11DataProcessor
{
public:
    explicit WorkProcessor(CallbackState& state) : state_(state) {}
    HRESULT STDMETHODCALLTYPE Process(void* data, SIZE_T bytes) override
    {
        state_.calls.fetch_or(8);
        return bytes == CallbackData.size() && !memcmp(data, CallbackData.data(), bytes) ? S_OK : E_INVALIDARG;
    }
    HRESULT STDMETHODCALLTYPE CreateDeviceObject(void** object) override
    {
        state_.calls.fetch_or(16);
        *object = &state_.result;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Destroy() override { state_.calls.fetch_or(32); return S_OK; }
private:
    CallbackState& state_;
};

bool D3dxWorkload(HMODULE module)
{
    auto pumpFactory = reinterpret_cast<decltype(&D3DX11CreateThreadPump)>(
        GetProcAddress(module, "D3DX11CreateThreadPump"));
    auto loaderFactory = reinterpret_cast<decltype(&D3DX11CreateAsyncMemoryLoader)>(
        GetProcAddress(module, "D3DX11CreateAsyncMemoryLoader"));
    auto processorFactory = reinterpret_cast<decltype(&D3DX11CreateAsyncShaderPreprocessProcessor)>(
        GetProcAddress(module, "D3DX11CreateAsyncShaderPreprocessProcessor"));
    if (!pumpFactory || !loaderFactory || !processorFactory) return false;

    // Application-owned plain vtables enter the provider through typed work-item inputs.
    CallbackState state;
    WorkLoader loader(state);
    WorkProcessor processor(state);
    ComPtr<ID3DX11ThreadPump> pump;
    if (FAILED(pumpFactory(1, 1, &pump)) || !pump) return false;
    HRESULT status = E_PENDING;
    void* object = nullptr;
    UINT io = 1, process = 1, device = 1;
    if (FAILED(pump->GetQueueStatus(&io, &process, &device)) || io || process || device ||
        FAILED(pump->AddWorkItem(&loader, &processor, &status, &object)) ||
        FAILED(pump->WaitForAllItems()) || FAILED(status) || object != &state.result ||
        state.calls.load() != 63 || !state.worker.load() || pump->GetWorkItemCount() ||
        FAILED(pump->ProcessDeviceWorkItems(1)) || FAILED(pump->PurgeAllItems())) return false;

    // Provider-owned callback objects must be discovered from their factories without a consumer boundary.
    ID3DX11DataLoader* memory = nullptr;
    if (FAILED(loaderFactory(CallbackData.data(), CallbackData.size(), &memory)) || !memory) return false;
    void* data = nullptr;
    SIZE_T bytes = 0;
    if (FAILED(memory->Load()) || FAILED(memory->Decompress(&data, &bytes)) ||
        bytes != CallbackData.size() || !data || memcmp(data, CallbackData.data(), bytes) ||
        FAILED(memory->Destroy())) return false;
    ComPtr<ID3DBlob> text, errors;
    ID3DX11DataProcessor* preprocess = nullptr;
    if (FAILED(processorFactory("fixture.hlsl", nullptr, nullptr, &text, &errors, &preprocess)) || !preprocess)
        return false;
    char source[] = "#define VALUE 7\nVALUE\n";
    void* compiled = nullptr;
    if (FAILED(preprocess->Process(source, strlen(source))) ||
        FAILED(preprocess->CreateDeviceObject(&compiled)) || !text || !text->GetBufferSize() ||
        FAILED(preprocess->Destroy())) return false;
    return true;
}
#endif

int TargetMain(int count, wchar_t** arguments)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    if (count != 3 && count != 4) return 1;
    if (count == 4)
    {
        FILE* report = nullptr;
        if (_wfreopen_s(&report, arguments[3], L"w", stdout)) return 2;
    }
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return 3;
    bool valid = false;
    {
        Module module(LoadLibraryW(arguments[2]), &FreeLibrary);
        if (!module)
        {
            // Missing optional providers are unavailable; an installed provider that fails to load is a regression.
            const auto error = GetLastError();
            wchar_t resolved[32768]{};
            const bool present = GetFileAttributesW(arguments[2]) != INVALID_FILE_ATTRIBUTES ||
                SearchPathW(nullptr, arguments[2], nullptr, static_cast<DWORD>(std::size(resolved)),
                    resolved, nullptr) != 0;
            std::printf("Provider load failed: %lu\n", error);
            return !present && (error == ERROR_MOD_NOT_FOUND || error == ERROR_FILE_NOT_FOUND) ? 77 : 4;
        }
        if (!wcscmp(arguments[1], L"combase")) valid = CombaseWorkload(module.get());
        else if (!wcscmp(arguments[1], L"capture")) valid = CaptureEngineWorkload(module.get());
        else if (!wcscmp(arguments[1], L"wab")) valid = AddressBookWorkload(module.get());
        else if (!wcscmp(arguments[1], L"compute")) valid = ComputeWorkload(module.get());
#ifdef DETOURIST_TEST_D3DX
        else if (!wcscmp(arguments[1], L"d3dx")) valid = D3dxWorkload(module.get());
#endif
    }
    CoUninitialize();
    std::puts(valid ? "PASS: provider exports, derived methods and callback lifetimes." : "FAIL: provider workload.");
    return valid ? 0 : 4;
}


void ProviderCom(const Context& context)
{
    // Factory exports and their derived interfaces must be discovered through the installed provider.
    std::map<std::string, std::vector<std::string>> required{
        {"combase", {"CoGetObjectContext", "CoGetContextToken", "CoGetApartmentType", "CoCreateGuid",
                        "IComThreadingInfo::GetCurrentApartmentType", "IComThreadingInfo::GetCurrentThreadType"}},
        {"capture", {"MFCreateCaptureEngine", "IMFCaptureEngine::GetSource",
                        "IMFCaptureEngineClassFactory::CreateInstance", "IMFCaptureSource::GetDeviceStreamCount"}},
        {"wab", {"WABOpen", "WABOpenEx", "IWABObject::AllocateBuffer", "IWABObject::AllocateMore",
                    "IWABObject::FreeBuffer", "IWABObject::GetLastError"}},
        {"compute", {"D3DX11CreateScan", "D3DX11CreateSegmentedScan", "D3DX11CreateFFT1DComplex",
                        "ID3DX11Scan::SetScanDirection", "ID3DX11SegmentedScan::SetScanDirection",
                        "ID3DX11FFT::SetForwardScale", "ID3DX11FFT::GetForwardScale", "ID3DX11FFT::SetInverseScale",
                        "ID3DX11FFT::GetInverseScale"}},
        {"d3dx", {"D3DX11CreateThreadPump", "D3DX11CreateAsyncMemoryLoader",
                     "D3DX11CreateAsyncShaderPreprocessProcessor", "ID3DX11ThreadPump::AddWorkItem",
                     "ID3DX11ThreadPump::GetWorkItemCount", "ID3DX11ThreadPump::GetQueueStatus",
                     "ID3DX11ThreadPump::WaitForAllItems", "ID3DX11ThreadPump::ProcessDeviceWorkItems",
                     "ID3DX11ThreadPump::PurgeAllItems", "ID3DX11DataLoader::Load", "ID3DX11DataLoader::Decompress",
                     "ID3DX11DataLoader::Destroy", "ID3DX11DataProcessor::Process",
                     "ID3DX11DataProcessor::CreateDeviceObject", "ID3DX11DataProcessor::Destroy"}}};
    auto mode = Text(context.Extra(0));
    auto provider = context.Extra(1);
    if (provider == L"wab32.dll")
    {
        wchar_t common[32768]{};
        Require(GetEnvironmentVariableW(L"CommonProgramFiles", common, static_cast<DWORD>(std::size(common))) != 0,
            "CommonProgramFiles is unavailable");
        provider = Path(common) / L"System" / provider;
    }
    auto arguments = Detourist::Wide(mode) + L" " + Quote(provider);
    RunTarget(context, arguments, 30000);
    std::vector<std::pair<uint32_t, bool>> cases{{16, false}, {16, true}};
    if (mode != "combase" && mode != "capture") cases.insert(cases.begin() + 1, {64, false});
    for (auto [limit, comOnly] : cases)
    {
        auto report = context.directory / L"provider.txt";
        Capture::Run(context, {.arguments = arguments + L" " + Quote(report), .limit = limit,
            .instructions = false, .comOnly = comOnly}, [&](Capture& capture)
        {
            Require(ReadLog(report).contains("PASS:"), "Provider fixture failed");
            auto rows = capture.Calls();
            std::map<std::string, Json> groups;
            auto module = Text(provider.filename());
            std::ranges::transform(
                module, module.begin(), [](unsigned char c) { return static_cast<char>(tolower(c)); });
            for (const auto& name : required.at(mode))
            {
                auto calls = Named(rows, name);
                groups[name] = calls;
                bool method = name.contains("::");
                Require(!calls.empty() || (!method && comOnly), "Provider API missing: " + name);
                Require(!comOnly || method || calls.empty(), "COM-only capture included a provider export: " + name);
                for (const auto& row : calls)
                {
                    // Forwarded SDK contracts may name the importing DLL while resolving to this provider.
                    bool sameExport = method || row["module"] == module;
                    if (!sameExport)
                    {
                        Module requested(LoadLibraryW(provider.c_str()), &FreeLibrary);
                        Module resolved(LoadLibraryExW(Detourist::Wide(row["module"]).c_str(), nullptr,
                            LOAD_LIBRARY_SEARCH_SYSTEM32), &FreeLibrary);
                        auto address = requested ? GetProcAddress(requested.get(), name.c_str()) : nullptr;
                        sameExport = address && resolved && address == GetProcAddress(resolved.get(), name.c_str());
                    }
                    Require(!(row["flags"].get<uint32_t>() & (4 | 256)) && sameExport,
                        "Provider call contract differs", row);
                    CheckLimit(row, limit);
                    if (mode == "capture")
                        Require(bool(row["flags"].get<uint32_t>() & 1) == name.ends_with("GetDeviceStreamCount"),
                            "Capture provider failure classification differs", row);
                }
            }
            capture.CheckDiagnostics(true);
            if (mode == "compute")
            {
                for (const auto& row : groups["D3DX11CreateFFT1DComplex"])
                    Require(
                        Regions(row["input"], {.parameter = 1}).empty(), "FFT scalar length was read as a descriptor");
                for (auto [name, value] : {std::pair{"GetForwardScale", 0.25f}, {"GetInverseScale", 0.5f}})
                    Require(
                        groups["ID3DX11FFT::" + std::string(name)].back()["result"] == std::bit_cast<uint32_t>(value),
                        "FFT scalar return differs");
            }
            if (mode == "d3dx")
            {
                for (auto name : {"ID3DX11DataLoader::Load", "ID3DX11DataLoader::Decompress",
                         "ID3DX11DataProcessor::Process", "ID3DX11DataProcessor::CreateDeviceObject"})
                    Require(groups[name].size() >= 2, "D3DX worker callbacks missing");
                Bytes bytes(limit);
                for (size_t index = 0; index < bytes.size(); ++index) bytes[index] = uint8_t(index + 1);
                for (auto [name, phase] :
                    {std::pair{"ID3DX11DataLoader::Decompress", "output"}, {"ID3DX11DataProcessor::Process", "input"}})
                    Require(std::ranges::any_of(groups[name], [&](const Json& row)
                    {
                        return std::ranges::any_of(Regions(row[phase], {.parameter = 1}), [&](const Value& value)
                        { return value.original == 64 && value.data == bytes; });
                    }), "D3DX worker bytes differ");
                auto main = groups["ID3DX11ThreadPump::AddWorkItem"][0]["tid"];
                Require(std::ranges::any_of(groups["ID3DX11DataLoader::Load"], [&](const Json& row)
                { return row["tid"] != main; }), "D3DX work did not run on a worker thread");
            }
        }, 60);
    }
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ProviderCom); }

#elif defined(DETOURIST_TEST_DetouristShellSdkTests)

using namespace Detourist::Tests;
using Microsoft::WRL::ComPtr;
using ItemId = std::remove_pointer_t<PIDLIST_ABSOLUTE>;

bool MatchesPath(IShellItem* item, const wchar_t* path)
{
    PWSTR value = nullptr;
    auto result = item->GetDisplayName(SIGDN_FILESYSPATH, &value);
    std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> name(value, &CoTaskMemFree);
    return SUCCEEDED(result) && name && !_wcsicmp(name.get(), path);
}

bool ShellItems(const wchar_t* path)
{
    // The executable's shell imports are resolved before capture starts.
    ComPtr<IShellItem2> item;
    if (FAILED(SHCreateItemFromParsingName(path, nullptr, IID_PPV_ARGS(&item))) || !MatchesPath(item.Get(), path))
        return false;
    SFGAOF attributes = 0;
    ULONGLONG size = 0;
    if (FAILED(item->GetAttributes(SFGAO_FILESYSTEM, &attributes)) || !(attributes & SFGAO_FILESYSTEM) ||
        FAILED(item->GetUInt64(PKEY_Size, &size)) || size != 64) return false;

    // Each factory's output is used immediately, before an input boundary can reveal its identity.
    ComPtr<IShellItem> parent, relative;
    auto leaf = wcsrchr(path, L'\\');
    if (!leaf || FAILED(item->GetParent(&parent)) ||
        FAILED(SHCreateItemFromRelativeName(parent.Get(), leaf + 1, nullptr, IID_PPV_ARGS(&relative))) ||
        !MatchesPath(relative.Get(), path)) return false;
    int order = 1;
    if (FAILED(relative->Compare(item.Get(), SICHINT_CANONICAL, &order)) || order) return false;
    PIDLIST_ABSOLUTE raw = nullptr;
    auto result = SHGetIDListFromObject(item.Get(), &raw);
    std::unique_ptr<ItemId, decltype(&CoTaskMemFree)> identity(raw, &CoTaskMemFree);
    if (FAILED(result) || !identity) return false;
    ComPtr<IShellItem> fromId;
    if (FAILED(SHCreateItemFromIDList(identity.get(), IID_PPV_ARGS(&fromId))) || !MatchesPath(fromId.Get(), path))
        return false;
    raw = nullptr;
    result = SHParseDisplayName(path, nullptr, &raw, SFGAO_FILESYSTEM, &attributes);
    std::unique_ptr<ItemId, decltype(&CoTaskMemFree)> parsed(raw, &CoTaskMemFree);
    if (FAILED(result) || !parsed || !(attributes & SFGAO_FILESYSTEM)) return false;

    // Array and enumerator outputs retain their declared element contracts.
    PCIDLIST_ABSOLUTE ids[]{identity.get(), parsed.get()};
    ComPtr<IShellItemArray> array;
    DWORD count = 0;
    if (FAILED(SHCreateShellItemArrayFromIDLists(2, ids, &array)) ||
        FAILED(array->GetCount(&count)) || count != 2) return false;
    ComPtr<IShellItem> selected;
    if (FAILED(array->GetItemAt(1, &selected)) || !MatchesPath(selected.Get(), path) ||
        FAILED(array->GetAttributes(SIATTRIBFLAGS_AND, SFGAO_FILESYSTEM, &attributes)) ||
        !(attributes & SFGAO_FILESYSTEM)) return false;
    ComPtr<IEnumShellItems> enumerator;
    ComPtr<IShellItem> first, second;
    ULONG fetched = 0;
    if (FAILED(array->EnumItems(&enumerator)) || enumerator->Next(1, &first, &fetched) != S_OK || fetched != 1 ||
        !MatchesPath(first.Get(), path) || enumerator->Next(1, &second, &fetched) != S_OK || fetched != 1 ||
        !MatchesPath(second.Get(), path)) return false;
    ComPtr<IShellItemArray> singleton;
    if (FAILED(SHCreateShellItemArrayFromShellItem(item.Get(), IID_PPV_ARGS(&singleton))) ||
        FAILED(singleton->GetCount(&count)) || count != 1) return false;

    // Failed queries must preserve the provider's HRESULT and clear output.
    constexpr IID unknown{0x61d27523, 0x4135, 0x4efb, {0x96, 0x60, 0x4b, 0x91, 0x27, 0xe5, 0x41, 0x7e}};
    void* unsupported = reinterpret_cast<void*>(1);
    return SHCreateItemFromIDList(identity.get(), unknown, &unsupported) == E_NOINTERFACE && !unsupported;
}

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 2 || FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return 1;
    std::wstring path(GetLongPathNameW(arguments[1], nullptr, 0), L'\0');
    auto length = path.empty() ? 0 : GetLongPathNameW(arguments[1], path.data(), static_cast<DWORD>(path.size()));
    auto success = length && length < path.size() && ShellItems(path.c_str());
    CoUninitialize();
    std::puts(success ? "PASS: direct shell imports and returned interfaces." : "FAIL: shell items.");
    return success ? 0 : 2;
}

void ShellItem(const Context& context)
{
    // Real shell items preserve imported factory identities and their first derived interface methods.
    auto path = context.directory / L"capture-\u0394.txt";
    {
        std::ofstream file(path, std::ios::binary);
        for (char value = 0; value < 64; ++value)
            file.put(value);
        Require(bool(file), "Cannot create shell item fixture");
    }
    RunTarget(context, Quote(path), 30000);
    std::vector<std::string> exports{"SHCreateItemFromParsingName",
                                     "SHCreateItemFromRelativeName",
                                     "SHGetIDListFromObject",
                                     "SHCreateItemFromIDList",
                                     "SHParseDisplayName",
                                     "SHCreateShellItemArrayFromIDLists",
                                     "SHCreateShellItemArrayFromShellItem"};
    std::vector<std::string> methods{"IShellItem::GetDisplayName", "IShellItem::GetAttributes",
                                     "IShellItem::GetParent",      "IShellItem::Compare",
                                     "IShellItem2::GetUInt64",     "IShellItemArray::GetCount",
                                     "IShellItemArray::GetItemAt", "IShellItemArray::GetAttributes",
                                     "IShellItemArray::EnumItems", "IEnumShellItems::Next"};
    const std::string provider = "shell32.dll";
    for (auto [limit, comOnly] : {std::pair{16u, false}, {64u, false}, {16u, true}})
    {
        Capture::Run(context, {.arguments = Quote(path), .limit = limit, .instructions = false, .comOnly = comOnly},
                     [&](Capture& capture)
        {
            auto rows = TargetCalls(context, capture.database);
            std::map<std::string, Json> groups;
            auto names = exports;
            names.insert(names.end(), methods.begin(), methods.end());
            for (const auto& name : names)
            {
                auto calls = Named(rows, name);
                if (name.starts_with("IShellItem::"))
                    for (const auto& row : Named(rows, "IShellItem2::" + name.substr(12)))
                        calls.push_back(row);
                groups[name] = calls;
                bool exported = std::ranges::find(exports, name) != exports.end();
                Require(!calls.empty() || (exported && comOnly), "Shell item API missing: " + name);
                if (exported) Require(!calls.empty() != comOnly, "Shell item export mask differs: " + name);
                for (const auto& row : calls)
                {
                    Require(!(row["flags"].get<uint32_t>() & (4 | 256)) && (!exported || row["module"] == provider),
                            "Shell item contract differs", row);
                    CheckLimit(row, limit);
                }
            }
            Require(groups["IShellItem::GetDisplayName"].size() == 6 && groups["IEnumShellItems::Next"].size() == 2 &&
                        groups["IShellItemArray::GetCount"].size() == 2 && groups["IShellItem2::GetUInt64"].size() == 1,
                    "Shell item method counts differ");
            auto sizes = Regions(groups["IShellItem2::GetUInt64"][0]["output"], {.parameter = 2});
            Require(std::ranges::any_of(sizes, [](const Value& value)
            { return value.original == 8 && value.data == Integer(64); }),
                    "Shell item file size differs");
            for (size_t index = 0; index < 2; ++index)
            {
                auto values = Regions(groups["IShellItemArray::GetCount"][index]["output"], {.parameter = 1});
                Require(!values.empty() && values[0].data == Integer(2 - index, 4), "Shell item array count differs");
            }
            if (!comOnly)
            {
                auto failures = groups["SHCreateItemFromIDList"];
                Require(failures.size() == 2 && !(failures[0]["flags"].get<uint32_t>() & 1) &&
                            (failures[1]["flags"].get<uint32_t>() & 1) && failures[1]["result"] == 0x80004002u &&
                            Data(failures[1]["output"]).empty(),
                        "Shell item failure differs");
            }
            capture.CheckDiagnostics(true);
        }, 60);
    }
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ShellItem); }

#else
#error Select a native test target.
#endif

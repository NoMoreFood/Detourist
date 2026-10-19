#include "TestSupport.h"

using namespace Detourist::Tests;

nlohmann::json dialog;

std::string Utf8(const wchar_t* text)
{
    auto count = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    std::string result(count, '\0');
    if (count) WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), count, nullptr, nullptr);
    if (!result.empty()) result.pop_back();
    return result;
}

void ReadAccessible(IAccessible* accessible, unsigned depth = 0)
{
    if (depth >= 12 || dialog["accessible"].size() >= 256) return;
    VARIANT self{};
    self.vt = VT_I4;
    BSTR name = nullptr;
    if (SUCCEEDED(accessible->get_accName(self, &name)) && name)
        dialog["accessible"].push_back(Utf8(name));
    SysFreeString(name);
    long count = 0, copied = 0;
    accessible->get_accChildCount(&count);
    VARIANT children[64]{};
    AccessibleChildren(accessible, 0, (std::min)(count, 64l), children, &copied);
    for (long index = 0; index < copied; ++index)
    {
        if (children[index].vt == VT_DISPATCH)
        {
            Microsoft::WRL::ComPtr<IAccessible> child;
            if (SUCCEEDED(children[index].pdispVal->QueryInterface(IID_PPV_ARGS(&child))))
                ReadAccessible(child.Get(), depth + 1);
        }
        else
        {
            name = nullptr;
            if (SUCCEEDED(accessible->get_accName(children[index], &name)) && name)
                dialog["accessible"].push_back(Utf8(name));
            SysFreeString(name);
        }
        VariantClear(&children[index]);
    }
}

void CALLBACK InspectDialog(HWND window, UINT, UINT_PTR timer, DWORD)
{
    // Read accessibility after activation completes so providers can process their window messages.
    KillTimer(window, timer);
    wchar_t title[256]{};
    GetWindowTextW(window, title, 256);
    dialog["title"] = Utf8(title);
    dialog["children"] = nlohmann::json::array();
    dialog["accessible"] = nlohmann::json::array();
    EnumChildWindows(window, [](HWND child, LPARAM)
    {
        wchar_t text[2048]{}, type[128]{};
        GetWindowTextW(child, text, 2048);
        GetClassNameW(child, type, 128);
        dialog["children"].push_back({{"class", Utf8(type)}, {"text", Utf8(text)}});
        Microsoft::WRL::ComPtr<IAccessible> accessible;
        if (!wcscmp(type, L"DirectUIHWND") &&
            SUCCEEDED(AccessibleObjectFromWindow(child, OBJID_CLIENT, IID_PPV_ARGS(&accessible))))
            ReadAccessible(accessible.Get());
        return TRUE;
    }, 0);
    PostMessageW(window, WM_COMMAND, IDOK, 0);
}

LRESULT CALLBACK ObserveDialog(int code, WPARAM first, LPARAM second)
{
    // Inspect and dismiss only dialogs created by this thread on its private desktop.
    if (code == HCBT_ACTIVATE)
    {
        const auto window = reinterpret_cast<HWND>(first);
        wchar_t type[32]{};
        GetClassNameW(window, type, 32);
        if (!wcscmp(type, L"#32770")) SetTimer(window, 0xD370, 1, InspectDialog);
    }
    return CallNextHookEx(nullptr, code, first, second);
}

template<size_t... Index>
int ShowMessage(FARPROC address, HINSTANCE instance, const void* format, const void* title,
    const std::array<uint64_t, 32>& arguments, std::index_sequence<Index...>)
{
    return reinterpret_cast<int (__cdecl *)(HINSTANCE, HWND, const void*, const void*, UINT, ...)>(address)(
        instance, nullptr, format, title, MB_OK, arguments[Index]...);
}

struct GuardedBytes
{
    void* allocation = nullptr;
    ~GuardedBytes() { if (allocation) VirtualFree(allocation, 0, MEM_RELEASE); }
};

int RunMessages(HDESK desktop, const nlohmann::json& cases, std::ofstream& report)
{
    if (!SetThreadDesktop(desktop)) return 2;
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 2;
    const auto initialLanguage = GetThreadUILanguage();
    const auto hook = SetWindowsHookExW(WH_CBT, ObserveDialog, nullptr, GetCurrentThreadId());
    const auto shlwapi = LoadLibraryExW(L"shlwapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    const auto shell32 = LoadLibraryExW(L"shell32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hook || !shlwapi || !shell32) return 3;

    // Every supplied string ends at a protected page, including unterminated precision-bounded inputs.
    for (const auto& item : cases)
    {
        const auto wide = item["wide"].get<bool>();
        const auto function = wide ? "ShellMessageBoxW" : "ShellMessageBoxA";
        const auto library = item.value("module", "shlwapi.dll") == "shell32.dll" ? shell32 : shlwapi;
        const auto address = GetProcAddress(library, function);
        if (!address) return 3;
        std::array<uint64_t, 32> arguments{};
        std::array<GuardedBytes, 32> storage;
        size_t index = 0;
        for (const auto& argument : item["arguments"])
        {
            if (index >= arguments.size()) return 6;
            if (argument.is_number_unsigned() || argument.is_number_integer())
                arguments[index] = argument.get<uint64_t>();
            else
            {
                const auto bytes = argument["bytes"].get<std::string>();
                if (bytes.size() % 2 || bytes.size() > 8192) return 6;
                auto allocation = VirtualAlloc(nullptr, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                DWORD old = 0;
                if (!allocation || !VirtualProtect(static_cast<char*>(allocation) + 4096, 4096, PAGE_NOACCESS, &old))
                    return 6;
                storage[index].allocation = allocation;
                auto data = static_cast<char*>(allocation) + 4096 - bytes.size() / 2;
                for (size_t offset = 0; offset < bytes.size(); offset += 2)
                    data[offset / 2] = static_cast<char>(std::stoul(bytes.substr(offset, 2), nullptr, 16));
                arguments[index] = reinterpret_cast<uint64_t>(data);

                // Counted inserts pass a descriptor at the page start that bounds the guarded payload.
                if (argument.contains("length"))
                {
                    auto descriptor = static_cast<UNICODE_STRING*>(allocation);
                    descriptor->Length = argument["length"].get<USHORT>();
                    descriptor->MaximumLength = argument["maximum"].get<USHORT>();
                    descriptor->Buffer = reinterpret_cast<PWSTR>(data);
                    arguments[index] = reinterpret_cast<uint64_t>(descriptor);
                }
            }
            ++index;
        }
        // Language choices are confined to this worker; optional modules exercise image and data-file mappings.
        SetThreadUILanguage(initialLanguage);
        ULONG languages = 0;
        std::wstring preferred;
        for (const auto& language : item.value("languages", nlohmann::json::array()))
        {
            const auto name = language.get<std::string>();
            preferred.append(name.begin(), name.end());
            preferred.push_back(0);
        }
        preferred.push_back(0);
        if (!SetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, preferred.c_str(), &languages)) return 7;
        if (item.contains("languageId")) SetThreadUILanguage(item["languageId"].get<LANGID>());
        auto instance = GetModuleHandleW(nullptr);
        HMODULE resourceModule = nullptr;
        if (item.contains("resourceModule"))
        {
            const auto path = std::filesystem::u8path(item["resourceModule"].get<std::string>());
            resourceModule = LoadLibraryExW(path.c_str(), nullptr, item.value("loadFlags", 0u));
            if (!resourceModule) return 8;
            instance = resourceModule;
        }
        if (item.value("nullModule", false)) instance = nullptr;
        const auto format = item.value("format", "");
        const std::wstring unicode(format.begin(), format.end());
        const auto resource = item.value("resource", 0);
        const void* pattern = resource ? MAKEINTRESOURCEW(resource) :
            wide ? static_cast<const void*>(unicode.c_str()) : format.c_str();
        if (item.value("null", false)) pattern = nullptr;
        const void* title = resource && !item.value("nullModule", false) ?
            MAKEINTRESOURCEW(item.value("titleResource", 302)) :
            wide ? static_cast<const void*>(L"Detourist shell capture") : "Detourist shell capture";
        dialog = {{"id", item["id"]}, {"function", function}, {"format", format},
            {"wide", wide}, {"arguments", arguments}, {"address", reinterpret_cast<uint64_t>(pattern)},
            {"codePage", GetACP()}, {"resourceModule", reinterpret_cast<uint64_t>(instance)}};
        SetLastError(0x1357);
        dialog["result"] = ShowMessage(address, instance, pattern, title, arguments, std::make_index_sequence<32>{});
        dialog["lastError"] = GetLastError();
        dialog["languageId"] = GetThreadUILanguage();
        ULONG characters = 0;
        GetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, &languages, nullptr, &characters);
        std::wstring languageNames(characters, 0);
        if (!GetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, &languages, languageNames.data(), &characters))
            return 9;
        dialog["languages"] = nlohmann::json::array();
        for (size_t offset = 0; offset < languageNames.size() && languageNames[offset];)
        {
            dialog["languages"].push_back(Utf8(languageNames.c_str() + offset));
            offset += wcslen(languageNames.c_str() + offset) + 1;
        }
        if (resourceModule) FreeLibrary(resourceModule);
        report << dialog.dump() << '\n' << std::flush;
    }
    UnhookWindowsHookEx(hook);
    FreeLibrary(shell32);
    FreeLibrary(shlwapi);
    CoUninitialize();
    return report ? 0 : 5;
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 3) return 1;
    std::ifstream config{std::filesystem::path(argv[1])};
    std::ofstream report{std::filesystem::path(argv[2])};
    if (!config || !report) return 1;
    const auto cases = nlohmann::json::parse(config);
    const auto name = L"Detourist.ShellMessages." + std::to_wstring(GetCurrentProcessId());
    const auto desktop = CreateDesktopW(name.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    if (!desktop) return 2;
    int result = 0;
    std::thread worker([&]() { result = RunMessages(desktop, cases, report); });
    worker.join();
    CloseDesktop(desktop);
    return result;
}

Json ShellCases(bool utf8)
{
    auto samples = Json::parse(utf8 ? R"cases(
    [ { "id" : 0 , "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0000 %1!.1hs!" , "arguments" : [ {
    "bytes" : "c3a9" } ] , "expected" : "SM0000 é" , "result" : 1 , "complete" : true , "consumed" : 6 , "fields" :
    [ { "index" : 0 , "type" : "char *" , "data" : "c3a9" } ] } , { "id" : 1 , "module" : "shlwapi.dll" , "wide" :
    false , "format" : "SM0001 %1!.2hs!" , "arguments" : [ { "bytes" : "c3a900" } ] , "expected" : "SM0001 é" ,
    "result" : 1 , "complete" : true , "consumed" : 6 , "fields" : [ { "index" : 0 , "type" : "char *" , "data" :
    "c3a9" } ] } , { "id" : 2 , "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0002 %1!.1hs!" ,
    "arguments" : [ { "bytes" : "e38182" } ] , "expected" : "SM0002 あ" , "result" : 1 , "complete" : true ,
    "consumed" : 6 , "fields" : [ { "index" : 0 , "type" : "char *" , "data" : "e38182" } ] } , { "id" : 3 ,
    "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0003 %1!.3hs!" , "arguments" : [ { "bytes" :
    "e3818200" } ] , "expected" : null , "result" : 0 , "complete" : true , "consumed" : 6 , "fields" : [ { "index"
    : 0 , "type" : "char *" , "data" : "e38182" } ] } , { "id" : 4 , "module" : "shlwapi.dll" , "wide" : false ,
    "format" : "SM0004 %1!.1hs!|%1!.3hs!" , "arguments" : [ { "bytes" : "c3a958" } ] , "expected" : "SM0004 é|éX" ,
    "complete" : true , "consumed" : 6 , "fields" : [ { "index" : 0 , "type" : "char *" , "data" : "c3a958" } ] } ,
    { "id" : 5 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0005 %1!.1hs!" , "arguments" : [ {
    "bytes" : "c3a9" } ] , "expected" : "SM0005 é" , "result" : 1 , "complete" : true , "consumed" : 6 , "fields" :
    [ { "index" : 0 , "type" : "char *" , "data" : "c3a9" } ] } , { "id" : 6 , "module" : "shlwapi.dll" , "wide" :
    true , "format" : "SM0006 %1!.2hs!" , "arguments" : [ { "bytes" : "c3a900" } ] , "expected" : "SM0006 é" ,
    "result" : 1 , "complete" : true , "consumed" : 6 , "fields" : [ { "index" : 0 , "type" : "char *" , "data" :
    "c3a9" } ] } , { "id" : 7 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0007 %1!.1hs!" ,
    "arguments" : [ { "bytes" : "e38182" } ] , "expected" : "SM0007 あ" , "result" : 1 , "complete" : true ,
    "consumed" : 6 , "fields" : [ { "index" : 0 , "type" : "char *" , "data" : "e38182" } ] } , { "id" : 8 ,
    "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0008 %1!.3hs!" , "arguments" : [ { "bytes" :
    "e3818200" } ] , "expected" : null , "result" : 0 , "complete" : true , "consumed" : 6 , "fields" : [ { "index"
    : 0 , "type" : "char *" , "data" : "e38182" } ] } , { "id" : 9 , "module" : "shlwapi.dll" , "wide" : true ,
    "format" : "SM0009 %1!.1hs!|%1!.3hs!" , "arguments" : [ { "bytes" : "c3a958" } ] , "expected" : "SM0009 é|éX" ,
    "complete" : true , "consumed" : 6 , "fields" : [ { "index" : 0 , "type" : "char *" , "data" : "c3a958" } ] } ]
)cases"
                                    : R"cases(
    [ { "id" : 0 , "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0000 No inserts" , "arguments" : [ {
    "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } ,
    { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" }
    , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : ""
    } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" :
    "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes"
    : "" } , { "bytes" : "" } , { "bytes" : "" } ] , "expected" : "SM0000 No inserts" , "fields" : [ ] , "complete"
    : true , "consumed" : 5 } , { "id" : 1 , "module" : "shlwapi.dll" , "wide" : false , "format" :
    "SM0001 %2!s!|%1!ld!|%1!lx!|%%" , "arguments" : [ 42 , { "bytes" : "416c70686100" } ] , "expected" :
    "SM0001 Alpha|42|2a|%" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type"
    : "char *" , "data" : "416c70686100" } ] , "complete" : true , "consumed" : 7 } , { "id" : 2 , "module" :
    "shlwapi.dll" , "wide" : false , "format" : "SM0002 %2|%1!d!" , "arguments" : [ 42 , { "bytes" : "416c70686100"
    } ] , "expected" : "SM0002 Alpha|42" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , {
    "index" : 1 , "type" : "char *" , "data" : "416c70686100" } ] , "complete" : true , "consumed" : 7 } , { "id" :
    3 , "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0003 %1!.3s!|%1!.6s!" , "arguments" : [ { "bytes"
    : "616263646566" } ] , "expected" : "SM0003 abc|abcdef" , "fields" : [ { "index" : 0 , "type" : "char *" ,
    "data" : "616263646566" } ] , "complete" : true , "consumed" : 6 } , { "id" : 4 , "module" : "shlwapi.dll" ,
    "wide" : false , "format" : "SM0004 %1!.3s!|%1!s!" , "arguments" : [ { "bytes" : "61626364656600" } ] ,
    "expected" : "SM0004 abc|abcdef" , "fields" : [ { "index" : 0 , "type" : "char *" , "data" : "61626364656600" }
    ] , "complete" : true , "consumed" : 6 } , { "id" : 5 , "module" : "shlwapi.dll" , "wide" : false , "format" :
    "SM0005 %1!.0s!" , "arguments" : [ { "bytes" : "" } ] , "expected" : "SM0005 " , "fields" : [ { "index" : 0 ,
    "type" : "char *" , "data" : "" } ] , "complete" : true , "consumed" : 6 } , { "id" : 6 , "module" :
    "shlwapi.dll" , "wide" : false , "format" : "SM0006 %1!s!|%2!s!" , "arguments" : [ 0 , { "bytes" :
    "416c70686100" } ] , "expected" : "SM0006 (null)|Alpha" , "fields" : [ { "index" : 0 , "type" : "char *" ,
    "data" : "" } , { "index" : 1 , "type" : "char *" , "data" : "416c70686100" } ] , "complete" : true ,
    "consumed" : 7 } , { "id" : 7 , "module" : "shlwapi.dll" , "wide" : false , "format" :
    "SM0007 %1!08lx!|%2!-10s!" , "arguments" : [ 42 , { "bytes" : "416c70686100" } ] , "expected" :
    "SM0007 0000002a|Alpha     " , "fields" : [ { "index" : 0 , "type" : "UInt32" , "data" : "" } , { "index" : 1 ,
    "type" : "char *" , "data" : "416c70686100" } ] , "complete" : true , "consumed" : 7 } , { "id" : 8 , "module"
    : "shlwapi.dll" , "wide" : false , "format" : "SM0008 %%|%b|%.|%!|%q|%0%1!s!" , "arguments" : [ ] , "expected"
    : "SM0008 %| |.|!|q|" , "fields" : [ ] , "complete" : true , "consumed" : 5 } , { "id" : 9 , "module" :
    "shlwapi.dll" , "wide" : false , "format" : "SM0009 %1!s!|%2!S!|%3!hs!|%4!hS!|%5!ls!|%6!lS!|%7!ws!|%8!wS!" ,
    "arguments" : [ { "bytes" : "576964746800" } , { "bytes" : "570069006400740068000000" } , { "bytes" :
    "576964746800" } , { "bytes" : "576964746800" } , { "bytes" : "570069006400740068000000" } , { "bytes" :
    "570069006400740068000000" } , { "bytes" : "570069006400740068000000" } , { "bytes" :
    "570069006400740068000000" } ] , "expected" : "SM0009 Width|Width|Width|Width|Width|Width|Width|Width" ,
    "fields" : [ { "index" : 0 , "type" : "char *" , "data" : "576964746800" } , { "index" : 1 , "type" :
    "wchar_t *" , "data" : "570069006400740068000000" } , { "index" : 2 , "type" : "char *" , "data" :
    "576964746800" } , { "index" : 3 , "type" : "char *" , "data" : "576964746800" } , { "index" : 4 , "type" :
    "wchar_t *" , "data" : "570069006400740068000000" } , { "index" : 5 , "type" : "wchar_t *" , "data" :
    "570069006400740068000000" } , { "index" : 6 , "type" : "wchar_t *" , "data" : "570069006400740068000000" } , {
    "index" : 7 , "type" : "wchar_t *" , "data" : "570069006400740068000000" } ] , "complete" : true , "consumed" :
    13 } , { "id" : 10 , "module" : "shlwapi.dll" , "wide" : false , "format" :
    "SM0010 %1!c!|%2!C!|%3!hc!|%4!hC!|%5!lc!|%6!lC!|%7!wc!|%8!wC!" , "arguments" : [ 65 , 65 , 65 , 65 , 65 , 65 ,
    65 , 65 ] , "expected" : "SM0010 A|A|A|A|A|A|A|A" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : ""
    } , { "index" : 1 , "type" : "Int32" , "data" : "" } , { "index" : 2 , "type" : "Int32" , "data" : "" } , {
    "index" : 3 , "type" : "Int32" , "data" : "" } , { "index" : 4 , "type" : "Int32" , "data" : "" } , { "index" :
    5 , "type" : "Int32" , "data" : "" } , { "index" : 6 , "type" : "Int32" , "data" : "" } , { "index" : 7 ,
    "type" : "Int32" , "data" : "" } ] , "complete" : true , "consumed" : 13 } , { "id" : 11 , "module" :
    "shlwapi.dll" , "wide" : false , "format" : "SM0011 %1!d!|%2!i!|%3!hd!|%4!ld!|%5!I32d!" , "arguments" : [
    4294967254 , 4294967254 , 4294967254 , 4294967254 , 4294967254 ] , "expected" : "SM0011 -42|-42|-42|-42|-42" ,
    "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "Int32" , "data" : ""
    } , { "index" : 2 , "type" : "Int32" , "data" : "" } , { "index" : 3 , "type" : "Int32" , "data" : "" } , {
    "index" : 4 , "type" : "Int32" , "data" : "" } ] , "complete" : true , "consumed" : 10 } , { "id" : 12 ,
    "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0012 %1!u!|%2!o!|%3!x!|%4!X!" , "arguments" : [ 42 ,
    42 , 42 , 42 ] , "expected" : "SM0012 42|52|2a|2A" , "fields" : [ { "index" : 0 , "type" : "UInt32" , "data" :
    "" } , { "index" : 1 , "type" : "UInt32" , "data" : "" } , { "index" : 2 , "type" : "UInt32" , "data" : "" } ,
    { "index" : 3 , "type" : "UInt32" , "data" : "" } ] , "complete" : true , "consumed" : 9 } , { "id" : 13 ,
    "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0013 %1!I64x!|%2!llx!|%3!Ix!" , "arguments" : [
    20015998343868 , 20015998343868 , 20015998343868 ] , "expected" :
    "SM0013 123456789abc|123456789abc|123456789abc" , "fields" : [ { "index" : 0 , "type" : "UInt64" , "data" : ""
    } , { "index" : 1 , "type" : "UInt64" , "data" : "" } , { "index" : 2 , "type" : "UInt64" , "data" : "" } ] ,
    "complete" : true , "consumed" : 8 } , { "id" : 14 , "module" : "shlwapi.dll" , "wide" : false , "format" :
    "SM0014 %1!p!" , "arguments" : [ 65536 ] , "expected" : "SM0014 0000000000010000" , "fields" : [ { "index" : 0
    , "type" : "void *" , "data" : "" } ] , "complete" : true , "consumed" : 6 } , { "id" : 15 , "module" :
    "shlwapi.dll" , "wide" : false , "format" : "SM0015 %1!wZ!|%2!hZ!|%3!Z!|%4!lZ!" , "arguments" : [ { "bytes" :
    "55006e00690063006f0064006500" , "length" : 14 , "maximum" : 14 } , { "bytes" : "416e7369" , "length" : 4 ,
    "maximum" : 4 } , { "bytes" : "506c61696e" , "length" : 5 , "maximum" : 5 } , { "bytes" : "4c6f6e67" , "length"
    : 4 , "maximum" : 4 } ] , "expected" : "SM0015 Unicode|Ansi|Plain|Long" , "fields" : [ { "index" : 0 , "type" :
    "UNICODE_STRING *" , "data" : "55006e00690063006f0064006500" , "descriptor" : [ 14 , 14 ] } , { "index" : 1 ,
    "type" : "ANSI_STRING *" , "data" : "416e7369" , "descriptor" : [ 4 , 4 ] } , { "index" : 2 , "type" :
    "ANSI_STRING *" , "data" : "506c61696e" , "descriptor" : [ 5 , 5 ] } , { "index" : 3 , "type" : "ANSI_STRING *"
    , "data" : "4c6f6e67" , "descriptor" : [ 4 , 4 ] } ] , "complete" : true , "consumed" : 9 } , { "id" : 16 ,
    "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0016 %1!-9wZ!|%1!wZ!|%2!.2hZ!" , "arguments" : [ {
    "bytes" : "500061006400" , "length" : 6 , "maximum" : 6 } , { "bytes" : "49676e6f72656420707265636973696f6e" ,
    "length" : 17 , "maximum" : 17 } ] , "expected" : "SM0016 Pad      |Pad|Ignored precision" , "fields" : [ {
    "index" : 0 , "type" : "UNICODE_STRING *" , "data" : "500061006400" , "descriptor" : [ 6 , 6 ] } , { "index" :
    1 , "type" : "ANSI_STRING *" , "data" : "49676e6f72656420707265636973696f6e" , "descriptor" : [ 17 , 17 ] } ] ,
    "complete" : true , "consumed" : 7 } , { "id" : 17 , "module" : "shlwapi.dll" , "wide" : false , "format" :
    "SM0017 %1!*wZ!|%2!Z!" , "arguments" : [ 8 , { "bytes" : "5300740061007200" , "length" : 8 , "maximum" : 8 } ,
    { "bytes" : "507265666978206f662074657874" , "length" : 6 , "maximum" : 14 } ] , "expected" :
    "SM0017     Star|Prefix" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 ,
    "type" : "UNICODE_STRING *" , "data" : "5300740061007200" , "descriptor" : [ 8 , 8 ] } , { "index" : 2 , "type"
    : "ANSI_STRING *" , "data" : "507265666978" , "descriptor" : [ 6 , 14 ] } ] , "complete" : true , "consumed" :
    8 } , { "id" : 18 , "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0018 %1!Z!|%2!wZ!|" , "arguments"
    : [ 0 , { "bytes" : "" , "length" : 0 , "maximum" : 0 } ] , "expected" : "SM0018 (null)||" , "fields" : [ {
    "index" : 0 , "type" : "ANSI_STRING *" , "data" : "" , "descriptor" : null } , { "index" : 1 , "type" :
    "UNICODE_STRING *" , "data" : "" , "descriptor" : [ 0 , 0 ] } ] , "complete" : true , "consumed" : 7 } , { "id"
    : 19 , "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0019 %1!wZ!|%1!s!" , "arguments" : [ { "bytes"
    : "43006f006e0066006c0069006300740069006e006700200076006900650077007300" , "length" : 34 , "maximum" : 34 } ] ,
    "expected" : null , "fields" : [ ] , "complete" : false , "consumed" : 6 } , { "id" : 20 , "module" :
    "shlwapi.dll" , "wide" : false , "format" : "SM0020 %1!*s!|%2" , "arguments" : [ 8 , { "bytes" : "416c70686100"
    } , { "bytes" : "4265746100" } ] , "expected" : "SM0020    Alpha|Beta" , "fields" : [ { "index" : 0 , "type" :
    "Int32" , "data" : "" } , { "index" : 1 , "type" : "char *" , "data" : "416c70686100" } , { "index" : 2 ,
    "type" : "char *" , "data" : "4265746100" } ] , "complete" : true , "consumed" : 8 } , { "id" : 21 , "module" :
    "shlwapi.dll" , "wide" : false , "format" : "SM0021 %1!.*s!|%2" , "arguments" : [ 3 , { "bytes" :
    "416c70686100" } , { "bytes" : "4265746100" } ] , "expected" : "SM0021 Alp|Beta" , "fields" : [ { "index" : 0 ,
    "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "char *" , "data" : "416c70" } , { "index" : 2 ,
    "type" : "char *" , "data" : "4265746100" } ] , "complete" : true , "consumed" : 8 } , { "id" : 22 , "module" :
    "shlwapi.dll" , "wide" : false , "format" : "SM0022 %1!*.*s!|%3|%4!*s!" , "arguments" : [ 6 , 3 , { "bytes" :
    "416c70686100" } , { "bytes" : "4265746100" } , 7 , { "bytes" : "47616d6d6100" } ] , "expected" :
    "SM0022    Alp|Beta|  Gamma" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 ,
    "type" : "Int32" , "data" : "" } , { "index" : 2 , "type" : "char *" , "data" : "416c70" } , { "index" : 3 ,
    "type" : "char *" , "data" : "4265746100" } , { "index" : 4 , "type" : "Int32" , "data" : "" } , { "index" : 5
    , "type" : "char *" , "data" : "47616d6d6100" } ] , "complete" : true , "consumed" : 11 } , { "id" : 23 ,
    "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0023 %1!*s!|%1!*s!|%2" , "arguments" : [ 6 , {
    "bytes" : "416c70686100" } , { "bytes" : "47616d6d6100" } , { "bytes" : "4265746100" } ] , "expected" :
    "SM0023  Alpha| Gamma|Beta" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 ,
    "type" : "char *" , "data" : "416c70686100" } , { "index" : 2 , "type" : "char *" , "data" : "47616d6d6100" } ,
    { "index" : 3 , "type" : "char *" , "data" : "4265746100" } ] , "complete" : true , "consumed" : 9 } , { "id" :
    24 , "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0024 %3!s!|%1!*s!|%2!d!" , "arguments" : [ 6 ,
    22 , { "bytes" : "416c70686100" } , { "bytes" : "47616d6d6100" } ] , "expected" : "SM0024 Alpha| Gamma|22" ,
    "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "Int32" , "data" : ""
    } , { "index" : 2 , "type" : "char *" , "data" : "416c70686100" } , { "index" : 3 , "type" : "char *" , "data"
    : "47616d6d6100" } ] , "complete" : true , "consumed" : 9 } , { "id" : 25 , "module" : "shlwapi.dll" , "wide" :
    false , "format" : "SM0025 %1!*.*s!|%2" , "arguments" : [ 6 , 3 , { "bytes" : "416c70686100" } ] , "expected" :
    "SM0025    Alp|Alpha" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type"
    : "Int32" , "data" : "" } , { "index" : 2 , "type" : "char *" , "data" : "416c70686100" } ] , "complete" : true
    , "consumed" : 8 } , { "id" : 26 , "module" : "shlwapi.dll" , "wide" : false , "format" :
    "SM0026 %1!.*s!|%1!.*s!" , "arguments" : [ 3 , { "bytes" : "416c70686100" } , { "bytes" : "47616d6d6100" } ] ,
    "expected" : "SM0026 Alp|Gam" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 ,
    "type" : "char *" , "data" : "416c70" } , { "index" : 2 , "type" : "char *" , "data" : "47616d" } ] ,
    "complete" : true , "consumed" : 8 } , { "id" : 27 , "module" : "shlwapi.dll" , "wide" : false , "format" :
    "SM0027 %1!.*s!" , "arguments" : [ 4294967295 , { "bytes" : "416c70686100" } ] , "expected" : "SM0027 Alpha" ,
    "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "char *" , "data" :
    "416c70686100" } ] , "complete" : true , "consumed" : 7 } , { "id" : 28 , "module" : "shlwapi.dll" , "wide" :
    false , "format" : "SM0028 %1!.*s!" , "arguments" : [ 0 , { "bytes" : "" } ] , "expected" : "SM0028 " ,
    "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "char *" , "data" : ""
    } ] , "complete" : true , "consumed" : 7 } , { "id" : 29 , "module" : "shlwapi.dll" , "wide" : false , "format"
    : "SM0029 %27!d!" , "arguments" : [ { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } ,
    { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" }
    , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : ""
    } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" :
    "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , 123 ] , "expected" :
    "SM0029 123" , "fields" : [ { "index" : 26 , "type" : "Int32" , "data" : "" } ] , "complete" : true ,
    "consumed" : 32 } , { "id" : 30 , "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0030 %28!s!" ,
    "arguments" : [ 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 ,
    0 , 0 , 0 , { "bytes" : "4265796f6e64206361707475726500" } ] , "expected" : "SM0030 Beyond capture" , "fields"
    : [ ] , "complete" : false , "consumed" : 33 } , { "id" : 31 , "module" : "shlwapi.dll" , "wide" : false ,
    "format" : "SM0031 %1!s!|%1!p!" , "arguments" : [ { "bytes" : "436f6e666c696374696e6720766965777300" } ] ,
    "expected" : null , "fields" : [ ] , "complete" : false , "consumed" : 6 } , { "id" : 32 , "module" :
    "shlwapi.dll" , "wide" : false , "format" : "SM0032 %1!q!" , "arguments" : [ 42 ] , "expected" : null ,
    "fields" : [ ] , "complete" : false , "consumed" : 6 } , { "id" : 33 , "module" : "shlwapi.dll" , "wide" :
    false , "format" : "SM0033 __LONG_FORMAT__%1!d!" , "arguments" : [ 42 ] , "expected" : null , "fields" : [ ] ,
    "complete" : false , "consumed" : 6 } , { "id" : 34 , "module" : "shlwapi.dll" , "wide" : false , "format" :
    "SM0034 " , "arguments" : [ 42 , { "bytes" : "5265736f7572636520696e7365727400" } ] , "expected" : null ,
    "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "char *" , "data" :
    "5265736f7572636520696e7365727400" } ] , "complete" : true , "consumed" : 7 , "resource" : 301 } , { "id" : 35
    , "module" : "shlwapi.dll" , "wide" : false , "format" : "SM0035 " , "arguments" : [ ] , "expected" : null ,
    "fields" : [ ] , "complete" : true , "consumed" : 5 , "null" : true } , { "id" : 36 , "module" : "shlwapi.dll"
    , "wide" : true , "format" : "SM0036 No inserts" , "arguments" : [ { "bytes" : "" } , { "bytes" : "" } , {
    "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } ,
    { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" }
    , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : ""
    } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" :
    "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes"
    : "" } ] , "expected" : "SM0036 No inserts" , "fields" : [ ] , "complete" : true , "consumed" : 5 } , { "id" :
    37 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0037 %2!s!|%1!ld!|%1!lx!|%%" , "arguments" : [ 42
    , { "bytes" : "41006c007000680061000000" } ] , "expected" : "SM0037 Alpha|42|2a|%" , "fields" : [ { "index" : 0
    , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "wchar_t *" , "data" : "41006c007000680061000000"
    } ] , "complete" : true , "consumed" : 7 } , { "id" : 38 , "module" : "shlwapi.dll" , "wide" : true , "format"
    : "SM0038 %2|%1!d!" , "arguments" : [ 42 , { "bytes" : "41006c007000680061000000" } ] , "expected" :
    "SM0038 Alpha|42" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" :
    "wchar_t *" , "data" : "41006c007000680061000000" } ] , "complete" : true , "consumed" : 7 } , { "id" : 39 ,
    "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0039 %1!.3s!|%1!.6s!" , "arguments" : [ { "bytes" :
    "610062006300640065006600" } ] , "expected" : "SM0039 abc|abcdef" , "fields" : [ { "index" : 0 , "type" :
    "wchar_t *" , "data" : "610062006300640065006600" } ] , "complete" : true , "consumed" : 6 } , { "id" : 40 ,
    "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0040 %1!.3s!|%1!s!" , "arguments" : [ { "bytes" :
    "6100620063006400650066000000" } ] , "expected" : "SM0040 abc|abcdef" , "fields" : [ { "index" : 0 , "type" :
    "wchar_t *" , "data" : "6100620063006400650066000000" } ] , "complete" : true , "consumed" : 6 } , { "id" : 41
    , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0041 %1!.0s!" , "arguments" : [ { "bytes" : "" } ] ,
    "expected" : "SM0041 " , "fields" : [ { "index" : 0 , "type" : "wchar_t *" , "data" : "" } ] , "complete" :
    true , "consumed" : 6 } , { "id" : 42 , "module" : "shlwapi.dll" , "wide" : true , "format" :
    "SM0042 %1!s!|%2!s!" , "arguments" : [ 0 , { "bytes" : "41006c007000680061000000" } ] , "expected" :
    "SM0042 (null)|Alpha" , "fields" : [ { "index" : 0 , "type" : "wchar_t *" , "data" : "" } , { "index" : 1 ,
    "type" : "wchar_t *" , "data" : "41006c007000680061000000" } ] , "complete" : true , "consumed" : 7 } , { "id"
    : 43 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0043 %1!08lx!|%2!-10s!" , "arguments" : [ 42 ,
    { "bytes" : "41006c007000680061000000" } ] , "expected" : "SM0043 0000002a|Alpha     " , "fields" : [ { "index"
    : 0 , "type" : "UInt32" , "data" : "" } , { "index" : 1 , "type" : "wchar_t *" , "data" :
    "41006c007000680061000000" } ] , "complete" : true , "consumed" : 7 } , { "id" : 44 , "module" : "shlwapi.dll"
    , "wide" : true , "format" : "SM0044 %%|%b|%.|%!|%q|%0%1!s!" , "arguments" : [ ] , "expected" :
    "SM0044 %| |.|!|q|" , "fields" : [ ] , "complete" : true , "consumed" : 5 } , { "id" : 45 , "module" :
    "shlwapi.dll" , "wide" : true , "format" : "SM0045 %1!s!|%2!S!|%3!hs!|%4!hS!|%5!ls!|%6!lS!|%7!ws!|%8!wS!" ,
    "arguments" : [ { "bytes" : "570069006400740068000000" } , { "bytes" : "576964746800" } , { "bytes" :
    "576964746800" } , { "bytes" : "576964746800" } , { "bytes" : "570069006400740068000000" } , { "bytes" :
    "570069006400740068000000" } , { "bytes" : "570069006400740068000000" } , { "bytes" :
    "570069006400740068000000" } ] , "expected" : "SM0045 Width|Width|Width|Width|Width|Width|Width|Width" ,
    "fields" : [ { "index" : 0 , "type" : "wchar_t *" , "data" : "570069006400740068000000" } , { "index" : 1 ,
    "type" : "char *" , "data" : "576964746800" } , { "index" : 2 , "type" : "char *" , "data" : "576964746800" } ,
    { "index" : 3 , "type" : "char *" , "data" : "576964746800" } , { "index" : 4 , "type" : "wchar_t *" , "data" :
    "570069006400740068000000" } , { "index" : 5 , "type" : "wchar_t *" , "data" : "570069006400740068000000" } , {
    "index" : 6 , "type" : "wchar_t *" , "data" : "570069006400740068000000" } , { "index" : 7 , "type" :
    "wchar_t *" , "data" : "570069006400740068000000" } ] , "complete" : true , "consumed" : 13 } , { "id" : 46 ,
    "module" : "shlwapi.dll" , "wide" : true , "format" :
    "SM0046 %1!c!|%2!C!|%3!hc!|%4!hC!|%5!lc!|%6!lC!|%7!wc!|%8!wC!" , "arguments" : [ 65 , 65 , 65 , 65 , 65 , 65 ,
    65 , 65 ] , "expected" : "SM0046 A|A|A|A|A|A|A|A" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : ""
    } , { "index" : 1 , "type" : "Int32" , "data" : "" } , { "index" : 2 , "type" : "Int32" , "data" : "" } , {
    "index" : 3 , "type" : "Int32" , "data" : "" } , { "index" : 4 , "type" : "Int32" , "data" : "" } , { "index" :
    5 , "type" : "Int32" , "data" : "" } , { "index" : 6 , "type" : "Int32" , "data" : "" } , { "index" : 7 ,
    "type" : "Int32" , "data" : "" } ] , "complete" : true , "consumed" : 13 } , { "id" : 47 , "module" :
    "shlwapi.dll" , "wide" : true , "format" : "SM0047 %1!d!|%2!i!|%3!hd!|%4!ld!|%5!I32d!" , "arguments" : [
    4294967254 , 4294967254 , 4294967254 , 4294967254 , 4294967254 ] , "expected" : "SM0047 -42|-42|-42|-42|-42" ,
    "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "Int32" , "data" : ""
    } , { "index" : 2 , "type" : "Int32" , "data" : "" } , { "index" : 3 , "type" : "Int32" , "data" : "" } , {
    "index" : 4 , "type" : "Int32" , "data" : "" } ] , "complete" : true , "consumed" : 10 } , { "id" : 48 ,
    "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0048 %1!u!|%2!o!|%3!x!|%4!X!" , "arguments" : [ 42 ,
    42 , 42 , 42 ] , "expected" : "SM0048 42|52|2a|2A" , "fields" : [ { "index" : 0 , "type" : "UInt32" , "data" :
    "" } , { "index" : 1 , "type" : "UInt32" , "data" : "" } , { "index" : 2 , "type" : "UInt32" , "data" : "" } ,
    { "index" : 3 , "type" : "UInt32" , "data" : "" } ] , "complete" : true , "consumed" : 9 } , { "id" : 49 ,
    "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0049 %1!I64x!|%2!llx!|%3!Ix!" , "arguments" : [
    20015998343868 , 20015998343868 , 20015998343868 ] , "expected" :
    "SM0049 123456789abc|123456789abc|123456789abc" , "fields" : [ { "index" : 0 , "type" : "UInt64" , "data" : ""
    } , { "index" : 1 , "type" : "UInt64" , "data" : "" } , { "index" : 2 , "type" : "UInt64" , "data" : "" } ] ,
    "complete" : true , "consumed" : 8 } , { "id" : 50 , "module" : "shlwapi.dll" , "wide" : true , "format" :
    "SM0050 %1!p!" , "arguments" : [ 65536 ] , "expected" : "SM0050 0000000000010000" , "fields" : [ { "index" : 0
    , "type" : "void *" , "data" : "" } ] , "complete" : true , "consumed" : 6 } , { "id" : 51 , "module" :
    "shlwapi.dll" , "wide" : true , "format" : "SM0051 %1!wZ!|%2!hZ!|%3!Z!|%4!lZ!" , "arguments" : [ { "bytes" :
    "55006e00690063006f0064006500" , "length" : 14 , "maximum" : 14 } , { "bytes" : "416e7369" , "length" : 4 ,
    "maximum" : 4 } , { "bytes" : "506c61696e" , "length" : 5 , "maximum" : 5 } , { "bytes" : "4c6f6e67" , "length"
    : 4 , "maximum" : 4 } ] , "expected" : "SM0051 Unicode|Ansi|Plain|Long" , "fields" : [ { "index" : 0 , "type" :
    "UNICODE_STRING *" , "data" : "55006e00690063006f0064006500" , "descriptor" : [ 14 , 14 ] } , { "index" : 1 ,
    "type" : "ANSI_STRING *" , "data" : "416e7369" , "descriptor" : [ 4 , 4 ] } , { "index" : 2 , "type" :
    "ANSI_STRING *" , "data" : "506c61696e" , "descriptor" : [ 5 , 5 ] } , { "index" : 3 , "type" : "ANSI_STRING *"
    , "data" : "4c6f6e67" , "descriptor" : [ 4 , 4 ] } ] , "complete" : true , "consumed" : 9 } , { "id" : 52 ,
    "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0052 %1!-9wZ!|%1!wZ!|%2!.2hZ!" , "arguments" : [ {
    "bytes" : "500061006400" , "length" : 6 , "maximum" : 6 } , { "bytes" : "49676e6f72656420707265636973696f6e" ,
    "length" : 17 , "maximum" : 17 } ] , "expected" : "SM0052 Pad      |Pad|Ignored precision" , "fields" : [ {
    "index" : 0 , "type" : "UNICODE_STRING *" , "data" : "500061006400" , "descriptor" : [ 6 , 6 ] } , { "index" :
    1 , "type" : "ANSI_STRING *" , "data" : "49676e6f72656420707265636973696f6e" , "descriptor" : [ 17 , 17 ] } ] ,
    "complete" : true , "consumed" : 7 } , { "id" : 53 , "module" : "shlwapi.dll" , "wide" : true , "format" :
    "SM0053 %1!*wZ!|%2!Z!" , "arguments" : [ 8 , { "bytes" : "5300740061007200" , "length" : 8 , "maximum" : 8 } ,
    { "bytes" : "507265666978206f662074657874" , "length" : 6 , "maximum" : 14 } ] , "expected" :
    "SM0053     Star|Prefix" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 ,
    "type" : "UNICODE_STRING *" , "data" : "5300740061007200" , "descriptor" : [ 8 , 8 ] } , { "index" : 2 , "type"
    : "ANSI_STRING *" , "data" : "507265666978" , "descriptor" : [ 6 , 14 ] } ] , "complete" : true , "consumed" :
    8 } , { "id" : 54 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0054 %1!Z!|%2!wZ!|" , "arguments"
    : [ 0 , { "bytes" : "" , "length" : 0 , "maximum" : 0 } ] , "expected" : "SM0054 (null)||" , "fields" : [ {
    "index" : 0 , "type" : "ANSI_STRING *" , "data" : "" , "descriptor" : null } , { "index" : 1 , "type" :
    "UNICODE_STRING *" , "data" : "" , "descriptor" : [ 0 , 0 ] } ] , "complete" : true , "consumed" : 7 } , { "id"
    : 55 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0055 %1!wZ!|%1!s!" , "arguments" : [ { "bytes"
    : "43006f006e0066006c0069006300740069006e006700200076006900650077007300" , "length" : 34 , "maximum" : 34 } ] ,
    "expected" : null , "fields" : [ ] , "complete" : false , "consumed" : 6 } , { "id" : 56 , "module" :
    "shlwapi.dll" , "wide" : true , "format" : "SM0056 %1!*s!|%2" , "arguments" : [ 8 , { "bytes" :
    "41006c007000680061000000" } , { "bytes" : "42006500740061000000" } ] , "expected" : "SM0056    Alpha|Beta" ,
    "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "wchar_t *" , "data" :
    "41006c007000680061000000" } , { "index" : 2 , "type" : "wchar_t *" , "data" : "42006500740061000000" } ] ,
    "complete" : true , "consumed" : 8 } , { "id" : 57 , "module" : "shlwapi.dll" , "wide" : true , "format" :
    "SM0057 %1!.*s!|%2" , "arguments" : [ 3 , { "bytes" : "41006c007000680061000000" } , { "bytes" :
    "42006500740061000000" } ] , "expected" : "SM0057 Alp|Beta" , "fields" : [ { "index" : 0 , "type" : "Int32" ,
    "data" : "" } , { "index" : 1 , "type" : "wchar_t *" , "data" : "41006c007000" } , { "index" : 2 , "type" :
    "wchar_t *" , "data" : "42006500740061000000" } ] , "complete" : true , "consumed" : 8 } , { "id" : 58 ,
    "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0058 %1!*.*s!|%3|%4!*s!" , "arguments" : [ 6 , 3 , {
    "bytes" : "41006c007000680061000000" } , { "bytes" : "42006500740061000000" } , 7 , { "bytes" :
    "470061006d006d0061000000" } ] , "expected" : "SM0058    Alp|Beta|  Gamma" , "fields" : [ { "index" : 0 ,
    "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "Int32" , "data" : "" } , { "index" : 2 , "type" :
    "wchar_t *" , "data" : "41006c007000" } , { "index" : 3 , "type" : "wchar_t *" , "data" :
    "42006500740061000000" } , { "index" : 4 , "type" : "Int32" , "data" : "" } , { "index" : 5 , "type" :
    "wchar_t *" , "data" : "470061006d006d0061000000" } ] , "complete" : true , "consumed" : 11 } , { "id" : 59 ,
    "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0059 %1!*s!|%1!*s!|%2" , "arguments" : [ 6 , { "bytes"
    : "41006c007000680061000000" } , { "bytes" : "470061006d006d0061000000" } , { "bytes" : "42006500740061000000"
    } ] , "expected" : "SM0059  Alpha| Gamma|Beta" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" }
    , { "index" : 1 , "type" : "wchar_t *" , "data" : "41006c007000680061000000" } , { "index" : 2 , "type" :
    "wchar_t *" , "data" : "470061006d006d0061000000" } , { "index" : 3 , "type" : "wchar_t *" , "data" :
    "42006500740061000000" } ] , "complete" : true , "consumed" : 9 } , { "id" : 60 , "module" : "shlwapi.dll" ,
    "wide" : true , "format" : "SM0060 %3!s!|%1!*s!|%2!d!" , "arguments" : [ 6 , 22 , { "bytes" :
    "41006c007000680061000000" } , { "bytes" : "470061006d006d0061000000" } ] , "expected" :
    "SM0060 Alpha| Gamma|22" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 ,
    "type" : "Int32" , "data" : "" } , { "index" : 2 , "type" : "wchar_t *" , "data" : "41006c007000680061000000" }
    , { "index" : 3 , "type" : "wchar_t *" , "data" : "470061006d006d0061000000" } ] , "complete" : true ,
    "consumed" : 9 } , { "id" : 61 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0061 %1!*.*s!|%2" ,
    "arguments" : [ 6 , 3 , { "bytes" : "41006c007000680061000000" } ] , "expected" : "SM0061    Alp|Alpha" ,
    "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "Int32" , "data" : ""
    } , { "index" : 2 , "type" : "wchar_t *" , "data" : "41006c007000680061000000" } ] , "complete" : true ,
    "consumed" : 8 } , { "id" : 62 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0062 %1!.*s!|%1!.*s!"
    , "arguments" : [ 3 , { "bytes" : "41006c007000680061000000" } , { "bytes" : "470061006d006d0061000000" } ] ,
    "expected" : "SM0062 Alp|Gam" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 ,
    "type" : "wchar_t *" , "data" : "41006c007000" } , { "index" : 2 , "type" : "wchar_t *" , "data" :
    "470061006d00" } ] , "complete" : true , "consumed" : 8 } , { "id" : 63 , "module" : "shlwapi.dll" , "wide" :
    true , "format" : "SM0063 %1!.*s!" , "arguments" : [ 4294967295 , { "bytes" : "41006c007000680061000000" } ] ,
    "expected" : "SM0063 Alpha" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 ,
    "type" : "wchar_t *" , "data" : "41006c007000680061000000" } ] , "complete" : true , "consumed" : 7 } , { "id"
    : 64 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0064 %1!.*s!" , "arguments" : [ 0 , { "bytes" :
    "" } ] , "expected" : "SM0064 " , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1
    , "type" : "wchar_t *" , "data" : "" } ] , "complete" : true , "consumed" : 7 } , { "id" : 65 , "module" :
    "shlwapi.dll" , "wide" : true , "format" : "SM0065 %27!d!" , "arguments" : [ { "bytes" : "" } , { "bytes" : ""
    } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" :
    "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes"
    : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , {
    "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } , { "bytes" : "" } ,
    { "bytes" : "" } , 123 ] , "expected" : "SM0065 123" , "fields" : [ { "index" : 26 , "type" : "Int32" , "data"
    : "" } ] , "complete" : true , "consumed" : 32 } , { "id" : 66 , "module" : "shlwapi.dll" , "wide" : true ,
    "format" : "SM0066 %28!s!" , "arguments" : [ 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
    , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , { "bytes" :
    "4200650079006f006e006400200063006100700074007500720065000000" } ] , "expected" : "SM0066 Beyond capture" ,
    "fields" : [ ] , "complete" : false , "consumed" : 33 } , { "id" : 67 , "module" : "shlwapi.dll" , "wide" :
    true , "format" : "SM0067 %1!s!|%1!p!" , "arguments" : [ { "bytes" :
    "43006f006e0066006c0069006300740069006e0067002000760069006500770073000000" } ] , "expected" : null , "fields" :
    [ ] , "complete" : false , "consumed" : 6 } , { "id" : 68 , "module" : "shlwapi.dll" , "wide" : true , "format"
    : "SM0068 %1!q!" , "arguments" : [ 42 ] , "expected" : null , "fields" : [ ] , "complete" : false , "consumed"
    : 6 } , { "id" : 69 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0069 __LONG_FORMAT__%1!d!" ,
    "arguments" : [ 42 ] , "expected" : null , "fields" : [ ] , "complete" : false , "consumed" : 6 } , { "id" : 70
    , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0070 " , "arguments" : [ 42 , { "bytes" :
    "5200650073006f007500720063006500200069006e0073006500720074000000" } ] , "expected" : null , "fields" : [ {
    "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "wchar_t *" , "data" :
    "5200650073006f007500720063006500200069006e0073006500720074000000" } ] , "complete" : true , "consumed" : 7 ,
    "resource" : 301 } , { "id" : 71 , "module" : "shlwapi.dll" , "wide" : true , "format" : "SM0071 " ,
    "arguments" : [ ] , "expected" : null , "fields" : [ ] , "complete" : true , "consumed" : 5 , "null" : true } ,
    { "id" : 72 , "module" : "shell32.dll" , "wide" : false , "format" : "SM0072 %2!s!|%1!ld!|%1!lx!|%%" ,
    "arguments" : [ 42 , { "bytes" : "416c70686100" } ] , "expected" : "SM0072 Alpha|42|2a|%" , "fields" : [ {
    "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 , "type" : "char *" , "data" : "416c70686100" }
    ] , "complete" : true , "consumed" : 7 } , { "id" : 73 , "module" : "shell32.dll" , "wide" : true , "format" :
    "SM0073 %2!s!|%1!ld!|%1!lx!|%%" , "arguments" : [ 42 , { "bytes" : "41006c007000680061000000" } ] , "expected"
    : "SM0073 Alpha|42|2a|%" , "fields" : [ { "index" : 0 , "type" : "Int32" , "data" : "" } , { "index" : 1 ,
    "type" : "wchar_t *" , "data" : "41006c007000680061000000" } ] , "complete" : true , "consumed" : 7 } ]
)cases");
    for (auto& sample : samples)
    {
        auto& format = sample["format"].get_ref<std::string&>();
        constexpr std::string_view marker = "__LONG_FORMAT__";
        if (auto offset = format.find(marker); offset != std::string::npos)
            format.replace(offset, marker.size(), std::string(4100, 'x'));
    }
    return samples;
}

Json ShellReports(const Path& path, const Json& samples)
{
    auto rows = JsonLines(path);
    Require(rows.size() == samples.size(), "Shell message report count differs", rows.size());
    for (size_t index = 0; index < samples.size(); ++index)
    {
        const auto& sample = samples[index];
        const auto& row = rows[index];
        Require(row["id"] == sample["id"] &&
                    row["result"] == sample.value("result", sample.value("null", false) ? 0 : 1),
                "Native shell message result differs", row);
        if (!sample["expected"].is_null())
            Require(std::ranges::any_of(row.value("accessible", Json::array()),
                                        [&](const Json& text) { return text == sample["expected"]; }) ||
                        std::ranges::any_of(row.value("children", Json::array()),
                                            [&](const Json& child) { return child["text"] == sample["expected"]; }),
                    "Native shell dialog text differs", row);
        if (sample.value("resource", 0))
        {
            Require(row["title"] == sample.value("expectedTitle", "Detourist resource title"),
                    "Shell resource title differs", row);
            if (!sample.contains("template"))
                Require(std::ranges::find(row["accessible"], "SM_RESOURCE Resource insert|42") !=
                            row["accessible"].end(),
                        "Embedded shell resource insert differs", row);
        }
    }
    return rows;
}

void CheckShellMessages(const Context& context, const Json& samples, bool utf8, const Path& desktop)
{
    auto config = context.directory / L"cases.json", report = context.directory / L"messages.jsonl";
    WriteJson(config, samples);
    auto arguments = Quote(config) + L" " + Quote(report);
    RunTarget(context, arguments, 180000);
    auto originals = ShellReports(report, samples);
    if (utf8)
        for (const auto& row : originals)
            Require(row["codePage"] == 65001, "UTF-8 manifest did not select UTF-8", row);
    Json inspections = Json::array();
    Collector metadata(context.collector, context.directory);
    auto hello = metadata.Call("hello");
    auto category = Only(Select(hello["categories"], [](const Json& item) { return item["name"] == "Shell"; }));
    metadata.Close();
    for (uint32_t limit : {16u, 64u, 512u})
    {
        Capture::Run(context, {.arguments = arguments, .limit = limit,
            .apiMask = Number(hello["allApis"]) & ~Number(hello["comMask"]),
            .categoryMask = Number(category["mask"])},
                     [&](Capture& capture)
        {
            auto observed = ShellReports(report, samples);
            auto rows = capture.Find("ShellMessageBox[AW]");
            Require(rows.size() == samples.size(), "Shell message capture count differs", rows.size());
            for (size_t index = 0; index < rows.size(); ++index)
            {
                auto row = rows[index], sample = samples[index], native = observed[index], original = originals[index];
                Require(row["name"] == native["function"] && native["result"] == original["result"] &&
                            row["result"] == original["result"] && native["codePage"] == original["codePage"] &&
                            native["languageId"] == original["languageId"] &&
                            native.value("languages", Json()) == original.value("languages", Json()),
                        "Traced shell dialog result differs", sample);
                Require(Data(row["arguments"]).size() == 256 &&
                            Read<uint64_t>(row["arguments"], 16) == native["address"] &&
                            Read<uint64_t>(row["arguments"]) == native["resourceModule"],
                        "Shell dialog fixed arguments differ", row);
                for (size_t ordinal = 0; ordinal < 27; ++ordinal)
                    Require(Read<uint64_t>(row["arguments"], (ordinal + 5) * 8) == native["arguments"][ordinal],
                            "Shell dialog variadic slot differs", row);
                auto before = Values(row["input"]);
                Require(Values(row["output"]).empty(), "Shell dialog has output memory capture", row);
                CheckLimit(row, limit);
                if (!sample.value("resource", 0))
                    Require(Regions(before, {.parameter = 2}).size() == size_t(!sample.value("null", false)) &&
                                Regions(before, {.parameter = 3}).size() == 1,
                            "Shell dialog text or title capture differs", row);
                bool complete = sample["complete"];
                auto flags = row["flags"].get<uint32_t>();
                Require(bool(flags & 2048) == complete, "Shell insert graph completeness differs", row);
                if (complete)
                {
                    Require(((flags >> 12) & 63) == sample["consumed"], "Shell insert consumption count differs", row);
                    std::set<uint32_t> expected, actual;
                    for (const auto& field : sample["fields"])
                    {
                        uint32_t parameter = field["index"].get<uint32_t>() + 5;
                        auto captured = Regions(before, {.parameter = parameter});
                        auto bytes = Unhex(field["data"]);
                        if (field.contains("descriptor") && !field["descriptor"].is_null())
                        {
                            expected.insert(parameter);
                            Require(!captured.empty(), "Shell counted insert descriptor missing", row);
                            auto header = captured[0];
                            Require(header.kind == 0 && !(header.flags & (2 | 8)) &&
                                        header.data.size() == std::min(16u, limit) &&
                                        Read<uint16_t>(header.data) == field["descriptor"][0] &&
                                        Read<uint16_t>(header.data, 2) == field["descriptor"][1],
                                    "Shell counted insert descriptor differs", row);
                            Require(captured.size() - 1 == size_t(!bytes.empty()),
                                    "Shell counted insert payload count differs", row);
                            for (size_t element = 1; element < captured.size(); ++element)
                            {
                                auto value = captured[element];
                                Require(value.kind == uint32_t(field["type"] == "UNICODE_STRING *") &&
                                            (value.flags & 8) && !(value.flags & 2) &&
                                            value.data == Prefix(bytes, limit),
                                        "Shell counted insert payload differs", row);
                            }
                        }
                        else if (bytes.empty())
                            Require(captured.empty(), "Shell scalar or zero precision insert was probed", row);
                        else
                        {
                            expected.insert(parameter);
                            Require(captured.size() == 1 &&
                                        captured[0].kind == uint32_t(field["type"] == "wchar_t *") &&
                                        captured[0].data == Prefix(bytes, limit) && !(captured[0].flags & 2),
                                    "Shell insert bytes differ", row);
                        }
                    }
                    for (const auto& value : before)
                        if (value.index >= 5) actual.insert(value.index);
                    Require(actual == expected, "Shell unused inserts were captured", row);
                }
                if (sample.value("resource", 0))
                {
                    auto text = sample.value("template", Json("SM_RESOURCE %2!s!|%1!ld!"));
                    std::vector<Value> templates;
                    if (!text.is_null())
                    {
                        bool wide = sample["wide"];
                        auto bytes = Encode(text, wide, true);
                        templates.push_back(
                            {2, uint32_t(wide), uint32_t(bytes.size() > limit), bytes.size(), Prefix(bytes, limit)});
                    }
                    Require(Regions(before, {.parameter = 2}) == templates &&
                                !Regions(before, {.parameter = 3}).empty() == sample.value("nullModule", false),
                            "Shell resource template capture differs", row);
                }
                if (limit == 512 && sample.value("inspect", true))
                    inspections.push_back({{"sample", sample}, {"call", capture.Details(row)}});
            }
        }, std::max<DWORD>(240, static_cast<DWORD>(samples.size()) * 6)); // Each captured dialog takes seconds.
    }
    Inspect(context, desktop, "--shell-messages", inspections);
}

Json ShellResourceCases(const Path& target, const Path& module, bool utf8)
{
    Json samples = Json::array();
    auto add = [&](Json sample)
    {
        sample["id"] = samples.size();
        samples.push_back(sample);
    };
    for (bool wide : {false, true})
    {
        for (auto [name, resource, flags] : {std::tuple{"embedded", Path{}, 0},
                                             {"datafile", target, 2},
                                             {"mui", module, 0},
                                             {"mui-datafile", module, 2},
                                             {"mui-image", module, 34}})
        {
            if (utf8 && std::string_view(name) != "mui-datafile") continue;
            for (auto language : {"en-US", "fr-FR"})
            {
                bool french = std::string_view(language) == "fr-FR";
                auto pattern = french ? "SM_FR %1!s!|%2!ld!" : "SM_EN %2!s!|%1!ld!";
                auto bytes = Encode("Localized insert", wide, true);
                auto hex = [](const Bytes& value)
                {
                    std::ostringstream stream;
                    for (auto byte : value)
                        stream << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte);
                    return stream.str();
                };
                auto text = hex(bytes);
                Json sample{
                    {"module", "shlwapi.dll"},
                    {"wide", wide},
                    {"resource", 401},
                    {"titleResource", 402},
                    {"format", pattern},
                    {"template", pattern},
                    {"languages", Json::array({language})},
                    {"expected", std::string(french ? "SM_FR" : "SM_EN") + " Localized insert|42"},
                    {"expectedTitle", french ? "Detourist French resource" : "Detourist English resource"},
                    {"arguments", french ? Json::array({{{"bytes", text}}, 42}) : Json::array({42, {{"bytes", text}}})},
                    {"fields",
                     Json::array({{{"index", int(!french)}, {"type", wide ? "wchar_t *" : "char *"}, {"data", text}},
                                  {{"index", int(french)}, {"type", "Int32"}, {"data", ""}}})},
                    {"complete", true},
                    {"consumed", 7}};
                if (!resource.empty()) sample["resourceModule"] = Text(resource);
                if (flags) sample["loadFlags"] = flags;
                add(sample);
                if (std::string_view(name) == "mui")
                {
                    sample["languages"] = Json::array({"es-ES", language});
                    add(sample);
                    if (!french)
                    {
                        sample["languages"] = Json::array({"es-ES"});
                        add(sample);
                    }
                }
                if (std::string_view(name) == "embedded")
                {
                    sample.update({{"nullModule", true},
                                   {"languageId", french ? 0x40c : 0x409},
                                   {"expectedTitle", "Detourist shell capture"}});
                    add(sample);
                }
            }
        }
        add({{"module", "shlwapi.dll"},
             {"wide", wide},
             {"resource", 4095},
             {"titleResource", 402},
             {"format", ""},
             {"template", nullptr},
             {"languages", Json::array({"fr-FR"})},
             {"expected", nullptr},
             {"expectedTitle", "Detourist French resource"},
             {"arguments", Json::array({{{"bytes", ""}}})},
             {"fields", Json::array()},
             {"complete", false},
             {"consumed", 32},
             {"resourceModule", Text(module)},
             {"loadFlags", 2}});
        for (int identifier : {403, 404})
        {
            if (identifier == 404 && !utf8 && !wide) continue;
            auto count = utf8 && !wide ? 256 : 260;
            std::string text;
            if (identifier == 403)
                text.assign(513, 'X');
            else
                for (int index = 0; index < count; ++index)
                    text += "é";
            bool insert = identifier == 404 && (!utf8 || wide);
            std::string data = insert ? (wide ? "0000" : "00") : "";
            add({{"module", "shlwapi.dll"},
                 {"wide", wide},
                 {"resource", identifier},
                 {"titleResource", 402},
                 {"format", text + (insert ? "%1!s!" : "")},
                 {"template", text + (insert ? "%1!s!" : "")},
                 {"languages", Json::array({"en-US"})},
                 {"expected", text},
                 {"expectedTitle", "Detourist English resource"},
                 {"arguments", Json::array({{{"bytes", data}}})},
                 {"fields", insert
                                ? Json::array({{{"index", 0}, {"type", wide ? "wchar_t *" : "char *"}, {"data", data}}})
                                : Json::array()},
                 {"complete", true},
                 {"consumed", insert ? 6 : 5},
                 {"resourceModule", Text(module)},
                 {"loadFlags", 2},
                 {"inspect", false}});
        }
    }
    return samples;
}

void ShellMessage(const Context& context)
{
    if (!context.Has(L"--resources"))
    {
        bool utf8 = context.Has(L"--utf8");
        CheckShellMessages(context, ShellCases(utf8), utf8, context.Optional(0));
        return;
    }

    // Build language satellites, then exercise native and UTF-8 resource mappings with preference fallbacks.
    auto module = context.directory / L"ShellMessages.dll";
    auto compiler = context.Extra(5), config = context.Extra(6);
    for (bool french : {false, true})
    {
        auto satellite = context.directory / (french ? L"fr-FR" : L"en-US") / L"ShellMessages.dll.mui";
        std::filesystem::create_directory(satellite.parent_path());
        auto neutral = french ? context.directory / L"French.dll" : module;
        auto arguments = L"-q " + Quote(config) + L" -x " + (french ? L"0x40c" : L"0x409") + L" -g 0x409 " +
                         Quote(context.Extra(french ? 4 : 3)) + L" " + Quote(neutral) + L" " + Quote(satellite);
        RunTarget(compiler, context.directory, arguments);
        if (french) RunTarget(compiler, context.directory, L"-c " + Quote(module) + L" -e " + Quote(satellite));
    }
    for (bool utf8 : {false, true})
    {
        auto variant = context;
        variant.directory /= utf8 ? L"utf8" : L"ansi";
        std::filesystem::create_directory(variant.directory);
        if (utf8) variant.target = context.Extra(1);
        CheckShellMessages(variant, ShellResourceCases(variant.target, module, utf8), utf8, context.Extra(2));
    }
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, ShellMessage); }

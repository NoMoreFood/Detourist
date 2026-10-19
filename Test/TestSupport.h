#pragma once

#include <winsock2.h>
#include "WinSupport.h"
#include <winternl.h>
#include <TraceLoggingProvider.h>
#include <activation.h>
#include <authz.h>
#include <comsvcs.h>
#include <ctxtcall.h>
#include <d3d11.h>
#include <d3dcsx.h>
#include <dsgetdc.h>
#include <dwmapi.h>
#include <filter.h>
#include <icodecapi.h>
#include <lm.h>
#include <mfapi.h>
#include <mfcaptureengine.h>
#include <ntdsapi.h>
#include <oaidl.h>
#include <objbase.h>
#include <objidl.h>
#include <ocidl.h>
#include <oleauto.h>
#include <propkey.h>
#include <propsys.h>
#include <propvarutil.h>
#include <rpc.h>
#include <sddl.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <vfw.h>
#include <wab.h>
#include <winstring.h>
#include <wrl/client.h>
#ifdef DETOURIST_TEST_D3DX
#include <D3DX11.h>
#endif

#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <mfidl.h>
#include <uiautomation.h>
#include <evntprov.h>
#include <evntrace.h>
#include <shlwapi.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <commctrl.h>
// winternl supplies the native string types that the LSA header otherwise aliases.
#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_
#include <winnetwk.h>
#include <npapi.h>
#include <oleacc.h>
#include <d3dkmthk.h>
#include <psapi.h>
#include <olectl.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <bit>
#include <chrono>
#include <climits>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <regex>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

namespace Detourist::Tests
{
using Json = nlohmann::json;
using Path = std::filesystem::path;
struct Skipped : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

void Require(bool condition, const std::string& message, const Json& detail = nullptr);
// Stack-owned COM fixtures report a stable count; counted fixtures expose theirs for ownership checks.
template<class... Interfaces> struct FixedUnknown : Interfaces...
{
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
};
template<class Interface> struct CountedUnknown : Interface
{
    ULONG references = 1;
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override { return --references; }
};
// CRT targets record invalid-argument results instead of terminating.
inline void __cdecl IgnoreInvalidParameter(const wchar_t*, const wchar_t*, const wchar_t*, unsigned, uintptr_t) {}
std::string Text(const Path& path);
Json Query(const Path& database, const char* sql, const Json& parameters = Json::array());
Json Calls(const Path& database, const std::string& condition = "", const Json& parameters = Json::array());
uint64_t UInt64(const Json& blob);
std::string RunTarget(const Path& executable, const Path& directory, DWORD timeout = 20000);
std::string RunTarget(const Path& executable, const Path& directory, const std::wstring& arguments,
                      DWORD timeout = 20000);
std::string ReadLog(const Path& path);
void WriteJson(const Path& path, const Json& value);
std::wstring Quote(const Path& path);

using Bytes = std::vector<uint8_t>;
template<std::ranges::input_range Range, class Predicate> auto Select(const Range& values, Predicate predicate)
{
    return values | std::views::filter(std::move(predicate)) |
           std::ranges::to<std::vector<std::ranges::range_value_t<Range>>>();
}
template<std::ranges::sized_range Range> auto Only(const Range& values)
{
    Require(std::ranges::size(values) == 1, "Expected exactly one captured value");
    return *std::ranges::begin(values);
}
Bytes Data(const Json& value);
Bytes Encode(const std::string& text, bool wide = false, bool terminated = false);
inline bool Starts(const Bytes& bytes, const Bytes& prefix)
{
    return bytes.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), bytes.begin());
}
Bytes Unhex(const std::string& text);
std::string String(const Bytes& bytes, bool wide = false);
template<class T> T Read(const Bytes& data, size_t offset = 0)
{
    Require(offset <= data.size() && data.size() - offset >= sizeof(T), "Incomplete captured scalar");
    T value{};
    memcpy(&value, data.data() + offset, sizeof(value));
    return value;
}
template<class T> T Read(const Json& data, size_t offset = 0) { return Read<T>(Data(data), offset); }

struct Value
{
    uint32_t index, kind, flags;
    uint64_t original;
    Bytes data;
    bool operator==(const Value&) const = default;
};
std::vector<Value> Values(const Json& payload);
struct RegionFilter
{
    std::optional<uint32_t> parameter, kind;
    uint32_t required = 0, excluded = 0;
    std::optional<uint32_t> element;
    std::optional<uint32_t> tag, record;
    uint32_t tagMask = 255;
    uint32_t parameterMask = UINT32_MAX;
};
std::vector<Value> Regions(const Json& payload, const RegionFilter& filter);
std::vector<Value> Regions(const std::vector<Value>& values, const RegionFilter& filter);
std::vector<Bytes> Snapshots(const Json& payload, uint32_t index, uint32_t kind);
void CheckLimit(const Json& row, size_t limit);
Json Named(const Json& rows, const std::string& name);
Json Matching(const Json& rows, const std::string& names, const std::string& modules = ".*");
Json Tsv(const Path& path);
Json Fields(const Path& path);
Json JsonLines(const Path& path);
inline std::vector<std::string> Split(std::string_view text, char separator)
{
    return text | std::views::split(separator) |
           std::views::transform([](auto part) { return std::string(std::from_range, part); }) |
           std::ranges::to<std::vector<std::string>>();
}
Json Columns(const Path& path, std::initializer_list<const char*> names,
             std::initializer_list<const char*> numbers = {}, std::initializer_list<const char*> hexadecimal = {});
Json Columns(const Json& rows, std::initializer_list<const char*> names,
             std::initializer_list<const char*> numbers = {}, std::initializer_list<const char*> hexadecimal = {});
std::string Key(const Json& row, std::initializer_list<const char*> fields);
Json Group(const Json& rows, std::initializer_list<const char*> fields);
Json Without(Json row, std::initializer_list<const char*> fields);
uint64_t Number(const Json& value, int base = 10);
Json Report(const Path& path);
Json InImage(const Json& rows, const Json& report);
void CompareCalls(const Json& baseline, const Json& report, std::initializer_list<const char*> fields);
Bytes Prefix(Bytes data, size_t limit);
Bytes Integer(uint64_t value, size_t size = 8);
struct Image
{
    explicit Image(const Path& path);
    size_t Offset(uint32_t rva) const;
    Json Exports() const;
    Bytes bytes;
    IMAGE_NT_HEADERS64 headers{};
    std::vector<IMAGE_SECTION_HEADER> sections;
};

class Collector;
struct CaptureSession
{
    std::shared_ptr<Collector> collector;
};

struct Context
{
    Path collector, target, directory;
    std::span<wchar_t*> arguments;
    bool self = false;
    std::shared_ptr<CaptureSession> session = std::make_shared<CaptureSession>();
    bool Has(const wchar_t* option) const;
    std::wstring Option(const wchar_t* option, const std::wstring& fallback = L"") const;
    Path Extra(size_t index) const;
    Path Optional(size_t index) const;
    Collector& GetCollector() const;
};

std::string RunTarget(const Context& context, const std::wstring& arguments = L"", DWORD timeout = 20000);
std::string TargetArguments(const Context& context, const std::wstring& arguments = L"");
Json TargetCalls(const Context& context, const Path& database);
int Run(int argc, wchar_t** argv, void (*test)(const Context&), int (*target)(int, wchar_t**) = nullptr);

template<auto Target> int Run(int argc, wchar_t** argv, void (*test)(const Context&))
{
    return Run(argc, argv, test, [](int count, wchar_t** arguments)
    {
        if constexpr (requires { Target(count, arguments); })
            return Target(count, arguments);
        else
            return Target();
    });
}

class ChildProcess;

class TargetProcess
{
public:
    TargetProcess(const Context& context, const std::wstring& arguments);
    ~TargetProcess();
    DWORD Pid() const;
    bool Running() const;
    DWORD Wait(DWORD timeout = 20000) const;

private:
    Handle input_, output_;
    std::unique_ptr<ChildProcess> process_;
};

class Collector
{
public:
    Collector(const Path& executable, const Path& directory);
    ~Collector();
    Json Call(const char* command, Json fields = Json::object());
    Json Wait(const std::function<bool(const Json&)>& predicate, DWORD seconds = 30);
    void Close();

private:
    Handle input_, output_, error_;
    std::unique_ptr<ChildProcess> process_;
    Path errorPath_;
    uint64_t nextId_ = 0;
};

struct CaptureOptions
{
    std::wstring arguments;
    uint32_t limit = 512;
    bool instructions = true, comOnly = false, followChildren = false;
    std::optional<uint64_t> apiMask, categoryMask;
    std::vector<std::string> excludedApis;
};

Path Launch(Collector& collector, const Context& context, const CaptureOptions& options,
            Json overrides = Json::object());

class Capture
{
public:
    template<class Verify>
    static void Run(const Context& context, const CaptureOptions& options, Verify&& verify, DWORD timeout = 90)
    {
        Capture capture(context, options, timeout);
        capture.CheckExited();
        std::invoke(std::forward<Verify>(verify), capture);
    }
    Capture(const Context& context, const CaptureOptions& options = {}, DWORD timeout = 90);
    const Json& Calls() const;
    Json Calls(const std::string& condition, const Json& parameters = Json::array()) const;
    Json Find(const std::string& names, const std::string& modules = ".*") const;
    Json Details(const Json& row);
    void CheckExited();
    void CheckDiagnostics(bool allowUnfinished = false);
    Collector& collector;
    Path database;
    Json status;

private:
    mutable std::optional<Json> calls_;
};

Path FirstMethod(const Context& context, const std::string& method, const Json& excluded,
                 const std::wstring& arguments = L"");

void Inspect(const Context& context, const Path& inspector, const char* mode, const Json& details,
             DWORD timeout = 60000);
}

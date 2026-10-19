#include "SqliteCatalog.h"
#include "TestSupport.h"
#include <sqlite3.h>

namespace Detourist::Tests
{
void Require(bool condition, const std::string& message, const Json& detail)
{
    if (!condition) throw std::runtime_error(message + (detail.is_null() ? "" : ": " + detail.dump()));
}

std::string Text(const Path& path) { return Utf8(path.wstring()); }

std::string ReadLog(const Path& path)
{
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

Handle OpenLog(const Path& path)
{
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr));
    Check(static_cast<bool>(file), "Create test log");
    return file;
}

class ChildProcess
{
public:
    ChildProcess(const Path& executable, HANDLE input, HANDLE output, HANDLE error,
                 const std::wstring& arguments = L"");
    ~ChildProcess();
    DWORD Wait(DWORD timeout) const;
    DWORD Pid() const { return GetProcessId(process_.get()); }
    bool Running() const { return WaitForSingleObject(process_.get(), 0) == WAIT_TIMEOUT; }

private:
    Handle job_, process_;
};

ChildProcess::ChildProcess(const Path& executable, HANDLE input, HANDLE output, HANDLE error,
                           const std::wstring& arguments)
{
    // Closing the job also releases a traced child held at a breakpoint after a failed assertion.
    job_.reset(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Check(job_ && SetInformationJobObject(job_.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
          "Create test process job");
    STARTUPINFOW startup{sizeof(startup)};
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input;
    startup.hStdOutput = output;
    startup.hStdError = error;
    PROCESS_INFORMATION created{};
    auto command = Quote(executable) + (arguments.empty() ? L"" : L" " + arguments);
    Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                         CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &created),
          "Start test process");
    process_.reset(created.hProcess);
    Handle thread(created.hThread);
    if (!AssignProcessToJobObject(job_.get(), process_.get()) || ResumeThread(thread.get()) == DWORD(-1))
    {
        auto errorCode = GetLastError();
        TerminateProcess(process_.get(), ERROR_CANCELLED);
        WaitForSingleObject(process_.get(), 5000);
        throw std::runtime_error("Cannot start owned test process: " + Utf8(ErrorText(errorCode)));
    }
}

ChildProcess::~ChildProcess()
{
    if (WaitForSingleObject(process_.get(), 0) == WAIT_TIMEOUT)
    {
        TerminateJobObject(job_.get(), ERROR_CANCELLED);
        WaitForSingleObject(process_.get(), 5000);
    }
}

DWORD ChildProcess::Wait(DWORD timeout) const
{
    Require(WaitForSingleObject(process_.get(), timeout) == WAIT_OBJECT_0, "Test process timed out");
    DWORD code = 0;
    Check(GetExitCodeProcess(process_.get(), &code), "Read test process result");
    return code;
}

TargetProcess::TargetProcess(const Context& context, const std::wstring& arguments)
{
    output_ = OpenLog(context.directory / ("target-" + std::to_string(GetTickCount64()) + ".log"));
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    input_.reset(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr));
    Check(bool(input_), "Open target input");
    process_ = std::make_unique<ChildProcess>(context.target, input_.get(), output_.get(), output_.get(),
                                              Wide(TargetArguments(context, arguments)));
}

TargetProcess::~TargetProcess() = default;
DWORD TargetProcess::Pid() const { return process_->Pid(); }
bool TargetProcess::Running() const { return process_->Running(); }
DWORD TargetProcess::Wait(DWORD timeout) const { return process_->Wait(timeout); }

std::string RunTarget(const Path& executable, const Path& directory, DWORD timeout)
{
    return RunTarget(executable, directory, L"", timeout);
}

std::string TargetArguments(const Context& context, const std::wstring& arguments)
{
    return Utf8((context.self ? L"--target " : L"") + arguments);
}

Json TargetCalls(const Context& context, const Path& database)
{
    auto name = Text(context.target.filename());
    std::ranges::transform(name, name.begin(), [](unsigned char c) { return static_cast<char>(tolower(c)); });
    auto bounds = Query(database, "SELECT base,size FROM modules WHERE lower(path) LIKE ?", Json::array({"%" + name}));
    Json result = Json::array();
    for (const auto& row : Calls(database))
        if (std::ranges::any_of(bounds, [&](const Json& bound)
        {
            auto caller = row["caller"].get<uint64_t>(), base = bound["base"].get<uint64_t>();
            return caller >= base && caller - base < bound["size"].get<uint64_t>();
        }))
            result.push_back(row);
    return result;
}

std::string RunTarget(const Context& context, const std::wstring& arguments, DWORD timeout)
{
    return RunTarget(context.target, context.directory, Wide(TargetArguments(context, arguments)), timeout);
}

std::string RunTarget(const Path& executable, const Path& directory, const std::wstring& arguments, DWORD timeout)
{
    // Run the same native workload without tracing and retain its output for comparison.
    auto log = directory / L"baseline.log";
    auto output = OpenLog(log);
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr));
    Check(static_cast<bool>(input), "Open test input");
    ChildProcess process(executable, input.get(), output.get(), output.get(), arguments);
    auto code = process.Wait(timeout);
    output.reset();
    auto text = ReadLog(log);
    if (code == 77) throw Skipped("The installed provider is unavailable");
    Require(code == 0, "Untraced target failed with exit code " + std::to_string(code) + "\n" + text);
    return text;
}

Collector::Collector(const Path& executable, const Path& directory) : errorPath_(directory / L"collector.log")
{
    // Only the collector's ends of the IPC pipes are inherited by the new process.
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    Handle childInput, childOutput;
    HANDLE read = nullptr, write = nullptr;
    Check(CreatePipe(&read, &write, &security, 0), "Create collector input pipe");
    childInput.reset(read);
    input_.reset(write);
    Check(SetHandleInformation(input_.get(), HANDLE_FLAG_INHERIT, 0), "Keep collector input private");
    Check(CreatePipe(&read, &write, &security, 0), "Create collector output pipe");
    output_.reset(read);
    childOutput.reset(write);
    Check(SetHandleInformation(output_.get(), HANDLE_FLAG_INHERIT, 0), "Keep collector output private");
    error_ = OpenLog(errorPath_);
    process_ = std::make_unique<ChildProcess>(executable, childInput.get(), childOutput.get(), error_.get());
}

Collector::~Collector() { input_.reset(); }

Json Collector::Call(const char* command, Json fields)
{
    // Exercise the executable's JSON protocol with the same request identities as the desktop client.
    fields["command"] = command;
    fields["id"] = ++nextId_;
    if (!strcmp(command, "launch") && !fields.contains("startMinimized")) fields["startMinimized"] = true;
    auto request = fields.dump() + '\n';
    DWORD written = 0;
    Check(WriteFile(input_.get(), request.data(), static_cast<DWORD>(request.size()), &written, nullptr),
          "Write collector request");
    Require(written == request.size(), "Collector request was incomplete");
    std::string line;
    std::array<char, 16384> buffer{};
    auto deadline = GetTickCount64() + 25000;
    while (line.empty() || line.back() != '\n')
    {
        DWORD available = 0, bytes = 0;
        if (!PeekNamedPipe(output_.get(), nullptr, 0, nullptr, &available, nullptr))
            throw std::runtime_error("Collector pipe closed\n" + ReadLog(errorPath_));
        if (!available)
        {
            if (GetTickCount64() >= deadline)
                throw std::runtime_error("Collector response timed out\n" + ReadLog(errorPath_));
            Sleep(10);
            continue;
        }
        Check(ReadFile(output_.get(), buffer.data(), std::min(available, static_cast<DWORD>(buffer.size())), &bytes,
                       nullptr),
              "Read collector response");
        line.append(buffer.data(), bytes);
    }
    auto response = Json::parse(line);
    Require(response.at("id") == nextId_ && response.at("ok") == true, "Collector request failed", response);
    return response.at("data");
}

Json Collector::Wait(const std::function<bool(const Json&)>& predicate, DWORD seconds)
{
    auto deadline = GetTickCount64() + uint64_t{seconds} * 1000;
    Json status;
    do
    {
        status = Call("status");
        if (predicate(status)) return status;
        Sleep(20);
    } while (GetTickCount64() < deadline);
    throw std::runtime_error("Capture timed out: " + status.dump());
}

void Collector::Close()
{
    input_.reset();
    auto code = process_->Wait(15000);
    Require(code == 0, "Collector failed with exit code " + std::to_string(code) + "\n" + ReadLog(errorPath_));
    process_.reset();
    error_.reset();
}

Json Query(const Path& database, const char* sql, const Json& parameters)
{
    // Read persisted capture data independently of the collector's query implementation.
    sqlite3* raw = nullptr;
    auto opened = sqlite3_open_v2(Text(database).c_str(), &raw, SQLITE_OPEN_READONLY, nullptr);
    if (opened == SQLITE_OK) opened = SelectCatalogArchitecture(raw, sizeof(void*));
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(raw, sqlite3_close);
    Require(opened == SQLITE_OK, "Cannot read test database: " + Text(database));
    sqlite3_stmt* prepared = nullptr;
    auto result = sqlite3_prepare_v2(raw, sql, -1, &prepared, nullptr);
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(prepared, sqlite3_finalize);
    Require(result == SQLITE_OK, "Cannot prepare test query: " + std::string(sqlite3_errmsg(raw)));
    Require(static_cast<size_t>(sqlite3_bind_parameter_count(prepared)) == parameters.size(),
            "Test query parameter count differs");
    for (size_t index = 0; index < parameters.size(); ++index)
    {
        const auto& value = parameters[index];
        auto ordinal = static_cast<int>(index + 1);
        if (value.is_string())
        {
            const auto& text = value.get_ref<const std::string&>();
            result = sqlite3_bind_text(prepared, ordinal, text.c_str(), -1, SQLITE_TRANSIENT);
        }
        else
            result = sqlite3_bind_int64(prepared, ordinal, value.get<int64_t>());
        Require(result == SQLITE_OK, "Cannot bind test query parameter");
    }
    Json rows = Json::array();
    while ((result = sqlite3_step(prepared)) == SQLITE_ROW)
    {
        Json row = Json::object();
        for (int column = 0; column < sqlite3_column_count(prepared); ++column)
        {
            auto& value = row[sqlite3_column_name(prepared, column)];
            switch (sqlite3_column_type(prepared, column))
            {
            case SQLITE_INTEGER:
                value = sqlite3_column_int64(prepared, column);
                break;
            case SQLITE_FLOAT:
                value = sqlite3_column_double(prepared, column);
                break;
            case SQLITE_TEXT:
                value = reinterpret_cast<const char*>(sqlite3_column_text(prepared, column));
                break;
            case SQLITE_BLOB:
            {
                auto data = static_cast<const uint8_t*>(sqlite3_column_blob(prepared, column));
                auto bytes = sqlite3_column_bytes(prepared, column);
                value = Json::binary(bytes ? std::vector<uint8_t>(data, data + bytes) : std::vector<uint8_t>());
                break;
            }
            default:
                value = nullptr;
            }
        }
        rows.push_back(std::move(row));
    }
    Require(result == SQLITE_DONE, "Cannot finish test query: " + std::string(sqlite3_errmsg(raw)));
    return rows;
}

uint64_t UInt64(const Json& blob)
{
    const auto& bytes = blob.get_binary();
    Require(bytes.size() == sizeof(uint64_t), "Expected one x64 argument");
    uint64_t value = 0;
    memcpy(&value, bytes.data(), sizeof(value));
    return value;
}

std::wstring Quote(const Path& path)
{
    // Quote Windows command-line arguments, including trailing backslashes before the closing quote.
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (auto character : path.wstring())
    {
        if (character == L'\\')
        {
            ++slashes;
            continue;
        }
        result.append(slashes * (character == L'"' ? 2 : 1), L'\\');
        slashes = 0;
        if (character == L'"') result += L'\\';
        result += character;
    }
    result.append(slashes * 2, L'\\');
    return result + L'"';
}

void WriteJson(const Path& path, const Json& value)
{
    std::ofstream stream(path, std::ios::binary);
    stream << value.dump();
    Require(static_cast<bool>(stream), "Cannot write test data: " + Text(path));
}

Bytes Data(const Json& value)
{
    if (value.is_null()) return {};
    return value.is_binary() ? Bytes(value.get_binary()) : value.get<Bytes>();
}

Bytes Prefix(Bytes data, size_t limit)
{
    if (data.size() > limit) data.resize(limit);
    return data;
}

Bytes Integer(uint64_t value, size_t size)
{
    Require(size <= 8, "Invalid integer width");
    auto begin = reinterpret_cast<const uint8_t*>(&value);
    return {begin, begin + size};
}

Json Report(const Path& path) { return Json::parse(ReadLog(path)); }

Image::Image(const Path& path)
{
    auto text = ReadLog(path);
    bytes.assign(text.begin(), text.end());
    auto dos = Read<IMAGE_DOS_HEADER>(bytes);
    Require(dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= 0, "Invalid DOS image header");
    headers = Read<IMAGE_NT_HEADERS64>(bytes, dos.e_lfanew);
    Require(headers.Signature == IMAGE_NT_SIGNATURE && headers.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
                headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            "Expected an x64 PE image");
    auto table = dos.e_lfanew + 24u + headers.FileHeader.SizeOfOptionalHeader;
    for (size_t index = 0; index < headers.FileHeader.NumberOfSections; ++index)
        sections.push_back(Read<IMAGE_SECTION_HEADER>(bytes, table + index * sizeof(IMAGE_SECTION_HEADER)));
}

size_t Image::Offset(uint32_t rva) const
{
    for (const auto& section : sections)
        if (rva >= section.VirtualAddress &&
            rva - section.VirtualAddress < std::max(section.Misc.VirtualSize, section.SizeOfRawData))
        {
            auto offset = size_t(section.PointerToRawData) + rva - section.VirtualAddress;
            Require(offset < bytes.size(), "Image RVA lies outside the file");
            return offset;
        }
    throw std::runtime_error("Image RVA has no section");
}

Json Image::Exports() const
{
    auto directory = headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    Json result = Json::object();
    if (!directory.VirtualAddress) return result;
    auto table = Read<IMAGE_EXPORT_DIRECTORY>(bytes, Offset(directory.VirtualAddress));
    auto text = [&](uint32_t rva)
    {
        auto start = Offset(rva);
        auto end = std::find(bytes.begin() + start, bytes.end(), uint8_t{});
        Require(end != bytes.end(), "Unterminated PE export name");
        return std::string(bytes.begin() + start, end);
    };
    for (uint32_t index = 0; index < table.NumberOfNames; ++index)
    {
        auto name = text(Read<uint32_t>(bytes, Offset(table.AddressOfNames + index * 4)));
        auto ordinal = Read<uint16_t>(bytes, Offset(table.AddressOfNameOrdinals + index * 2));
        Require(ordinal < table.NumberOfFunctions, "PE export ordinal is outside its function table");
        auto rva = Read<uint32_t>(bytes, Offset(table.AddressOfFunctions + ordinal * 4));
        bool forwarded = rva >= directory.VirtualAddress && rva - directory.VirtualAddress < directory.Size;
        bool executable = std::ranges::any_of(sections, [&](const auto& section)
        {
            return rva >= section.VirtualAddress &&
                   rva - section.VirtualAddress < std::max(section.Misc.VirtualSize, section.SizeOfRawData) &&
                   (section.Characteristics & IMAGE_SCN_MEM_EXECUTE);
        });
        result[name] = {{"rva", rva}, {"forwarder", forwarded ? text(rva) : ""}, {"executable", executable}};
    }
    return result;
}

Json InImage(const Json& rows, const Json& report)
{
    Json result = Json::array();
    for (const auto& row : rows)
        if (row["caller"] >= report["image"][0] && row["caller"] < report["image"][1]) result.push_back(row);
    return result;
}

void CompareCalls(const Json& baseline, const Json& report, std::initializer_list<const char*> fields)
{
    Require(baseline["calls"].size() == report["calls"].size(), "Native call count differs", report);
    for (size_t index = 0; index < baseline["calls"].size(); ++index)
        for (auto field : fields)
            Require(baseline["calls"][index][field] == report["calls"][index][field],
                    "Native result differs: " + std::string(field), report["calls"][index]);
}

Bytes Encode(const std::string& text, bool wide, bool terminated)
{
    Bytes bytes;
    if (wide)
    {
        auto value = Wide(text);
        auto begin = reinterpret_cast<const uint8_t*>(value.data());
        bytes.assign(begin, begin + value.size() * sizeof(wchar_t));
    }
    else
        bytes.assign(text.begin(), text.end());
    if (terminated) bytes.insert(bytes.end(), wide ? 2 : 1, 0);
    return bytes;
}

Bytes Unhex(const std::string& text)
{
    Require(text.size() % 2 == 0, "Invalid hexadecimal test data");
    Bytes bytes;
    for (size_t index = 0; index < text.size(); index += 2)
        bytes.push_back(static_cast<uint8_t>(std::stoul(text.substr(index, 2), nullptr, 16)));
    return bytes;
}

std::string String(const Bytes& bytes, bool wide)
{
    if (!wide) return {bytes.begin(), bytes.end()};
    std::wstring value(bytes.size() / 2, L'\0');
    memcpy(value.data(), bytes.data(), value.size() * 2);
    return Utf8(value);
}

std::vector<Value> Values(const Json& payload)
{
    // Decode the persisted wire format independently of the production capture reader.
    auto bytes = Data(payload);
    std::vector<Value> result;
    for (size_t offset = 0; offset < bytes.size();)
    {
        Require(bytes.size() - offset >= 24, "Incomplete capture header");
        auto count = Read<uint32_t>(bytes, offset + 12);
        Value value{Read<uint32_t>(bytes, offset),
                    Read<uint32_t>(bytes, offset + 4),
                    Read<uint32_t>(bytes, offset + 8),
                    Read<uint64_t>(bytes, offset + 16),
                    {}};
        offset += 24;
        Require(count <= bytes.size() - offset, "Incomplete captured value");
        value.data.assign(bytes.begin() + offset, bytes.begin() + offset + count);
        result.push_back(std::move(value));
        offset += count;
    }
    return result;
}

std::vector<Bytes> Snapshots(const Json& payload, uint32_t index, uint32_t kind)
{
    std::vector<Bytes> result;
    for (const auto& value : Values(payload))
        if (value.index == index && value.kind == kind) result.push_back(value.data);
    return result;
}

std::vector<Value> Regions(const Json& payload, const RegionFilter& filter) { return Regions(Values(payload), filter); }

std::vector<Value> Regions(const std::vector<Value>& values, const RegionFilter& filter)
{
    return Select(values, [&](const Value& value)
    {
        return (!filter.parameter || (value.index & filter.parameterMask) == *filter.parameter) &&
               (!filter.kind || value.kind == *filter.kind) && (value.flags & filter.required) == filter.required &&
               !(value.flags & filter.excluded) && (!filter.element || (value.flags >> 16) == *filter.element) &&
               (!filter.tag || ((value.flags >> 8) & filter.tagMask) == *filter.tag) &&
               (!filter.record || (value.index >> 8) == *filter.record);
    });
}

void CheckLimit(const Json& row, size_t limit)
{
    for (auto phase : {"input", "output"})
        for (const auto& value : Values(row[phase]))
            Require(value.data.size() <= limit, "Captured value exceeds buffer limit", row);
}

Json Named(const Json& rows, const std::string& name)
{
    return Select(rows, [&](const Json& row) { return row["name"] == name; });
}

Json Matching(const Json& rows, const std::string& names, const std::string& modules)
{
    std::regex name(names, std::regex::ECMAScript | std::regex::optimize);
    std::regex module(modules, std::regex::ECMAScript | std::regex::optimize);
    return Select(rows, [&](const Json& row)
    {
        return row["name"].is_string() && row["module"].is_string() &&
               std::regex_match(row["name"].get_ref<const std::string&>(), name) &&
               std::regex_match(row["module"].get_ref<const std::string&>(), module);
    });
}

Json Tsv(const Path& path)
{
    Json rows = Json::array();
    std::istringstream stream(ReadLog(path));
    std::string line;
    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        Json row = Json::array();
        size_t begin = 0, end = 0;
        do
        {
            end = line.find('\t', begin);
            row.push_back(line.substr(begin, end == std::string::npos ? end : end - begin));
            begin = end + 1;
        } while (end != std::string::npos);
        rows.push_back(std::move(row));
    }
    Require(!rows.empty(), "Target report is empty: " + Text(path));
    return rows;
}

Json Fields(const Path& path)
{
    Json result = Json::array();
    std::istringstream stream(ReadLog(path));
    std::string line;
    while (std::getline(stream, line))
    {
        Json row = Json::array();
        std::istringstream fields(line);
        std::string field;
        while (fields >> field)
            row.push_back(field);
        if (!row.empty()) result.push_back(row);
    }
    Require(!result.empty(), "Target report is empty: " + Text(path));
    return result;
}

Json JsonLines(const Path& path)
{
    Json result = Json::array();
    std::istringstream stream(ReadLog(path));
    std::string line;
    while (std::getline(stream, line))
        if (!line.empty()) result.push_back(Json::parse(line));
    return result;
}

Json Columns(const Path& path, std::initializer_list<const char*> names, std::initializer_list<const char*> numbers,
             std::initializer_list<const char*> hexadecimal)
{
    return Columns(Tsv(path), names, numbers, hexadecimal);
}

Json Columns(const Json& rows, std::initializer_list<const char*> names, std::initializer_list<const char*> numbers,
             std::initializer_list<const char*> hexadecimal)
{
    Json result = Json::array();
    for (const auto& fields : rows)
    {
        Require(fields.size() == names.size(), "Target report column count differs", fields);
        Json row;
        size_t index = 0;
        for (auto name : names)
            row[name] = fields[index++];
        for (auto name : numbers)
        {
            auto text = row[name].get<std::string>();
            row[name] = text.starts_with('-') ? Json(std::stoll(text)) : Json(std::stoull(text));
        }
        for (auto name : hexadecimal)
            row[name] = Number(row[name], 16);
        result.push_back(row);
    }
    return result;
}

std::string Key(const Json& row, std::initializer_list<const char*> fields)
{
    Json key = Json::array();
    for (auto field : fields)
        key.push_back(row[field]);
    return key.dump();
}

Json Group(const Json& rows, std::initializer_list<const char*> fields)
{
    Json result = Json::object();
    for (const auto& row : rows)
        result[Key(row, fields)].push_back(row);
    return result;
}

Json Without(Json row, std::initializer_list<const char*> fields)
{
    for (auto field : fields)
        row.erase(field);
    return row;
}

uint64_t Number(const Json& value, int base)
{
    return value.is_string() ? std::stoull(value.get<std::string>(), nullptr, base) : value.get<uint64_t>();
}

bool Context::Has(const wchar_t* option) const
{
    return std::ranges::any_of(arguments, [option](auto value) { return !wcscmp(value, option); });
}

std::wstring Context::Option(const wchar_t* option, const std::wstring& fallback) const
{
    for (size_t index = 0; index + 1 < arguments.size(); ++index)
        if (!wcscmp(arguments[index], option)) return arguments[index + 1];
    return fallback;
}

Path Context::Extra(size_t index) const
{
    Require(index < arguments.size(), "Missing test argument");
    return arguments[index];
}

Path Context::Optional(size_t index) const
{
    return index < arguments.size() && !std::wstring_view(arguments[index]).starts_with(L"--") ? Path(arguments[index])
                                                                                               : Path{};
}

Collector& Context::GetCollector() const
{
    if (!session->collector) session->collector = std::make_shared<Collector>(collector, directory);
    return *session->collector;
}

Path Launch(Collector& collector, const Context& context, const CaptureOptions& options, Json overrides)
{
    auto database = context.directory / ("calls-" + std::to_string(GetTickCount64()) + ".sqlite");
    auto hello = collector.Call("hello");
    Json fields{{"database", Text(database)},
                {"executable", Text(context.target)},
                {"arguments", TargetArguments(context, options.arguments)},
                {"apiMask", options.comOnly ? hello["comMask"] : hello["allApis"]},
                {"bufferLimit", options.limit},
                {"followChildren", options.followChildren},
                {"instructionEngine", options.instructions},
                {"excludedApis", options.excludedApis}};
    if (options.apiMask) fields["apiMask"] = *options.apiMask;
    if (options.categoryMask) fields["categoryMask"] = *options.categoryMask;
    fields.update(overrides);
    collector.Call("launch", fields);
    return database;
}

Capture::Capture(const Context& context, const CaptureOptions& options, DWORD timeout)
    : collector(context.GetCollector()), database(Launch(collector, context, options))
{
    status = collector.Wait([](const Json& state) { return state["finished"] == true; }, timeout);
    Require(!status["message"].get<std::string>().contains("nonzero exit code"), "Traced target failed", status);
}

Json Capture::Calls(const std::string& condition, const Json& parameters) const
{
    return Tests::Calls(database, condition, parameters);
}

const Json& Capture::Calls() const
{
    if (!calls_) calls_ = Tests::Calls(database);
    return *calls_;
}

Json Capture::Find(const std::string& names, const std::string& modules) const
{
    // Match API metadata before reading the corresponding argument and memory payloads.
    auto bindings =
        Query(database,
              "SELECT DISTINCT c.target,c.api,COALESCE(d.name,a.name) name,lower(COALESCE(d.module,a.module)) module "
              "FROM calls c LEFT JOIN apis a ON a.target=0 AND a.id=c.api "
              "LEFT JOIN apis d ON d.target=c.target AND d.id=c.api WHERE c.ended IS NOT NULL");
    auto selected = Matching(bindings, names, modules);
    if (selected.empty()) return Json::array();
    std::string condition = "(c.target,c.api) IN (";
    Json parameters = Json::array();
    for (const auto& binding : selected)
    {
        if (!parameters.empty()) condition += ',';
        condition += "(?,?)";
        parameters.push_back(binding["target"]);
        parameters.push_back(binding["api"]);
    }
    return Calls(condition + ')', parameters);
}

Json Calls(const Path& database, const std::string& condition, const Json& parameters)
{
    auto sql =
        "SELECT c.*,COALESCE(d.name,a.name) name,lower(COALESCE(d.module,a.module)) module,"
        "COALESCE(d.parameters,a.parameters) parameters,COALESCE(d.argument_count,a.argument_count) argument_count "
        "FROM calls c LEFT JOIN apis a ON a.target=0 AND a.id=c.api "
        "LEFT JOIN apis d ON d.target=c.target AND d.id=c.api WHERE c.ended IS NOT NULL" +
        (condition.empty() ? "" : " AND (" + condition + ")") + " ORDER BY c.id";
    return Query(database, sql.c_str(), parameters);
}

Json Capture::Details(const Json& row)
{
    return collector.Call("details", {{"database", Text(database)}, {"target", row["target"]}, {"callId", row["id"]}});
}

void Capture::CheckExited()
{
    auto targets = collector.Call("page", {{"database", Text(database)}, {"limit", 1}})["targets"];
    Require(!targets.empty() &&
                std::ranges::all_of(targets, [](const Json& target) { return target["state"] == "Exited"; }),
            "Target did not exit cleanly", targets);
}

void Capture::CheckDiagnostics(bool allowUnfinished)
{
    auto rows = Query(database, "SELECT message FROM diagnostics");
    Require(rows.empty() || (allowUnfinished && rows.size() == 1 &&
                             rows[0]["message"] == "Capture ended with unfinished calls or uncommitted records."),
            "Unexpected capture diagnostics", rows);
}

Path FirstMethod(const Context& context, const std::string& method, const Json& excluded, const std::wstring& arguments)
{
    // An excluded producer must discover its returned interface before that interface's first entry stop.
    Collector collector(context.collector, context.directory);
    auto hello = collector.Call("hello");
    auto api = Named(hello["catalog"], method)[0]["id"];
    auto database = context.directory / ("first-method-" + std::to_string(GetTickCount64()) + ".sqlite");
    collector.Call("launch", {{"database", Text(database)},
                              {"executable", Text(context.target)},
                              {"arguments", TargetArguments(context, arguments)},
                              {"instructionEngine", true},
                              {"apiMask", hello["comMask"]},
                              {"bufferLimit", 16},
                              {"followChildren", false},
                              {"excludedApis", excluded},
                              {"entryApi", api}});
    auto stopped =
        collector.Wait([](const Json& status) { return status["breakpoint"] == true || status["finished"] == true; });
    Require(stopped["breakpoint"] == true && stopped["leaving"] == false && stopped["stoppedCall"]["name"] == method,
            "First-method breakpoint missing", stopped);
    collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
    collector.Call("continue", {{"callId", stopped["stoppedCall"]["id"]}});
    auto finished = collector.Wait([](const Json& status) { return status["finished"] == true; }, 45);
    Require(!finished["message"].get<std::string>().contains("nonzero exit code"), "Breakpoint target failed",
            finished);
    collector.Close();
    return database;
}

void Inspect(const Context& context, const Path& inspector, const char* mode, const Json& details, DWORD timeout)
{
    if (inspector.empty()) return;
    auto path = context.directory / L"inspection.json";
    WriteJson(path, details);
    wchar_t executable[32768]{};
    Check(SearchPathW(nullptr, L"dotnet.exe", nullptr, static_cast<DWORD>(std::size(executable)), executable,
                      nullptr) != 0,
          "Find desktop test runtime");
    auto output =
        RunTarget(executable, context.directory, Quote(inspector) + L" " + Wide(mode) + L" " + Quote(path), timeout);
    std::cout << output;
}

void RemoveTestArtifacts(const Path& directory)
{
    // Allow transient sharing locks to clear before removing completed test artifacts.
    const auto deadline = GetTickCount64() + 5000;
    for (;;)
    {
        try
        {
            std::filesystem::remove_all(directory);
            return;
        }
        catch (const std::filesystem::filesystem_error& error)
        {
            if ((error.code() != std::error_code(ERROR_SHARING_VIOLATION, std::system_category()) &&
                error.code() != std::error_code(ERROR_LOCK_VIOLATION, std::system_category())) ||
                GetTickCount64() >= deadline) throw;
            Sleep(10);
        }
    }
}

int Run(int argc, wchar_t** argv, void (*test)(const Context&), int (*target)(int, wchar_t**))
{
    if (target && argc > 1 && !wcscmp(argv[1], L"--target"))
    {
        // Workload mode preserves argv[0] and forwards the workload's original argument list.
        for (int index = 1; index < argc; ++index)
            argv[index] = argv[index + 1];
        return target(argc - 1, argv);
    }
    Path directory;
    bool retain = false;
    try
    {
        Require(argc >= (target ? 2 : 3), target ? "Usage: <test> <collector> [options] | --target [arguments]"
                                                 : "Usage: <test> <collector> <target> [options]");

        // Keep each run's captures and logs together, retaining them when a check fails.
        auto temporary = std::filesystem::canonical(std::filesystem::temp_directory_path());
        auto name = L"Detourist-Cpp-" + std::to_wstring(GetCurrentProcessId()) + L"-";
        auto sequence = GetTickCount64();
        auto offset = target ? 2 : 3;
        for (int index = offset; index + 1 < argc; ++index)
            if (!wcscmp(argv[index], L"--artifact") || !wcscmp(argv[index], L"--artifacts"))
            {
                directory = std::filesystem::absolute(argv[index + 1]);
                retain = true;
            }
        if (retain)
        {
            std::filesystem::create_directories(directory);
            Require(std::filesystem::is_empty(directory), "Use a fresh capture directory");
        }
        else
        {
            do
            {
                directory = temporary / (name + std::to_wstring(sequence++));
            } while (!std::filesystem::create_directory(directory));
        }
        Context context{std::filesystem::absolute(argv[1]),
                        std::filesystem::absolute(target ? argv[0] : argv[2]),
                        directory,
                        {argv + offset, static_cast<size_t>(argc - offset)},
                        target != nullptr};
        test(context);
        if (auto& collector = context.session->collector; collector)
        {
            collector->Close();
            collector.reset();
        }
        if (!retain)
        {
            Require(std::filesystem::canonical(directory).parent_path() == temporary,
                    "Test artifacts are outside the temporary directory");
            RemoveTestArtifacts(directory);
        }
        std::cout << "PASS: " << Text(Path(argv[0]).stem()) << '\n';
        return 0;
    }
    catch (const Skipped& error)
    {
        std::cout << "SKIP: " << error.what() << '\n';
        if (!retain && !directory.empty() &&
            std::filesystem::canonical(directory).parent_path() ==
                std::filesystem::canonical(std::filesystem::temp_directory_path()))
            RemoveTestArtifacts(directory);
        return 77;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL: " << error.what() << '\n';
        if (!directory.empty()) std::cerr << "Artifacts: " << Text(directory) << '\n';
        return 1;
    }
}
}

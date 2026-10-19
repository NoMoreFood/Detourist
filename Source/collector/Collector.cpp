#include "ApiCatalog.h"
#include "Session.h"
#include "Inventory.h"
#include "WindowSpy.h"
#include "NetApiRecordLayouts.h"
#include "RpcCapture.h"
#include <objbase.h>
#include <fcntl.h>
#include <nlohmann/json.hpp>
#include <charconv>
#include <array>
#include <algorithm>
#include <cstdio>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <string_view>
#include <tuple>
#include <condition_variable>
#include <deque>
#include <shared_mutex>

namespace Detourist
{
using Json = nlohmann::json;
std::shared_mutex CatalogAccess;

constexpr size_t MaxOpenViews = 16;
constexpr uint64_t DefaultRowsLimit = 128;
constexpr uint64_t DefaultPageLimit = 200;
constexpr uint64_t MaxPageLimit = 1000;
constexpr uint64_t DefaultSliceBudgetMs = 20;
constexpr uint64_t DefaultTimelineBudgetMs = 100;
constexpr uint64_t MaxSliceBudgetMs = 1000;
constexpr uint64_t DefaultTimelineBuckets = 200;
constexpr uint64_t MaxTimelineBuckets = 2000;
constexpr uint64_t DefaultQueryTimeoutMs = 30000;
constexpr size_t MaxPendingQueries = 64;
constexpr size_t MaxPendingQueryBytes = 8 * 1024 * 1024;
constexpr size_t MaxCollectorRequestBytes = 2 * 1024 * 1024;
constexpr size_t SummaryPreviewChars = 64;

bool IsViewCommand(const std::string& command)
{
    return command == "view" || command == "rows" || command == "locate" || command == "release" || command == "seek" ||
        command == "mark" || command == "summary" || command == "timeline";
}

int32_t ParseCategory(const Json& request)
{
    auto category = request.value("category", int64_t{-1});
    if (category < -1 || category >= static_cast<int64_t>(ApiCategory::Count))
        throw std::runtime_error("Select a valid API category.");
    return static_cast<int32_t>(category);
}

uint64_t Integer(const Json& value)
{
    if (value.is_number_unsigned()) return value.get<uint64_t>();
    if (value.is_number_integer() && value.get<int64_t>() >= 0) return value.get<uint64_t>();
    if (!value.is_string()) throw std::runtime_error("Expected an unsigned integer or hexadecimal string.");
    const auto& text = value.get_ref<const std::string&>();
    std::string_view digits(text);
    int base = 10;
    if (digits.starts_with("0x") || digits.starts_with("0X")) { digits.remove_prefix(2); base = 16; }
    uint64_t result = 0;
    auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), result, base);
    if (digits.empty() || parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size())
        throw std::runtime_error("Invalid unsigned integer.");
    return result;
}

uint64_t Number(const Json& request, const char* field, uint64_t fallback = 0,
    uint64_t maximum = std::numeric_limits<uint64_t>::max())
{
    auto found = request.find(field);
    auto value = found == request.end() ? fallback : Integer(*found);
    if (value > maximum) throw std::runtime_error(std::string(field) + " exceeds the supported range.");
    return value;
}

std::string Hex(uint64_t value)
{
    char text[24];
    std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(value));
    return text;
}

Json ProcessList()
{
    auto processes = Json::array();
    for (const auto& process : Processes())
        processes.push_back({{"pid", process.id}, {"name", Utf8(process.name)},
            {"architecture", Utf8(process.architecture)}});
    return processes;
}

bool BreakableApi(int64_t api)
{
    return api == -1 || (api >= 0 && api < static_cast<int64_t>(Api::Count)) ||
        (api >= InterfaceApiStart && api <= INT32_MAX);
}

Json Arguments(uint32_t count, const uint64_t* values)
{
    auto result = Json::array();
    for (uint32_t index = 0; index < count; ++index) result.push_back(Hex(values[index]));
    return result;
}

Json RpcDescription(const RpcCallInfo& info)
{
    if (info.parameterCount > std::size(info.parameters) || info.argumentCount > MaximumArguments ||
        info.prefix > info.argumentCount) throw std::runtime_error("Invalid RPC descriptor.");
    wchar_t identifier[48]{};
    StringFromGUID2(info.interfaceId, identifier, static_cast<int>(std::size(identifier)));
    Json result{{"interface", Utf8(identifier)}, {"major", info.major}, {"minor", info.minor},
        {"procedure", info.procedure}, {"syntax", info.flags & RpcNdr64 ? "NDR64" : "NDR32"},
        {"flags", info.flags}, {"state", !(info.flags & RpcDescriptorValid) ? "Descriptor unavailable" :
            info.flags & RpcPartial ? "Partial decoding" : "Decoded"},
        {"prefix", info.prefix}, {"argumentCount", info.argumentCount},
        {"outputsDeferred", bool(info.flags & RpcOutputsDeferred)}};
    if (info.interfaceId == GUID{}) result["interface"] = "Unknown interface";
    if (info.flags & RpcPickling) result["operation"] = info.flags & RpcEncoding ? "Encoding" :
        info.flags & RpcDecoding ? "Decoding" : "Unknown serialization operation";
    if ((info.flags & (RpcObjectProcedure | RpcAsynchronous)) == (RpcObjectProcedure | RpcAsynchronous) &&
        info.procedure >= 3) result["operation"] = info.procedure & 1 ? "Begin" : "Finish";
    auto parameters = Json::array();
    for (uint32_t index = 0; index < info.parameterCount; ++index)
    {
        const auto& parameter = info.parameters[index];
        if (!(parameter.attributes & RpcReturn) && parameter.argument >= MaximumArguments)
            throw std::runtime_error("Invalid RPC parameter.");
        std::string type = RpcTypeName(parameter.type);
        for (uint32_t depth = 0; depth < std::min(parameter.pointerDepth, uint8_t{16}); ++depth) type += " *";
        parameters.push_back(
            {{"argument", parameter.argument}, {"attributes", parameter.attributes}, {"type", std::move(type)},
                {"typeId", static_cast<uint32_t>(parameter.type)}, {"pointerDepth", parameter.pointerDepth},
                {"width", parameter.width}, {"memorySize", parameter.memorySize}});
    }
    result["parameters"] = std::move(parameters);
    return result;
}

static std::string HexBytes(std::span<const std::byte> bytes)
{
    constexpr char digits[] = "0123456789ABCDEF";
    std::string encoded(bytes.size() * 2, '0');
    for (size_t index = 0; index < bytes.size(); ++index)
    {
        auto value = std::to_integer<unsigned>(bytes[index]);
        encoded[index * 2] = digits[value >> 4];
        encoded[index * 2 + 1] = digits[value & 15];
    }
    return encoded;
}

Json Snapshots(const std::vector<std::byte>& payload)
{
    // Send typed memory only when a call is inspected, keeping the event stream compact.
    auto result = Json::array();
    size_t position = 0;
    std::map<std::pair<uint32_t, uint32_t>, AutomationLink> arrays;
    std::map<std::tuple<uint32_t, uint32_t, uint32_t>, uint32_t> references;
    while (payload.size() - position >= sizeof(Value))
    {
        Value value;
        memcpy(&value, payload.data() + position, sizeof(value));
        auto stride = value.kind == ValueKind::ManagedArray ? static_cast<uint32_t>(value.originalBytes >> 32) : 0u;
        if (value.kind == ValueKind::ManagedArray)
            value.originalBytes = uint64_t{stride} * static_cast<uint32_t>(value.originalBytes);
        position += sizeof(value);
        if (value.capturedBytes > payload.size() - position)
            throw std::runtime_error("The call contains an invalid memory snapshot.");
        if (value.kind == ValueKind::RpcCall)
        {
            RpcCallInfo info{};
            if (value.capturedBytes != sizeof(info)) throw std::runtime_error("Invalid RPC descriptor.");
            memcpy(&info, payload.data() + position, sizeof(info));
            result.push_back({{"parameter", value.parameter}, {"kind", static_cast<uint32_t>(value.kind)},
                {"flags", value.flags}, {"originalBytes", value.originalBytes}, {"bytes", ""},
                {"rpc", RpcDescription(info)}});
            position += value.capturedBytes;
            continue;
        }
        RpcValueInfo rpc{};
        if (value.kind == ValueKind::RpcValue)
        {
            if (value.capturedBytes < sizeof(rpc)) throw std::runtime_error("Invalid RPC value.");
            memcpy(&rpc, payload.data() + position, sizeof(rpc));
            if (rpc.node >= RpcMaxValueNodes || rpc.parent != RpcNoParent && rpc.parent >= rpc.node ||
                rpc.type > RpcValueType::Union) throw std::runtime_error("Invalid RPC value.");
            position += sizeof(rpc);
            value.capturedBytes -= sizeof(rpc);
        }
        if (value.kind == ValueKind::AutomationLink)
        {
            if (value.capturedBytes != sizeof(AutomationLink))
                throw std::runtime_error("The call contains an invalid Automation link.");
            AutomationLink link{};
            memcpy(&link, payload.data() + position, sizeof(link));
            if (link.childArray == UINT32_MAX)
                references[{value.parameter, link.parentArray, link.element}] = link.variantType;
            else arrays[{value.parameter, link.childArray}] = link;
            position += value.capturedBytes;
            continue;
        }
        auto bytes = HexBytes(std::span(payload).subspan(position, value.capturedBytes));
        bool array = value.kind == ValueKind::SafeArray || value.kind == ValueKind::SafeArrayData ||
            value.kind == ValueKind::PropertyVector || value.kind == ValueKind::PropertyVectorData ||
            (value.flags & AutomationElement);
        auto parameter =
            array || value.flags & (MemberData | LdapData | SyncAllData | ReplicaData | NetApiData | EtwData)
                ? UnpackValueParameter(value.parameter)
                : value.parameter;
        if ((value.flags & LdapData) && parameter == ValueReturnedParameter) parameter = UINT32_MAX;
        Json snapshot{{"parameter", parameter},
            {"kind", static_cast<uint32_t>(value.kind)}, {"flags", value.flags},
            {"originalBytes", value.originalBytes}, {"bytes", std::move(bytes)}};
        if (value.kind == ValueKind::RpcValue)
        {
            snapshot["node"] = rpc.node;
            snapshot["parent"] = rpc.parent;
            snapshot["rpcType"] = RpcTypeName(rpc.type);
            snapshot["typeId"] = static_cast<uint32_t>(rpc.type);
            snapshot["offset"] = rpc.offset;
            snapshot["stride"] = rpc.stride;
            snapshot["address"] = Hex(rpc.address);
        }
        if (value.kind == ValueKind::ManagedArray) snapshot["elementSize"] = stride;
        if (value.flags & MemberData) snapshot["memberOffset"] = UnpackMemberOffset(value.parameter) - 1u;
        if (array) snapshot["arrayIndex"] = UnpackMemberOffset(value.parameter);
        if (value.flags & AutomationElement) snapshot["elementIndex"] = value.flags >> ValueDetailShift;
        if (value.flags & StringArrayElement) snapshot["elementIndex"] = value.flags >> ValueDetailShift;
        if (value.flags & LdapData)
        {
            snapshot["modIndex"] = UnpackMemberOffset(value.parameter);
            snapshot["ldapPart"] = (value.flags >> ValueSubIndexShift) & ValueNibbleMask;
            snapshot["elementIndex"] = value.flags >> ValueDetailShift;
        }
        if ((value.flags & SyncAllData) && !(value.flags & LdapData))
        {
            snapshot["errorIndex"] = UnpackMemberOffset(value.parameter);
            snapshot["syncPart"] = (value.flags >> ValueSyncAllShift) & ValueNibbleMask;
            if (snapshot["syncPart"] == 3) snapshot["memberOffset"] = value.flags >> ValueDetailShift;
        }
        if ((value.flags & ReplicaData) && !(value.flags & LdapData))
            snapshot["replicaType"] = (value.flags >> ValueReplicaShift) & ValueNibbleMask;
        if ((value.flags & NetApiData) && !(value.flags & (LdapData | SyncAllData | ReplicaData)))
        {
            if (value.flags & SecurityDescriptorData) snapshot["securityPart"] = value.flags >> ValueDetailShift;
            else snapshot["structure"] = NetApiLayoutName(value.flags >> ValueDetailShift);
            if (value.flags & SidData) snapshot["sid"] = true;
            if (value.flags & NetApiBytesData) snapshot["buffer"] = true;
        }
        if ((value.flags & EtwData) && !(value.flags & (LdapData | SyncAllData | ReplicaData | NetApiData)))
            snapshot["etwFormat"] = value.flags >> ValueDetailShift;
        if ((value.flags & SecurityDescriptorData) &&
            !(value.flags & (LdapData | SyncAllData | ReplicaData | NetApiData | EtwData)))
            snapshot["securityPart"] = value.flags >> ValueDetailShift;
        result.push_back(std::move(snapshot));
        position += value.capturedBytes;
    }
    if (position != payload.size()) throw std::runtime_error("The call contains an incomplete memory snapshot.");

    // Keep graph metadata out of raw memory regions and associate it with the captured value it describes.
    for (auto& snapshot : result)
    {
        auto parameter = snapshot["parameter"].get<uint32_t>();
        auto array = snapshot.value("arrayIndex", UINT32_MAX);
        auto flags = snapshot["flags"].get<uint32_t>();
        if (flags & (AutomationElement | StringArrayElement))
        {
            auto found = references.find({parameter, array, snapshot["elementIndex"].get<uint32_t>()});
            if (found != references.end()) snapshot["variantType"] = found->second;
        }
        else if (auto found = arrays.find({parameter, array}); found != arrays.end())
        {
            snapshot["parentArrayIndex"] = found->second.parentArray;
            snapshot["parentElementIndex"] = found->second.element;
        }
    }
    return result;
}

std::string CallState(uint32_t flags, int64_t duration)
{
    if (flags & Unwound) return "Unwound";
    if (flags & Skipped) return "Skipped";
    if (flags & Continuation) return "Entry only";
    if (flags & AsyncCancelled) return "Cancelled";
    if (flags & AsyncCompleted) return flags & Failed ? "Async failed" : "Completed";
    if (duration < 0) return "Running";
    if (flags & AsyncPending) return "Async pending";
    if (flags & Failed) return "Failed";
    if (flags & Edited) return "Edited";
    return "Returned";
}

std::string Timestamp(int64_t clock, const TracePage& page)
{
    auto delta = static_cast<long double>(clock - page.startClock) * 10000000 / page.frequency;
    auto utc = static_cast<uint64_t>(static_cast<long double>(page.startUtc) + delta);
    FILETIME fileTime{static_cast<DWORD>(utc), static_cast<DWORD>(utc >> 32)};
    FILETIME local{};
    SYSTEMTIME system{};
    if (!FileTimeToLocalFileTime(&fileTime, &local) || !FileTimeToSystemTime(&local, &system)) return {};
    char text[24];
    std::snprintf(text, sizeof(text), "%02u:%02u:%02u.%03u",
        system.wHour, system.wMinute, system.wSecond, system.wMilliseconds);
    return text;
}

std::string CallSummary(const CallRow& call)
{
    // Summaries use bounded prefixes of recorded values; no target memory or catalog queries are required.
    constexpr uint32_t count = MaximumArguments;
    std::array<std::string, count> names, values, snapshots;
    std::array<bool, count> outputs{};
    auto arguments = std::min(call.argumentCount, count);
    for (uint32_t index = 0; index < arguments; ++index)
    {
        names[index] = "arg" + std::to_string(index);
        values[index] = Hex(call.arguments[index]);
    }
    size_t start = 0;
    int depth = 0;
    uint32_t parameter = 0;
    for (size_t cursor = 0; cursor <= call.parameters.size() && parameter < arguments &&
        !(call.flags & RawArguments); ++cursor)
    {
        auto character = cursor < call.parameters.size() ? call.parameters[cursor] : L',';
        if (character == L'(' || character == L'[' || character == L'<') ++depth;
        else if (character == L')' || character == L']' || character == L'>') depth = std::max(0, depth - 1);
        else if (character == L',' && !depth)
        {
            auto end = call.parameters.find(L" -> ", start);
            end = std::min(cursor, end);
            while (end > start && call.parameters[end - 1] == L' ') --end;
            auto nameStart = end;
            auto identifier = [](wchar_t value)
            {
                return (value >= L'a' && value <= L'z') || (value >= L'A' && value <= L'Z') ||
                    (value >= L'0' && value <= L'9') || value == L'_';
            };
            while (nameStart > start && identifier(call.parameters[nameStart - 1])) --nameStart;
            if (nameStart > start && nameStart < end && end - nameStart <= 40)
                names[parameter] = Utf8(call.parameters.substr(nameStart, end - nameStart));
            ++parameter;
            start = cursor + 1;
        }
    }

    // Preserve inputs and append changed text, scalar outputs and newly captured buffers.
    for (const auto* payload : {&call.input, &call.output})
    {
        bool output = payload == &call.output;
        if (output && (call.duration < 0 || (call.flags & (Unwound | Continuation)))) continue;
        size_t position = 0;
        while (payload->size() - position >= sizeof(Value))
        {
            Value value;
            memcpy(&value, payload->data() + position, sizeof(value));
            if (value.kind == ValueKind::ManagedArray)
                value.originalBytes = (value.originalBytes >> 32) * static_cast<uint32_t>(value.originalBytes);
            position += sizeof(value);
            auto available = payload->size() - position;
            auto bytes = std::min<size_t>(value.capturedBytes, available);
            if (value.parameter < arguments && value.kind != ValueKind::Stack &&
                !(value.flags & ValueStructuredMask))
            {
                std::string text;
                if (value.flags & Unreadable) text = "<unreadable>";
                else if (value.flags & Pending) text = "<pending>";
                else if (value.kind == ValueKind::Utf16)
                {
                    auto characters = std::min<size_t>(bytes / sizeof(wchar_t), SummaryPreviewChars);
                    std::wstring captured(characters, L'\0');
                    if (characters) memcpy(captured.data(), payload->data() + position, characters * sizeof(wchar_t));
                    auto end = captured.find(L'\0');
                    if (end != std::wstring::npos) captured.resize(end);
                    for (auto& character : captured) if (character < L' ' || character == 127) character = L' ';
                    text = "\"" + Utf8(captured) + "\"";
                    if ((value.flags & Truncated) ||
                        (end == std::wstring::npos && characters * 2 < value.capturedBytes)) text += "…";
                }
                else if (value.kind == ValueKind::Scalar && bytes == value.capturedBytes && bytes && bytes <= 8)
                {
                    uint64_t scalar = 0;
                    memcpy(&scalar, payload->data() + position, bytes);
                    text = Hex(scalar);
                }
                else if (value.kind == ValueKind::ProcessInformation && bytes >= call.pointerSize * 2 + 8)
                {
                    uint64_t process = 0;
                    uint32_t pid = 0;
                    memcpy(&process, payload->data() + position, call.pointerSize);
                    memcpy(&pid, payload->data() + position + call.pointerSize * 2, sizeof(pid));
                    text = "PID " + std::to_string(pid) + " / " + Hex(process);
                }
                else if ((value.kind == ValueKind::Bytes || value.kind == ValueKind::ManagedArray) &&
                    (!output || snapshots[value.parameter].empty() || snapshots[value.parameter][0] == '<'))
                    text = "[" + std::to_string(value.capturedBytes) + "/" +
                        std::to_string(value.originalBytes) + " B]";
                if (!text.empty() && text != snapshots[value.parameter])
                {
                    auto& display = values[value.parameter];
                    if (!output && value.kind == ValueKind::Utf16) display = text;
                    else display += (output || value.kind == ValueKind::Scalar ? " → " : " ") + text;
                    snapshots[value.parameter] = std::move(text);
                    outputs[value.parameter] = output;
                }
            }
            if (value.capturedBytes > available) break;
            position += value.capturedBytes;
        }
    }
    std::string summary;
    bool omitted = false;
    for (uint32_t index = 0; index < arguments; ++index)
    {
        if (index >= 6 && !outputs[index]) { omitted = true; continue; }
        auto argument = names[index] + "=" + values[index];
        if (summary.size() + argument.size() > 700) { summary += ", …"; break; }
        if (!summary.empty()) summary += ", ";
        summary += argument;
    }
    if (omitted || call.argumentCount > arguments) summary += ", …";
    return summary;
}

Json Row(const CallRow& call, const TracePage& page, bool includeSummary = false)
{
    Json result = {{"id", call.id}, {"target", call.target}, {"pid", call.processId}, {"tid", call.threadId},
        {"pointerSize", call.pointerSize},
        {"api", static_cast<uint32_t>(call.api)}, {"name", call.name}, {"module", call.module},
        {"category", static_cast<uint32_t>(call.category)}, {"categoryName", Category(call.category).name},
        {"started", call.timestamp}, {"time", Timestamp(call.timestamp, page)},
        {"deltaUs", static_cast<double>(call.delta) * 1000000 / static_cast<double>(page.frequency)},
        {"durationUs", call.duration < 0 ? -1.0 :
            static_cast<double>(call.duration) * 1000000 / static_cast<double>(page.frequency)},
        {"adjustedDurationUs", call.adjustedDuration < 0 ? -1.0 :
            static_cast<double>(call.adjustedDuration) * 1000000 / static_cast<double>(page.frequency)},
        {"result", Hex(call.result)}, {"error", call.error}, {"flags", call.flags},
        {"state", CallState(call.flags, call.duration)}, {"parent", call.parent}, {"depth", call.depth},
        {"marks", call.marks}};
    result["callerText"] = call.callerModule.empty() ?
        (call.caller ? Hex(call.caller) : "") : call.callerModule + "+" + Hex(call.callerOffset);
    result["symbolState"] = call.callerSymbol.state;
    if (!call.callerSymbol.name.empty())
    {
        result["callerSymbol"] = call.callerSymbol.name;
        result["callerDisplay"] = call.callerModule + "!" + call.callerSymbol.name +
            "+" + Hex(call.callerSymbol.displacement);
        result["callerSource"] = call.callerSymbol.source;
        result["callerLine"] = call.callerSymbol.line;
    }
    if (includeSummary) result["summary"] = CallSummary(call);
    return result;
}

Json Targets(const TracePage& page)
{
    auto targets = Json::array();
    for (const auto& target : page.targets)
    {
        auto unknown = Json::array();
        size_t start = 0;
        while (start < target.unknownExports.size())
        {
            auto end = target.unknownExports.find(',', start);
            auto name = target.unknownExports.substr(start, end - start);
            if (!name.empty()) unknown.push_back(std::move(name));
            if (end == std::string::npos) break;
            start = end + 1;
        }
        targets.push_back({{"id", target.id}, {"pid", target.processId}, {"image", Utf8(target.image)},
            {"state", Utf8(target.state)}, {"pointerSize", target.pointerSize},
            {"nativeCoverage", {{"installed", target.installedNative},
                {"available", target.availableNative}, {"catalog", target.catalogNative},
                {"nativeExports", target.nativeExports}, {"unknownExports", std::move(unknown)}}},
            {"win32Coverage", {{"installed", target.installedWin32}, {"available", target.availableWin32},
                {"catalog", Win32ApiEnd - Win32ApiStart + NativeApiStart + Win32uApiEnd - Win32uApiStart}}},
            {"comHooks", target.installedCom},
            {"managedState", target.managedState}, {"managedApis", target.managedApiCount},
            {"moduleRefreshError", target.moduleRefreshError}, {"instructionState", target.instructionState},
            {"installedExports", target.installedExports}});
    }
    return targets;
}

class Collector
{
public:
    Json Dispatch(const Json& request);
    void BindDatabase(Json& request) const;
    bool Capturing() const { return session_ && !session_->Status().finished; }
    void Shutdown() { spy_.Stop(); session_.reset(); }
private:
    Json Status() const;
    Json View(const std::string& command, const Json& request);
    Session& Active() const;
    std::wstring Database(const Json& request) const;
    std::unique_ptr<Session> session_;
    WindowSpy spy_;
    std::map<uint64_t, std::unique_ptr<TraceView>> views_;
    uint64_t nextView_ = 0;
};

void Collector::BindDatabase(Json& request) const
{
    const auto command = request.value("command", std::string{});
    if (command == "page" || command == "details" || (command == "view" && !Number(request, "view")))
        request["database"] = Utf8(Database(request));
}

Session& Collector::Active() const
{
    if (!session_ || session_->Status().finished) throw std::runtime_error("No capture is active.");
    return *session_;
}

std::wstring Collector::Database(const Json& request) const
{
    auto path = request.value("database", std::string{});
    if (!path.empty()) return Wide(path);
    if (session_) return session_->Database();
    throw std::runtime_error("Select a capture database.");
}

Json Collector::Status() const
{
    SessionStatus status;
    status.finished = true;
    status.message = L"Ready to capture";
    if (session_) status = session_->Status();
    Json stopped = nullptr;
    if (status.breakpoint)
    {
        const auto& event = status.stoppedCall;
        const auto& metadata = status.stoppedDefinition;
        const auto definition = IsDynamicApi(event.api) ? ApiDefinition{event.api, metadata.module, metadata.name,
            metadata.parameters, metadata.argumentCount} : Definition(event.api);
        stopped = {{"id", event.callId}, {"target", status.stoppedTarget},
            {"pid", event.processId}, {"tid", event.threadId}, {"pointerSize", status.stoppedPointerSize},
            {"api", static_cast<uint32_t>(event.api)}, {"name", definition.name}, {"module", definition.module},
            {"parameters", Utf8(definition.parameters)},
            {"arguments", Arguments(definition.argumentCount -
                bool(definition.argumentCount && event.flags & OptionalArgumentAbsent), event.arguments)},
            {"result", Hex(event.result)},
            {"error", event.error}, {"flags", event.flags}};
    }
    return {{"finished", status.finished}, {"capturing", status.capturing}, {"breakpoint", status.breakpoint},
        {"partial", status.partial}, {"skippedChildren", status.skippedChildren},
        {"calls", status.calls}, {"records", status.records}, {"queued", status.queued},
        {"processes", status.processes}, {"blockedMilliseconds", status.blockedMilliseconds},
        {"attaching", status.attaching},
        {"message", Utf8(status.message)}, {"database", session_ ? Utf8(session_->Database()) : ""},
        {"bufferLimit", session_ ? session_->BufferLimit() : DefaultBufferLimit},
        {"leaving", status.leaving}, {"stoppedCall", std::move(stopped)}};
}

Json Collector::View(const std::string& command, const Json& request)
{
    auto id = Number(request, "view");
    if (command == "release")
    {
        views_.erase(id);
        return Json::object();
    }
    if (command == "view" && !id)
    {
        ViewQuery query;
        query.target = static_cast<int64_t>(Number(request, "target", 0, INT64_MAX));
        query.thread = static_cast<uint32_t>(Number(request, "thread", 0, MAXDWORD));
        query.filter = request.value("filter", std::string{});
        query.category = ParseCategory(request);
        query.failuresOnly = request.value("failuresOnly", false);
        auto order = request.value("order", std::string("newest"));
        if (order != "oldest" && order != "newest" && order != "slowest")
            throw std::runtime_error("Select a valid call order.");
        query.order = order == "oldest" ? ViewOrder::Oldest : order == "slowest" ? ViewOrder::Slowest :
            ViewOrder::Newest;

        // Each view holds a database connection; retire the oldest when an interface stops releasing them.
        while (views_.size() >= MaxOpenViews) views_.erase(views_.begin());
        id = ++nextView_;
        views_.emplace(id, std::make_unique<TraceView>(Database(request), query));
    }
    auto found = views_.find(id);
    if (found == views_.end()) throw std::runtime_error("The call view is no longer available.");
    auto& view = *found->second;
    auto reply = [&](Json result)
    {
        result["view"] = id;
        result["revision"] = view.Revision();
        return result;
    };
    if (request.contains("revision") && Number(request, "revision") != view.Revision())
        return reply({{"stale", true}});
    if (command == "mark")
    {
        // A mark that does not compile leaves the view listed without marks.
        view.Mark(request.value("filters", std::vector<std::string>{}));
        return reply(Json::object());
    }
    try
    {
        if (command == "rows")
        {
            auto calls = Json::array();
            for (const auto& call : view.Rows(Number(request, "index"),
                static_cast<uint32_t>(Number(request, "limit", DefaultRowsLimit, MaxPageLimit)),
                request.value("includeSummary", true)))
                calls.push_back(Row(call, view.Trace(), true));
            return reply({{"calls", std::move(calls)}, {"count", view.Count()}});
        }
        if (command == "locate")
            return reply({{"index", request.contains("time") ?
                view.LocateTime(static_cast<int64_t>(Number(request, "time", 0, INT64_MAX))) :
                view.Locate(static_cast<int64_t>(Number(request, "target", 0, INT64_MAX)),
                    Number(request, "callId", 0, INT64_MAX))}});
        if (command == "seek")
        {
            auto match = view.Seek(static_cast<int64_t>(Number(request, "target", 0, INT64_MAX)),
                Number(request, "callId", 0, INT64_MAX), request.value("forward", true));
            return reply({{"index", match.index}, {"target", match.target},
                {"callId", match.id}, {"count", view.Count()}});
        }
        if (command == "summary")
        {
            // Totals are returned once every recorded call has been visited.
            bool complete = view.Summarize(
                static_cast<uint32_t>(Number(request, "budget", DefaultSliceBudgetMs, MaxSliceBudgetMs)),
                request.value("restart", false));
            Json result{{"complete", complete}, {"progress", view.SummaryProgress()}};
            if (!complete) return reply(std::move(result));
            auto frequency = static_cast<double>(view.Trace().frequency);
            auto items = Json::array();
            for (const auto& api : view.Summary())
                items.push_back({{"module", api.module}, {"name", api.name},
                    {"categoryName", Category(api.category).name}, {"calls", api.calls}, {"failed", api.failed},
                    {"returned", api.returned}, {"totalUs", static_cast<double>(api.total) * 1000000 / frequency},
                    {"longestUs", static_cast<double>(api.longest) * 1000000 / frequency}});
            result["items"] = std::move(items);
            return reply(std::move(result));
        }
        if (command == "timeline")
        {
            auto density = view.Timeline(
                static_cast<uint32_t>(Number(request, "buckets", DefaultTimelineBuckets, MaxTimelineBuckets)),
                static_cast<uint32_t>(Number(request, "budget", DefaultTimelineBudgetMs, MaxSliceBudgetMs)));
            return reply({{"begin", density.begin}, {"end", density.end}, {"calls", density.calls},
                {"failures", density.failures}});
        }

        // Indexing continues in bounded slices; a complete view instead picks up calls recorded since.
        bool changed = request.value("advance", true) && view.Advance(
            static_cast<uint32_t>(Number(request, "budget", DefaultSliceBudgetMs, MaxSliceBudgetMs)),
            request.value("extend", true));
        Json result{{"view", id}, {"count", view.Count()}, {"complete", view.Complete()},
            {"scanned", view.Scanned()}, {"changed", changed}, {"changedFrom", view.ChangedFrom()},
            {"stale", view.Stale()}};
        if (request.value("includeMetadata", true))
        {
            auto page = view.Metadata();
            auto threads = Json::array();
            for (const auto& thread : page.traceThreads)
                threads.push_back({{"target", thread.target}, {"tid", thread.threadId}});
            auto diagnostics = Json::array();
            for (const auto& diagnostic : page.diagnostics)
                diagnostics.push_back({{"target", diagnostic.target}, {"message", diagnostic.message}});
            result.update({{"targets", Targets(page)}, {"threads", std::move(threads)},
                {"frequency", page.frequency}, {"startClock", page.startClock}, {"startUtc", page.startUtc},
                {"totalCalls", page.totalCalls}, {"modules", page.modules.size()},
                {"diagnostics", std::move(diagnostics)}, {"skippedChildren", page.skippedChildren}});
        }
        return reply(std::move(result));
    }
    catch (...)
    {
        views_.erase(found);
        throw;
    }
}

Json Collector::Dispatch(const Json& request)
{
    if (!request.is_object()) throw std::runtime_error("Expected a request object.");
    auto command = request.at("command").get<std::string>();
    if (command == "spySnapshot") return SpySnapshot();
    if (command == "spyPick") return SpyPick();
    if (command == "spyProperties" || command == "spyWindow" || command == "spyStart")
    {
        const auto pid = static_cast<DWORD>(Number(request, "pid", 0, MAXDWORD));
        const auto tid = static_cast<DWORD>(Number(request, "tid", 0, MAXDWORD));
        const auto window = reinterpret_cast<HWND>(static_cast<uintptr_t>(
            Number(request, "window", 0, UINTPTR_MAX)));
        if (command == "spyProperties") return SpyProperties(pid, tid, window);
        if (command == "spyWindow")
        {
            auto item = SpyWindowInfo(window);
            if (item.is_null() || item["pid"] != pid)
                throw std::runtime_error("The selected window no longer exists. Refresh the view.");
            return item;
        }
        spy_.Start(pid, tid, window, request.value("children", true));
        return Json::object();
    }
    if (command == "spyPoll") return spy_.Poll();
    if (command == "spyStop") return spy_.Poll(true);
    if (command == "hello")
    {
        PrepareApiCatalog();
        auto catalog = Json::array(), categories = Json::array();
        for (const auto& definition : CategoryDefinitions)
            categories.push_back({{"id", static_cast<uint32_t>(definition.id)}, {"name", definition.name},
                {"description", definition.description}, {"mask", std::to_string(CategoryMask(definition.id))}});
        for (const auto& definition : ApiDefinitions)
        {
            auto index = static_cast<uint32_t>(definition.id);
            auto mask = ApiMask(definition.id);
            auto category = ClassifyApi(definition.module, definition.name);
            catalog.push_back({{"id", index}, {"module", definition.module}, {"name", definition.name},
                {"parameters", Utf8(definition.parameters)}, {"argumentCount", definition.argumentCount},
                {"mask", std::to_string(mask)}, {"category", static_cast<uint32_t>(category)}});
        }

        // Noise profiles are presets that clients add to their editable exclusion lists.
        auto noiseProfiles = Json::array({
            {{"id", "queries"}, {"name", "Common queries"},
                {"description", "Thread, process and error-state queries."},
                {"apis", {"GetLastError", "GetCurrentThreadId", "GetCurrentProcessId", "GetCurrentThread",
                    "GetCurrentProcess", "IsThreadAFiber", "GetProcessHeap", "FlsGetValue"}}},
            {{"id", "runtime"}, {"name", "Runtime helpers"},
                {"description", "Common queries, string comparison, error-state updates and C++ mutex helpers."},
                {"apis", {"GetLastError", "GetCurrentThreadId", "GetCurrentProcessId", "GetCurrentThread",
                    "GetCurrentProcess", "IsThreadAFiber", "GetProcessHeap", "FlsGetValue", "lstrcmpiW",
                    "SetLastError", "_Mtx_lock", "_Mtx_unlock"}}}});
        return {{"protocol", 1}, {"pointerSize", sizeof(void*)}, {"catalog", std::move(catalog)},
            {"allApis", std::to_string(AllApis)}, {"categories", std::move(categories)},
            {"noiseProfiles", std::move(noiseProfiles)},
            {"allCategories", std::to_string(AllCategories)}, {"maximumBufferLimit", MaximumBufferLimit},
            {"maximumStack", MaximumStack}, {"managedMask", std::to_string(ManagedApis)},
            {"comMask", std::to_string(ComApis)}, {"win32uMask", std::to_string(Win32uApis)},
            {"syscallMask", std::to_string(DirectSyscalls)},
            {"coverage",
                "User-mode Windows API tracing across native exports, COM, WinRT and .NET. "
                "Broad coverage records executable DLL "
                "exports, syscall instructions and discovered interface slots, using bounded raw snapshots when "
                "signatures are unavailable. CoreCLR, CLR 2 and CLR 4 support launch and attach; "
                "CLR 2 and CLR 4 attach use managed debugging. Attach captures calls after instrumentation finishes. "
                "Full stacks are limited to safe typed Win32 hooks; broad coverage records caller addresses. "
                "Managed launch tracing disables inlining, precompiled images and concurrent GC. "
                "CoreCLR attach recompiles callers. Buffer outputs follow GC relocations and replaced arrays. "
                "Tail calls are recorded as continuations. Functional categories are inferred from API names, "
                "namespaces and modules; unknown purposes remain unclassified. Universal coverage is incomplete."}};
    }
    if (command == "symbols")
    {
        std::vector<std::wstring> directories;
        for (const auto& directory : request.value("directories", Json::array()))
            directories.push_back(Wide(directory.get<std::string>()));
        SetSymbolDirectories(directories);
        return Json::object();
    }
    if (command == "processes") return ProcessList();
    if (command == "launch" || command == "attach")
    {
        // Starting a new session never abandons a live target or overwrites an existing trace.
        if (session_ && !session_->Status().finished) throw std::runtime_error("Stop the current capture first.");
        auto database = Wide(request.at("database").get<std::string>());
        if (database.empty()) throw std::runtime_error("Select a new capture database.");
        CaptureOptions options;
        options.bufferLimit = static_cast<uint32_t>(Number(request, "bufferLimit", DefaultBufferLimit,
            MaximumBufferLimit));
        if (options.bufferLimit < MinimumBufferLimit)
            throw std::runtime_error("Buffer limit must be at least 16 bytes.");
        options.traceStopMiB = static_cast<uint32_t>(Number(request, "traceStopMiB", 0, UINT32_MAX));
        options.stackDepth = static_cast<uint32_t>(Number(request, "stackDepth", 0, MaximumStack));
        options.apiMask = Number(request, "apiMask", AllApis) & AllApis;
        options.categoryMask = Number(request, "categoryMask", AllCategories) & AllCategories;
        options.excludedApis = request.value("excludedApis", std::vector<std::string>{});
        const auto codes = request.value("expectedExitCodes", Json::array());
        if (!codes.is_array()) throw std::runtime_error("Expected exit codes must be an array.");
        for (const auto& code : codes)
        {
            auto value = Integer(code);
            if (value > MAXDWORD) throw std::runtime_error("Expected exit codes must fit in 32 bits.");
            options.expectedExitCodes.push_back(static_cast<uint32_t>(value));
        }
        options.entryBreaks = Number(request, "entryMask") & AllApis;
        options.exitBreaks = Number(request, "exitMask") & AllApis;
        auto entry = request.value("entryApi", int64_t{-1});
        auto exit = request.value("exitApi", int64_t{-1});
        if (!BreakableApi(entry) || !BreakableApi(exit))
            throw std::runtime_error("Select a native API from the catalog or captured calls.");
        options.entryApi = static_cast<int32_t>(entry);
        options.exitApi = static_cast<int32_t>(exit);
        options.followChildren = request.value("followChildren", true);
        options.instructionEngine = request.value("instructionEngine", false);
        options.startMinimized = request.value("startMinimized", false);
        options.workingDirectory = Wide(request.value("workingDirectory", std::string{}));
        auto pid = static_cast<uint32_t>(Number(request, "pid", 0, MAXDWORD));
        auto executable = Wide(request.value("executable", std::string{}));
        if ((command == "attach" && !pid) || (command == "launch" && executable.empty()))
            throw std::runtime_error("Select a process or executable to capture.");

        // Join the previous worker before changing controller definitions for the next capture.
        session_.reset();
        std::unique_lock catalogLock(CatalogAccess);
        PrepareApiCatalog(true);
        session_ = std::make_unique<Session>(database, options, command == "attach" ? pid : 0,
            executable, Wide(request.value("arguments", std::string{})));
        return Status();
    }
    if (command == "status") return Status();
    if (command == "stop")
    {
        if (session_) session_->Stop();
        return Json::object();
    }
    if (command == "pause")
    {
        Active().Pause(request.at("paused").get<bool>());
        return Json::object();
    }
    if (command == "filters")
    {
        if (request.contains("excludedApis"))
            Active().SetExcludedApis(request.at("excludedApis").get<std::vector<std::string>>());
        Active().SetFilters(Number(request, "apiMask", AllApis) & AllApis,
            Number(request, "categoryMask", AllCategories) & AllCategories);
        return Json::object();
    }
    if (command == "breaks")
    {
        Active().SetBreaks(Number(request, "entryMask") & AllApis, Number(request, "exitMask") & AllApis);
        return Json::object();
    }
    if (command == "breakApi")
    {
        auto entry = request.value("entryApi", int64_t{-1});
        auto exit = request.value("exitApi", int64_t{-1});
        if (!BreakableApi(entry) || !BreakableApi(exit))
            throw std::runtime_error("Select a native API from the catalog or captured calls.");
        Active().SetApiBreaks(static_cast<int32_t>(entry), static_cast<int32_t>(exit));
        return Json::object();
    }
    if (command == "continue")
    {
        auto& session = Active();
        auto status = session.Status();
        if (!status.breakpoint) throw std::runtime_error("No API breakpoint is active.");
        auto event = status.stoppedCall;
        if (Number(request, "callId", event.callId) != event.callId ||
            Number(request, "pid", event.processId) != event.processId ||
            Number(request, "tid", event.threadId) != event.threadId)
            throw std::runtime_error("The selected API breakpoint is no longer active.");
        if (auto arguments = request.find("arguments"); arguments != request.end())
        {
            auto argumentCount = IsDynamicApi(event.api) ? status.stoppedDefinition.argumentCount :
                Definition(event.api).argumentCount;
            if (!arguments->is_array() || arguments->size() != argumentCount -
                bool(argumentCount && event.flags & OptionalArgumentAbsent))
                throw std::runtime_error("Supply one value for each argument.");
            if (status.leaving) throw std::runtime_error("Arguments can only be edited before an API call.");
            for (size_t index = 0; index < arguments->size(); ++index)
                event.arguments[index] = Integer((*arguments)[index]);
            if (event.flags & OptionalArgumentAbsent && event.arguments[1] & _O_CREAT)
                throw std::runtime_error("A creation mode is required when _O_CREAT is set.");
        }
        event.result = Number(request, "result", event.result);
        event.error = static_cast<uint32_t>(Number(request, "error", event.error, MAXDWORD));
        bool skip = request.value("skip", false);
        if (skip && status.leaving) throw std::runtime_error("A returned call cannot be skipped.");
        session.Continue(event, skip);
        return Json::object();
    }
    if (command == "writeMemory" || command == "readMemory")
    {
        // Bind debugger memory operations to the inspected call rather than a subsequent breakpoint.
        auto& session = Active();
        auto status = session.Status();
        if (!status.breakpoint || Number(request, "callId", status.stoppedCall.callId) != status.stoppedCall.callId ||
            Number(request, "pid", status.stoppedCall.processId) != status.stoppedCall.processId ||
            Number(request, "tid", status.stoppedCall.threadId) != status.stoppedCall.threadId)
            throw std::runtime_error("The selected API breakpoint is no longer active.");
        if (command == "readMemory")
        {
            auto length = Number(request, "length", session.BufferLimit(), session.BufferLimit());
            std::vector<uint8_t> bytes;
            std::wstring error;
            if (!session.ReadMemory(Number(request, "address"), static_cast<size_t>(length), bytes, error))
                throw std::runtime_error(Utf8(error));
            return {{"bytes", HexBytes(std::as_bytes(std::span(bytes)))}, {"requested", length},
                {"captured", bytes.size()}};
        }
        auto encoded = request.at("bytes").get<std::string>();
        if (encoded.empty() || encoded.size() % 2 || encoded.size() > MaximumBufferLimit * 2)
            throw std::runtime_error("Memory data must contain 1 to 65536 bytes of hexadecimal pairs.");
        std::vector<uint8_t> bytes(encoded.size() / 2);
        for (size_t index = 0; index < bytes.size(); ++index)
        {
            unsigned value = 0;
            auto first = encoded.data() + index * 2;
            auto parsed = std::from_chars(first, first + 2, value, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != first + 2)
                throw std::runtime_error("Memory data contains an invalid hexadecimal pair.");
            bytes[index] = static_cast<uint8_t>(value);
        }
        std::wstring error;
        if (!session.WriteMemory(Number(request, "address"), bytes.data(), bytes.size(), error))
            throw std::runtime_error(Utf8(error));
        return Json::object();
    }
    if (command == "page" || command == "details")
    {
        PrepareApiCatalog();
        // Keep list transfers bounded; an indexed cursor supports loading a complete view in batches.
        Query query;
        query.target = static_cast<int64_t>(Number(request, "target", 0, INT64_MAX));
        query.thread = static_cast<uint32_t>(Number(request, "thread", 0, MAXDWORD));
        query.api = request.value("api", std::string{});
        query.category = ParseCategory(request);
        query.failuresOnly = request.value("failuresOnly", false);
        query.offset = static_cast<uint32_t>(Number(request, "offset", 0, MAXDWORD));
        query.limit = static_cast<uint32_t>(Number(request, "limit", DefaultPageLimit, MaxPageLimit));
        query.newestTimestamp = static_cast<int64_t>(Number(request, "newestTimestamp", 0, INT64_MAX));
        query.newestTarget = static_cast<int64_t>(Number(request, "newestTarget", 0, INT64_MAX));
        query.newestCallId = Number(request, "newestCallId", 0, INT64_MAX);
        query.beforeTimestamp = static_cast<int64_t>(Number(request, "beforeTimestamp", 0, INT64_MAX));
        query.beforeTarget = static_cast<int64_t>(Number(request, "beforeTarget", 0, INT64_MAX));
        query.beforeCallId = Number(request, "beforeCallId", 0, INT64_MAX);
        query.includeMetadata = request.value("includeMetadata", true);
        query.includeSummary = request.value("includeSummary", false);
        if (command == "details")
        {
            query.callId = Number(request, "callId", 0, INT64_MAX);
            if (!query.target || !query.callId) throw std::runtime_error("Select a call to inspect.");
            query.limit = 1;
            query.includePayload = true;
        }
        auto page = TraceStore::ReadPage(Database(request), query);
        if (command == "details")
        {
            if (page.calls.empty()) throw std::runtime_error("The selected call was not found.");
            const auto& call = page.calls.front();
            auto result = Row(call, page);
            result["arguments"] = Arguments(call.argumentCount, call.arguments);
            if (call.rawArgumentCount > call.argumentCount)
                result["rawArguments"] = Arguments(call.rawArgumentCount, call.arguments);
            result["parameters"] = Utf8(call.parameters);
            result["layout"] = call.layout;
            result["caller"] = Hex(call.caller);
            result["callerPath"] = call.callerPath;
            result["input"] = Snapshots(call.input);
            result["output"] = Snapshots(call.output);
            for (const auto& side : {"input", "output"})
                for (const auto& value : result[side])
                    if (value.contains("rpc")) result["rpc"] = value["rpc"];
            auto stack = Json::array();
            for (const auto& frame : call.stack)
            {
                auto display = frame.module.empty() ? Hex(frame.address) : frame.module + "+" + Hex(frame.offset);
                if (!frame.symbol.name.empty()) display = frame.module + "!" + frame.symbol.name +
                    "+" + Hex(frame.symbol.displacement);
                stack.push_back({{"address", Hex(frame.address)}, {"display", display}, {"path", frame.path},
                    {"application", ApplicationModule(frame.path)},
                    {"symbol", frame.symbol.name}, {"source", frame.symbol.source}, {"line", frame.symbol.line},
                    {"state", frame.symbol.state}});
            }
            result["stack"] = std::move(stack);
            if (call.completion.observed)
            {
                const auto& completion = call.completion;
                auto buffers = Json::array();
                for (const auto& buffer : completion.buffers)
                    buffers.push_back(
                        {{"parameter", buffer.parameter}, {"index", buffer.index}, {"address", Hex(buffer.address)},
                            {"requested", buffer.requested}, {"completed", buffer.completed}});
                result["completion"] = {{"observed", completion.observed},
                    {"elapsedUs", static_cast<double>(completion.observed - call.timestamp) * 1000000 / page.frequency},
                    {"control", Hex(completion.control)}, {"observer", completion.observer}, {"tid", completion.thread},
                    {"transferred", completion.transferred}, {"status", Hex(completion.status)},
                    {"domain", static_cast<uint32_t>(completion.domain)},
                    {"source", static_cast<uint32_t>(completion.source)}, {"flags", completion.flags},
                    {"ioFlags", completion.ioFlags}, {"buffers", std::move(buffers)}};
            }
            result["text"] = Utf8(DescribeCall(call, page.frequency));
            return result;
        }
        auto calls = Json::array();
        for (const auto& call : page.calls) calls.push_back(Row(call, page, query.includeSummary));
        return {{"calls", std::move(calls)}, {"targets", Targets(page)}, {"threads", page.threads},
            {"frequency", page.frequency}, {"startClock", page.startClock}, {"startUtc", page.startUtc},
            {"totalCalls", page.totalCalls}};
    }
    if (IsViewCommand(command))
    {
        PrepareApiCatalog();
        return View(command, request);
    }
    if (command == "exports")
    {
        auto exports = Json::array();
        for (const auto& value : ReadExports(Wide(request.at("path").get<std::string>())))
            exports.push_back({{"name", value.name}, {"ordinal", value.ordinal}, {"rva", value.rva},
                {"forwarder", value.forwarder}, {"executable", value.executable}});
        return exports;
    }
    throw std::runtime_error("Unknown collector command.");
}

// Control requests stay on the input thread; one query owner serializes views and their SQLite connections.
class QueryQueue
{
public:
    explicit QueryQueue(Collector& collector) : collector_(collector), worker_([this] { Run(); }) {}
    ~QueryQueue()
    {
        Stop();
        worker_.join();
    }
    static bool Accepts(const std::string& command)
    {
        return IsViewCommand(command) || command == "page" || command == "details" || command == "exports" ||
            command == "symbols" || command == "processes";
    }
    void Submit(Json request, size_t bytes)
    {
        auto job = std::make_shared<Job>();
        job->id = Number(request, "id");
        job->work.deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(Number(request, "timeout", DefaultQueryTimeoutMs, DefaultQueryTimeoutMs));
        job->request = std::move(request);
        job->bytes = bytes;
        std::lock_guard lock(mutex_);
        if (jobs_.size() >= MaxPendingQueries || bytes_ + bytes > MaxPendingQueryBytes)
            throw std::runtime_error("Too many queries are pending. Try again when the current query finishes.");
        if (!jobs_.emplace(job->id, job).second) throw std::runtime_error("Duplicate query identifier.");
        bytes_ += bytes;
        queue_.push_back(std::move(job));
        ready_.notify_one();
    }
    void Cancel(uint64_t id)
    {
        std::lock_guard lock(mutex_);
        if (auto found = jobs_.find(id); found != jobs_.end()) found->second->work.cancelled = true;
    }
    void Stop()
    {
        std::lock_guard lock(mutex_);
        stopping_ = true;
        for (const auto& [id, job] : jobs_) job->work.cancelled = true;
        ready_.notify_one();
    }
    void CancelAll()
    {
        std::lock_guard lock(mutex_);
        for (const auto& [id, job] : jobs_) job->work.cancelled = true;
    }
    static void Respond(const Json& response)
    {
        // Formatting can be expensive, but only writing a complete response holds the output lock.
        auto line = response.dump(-1, ' ', false, Json::error_handler_t::replace);
        static std::mutex output;
        std::lock_guard lock(output);
        std::cout << line << '\n' << std::flush;
    }
private:
    struct Job
    {
        uint64_t id = 0;
        size_t bytes = 0;
        Json request;
        QueryWork work;
    };
    void Run()
    {
        for (;;)
        {
            std::shared_ptr<Job> job;
            {
                std::unique_lock lock(mutex_);
                ready_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (stopping_) return;
                job = std::move(queue_.front());
                queue_.pop_front();
            }
            QueryWork::current = &job->work;
            Json response{{"id", job->id}};
            try
            {
                if (job->work.Interrupted()) throw std::runtime_error("Query interrupted.");
                std::shared_lock catalogLock(CatalogAccess);
                response["data"] = collector_.Dispatch(job->request);
                if (job->work.Interrupted()) throw std::runtime_error("Query interrupted.");
                response["ok"] = true;
            }
            catch (const std::exception& error)
            {
                response["ok"] = false;
                response["error"] = job->work.Interrupted() ?
                    job->work.cancelled ? "Query canceled." : "The query exceeded its time limit." : error.what();
            }
            QueryWork::current = nullptr;
            {
                std::lock_guard lock(mutex_);
                jobs_.erase(job->id);
                bytes_ -= job->bytes;
                if (stopping_) return;
            }
            Respond(response);
        }
    }
    Collector& collector_;
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<std::shared_ptr<Job>> queue_;
    std::map<uint64_t, std::shared_ptr<Job>> jobs_;
    size_t bytes_ = 0;
    bool stopping_ = false;
    std::thread worker_;
};
}

int main(int argc, char** argv)
{
    using namespace Detourist;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    // Keep inspected rectangles and finder points in physical pixels on mixed-DPI desktops.
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    if (argc == 8 && std::string_view(argv[1]) == "--bootstrap")
    {
        try
        {
            BootstrapTarget(std::strtoul(argv[2], nullptr, 10), std::strtoul(argv[3], nullptr, 10),
                std::strtoul(argv[4], nullptr, 10) != 0, std::strtoul(argv[5], nullptr, 10) != 0,
                std::strtoul(argv[6], nullptr, 10) != 0, Wide(argv[7]));
            return 0;
        }
        catch (...)
        {
            return 1;
        }
    }
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    SetHandleInformation(GetStdHandle(STD_INPUT_HANDLE), HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(GetStdHandle(STD_OUTPUT_HANDLE), HANDLE_FLAG_INHERIT, 0);

    // The CRT owns the private IPC streams; launched applications must not receive their standard-handle slots.
    SetStdHandle(STD_INPUT_HANDLE, nullptr);
    SetStdHandle(STD_OUTPUT_HANDLE, nullptr);
    SetStdHandle(STD_ERROR_HANDLE, nullptr);
    Collector collector;
    QueryQueue queries(collector);

    // Closing the UI's pipe destroys the session and releases targets, including API breakpoints.
    std::string line;
    while (std::getline(std::cin, line))
    {
        Json response{{"id", nullptr}};
        try
        {
            if (line.size() > MaxCollectorRequestBytes)
                throw std::runtime_error("Collector request is too large.");
            auto request = Json::parse(line);
            if (request.is_object() && request.contains("id")) response["id"] = request["id"];
            const auto command = request.at("command").get<std::string>();
            if (QueryQueue::Accepts(command))
            {
                collector.BindDatabase(request);
                queries.Submit(std::move(request), line.size());
                continue;
            }
            if (command == "cancel")
            {
                queries.Cancel(Number(request, "request"));
                response["data"] = Json::object();
            }
            else
            {
                // A new capture refreshes catalog definitions only after old query work relinquishes them.
                if ((command == "launch" || command == "attach") && !collector.Capturing()) queries.CancelAll();
                response["data"] = collector.Dispatch(request);
            }
            response["ok"] = true;
        }
        catch (const std::exception& error)
        {
            response["ok"] = false;
            response["error"] = error.what();
        }
        QueryQueue::Respond(response);
    }
    queries.Stop();
    collector.Shutdown();
    return 0;
}

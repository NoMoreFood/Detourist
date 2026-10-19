#include "TestSupport.h"
#include "GuardedPages.h"
#include "ApiCategories.h"

#if defined(DETOURIST_TEST_DetouristAuthzAccessTests)

using namespace Detourist::Tests;
using namespace Detourist;
using nlohmann::json;

struct AccessCallbacks
{
    BOOL applicable = TRUE;
    unsigned checks = 0, groups = 0, freed = 0;
    PSID group = nullptr;
};
AccessCallbacks Callbacks;

BOOL CALLBACK CheckAccess(AUTHZ_CLIENT_CONTEXT_HANDLE, PACE_HEADER ace, PVOID arguments, PBOOL applicable)
{
    if (arguments != &Callbacks || ace->AceType != ACCESS_ALLOWED_CALLBACK_ACE_TYPE) return FALSE;
    ++Callbacks.checks;
    *applicable = Callbacks.applicable;
    return TRUE;
}

BOOL CALLBACK ComputeGroups(AUTHZ_CLIENT_CONTEXT_HANDLE, PVOID arguments, PSID_AND_ATTRIBUTES* groups,
    PDWORD count, PSID_AND_ATTRIBUTES* restricted, PDWORD restrictedCount)
{
    if (arguments != &Callbacks) return FALSE;
    auto value = static_cast<PSID_AND_ATTRIBUTES>(HeapAlloc(GetProcessHeap(), 0, sizeof(SID_AND_ATTRIBUTES)));
    if (!value) return FALSE;
    *value = {Callbacks.group, SE_GROUP_ENABLED | SE_GROUP_MANDATORY};
    *groups = value;
    *count = 1;
    *restricted = nullptr;
    *restrictedCount = 0;
    ++Callbacks.groups;
    return TRUE;
}

VOID CALLBACK FreeGroups(PSID_AND_ATTRIBUTES groups)
{
    if (!groups) return;
    ++Callbacks.freed;
    HeapFree(GetProcessHeap(), 0, groups);
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 2) return 1;
    try
    {
        // The local authorization context and security descriptors do not change operating-system permissions.
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        auto pages = GuardedPages(system.dwPageSize, PAGE_NOACCESS, 24);
        size_t region = 0;
        auto guarded = [&](const void* data, size_t size)
        {
            Check(region < 24 && size <= system.dwPageSize, "Fit authorization buffer");
            auto value = reinterpret_cast<BYTE*>(pages.get()) + (++region * 2 - 1) * system.dwPageSize - size;
            memcpy(value, data, size);
            return value;
        };
        auto bits = [](const void* pointer) { return reinterpret_cast<uint64_t>(pointer); };
        auto snapshot = [](uint32_t parameter, uint32_t kind, const void* data, size_t size,
            uint32_t flags = 0, uint32_t minimum = 0)
        {
            auto begin = static_cast<const BYTE*>(data);
            return json{{"parameter", parameter}, {"kind", kind}, {"flags", flags},
                {"data", std::vector<BYTE>(begin, begin + size)}, {"minimum", minimum}};
        };
        std::array<BYTE, 20> userData{1, 3, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 42, 0, 0, 0, 7, 0, 0, 0};
        std::array<BYTE, 12> worldData{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};
        auto user = guarded(userData.data(), userData.size());
        auto world = guarded(worldData.data(), worldData.size());
        Callbacks.group = world;
        AUTHZ_RESOURCE_MANAGER_HANDLE manager = nullptr;
        Check(AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, CheckAccess, ComputeGroups, FreeGroups,
            L"Local authorization capture", &manager), "Create authorization manager");
        AUTHZ_CLIENT_CONTEXT_HANDLE context = nullptr;
        Check(AuthzInitializeContextFromSid(AUTHZ_SKIP_TOKEN_GROUPS, user, manager, nullptr, {}, &Callbacks, &context),
            "Create authorization context");

        // Each callback ACE grants a separate access bit to the group supplied by ComputeGroups.
        std::array<BYTE, sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + 12> aclData{};
        auto acl = reinterpret_cast<PACL>(aclData.data());
        Check(InitializeAcl(acl, static_cast<DWORD>(aclData.size()), ACL_REVISION), "Initialize local ACL");
        Check(AddAccessAllowedAce(acl, ACL_REVISION, 1, world), "Add local access entry");
        auto ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(aclData.data() + sizeof(ACL));
        ace->Header.AceType = ACCESS_ALLOWED_CALLBACK_ACE_TYPE;
        auto firstAcl = reinterpret_cast<PACL>(guarded(acl, aclData.size()));
        ace->Mask = 2;
        auto secondAcl = reinterpret_cast<PACL>(guarded(acl, aclData.size()));
        SECURITY_DESCRIPTOR descriptor{};
        Check(InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION), "Initialize local descriptor");
        Check(SetSecurityDescriptorOwner(&descriptor, user, FALSE) &&
            SetSecurityDescriptorGroup(&descriptor, world, FALSE) &&
            SetSecurityDescriptorDacl(&descriptor, TRUE, firstAcl, FALSE), "Set local descriptor fields");
        auto absolute = reinterpret_cast<PSECURITY_DESCRIPTOR>(guarded(&descriptor, sizeof(descriptor)));
        Check(SetSecurityDescriptorDacl(&descriptor, TRUE, secondAcl, FALSE), "Set additional access entry");
        DWORD relativeSize = 0;
        MakeSelfRelativeSD(&descriptor, nullptr, &relativeSize);
        std::vector<BYTE> relativeData(relativeSize);
        Check(MakeSelfRelativeSD(&descriptor, relativeData.data(), &relativeSize), "Create relative descriptor");
        auto relative = reinterpret_cast<PSECURITY_DESCRIPTOR>(guarded(relativeData.data(), relativeData.size()));
        std::array<PSECURITY_DESCRIPTOR, 2> optional{relative, nullptr};
        auto additional = reinterpret_cast<PSECURITY_DESCRIPTOR*>(guarded(optional.data(), sizeof(optional)));
        std::array<GUID, 7> identities{};
        for (uint32_t index = 0; index < identities.size(); ++index)
            identities[index] = {0x12340000 + index, 0x1234, 0x5678, {1, 2, 3, 4, 5, 6, 7, 8}};
        auto guids = reinterpret_cast<GUID*>(guarded(identities.data(), sizeof(identities)));
        std::array<OBJECT_TYPE_LIST, 7> objectTypes{};
        for (uint32_t index = 0; index < objectTypes.size(); ++index)
            objectTypes[index] = {static_cast<WORD>(index ? 1 : 0), 0, guids + index};
        auto objects = reinterpret_cast<POBJECT_TYPE_LIST>(guarded(objectTypes.data(), sizeof(objectTypes)));
        AUTHZ_ACCESS_REQUEST emptyRequest{};
        auto request = reinterpret_cast<PAUTHZ_ACCESS_REQUEST>(guarded(&emptyRequest, sizeof(emptyRequest)));
        std::array<DWORD, 7> emptyResults{};
        auto granted = reinterpret_cast<PDWORD>(guarded(emptyResults.data(), sizeof(emptyResults)));
        auto errors = reinterpret_cast<PDWORD>(guarded(emptyResults.data(), sizeof(emptyResults)));
        auto audit = reinterpret_cast<PDWORD>(guarded(emptyResults.data(), sizeof(emptyResults)));
        AUTHZ_ACCESS_REPLY emptyReply{};
        auto reply = reinterpret_cast<PAUTHZ_ACCESS_REPLY>(guarded(&emptyReply, sizeof(emptyReply)));
        AUTHZ_ACCESS_CHECK_RESULTS_HANDLE cached = nullptr;
        json calls = json::array();
        auto security = [&](json& input, uint32_t parameter, PSECURITY_DESCRIPTOR value,
            uint32_t minimum = 0, bool member = false)
        {
            SECURITY_DESCRIPTOR_CONTROL control;
            DWORD revision;
            Check(GetSecurityDescriptorControl(value, &control, &revision), "Read descriptor control");
            auto size = control & SE_SELF_RELATIVE ? 20u : 40u;
            auto flags = 16384u | (member ? 16u : 0u);
            input.push_back(snapshot(parameter, 0, value, size, flags, minimum));
            minimum = std::max(minimum, size);
            PSID owner, group;
            BOOL defaulted, present;
            PACL dacl;
            Check(GetSecurityDescriptorOwner(value, &owner, &defaulted) &&
                GetSecurityDescriptorGroup(value, &group, &defaulted) &&
                GetSecurityDescriptorDacl(value, &present, &dacl, &defaulted), "Read descriptor fields");
            input.push_back(snapshot(parameter, 0, owner, GetLengthSid(owner), flags | (1u << 16) | 4096, minimum));
            input.push_back(snapshot(parameter, 0, group, GetLengthSid(group), flags | (2u << 16) | 4096, minimum));
            input.push_back(snapshot(parameter, 0, dacl, dacl->AclSize, flags | (3u << 16), minimum));
        };
        auto check = [&](const char* label, DWORD desired, bool applies, bool multiple, bool extra, bool cache,
            bool cachedCall = false, DWORD flags = 0, bool empty = false, bool invalid = false)
        {
            Callbacks.applicable = applies;
            *request = {desired, user, multiple ? objects : nullptr, multiple ? 7u : 0u, &Callbacks};
            *reply = {empty ? 0u : multiple ? 7u : 1u, granted, audit, errors};
            std::fill_n(granted, 7, 0xaaaaaaaa);
            std::fill_n(errors, 7, 0xbbbbbbbb);
            std::fill_n(audit, 7, 0xcccccccc);
            auto replyIndex = cachedCall ? 4u : 7u;
            json input = json::array({snapshot(2, 0, request, sizeof(*request), 32768 | (4u << 16)),
                snapshot(((8u + 1) << 8) | 2, 0, user, userData.size(), 32768 | (5u << 16) | 16 | 4096, 16)});
            if (multiple)
            {
                input.push_back(snapshot(((16u + 1) << 8) | 2, 0, objects, sizeof(objectTypes),
                    32768 | (6u << 16) | 16, 28));
                for (uint32_t index = 0; index < objectTypes.size(); ++index)
                    input.push_back(snapshot(((index * 16 + 8 + 1) << 8) | 2, 0, guids + index, sizeof(GUID),
                        32768 | (7u << 16) | 16, std::max(28u, (index + 1) * 16)));
            }
            if (!cachedCall)
            {
                security(input, 4, absolute);
                if (extra)
                {
                    input.push_back(snapshot(5, 0, additional, 8, 16384 | (5u << 16)));
                    security(input, (1u << 8) | 5, relative, 8, true);
                }
            }
            input.push_back(snapshot(replyIndex, 0, reply, sizeof(*reply)));
            std::vector<uint64_t> arguments{flags, invalid ? 0 : bits(cachedCall ?
                reinterpret_cast<void*>(cached) : reinterpret_cast<void*>(context)), bits(request), 0};
            if (!cachedCall)
                arguments.insert(arguments.end(), {bits(absolute), extra ? bits(additional) : 0, extra ? 1u : 0u});
            arguments.push_back(bits(reply));
            if (!cachedCall) arguments.push_back(cache ? bits(&cached) : 0);
            auto checks = Callbacks.checks;
            SetLastError(0x1234);
            auto result = cachedCall ?
                AuthzCachedAccessCheck(flags, invalid ? nullptr : cached, request, nullptr, reply) :
                AuthzAccessCheck(flags, invalid ? nullptr : context, request, nullptr, absolute,
                    extra ? additional : nullptr, extra ? 1u : 0u, reply, cache ? &cached : nullptr);
            auto error = GetLastError();
            json output = json::array();
            if (result)
            {
                output.push_back(snapshot(replyIndex, 0, reply, sizeof(*reply)));
                if (reply->ResultListLength)
                {
                    output.push_back(snapshot(((8u + 1) << 8) | replyIndex, 0, granted,
                        reply->ResultListLength * 4, 16, 16));
                    output.push_back(snapshot(((24u + 1) << 8) | replyIndex, 0, errors,
                        reply->ResultListLength * 4, 16, 32));
                }
                if (cache) output.push_back(snapshot(8, 2, &cached, sizeof(cached)));
            }
            calls.push_back({{"name", cachedCall ? "AuthzCachedAccessCheck" : "AuthzAccessCheck"}, {"label", label},
                {"arguments", arguments}, {"input", input}, {"output", output}, {"result", result},
                {"error", error}, {"granted", std::vector<DWORD>(granted, granted + 7)},
                {"errors", std::vector<DWORD>(errors, errors + 7)},
                {"audit", std::vector<DWORD>(audit, audit + 7)}, {"callbacks", Callbacks.checks - checks}});
        };
        check("allow", 1, true, false, false, false);
        check("deny", 1, false, false, false, false);
        check("missing-right", 2, true, false, false, false);
        check("objects", 1, true, true, false, false);
        check("optional", 3, true, true, true, false);
        check("cache", 1, true, false, false, true);
        Check(cached != nullptr, "Retain authorization cache");
        check("cached-allow", 1, true, false, false, false, true);
        check("cached-deny", 1, false, false, false, false, true);
        check("reserved-flags", 1, true, false, false, false, false, 0x80000000);
        check("zero-count", 1, true, false, false, false, false, 0, true);
        check("invalid-context", 1, true, false, false, false, false, 0, false, true);
        check("invalid-cache", 1, true, false, false, false, true, 0, false, true);
        Check(AuthzFreeHandle(cached), "Free authorization cache");
        Check(AuthzFreeContext(context), "Free authorization context");
        Check(AuthzFreeResourceManager(manager), "Free authorization manager");
        auto image = bits(GetModuleHandleW(nullptr));
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
        std::ofstream(std::filesystem::path(argv[1]), std::ios::binary) << json{{"calls", calls},
            {"image", {image, image + nt->OptionalHeader.SizeOfImage}}, {"groups", Callbacks.groups},
            {"freed", Callbacks.freed}}.dump(2);
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 2;
    }
}

void AuthzAccess(const Context& context)
{
    // Establish provider decisions, callback counts and cleanup without instrumentation.
    auto path = context.directory / L"native.json";
    RunTarget(context, Quote(path));
    auto native = Report(path);
    Require(native["groups"] == 1 && native["freed"] == 1, "Authorization cleanup differs", native);
    Json labels;
    for (const auto& call : native["calls"])
        labels[call["label"].get<std::string>()] = call;
    for (auto label : {"deny", "missing-right", "cached-deny"})
        Require(labels[label]["result"] != 0 && labels[label]["errors"][0] == 5, "Deny decision differs");
    for (auto label : {"invalid-context", "invalid-cache"})
        Require(labels[label]["result"] == 0, "Invalid authorization context succeeded");
    Require(labels["optional"]["granted"] == Json(std::vector<int>(7, 3)) && labels["optional"]["callbacks"] == 2 &&
                labels["cached-allow"]["callbacks"] == 1 && labels["cached-deny"]["callbacks"] == 1,
            "Authorization callbacks differ", labels);
    Json details = Json::array();
    for (bool instructions : {false, true})
        for (uint32_t limit : {16u, 17u, 32u, 40u, 128u})
        {
            Capture::Run(context, {.arguments = Quote(path), .limit = limit, .instructions = instructions},
                         [&](Capture& capture)
            {
                auto report = Report(path);
                Require(report["groups"] == native["groups"] && report["freed"] == native["freed"],
                        "Authorization cleanup differs", report);
                CompareCalls(native, report, {"name", "result", "error", "granted", "errors", "audit", "callbacks"});
                Require(Query(capture.database, "SELECT message FROM diagnostics").empty(), "Capture diagnostics");

                // Lifecycle output and access-decision arrays must have the exact bounded wire representation.
                auto lifecycle = InImage(
                    capture.Find(
                        "AuthzInitializeContextFromSid|AuthzFreeHandle|AuthzFreeContext|AuthzFreeResourceManager"),
                    report);
                Require(lifecycle.size() == 4, "Authorization lifecycle call missing", lifecycle);
                for (const auto& row : lifecycle)
                {
                    Require(row["result"] != 0 && !(row["flags"].get<uint32_t>() & (1 | 4 | 256)),
                            "Authorization lifecycle failed", row);
                    std::vector<Value> before, after;
                    if (row["name"] == "AuthzInitializeContextFromSid")
                    {
                        auto sid = Data(report["calls"][0]["input"][1]["data"]);
                        before.push_back({1, 0, 4096u | uint32_t(limit < sid.size()), sid.size(), Prefix(sid, limit)});
                        after.push_back({6, 2, 0, 8, Integer(report["calls"][0]["arguments"][1].get<uint64_t>())});
                    }
                    Require(Values(row["input"]) == before && Values(row["output"]) == after,
                            "Authorization lifecycle capture differs", row);
                }
                auto rows = InImage(capture.Find("AuthzAccessCheck|AuthzCachedAccessCheck"), report);
                Require(rows.size() == report["calls"].size(), "Authorization call count differs", rows);
                for (size_t index = 0; index < rows.size(); ++index)
                {
                    const auto& row = rows[index];
                    const auto& call = report["calls"][index];
                    Require(row["name"] == call["name"] && !(row["flags"].get<uint32_t>() & (4 | 256)) &&
                                row["result"] == call["result"] && row["error"] == call["error"] &&
                                bool(row["flags"].get<uint32_t>() & 1) == (call["result"] == 0),
                            "Access result differs", row);
                    auto arguments = Data(row["arguments"]);
                    Require(arguments.size() == call["arguments"].size() * 8, "Access argument count differs", row);
                    for (size_t ordinal = 0; ordinal < call["arguments"].size(); ++ordinal)
                        Require(Read<uint64_t>(arguments, ordinal * 8) == call["arguments"][ordinal],
                                "Access argument differs", row);
                    for (auto direction : {"input", "output"})
                    {
                        std::vector<Value> expected;
                        for (const auto& item : call[direction])
                        {
                            if (limit < item["minimum"].get<uint32_t>()) continue;
                            auto data = Data(item["data"]);
                            expected.push_back({item["parameter"], item["kind"],
                                                item["flags"].get<uint32_t>() | uint32_t(data.size() > limit),
                                                data.size(), Prefix(data, limit)});
                        }
                        Require(Values(row[direction]) == expected, "Access decision capture differs", call);
                    }
                    details.push_back({{"expected", call}, {"limit", limit}, {"call", capture.Details(row)}});
                }
            });
        }
    Inspect(context, context.Option(L"--inspector"), "--authz-access", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, AuthzAccess); }

#elif defined(DETOURIST_TEST_DetouristAuthzAuditTests)

#include "InvokeArguments.h"

using namespace Detourist::Tests;
using namespace Detourist;
using nlohmann::json;

__declspec(noinline) uint64_t __cdecl ProbeArguments(uint64_t count, uint64_t seed, uint64_t expected,
    uint64_t unwind, ...)
{
    Check(seed == 0xfedcba9876543210 && expected == 0x89abcdef01234567, "Preserve register arguments");
    va_list arguments;
    va_start(arguments, unwind);
    for (uint64_t index = 0; index < count; ++index)
        Check(va_arg(arguments, uint64_t) == (seed ^ (index + 4)), "Preserve all stack arguments");
    va_end(arguments);
    if (unwind) RaiseException(0xe0424242, 0, 0, nullptr);
    SetLastError(0x4321);
    return expected;
}

DWORD ProbeUnwind(const uint64_t* arguments, size_t count)
{
    __try
    {
        InvokeIntegerArguments(reinterpret_cast<void*>(&ProbeArguments), arguments, 32,
            arguments + 32, count - 32);
        return 0;
    }
    __except (GetExceptionCode() == 0xe0424242 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        return GetExceptionCode();
    }
}

int TargetMain(int argc, wchar_t** argv)
{
    if (argc != 2) return 1;
    try
    {
        // Exercise dynamic stack probing, full-width values and unwinding through the forwarding frame.
        std::array<uint64_t, 1200> forwarded{1196, 0xfedcba9876543210, 0x89abcdef01234567, 0};
        for (size_t index = 4; index < forwarded.size(); ++index) forwarded[index] = forwarded[1] ^ index;
        auto forwardedResult = InvokeIntegerArguments(reinterpret_cast<void*>(&ProbeArguments),
            forwarded.data(), 32, forwarded.data() + 32, forwarded.size() - 32);
        Check(forwardedResult == forwarded[2] && GetLastError() == 0x4321, "Preserve variadic return state");
        forwarded[3] = 1;
        Check(ProbeUnwind(forwarded.data(), forwarded.size()) == 0xe0424242, "Unwind the variadic frame");

        // Every caller-owned region ends at an inaccessible page.
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        auto pages = GuardedPages(system.dwPageSize, PAGE_NOACCESS, 24);
        size_t region = 0;
        auto guarded = [&](const void* data, size_t bytes)
        {
            Check(region < 24 && bytes <= system.dwPageSize, "Fit guarded audit buffer");
            auto destination = reinterpret_cast<BYTE*>(pages.get()) + (++region * 2 - 1) * system.dwPageSize - bytes;
            memcpy(destination, data, bytes);
            return destination;
        };
        auto bytes = [](const void* data, size_t count)
        {
            if (!count) return std::vector<BYTE>{};
            auto start = static_cast<const BYTE*>(data);
            return std::vector<BYTE>(start, start + count);
        };
        auto bits = [](const void* pointer) { return reinterpret_cast<uint64_t>(pointer); };
        auto snapshot = [&](uint32_t parameter, uint32_t kind, const void* data, size_t size, uint32_t flags = 0)
        {
            return json{{"parameter", parameter}, {"kind", kind}, {"data", bytes(data, size)}, {"flags", flags}};
        };
        std::array<PWSTR, 5> strings{};
        constexpr const wchar_t* contents[]{L"Audit operation", L"Local object", L"Object \x03bb",
            L"Additional audit data", L"Second audit detail"};
        for (size_t index = 0; index < strings.size(); ++index)
            strings[index] = reinterpret_cast<PWSTR>(guarded(contents[index], (wcslen(contents[index]) + 1) * 2));
        AUTHZ_AUDIT_EVENT_HANDLE empty = nullptr;
        auto output = reinterpret_cast<PAUTHZ_AUDIT_EVENT_HANDLE>(guarded(&empty, sizeof(empty)));
        json calls = json::array();
        auto initialize = [&](bool extended, DWORD flags, DWORD count, bool missing)
        {
            *output = reinterpret_cast<AUTHZ_AUDIT_EVENT_HANDLE>(uintptr_t{0x12345678});
            auto operation = missing ? nullptr : strings[0];
            std::vector<uint64_t> arguments{flags, 0, bits(operation), bits(strings[1]), bits(strings[2]),
                bits(strings[3])};
            if (extended) arguments.push_back(bits(strings[4]));
            auto outputIndex = static_cast<uint32_t>(arguments.size());
            arguments.push_back(bits(output));
            arguments.push_back(count);
            SetLastError(0x1234);
            auto result = extended ? AuthzInitializeObjectAccessAuditEvent2(flags, nullptr, operation, strings[1],
                strings[2], strings[3], strings[4], output, count) :
                AuthzInitializeObjectAccessAuditEvent(flags, nullptr, operation, strings[1], strings[2],
                    strings[3], output, count);
            auto error = GetLastError();
            auto handle = bits(*output);
            Check((result && handle && handle != 0x12345678) || (!result && handle == 0x12345678),
                "Audit output handle lifetime");
            if (result) Check(AuthzFreeAuditEvent(*output), "Free initialized audit event");
            json input = json::array();
            for (uint32_t index = 2; index < outputIndex; ++index)
                if (arguments[index]) input.push_back(snapshot(index, 1,
                    reinterpret_cast<void*>(arguments[index]), (wcslen(strings[index - 2]) + 1) * 2));
            calls.push_back({{"name", extended ? "AuthzInitializeObjectAccessAuditEvent2" :
                "AuthzInitializeObjectAccessAuditEvent"}, {"arguments", arguments}, {"input", input},
                {"result", result}, {"error", error}, {"outputIndex", outputIndex}, {"handle", handle}});
        };
        for (bool extended : {false, true})
        {
            initialize(extended, 0, 0, false);
            initialize(extended, AUTHZ_NO_ALLOC_STRINGS | AUTHZ_NO_SUCCESS_AUDIT | AUTHZ_NO_FAILURE_AUDIT, 0, false);
            initialize(extended, 0x80000000, 0, false);
            initialize(extended, 0, 1, false);
            initialize(extended, 0, UINT32_MAX, false);
            initialize(extended, 0, 0, true);
        }

        // Reporting validates and converts its typed arguments before rejecting the absent event provider.
        std::array<BYTE, 20> sidData{1, 3, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 42, 0, 0, 0, 7, 0, 0, 0};
        auto sid = guarded(sidData.data(), sidData.size());
        GUID identity{0x01234567, 0x89ab, 0xcdef, {0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}};
        auto guid = guarded(&identity, sizeof(identity));
        std::array<AUDIT_OBJECT_TYPE, 2> elements{{{identity, 0, 0, 0x10000}, {identity, 0, 1, 0x20000}}};
        auto elementData = guarded(elements.data(), sizeof(elements));
        AUDIT_OBJECT_TYPES objectTypes{2, 0, reinterpret_cast<PAUDIT_OBJECT_TYPE>(elementData)};
        auto objects = guarded(&objectTypes, sizeof(objectTypes));
        AUDIT_IP_ADDRESS ipv4{}, ipv6{};
        ipv4.pIpAddress[0] = 2;
        ipv4.pIpAddress[2] = 0x1f;
        ipv4.pIpAddress[3] = 0x90;
        ipv4.pIpAddress[4] = 127;
        ipv4.pIpAddress[7] = 1;
        ipv6.pIpAddress[0] = 23;
        ipv6.pIpAddress[23] = 1;
        auto ip4 = guarded(&ipv4, sizeof(ipv4));
        auto ip6 = guarded(&ipv6, sizeof(ipv6));
        auto inaccessible = bits(reinterpret_cast<BYTE*>(pages.get()) + system.dwPageSize);
        auto report = [&](const char* label, DWORD count, const std::vector<uint64_t>& supplied, json input)
        {
            std::array<uint64_t, 96> tail;
            tail.fill(inaccessible);
            std::copy(supplied.begin(), supplied.end(), tail.begin());
            std::vector<uint64_t> arguments{APF_AuditSuccess, 0, 0x1234, bits(sid), count};
            arguments.insert(arguments.end(), supplied.begin(), supplied.end());
            input.insert(input.begin(), snapshot(3, 0, sid, sidData.size(), 4096));
            auto invoke = [&]<size_t... Index>(std::index_sequence<Index...>)
            {
                return AuthzReportSecurityEvent(APF_AuditSuccess, nullptr, 0x1234, sid, count, tail[Index]...);
            };
            SetLastError(0x1234);
            auto result = invoke(std::make_index_sequence<96>{});
            auto error = GetLastError();
            Check(!result && error != 0x1234, "Reject an unregistered audit provider");
            calls.push_back({{"name", "AuthzReportSecurityEvent"}, {"label", label}, {"count", count},
                {"arguments", arguments}, {"input", input}, {"result", result}, {"error", error}});
        };
        auto text = snapshot(6, 1, strings[0], (wcslen(strings[0]) + 1) * 2);
        report("values", 6, {APT_String, bits(strings[0]), APT_Ulong, 0xfedcba98,
            APT_Pointer, inaccessible, APT_Guid, bits(guid), APT_Sid, bits(sid), APT_Time, inaccessible},
            json::array({text, snapshot(12, 0, guid, sizeof(identity)), snapshot(14, 0, sid, sidData.size(), 4096)}));
        report("aggregates", 4, {APT_Luid, inaccessible, APT_Int64, inaccessible, APT_LogonId, inaccessible,
            APT_ObjectTypeList, bits(objects), 0}, json::array({snapshot(12, 0, objects, sizeof(objectTypes)),
                snapshot(((8 + 1) << 8) | 12, 0, elementData, sizeof(elements), 16)}));
        report("flags", 6, {APT_String, bits(strings[0]), APT_Ulong | AP_AccessMask, 0x10000, 0,
            APT_LogonId | AP_PrimaryLogonId, APT_LogonId | AP_ClientLogonId,
            APT_LogonIdWithSid | AP_PrimaryLogonId, APT_Guid, bits(guid)},
            json::array({text, snapshot(14, 0, guid, sizeof(identity))}));
        report("addresses", 2, {APT_IpAddress, bits(ip4), APT_IpAddress, bits(ip6)},
            json::array({snapshot(6, 0, ip4, sizeof(ipv4)), snapshot(8, 0, ip6, sizeof(ipv6))}));
        report("formatted", 3, {APT_String | AP_Filespec, bits(strings[0]),
            APT_Ulong | AP_FormatHex, 0xfedcba98, APT_Sid | AP_SidAsLogonId, bits(sid)},
            json::array({text, snapshot(10, 0, sid, sidData.size(), 4096)}));
        report("logon", 3, {APT_LogonIdWithSid, inaccessible, APT_LogonId, 0,
            APT_Luid, 0xffffffff80000001}, json::array());
        AUDIT_OBJECT_TYPES noObjects{0, 0, reinterpret_cast<PAUDIT_OBJECT_TYPE>(inaccessible)};
        auto emptyObjects = guarded(&noObjects, sizeof(noObjects));
        report("empty-objects", 1, {APT_ObjectTypeList, bits(emptyObjects), 0},
            json::array({snapshot(6, 0, emptyObjects, sizeof(noObjects))}));
        auto guardedHeader = guarded(&objectTypes, 8);
        report("guarded-header", 1, {APT_ObjectTypeList, bits(guardedHeader), 0},
            json::array({json{{"parameter", 6}, {"kind", 0}, {"flags", 2},
                {"original", sizeof(objectTypes)}, {"data", json::array()}}}));
        report("empty", 0, {}, json::array());
        report("unknown", 1, {0x7fff}, json::array());
        report("null-string", 1, {APT_String, 0}, json::array());
        report("window", 14, {APT_Ulong, 1, APT_Ulong, 2, APT_Ulong, 3, APT_Ulong, 4, APT_Ulong, 5,
            APT_Ulong, 6, APT_Ulong, 7, APT_Ulong, 8, APT_Ulong, 9, APT_Ulong, 10,
            APT_Ulong, 11, APT_Ulong, 12, APT_Ulong, 13, APT_Ulong, 14}, json::array());
        std::vector<uint64_t> extended;
        for (uint64_t value = 1; value <= 30; ++value)
            extended.insert(extended.end(), {APT_Ulong, 0xf0000000 | value});
        report("extended-window", 30, extended, json::array());
        extended.back() = 0x7fff;
        extended.erase(extended.end() - 2);
        report("unknown-tail", 30, extended, json::array());

        // Structured reports retain descriptor bytes and follow only the pointers selected by complete records.
        auto parameter = [](AUDIT_PARAM_TYPE type, uint64_t data0, uint64_t data1 = 0, DWORD flags = 0)
        {
            AUDIT_PARAM value{};
            value.Type = type;
            value.Flags = flags;
            value.Data0 = data0;
            value.Data1 = data1;
            return value;
        };
        std::array descriptors{
            parameter(APT_String, bits(strings[0])), parameter(APT_Pointer, inaccessible),
            parameter(APT_Ulong, 0xfedcba98, 1, AP_AccessMask), parameter(APT_Sid, bits(sid)),
            parameter(APT_Guid, bits(guid)), parameter(APT_ObjectTypeList, bits(objects), 1),
            parameter(APT_Luid, 0x80000001, 0xffffffff), parameter(APT_Time, 0x01234567, 0x89abcdef),
            parameter(APT_Int64, 0x76543210, 0xfedcba98), parameter(APT_LogonId, 42, 7),
            parameter(APT_LogonIdWithSid, 21, 5), parameter(APT_IpAddress, bits(ip4)),
            parameter(APT_IpAddress, bits(ip6)), parameter(static_cast<AUDIT_PARAM_TYPE>(0x7fff), inaccessible)};
        auto descriptorData = reinterpret_cast<PAUDIT_PARAM>(guarded(descriptors.data(), sizeof(descriptors)));
        auto referenced = [&](uint32_t index, uint32_t kind, const void* data, size_t size,
            uint32_t part = 2, uint32_t flags = 0)
        {
            auto result = snapshot((((index * 32 + 16) + 1) << 8) | 4, kind, data, size,
                32768 | (part << 16) | 16 | flags);
            result["requires"] = (index + 1) * 32;
            return result;
        };
        auto structured = [&](const char* label, PAUDIT_PARAMS parameters, size_t readable,
            const void* table, size_t tableBytes, json references)
        {
            json input = json::array({snapshot(3, 0, sid, sidData.size(), 4096)});
            if (parameters)
            {
                auto root = snapshot(4, 0, parameters, readable, 32768);
                root["original"] = sizeof(AUDIT_PARAMS);
                input.push_back(root);
                if (table)
                {
                    auto values = snapshot(((16 + 1) << 8) | 4, 0, table, tableBytes, 32768 | (1 << 16) | 16);
                    values["original"] = parameters->Count * sizeof(AUDIT_PARAM);
                    values["minLimit"] = sizeof(AUDIT_PARAMS);
                    input.push_back(values);
                    for (auto& value : references) input.push_back(value);
                }
            }
            SetLastError(0x1234);
            auto result = AuthzReportSecurityEventFromParams(APF_AuditSuccess, nullptr, 0x1234, sid, parameters);
            auto error = GetLastError();
            Check(!result && error != 0x1234, "Reject an unregistered structured audit provider");
            calls.push_back({{"name", "AuthzReportSecurityEventFromParams"}, {"label", label},
                {"arguments", {APF_AuditSuccess, 0, 0x1234, bits(sid), bits(parameters)}},
                {"input", input}, {"result", result}, {"error", error}});
        };
        AUDIT_PARAMS header{};
        header.Length = sizeof(header);
        header.Flags = APF_AuditSuccess;
        header.Count = static_cast<USHORT>(descriptors.size());
        header.Parameters = descriptorData;
        auto parameters = reinterpret_cast<PAUDIT_PARAMS>(guarded(&header, sizeof(header)));
        structured("typed-array", parameters, sizeof(header), descriptorData, sizeof(descriptors),
            json::array({referenced(0, 1, strings[0], (wcslen(strings[0]) + 1) * 2),
                referenced(3, 0, sid, sidData.size(), 2, 4096), referenced(4, 0, guid, sizeof(identity)),
                referenced(5, 0, objects, sizeof(objectTypes)), referenced(5, 0, elementData, sizeof(elements), 3),
                referenced(11, 0, ip4, sizeof(ipv4)), referenced(12, 0, ip6, sizeof(ipv6))}));
        parameters->Count = 0;
        parameters->Parameters = reinterpret_cast<PAUDIT_PARAM>(inaccessible);
        structured("zero-count", parameters, sizeof(header), nullptr, 0, json::array());
        parameters->Count = 1;
        parameters->Parameters = nullptr;
        structured("null-array", parameters, sizeof(header), nullptr, 0, json::array());
        structured("null-root", nullptr, 0, nullptr, 0, json::array());
        auto shortHeader = reinterpret_cast<PAUDIT_PARAMS>(guarded(&header, 16));
        structured("short-root", shortHeader, 16, nullptr, 0, json::array());
        auto shortTable = reinterpret_cast<PAUDIT_PARAM>(guarded(descriptors.data(), 48));
        parameters->Count = 2;
        parameters->Parameters = shortTable;
        structured("short-array", parameters, sizeof(header), shortTable, 48,
            json::array({referenced(0, 1, strings[0], (wcslen(strings[0]) + 1) * 2)}));
        parameters->Count = UINT16_MAX;
        structured("large-count", parameters, sizeof(header), shortTable, 48,
            json::array({referenced(0, 1, strings[0], (wcslen(strings[0]) + 1) * 2)}));
        parameters->Count = 1;
        parameters->Parameters = descriptorData;
        descriptorData[0] = parameter(APT_ObjectTypeList, bits(emptyObjects));
        structured("empty-object-array", parameters, sizeof(header), descriptorData, sizeof(AUDIT_PARAM),
            json::array({referenced(0, 0, emptyObjects, sizeof(noObjects))}));
        descriptorData[0] = parameter(APT_ObjectTypeList, bits(guardedHeader));
        auto unreadable = referenced(0, 0, guardedHeader, 8);
        unreadable["original"] = sizeof(AUDIT_OBJECT_TYPES);
        structured("short-object-header", parameters, sizeof(header), descriptorData, sizeof(AUDIT_PARAM),
            json::array({unreadable}));
        descriptorData[0] = parameter(APT_Guid, inaccessible);
        auto inaccessibleGuid = referenced(0, 0, nullptr, 0);
        inaccessibleGuid["original"] = sizeof(GUID);
        structured("unreadable-guid", parameters, sizeof(header), descriptorData, sizeof(AUDIT_PARAM),
            json::array({inaccessibleGuid}));
        auto image = bits(GetModuleHandleW(nullptr));
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
        std::ofstream(std::filesystem::path(argv[1]), std::ios::binary) << json{{"calls", calls},
            {"image", {image, image + nt->OptionalHeader.SizeOfImage}}}.dump(2);
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 2;
    }
}

Json VerifyAudit(const Path& database, const Json& report, uint32_t limit)
{
    auto all = Calls(database);
    Json selected = Json::array();
    for (const auto& row : all)
        if (row["module"] == "authz.dll" &&
            (row["name"] == "AuthzInitializeObjectAccessAuditEvent" ||
             row["name"] == "AuthzInitializeObjectAccessAuditEvent2" || row["name"] == "AuthzReportSecurityEvent" ||
             row["name"] == "AuthzReportSecurityEventFromParams"))
            selected.push_back(row);
    auto rows = InImage(selected, report);
    Require(Query(database, "SELECT message FROM diagnostics").empty(), "Capture diagnostics");
    Require(rows.size() == report["calls"].size(), "Audit call count differs", rows);
    for (size_t index = 0; index < rows.size(); ++index)
    {
        const auto& row = rows[index];
        const auto& call = report["calls"][index];
        auto flags = row["flags"].get<uint32_t>();
        auto reporting = call["name"] == "AuthzReportSecurityEvent";
        auto count = std::min<size_t>(call["arguments"].size(), 32);
        Require(row["name"] == call["name"] && !(flags & 4) && row["result"] == call["result"] &&
                    row["error"] == call["error"] && bool(flags & 1) == (call["result"] == 0),
                "Audit result differs", row);
        auto arguments = Data(row["arguments"]);
        Require(arguments.size() == row["argument_count"].get<size_t>() * 8, "Audit argument bytes differ", row);
        for (size_t ordinal = 0; ordinal < arguments.size() / 8; ++ordinal)
            Require(Read<uint64_t>(arguments, ordinal * 8) ==
                        (ordinal < count ? call["arguments"][ordinal].get<uint64_t>() : 0),
                    "Audit argument differs", row);
        if (reporting)
        {
            Require(row["argument_count"] == 32 && (flags & (256 | 2048)) == (256 | 2048) &&
                        ((flags >> 12) & 63) == count,
                    "Audit variadic contract differs", row);
            auto label = call["label"].get<std::string>();
            auto valid = label != "unknown" && label != "unknown-tail" && label != "null-string";
            Json converted = Json::array();
            for (const auto& item : Named(all, "AuthzReportSecurityEventFromParams"))
                if (item["parent"] == row["id"]) converted.push_back(item);
            Require(!converted.empty() == valid, "Native audit conversion differs", call);
            if (valid)
            {
                auto input = Values(converted.back()["input"]);
                auto header = Snapshots(converted.back()["input"], 4, 0);
                Require(!header.empty() && header[0].size() >= 10 && Read<uint16_t>(header[0], 8) == call["count"],
                        "Converted audit header differs", call);
                if ((label == "window" || label == "extended-window") && limit >= call["count"].get<size_t>() * 32)
                    for (const auto& value : input)
                        if ((value.flags & 32768) && (value.flags >> 16) == 1)
                            for (size_t element = 0; element < call["count"].get<size_t>(); ++element)
                                Require(Read<uint32_t>(value.data, element * 32) == 3 &&
                                            Read<uint64_t>(value.data, element * 32 + 16) ==
                                                call["arguments"][6 + element * 2],
                                        "Converted window value differs", call);
            }
        }
        else
            Require(row["argument_count"] == count && !(flags & (256 | 2048)), "Audit fixed contract differs", row);
        std::vector<Value> expected;
        size_t tableBytes = 0;
        for (const auto& item : call["input"])
        {
            if (limit < item.value("minLimit", 0u) || tableBytes < item.value("requires", size_t{})) continue;
            auto data = Data(item["data"]);
            auto original = item.value("original", uint64_t(data.size()));
            auto size = std::min<uint64_t>(original, item["kind"] == 1 ? limit & ~1u : limit);
            auto itemFlags = item["flags"].get<uint32_t>();
            if (size > data.size())
            {
                size = 0;
                itemFlags |= 2;
            }
            else if (size < original)
                itemFlags |= 1;
            if (item["kind"] == 1 && size < data.size()) original = 0;
            if ((itemFlags & 32768) && (itemFlags >> 16) == 1) tableBytes = size;
            expected.push_back({item["parameter"], item["kind"], itemFlags, original, Prefix(data, size)});
        }
        std::vector<Value> output;
        if (call.contains("outputIndex") && call["result"] != 0)
            output.push_back({call["outputIndex"], 2, 0, 8, Integer(call["handle"].get<uint64_t>())});
        Require(Values(row["input"]) == expected && Values(row["output"]) == output, "Audit capture differs", call);
    }
    return rows;
}

void AuthzAudit(const Context& context)
{
    // Compare each audit shape with the provider's untraced result and structured conversion.
    auto path = context.directory / L"native.json";
    RunTarget(context, Quote(path));
    auto native = Report(path);
    Require(std::ranges::count_if(native["calls"], [](const Json& call) { return call["result"] != 0; }) == 6,
            "Native audit success count differs", native);
    auto hello = context.GetCollector().Call("hello");
    auto mask = Number(hello["allApis"]) & ~Number(hello["comMask"]);
    auto categories = Detourist::CategoryMask(Detourist::ApiCategory::Security);
    Json details = Json::array();
    for (bool instructions : {false, true})
    {
        for (uint32_t limit : {16u, 17u, 32u, 40u, 128u, 1024u})
        {
            Capture::Run(context, {.arguments = Quote(path), .limit = limit, .instructions = instructions,
                .apiMask = mask, .categoryMask = categories},
                         [&](Capture& capture)
            {
                auto report = Report(path);
                CompareCalls(native, report, {"name", "result", "error"});
                auto rows = VerifyAudit(capture.database, report, limit);
                for (size_t index = 0; index < rows.size(); ++index)
                    details.push_back({{"expected", report["calls"][index]},
                                       {"limit", limit},
                                       {"call", capture.Details(rows[index])}});
            });
        }

        // Entry edits must preserve the uncaptured argument tail; return edits reach the caller's last error.
        Collector collector(context.collector, context.directory);
        auto hello = collector.Call("hello");
        auto api = Named(hello["catalog"], "AuthzReportSecurityEvent")[0]["id"];
        auto database = context.directory / (instructions ? L"edited-instructions.sqlite" : L"edited-hooks.sqlite");
        collector.Call("launch", {{"database", Text(database)},
                                  {"executable", Text(context.target)},
                                  {"arguments", TargetArguments(context, Quote(path))},
                                  {"apiMask", mask},
                                  {"categoryMask", categories},
                                  {"bufferLimit", 1024},
                                  {"followChildren", false},
                                  {"instructionEngine", instructions},
                                  {"entryApi", api}});
        Json previous = nullptr, stopped, arguments = Json::array();
        for (;;)
        {
            stopped = collector.Wait([&](const Json& status) {
                return status["finished"] == true ||
                       (status["breakpoint"] == true && status["stoppedCall"]["id"] != previous);
            }, 45);
            Require(stopped["breakpoint"] == true && stopped["leaving"] == false, "Audit entry stop missing", stopped);
            arguments = Json::array();
            for (const auto& argument : stopped["stoppedCall"]["arguments"])
                arguments.push_back(std::stoull(argument.get<std::string>(), nullptr, 16));
            Require(arguments.size() == 32 && (stopped["stoppedCall"]["flags"].get<uint32_t>() & 2048),
                    "Audit stopped arguments differ", stopped);
            if (arguments[4] == 30) break;
            previous = stopped["stoppedCall"]["id"];
            collector.Call("continue");
        }
        arguments[6] = 0x12345678;
        arguments[30] = 0xabcdef01u;
        collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", api}});
        collector.Call("continue", {{"arguments", arguments}});
        auto returned = collector.Wait([](const Json& status)
        { return status["finished"] == true || (status["breakpoint"] == true && status["leaving"] == true); }, 45);
        Require(returned["breakpoint"] == true && returned["leaving"] == true &&
                    returned["stoppedCall"]["id"] == stopped["stoppedCall"]["id"],
                "Audit return stop differs", returned);
        collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
        collector.Call("continue", {{"error", 0x4321}});
        auto finished = collector.Wait([](const Json& status) { return status["finished"] == true; }, 45);
        Require(!finished["message"].get<std::string>().contains("nonzero exit code"), "Edited audit target failed");
        auto report = Report(path);
        for (auto& call : report["calls"])
            if (call.value("label", "") == "extended-window")
            {
                call["arguments"][6] = arguments[6];
                call["arguments"][30] = arguments[30];
                Require(call["error"] == 0x4321, "Audit return edit missing", call);
            }
        VerifyAudit(database, report, 1024);
        collector.Close();
    }
    Inspect(context, context.Option(L"--inspector"), "--authz-audit", details);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, AuthzAudit); }

#else
#error Select a native test target.
#endif

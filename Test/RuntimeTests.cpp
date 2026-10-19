#include "TestSupport.h"
#include "GuardedPages.h"

#if defined(DETOURIST_TEST_DetouristCppRuntimeTests)

using namespace Detourist::Tests;
#ifdef _DEBUG
constexpr auto RuntimeModule = "vcruntime140d.dll";
#else
constexpr auto RuntimeModule = "vcruntime140.dll";
#endif
struct RuntimeBase
{
    virtual ~RuntimeBase() = default;
};

struct RuntimeDerived : RuntimeBase
{
};

__declspec(noinline) RuntimeBase* MakeRuntimeObject()
{
    return new RuntimeDerived;
}

int TargetMain()
{
    // Resolve RTTI at runtime so the compiler calls the shared C++ runtime exports.
    RuntimeBase* object = MakeRuntimeObject();
    bool valid = dynamic_cast<RuntimeDerived*>(object) != nullptr &&
        dynamic_cast<void*>(object) == object && typeid(*object) == typeid(RuntimeDerived);
    delete object;
    if (!valid) return 1;

    // Locale factories consume the constructor's physical return even when its catalog result is void.
    const std::locale current;
    const std::locale::facet* facet = nullptr;
    std::ctype<unsigned short>::_Getcat(&facet, &current);
    if (!facet) return 6;
    const std::locale locale(current,
        const_cast<std::ctype<unsigned short>*>(static_cast<const std::ctype<unsigned short>*>(facet)));
    if (std::use_facet<std::ctype<unsigned short>>(locale).tolower('A') != 'a') return 7;

    // Unwind a copy of this frame through the exported contract.
    using Unwind2 = NTSTATUS (NTAPI*)(ULONG, ULONG64, ULONG64, PRUNTIME_FUNCTION, PCONTEXT,
        PBOOLEAN, PVOID*, PULONG64, PKNONVOLATILE_CONTEXT_POINTERS, PULONG64, PULONG64,
        PEXCEPTION_ROUTINE*, ULONG);
    auto kernel = LoadLibraryExW(L"kernel32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto unwind = kernel ? reinterpret_cast<Unwind2>(GetProcAddress(kernel, "RtlVirtualUnwind2")) : nullptr;
    if (unwind)
    {
        CONTEXT frame{};
        RtlCaptureContext(&frame);
        DWORD64 image = 0;
        auto function = RtlLookupFunctionEntry(frame.Rip, &image, nullptr);
        if (!function) return 4;
        BOOLEAN machineFrame = FALSE;
        PVOID handlerData = nullptr;
        ULONG64 establisher = 0;
        PEXCEPTION_ROUTINE handler = nullptr;
        auto status = unwind(UNW_FLAG_NHANDLER, image, frame.Rip, function, &frame, &machineFrame, &handlerData,
            &establisher, nullptr, nullptr, nullptr, &handler, 0);
        if (status < 0 || !frame.Rip || !establisher) return 5;
    }
    if (kernel) FreeLibrary(kernel);
    try
    {
        throw 42;
    }
    catch (int value)
    {
        return value == 42 ? 0 : 2;
    }
}

void CppRuntime(const Context& context)
{
    // The fixture imports the shared runtime so RTTI and throw calls reach physical DLL exports.
    RunTarget(context);
    std::vector<std::pair<std::string, size_t>> names{
        {"__RTDynamicCast", 5}, {"__RTCastToVoid", 1}, {"__RTtypeid", 1}, {"_CxxThrowException", 2}};
    auto catalog = context.collector.parent_path() / L"ApiCatalog.sqlite";
    for (const auto& [name, count] : names)
    {
        auto plans = Query(catalog,
                           "SELECT f.parameters,p.argument_count FROM functions f "
                           "JOIN plans p ON p.function_id=f.id WHERE f.module='vcruntime140.dll' AND f.name=?",
                           Json::array({name}));
        Require(plans.size() == 1 && plans[0]["argument_count"] == count &&
                    Json::parse(plans[0]["parameters"].get<std::string>()).size() == count,
                "RTTI catalog differs", plans);
    }
    auto layout = Query(catalog, "SELECT layout FROM types WHERE name='ThrowInfo'");
    Require(layout.size() == 1 && Json::parse(layout[0]["layout"].get<std::string>())["kind"] == "Structure",
            "ThrowInfo layout missing", layout);
    for (auto module : {"kernel32.dll", "ntdll.dll"})
    {
        auto plans = Query(catalog,
                           "SELECT f.result,f.parameters,p.argument_count FROM functions f "
                           "JOIN plans p ON p.function_id=f.id WHERE f.module=? AND f.name='RtlVirtualUnwind2'",
                           Json::array({module}));
        Require(plans.size() == 1 && plans[0]["result"] == "NTSTATUS" && plans[0]["argument_count"] == 13 &&
                    Json::parse(plans[0]["parameters"].get<std::string>()).size() == 13,
                "Unwind catalog differs", plans);
    }
    auto native = context.Has(L"--native");
    Capture::Run(context, {.limit = 64, .instructions = !native}, [&](Capture& capture)
    {
        auto rows = capture.Calls();
#ifndef _DEBUG
        auto constructors = Named(rows, "??0?$ctype@G@std@@QEAA@AEBV_Locinfo@1@_K@Z");
        Require(!constructors.empty(), "Locale facet constructor missing");
        for (const auto& row : constructors)
            Require(row["argument_count"] == 3 && Data(row["arguments"]).size() == 24 &&
                        Read<uint64_t>(Data(row["arguments"])) && row["result"] == 0 && !row["ended"].is_null(),
                    "Locale constructor contract differs", row);
#endif
        if (native) return;
        bool throwInfo = false, unwindInput = false, unwindOutput = false;
        if (GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "RtlVirtualUnwind2"))
            names.emplace_back("RtlVirtualUnwind2", 13);
        for (const auto& [name, count] : names)
        {
            Json calls = Json::array();
            for (const auto& row : Named(rows, name))
                if (!_stricmp(row["module"].get_ref<const std::string&>().c_str(),
                    count == 13 ? "kernel32.dll" : RuntimeModule)) calls.push_back(row);
            Require(!calls.empty(), "Runtime export missing: " + name);
            for (const auto& row : calls)
            {
                Require(row["argument_count"] == count && Data(row["arguments"]).size() == count * 8 &&
                            !(row["flags"].get<uint32_t>() & 256) && !row["ended"].is_null(),
                        "Runtime contract differs", row);
                if (name == "__RTDynamicCast")
                    Require(row["parameters"].get<std::string>().contains("vfptrOffset"), "RTTI parameter missing");
                if (name == "_CxxThrowException")
                    Require(row["parameters"].get<std::string>().contains("pThrowInfo"), "Throw parameter missing");
                for (const auto& value : Values(row["input"]))
                {
                    throwInfo |= name == "_CxxThrowException" && value.index == 1 && value.data.size() == 16;
                    unwindInput |= count == 13 && value.index == 4 && value.original > 64 && value.data.size() == 64 &&
                                   (value.flags & 1);
                }
                for (const auto& value : Values(row["output"]))
                    unwindOutput |= count == 13 && value.index == 4 && value.data.size() == 64;
                CheckLimit(row, 64);
            }
        }
        Require(throwInfo, "ThrowInfo capture missing");
        Require(names.size() == 4 || (unwindInput && unwindOutput), "Unwind context captures missing");
    }, 60);
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, CppRuntime); }

#elif defined(DETOURIST_TEST_DetouristCxxCxTests)

using namespace Detourist::Tests;
int CxxCxWorkload();

void CxxCx(const Context& context)
{
    // C++/CX constructors and accessors must preserve their native reference argument convention.
    const std::string method = "??0FailureException@Platform@@QE$AAA@PE$AAVString@1@@Z";
    const std::vector<std::string> accessors{"?ToString@Exception@Platform@@UE$AAAPE$AAVString@2@XZ",
                                             "?get@Message@Exception@Platform@@QE$AAAPE$AAVString@3@XZ"};
    auto catalog = context.collector.parent_path() / L"ApiCatalog.sqlite";
    for (const auto& name : {method, accessors[0], accessors[1]})
    {
        auto plans = Query(catalog,
                           "SELECT f.parameters,p.argument_bytes,p.result_bytes FROM functions f "
                           "JOIN plans p ON p.function_id=f.id WHERE f.module='vccorlib140.dll' AND f.name=?",
                           Json::array({name}));
        Require(plans.size() == 1 && Data(plans[0]["argument_bytes"]) == (name == method ? Bytes{8, 8} : Bytes{8}) &&
                    plans[0]["result_bytes"] == (name == method ? 0 : 8),
                "C++/CX catalog plan differs", plans);
    }
    RunTarget(context);
    Capture::Run(context, {.limit = 64}, [&](Capture& capture)
    {
        auto rows = capture.Calls("lower(COALESCE(d.module,a.module))='vccorlib140.dll' AND (c.flags & 256)=0");
        for (const auto& name : {method, accessors[0], accessors[1]})
        {
            auto calls = Named(rows, name);
            Require(!calls.empty(), "C++/CX method missing", rows);
            const auto& row = calls.back();
            auto arguments = Data(row["arguments"]);
            Require(arguments.size() == (name == method ? 16u : 8u) && Read<uint64_t>(arguments) &&
                        (name == method ? Read<uint64_t>(arguments, 8) && row["result"] == 0 : row["result"] != 0),
                    "C++/CX reference arguments differ", row);
        }
    });
}

int wmain(int argc, wchar_t** argv) { return Run<CxxCxWorkload>(argc, argv, CxxCx); }

#elif defined(DETOURIST_TEST_DetouristHookTests)

#include <detours.h>
#include "DetoursAllocation.h"

using namespace Detourist;

struct HeapOwner
{
    HANDLE start;
    HANDLE locked;
    HANDLE release;
};

DWORD WINAPI HoldHeap(void* parameter)
{
    auto& owner = *static_cast<HeapOwner*>(parameter);
    WaitForSingleObject(owner.start, INFINITE);
    if (!HeapLock(GetProcessHeap())) return GetLastError();
    SetEvent(owner.locked);
    WaitForSingleObject(owner.release, INFINITE);
    HeapUnlock(GetProcessHeap());
    return ERROR_SUCCESS;
}

__declspec(noinline) DWORD WINAPI Probe(DWORD value)
{
    volatile DWORD result = value;
    return result * 17 + 3;
}
decltype(&Probe) OriginalProbe = Probe;
DWORD WINAPI ObserveProbe(DWORD value) { return OriginalProbe(value) + 11; }

template<size_t Index> __declspec(noinline) DWORD WINAPI ConcurrentProbe(DWORD value)
{
    volatile DWORD input = value;
    return input * 17 + 3 + static_cast<DWORD>(Index);
}

constexpr auto ConcurrentProbes = []<size_t... Indices>(std::index_sequence<Indices...>)
{
    return std::array{&ConcurrentProbe<Indices>...};
}(std::make_index_sequence<32>{});

DWORD WINAPI ConcurrentObserver(DWORD value) { return value * 23 + 5; }

struct TransactionWorkload
{
    std::atomic<bool> stop = false;
    std::atomic<DWORD> calls = 0, invalid = 0, created = 0;
    std::atomic<DWORD> badIndex = 0, badValue = 0;
};

DWORD WINAPI CallProbes(void* parameter)
{
    auto& state = *static_cast<TransactionWorkload*>(parameter);
    for (unsigned pass = 0; pass < 256 && !state.stop; ++pass)
    {
        auto index = pass % ConcurrentProbes.size();
        auto volatile probe = ConcurrentProbes[index];
        auto result = probe(9);
        if (result != 156 + index && result != 212)
        {
            state.badIndex = static_cast<DWORD>(index);
            state.badValue = result;
            ++state.invalid;
        }
        ++state.calls;
    }
    return 0;
}

DWORD WINAPI ContinuousProbes(void* parameter)
{
    auto& state = *static_cast<TransactionWorkload*>(parameter);
    while (!state.stop) CallProbes(parameter);
    return 0;
}

DWORD WINAPI CreateProbeThreads(void* parameter)
{
    auto& state = *static_cast<TransactionWorkload*>(parameter);
    while (!state.stop)
    {
        Handle thread(CreateThread(nullptr, 0, CallProbes, parameter, 0, nullptr));
        if (!thread) return GetLastError();
        ++state.created;
        if (WaitForSingleObject(thread.get(), 5000) != WAIT_OBJECT_0) return ERROR_TIMEOUT;
    }
    return 0;
}

int ConcurrentTransactions(bool denied, bool granted)
{
    // An inaccessible peer requires an existing capability even when other peers have already been suspended.
    const bool restricted = denied || granted;
    if (restricted)
    {
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &raw)) return 1;
        Handle token(raw);
        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid) ||
            !AdjustTokenPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr)) return 2;
    }
    TransactionWorkload state;
    std::array<Handle, 5> workers;
    auto stop = [&](TransactionWorkload*)
    {
        state.stop = true;
        for (auto& worker : workers)
            if (worker && WaitForSingleObject(worker.get(), 10000) != WAIT_OBJECT_0) std::abort();
    };
    std::unique_ptr<TransactionWorkload, decltype(stop)> cleanup(&state, stop);
    for (size_t index = 0; index < workers.size() - 1; ++index)
    {
        workers[index].reset(CreateThread(nullptr, 0, ContinuousProbes, &state, 0, nullptr));
        if (!workers[index]) return 3;
    }
    ACL acl{ACL_REVISION, 0, sizeof(ACL), 0, 0};
    SECURITY_DESCRIPTOR descriptor{};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, &acl, FALSE)) return 4;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), &descriptor, FALSE};

    // Retained exited thread objects must not prevent a transaction from suspending its live peers.
    Handle exited(CreateThread(nullptr, 0, CallProbes, &state, 0, nullptr));
    DWORD exitedCode = STILL_ACTIVE;
    if (!exited || WaitForSingleObject(exited.get(), 5000) != WAIT_OBJECT_0 ||
        !GetExitCodeThread(exited.get(), &exitedCode) || exitedCode != ERROR_SUCCESS) return 15;
    DWORD id = 0;
    workers.back().reset(CreateThread(restricted ? &attributes : nullptr, 0,
        denied ? ContinuousProbes : CreateProbeThreads, &state, 0, &id));
    if (!workers.back()) return 5;
    if (restricted)
    {
        Handle inaccessible(OpenThread(THREAD_SUSPEND_RESUME, FALSE, id));
        if (inaccessible || GetLastError() != ERROR_ACCESS_DENIED) return 6;
    }
    auto deadline = GetTickCount64() + 5000;
    while ((!state.calls || (!denied && !state.created)) && GetTickCount64() < deadline) Sleep(1);
    if (!state.calls || (!denied && !state.created)) return 7;

    // Publish distinct hooks while peers execute them and create short-lived callers.
    auto originals = ConcurrentProbes;
    for (size_t index = 0; index < originals.size(); ++index)
    {
        LONG error = DetourTransactionBegin();
        if (error) return 8;
        error = DetourAttach(reinterpret_cast<void**>(&originals[index]),
            reinterpret_cast<void*>(ConcurrentObserver));
        if (error) { DetourTransactionAbort(); return 9; }
        auto prior = std::exchange(DetouristTransactionThreads::StartupThread,
            granted ? workers.back().get() : nullptr);
        error = DetourTransactionCommit();
        DetouristTransactionThreads::StartupThread = prior;
        auto volatile probe = ConcurrentProbes[index];
        if (denied)
        {
            if (error != ERROR_ACCESS_DENIED || originals[index] != ConcurrentProbes[index] ||
                probe(9) != 156 + index)
            {
                std::cerr << "FAIL: denied transaction " << index << ": error=" << error <<
                    ", call=" << probe(9) << ", original changed=" <<
                    (originals[index] != ConcurrentProbes[index]) << '\n';
                return 10;
            }
        }
        else if (error || probe(9) != 212 || originals[index](9) != 156 + index)
        {
            std::cerr << "FAIL: concurrent transaction " << index << ": error=" << error <<
                ", call=" << probe(9) << ", original=" << originals[index](9) << '\n';
            return 11;
        }
    }
    cleanup.reset();
    for (auto& worker : workers)
    {
        DWORD code = 0;
        if (!GetExitCodeThread(worker.get(), &code) || code) return 12;
    }
    if (state.invalid)
    {
        std::cerr << "FAIL: concurrent calls=" << state.calls << ", invalid=" << state.invalid <<
            ", index=" << state.badIndex << ", value=" << state.badValue << '\n';
        return 13;
    }
    std::cout << "PASS: " << (denied ? "inaccessible peers abort hooks and resume callers" :
        granted ? "granted peer handles preserve hooks, churn and retained exited callers" :
        "thread churn and retained exited callers preserve calls and trampolines") <<
        "; calls=" << state.calls << ".\n";
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2)
    {
        // The fixture must prove strict CFG is active before exercising indirect calls and trampolines.
        if (!wcscmp(argv[1], L"--cfg"))
        {
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy{};
            policy.EnableControlFlowGuard = 1;
            policy.StrictMode = 1;
            if (!SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, &policy, sizeof(policy)) ||
                !GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy,
                    &policy, sizeof(policy)) || !policy.EnableControlFlowGuard || !policy.StrictMode) return 14;
        }
        return ConcurrentTransactions(!wcscmp(argv[1], L"--denied"), !wcscmp(argv[1], L"--granted"));
    }

    // A heap owner remains suspended throughout the real hook transaction.
    Handle start(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Handle locked(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Handle release(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    HeapOwner owner{start.get(), locked.get(), release.get()};
    Handle thread(CreateThread(nullptr, 0, HoldHeap, &owner, 0, nullptr));
    SetEvent(start.get());
    if (!start || !locked || !release || !thread || WaitForSingleObject(locked.get(), 5000) != WAIT_OBJECT_0)
    {
        SetEvent(release.get());
        if (thread) WaitForSingleObject(thread.get(), 5000);
        std::cerr << "FAIL: cannot establish heap owner.\n";
        return 1;
    }
    LONG status = DetourTransactionBegin();
    if (!status)
    {
        status = DetourUpdateThread(thread.get());
        if (!status) status = DetourAttach(reinterpret_cast<void**>(&OriginalProbe),
            reinterpret_cast<void*>(ObserveProbe));
        if (status) DetourTransactionAbort();
        else status = DetourTransactionCommit();
    }
    SetEvent(release.get());
    bool resumed = WaitForSingleObject(thread.get(), 5000) == WAIT_OBJECT_0;
    DWORD exitCode = ERROR_GEN_FAILURE;
    GetExitCodeThread(thread.get(), &exitCode);
    volatile DWORD input = 9;
    if (status || !resumed || exitCode || Probe(input) != 167 || OriginalProbe(input) != 156)
    {
        std::cerr << "FAIL: hook transaction under heap lock: " << status << '\n';
        return 1;
    }
    std::cout << "PASS: heap owner resumed, hook executes, trampoline preserves original.\n";
    return 0;
}

#elif defined(DETOURIST_TEST_DetouristMemoryCaptureTests)

#include "CaptureValues.h"

using namespace Detourist;
using namespace Detourist::Tests;
volatile LONG CaptureMemoryFaults = 0;

LONG CALLBACK ObserveCaptureMemoryFault(EXCEPTION_POINTERS* exception)
{
    const auto code = exception->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ACCESS_VIOLATION || code == STATUS_GUARD_PAGE_VIOLATION)
        InterlockedIncrement(&CaptureMemoryFaults);
    return EXCEPTION_CONTINUE_SEARCH;
}

int wmain()
{
    try
    {
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        auto release = [](void* memory) { if (memory) VirtualFree(memory, 0, MEM_RELEASE); };
        std::unique_ptr<void, decltype(release)> allocation(VirtualAlloc(nullptr, system.dwPageSize * 2,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), release);
        std::unique_ptr<void, decltype(&RemoveVectoredExceptionHandler)> handler(
            AddVectoredExceptionHandler(1, ObserveCaptureMemoryFault), &RemoveVectoredExceptionHandler);
        Require(allocation && handler, "Cannot initialize capture memory probes");
        auto boundary = static_cast<BYTE*>(allocation.get()) + system.dwPageSize;
        std::array<BYTE, 32> expected{}, copied{};
        for (size_t index = 0; index < expected.size(); ++index) expected[index] = static_cast<BYTE>(index + 1);
        memcpy(boundary - expected.size(), expected.data(), expected.size());
        Require(ReadCaptureMemory(boundary - expected.size(), copied.data(), copied.size()) && copied == expected,
            "Readable memory lost captured bytes");

        // Invalid, inaccessible and partially readable spans never enter the application's exception handlers.
        SetLastError(0x12345678);
        Require(!ReadCaptureMemory(reinterpret_cast<void*>(9), copied.data(), copied.size()) &&
            GetLastError() == 0x12345678, "Invalid memory changed the caller's error state");
        DWORD previous = 0;
        Require(VirtualProtect(boundary, system.dwPageSize, PAGE_NOACCESS, &previous) &&
            !ReadCaptureMemory(boundary - 16, copied.data(), copied.size()),
            "A partial memory read was reported as complete");

        // A capture probe must preserve the application's first guard-page fault.
        Require(VirtualProtect(boundary, system.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &previous) &&
            !ReadCaptureMemory(boundary, copied.data(), copied.size()), "A guarded page was captured");
        MEMORY_BASIC_INFORMATION region{};
        Require(VirtualQuery(boundary, &region, sizeof(region)) && (region.Protect & PAGE_GUARD),
            "Capture consumed the application's guard page");
        auto freed = allocation.get();
        allocation.reset();
        Require(!ReadCaptureMemory(freed, copied.data(), copied.size()) && !CaptureMemoryFaults,
            "Memory capture dispatched an application exception");
        std::cout << "PASS: inaccessible, partial, guarded and released memory remains passive.\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}

#elif defined(DETOURIST_TEST_DetouristAutomationCaptureTests)

#include "CatalogCaptureValues.h"

using namespace Detourist;

struct Snapshot
{
    Value value;
    std::vector<std::byte> bytes;
};

void Require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

int wmain()
{
    try
    {
        Transport transport;
        transport.Create(L"Local\\DetouristAutomationBuffers." + std::to_wstring(GetCurrentProcessId()),
            GetCurrentProcessId(), 128, 0, AllApis, false);
        auto slot = transport.Acquire();
        Require(slot != nullptr, "Cannot acquire capture storage.");
        struct State
        {
            Transport* transport;
            Event event{};
            uint64_t captureLimits[MaximumArguments]{};
            uint32_t initializedOutputs = 0;
        } state{&transport};
        ExportParameter parameter{32, -1, 0, 1, 19, ExportValueKind::SafeArray};
        std::span<const ExportMember> members;
        auto capture = [&](const void* pointer, bool leaving = false, uint32_t flags = 0, uint64_t result = 0)
        {
            slot->event = {};
            state.event = {};
            state.event.arguments[0] = reinterpret_cast<uint64_t>(pointer);
            state.event.flags = flags;
            state.event.result = result;
            CaptureCatalogValues(state, slot, leaving, std::span{&parameter, 1}, members);
            std::vector<Snapshot> values;
            for (uint32_t offset = 0; offset < slot->event.payloadBytes;)
            {
                Value value{};
                memcpy(&value, Transport::Payload(slot) + offset, sizeof(value));
                auto bytes = Transport::Payload(slot) + offset + sizeof(value);
                if (value.kind != ValueKind::AutomationLink)
                    values.push_back({value, {bytes, bytes + value.capturedBytes}});
                offset += static_cast<uint32_t>(sizeof(value)) + value.capturedBytes;
            }
            return values;
        };

        // Real guard pages bound pointer storage, descriptors, dimension tables and array data independently.
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        auto pages = Detourist::Tests::GuardedPages(system.dwPageSize, PAGE_NOACCESS);
        auto boundary = pages.get() + system.dwPageSize;
        struct Descriptor
        {
            SAFEARRAY array;
            SAFEARRAYBOUND more[2];
        } descriptor{{3, FADF_STATIC, 1, 0, nullptr, {{3, -4}}}, {{2, 7}, {2, 1}}};
        BYTE data[]{0, 7, 14, 21, 28, 35, 42, 49, 56, 63, 70, 77};
        descriptor.array.pvData = data;
        for (uint32_t limit : {16u, 31u, 64u, 128u})
        {
            transport.Header()->bufferLimit = limit;
            auto array = &descriptor.array;
            auto values = capture(&array);
            Require(values.size() == 3 && values[1].value.kind == ValueKind::SafeArray &&
                values[1].value.originalBytes == 48 && values[1].bytes.size() == std::min(limit, 48u) &&
                values[2].value.kind == ValueKind::SafeArrayData && values[2].value.originalBytes == sizeof(data) &&
                values[2].bytes.size() == sizeof(data) && !memcmp(values[2].bytes.data(), data, sizeof(data)),
                "A multidimensional array lost its descriptor, dimensions or bounded data.");
            Require(capture(&array, true, Failed).empty() && capture(&array, true, Unwound).empty() &&
                capture(&array, true, Skipped).empty(), "An unsuccessful call exposed an output array.");
            values = capture(boundary);
            Require(values.size() == 1 && values[0].value.flags & Unreadable,
                "Unreadable pointer storage established an array.");
            array = nullptr;
            Require(capture(&array).size() == 1, "A null array established referenced data.");
            array = reinterpret_cast<SAFEARRAY*>(boundary);
            values = capture(&array);
            Require(values.size() == 2 && values[1].value.flags & Unreadable,
                "An unreadable array descriptor established elements.");
            array = reinterpret_cast<SAFEARRAY*>(boundary - 16);
            memcpy(array, &descriptor, 16);
            values = capture(&array);
            Require(values.size() == 2 && values[1].bytes.size() == (limit <= 16 ? limit : 0),
                "An incomplete descriptor established elements.");
            array = reinterpret_cast<SAFEARRAY*>(boundary - sizeof(SAFEARRAY));
            memcpy(array, &descriptor, sizeof(SAFEARRAY));
            values = capture(&array);
            Require(values.size() == 3 && values[2].value.flags & Unreadable && values[2].bytes.empty(),
                "An incomplete dimension table established data.");
            array = &descriptor.array;
            descriptor.array.pvData = boundary - 8;
            values = capture(&array);
            Require(values.size() == 3 && values[2].value.flags & Unreadable && values[2].bytes.empty(),
                "An unreadable data tail fabricated a complete snapshot.");
            descriptor.array.pvData = data;
            descriptor.array.rgsabound[0].cElements = MAXDWORD;
            descriptor.more[0].cElements = descriptor.more[1].cElements = MAXDWORD;
            values = capture(&array);
            Require(values.size() == 3 && values[2].value.flags & Unreadable && values[2].bytes.empty(),
                "An overflowing dimension product established array data.");
            descriptor.array.rgsabound[0].cElements = 3;
            descriptor.more[0].cElements = descriptor.more[1].cElements = 2;
        }

        // A variant referring back to its enclosing array terminates traversal without following a cycle.
        VARIANT child{};
        SAFEARRAY cyclic{1, FADF_VARIANT, sizeof(VARIANT), 0, &child, {{1, 0}}};
        auto array = &cyclic;
        child.vt = VT_ARRAY | VT_VARIANT;
        child.parray = array;
        auto values = capture(&array);
        Require(values.size() == 5, "A cyclic array did not stop reference traversal.");

        // Return-bounded wire spans avoid entry reads and reject invalid completion pointers before touching memory.
        parameter = {0, -1, 0, 1, 2, ExportValueKind::ReturnedSpan};
        auto end = reinterpret_cast<uint64_t>(boundary);
        memset(boundary - 32, 0x6a, 32);
        for (uint32_t limit : {16u, 64u})
        {
            transport.Header()->bufferLimit = limit;
            Require(capture(boundary).empty() && capture(boundary - 32, true).empty() &&
                capture(boundary - 32, true, 0, end - 33).empty() &&
                capture(boundary - 32, true, Failed, end).empty() &&
                capture(boundary - 32, true, Skipped, end).empty() &&
                capture(boundary - 32, true, Unwound, end).empty(),
                "An invalid completion established a wire buffer.");
            values = capture(boundary - 32, true, 0, end);
            Require(values.size() == 1 && values[0].value.originalBytes == 32 &&
                values[0].bytes == std::vector<std::byte>(std::min(limit, 32u), std::byte{0x6a}) &&
                values[0].value.flags == (limit < 32 ? Truncated : 0), "A wire span lost its bounded bytes.");
            values = capture(boundary - 8, true, 0, end + 8);
            Require(values.size() == 1 && values[0].bytes.empty() && values[0].value.flags & Unreadable,
                "An unreadable wire span fabricated a complete snapshot.");
        }
        // A font name is followed only when the owning snapshot retains its entire pointer field.
        parameter = {sizeof(FONTDESC), -1, 0, 1, 1, ExportValueKind::Bytes};
        ExportMember member{0, offsetof(FONTDESC, lpstrName), 0, 2, 0, 9};
        members = std::span{&member, 1};
        FONTDESC font{};
        font.cbSizeofstruct = sizeof(font);
        wchar_t name[] = L"Segoe UI";
        auto guardedName = boundary - sizeof(name);
        for (uint32_t limit : {8u, 16u, 31u, 64u})
        {
            transport.Header()->bufferLimit = limit;
            memcpy(guardedName, name, sizeof(name));
            font.lpstrName = reinterpret_cast<wchar_t*>(guardedName);
            values = capture(&font);
            Require(values.size() == (limit < 16 ? 1 : 2), "An incomplete font pointer established text.");
            if (limit >= 16)
            {
                const auto& text = values[1];
                Require(text.value.parameter == ((offsetof(FONTDESC, lpstrName) + 1) << 8) &&
                    text.value.kind == ValueKind::Utf16 && text.bytes.size() == std::min(limit, 18u) &&
                    !memcmp(text.bytes.data(), name, text.bytes.size()) &&
                    text.value.flags == (MemberData | ReferencedData | (limit < sizeof(name) ? Truncated : 0)),
                    "A guarded font name lost text, ownership or truncation state.");
                font.lpstrName = reinterpret_cast<wchar_t*>(boundary);
                values = capture(&font);
                Require(values.size() == 2 && values[1].bytes.empty() && values[1].value.flags & Unreadable,
                    "An unreadable font pointer fabricated text.");
            }
            font.lpstrName = nullptr;
            Require(capture(&font).size() == 1, "A null font name established text.");
            font.lpstrName = reinterpret_cast<wchar_t*>(guardedName);
            memcpy(boundary - 8, &font, 8);
            values = capture(boundary - 8);
            Require(values.size() == 1, "A partial font descriptor fabricated referenced text.");
            Require(capture(&font, true).empty() && capture(&font, false, Skipped).size() <= 1 &&
                capture(&font, false, Unwound).size() <= 1, "An invalid invocation followed a font pointer.");
        }
        std::cout << "PASS: bounded Automation arrays, wire spans and font names with guard pages and cycles.\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}

#elif defined(DETOURIST_TEST_DetouristBreakpointMetadataTests)

using namespace Detourist::Tests;
void BreakpointMetadata(const Context& context)
{
    int repeats = 8;
    if (!context.arguments.empty())
    {
        Require(context.arguments.size() == 2 && std::wstring_view(context.arguments[0]) == L"--repeats",
                "Expected --repeats <count>");
        size_t end = 0;
        std::wstring value(context.arguments[1]);
        repeats = std::stoi(value, &end);
        Require(end == value.size() && repeats > 0, "Repeat count must be positive");
    }
    Collector collector(context.collector, context.directory);
    auto hello = collector.Call("hello");
    const std::string expected = "ABI::Windows::Foundation::IStringable::ToString";
    for (int index = 0; index < repeats; ++index)
    {
        // The first entry stop must expose the published name and complete argument metadata.
        auto database = context.directory / (L"first-" + std::to_wstring(index) + L".db");
        collector.Call("launch", {{"database", Text(database)},
                                  {"executable", Text(context.target)},
                                  {"arguments", "--private-projected"},
                                  {"bufferLimit", 64},
                                  {"apiMask", hello["comMask"]},
                                  {"followChildren", false},
                                  {"instructionEngine", true},
                                  {"entryMask", hello["comMask"]}});
        auto stopped = collector.Wait([](const Json& status)
        { return status["breakpoint"] == true || status["finished"] == true; });
        Require(stopped["breakpoint"] == true && stopped["leaving"] == false, "Entry breakpoint missing", stopped);
        auto call = stopped["stoppedCall"];
        Require(call["name"] == expected && call["arguments"].size() == 2 &&
                    call["parameters"].get<std::string>().contains("HSTRING * value") &&
                    stopped["message"] == "Paused at " + expected,
                "Entry metadata differs", stopped);
        auto definitions = Query(database,
                                 "SELECT a.name,a.argument_count FROM apis a "
                                 "JOIN targets t ON t.id=a.target WHERE t.pid=? AND a.id=?",
                                 Json::array({call["pid"], call["api"]}));
        Require(definitions.size() == 1 && definitions[0]["name"] == expected && definitions[0]["argument_count"] == 2,
                "Entry metadata was not persisted", definitions);

        // Switch to an exact return stop for the same first call before allowing the process to exit.
        collector.Call("breaks", {{"entryMask", 0}, {"exitMask", 0}});
        collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", call["api"]}});
        collector.Call("continue");
        stopped = collector.Wait([&](const Json& status)
        {
            return status["finished"] == true || (status["breakpoint"] == true && status["leaving"] == true &&
                                                  status["stoppedCall"]["id"] == call["id"]);
        });
        Require(stopped["breakpoint"] == true && stopped["stoppedCall"]["name"] == expected &&
                    stopped["stoppedCall"]["arguments"].size() == 2 &&
                    std::stoull(stopped["stoppedCall"]["result"].get<std::string>(), nullptr, 16) == 0,
                "Return metadata differs", stopped);
        collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
        collector.Call("continue");
        collector.Wait([](const Json& status) { return status["finished"] == true; });
        auto page = collector.Call("page", {{"database", Text(database)}, {"limit", 1}});
        const auto& targets = page["targets"];
        Require(!targets.empty() &&
                    std::ranges::all_of(targets, [](const Json& target) { return target["state"] == "Exited"; }),
                "Target did not exit cleanly", targets);
        std::cout << "First entry/return metadata passed: " << index + 1 << '/' << repeats << '\n' << std::flush;
    }
    collector.Close();
}

int wmain(int argc, wchar_t** argv) { return Run(argc, argv, BreakpointMetadata); }

#else
#error Select a native test target.
#endif

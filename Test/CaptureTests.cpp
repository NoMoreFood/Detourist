#include "TestSupport.h"
#include "Session.h"
#include "FixtureProtocol.h"
#include <winternl.h>
#include <detours.h>

using namespace Detourist;

void Require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

void Wait(Session& session, std::function<void(const SessionStatus&)> inspect = {})
{
    auto deadline = GetTickCount64() + 40000;
    while (GetTickCount64() < deadline)
    {
        auto status = session.Status();
        if (inspect) inspect(status);
        if (status.finished)
        {
            std::wcout << status.message << L" Calls=" << status.calls << L" Records=" << status.records << L'\n';
            Require(status.message.find(L"stopped:") == std::wstring::npos, "Capture failed.");
            return;
        }
        Sleep(10);
    }
    throw std::runtime_error("Capture did not finish.");
}

struct Fixture
{
    std::wstring name;
    Handle mapping, run, done, stop, process;
    std::unique_ptr<FixtureMetrics, decltype(&UnmapViewOfFile)> metrics{nullptr, UnmapViewOfFile};
    DWORD pid = 0;
    double startupMilliseconds = 0;
    Fixture()
    {
        static uint32_t sequence = 0;
        name = L"Local\\DetouristFixture." + std::to_wstring(GetCurrentProcessId()) + L"." +
            std::to_wstring(++sequence);
        mapping.reset(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
            sizeof(FixtureMetrics), name.c_str()));
        metrics.reset(static_cast<FixtureMetrics*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, 0)));
        run.reset(CreateEventW(nullptr, FALSE, FALSE, (name + L".run").c_str()));
        done.reset(CreateEventW(nullptr, FALSE, FALSE, (name + L".done").c_str()));
        stop.reset(CreateEventW(nullptr, TRUE, FALSE, (name + L".stop").c_str()));
        Require(metrics && run && done && stop, "Cannot create fixture controls.");
        auto command = L"\"" + ModuleDirectory() + L"\\DetouristTestTarget.exe\" --controlled " + name;
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION created{};
        auto started = std::chrono::steady_clock::now();
        Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
            &startup, &created) != FALSE, "Start fixture");
        process.reset(created.hProcess);
        Handle thread(created.hThread);
        pid = created.dwProcessId;
        if (WaitForSingleObject(done.get(), 10000) != WAIT_OBJECT_0)
        {
            TerminateProcess(process.get(), ERROR_TIMEOUT);
            throw std::runtime_error("Fixture did not start.");
        }
        startupMilliseconds = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
    }
    ~Fixture()
    {
        SetEvent(stop.get());
        if (WaitForSingleObject(process.get(), 10000) != WAIT_OBJECT_0) TerminateProcess(process.get(), ERROR_TIMEOUT);
    }
    void Start(uint32_t iterations)
    {
        metrics->iterations = iterations;
        SetEvent(run.get());
    }
    void Done()
    {
        Require(WaitForSingleObject(done.get(), 30000) == WAIT_OBJECT_0, "Fixture workload did not finish.");
        Require(!metrics->errors && metrics->exceptionsHandled, "Capture changed fixture behavior.");
    }
};

void Ready(Session& session)
{
    auto deadline = GetTickCount64() + 20000;
    while (GetTickCount64() < deadline)
    {
        auto status = session.Status();
        if (status.capturing) return;
        if (status.finished) throw std::runtime_error(Utf8(status.message));
        Sleep(5);
    }
    throw std::runtime_error("Attachment did not finish.");
}

struct FixtureProcess
{
    Handle handle;
    DWORD pid;

    explicit FixtureProcess(std::wstring command)
    {
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION created{};
        Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
            &startup, &created) != FALSE, "Start capture fixture");
        handle.reset(created.hProcess);
        Handle thread(created.hThread);
        pid = created.dwProcessId;
    }

    ~FixtureProcess()
    {
        if (WaitForSingleObject(handle.get(), 0) == WAIT_TIMEOUT)
        {
            TerminateProcess(handle.get(), ERROR_TIMEOUT);
            WaitForSingleObject(handle.get(), 5000);
        }
    }
};

SessionStatus WaitForRejectedAttach(Session& session)
{
    auto deadline = GetTickCount64() + 20000;
    do
    {
        auto status = session.Status();
        Require(!status.capturing, "A rejected attachment entered the capturing state.");
        if (status.finished) return status;
        Sleep(5);
    } while (GetTickCount64() < deadline);
    throw std::runtime_error("Attachment did not report its failure.");
}

int ImageSigningTarget(const wchar_t* name)
{
    Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, (std::wstring(name) + L".ready").c_str()));
    Handle stop(OpenEventW(SYNCHRONIZE, FALSE, (std::wstring(name) + L".stop").c_str()));
    Require(ready && stop, "Cannot open signing-policy controls.");
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature{};
    signature.MicrosoftSignedOnly = 1;
    Check(SetProcessMitigationPolicy(ProcessSignaturePolicy, &signature, sizeof(signature)) != FALSE,
        "Set fixture image-signing policy");
    SetEvent(ready.get());
    Require(WaitForSingleObject(stop.get(), 30000) == WAIT_OBJECT_0, "Signing-policy fixture was not released.");
    return 0;
}

void ImageSigning(const std::wstring& output, bool instructions)
{
    auto name = L"Local\\DetouristImageSigning." + std::to_wstring(GetCurrentProcessId());
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, (name + L".ready").c_str()));
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, (name + L".stop").c_str()));
    Require(ready && stop, "Cannot create signing-policy controls.");
    FixtureProcess process(L"\"" + ModuleDirectory() + L"\\DetouristCaptureTests.exe\" --image-signing-target " + name);
    Require(WaitForSingleObject(ready.get(), 10000) == WAIT_OBJECT_0, "Signing-policy fixture did not start.");
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY before{};
    Require(GetProcessMitigationPolicy(process.handle.get(), ProcessSignaturePolicy, &before, sizeof(before)) &&
        before.MicrosoftSignedOnly, "Fixture signing policy was not enabled.");

    // A loader rejection must fail attachment without changing policy or terminating the application.
    CaptureOptions options{.followChildren = false, .startMinimized = true};
    options.instructionEngine = instructions;
    {
        Session session(output + L"\\image-signing.db", options, process.pid);
        auto status = WaitForRejectedAttach(session);
        std::wcout << status.message << L'\n';
        Require(status.message.find(
            L"Capture agent injection is blocked by the target's image-signing policy.") != std::wstring::npos,
            "A signing-policy rejection did not report the capture fault.");
    }
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY after{};
    Require(WaitForSingleObject(process.handle.get(), 0) == WAIT_TIMEOUT &&
        GetProcessMitigationPolicy(process.handle.get(), ProcessSignaturePolicy, &after, sizeof(after)) &&
        after.Flags == before.Flags, "Failed attachment changed target lifetime or signing policy.");
    SetEvent(stop.get());
    Require(WaitForSingleObject(process.handle.get(), 5000) == WAIT_OBJECT_0, "Signing-policy fixture did not finish.");
    DWORD code = STILL_ACTIVE;
    Require(GetExitCodeProcess(process.handle.get(), &code) && !code, "Signing-policy fixture failed.");
}

struct ThreadDiscoveryState
{
    volatile LONG filtered;
    volatile LONG suspended;
    volatile LONG stop;
    volatile LONG heartbeat[4];
};

ThreadDiscoveryState* DiscoveryState = nullptr;
auto OriginalSystemInformation = NtQuerySystemInformation;
using SuspendThreadFunction = NTSTATUS(NTAPI*)(HANDLE, PULONG);
SuspendThreadFunction OriginalSuspendThread = nullptr;

NTSTATUS NTAPI FilterSystemInformation(SYSTEM_INFORMATION_CLASS information, PVOID buffer, ULONG bytes,
    PULONG required)
{
    if (information != SystemProcessInformation)
        return OriginalSystemInformation(information, buffer, bytes, required);
    if (required) *required = sizeof(SYSTEM_PROCESS_INFORMATION);
    if (bytes < sizeof(SYSTEM_PROCESS_INFORMATION)) return static_cast<NTSTATUS>(0xC0000004);
    memset(buffer, 0, sizeof(SYSTEM_PROCESS_INFORMATION));
    InterlockedIncrement(&DiscoveryState->filtered);
    return 0;
}

NTSTATUS NTAPI CountThreadSuspension(HANDLE thread, PULONG previous)
{
    auto status = OriginalSuspendThread(thread, previous);
    if (status >= 0) InterlockedIncrement(&DiscoveryState->suspended);
    return status;
}

int ThreadDiscoveryTarget(const wchar_t* name, bool denied)
{
    Handle mapping(OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name));
    std::unique_ptr<ThreadDiscoveryState, decltype(&UnmapViewOfFile)> state(
        static_cast<ThreadDiscoveryState*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, 0)),
        UnmapViewOfFile);
    Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, (std::wstring(name) + L".ready").c_str()));
    Handle run(OpenEventW(SYNCHRONIZE, FALSE, (std::wstring(name) + L".run").c_str()));
    Require(state && ready && run, "Cannot open thread discovery controls.");
    // The installed observers retain this shared view until the target process exits.
    DiscoveryState = state.release();

    // Install the restricted snapshot before peers exist; only the external collector sees their IDs.
    OriginalSuspendThread = reinterpret_cast<SuspendThreadFunction>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendThread"));
    Require(OriginalSuspendThread && !DetourTransactionBegin(), "Cannot begin thread discovery hooks.");
    auto error = DetourAttach(reinterpret_cast<void**>(&OriginalSystemInformation),
        reinterpret_cast<void*>(FilterSystemInformation));
    if (!error) error = DetourAttach(reinterpret_cast<void**>(&OriginalSuspendThread),
        reinterpret_cast<void*>(CountThreadSuspension));
    if (error) DetourTransactionAbort();
    else error = DetourTransactionCommit();
    Require(!error, "Cannot install thread discovery hooks.");
    if (denied)
    {
        HANDLE raw = nullptr;
        Require(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &raw) != FALSE,
            "Cannot open fixture token.");
        Handle token(raw);
        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        Require(LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid) &&
            AdjustTokenPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr),
            "Cannot disable fixture debug privilege.");
    }
    ACL acl{ACL_REVISION, 0, sizeof(ACL), 0, 0};
    SECURITY_DESCRIPTOR descriptor{};
    Require(InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) &&
        SetSecurityDescriptorDacl(&descriptor, TRUE, &acl, FALSE), "Cannot restrict fixture peer.");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), &descriptor, FALSE};
    struct Worker { ThreadDiscoveryState* state; size_t index; };
    std::array<Worker, 4> contexts{};
    std::array<Handle, 4> workers;
    for (size_t index = 0; index < workers.size(); ++index)
    {
        contexts[index] = {DiscoveryState, index};
        DWORD id = 0;
        workers[index].reset(CreateThread(denied && index + 1 == workers.size() ? &attributes : nullptr, 0,
            [](void* value) -> DWORD
            {
                auto& worker = *static_cast<Worker*>(value);
                while (!InterlockedCompareExchange(&worker.state->stop, 0, 0))
                {
                    InterlockedIncrement(&worker.state->heartbeat[worker.index]);
                    Sleep(1);
                }
                return 0;
            }, &contexts[index], 0, &id));
        Require(static_cast<bool>(workers[index]), "Cannot start fixture peer.");
        if (denied && index + 1 == workers.size())
        {
            Handle inaccessible(OpenThread(THREAD_SUSPEND_RESUME, FALSE, id));
            Require(!inaccessible && GetLastError() == ERROR_ACCESS_DENIED, "Fixture peer is not inaccessible.");
        }
    }
    SetEvent(ready.get());
    Require(WaitForSingleObject(run.get(), 30000) == WAIT_OBJECT_0, "Thread discovery workload was not released.");
    for (int index = 0; index < 8; ++index)
        Require(MulDiv(21 + index, 6, 3) == 42 + index * 2, "Thread discovery capture changed MulDiv.");
    InterlockedExchange(&DiscoveryState->stop, 1);
    for (auto& worker : workers)
        Require(WaitForSingleObject(worker.get(), 5000) == WAIT_OBJECT_0, "Fixture peer remained suspended.");
    return 0;
}

void ThreadDiscovery(const std::wstring& output)
{
    for (bool denied : {false, true})
    {
        auto name = L"Local\\DetouristThreadDiscovery." + std::to_wstring(GetCurrentProcessId()) +
            (denied ? L".denied" : L".allowed");
        Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
            sizeof(ThreadDiscoveryState), name.c_str()));
        std::unique_ptr<ThreadDiscoveryState, decltype(&UnmapViewOfFile)> state(
            static_cast<ThreadDiscoveryState*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, 0)),
            UnmapViewOfFile);
        Handle ready(CreateEventW(nullptr, TRUE, FALSE, (name + L".ready").c_str()));
        Handle run(CreateEventW(nullptr, TRUE, FALSE, (name + L".run").c_str()));
        Require(state && ready && run, "Cannot create thread discovery controls.");
        FixtureProcess process(L"\"" + ModuleDirectory() + L"\\DetouristCaptureTests.exe\" --thread-discovery-target " +
            name + (denied ? L" denied" : L" allowed"));
        Require(WaitForSingleObject(ready.get(), 10000) == WAIT_OBJECT_0, "Thread discovery fixture did not start.");
        CaptureOptions options{.followChildren = false, .startMinimized = true};
        auto database = output + (denied ? L"\\thread-discovery-denied.db" : L"\\thread-discovery.db");
        {
            Session session(database, options, process.pid);
            if (denied)
            {
                auto status = WaitForRejectedAttach(session);
                Require(status.message.find(L"Capture hook installation failed: " +
                    ErrorText(ERROR_ACCESS_DENIED)) != std::wstring::npos,
                    "A denied fallback peer did not abort attachment with access denied.");
            }
            else Ready(session);
            Require(state->filtered > 0 && state->suspended > 0,
                "Attachment did not exercise restricted discovery and peer suspension.");

            // Each peer must make fresh progress after commit or abort, including the inaccessible one.
            std::array<LONG, 4> before{};
            for (size_t index = 0; index < before.size(); ++index) before[index] = state->heartbeat[index];
            auto deadline = GetTickCount64() + 5000;
            bool resumed = false;
            do
            {
                resumed = true;
                for (size_t index = 0; index < before.size(); ++index)
                    resumed &= state->heartbeat[index] != before[index];
                if (!resumed) Sleep(1);
            } while (!resumed && GetTickCount64() < deadline);
            Require(resumed, "Attachment left a peer suspended.");
            SetEvent(run.get());
            Require(WaitForSingleObject(process.handle.get(), 15000) == WAIT_OBJECT_0,
                "Thread discovery target did not finish.");
            DWORD code = STILL_ACTIVE;
            Require(GetExitCodeProcess(process.handle.get(), &code) && !code, "Thread discovery target failed.");
            if (!denied) Wait(session);
        }
        if (!denied)
        {
            Query query;
            query.api = "MulDiv";
            auto page = TraceStore::ReadPage(database, query);
            Require(page.calls.size() == 8, "Restricted discovery lost MulDiv calls.");
            for (auto& call : page.calls)
                Require(call.arguments[0] >= 21 && call.arguments[0] < 29 && call.arguments[1] == 6 &&
                    call.arguments[2] == 3 && call.result == call.arguments[0] * 2 && call.duration >= 0,
                    "Restricted discovery changed captured arguments or results.");
        }
    }
}

void ThreadDiscoveryMailbox()
{
    Transport collector, target;
    auto name = L"Local\\DetouristThreadMailbox." + std::to_wstring(GetCurrentProcessId());
    collector.Create(name, GetCurrentProcessId(), 128, 0, AllApis, false);
    Require(target.Open(name), "Cannot open thread discovery mailbox.");
    auto& request = collector.Header()->threadIds;
    std::array<DWORD, ThreadIdCapacity> ids{};
    DWORD count = 0;
    auto pending = [&]()
    {
        auto deadline = GetTickCount64() + 3000;
        while (InterlockedCompareExchange(&request.state, 2, 1) != 1)
        {
            Require(GetTickCount64() < deadline, "Thread discovery request did not become pending.");
            Sleep(1);
        }
    };
    auto begin = [&](DWORD capacity)
    {
        ids.fill(MAXDWORD);
        count = MAXDWORD;
        return std::async(std::launch::async, [&, capacity]()
        {
            return target.RequestThreadIds(ids.data(), capacity, &count);
        });
    };

    // A collector writing past the deadline retains its slot; its stale response cannot satisfy a new request.
    auto delayed = begin(ThreadIdCapacity);
    pending();
    Require(delayed.wait_for(std::chrono::seconds(7)) == std::future_status::ready &&
        delayed.get() == ERROR_TIMEOUT && !count && ids.front() == MAXDWORD && request.state == 2,
        "Timed-out processing reused or published its thread response.");
    Require(target.RequestThreadIds(ids.data(), ThreadIdCapacity, &count) == ERROR_BUSY && !count,
        "A timed-out collector lost ownership of its response slot.");
    request.error = ERROR_SUCCESS;
    request.count = 1;
    request.ids[0] = MAXDWORD;
    InterlockedExchange(&request.state, 3);
    auto fresh = begin(ThreadIdCapacity);
    pending();
    InterlockedExchange(&request.state, 1);
    collector.ServiceThreadIds(GetCurrentProcess(), GetCurrentProcessId());
    Require(fresh.get() == ERROR_SUCCESS && count &&
        std::find(ids.begin(), ids.begin() + count, GetCurrentThreadId()) != ids.begin() + count &&
        std::find(ids.begin(), ids.begin() + count, MAXDWORD) == ids.begin() + count,
        "A fresh request consumed stale thread IDs or omitted its process.");

    // Invalid responses and insufficient capacity fail without copying a partial thread set.
    for (unsigned scenario = 0; scenario < 4; ++scenario)
    {
        auto response = begin(scenario == 3 ? 1 : ThreadIdCapacity);
        pending();
        request.error = scenario == 2 ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
        request.count = scenario == 0 ? ThreadIdCapacity + 1 : 2;
        request.ids[0] = scenario == 1 ? 0 : GetCurrentThreadId();
        request.ids[1] = GetCurrentThreadId();
        InterlockedExchange(&request.state, 3);
        auto expected = scenario == 3 ? ERROR_INSUFFICIENT_BUFFER : ERROR_INVALID_DATA;
        Require(response.get() == expected && !count && ids.front() == MAXDWORD && ids.back() == MAXDWORD,
            "Malformed or oversized thread response was accepted or truncated.");
    }
    auto stopped = begin(ThreadIdCapacity);
    pending();
    collector.Stop();
    Require(stopped.get() == ERROR_CANCELLED && !count, "Stopped thread discovery did not cancel its waiter.");
}

void TransportPressure()
{
    // Delay the consumer until the bounded queue fills, then verify every producer's sequence.
    Transport consumer, producer;
    auto name = L"Local\\DetouristQueueTest." + std::to_wstring(GetCurrentProcessId());
    Require(!producer.Open(name) && GetLastError() == ERROR_FILE_NOT_FOUND,
        "A missing transport must preserve the Windows error.");
    consumer.Create(name, GetCurrentProcessId(), 128, 0, AllApis, false);

    // Malformed data and failed object access must remain distinguishable during bootstrap.
    {
        Transport invalid;
        auto version = std::exchange(consumer.Header()->version, 0u);
        auto opened = invalid.Open(name);
        auto error = GetLastError();
        consumer.Header()->version = version;
        Require(!opened && error == ERROR_INVALID_DATA, "Malformed transport did not report invalid data.");
    }
    {
        Transport invalid;
        auto controller = std::exchange(consumer.Header()->controllerId, 0u);
        auto opened = invalid.Open(name);
        auto error = GetLastError();
        consumer.Header()->controllerId = controller;
        Require(!opened && error == ERROR_INVALID_PARAMETER, "Controller access failure lost its Windows error.");
    }

    // Imported channels own their handles, while another observer can outlive the original owner.
    DWORD handlesBefore = 0, handlesAfter = 0;
    Require(GetProcessHandleCount(GetCurrentProcess(), &handlesBefore) != FALSE, "Cannot count capture handles.");
    {
        Transport observer;
        HANDLE transferredThread = nullptr;
        {
            TransportStartup startup{consumer.DuplicateTo(GetCurrentProcess(), GetCurrentThread()),
                consumer.Header()->captureIdentity};
            transferredThread = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.startupThread));
            Transport imported(startup);
            Require(startup.owned && imported.Open(startup.captureIdentity), "Cannot adopt capture handles.");
            PUBLIC_OBJECT_BASIC_INFORMATION information{};
            DWORD flags = HANDLE_FLAG_INHERIT;

            // Windows includes the limited-query and resume-only rights implied by the requested mask.
            constexpr DWORD expectedAccess = 0x185A;
            Require(imported.StartupThread() == transferredThread &&
                GetThreadId(transferredThread) == GetCurrentThreadId() &&
                GetProcessIdOfThread(transferredThread) == GetCurrentProcessId() &&
                GetHandleInformation(transferredThread, &flags) && !(flags & HANDLE_FLAG_INHERIT) &&
                NtQueryObject(transferredThread, ObjectBasicInformation, &information,
                    sizeof(information), nullptr) >= 0 &&
                information.GrantedAccess == expectedAccess,
                "Startup thread capability has incorrect identity or rights.");
            Require(observer.Open(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(startup.handles.mapping)),
                startup.captureIdentity), "Cannot duplicate an adopted capture channel.");
            Require(!observer.StartupThread(), "An independent observer acquired an unused startup capability.");
        }
        DWORD flags = 0;
        Require(!GetHandleInformation(transferredThread, &flags) && GetLastError() == ERROR_INVALID_HANDLE,
            "The imported owner retained its startup thread capability after destruction.");
        auto slot = observer.Acquire();
        Require(slot != nullptr, "An observer lost its independently owned capture channel.");
        slot->event = {};
        slot->event.callId = 17;
        observer.Publish(slot);
        Record captured;
        Require(consumer.Read(captured) && captured.event.callId == 17, "An imported capture record was lost.");
    }
    {
        TransportStartup startup{consumer.DuplicateTo(GetCurrentProcess(), GetCurrentThread()),
            consumer.Header()->captureIdentity + 1};
        Transport invalid(startup);
        Require(startup.owned && !invalid.Open(startup.captureIdentity) && GetLastError() == ERROR_INVALID_DATA,
            "A different capture identity was accepted.");
    }
    Require(GetProcessHandleCount(GetCurrentProcess(), &handlesAfter) != FALSE && handlesAfter == handlesBefore,
        "Imported capture handles leaked after success or rejection.");
    Require(producer.Open(name), "Cannot open transport fixture.");
    Require(consumer.Header()->mappingBytes <= TransportBudget, "Transport exceeds its memory budget.");
    uint32_t perThread = consumer.Header()->capacity;
    std::vector<std::jthread> writers;
    for (uint32_t thread = 0; thread < 4; ++thread)
        writers.emplace_back([&, thread]()
        {
            for (uint32_t sequence = 0; sequence < perThread; ++sequence)
            {
                auto slot = producer.Acquire();
                if (!slot) return;
                slot->event = {};
                slot->event.threadId = thread;
                slot->event.callId = sequence;
                producer.Publish(slot);
            }
        });
    auto deadline = GetTickCount64() + 10000;
    while (!consumer.Header()->waiters && GetTickCount64() < deadline) Sleep(1);
    bool waited = consumer.Header()->waiters != 0;
    uint32_t expected[4]{};
    uint32_t received = 0;
    bool valid = true;
    Record record;
    while (received < perThread * 4 && GetTickCount64() < deadline)
    {
        if (!consumer.Read(record)) { SwitchToThread(); continue; }
        auto thread = record.event.threadId;
        if (thread >= 4 || record.event.callId != expected[thread]++) valid = false;
        ++received;
    }
    consumer.Stop();
    writers.clear();
    Require(waited && consumer.Header()->waitTicks > 0, "Backpressure did not block producers.");
    Require(valid && received == perThread * 4, "Transport lost, reordered, or duplicated records.");
}

void TransportSuspendedProducer()
{
    // A thread paused while preparing a snapshot must not block completed records from other threads.
    Transport consumer, producer;
    auto name = L"Local\\DetouristHeldQueueTest." + std::to_wstring(GetCurrentProcessId());
    consumer.Create(name, GetCurrentProcessId(), 128, 0, AllApis, false);
    Require(producer.Open(name), "Cannot open suspended-producer fixture.");
    auto held = producer.Acquire();
    held->event = {};
    held->event.threadId = 99;
    uint32_t total = consumer.Header()->capacity * 2;
    std::jthread writer([&]()
    {
        for (uint32_t index = 0; index < total; ++index)
        {
            auto slot = producer.Acquire();
            if (!slot) return;
            slot->event = {};
            slot->event.callId = index;
            slot->event.payloadBytes = sizeof(index);
            memcpy(Transport::Payload(slot), &index, sizeof(index));
            producer.Publish(slot);
        }
    });
    auto deadline = GetTickCount64() + 3000;
    uint32_t received = 0;
    bool valid = true;
    Record record;
    while (received < total && GetTickCount64() < deadline)
    {
        if (!consumer.Read(record)) { SwitchToThread(); continue; }
        uint32_t payload = UINT32_MAX;
        if (record.payload.size() == sizeof(payload)) memcpy(&payload, record.payload.data(), sizeof(payload));
        valid &= record.event.callId == received && payload == received;
        ++received;
    }
    producer.Publish(held);
    auto resumed = consumer.Read(record) && record.event.threadId == 99;
    consumer.Stop();
    writer.join();
    Require(valid && received == total && resumed, "A suspended producer blocked or reordered capture records.");
}

void CaptureModeTransitions(const std::wstring& output)
{
    if (GetFileAttributesW((ModuleDirectory() + L"\\DetouristInstructions.dll").c_str()) == INVALID_FILE_ATTRIBUTES)
        return;

    // The same process keeps native coverage when switching from broad capture to repeated typed captures.
    Fixture fixture;
    CaptureOptions options{.followChildren = false, .startMinimized = true};
    for (int phase = 0; phase < 3; ++phase)
    {
        options.instructionEngine = phase == 0;
        Session session(output + L"\\mode-" + std::to_wstring(phase) + L".db", options, fixture.pid);
        Ready(session);
        fixture.Start(10);
        fixture.Done();
        session.Stop();
        Wait(session);
        if (phase == 0) continue;
        Query query;
        query.api = "NtWriteFile";
        auto page = TraceStore::ReadPage(session.Database(), query);
        Require(page.calls.size() == 40, "A typed reattachment lost or duplicated native write hooks.");
    }
}

void AttachRecovery(const std::wstring& output)
{
    Fixture fixture;
    CaptureOptions options{.startMinimized = true};
    options.bufferLimit = 128;
    options.followChildren = false;
    {
        Session session(output + L"\\attach.db", options, fixture.pid);
        Ready(session);
        fixture.Start(100);
        fixture.Done();
        session.Pause(true);
        auto pausedAt = Clock();
        fixture.Start(100);
        fixture.Done();
        session.SetFilters(uint64_t{1} << static_cast<uint32_t>(Api::GetFileAttributesW));
        auto resumedAt = Clock();
        session.Pause(false);
        fixture.Start(100);
        fixture.Done();
        session.Stop();
        Wait(session);

        // Recorded entry times distinguish new admissions from earlier calls draining after pause.
        sqlite3* stored = nullptr;
        Require(sqlite3_open16(session.Database().c_str(), &stored) == SQLITE_OK, "Cannot open control capture.");
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> connection(stored, sqlite3_close);
        sqlite3_stmt* query = nullptr;
        Require(sqlite3_prepare_v2(stored, "SELECT sum(api=?3 AND started>=?1 AND started<?2),"
            "sum(api=?3 AND started>=?2),sum(api=?4 AND started>=?2) FROM calls", -1, &query, nullptr) == SQLITE_OK,
            "Cannot query control capture.");
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(query, sqlite3_finalize);
        sqlite3_bind_int64(query, 1, pausedAt);
        sqlite3_bind_int64(query, 2, resumedAt);
        sqlite3_bind_int(query, 3, static_cast<int>(Api::GetFileAttributesW));
        sqlite3_bind_int(query, 4, static_cast<int>(Api::WriteFile));
        Require(sqlite3_step(query) == SQLITE_ROW, "Cannot inspect control capture.");
        Require(sqlite3_column_int64(query, 0) == 0, "Pause admitted new calls.");
        Require(sqlite3_column_int64(query, 1) == 400 && sqlite3_column_int64(query, 2) == 0,
            "Capture filter did not select precisely the requested calls.");
        Require(WaitForSingleObject(fixture.process.get(), 0) == WAIT_TIMEOUT, "Detach terminated the target.");
    }

    // A second attachment verifies pinned hooks, debugger exception delivery, and return overrides.
    bool stopped = false;
    options.exitBreaks = uint64_t{1} << static_cast<uint32_t>(Api::GetFileAttributesW);
    {
        Session session(output + L"\\reattach.db", options, fixture.pid);
        Ready(session);
        fixture.Start(10);
        auto deadline = GetTickCount64() + 15000;
        bool completed = false;
        while (GetTickCount64() < deadline)
        {
            auto status = session.Status();
            if (status.breakpoint)
            {
                if (!stopped)
                {
                    auto pulse = fixture.metrics->heartbeat;
                    Sleep(80);
                    Require(fixture.metrics->heartbeat == pulse, "Breakpoint did not suspend all target threads.");
                }
                stopped = true;
                auto edited = status.stoppedCall;
                edited.result = INVALID_FILE_ATTRIBUTES;
                edited.error = ERROR_ACCESS_DENIED;
                session.SetBreaks(0, 0);
                session.Continue(edited, false);
            }
            if (WaitForSingleObject(fixture.done.get(), 5) == WAIT_OBJECT_0) { completed = true; break; }
        }
        Require(completed && stopped && fixture.metrics->exceptionsHandled,
            "Return breakpoint or exception handling failed.");
        session.Stop();
        Wait(session);
    }
    Query query;
    query.api = "GetFileAttributesW";
    query.failuresOnly = true;
    auto failures = TraceStore::ReadPage(output + L"\\reattach.db", query);
    Require(!failures.calls.empty() && failures.calls.front().error == ERROR_ACCESS_DENIED,
        "Edited return was not classified as a failure.");
    Require((failures.calls.front().flags & Edited) != 0, "Breakpoint edits were not identified in the trace.");

    // Killing only this test's collector must leave the observed process runnable.
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, (fixture.name + L".collector").c_str()));
    FixtureProcess collector(L"\"" + ModuleDirectory() + L"\\DetouristCaptureTests.exe\" --collector " +
        std::to_wstring(fixture.pid) + L" \"" + output + L"\\controller-loss.db\" " + fixture.name + L".collector");
    bool started = WaitForSingleObject(ready.get(), 20000) == WAIT_OBJECT_0;
    if (started) { fixture.Start(10000); Sleep(20); }
    TerminateProcess(collector.handle.get(), ERROR_CANCELLED);
    WaitForSingleObject(collector.handle.get(), 5000);
    Require(started, "Collector fixture did not attach.");
    fixture.Done();
    fixture.Start(10);
    fixture.Done();
}

void ChildPressure(const std::wstring& output)
{
    // Every child must be attached even when simultaneous launches exceed the request queue.
    auto database = output + L"\\child-pressure.db";
    CaptureOptions options{.startMinimized = true};
    options.bufferLimit = 128;
    {
        Session session(database, options, 0, ModuleDirectory() + L"\\DetouristTestTarget.exe", L"--burst 34");
        Wait(session);
        Require(session.Status().processes == 35, "Concurrent child launches escaped capture.");
        Require(session.Status().blockedMilliseconds > 0, "Child request saturation was not exercised.");
    }
    Query query;
    query.api = "WriteFile";
    query.limit = 1000;
    auto page = TraceStore::ReadPage(database, query);
    Require(page.targets.size() == 35, "Child pressure target metadata is incomplete.");
    for (const auto& target : page.targets)
    {
        if (target.id == page.targets.front().id) continue;
        Require(std::any_of(page.calls.begin(), page.calls.end(), [&](const auto& call)
        {
            return call.target == target.id && call.duration >= 0 && call.result;
        }), "A followed child has no completed workload calls.");
    }

    // Sequential children that exit must release their active slots and transports while preserving session totals.
    auto sequentialDatabase = output + L"\\child-retirement.db";
    options.apiMask = uint64_t{1} << static_cast<uint32_t>(Api::WriteFile);
    {
        PROCESS_MEMORY_COUNTERS_EX before{};
        before.cb = sizeof(before);
        Check(GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&before),
            sizeof(before)) != FALSE, "Read initial memory");
        Session session(sequentialDatabase, options, 0,
            ModuleDirectory() + L"\\DetouristTestTarget.exe", L"--sequential 70");
        Wait(session);
        auto status = session.Status();
        PROCESS_MEMORY_COUNTERS_EX after{};
        after.cb = sizeof(after);
        Check(GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&after),
            sizeof(after)) != FALSE, "Read post-retirement memory");
        Require(status.processes == 71 && !status.partial && status.skippedChildren == 0,
            "Exited children were not retired before reaching the active process limit.");
        Require(status.calls >= 280 && status.records >= status.calls * 2,
            "Retired targets lost their cumulative call or record totals.");
        Require(after.PrivateUsage <= before.PrivateUsage + 128ull * 1024 * 1024,
            "Retired target transports remained mapped in the collector.");
    }
    auto sequentialPage = TraceStore::ReadPage(sequentialDatabase, query);
    Require(sequentialPage.targets.size() == 71 &&
        std::all_of(sequentialPage.targets.begin(), sequentialPage.targets.end(), [](const auto& target)
        {
            return target.state == L"Exited";
        }), "Sequential child target states were not finalized.");
}

void CaptureDurations(const std::wstring& output, bool instructions, int scenario)
{
    auto database = output + L"\\durations-" + std::to_wstring(scenario) + L".db";
    CaptureOptions options{.startMinimized = true};
    options.instructionEngine = instructions;
    if (scenario == 1) options.excludedApis = {"GetFileAttributesW"};
    options.followChildren = false;
    options.exitBreaks = uint64_t{1} << static_cast<uint32_t>(Api::GetFileAttributesW);
    uint64_t delayed = 0;
    {
        Session session(database, options, 0, ModuleDirectory() + L"\\DetouristTestTarget.exe",
            scenario == 2 ? L"--duration-unwind" : L"--durations");
        Wait(session, [&](const SessionStatus& status)
        {
            if (!status.breakpoint) return;
            std::vector<uint8_t> text;
            std::wstring error;
            constexpr wchar_t expected[] = L"Detourist-duration-probe.invalid";
            if (session.ReadMemory(status.stoppedCall.arguments[0], sizeof(expected), text, error) &&
                text.size() == sizeof(expected) && !memcmp(text.data(), expected, sizeof(expected)))
            {
                delayed = status.stoppedCall.callId;
                Sleep(150);
                session.SetBreaks(0, 0);
            }
            session.Continue(status.stoppedCall, false);
        });
    }
    Require(delayed != 0, "Nested timing probe did not stop at its breakpoint.");
    Query query;
    query.api = "EnumSystemLocalesW";
    auto page = TraceStore::ReadPage(database, query);
    Require(page.calls.size() == 1, "Timing probe did not record its enclosing API.");
    const auto& parent = page.calls.front();
    auto milliseconds = [&](int64_t ticks) { return ticks * 1000.0 / page.frequency; };
    Require(milliseconds(parent.duration) >= 180 && milliseconds(parent.adjustedDuration) >= 30 &&
        milliseconds(parent.duration - parent.adjustedDuration) >= 130,
        "Adjusted duration lost nested application time or retained nested breakpoint overhead.");
    query.api = "GetFileAttributesW";
    query.callId = delayed;
    auto child = TraceStore::ReadPage(database, query);
    if (scenario == 1) Require(child.calls.empty(), "Excluded nested call was recorded.");
    else Require(child.calls.size() == 1 && child.calls.front().adjustedDuration >= 0 &&
        milliseconds(child.calls.front().duration - child.calls.front().adjustedDuration) >= 130 &&
        child.calls.front().timestamp >= parent.timestamp && child.calls.front().timestamp <=
            parent.timestamp + parent.duration, "Adjusted timing changed raw timeline containment.");
    if (scenario == 2) Require(parent.flags & Unwound, "Exceptional timing probe did not unwind.");
    TraceView matching(database, {.filter = "adjusted>30ms EnumSystemLocalesW"});
    while (!matching.Complete()) matching.Advance(100);
    Require(matching.Count() == 1, "Adjusted duration filter lost the parent.");
    TraceView excluded(database, {.filter = "adjusted<1us EnumSystemLocalesW"});
    while (!excluded.Complete()) excluded.Advance(100);
    Require(excluded.Count() == 0, "Adjusted duration filter ignored its measured value.");
    std::cout << "PASS: nested timing, raw=" << milliseconds(parent.duration) << " ms, adjusted="
        << milliseconds(parent.adjustedDuration) << " ms\n";
}

int Benchmark(const std::wstring& output)
{
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    std::ofstream report(std::filesystem::path(output) / L"benchmark.csv");
    report << "round,mode,cap,stack_frames,startup_ms,attach_ms,workload_ms,target_cpu_ms,collector_cpu_ms,"
        "target_peak_working_set,target_private_bytes,calls,blocked_thread_ms,database_bytes\n";
    constexpr uint32_t iterations = 3000;
    for (int round = 0; round < 5; ++round)
    {
        for (int mode = 0; mode < 3; ++mode)
        {
            // Fresh targets keep pass-through hooks out of the baseline measurement.
            Fixture fixture;
            CaptureOptions options{.startMinimized = true};
            options.stackDepth = mode == 2 ? MaximumStack : 0;
            options.followChildren = false;
            auto database = output + L"\\benchmark-" + std::to_wstring(round) + L"-" + std::to_wstring(mode) + L".db";
            std::unique_ptr<Session> session;
            double attach = 0;
            FILETIME created, ended, kernel, user;
            auto cpu = [&]()
            {
                GetProcessTimes(GetCurrentProcess(), &created, &ended, &kernel, &user);
                return (uint64_t{kernel.dwHighDateTime} << 32) + kernel.dwLowDateTime +
                    (uint64_t{user.dwHighDateTime} << 32) + user.dwLowDateTime;
            };
            auto before = cpu();
            if (mode)
            {
                auto start = Clock();
                session = std::make_unique<Session>(database, options, fixture.pid);
                Ready(*session);
                attach = (Clock() - start) * 1000.0 / frequency.QuadPart;
            }
            fixture.Start(iterations);
            fixture.Done();
            SessionStatus status;
            if (session)
            {
                session->Stop();
                Wait(*session);
                status = session->Status();
                session.reset();
            }
            auto collector = (cpu() - before) / 10000.0;
            auto elapsed = fixture.metrics->elapsedTicks * 1000.0 / frequency.QuadPart;
            report << round + 1 << ',' << (mode == 0 ? "baseline" : mode == 1 ? "capture" : "stacks") << ','
                << (mode ? options.bufferLimit : 0) << ',' << options.stackDepth << ',' << fixture.startupMilliseconds
                << ',' << attach << ',' << elapsed << ',' << fixture.metrics->cpuTicks / 10000.0 << ',' << collector
                << ',' << fixture.metrics->peakWorkingSet << ',' << fixture.metrics->privateBytes << ',' << status.calls
                << ',' << status.blockedMilliseconds << ','
                << (mode ? std::filesystem::file_size(database) : 0) << '\n';
            report.flush();
            std::wcout << L"Round " << round + 1 << L" mode " << mode << L": " << elapsed << L" ms\n";
        }
    }
    std::wcout << L"Benchmark: " << output << L"\\benchmark.csv\n";
    return 0;
}

Record EnterRecord(Api api, uint32_t threadId, uint64_t callId = 1)
{
    return {.event = {.kind = EventKind::Enter, .api = api, .callId = callId, .timestamp = Clock(),
        .threadId = threadId}};
}

void ManagedLayoutFragments(const std::wstring& output)
{
    // Interrupted publications stay invisible while layouts from independent targets finish or restart.
    auto path = output + L"\\layout-fragments.db";
    TraceStore store(path);
    auto first = store.AddTarget(100, L"first.exe", 0, ManagedApis);
    auto second = store.AddTarget(200, L"second.exe", 0, ManagedApis);
    auto stopped = store.AddTarget(300, L"stopped.exe", 0, ManagedApis);
    DynamicApiMetadata metadata{};
    metadata.argumentCount = 1;
    metadata.category = ApiCategory::Unclassified;
    strcpy_s(metadata.module, "ManagedFixture");
    strcpy_s(metadata.name, "LargeValue.Read()");
    wcscpy_s(metadata.parameters, L"this: LargeValue& -> int64");
    for (auto target : {first, second, stopped})
    {
        Record record;
        record.event = {};
        record.event.kind = EventKind::ApiMetadata;
        record.event.api = static_cast<Api>(ManagedApiStart);
        record.payload.resize(sizeof(metadata));
        memcpy(record.payload.data(), &metadata, sizeof(metadata));
        store.Add(target, record);
        store.Add(target, EnterRecord(record.event.api, 1));
    }
    auto firstLayout = "{\"Name\":\"" + std::string(4000, 'a') +
        "\",\"Size\":8,\"Fields\":[[\"Value\",\"int64\",0,8]]}";
    auto secondLayout = "{\"Name\":\"" + std::string(5000, 'b') +
        "\",\"Size\":4,\"Fields\":[[\"Value\",\"int32\",0,4]]}";
    auto publish = [&](int64_t target, const std::string& layout, uint32_t offset, uint32_t bytes)
    {
        ApiLayoutFragment fragment{offset, static_cast<uint32_t>(layout.size())};
        Record record;
        record.event = {};
        record.event.kind = EventKind::ApiLayout;
        record.event.api = static_cast<Api>(ManagedApiStart);
        record.payload.resize(sizeof(fragment) + bytes);
        memcpy(record.payload.data(), &fragment, sizeof(fragment));
        memcpy(record.payload.data() + sizeof(fragment), layout.data() + offset, bytes);
        store.Add(target, record);
    };
    auto read = [&](int64_t target)
    {
        Query query;
        query.target = target;
        query.includePayload = true;
        auto page = TraceStore::ReadPage(path, query);
        Require(page.calls.size() == 1, "Layout metadata changed recorded calls.");
        return page.calls.front().layout;
    };
    publish(first, firstLayout, 0, 700);
    publish(second, secondLayout, 0, 512);
    publish(stopped, firstLayout, 0, 300);
    store.Flush();
    Require(read(first).empty() && read(second).empty() && read(stopped).empty(),
        "An incomplete layout was exposed to a live reader.");

    // A restarted descriptor replaces its partial bytes without affecting another target's publication.
    publish(first, firstLayout, 0, 311);
    bool rejected = false;
    try { publish(first, firstLayout, 700, 100); }
    catch (const std::runtime_error&) { rejected = true; }
    Require(rejected, "A discontinuous layout was accepted.");
    publish(second, secondLayout, 512, static_cast<uint32_t>(secondLayout.size()) - 512);
    publish(first, firstLayout, 311, 500);
    store.Flush();
    Require(read(first).empty() && read(second) == secondLayout,
        "Interleaved targets lost or mixed their layouts.");
    publish(first, firstLayout, 811, static_cast<uint32_t>(firstLayout.size()) - 811);
    store.TargetState(stopped, L"Detached");
    store.Flush();
    Require(read(first) == firstLayout && read(second) == secondLayout && read(stopped).empty(),
        "Completed or interrupted layouts were not saved correctly.");
    rejected = false;
    try { publish(stopped, firstLayout, 300, static_cast<uint32_t>(firstLayout.size()) - 300); }
    catch (const std::runtime_error&) { rejected = true; }
    Require(rejected && store.Count() == 3, "A stopped target retained its unfinished layout.");
}

void FrozenPage(const std::wstring& output)
{
    // A frozen reader must see returns without admitting newly recorded calls ahead of its selection.
    auto path = output + L"\\frozen-page.db";
    TraceStore store(path);
    auto target = store.AddTarget(100, L"fixture.exe", 0, AllApis);
    auto record = EnterRecord(Api::WriteFile, 1);
    store.Add(target, record);
    store.Flush();
    Query query;
    auto initial = TraceStore::ReadPage(path, query);
    Require(initial.calls.size() == 1 && initial.calls.front().duration < 0 &&
        initial.calls.front().adjustedDuration < 0, "Pending call was not visible.");
    const auto& selected = initial.calls.front();
    query.newestTimestamp = selected.timestamp;
    query.newestTarget = selected.target;
    query.newestCallId = selected.id;
    record.event.kind = EventKind::Leave;
    record.event.timestamp += 100;
    record.event.flags = DurationMeasured;
    record.event.adjustedDuration = 40;
    record.event.result = 1;
    store.Add(target, record);
    store.Add(target, EnterRecord(Api::WriteFile, 1, 2));
    store.Flush();
    auto refreshed = TraceStore::ReadPage(path, query);
    Require(refreshed.calls.size() == 1 && refreshed.calls.front().id == selected.id &&
        refreshed.calls.front().duration == 100 && refreshed.calls.front().adjustedDuration == 40 &&
        refreshed.calls.front().result == 1,
        "Frozen page moved or failed to receive a return.");
    query.newestCallId = 0;
    auto newest = TraceStore::ReadPage(path, query);
    Require(newest.calls.size() == 2 && newest.calls.front().id == 2, "Resuming newest omitted captured calls.");
}

void CompleteViewCursor(const std::wstring& output)
{
    // Identical timestamps across targets must not lose or duplicate calls between batches.
    auto path = output + L"\\complete-view.db";
    TraceStore store(path);
    auto first = store.AddTarget(100, L"first.exe", 0, AllApis);
    auto second = store.AddTarget(200, L"second.exe", 0, AllApis);
    auto record = EnterRecord(Api::WriteFile, 1);
    for (auto target : {first, second})
        for (uint64_t id = 1; id <= 1202; ++id)
        {
            record.event.callId = id;
            store.Add(target, record);
        }
    store.Flush();
    Query query;
    query.limit = 1000;
    std::vector<std::pair<int64_t, uint64_t>> identities;
    for (;;)
    {
        auto page = TraceStore::ReadPage(path, query);
        if (!query.newestCallId)
        {
            const auto& newest = page.calls.front();
            query.newestTimestamp = newest.timestamp;
            query.newestTarget = newest.target;
            query.newestCallId = newest.id;
            record.event.timestamp += 1;
            record.event.callId = 1203;
            store.Add(second, record);
            store.Flush();
        }
        else Require(page.targets.empty() && page.threads.empty(), "Batch metadata was unnecessarily repeated.");
        for (const auto& call : page.calls) identities.emplace_back(call.target, call.id);
        if (page.calls.size() < query.limit) break;
        const auto& last = page.calls.back();
        query.beforeTimestamp = last.timestamp;
        query.beforeTarget = last.target;
        query.beforeCallId = last.id;
        query.includeMetadata = false;
    }
    std::sort(identities.begin(), identities.end());
    Require(identities.size() == 2404 && std::adjacent_find(identities.begin(), identities.end()) == identities.end(),
        "Complete view omitted or duplicated calls, or admitted calls after its snapshot.");
}

void StorageFailures(const std::wstring& output)
{
    // Concurrent sessions must have one owner for a new capture file.
    auto path = output + L"\\storage-owner.db";
    std::barrier ready(2);
    std::atomic<uint32_t> accepted = 0, rejected = 0;
    auto create = [&]
    {
        ready.arrive_and_wait();
        try
        {
            TraceStore store(path);
            store.AddTarget(100, L"owner.exe", 0, AllApis);
            store.Flush();
            ++accepted;
        }
        catch (const std::runtime_error& error)
        {
            if (std::string_view(error.what()) == "Choose a new database filename for this capture.") ++rejected;
        }
    };
    std::thread first(create), second(create);
    first.join();
    second.join();
    Require(accepted == 1 && rejected == 1 && TraceStore::ReadPage(path, {}).targets.size() == 1,
        "Concurrent captures did not reserve exactly one database owner.");

    // Invalid time bounds must be rejected before conversion can turn them into a different filter.
    path = output + L"\\storage-errors.db";
    TraceStore store(path);
    auto target = store.AddTarget(100, L"storage.exe", 0, AllApis);
    store.AddModule(target, 0x10000, 0x1000, L"storage.exe");
    auto record = EnterRecord(Api::WriteFile, 0);
    store.Add(target, record);
    record.event.kind = EventKind::Leave;
    record.event.timestamp += 100;
    record.event.flags = DurationMeasured;
    record.event.adjustedDuration = 50;
    store.Add(target, record);
    store.Flush();
    for (const char* filter : {"duration>nan", "adjusted<inf", "duration>1e300s", "after:nan", "before:inf",
        "after:1e300"})
    {
        bool failed = false;
        try { TraceView view(path, {.filter = filter}); }
        catch (const std::runtime_error&) { failed = true; }
        Require(failed, "A non-finite or overflowing filter was accepted.");
    }
    TraceView valid(path, {.filter = "duration>0us after:0"});
    while (!valid.Complete()) valid.Advance(100);
    Require(valid.Count() == 1, "A valid time filter lost its recorded call.");

    sqlite3* raw = nullptr;
    SqlCheck(sqlite3_open_v2(Utf8(path).c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr), raw);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(raw, sqlite3_close);
    SqlCheck(sqlite3_exec(raw, "UPDATE session SET start_clock=9223372036854775806", nullptr, nullptr, nullptr), raw);
    bool failed = false;
    try { TraceView view(path, {.filter = "after:1"}); }
    catch (const std::runtime_error&) { failed = true; }
    Require(failed, "A time filter overflowed the capture's start clock.");

    // A read failure must reach the caller instead of producing successful empty metadata.
    SqlCheck(sqlite3_create_function(raw, "read_failure", 0, SQLITE_UTF8, nullptr,
        [](sqlite3_context* context, int, sqlite3_value**)
        {
            sqlite3_result_error(context, "Simulated metadata read failure.", -1);
        }, nullptr, nullptr), raw);
    SqlCheck(sqlite3_exec(raw, "ALTER TABLE targets RENAME TO stored_targets;"
        "CREATE VIEW targets AS SELECT * FROM stored_targets WHERE read_failure();"
        "ALTER TABLE modules RENAME TO stored_modules;"
        "CREATE VIEW modules AS SELECT * FROM stored_modules WHERE read_failure();", nullptr, nullptr, nullptr), raw);
    for (bool modules : {false, true})
    {
        failed = false;
        try
        {
            if (modules) ReadModules(raw);
            else
            {
                TracePage page;
                ReadTargets(raw, page);
            }
        }
        catch (const std::runtime_error& error)
        {
            failed = std::string_view(error.what()) == "Simulated metadata read failure.";
        }
        Require(failed, "A metadata read error was treated as an empty result.");
    }
}

void TraceSizeThreshold(const std::wstring& output)
{
    Fixture fixture;
    auto path = output + L"\\trace-size.db";
    CaptureOptions options{.traceStopMiB = 8, .followChildren = false};
    Session session(path, options, fixture.pid);
    Ready(session);
    fixture.Start(5000);
    fixture.Done();
    Wait(session);

    // The writer finishes draining and leaves a usable trace and running target.
    auto page = TraceView(path, {}).Metadata();
    Require(session.Status().message.starts_with(L"Capture reached the configured trace size threshold.") &&
        page.totalCalls > 0 && page.targets.size() == 1 &&
        std::ranges::any_of(page.diagnostics, [](const TraceDiagnostic& diagnostic)
        {
            return diagnostic.message == "Capture reached the configured trace size threshold.";
        }) &&
        WaitForSingleObject(fixture.process.get(), 0) == WAIT_TIMEOUT,
        "The trace size threshold did not stop capture cleanly.");
}

void NativeCoverage(const std::wstring& output)
{
    CaptureOptions options{.startMinimized = true};
    options.apiMask = NativeApis;
    options.followChildren = false;
    options.bufferLimit = 16;
    auto database = output + L"\\native.db";
    {
        Session session(database, options, 0, ModuleDirectory() + L"\\DetouristTestTarget.exe", L"--native");
        Wait(session);
    }
    Query query;
    query.api = "NtQueryInformationProcess";
    query.includePayload = true;
    query.limit = 1000;
    auto page = TraceStore::ReadPage(database, query);
    size_t matching = 0;
    for (auto& row : page.calls)
    {
        if (row.arguments[1] || row.arguments[3] != sizeof(PROCESS_BASIC_INFORMATION)) continue;
        Require(row.duration >= 0 && !(row.flags & Failed), "Direct Nt query did not return successfully.");
        bool buffer = false;
        for (size_t offset = 0; offset + sizeof(Value) <= row.output.size();)
        {
            Value value;
            memcpy(&value, row.output.data() + offset, sizeof(value));
            offset += sizeof(value);
            Require(value.capturedBytes <= options.bufferLimit, "Native buffer capture exceeded global cap.");
            Require(offset + value.capturedBytes <= row.output.size(), "Native output framing is invalid.");
            if (value.parameter == 2)
                buffer = value.originalBytes == sizeof(PROCESS_BASIC_INFORMATION) &&
                    value.capturedBytes == options.bufferLimit && (value.flags & Truncated);
            offset += value.capturedBytes;
        }
        Require(buffer, "Typed native output snapshot or truncation is missing.");
        ++matching;
    }
    Require(matching == 2, "Nt and Zw calls did not share their canonical native capture identity.");
    query.api = "NtGetTickCount";
    page = TraceStore::ReadPage(database, query);
    Require(!page.calls.empty() && page.calls.front().duration >= 0 && !(page.calls.front().flags & Failed),
        "Native tick count export was not captured with its ULONG result semantics.");
    query.api = "NtAllocateVirtualMemory";
    page = TraceStore::ReadPage(database, query);
    Require(std::any_of(page.calls.begin(), page.calls.end(), [](const auto& call)
    {
        return call.arguments[4] == (MEM_RESERVE | MEM_COMMIT) && call.arguments[5] == PAGE_READWRITE &&
            call.duration >= 0 && !(call.flags & Failed) && !call.output.empty();
    }), "Native allocation arguments and output pointer were not captured.");

    // An exact native breakpoint must not expand into a category-wide syscall breakpoint.
    options.entryApi = static_cast<int32_t>(Api::NtQueryInformationProcess);
    bool stopped = false;
    {
        Session session(output + L"\\native-breakpoint.db", options, 0,
            ModuleDirectory() + L"\\DetouristTestTarget.exe", L"--native");
        Wait(session, [&](const SessionStatus& status)
        {
            if (!status.breakpoint) return;
            Require(status.stoppedCall.api == Api::NtQueryInformationProcess,
                "Native breakpoint stopped an unrelated API.");
            stopped = true;
            session.SetApiBreaks(-1, -1);
            session.Continue(status.stoppedCall, false);
        });
    }
    Require(stopped, "Exact native breakpoint did not stop.");
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        if (argc == 3 && !wcscmp(argv[1], L"--image-signing-target")) return ImageSigningTarget(argv[2]);
        if (argc == 4 && !wcscmp(argv[1], L"--thread-discovery-target"))
            return ThreadDiscoveryTarget(argv[2], !wcscmp(argv[3], L"denied"));
        if (argc == 5 && !wcscmp(argv[1], L"--collector"))
        {
            CaptureOptions options{.startMinimized = true};
            options.bufferLimit = 128;
            Session session(argv[3], options, static_cast<DWORD>(_wtoi(argv[2])));
            Ready(session);
            Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[4]));
            SetEvent(ready.get());
            for (;;) Sleep(1000);
        }
        auto directory = ModuleDirectory();
        auto run = GetTickCount64();
        std::wstring output;
        do
        {
            output = directory + L"\\test-results-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(run++);
        } while (!std::filesystem::create_directory(output));
        if (argc == 2 && !wcscmp(argv[1], L"--benchmark")) return Benchmark(output);
        if (argc >= 2 && !wcscmp(argv[1], L"--image-signing"))
        {
            ImageSigning(output, argc > 2);
            return 0;
        }
        if (argc >= 2 && !wcscmp(argv[1], L"--durations"))
        {
            for (int scenario = 0; scenario < 3; ++scenario) CaptureDurations(output, argc > 2, scenario);
            return 0;
        }
        if (argc == 2 && !wcscmp(argv[1], L"--storage"))
        {
            ManagedLayoutFragments(output);
            FrozenPage(output);
            CompleteViewCursor(output);
            StorageFailures(output);
            TraceSizeThreshold(output);
            TransportPressure();
            TransportSuspendedProducer();
            std::wcout << L"PASS: storage ownership, metadata errors, filters, layouts, paging and transport.\n";
            return 0;
        }
        if (argc == 2 && !wcscmp(argv[1], L"--thread-discovery"))
        {
            ThreadDiscoveryMailbox();
            ThreadDiscovery(output);
            std::wcout << L"PASS: collector thread discovery, denied peers, abort resume and mailbox ownership.\n";
            return 0;
        }
        NativeCoverage(output);
        CaptureModeTransitions(output);
        AttachRecovery(output);
        ChildPressure(output);
        auto fixture = directory + L"\\DetouristTestTarget.exe";
        CaptureOptions options{.startMinimized = true};
        options.bufferLimit = 128;

        // Real debugger events verify process suspension, argument editing, and continuation.
        options.followChildren = false;
        options.entryBreaks = uint64_t{1} << static_cast<uint32_t>(Api::GetFileAttributesW);
        bool breakpoint = false;
        {
            Session session(output + L"\\breakpoint.db", options, 0, fixture, L"--leaf 5");
            Wait(session, [&](const SessionStatus& status)
            {
                if (!status.breakpoint) return;
                breakpoint = true;
                auto edited = status.stoppedCall;
                edited.result = INVALID_FILE_ATTRIBUTES;
                edited.error = ERROR_ACCESS_DENIED;
                session.SetBreaks(0, 0);
                session.Continue(edited, true);
            });
        }
        Require(breakpoint, "API breakpoint did not stop.");
        Query query;
        query.api = "GetFileAttributesW";
        auto stopped = TraceStore::ReadPage(output + L"\\breakpoint.db", query);
        Require(std::any_of(stopped.calls.begin(), stopped.calls.end(), [](const auto& call)
        {
            return (call.flags & Skipped) && call.error == ERROR_ACCESS_DENIED && call.adjustedDuration == 0;
        }), "Skipped-call result was not recorded.");
        std::wcout << L"PASS: native capture, attach, reattach, child capture, snapshots, caps, breakpoints,"
            L" pause, capture filters, controller loss, exception delivery.\n"
            << L"Artifacts: " << output << L'\n';
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}

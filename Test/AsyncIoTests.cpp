#include "TestSupport.h"
#include "TraceStore.h"

using namespace Detourist::Tests;

struct Pipe
{
    Detourist::Handle server, client;
    Pipe()
    {
        static uint32_t serial = 0;
        auto name = L"\\\\.\\pipe\\Detourist.Async." + std::to_wstring(GetCurrentProcessId()) + L"." +
            std::to_wstring(++serial);
        server.reset(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr));
        Require(static_cast<bool>(server), "Create asynchronous pipe");
        client.reset(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        Require(static_cast<bool>(client), "Open asynchronous pipe");
        OVERLAPPED connected{};
        Require(ConnectNamedPipe(server.get(), &connected) || GetLastError() == ERROR_PIPE_CONNECTED,
            "Connect asynchronous pipe");
    }
    void Write(std::string_view message)
    {
        DWORD bytes = 0;
        Require(WriteFile(client.get(), message.data(), static_cast<DWORD>(message.size()), &bytes, nullptr) &&
            bytes == message.size(), "Write asynchronous payload");
    }
};

struct ApcState
{
    OVERLAPPED overlapped{};
    char buffer[128]{};
    bool completed = false;
};
void WINAPI Win32Completed(DWORD error, DWORD bytes, OVERLAPPED* overlapped)
{
    auto state = reinterpret_cast<ApcState*>(overlapped);
    state->completed = !error && std::string_view(state->buffer, bytes) == "async-apc";
    memset(state->buffer, 0xCC, sizeof(state->buffer));
}
void NTAPI NativeCompleted(void* context, IO_STATUS_BLOCK* status, ULONG)
{
    auto state = static_cast<ApcState*>(context);
    state->completed = status->Status == 0 &&
        std::string_view(state->buffer, status->Information) == "async-native";
    memset(state->buffer, 0xDD, sizeof(state->buffer));
}
void CALLBACK WinsockCompleted(DWORD error, DWORD bytes, WSAOVERLAPPED* overlapped, DWORD flags)
{
    auto state = reinterpret_cast<ApcState*>(overlapped);
    state->completed = !error && !flags && std::string_view(state->buffer, bytes) == "async-wsa-apc";
    memset(state->buffer, 0xCE, sizeof(state->buffer));
}

int TargetMain(int count, wchar_t** arguments)
{
    if (count > 1 && !wcscmp(arguments[1], L"edited"))
    {
        Pipe pipe;
        OVERLAPPED overlapped{};
        char buffer[128]{};
        Require(ReadFile(pipe.server.get(), buffer, sizeof(buffer), nullptr, &overlapped) && GetLastError() == 0,
            "Submission return edit was not applied");
        pipe.Write("async-edited");
        DWORD bytes = 0;
        Require(GetOverlappedResult(pipe.server.get(), &overlapped, &bytes, TRUE) &&
            std::string_view(buffer, bytes) == "async-edited", "Return edit lost the real pending request");
        return 0;
    }
    const bool paused = count > 1 && !wcscmp(arguments[1], L"paused");
    const bool detached = count > 1 && !wcscmp(arguments[1], L"detached");
    if (paused || detached)
    {
        Pipe pipe;
        Detourist::Handle port(paused ? CreateIoCompletionPort(pipe.server.get(), nullptr, 0xABC, 1) : nullptr);
        ApcState state;
        auto gateName = L"Local\\Detourist.Async.Gate." + std::to_wstring(GetCurrentProcessId());
        Detourist::Handle gate(CreateEventW(nullptr, TRUE, FALSE, gateName.c_str()));
        if (detached)
        {
            Require(ReadFileEx(pipe.server.get(), state.buffer, sizeof(state.buffer), &state.overlapped,
                Win32Completed) != FALSE, "Submit detached APC read");
        }
        else Require(!ReadFile(pipe.server.get(), state.buffer, sizeof(state.buffer), nullptr, &state.overlapped) &&
            GetLastError() == ERROR_IO_PENDING, "Paused read was not pending");
        Require(WaitForSingleObject(gate.get(), detached ? 60000 : 20000) == WAIT_OBJECT_0,
            "Capture gate timed out");
        if (detached)
        {
            pipe.Write("async-apc");
            for (uint32_t wait = 0; wait < 20 && !state.completed; ++wait) SleepEx(500, TRUE);
            if (!state.completed || static_cast<unsigned char>(state.buffer[0]) != 0xCC) return 7;
            OVERLAPPED fresh{};
            char buffer[32]{};
            DWORD bytes = 0;
            Require(!ReadFile(pipe.server.get(), buffer, sizeof(buffer), nullptr, &fresh) &&
                GetLastError() == ERROR_IO_PENDING, "Submit fresh I/O after detach");
            pipe.Write("async-restarted");
            Require(GetOverlappedResult(pipe.server.get(), &fresh, &bytes, TRUE) &&
                std::string_view(buffer, bytes) == "async-restarted", "Fresh I/O failed after detach");
            return 0;
        }
        pipe.Write("async-paused");
        OVERLAPPED* completed = nullptr;
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        Require(GetQueuedCompletionStatus(port.get(), &bytes, &key, &completed, 10000) &&
            completed == &state.overlapped && key == 0xABC &&
                std::string_view(state.buffer, bytes) == "async-paused",
            "Paused completion was altered");
        return 0;
    }

    // Result queries retain the original pending return and do not rewrite the submission's count pointer.
    {
        Pipe pipe;
        OVERLAPPED overlapped{};
        char buffer[128]{};
        DWORD submitted = 0xBAD, bytes = 0;
        Require(!ReadFile(pipe.server.get(), buffer, sizeof(buffer), &submitted, &overlapped) &&
            GetLastError() == ERROR_IO_PENDING, "Result read was not pending");
        Require(!GetOverlappedResult(pipe.server.get(), &overlapped, &bytes, FALSE) &&
            GetLastError() == ERROR_IO_INCOMPLETE, "Incomplete query changed the outcome");
        pipe.Write("async-result");
        Require(GetOverlappedResult(pipe.server.get(), &overlapped, &bytes, TRUE) && submitted == 0 &&
            std::string_view(buffer, bytes) == "async-result", "Result completion was altered");
    }

    // Reuse the same control block after each dequeue, including failure packets and batched completion.
    {
        Pipe pipe;
        Detourist::Handle port(CreateIoCompletionPort(pipe.server.get(), nullptr, 0xABC, 1));
        Require(static_cast<bool>(port), "Associate completion port");
        OVERLAPPED overlapped{};
        char buffer[128]{};
        for (uint32_t index = 0; index < 5; ++index)
        {
            overlapped = {};
            memset(buffer, 0xEE, sizeof(buffer));
            Require(!ReadFile(pipe.server.get(), buffer, sizeof(buffer), nullptr, &overlapped) &&
                GetLastError() == ERROR_IO_PENDING, "Completion port read was not pending");
            if (index == 3) Require(CancelIoEx(pipe.server.get(), &overlapped) != FALSE, "Cancel pending read");
            else pipe.Write("async-port-" + std::to_string(index));
            DWORD bytes = 0;
            if (index == 4)
            {
                OVERLAPPED_ENTRY entries[2]{};
                ULONG removed = 0;
                Require(GetQueuedCompletionStatusEx(port.get(), entries, 2, &removed, 10000, FALSE) &&
                    removed == 1 && entries[0].lpOverlapped == &overlapped && entries[0].lpCompletionKey == 0xABC,
                    "Batched completion was altered");
                bytes = entries[0].dwNumberOfBytesTransferred;
            }
            else
            {
                OVERLAPPED* completed = nullptr;
                ULONG_PTR key = 0;
                auto success = GetQueuedCompletionStatus(port.get(), &bytes, &key, &completed, 10000);
                auto error = GetLastError();
                Require(completed == &overlapped && key == 0xABC && (index == 3 ?
                    !success && error == ERROR_OPERATION_ABORTED : success != FALSE),
                    "Dequeued completion was altered");
            }
            if (index != 3) Require(std::string_view(buffer, bytes) == "async-port-" + std::to_string(index),
                "Reused control returned the wrong payload");
        }
    }
    {
        Pipe pipe;
        Detourist::Handle signal(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        OVERLAPPED overlapped{};
        overlapped.hEvent = signal.get();
        char buffer[128]{};
        Require(!ReadFile(pipe.server.get(), buffer, sizeof(buffer), nullptr, &overlapped) &&
            GetLastError() == ERROR_IO_PENDING, "Event read was not pending");
        pipe.Write("async-event");
        Require(WaitForSingleObject(signal.get(), 10000) == WAIT_OBJECT_0 &&
            std::string_view(buffer, overlapped.InternalHigh) == "async-event", "Event completion was altered");
        overlapped = {};
        pipe.Write("async-immediate");
        Require(ReadFile(pipe.server.get(), buffer, sizeof(buffer), nullptr, &overlapped) &&
            std::string_view(buffer, overlapped.InternalHigh) == "async-immediate", "Immediate completion was altered");
    }

    // A filtered worker can already be blocked in the completion API when the first request is submitted.
    {
        Pipe pipe;
        Detourist::Handle port(CreateIoCompletionPort(pipe.server.get(), nullptr, 0xABC, 1));
        OVERLAPPED overlapped{};
        char buffer[128]{};
        bool valid = false;
        std::thread worker([&]()
        {
            DWORD bytes = 0;
            ULONG_PTR key = 0;
            OVERLAPPED* completed = nullptr;
            valid = GetQueuedCompletionStatus(port.get(), &bytes, &key, &completed, 10000) &&
                completed == &overlapped && key == 0xABC && std::string_view(buffer, bytes) == "async-prewait";
            memset(buffer, 0xCC, sizeof(buffer));
        });
        Sleep(100);
        auto pending = !ReadFile(pipe.server.get(), buffer, sizeof(buffer), nullptr, &overlapped) &&
            GetLastError() == ERROR_IO_PENDING;
        pipe.Write("async-prewait");
        worker.join();
        Require(pending && valid, "Blocked completion worker was altered");
    }

    // Completed data retains explicit capture limits and inaccessible-memory state independently of I/O success.
    {
        Pipe pipe;
        OVERLAPPED overlapped{};
        char buffer[256]{};
        auto message = std::string("async-truncated") + std::string(185, 'Z');
        pipe.Write(message);
        Require(ReadFile(pipe.server.get(), buffer, sizeof(buffer), nullptr, &overlapped) &&
            std::string_view(buffer, overlapped.InternalHigh) == message, "Large immediate completion was altered");
    }
    {
        Pipe pipe;
        OVERLAPPED overlapped{};
        auto buffer = static_cast<char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        Require(buffer && !ReadFile(pipe.server.get(), buffer, 128, nullptr, &overlapped) &&
            GetLastError() == ERROR_IO_PENDING, "Submit guarded asynchronous read");
        pipe.Write("async-inaccessible");
        auto deadline = GetTickCount64() + 10000;
        while (static_cast<volatile OVERLAPPED*>(&overlapped)->Internal == 0x103 && GetTickCount64() < deadline)
            SwitchToThread();
        Require(overlapped.Internal == 0, "Guarded asynchronous read did not complete");
        DWORD protection = 0, bytes = 0;
        Require(VirtualProtect(buffer, 4096, PAGE_NOACCESS, &protection) &&
            GetOverlappedResult(pipe.server.get(), &overlapped, &bytes, TRUE), "Query inaccessible completion");
        Require(VirtualProtect(buffer, 4096, PAGE_READWRITE, &protection) &&
            std::string_view(buffer, bytes) == "async-inaccessible", "Guarded completion was altered");
        VirtualFree(buffer, 0, MEM_RELEASE);
    }

    // APC observers must run before application callbacks overwrite the completed buffers.
    {
        Pipe pipe;
        ApcState state;
        Require(ReadFileEx(pipe.server.get(), state.buffer, sizeof(state.buffer), &state.overlapped,
            Win32Completed) != FALSE, "Submit APC read");
        pipe.Write("async-apc");
        for (uint32_t wait = 0; wait < 20 && !state.completed; ++wait) SleepEx(500, TRUE);
        Require(state.completed && static_cast<unsigned char>(state.buffer[0]) == 0xCC,
            "Win32 callback arguments were altered");
    }
    {
        Pipe pipe;
        ApcState state;
        IO_STATUS_BLOCK status{};
        using NativeApc = void(NTAPI*)(void*, IO_STATUS_BLOCK*, ULONG);
        using NativeRead = NTSTATUS(NTAPI*)(HANDLE, HANDLE, NativeApc, void*, IO_STATUS_BLOCK*, void*,
            ULONG, LARGE_INTEGER*, ULONG*);
        auto read = reinterpret_cast<NativeRead>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadFile"));
        Require(read && read(pipe.server.get(), nullptr, NativeCompleted, &state, &status, state.buffer,
            sizeof(state.buffer), nullptr, nullptr) == 0x103, "Submit native APC read");
        pipe.Write("async-native");
        for (uint32_t wait = 0; wait < 20 && !state.completed; ++wait) SleepEx(500, TRUE);
        Require(state.completed && static_cast<unsigned char>(state.buffer[0]) == 0xDD,
            "Native callback context was altered");
    }
    {
        WSADATA data{};
        Require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Initialize Winsock");
        auto listener = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        auto client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int size = sizeof(address);
        Require(listener != INVALID_SOCKET && client != INVALID_SOCKET &&
            bind(listener, reinterpret_cast<sockaddr*>(&address), size) == 0 && listen(listener, 1) == 0 &&
            getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size) == 0 &&
            connect(client, reinterpret_cast<sockaddr*>(&address), size) == 0, "Connect Winsock pair");
        auto server = accept(listener, nullptr, nullptr);
        Require(server != INVALID_SOCKET, "Accept Winsock pair");
        OVERLAPPED overlapped{};
        char first[4]{}, second[64]{};
        DWORD bytes = 0, flags = 0;
        {
            WSABUF buffers[]{{sizeof(first), first}, {sizeof(second), second}};
            Require(WSARecv(server, buffers, 2, &bytes, &flags, &overlapped, nullptr) == SOCKET_ERROR &&
                WSAGetLastError() == WSA_IO_PENDING, "Submit vector receive");
            memset(buffers, 0xCC, sizeof(buffers));
        }
        Require(send(client, "async-wsa", 9, 0) == 9 &&
            WSAGetOverlappedResult(server, &overlapped, &bytes, TRUE, &flags) && bytes == 9 &&
            std::string(first, 4) + std::string(second, 5) == "async-wsa", "Vector completion was altered");
        ApcState state;
        WSABUF callbackBuffer{sizeof(state.buffer), state.buffer};
        Require(WSARecv(server, &callbackBuffer, 1, &bytes, &flags,
            &state.overlapped, WinsockCompleted) == SOCKET_ERROR &&
            WSAGetLastError() == WSA_IO_PENDING && send(client, "async-wsa-apc", 13, 0) == 13,
            "Submit Winsock APC receive");
        for (uint32_t wait = 0; wait < 20 && !state.completed; ++wait) SleepEx(500, TRUE);
        Require(state.completed && static_cast<unsigned char>(state.buffer[0]) == 0xCE,
            "Winsock callback arguments were altered");
        closesocket(server);
        closesocket(client);
        closesocket(listener);
        WSACleanup();
    }
    std::puts("PASS: result, IOCP, APC, cancellation and reused controls.");
    return 0;
}

void CompletionRace(const Context& context)
{
    // A real trace store must preserve completion outputs when the submitting return arrives later.
    auto path = context.directory / L"async-race.sqlite";
    Detourist::TraceStore store(path);
    auto target = store.AddTarget(123, L"race.exe", 0, Detourist::AllApis);
    Detourist::Record record;
    record.event.kind = Detourist::EventKind::Enter;
    record.event.api = Detourist::Api::ReadFile;
    record.event.callId = 1;
    record.event.timestamp = Detourist::Clock();
    store.Add(target, record);
    record.event.kind = Detourist::EventKind::AsyncCompletion;
    record.event.timestamp = Detourist::Clock();
    record.event.flags = Detourist::AsyncCompleted | Detourist::Failed | Detourist::AsyncCancelled;
    record.event.arguments[3] = ERROR_OPERATION_ABORTED;
    record.event.arguments[4] = static_cast<uint32_t>(Detourist::AsyncIoDomain::Win32);
    record.event.arguments[5] = static_cast<uint32_t>(Detourist::AsyncIoSource::CompletionPort);
    store.Add(target, record);
    record.event.kind = Detourist::EventKind::Leave;
    record.event.timestamp = Detourist::Clock();
    record.event.result = 0;
    record.event.error = ERROR_IO_PENDING;
    record.event.flags = Detourist::Failed | Detourist::AsyncPending;
    store.Add(target, record);
    store.Flush();
    auto rows = Detourist::TraceStore::ReadPage(path, {.includePayload = true}).calls;
    Require(rows.size() == 1 && rows[0].flags == (Detourist::AsyncCompleted | Detourist::Failed |
        Detourist::AsyncCancelled) && rows[0].error == ERROR_IO_PENDING && rows[0].duration >= 0 &&
        rows[0].completion.status == ERROR_OPERATION_ABORTED, "Late API return overwrote completion data");

    // A returned pending call can enter the live failures view when its asynchronous result becomes known.
    record = {};
    record.event.kind = Detourist::EventKind::Enter;
    record.event.api = Detourist::Api::ReadFile;
    record.event.callId = 2;
    record.event.timestamp = Detourist::Clock();
    store.Add(target, record);
    record.event.kind = Detourist::EventKind::Leave;
    record.event.flags = Detourist::AsyncPending;
    store.Add(target, record);
    store.Flush();
    Detourist::TraceView view(path, {.failuresOnly = true, .order = Detourist::ViewOrder::Oldest});
    while (!view.Complete()) view.Advance(100);
    Require(view.Count() == 1, "Pending I/O entered the failures view before its outcome was known");
    record.event.kind = Detourist::EventKind::AsyncCompletion;
    record.event.flags = Detourist::AsyncCompleted | Detourist::Failed;
    record.event.arguments[3] = ERROR_CRC;
    record.event.arguments[4] = static_cast<uint32_t>(Detourist::AsyncIoDomain::Win32);
    record.event.arguments[5] = static_cast<uint32_t>(Detourist::AsyncIoSource::Result);
    store.Add(target, record);
    store.Flush();
    view.Advance(100);
    while (!view.Complete()) view.Advance(100);
    Require(view.Count() == 2 && view.Rows(0, 10, false)[1].id == 2,
        "An asynchronous failure did not enter the live filtered view");
}

void AsyncIo(const Context& context)
{
    CompletionRace(context);
    Require(RunTarget(context).contains("PASS:"), "Asynchronous workload baseline failed");
    for (bool instructions : {false, true})
    {
        Capture::Run(context, {.limit = 32, .instructions = instructions,
            .excludedApis = {"GetQueuedCompletionStatus", "GetQueuedCompletionStatusEx",
                "NtRemoveIoCompletion", "NtRemoveIoCompletionEx"}}, [&](Capture& capture)
        {
            auto completed = capture.Calls("(c.flags & 262144)!=0");
            std::set<std::string> messages;
            std::set<uint32_t> sources;
            bool cancelled = false;
            bool vector = false;
            bool truncated = false, unreadable = false;
            auto inspections = Json::array();
            for (const auto& row : completed)
            {
                auto details = capture.Details(row);
                inspections.push_back(details);
                const auto& completion = details.at("completion");
                Require(completion["elapsedUs"].get<double>() >= 0 && (row["flags"].get<uint32_t>() & 8) == 0,
                    "Completed request remained pending", details);
                sources.insert(completion["source"].get<uint32_t>());
                if (row["name"] == "WSARecv" && completion["buffers"].size() == 2)
                {
                    auto buffers = Regions(row["output"], {.parameter = 1, .kind = 0,
                        .required = Detourist::ReferencedData});
                    Require(buffers.size() == 2 && buffers[0].data == Encode("asyn") &&
                        buffers[1].data == Encode("c-wsa") && completion["transferred"] == 9,
                        "Stack WSABUF descriptors were not retained", details);
                    vector = true;
                }
                if (row["flags"].get<uint32_t>() & Detourist::AsyncCancelled)
                {
                    cancelled = true;
                    Require((row["flags"].get<uint32_t>() & Detourist::Failed) != 0 &&
                        completion["transferred"] == 0, "Cancellation lost final status", details);
                }
                for (const auto& value : Values(row["output"]))
                {
                    if (value.index == 1 && row["name"] == "ReadFile")
                    {
                        if (completion["transferred"] == 200)
                        {
                            Require(value.data.size() == 32 && value.original == 200 &&
                                value.flags & Detourist::Truncated, "Completion exceeded its capture limit", details);
                            truncated = true;
                        }
                        if (completion["transferred"] == 18 && value.data.empty() &&
                            value.flags & Detourist::Unreadable) unreadable = true;
                    }
                    auto text = String(value.data);
                    if (text.starts_with("async-")) messages.insert(text);
                }
            }
            const std::set<std::string> expected{"async-result", "async-port-0", "async-port-1", "async-port-2",
                "async-port-4", "async-apc", "async-native", "async-prewait", "async-event", "async-immediate",
                "async-wsa-apc"};
            Require(std::ranges::all_of(expected, [&](const auto& message) { return messages.contains(message); }) &&
                cancelled && vector && truncated && unreadable && sources.contains(1) &&
                sources.contains(2) && sources.contains(3) && sources.contains(4) && sources.contains(5),
                "Asynchronous completion coverage is incomplete",
                {{"messages", messages}, {"sources", sources}, {"calls", completed}});
            capture.CheckDiagnostics(true);
            auto path = context.directory / (instructions ? L"async-instructions.json" : L"async-typed.json");
            WriteJson(path, inspections);
            if (context.Has(L"--inspector"))
                Inspect(context, context.Option(L"--inspector"), "--async-io", inspections);
        });

        // Editing the reported API return must not discard the actual kernel submission or its completion.
        Collector edited(context.collector, context.directory);
        auto editedPath = Launch(edited, context, {.arguments = L"edited", .instructions = instructions},
            {{"exitApi", static_cast<uint32_t>(Detourist::Api::ReadFile)}});
        auto stopped = edited.Wait([](const Json& state) { return state["breakpoint"] == true; });
        Require(stopped["leaving"] == true && stopped["stoppedCall"]["name"] == "ReadFile" &&
            (stopped["stoppedCall"]["flags"].get<uint32_t>() & Detourist::AsyncPending) != 0,
            "Return stop did not retain the real pending state", stopped);
        edited.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
        edited.Call("continue", {{"result", 1}, {"error", 0}});
        edited.Wait([](const Json& state) { return state["finished"] == true; });
        auto editedRow = Only(Calls(editedPath, "a.name='ReadFile'"));
        Require(editedRow["result"] == 1 && editedRow["error"] == 0 &&
            (editedRow["flags"].get<uint32_t>() & (Detourist::Edited | Detourist::AsyncCompleted)) ==
                (Detourist::Edited | Detourist::AsyncCompleted) &&
            Only(Snapshots(editedRow["output"], 1, 0)) == Encode("async-edited"),
            "A return edit replaced the real I/O outcome", editedRow);
        edited.Close();

        // Completion observers stay active while paused and excluded from the event stream.
        Collector collector(context.collector, context.directory);
        auto database = Launch(collector, context, {.arguments = L"paused", .instructions = instructions,
            .excludedApis = {"GetQueuedCompletionStatus", "NtRemoveIoCompletion"}});
        collector.Wait([&](const Json&)
        {
            return !Calls(database, "a.name='ReadFile' AND (c.flags & 8)!=0").empty();
        });
        auto pid = Only(Query(database, "SELECT pid FROM targets ORDER BY id LIMIT 1"))["pid"].get<uint32_t>();
        auto gateName = L"Local\\Detourist.Async.Gate." + std::to_wstring(pid);
        Detourist::Handle gate(OpenEventW(EVENT_MODIFY_STATE, FALSE, gateName.c_str()));
        Require(static_cast<bool>(gate), "Paused capture gate was not created");
        collector.Call("pause", {{"paused", true}});
        Require(SetEvent(gate.get()) != FALSE, "Release paused capture gate");
        collector.Wait([](const Json& state) { return state["finished"] == true; });
        auto completed = Calls(database, "a.name='ReadFile' AND (c.flags & 262144)!=0");
        Require(completed.size() == 1 && Only(Snapshots(completed[0]["output"], 1, 0)) == Encode("async-paused"),
            "Filtered observer lost a completion while paused", completed);
        collector.Close();
    }
}

void AsyncLifecycle(const Context& context)
{
    // Keep a native wait and an APC outstanding across detach, then verify fresh observations after reattachment.
    for (bool instructions : {false, true})
    for (bool reattach : {false, true})
    {
        Collector reconnect(context.collector, context.directory);
        auto first = Launch(reconnect, context, {.arguments = L"detached", .instructions = instructions});
        reconnect.Wait([&](const Json&)
        {
            return !Calls(first, "COALESCE(d.name,a.name)='ReadFileEx' AND (c.flags & 8)!=0").empty() &&
                !Query(first, "SELECT c.id FROM calls c LEFT JOIN apis a ON a.target=0 AND a.id=c.api "
                    "LEFT JOIN apis d ON d.target=c.target AND d.id=c.api WHERE c.ended IS NULL AND "
                    "COALESCE(d.name,a.name)='WaitForSingleObject'").empty();
        });
        auto pid = Only(Query(first, "SELECT pid FROM targets ORDER BY id LIMIT 1"))["pid"].get<uint32_t>();
        auto gateName = L"Local\\Detourist.Async.Gate." + std::to_wstring(pid);
        Detourist::Handle gate(OpenEventW(EVENT_MODIFY_STATE, FALSE, gateName.c_str()));
        Require(static_cast<bool>(gate), "Detached callback gate was not created");
        Detourist::Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        Require(static_cast<bool>(process), "Open detached callback target");
        reconnect.Call("stop");
        reconnect.Wait([](const Json& state) { return state["finished"] == true; });
        if (!reattach)
        {
            Require(SetEvent(gate.get()) && WaitForSingleObject(process.get(), 20000) == WAIT_OBJECT_0,
                "Outstanding APC did not return after capture detached");
            DWORD code = 1;
            Require(GetExitCodeProcess(process.get(), &code) && !code,
                "Outstanding APC arguments were altered after capture detached");
            reconnect.Close();
            continue;
        }
        auto second = context.directory / ("async-reconnected-" + std::to_string(instructions) + ".sqlite");
        reconnect.Call("attach", {{"pid", pid}, {"database", Text(second)}, {"instructionEngine", instructions}});
        reconnect.Wait([](const Json& state) { return state["capturing"] == true; });
        Require(SetEvent(gate.get()) != FALSE, "Release detached callback gate");
        auto ended = reconnect.Wait([](const Json& state) { return state["finished"] == true; });
        Require(!ended["message"].get<std::string>().contains("nonzero exit code") &&
            Calls(second, "COALESCE(d.name,a.name)='ReadFileEx'").empty(),
            "An outstanding callback failed after detach or completed a different session", ended);
        auto fresh = Calls(second, "COALESCE(d.name,a.name)='ReadFile' AND (c.flags & 262144)!=0");
        Require(fresh.size() == 1 && fresh[0]["parent"] == 0 &&
            Only(Snapshots(fresh[0]["output"], 1, 0)) == Encode("async-restarted"),
            "Reattached capture did not observe fresh I/O after the pending wait returned", fresh);
        reconnect.Close();
    }
}

int wmain(int argc, wchar_t** argv)
{
    return Run(argc, argv, [](const Context& context)
    {
        if (context.Has(L"--lifecycle")) AsyncLifecycle(context);
        else AsyncIo(context);
    }, TargetMain);
}

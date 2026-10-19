#include "TestSupport.h"
#include "TraceStore.h"

using namespace Detourist::Tests;

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 3) return 1;
    Detourist::Handle output(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr));
    if (!output) return 2;
    HMODULE first = nullptr;

    // Replace the image at one address faster than the controller's module polling interval.
    for (uint32_t index = 0; index < 6; ++index)
    {
        auto module = LoadLibraryW(arguments[1 + index % 2]);
        if (!module) return 3;
        if (!first) first = module;
        if (module != first) return 4;
        auto call = reinterpret_cast<BOOL(WINAPI*)(HANDLE)>(GetProcAddress(module, "ModuleLifetimeCall"));
        if (!call || !call(output.get())) return 5;
        if (!FreeLibrary(module)) return 6;
    }
    std::puts("PASS: six calls from two images reused one base address.");
    return 0;
}

void ModuleLifetimes(const Context& context)
{
    // Module publications update existing visible rows without changing their saved call identities.
    {
        auto path = context.directory / L"module-view.db";
        Detourist::TraceStore store(path);
        auto target = store.AddTarget(123, L"module-view.exe", 0, Detourist::AllApis);
        constexpr uint64_t base = 0x180000000;
        store.AddModule(target, base, 0x10000, L"first.dll");
        auto publish = [&](uint64_t id, uint64_t epoch)
        {
            Detourist::Record record;
            record.event = {};
            record.event.kind = Detourist::EventKind::Enter;
            record.event.api = Detourist::Api::WriteFile;
            record.event.callId = id;
            record.event.timestamp = Detourist::Clock();
            record.event.caller = base + 0x1234;
            record.event.moduleEpoch = epoch;
            store.Add(target, record);
            record.event.kind = Detourist::EventKind::Leave;
            record.event.timestamp = Detourist::Clock();
            store.Add(target, record);
        };
        publish(1, 0);
        store.Flush();
        Detourist::TraceView view(path, {.order = Detourist::ViewOrder::Oldest});
        while (!view.Complete()) view.Advance(100);
        Require(view.Rows(0, 10, false)[0].callerModule == "first.dll", "Initial caller module missing");
        store.AddModule(target, base, 0x10000, L"first.dll", 1, false);
        store.AddModule(target, base, 0x10000, L"second.dll", 2);
        publish(2, 2);
        store.Flush();
        Require(view.Advance(100) && view.ChangedFrom() == 0, "Live caller metadata was not invalidated");
        auto rows = view.Rows(0, 10, false);
        Require(rows.size() == 2 && rows[0].id == 1 && rows[0].callerModule == "first.dll" &&
            rows[1].id == 2 && rows[1].callerModule == "second.dll", "Live rows mixed image lifetimes");
    }

    // Native loading exercises short-lived images and address reuse through both capture engines.
    auto arguments = Quote(context.Extra(0)) + L" " + Quote(context.Extra(1));
    Require(RunTarget(context, arguments).contains("PASS:"), "Module reuse baseline failed");
    for (bool instructions : {false, true})
    {
        Capture::Run(context, {.arguments = arguments, .instructions = instructions}, [&](Capture& capture)
        {
            auto histories = Query(capture.database, "SELECT base,count(DISTINCT path) identities FROM modules "
                "WHERE path LIKE '%DetouristModule%.dll' GROUP BY base");
            Require(histories.size() == 1 && histories[0]["identities"] == 2,
                "Image address reuse lost a module identity", histories);
            Require(Query(capture.database, "SELECT * FROM coverage WHERE module_error<>0").empty(),
                "Module history reported incomplete discovery");

            // Saved callers and caller filters must select the same historical image after both DLLs are gone.
            for (uint32_t index = 0; index < 2; ++index)
            {
                auto name = Text(context.Extra(index).filename());
                auto state = capture.collector.Call("view", {{"database", Text(capture.database)},
                    {"filter", "=WriteFile from:" + name}, {"order", "oldest"}, {"budget", 1000}});
                auto view = state.at("view");
                auto deadline = GetTickCount64() + 10000;
                while (!state.at("complete").get<bool>())
                {
                    Require(GetTickCount64() < deadline, "Module caller filter did not finish");
                    state = capture.collector.Call("view", {{"view", view}, {"budget", 1000}});
                }
                auto rows = capture.collector.Call("rows", {{"view", view}, {"limit", 20}}).at("calls");
                Require(rows.size() == 3, "Caller filter mixed image lifetimes", rows);
                for (const auto& row : rows)
                    Require(row.value("callerText", std::string{}).starts_with(name + "+"),
                        "Saved caller resolved to a replacement image", row);
                capture.collector.Call("release", {{"view", view}});
            }
            capture.CheckDiagnostics(true);
        });
    }
}

int wmain(int argc, wchar_t** argv) { return Run(argc, argv, ModuleLifetimes, TargetMain); }

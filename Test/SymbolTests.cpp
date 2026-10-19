#include "TestSupport.h"
#include "TraceStore.h"

using namespace Detourist::Tests;

#ifdef _WIN64
void ObserverStackRegions(const Context& context)
{
    const auto module = LoadLibraryW((context.collector.parent_path() / L"DetouristAgent.dll").c_str());
    using Capture = uint32_t(WINAPI*)(const CONTEXT*, uint64_t, uint64_t*, uint32_t, uint32_t*);
    const auto capture = module ? reinterpret_cast<Capture>(GetProcAddress(module, "DetouristCaptureStack")) : nullptr;
    const auto other = module ? GetProcAddress(module, "DetouristStart") : nullptr;
    Require(capture && other, "Load native stack capture");
    const auto base = reinterpret_cast<uint64_t>(module);
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    const auto image = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const auto code = reinterpret_cast<void*>(base + image->OptionalHeader.BaseOfCode);
    alignas(16) uint64_t stack[4]{};
    uint64_t frames[Detourist::MaximumStack]{};

    // Check earlier code, the caller's own page and observer headers unrelated to an application frame.
    for (uint32_t boundary : {0u, 1u, 2u})
    for (DWORD protection : {PAGE_EXECUTE_READ | PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY})
    {
        const auto current = boundary == 1;
        CONTEXT source{};
        RtlCaptureContext(&source);
        source.Rip = boundary == 2 ? reinterpret_cast<uint64_t>(&ObserverStackRegions) :
            reinterpret_cast<uint64_t>(current ? other : reinterpret_cast<FARPROC>(capture));
        source.Rsp = reinterpret_cast<uint64_t>(stack);
        auto address = boundary == 2 ? module : current ? reinterpret_cast<void*>(other) : code;
        DWORD previous = 0, ignored = 0;
        Require(VirtualProtect(address, 1, protection, &previous) != FALSE, "Protect observer code page");
        uint32_t flags = 0;
        SetLastError(ERROR_CANCELLED);
        const auto count = capture(&source, 0, frames, Detourist::MaximumStack, &flags);
        const auto error = GetLastError();
        MEMORY_BASIC_INFORMATION region{};
        const auto queried = VirtualQuery(address, &region, sizeof(region));
        const auto restored = VirtualProtect(address, 1, previous, &ignored);
        Require(queried && restored && region.Protect == protection && error == ERROR_CANCELLED &&
            count == (current ? 0u : 1u) && flags == (current ? Detourist::Truncated : 0u) &&
            (current || frames[0] == source.Rip), "Observer stack crossed or consumed a protected page");
    }
}
#endif

int TargetMain(int count, wchar_t** arguments)
{
    if (count != 3) return 1;
    Detourist::Handle file(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr));
    if (!file) return 2;
    if (!wcsncmp(arguments[2], L"--preexisting-", 14))
    {
        auto module = LoadLibraryW(arguments[1]);
        auto dynamic = module ? reinterpret_cast<BOOL(WINAPI*)(HANDLE, DWORD)>(
            GetProcAddress(module, "SymbolDynamic")) : nullptr;
        return dynamic && dynamic(file.get(), 0x100 | wcstoul(arguments[2] + 14, nullptr, 10)) ? 0 : 6;
    }
    HMODULE base = nullptr;
    for (uint32_t image = 0; image < 2; ++image)
    {
        auto module = LoadLibraryW(arguments[image + 1]);
        if (!module || base && base != module) return 3;
        base = module;
        auto capture = reinterpret_cast<BOOL(WINAPI*)(HANDLE, DWORD)>(GetProcAddress(module, "SymbolCapture"));
        if (!capture || !capture(file.get(), 0) || !capture(file.get(), 1) || !capture(file.get(), 3)) return 4;
#ifdef _WIN64
        if (!capture(file.get(), (32u << 8) | 4) || !capture(file.get(), (64u << 8) | 5)) return 4;
#endif
        auto locked = reinterpret_cast<BOOL(WINAPI*)(HANDLE)>(GetProcAddress(module, "SymbolLocked"));
        auto dynamic = reinterpret_cast<BOOL(WINAPI*)(HANDLE, DWORD)>(GetProcAddress(module, "SymbolDynamic"));
        if (!locked || !dynamic || !locked(file.get()) || !dynamic(file.get(), 0)) return 5;
#ifdef _WIN64
        for (DWORD mode : {1u, 2u, 3u, 4u, 5u}) if (!dynamic(file.get(), mode)) return 6;
#endif
        if (!FreeLibrary(module)) return 7;

        // Module observers can hold temporary references while inspecting a loaded image.
        const auto deadline = GetTickCount64() + 5000;
        for (;;)
        {
            MEMORY_BASIC_INFORMATION region{};
            if (!VirtualQuery(module, &region, sizeof(region))) return 7;
            if (region.Type != MEM_IMAGE || region.AllocationBase != module) break;
            if (GetTickCount64() >= deadline) return 7;
            Sleep(10);
        }
    }
    std::puts("PASS: private-symbol callers from two image lifetimes.");
    return 0;
}

void AttachedSymbols(const Context& context)
{
    for (bool instructions : {false, true})
    for (DWORD mode : {0u, 1u, 2u, 4u, 5u})
    {
        TargetProcess target(context, Quote(context.Extra(0)) + L" --preexisting-" + std::to_wstring(mode));
        const auto name = L"Local\\Detourist.Symbol." + std::to_wstring(target.Pid());
        Detourist::Handle ready;
        const auto deadline = GetTickCount64() + 10000;
        while (!ready && GetTickCount64() < deadline && target.Running())
        {
            ready.reset(OpenEventW(SYNCHRONIZE, FALSE, (name + L".Ready").c_str()));
            if (!ready) Sleep(10);
        }
        Require(ready && WaitForSingleObject(ready.get(), 10000) == WAIT_OBJECT_0,
            "Dynamic function table was not registered before attachment");
        Detourist::Handle gate(OpenEventW(EVENT_MODIFY_STATE, FALSE, (name + L".Gate").c_str()));
        Collector collector(context.collector, context.directory);
        const auto database = context.directory / ("attached-" + std::to_string(instructions) + "-" +
            std::to_string(mode) + ".sqlite");
        collector.Call("attach", {{"pid", target.Pid()}, {"database", Text(database)},
            {"instructionEngine", instructions}, {"stackDepth", 16}});
        collector.Wait([](const Json& state) { return state["capturing"] == true; });
        Require(gate && SetEvent(gate.get()), "Release attached dynamic function");
        collector.Wait([](const Json& state) { return state["finished"] == true; });
        Require(target.Wait() == 0, "Attached dynamic unwind workload failed");
        uint32_t available = 0, partial = 0;
        for (const auto& call : Calls(database, "COALESCE(d.name,a.name)='WriteFile'"))
        {
            auto buffers = Snapshots(call["input"], 1, static_cast<uint32_t>(Detourist::ValueKind::Bytes));
            if (buffers.empty()) continue;
            auto message = String(buffers.front());
            if (!message.starts_with("Table") && !message.starts_with("Dynamic")) continue;
            auto page = Detourist::TraceStore::ReadPage(database.wstring(), {.target = call["target"].get<int64_t>(),
                                                                                .callId = call["id"].get<uint64_t>(),
                                                                                .includePayload = true});
            Require(page.calls.size() == 1, "Attached stack is missing");
            const auto& row = page.calls.front();
            if (message.starts_with("TableOn"))
            {
                Require(row.stack.size() >= 2 && std::ranges::any_of(row.stack, [](const auto& frame)
                                                     { return frame.symbol.name == "SymbolDynamic"; }),
                    "Pre-attachment unwind metadata lost its caller", {{"engine", instructions}, {"mode", mode}});
                ++available;
            }
            else
            {
                const auto values = Values(call["input"]);
                const auto stack = std::find_if(values.begin(), values.end(), [](const auto& value)
                    { return value.kind == static_cast<uint32_t>(Detourist::ValueKind::Stack); });
                Require(row.stack.size() == 1 && stack != values.end() && (stack->flags & Detourist::Truncated),
                    "Unavailable metadata was not explicitly partial");
                ++partial;
            }
        }
        Require(available == (mode == 5 ? 4u : mode ? 1u : 0u) &&
            partial == (mode == 5 ? 5u : mode == 2 ? 2u : 1u),
            "Pre-attachment stack coverage differs", {{"mode", mode}, {"available", available}, {"partial", partial}});
        collector.Close();
    }
}

void Symbols(const Context& context)
{
#ifdef _WIN64
    ObserverStackRegions(context);
#endif
    for (bool instructions : {false, true})
    {
        auto root = context.directory / (instructions ? L"instructions" : L"typed");
        auto images = root / L"images";
        auto symbols = root / L"symbols";
        auto empty = root / L"empty";
        std::filesystem::create_directories(images);
        std::filesystem::create_directory(symbols);
        std::filesystem::create_directory(empty);
        std::array<Path, 2> dlls, pdbs;
        for (uint32_t index = 0; index < 2; ++index)
        {
            dlls[index] = images / context.Extra(index).filename();
            pdbs[index] = images / context.Extra(index + 2).filename();
            std::filesystem::copy_file(context.Extra(index), dlls[index]);
            std::filesystem::copy_file(context.Extra(index + 2), pdbs[index]);
        }
        auto arguments = Quote(dlls[0]) + L" " + Quote(dlls[1]);
        Require(RunTarget(context, arguments).contains("PASS:"), "Private-symbol workload baseline failed");
        Path database;
        Json callers = Json::array();
        Json inspections = Json::array();
        uint32_t loaderCalls = 0, dynamicCalls = 0, directCalls = 0;
        uint32_t registeredCalls = 0, retiredCalls = 0, deepCalls = 0;
        {
            Collector collector(context.collector, context.directory);
            database = Launch(collector, context, {.arguments = arguments, .instructions = instructions},
                {{"stackDepth", Detourist::MaximumStack}});
            auto status = collector.Wait([](const Json& value) { return value["finished"] == true; });
            Require(
                !status["message"].get<std::string>().contains("nonzero exit code"), "Symbol workload failed", status);
            for (const auto& call : Calls(database,
                "COALESCE(d.name,a.name) IN('WriteFile','NtWriteFile','NtWriteFile [syscall]')"))
            {
                auto page =
                    Detourist::TraceStore::ReadPage(database.wstring(), {.target = call["target"].get<int64_t>(),
                                                                            .callId = call["id"].get<uint64_t>(),
                                                                            .includePayload = true});
                Require(page.calls.size() == 1, "Saved caller was not found");
                const auto& row = page.calls.front();
                auto buffers = Snapshots(call["input"], 1, static_cast<uint32_t>(Detourist::ValueKind::Bytes));
                const auto message = buffers.empty() ? std::string{} : String(buffers.front());
                if (row.name == "WriteFile" && message.starts_with("TableOn"))
                {
                    Require(!(row.flags & Detourist::StackUnavailable) && row.stack.size() >= 2 &&
                                row.stack[0].address == row.caller &&
                                std::ranges::any_of(
                                    row.stack, [](const auto& frame) { return frame.symbol.name == "SymbolDynamic"; }),
                        "Registered dynamic unwind metadata lost its static caller",
                        {{"engine", instructions ? "instructions" : "typed"}, {"frames", row.stack.size()}});
                    inspections.push_back(collector.Call("details", {{"database", Text(database)},
                        {"target", row.target}, {"callId", row.id}}));
                    ++registeredCalls;
                }
                if (row.name == "WriteFile" && (message.starts_with("Dynamic") || message.starts_with("TableNo")))
                {
                    auto values = Values(call["input"]);
                    auto stack = std::find_if(values.begin(), values.end(), [](const auto& value)
                    {
                        return value.kind == static_cast<uint32_t>(Detourist::ValueKind::Stack);
                    });
                    Require(!(row.flags & Detourist::StackUnavailable) && row.stack.size() == 1 &&
                        row.stack[0].address == row.caller && stack != values.end() &&
                        (stack->flags & Detourist::Truncated), "Dynamic stack was not explicitly partial");
                    inspections.push_back(collector.Call("details", {{"database", Text(database)},
                        {"target", row.target}, {"callId", row.id}}));
                    if (message.starts_with("Dynamic")) ++dynamicCalls;
                    else ++retiredCalls;
                }
                for (uint32_t index = 0; index < 2; ++index)
                {
                    auto expected = std::string(index ? "SymbolSecondInner" : "SymbolFirstInner");
                    auto outer = std::string(index ? "SymbolSecondOuter" : "SymbolFirstOuter");
                    if (row.callerModule != Text(dlls[index].filename())) continue;
                    if (row.name == "NtWriteFile [syscall]")
                    {
                        Require(instructions && row.callerSymbol.name == "SymbolSyscall" && row.stack.size() >= 3 &&
                            row.stack[0].symbol.name == "SymbolSyscall" && row.stack[1].symbol.name == expected &&
                            row.stack[2].symbol.name == outer, "Direct syscall lost its static native stack");
                        ++directCalls;
                        continue;
                    }
                    Require(row.callerSymbol.name == expected && row.callerSymbol.line != 0 &&
                        row.callerSymbol.source.ends_with("SymbolFixture.cpp"), "Offline private caller symbol differs",
                        {{"expected", expected}, {"symbol", row.callerSymbol.name}, {"state", row.callerSymbol.state}});
                    if (row.name == "WriteFile" && !buffers.empty() && String(buffers.front()).starts_with("Locked"))
                    {
                        Require((row.flags & Detourist::StackUnavailable) && row.stack.empty(),
                            "A loader-lock call attempted a full stack walk");
                        ++loaderCalls;
                        continue;
                    }
                    Require(!(row.flags & Detourist::StackUnavailable) && row.stack.size() >= 2 &&
                        row.stack[0].symbol.name == expected && row.stack[1].symbol.name == outer,
                        "Private inner and outer stack frames were not captured",
                        {{"engine", instructions ? "instructions" : "typed"}, {"api", row.name},
                            {"flags", row.flags}, {"frames", row.stack.size()}});
                    if (message.starts_with("Deep") || message.starts_with("Capped"))
                    {
                        // Repeated frames must survive caching, and only the depth cap may shorten the deep chain.
                        const auto capped = message.starts_with("Capped");
                        const auto repeated = capped ? Detourist::MaximumStack - 1 : 33u;
                        const auto values = Values(call["input"]);
                        const auto stack = std::find_if(values.begin(), values.end(), [](const auto& value)
                            { return value.kind == static_cast<uint32_t>(Detourist::ValueKind::Stack); });
                        Require(row.stack.size() >= repeated + (capped ? 1u : 2u) && stack != values.end() &&
                            stack->flags == (capped ? Detourist::Truncated : 0u) &&
                            (!capped || row.stack.size() == Detourist::MaximumStack),
                            "Deep stack length or truncation differs",
                            {{"frames", row.stack.size()}, {"capped", capped}});
                        for (uint32_t frame = 1; frame <= repeated; ++frame)
                            Require(row.stack[frame].symbol.name == outer, "Deep stack lost a repeated caller");
                        if (!capped) Require(row.stack[repeated + 1].symbol.name != outer,
                            "Deep stack repeated a caller beyond its real depth");
                        ++deepCalls;
                        continue;
                    }
                    auto details = collector.Call("details", {{"database", Text(database)}, {"target", row.target},
                        {"callId", row.id}});
                    Require(details["callerSymbol"] == expected && details["symbolState"] == "resolved" &&
                        details["callerDisplay"].get<std::string>().contains("!" + expected),
                        "Collector omitted the resolved caller symbol", details);
                    Require(details["stack"].size() >= 2 && details["stack"][0]["symbol"] == expected &&
                        details["stack"][1]["symbol"] == outer, "Collector omitted resolved stack frames", details);
                    inspections.push_back(details);
                    callers.push_back({{"target", row.target}, {"id", row.id}, {"index", index}, {"symbol", expected}});
                }
            }
            Require(callers.size() == 4, "Module address reuse lost a private caller", callers);
            Require(deepCalls == (sizeof(void*) == 8 ? 4u : 0u), "Deep stack coverage differs");
            Require(loaderCalls == 2 && dynamicCalls == 2 && directCalls == (instructions ? 2u : 0u) &&
                registeredCalls == (sizeof(void*) == 8 ? 14u : 0u) && retiredCalls == (sizeof(void*) == 8 ? 20u : 0u),
                "Dynamic, unsafe-stack or syscall capture coverage differs",
                {{"loader", loaderCalls}, {"dynamic", dynamicCalls}, {"direct", directCalls},
                    {"registered", registeredCalls}, {"retired", retiredCalls}});
            collector.Close();
        }
        Detourist::SetSymbolDirectories({});

        // Resolve a saved trace using only matching PDBs after both original images have disappeared.
        for (const auto& dll : dlls) std::filesystem::remove(dll);
        Collector offline(context.collector, context.directory);
        for (const auto& caller : callers)
        {
            auto details = offline.Call("details", {{"database", Text(database)}, {"target", caller["target"]},
                {"callId", caller["id"]}});
            Require(details["callerSymbol"] == caller["symbol"], "PDB resolution depended on the executable image",
                details);
        }
        offline.Call("symbols");
        for (const auto& pdb : pdbs) std::filesystem::rename(pdb, symbols / pdb.filename());
        offline.Call("symbols", {{"directories", Json::array({Text(empty)})}});
        auto first = callers.front();
        auto details = offline.Call("details", {{"database", Text(database)}, {"target", first["target"]},
            {"callId", first["id"]}});
        Require(!details.contains("callerSymbol") && details["symbolState"] == "pdb_missing",
            "Missing PDB fabricated a caller symbol", details);
        inspections.push_back(details);
        offline.Call("symbols", {{"directories", Json::array({Text(symbols)})}});
        details = offline.Call("details", {{"database", Text(database)}, {"target", first["target"]},
            {"callId", first["id"]}});
        Require(details["callerSymbol"] == first["symbol"], "Configured PDB folder was not used", details);
        offline.Call("symbols", {{"directories", Json::array({Text(empty)})}});
        auto correct = symbols / pdbs[0].filename();
        auto saved = symbols / L"first-correct.pdb";
        std::filesystem::rename(correct, saved);
        std::filesystem::copy_file(symbols / pdbs[1].filename(), correct);
        offline.Call("symbols", {{"directories", Json::array({Text(symbols)})}});
        details = offline.Call("details", {{"database", Text(database)}, {"target", first["target"]},
            {"callId", first["id"]}});
        Require(!details.contains("callerSymbol") && details["symbolState"] == "pdb_mismatch",
            "An unrelated PDB was accepted under the expected filename", details);
        inspections.push_back(details);
        offline.Call("symbols", {{"directories", Json::array({Text(empty)})}});
        std::filesystem::remove(correct);
        std::filesystem::rename(saved, correct);
        offline.Call("symbols", {{"directories", Json::array({Text(symbols)})}});
        details = offline.Call("details", {{"database", Text(database)}, {"target", first["target"]},
            {"callId", first["id"]}});
        Require(details["callerSymbol"] == first["symbol"], "Reload did not recover the matching PDB", details);
        WriteJson(root / L"caller.json", details);
        if (context.Has(L"--inspector")) Inspect(context, context.Option(L"--inspector"), "--symbols",
            {{"calls", inspections}, {"hello", offline.Call("hello")}});
        offline.Close();
    }
}

int wmain(int argc, wchar_t** argv)
{
    return Run(argc, argv, [](const Context& context)
    {
        if (context.Has(L"--attach")) AttachedSymbols(context);
        else Symbols(context);
    }, TargetMain);
}

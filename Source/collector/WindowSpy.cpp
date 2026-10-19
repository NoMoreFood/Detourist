#include "WindowSpy.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <vector>

namespace Detourist
{
using Json = nlohmann::json;

constexpr size_t MaxSnapshotWindows = 30000;
constexpr size_t MaxSnapshotThreads = 100000;
constexpr int MaxPickDepth = 100;
constexpr UINT MessageTextTimeoutMs = 100;
constexpr ULONGLONG SpyBufferLockTimeoutMs = 200;
constexpr ULONGLONG SpyStopLockTimeoutMs = 100;
constexpr ULONGLONG SpyThreadRefreshMs = 1000;
constexpr uint32_t RegisteredMessageFirst = 0xC000;
constexpr uint32_t RegisteredMessageLast = 0xFFFF;

Json SpyWindowInfo(HWND window)
{
    DWORD pid = 0;
    const auto tid = GetWindowThreadProcessId(window, &pid);
    WINDOWINFO info{sizeof(info)};
    if (!tid || !GetWindowInfo(window, &info)) return nullptr;
    wchar_t title[1024]{}, name[256]{};
    GetWindowTextW(window, title, static_cast<int>(std::size(title)));
    GetClassNameW(window, name, static_cast<int>(std::size(name)));
    return {{"window", Hex(reinterpret_cast<uintptr_t>(window))}, {"pid", pid}, {"tid", tid},
        {"parent", Hex(reinterpret_cast<uintptr_t>(GetAncestor(window, GA_PARENT)))},
        {"owner", Hex(reinterpret_cast<uintptr_t>(GetWindow(window, GW_OWNER)))},
        {"title", Utf8(title)}, {"class", Utf8(name)}, {"style", info.dwStyle}, {"extendedStyle", info.dwExStyle},
        {"visible", IsWindowVisible(window) != FALSE}, {"enabled", IsWindowEnabled(window) != FALSE},
        {"left", info.rcWindow.left}, {"top", info.rcWindow.top}, {"right", info.rcWindow.right},
        {"bottom", info.rcWindow.bottom}, {"clientWidth", info.rcClient.right - info.rcClient.left},
        {"clientHeight", info.rcClient.bottom - info.rcClient.top}};
}

Json SpySnapshot()
{
    // A bounded snapshot uses stored captions, without sending messages to applications being inspected.
    auto windows = Json::array(), threads = Json::array();
    auto append = [](HWND window, LPARAM context) -> BOOL
    {
        auto& items = *reinterpret_cast<Json*>(context);
        if (items.size() >= MaxSnapshotWindows) return FALSE;
        auto item = SpyWindowInfo(window);
        if (!item.is_null()) items.push_back(std::move(item));
        return TRUE;
    };
    struct Enumeration { Json* windows; WNDENUMPROC append; } context{&windows, append};
    EnumWindows([](HWND window, LPARAM parameter) -> BOOL
    {
        auto& state = *reinterpret_cast<Enumeration*>(parameter);
        if (!state.append(window, reinterpret_cast<LPARAM>(state.windows))) return FALSE;
        EnumChildWindows(window, state.append, reinterpret_cast<LPARAM>(state.windows));
        return TRUE;
    }, reinterpret_cast<LPARAM>(&context));

    // Message-only windows belong in process and thread trees even though they have no screen rectangle.
    HWND previous = nullptr;
    for (size_t count = 0; count < MaxSnapshotWindows; ++count)
    {
        auto window = FindWindowExW(HWND_MESSAGE, previous, nullptr, nullptr);
        if (!window || !append(window, reinterpret_cast<LPARAM>(&windows))) break;
        EnumChildWindows(window, append, reinterpret_cast<LPARAM>(&windows));
        previous = window;
    }
    auto processes = ProcessList();
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    Check(static_cast<bool>(snapshot), "List threads");
    THREADENTRY32 entry{sizeof(entry)};
    if (Thread32First(snapshot.get(), &entry))
    {
        do
        {
            threads.push_back({{"pid", entry.th32OwnerProcessID}, {"tid", entry.th32ThreadID},
                {"priority", entry.tpBasePri}});
        } while (threads.size() < MaxSnapshotThreads && Thread32Next(snapshot.get(), &entry));
    }
    const auto truncated = windows.size() >= MaxSnapshotWindows || threads.size() >= MaxSnapshotThreads;
    return {{"windows", std::move(windows)}, {"processes", std::move(processes)},
        {"threads", std::move(threads)}, {"truncated", truncated}};
}

Json SpyProperties(DWORD pid, DWORD tid, HWND window)
{
    auto properties = Json::array();
    auto add = [&](const char* name, const std::string& value)
    {
        properties.push_back({{"name", name}, {"value", value}});
    };
    auto number = [&](const char* name, uint64_t value) { add(name, std::to_string(value)); };
    auto times = [&](FILETIME created, FILETIME kernel, FILETIME user)
    {
        SYSTEMTIME time{};
        if (FileTimeToSystemTime(&created, &time))
        {
            char text[64];
            snprintf(text, sizeof(text), "%04u-%02u-%02u %02u:%02u:%02u UTC", time.wYear, time.wMonth,
                time.wDay, time.wHour, time.wMinute, time.wSecond);
            add("Created", text);
        }
        auto milliseconds = [](FILETIME value)
        {
            return ((uint64_t{value.dwHighDateTime} << 32) | value.dwLowDateTime) / 10000;
        };
        number("Kernel CPU (ms)", milliseconds(kernel));
        number("User CPU (ms)", milliseconds(user));
    };

    // Validate the selected identity again because windows and threads can disappear between requests.
    if (window)
    {
        auto item = SpyWindowInfo(window);
        if (item.is_null() || item["pid"] != pid || tid && item["tid"] != tid)
            throw std::runtime_error("The selected window no longer exists. Refresh the view.");
        for (const auto& [field, label] : std::vector<std::pair<const char*, const char*>>{
            {"window", "Handle"}, {"title", "Caption"}, {"class", "Class"}, {"pid", "Process ID"},
            {"tid", "Thread ID"}, {"parent", "Parent"}, {"owner", "Owner"}})
            add(label, item[field].is_string() ? item[field].get<std::string>() : item[field].dump());
        wchar_t title[2048]{};
        DWORD_PTR length = 0;
        if (SendMessageTimeoutW(window, WM_GETTEXT, std::size(title), reinterpret_cast<LPARAM>(title),
                SMTO_ABORTIFHUNG | SMTO_BLOCK | SMTO_ERRORONEXIT, MessageTextTimeoutMs, &length))
            add("Text", Utf8(title));
        else add("Text", "Unavailable (window is busy or access is denied)");
        const auto style = item["style"].get<DWORD>();
        const auto extended = item["extendedStyle"].get<DWORD>();
        auto flags = [](DWORD value, const std::vector<std::pair<DWORD, const char*>>& names)
        {
            auto text = Hex(value);
            for (const auto& [bit, name] : names) if (value & bit) text += std::string(" · ") + name;
            return text;
        };
        add("Style", flags(style, {{WS_POPUP, "WS_POPUP"}, {WS_CHILD, "WS_CHILD"}, {WS_VISIBLE, "WS_VISIBLE"},
            {WS_DISABLED, "WS_DISABLED"}, {WS_MINIMIZE, "WS_MINIMIZE"}, {WS_MAXIMIZE, "WS_MAXIMIZE"},
            {WS_CLIPSIBLINGS, "WS_CLIPSIBLINGS"}, {WS_CLIPCHILDREN, "WS_CLIPCHILDREN"},
            {WS_BORDER, "WS_BORDER"}, {WS_DLGFRAME, "WS_DLGFRAME"}, {WS_VSCROLL, "WS_VSCROLL"},
            {WS_HSCROLL, "WS_HSCROLL"}, {WS_SYSMENU, "WS_SYSMENU"}, {WS_THICKFRAME, "WS_THICKFRAME"},
            {WS_GROUP, style & WS_CHILD ? "WS_GROUP" : "WS_MINIMIZEBOX"},
            {WS_TABSTOP, style & WS_CHILD ? "WS_TABSTOP" : "WS_MAXIMIZEBOX"}}));
        add("Extended style", flags(extended, {{WS_EX_DLGMODALFRAME, "WS_EX_DLGMODALFRAME"},
            {WS_EX_TOPMOST, "WS_EX_TOPMOST"}, {WS_EX_ACCEPTFILES, "WS_EX_ACCEPTFILES"},
            {WS_EX_TRANSPARENT, "WS_EX_TRANSPARENT"}, {WS_EX_TOOLWINDOW, "WS_EX_TOOLWINDOW"},
            {WS_EX_WINDOWEDGE, "WS_EX_WINDOWEDGE"}, {WS_EX_CLIENTEDGE, "WS_EX_CLIENTEDGE"},
            {WS_EX_CONTEXTHELP, "WS_EX_CONTEXTHELP"}, {WS_EX_APPWINDOW, "WS_EX_APPWINDOW"},
            {WS_EX_LAYERED, "WS_EX_LAYERED"}, {WS_EX_LAYOUTRTL, "WS_EX_LAYOUTRTL"},
            {WS_EX_COMPOSITED, "WS_EX_COMPOSITED"}, {WS_EX_NOACTIVATE, "WS_EX_NOACTIVATE"}}));
        add("Rectangle (screen pixels)", item["left"].dump() + ", " + item["top"].dump() + " — " +
            item["right"].dump() + ", " + item["bottom"].dump());
        add("Client size", item["clientWidth"].dump() + " × " + item["clientHeight"].dump());
        add("Visible", IsWindowVisible(window) ? "Yes" : "No");
        add("Enabled", IsWindowEnabled(window) ? "Yes" : "No");
        add("Unicode", IsWindowUnicode(window) ? "Yes" : "No");
        number("DPI", GetDpiForWindow(window));
        add("Control ID", Hex(static_cast<uintptr_t>(GetWindowLongPtrW(window, GWLP_ID))));
        add("Instance", Hex(GetWindowLongPtrW(window, GWLP_HINSTANCE)));
        add("Class style", Hex(GetClassLongPtrW(window, GCL_STYLE)));
        number("Class extra bytes", GetClassLongW(window, GCL_CBCLSEXTRA));
        number("Window extra bytes", GetClassLongW(window, GCL_CBWNDEXTRA));
        add("Class atom", Hex(GetClassLongPtrW(window, GCW_ATOM)));
        return properties;
    }
    if (tid)
    {
        Handle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid));
        Check(static_cast<bool>(thread), "Read thread properties");
        if (GetProcessIdOfThread(thread.get()) != pid)
            throw std::runtime_error("The selected thread no longer belongs to this process.");
        number("Thread ID", tid);
        number("Process ID", pid);
        PWSTR description = nullptr;
        if (SUCCEEDED(GetThreadDescription(thread.get(), &description)))
        {
            add("Description", Utf8(description));
            LocalFree(description);
        }
        auto priority = GetThreadPriority(thread.get());
        if (priority != THREAD_PRIORITY_ERROR_RETURN) add("Priority", std::to_string(priority));
        FILETIME created{}, ended{}, kernel{}, user{};
        if (GetThreadTimes(thread.get(), &created, &ended, &kernel, &user)) times(created, kernel, user);
        return properties;
    }
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    Check(static_cast<bool>(process), "Read process properties");
    number("Process ID", pid);
    wchar_t path[ExtendedPathCapacity];
    DWORD length = static_cast<DWORD>(std::size(path));
    if (QueryFullProcessImageNameW(process.get(), 0, path, &length)) add("Image", Utf8({path, length}));
    if (auto machine = ProcessMachine(process.get()))
    {
        add("Architecture", machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" :
            machine == IMAGE_FILE_MACHINE_I386 ? "x86" : "Other");
    }
    number("Priority class", GetPriorityClass(process.get()));
    DWORD handles = 0;
    if (GetProcessHandleCount(process.get(), &handles)) number("Handles", handles);
    number("USER objects", GetGuiResources(process.get(), GR_USEROBJECTS));
    number("GDI objects", GetGuiResources(process.get(), GR_GDIOBJECTS));
    FILETIME created{}, ended{}, kernel{}, user{};
    if (GetProcessTimes(process.get(), &created, &ended, &kernel, &user)) times(created, kernel, user);
    PROCESS_MEMORY_COUNTERS memory{sizeof(memory)};
    if (GetProcessMemoryInfo(process.get(), &memory, sizeof(memory)))
    {
        number("Working set (bytes)", memory.WorkingSetSize);
        number("Peak working set (bytes)", memory.PeakWorkingSetSize);
        number("Page faults", memory.PageFaultCount);
    }
    return properties;
}

Json SpyPick()
{
    // Descend from the root so disabled child controls can also be found by pointing at them.
    POINT screen;
    if (!GetCursorPos(&screen)) return nullptr;
    auto window = GetAncestor(WindowFromPoint(screen), GA_ROOT);
    for (int depth = 0; window && depth < MaxPickDepth; ++depth)
    {
        auto point = screen;
        ScreenToClient(window, &point);
        auto child = ChildWindowFromPointEx(window, point, CWP_SKIPINVISIBLE | CWP_SKIPTRANSPARENT);
        if (!child || child == window) break;
        window = child;
    }
    return SpyWindowInfo(window);
}

WindowSpy::~WindowSpy()
{
    Stop();
    if (module_) FreeLibrary(module_);
}

void WindowSpy::Start(DWORD pid, DWORD tid, HWND window, bool children)
{
    if (buffer_) throw std::runtime_error("Stop message logging before selecting another target.");
    if (!pid || pid == GetCurrentProcessId()) throw std::runtime_error("Choose an application process.");
    try
    {
        // Hold the process identity and a per-process lease for the entire logging session.
        process_.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
        Check(static_cast<bool>(process_), "Open message target");
        auto target = ProcessMachine(process_.get());
        Check(target != IMAGE_FILE_MACHINE_UNKNOWN, "Read target architecture");
        auto current = ProcessMachine(GetCurrentProcess());
        Check(current != IMAGE_FILE_MACHINE_UNKNOWN, "Read collector architecture");
        if (current != target) throw std::runtime_error("Use the collector matching the target architecture.");
        if (window)
        {
            DWORD owner = 0;
            const auto thread = GetWindowThreadProcessId(window, &owner);
            if (!thread || owner != pid || tid && thread != tid)
                throw std::runtime_error("The selected window no longer belongs to this target.");
            if (!children) tid = thread;
        }
        wchar_t name[SpyObjectNameCapacity];
        SpyName(name, pid, L"owner");
        owner_.reset(CreateMutexW(nullptr, FALSE, name));
        Check(static_cast<bool>(owner_), "Reserve message target");
        const auto acquired = WaitForSingleObject(owner_.get(), 0);
        if (acquired != WAIT_OBJECT_0 && acquired != WAIT_ABANDONED)
            throw std::runtime_error("Another Window Spy is already logging this process.");
        SpyName(name, pid, L"buffer");
        mapping_.reset(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(SpyBuffer), name));
        Check(static_cast<bool>(mapping_), "Create message buffer");
        buffer_ = static_cast<SpyBuffer*>(MapViewOfFile(mapping_.get(), FILE_MAP_READ | FILE_MAP_WRITE,
            0, 0, sizeof(SpyBuffer)));
        Check(buffer_ != nullptr, "Map message buffer");
        const auto deadline = GetTickCount64() + SpyBufferLockTimeoutMs;
        while (InterlockedCompareExchange(&buffer_->lock, 1, 0))
        {
            if (GetTickCount64() >= deadline) throw std::runtime_error("The message buffer is busy. Try again.");
            Sleep(1);
        }
        buffer_->signature = SpySignature;
        buffer_->read = buffer_->write = 0;
        buffer_->dropped = 0;
        buffer_->window = reinterpret_cast<uintptr_t>(window);
        buffer_->children = children;
        buffer_->finished = 0;
        InterlockedExchange(&buffer_->active, 1);
        InterlockedExchange(&buffer_->lock, 0);
        if (!module_)
        {
            const auto path = ModuleDirectory() +
                (sizeof(void*) == 4 ? L"\\DetouristSpy32.dll" : L"\\DetouristSpy64.dll");
            module_ = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                LOAD_LIBRARY_SEARCH_SYSTEM32);
            Check(module_ != nullptr, "Load message hooks");
        }
        pid_ = pid;
        tid_ = tid;
        LARGE_INTEGER clock, frequency;
        QueryPerformanceCounter(&clock);
        QueryPerformanceFrequency(&frequency);
        started_ = clock.QuadPart;
        frequency_ = frequency.QuadPart;
        RefreshThreads();
        if (threads_.empty())
            throw std::runtime_error("Cannot install message hooks: " + Utf8(ErrorText(hookError_ ?
                hookError_ : ERROR_INVALID_THREAD_ID)));
    }
    catch (...)
    {
        Stop();
        throw;
    }
}

void WindowSpy::RefreshThreads()
{
    // New GUI threads are picked up on each refresh; terminated thread identities are never reused.
    for (auto item = threads_.begin(); item != threads_.end();)
    {
        if (WaitForSingleObject(item->second.thread.get(), 0) == WAIT_OBJECT_0)
            item = threads_.erase(item);
        else ++item;
    }
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    Check(static_cast<bool>(snapshot), "Refresh message threads");
    THREADENTRY32 entry{sizeof(entry)};
    hookError_ = 0;
    if (Thread32First(snapshot.get(), &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID != pid_ || tid_ && entry.th32ThreadID != tid_ ||
                threads_.contains(entry.th32ThreadID)) continue;
            GUITHREADINFO gui{sizeof(gui)};
            if (!GetGUIThreadInfo(entry.th32ThreadID, &gui))
            {
                const auto error = GetLastError();
                if (error != ERROR_INVALID_PARAMETER && error != ERROR_INVALID_THREAD_ID) hookError_ = error;
                continue;
            }
            ThreadHooks item;
            item.thread.reset(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
                entry.th32ThreadID));
            if (!item.thread || GetProcessIdOfThread(item.thread.get()) != pid_) continue;
            const int kinds[]{WH_CALLWNDPROC, WH_CALLWNDPROCRET, WH_GETMESSAGE};
            const char* names[]{"SpySent", "SpyReturned", "SpyPosted"};
            for (size_t index = 0; index < item.hooks.size(); ++index)
            {
                auto procedure = reinterpret_cast<HOOKPROC>(GetProcAddress(module_, names[index]));
                if (procedure) item.hooks[index].reset(SetWindowsHookExW(kinds[index], procedure, module_,
                    entry.th32ThreadID));
                if (!item.hooks[index]) { hookError_ = GetLastError(); break; }
            }
            if (std::all_of(item.hooks.begin(), item.hooks.end(), [](const auto& hook) { return hook != nullptr; }))
                threads_.emplace(entry.th32ThreadID, std::move(item));
        } while (Thread32Next(snapshot.get(), &entry));
    }
    // shortcut: new threads are sampled each second; use desktop hooks when their first messages are required.
    refresh_ = GetTickCount64() + SpyThreadRefreshMs;
}

Json WindowSpy::Poll(bool stop)
{
    if (!buffer_) throw std::runtime_error("No message log is active.");
    if (stop)
    {
        InterlockedExchange(&buffer_->active, 0);
        threads_.clear();
    }

    // Check window lifetime even when its final hook notification was dropped.
    const auto window = reinterpret_cast<HWND>(static_cast<uintptr_t>(buffer_->window));
    DWORD owner = 0;
    auto running = !stop && !InterlockedCompareExchange(&buffer_->finished, 0, 0) &&
        WaitForSingleObject(process_.get(), 0) == WAIT_TIMEOUT &&
        (!window || GetWindowThreadProcessId(window, &owner) && owner == pid_);
    if (running && GetTickCount64() >= refresh_) RefreshThreads();
    if (tid_ && threads_.empty()) running = false;

    // Copy under a short try-lock, then format outside the shared buffer to keep target callbacks bounded.
    std::vector<SpyMessage> messages;
    messages.reserve(SpyCapacity);
    auto locked = !InterlockedCompareExchange(&buffer_->lock, 1, 0);
    const auto deadline = GetTickCount64() + SpyStopLockTimeoutMs;
    while (!running && !locked && GetTickCount64() < deadline)
    {
        Sleep(1);
        locked = !InterlockedCompareExchange(&buffer_->lock, 1, 0);
    }
    if (locked)
    {
        const auto count = std::min(buffer_->write - buffer_->read, SpyCapacity);
        for (uint32_t index = 0; index < count; ++index)
            messages.push_back(buffer_->messages[(buffer_->read + index) % SpyCapacity]);
        buffer_->read = buffer_->write;
        InterlockedExchange(&buffer_->lock, 0);
    }
    auto items = Json::array();
    for (const auto& message : messages)
    {
        if (message.kind > static_cast<uint32_t>(SpyMessageKind::PostedPeeked)) continue;
        auto name = std::wstring(message.className, wcsnlen_s(message.className, std::size(message.className)));
        wchar_t registered[256]{};
        if (message.message >= RegisteredMessageFirst && message.message <= RegisteredMessageLast)
            GetClipboardFormatNameW(message.message, registered, static_cast<int>(std::size(registered)));
        items.push_back({{"time", (static_cast<double>(message.clock) - started_) / frequency_},
            {"window", Hex(message.window)}, {"tid", message.thread}, {"message", message.message},
            {"class", Utf8(name)}, {"registered", Utf8(registered)},
            {"kind", message.kind}, {"wparam", Hex(message.wparam)}, {"lparam", Hex(message.lparam)},
            {"result", Hex(message.result)}});
    }
    const auto warning = !running && !locked ? "Some buffered messages could not be read while stopping." :
        hookError_ ? "Some threads could not be hooked: " + Utf8(ErrorText(hookError_)) : "";
    auto result = Json{{"messages", std::move(items)}, {"running", running}, {"threads", threads_.size()},
        {"dropped", static_cast<uint32_t>(InterlockedCompareExchange(&buffer_->dropped, 0, 0))},
        {"warning", warning}};
    if (!running) Stop();
    return result;
}

void WindowSpy::Stop()
{
    // Disable recording before unhooking; closing the collector pipe also takes this path.
    if (buffer_) InterlockedExchange(&buffer_->active, 0);
    threads_.clear();
    if (buffer_) UnmapViewOfFile(buffer_);
    buffer_ = nullptr;
    mapping_.reset();
    if (owner_) ReleaseMutex(owner_.get());
    owner_.reset();
    process_.reset();
}
}

#include <windows.h>
#include <atomic>
#include <iostream>

HWND MainWindow = nullptr;
HWND ChildWindow = nullptr;
std::atomic<HWND> WorkerWindow = nullptr;
HANDLE Worker = nullptr;
HANDLE Ready = nullptr;
DWORD WorkerId = 0;

DWORD WINAPI WorkerMain(void*)
{
    // A second GUI thread exercises hooks installed after the initial process snapshot.
    WorkerWindow = CreateWindowExW(0, L"DetouristSpyFixture", L"Worker window", WS_OVERLAPPED,
        0, 0, 10, 10, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    SetEvent(Ready);
    MSG message;
    while (GetMessageW(&message, nullptr, 0, 0) > 0) DispatchMessageW(&message);
    DestroyWindow(WorkerWindow);
    return 0;
}

LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM first, LPARAM second)
{
    // The target handles both synchronous and queued traffic without depending on the collector.
    switch (message)
    {
    case WM_APP + 1:
        return static_cast<LRESULT>(first ^ static_cast<uintptr_t>(second));
    case WM_APP + 2:
        SendMessageW(ChildWindow, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(L"Changed child"));
        return reinterpret_cast<LRESULT>(ChildWindow);
    case WM_APP + 3:
        if (!Worker)
        {
            Ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            Worker = CreateThread(nullptr, 0, WorkerMain, nullptr, 0, &WorkerId);
            WaitForSingleObject(Ready, 3000);
        }
        return reinterpret_cast<LRESULT>(WorkerWindow.load());
    case WM_APP + 5:
        for (int index = 0; index < 20000; ++index) SendMessageW(window, WM_APP + 1, index, index + 1);
        return 0;
    case WM_APP + 6:
        Sleep(1500);
        return 0;
    case WM_APP + 7:
        DestroyWindow(ChildWindow);
        ChildWindow = nullptr;
        return 0;
    case WM_DESTROY:
        if (window == MainWindow) PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, first, second);
}

int main()
{
    // Hidden real HWNDs make the integration fixture independent of the user's foreground application.
    SetProcessDPIAware();
    WNDCLASSW type{};
    type.lpfnWndProc = WindowProcedure;
    type.hInstance = GetModuleHandleW(nullptr);
    type.lpszClassName = L"DetouristSpyFixture";
    if (!RegisterClassW(&type)) return 1;
    MainWindow = CreateWindowExW(0, type.lpszClassName, L"Detourist Window Spy test", WS_OVERLAPPEDWINDOW,
        80, 80, 420, 240, nullptr, nullptr, type.hInstance, nullptr);
    ChildWindow = CreateWindowExW(0, L"EDIT", L"Spy child", WS_CHILD | WS_VISIBLE | WS_DISABLED,
        10, 10, 200, 30, MainWindow, reinterpret_cast<HMENU>(42), type.hInstance, nullptr);
    if (!MainWindow || !ChildWindow) return 2;
    std::cout << "{\"pid\":" << GetCurrentProcessId() << ",\"tid\":" << GetCurrentThreadId() <<
        ",\"window\":\"0x" << std::hex << reinterpret_cast<uintptr_t>(MainWindow) <<
        "\",\"child\":\"0x" << reinterpret_cast<uintptr_t>(ChildWindow) << "\",\"bits\":" <<
        std::dec << sizeof(void*) * 8 << "}" << std::endl;
    MSG message;
    while (true)
    {
        PeekMessageW(&message, nullptr, 0, 0, PM_NOREMOVE);
        if (GetMessageW(&message, nullptr, 0, 0) <= 0) break;
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    if (Worker)
    {
        PostThreadMessageW(WorkerId, WM_QUIT, 0, 0);
        WaitForSingleObject(Worker, 3000);
        CloseHandle(Worker);
        CloseHandle(Ready);
    }
    return 0;
}

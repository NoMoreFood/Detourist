#include <windows.h>

extern "C" __declspec(dllexport) BOOL WINAPI ModuleLifetimeCall(HANDLE file)
{
    // The captured API's caller must belong to this image's current lifetime.
    const char message[] = DETOURIST_MODULE_MESSAGE;
    DWORD written = 0;
    return WriteFile(file, message, sizeof(message) - 1, &written, nullptr) && written == sizeof(message) - 1;
}

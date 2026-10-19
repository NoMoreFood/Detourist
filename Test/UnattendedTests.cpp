#include <windows.h>
#include <crtdbg.h>
#include <cstdlib>

namespace Detourist::Tests
{
int __cdecl FatalCrtReport(int kind, char* message, int*)
{
    // Format fixtures explicitly disable reports while exercising invalid inputs.
    if ((kind != _CRT_ASSERT && kind != _CRT_ERROR) || _CrtSetReportMode(kind, _CRTDBG_REPORT_MODE) == 0)
        return FALSE;

    // Avoid CRT calls while reporting a failure inside the CRT itself.
    DWORD bytes = 0, written = 0;
    while (message[bytes]) ++bytes;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), message, bytes, &written, nullptr);
    TerminateProcess(GetCurrentProcess(), ERROR_ASSERTION_FAILURE);
    return TRUE;
}

struct UnattendedReporting
{
    UnattendedReporting()
    {
        auto error = GetLastError();
        wchar_t enabled[2]{};
        size_t count = 0;
        auto active = _wgetenv_s(&count, enabled, 2, L"DETOURIST_TEST_UNATTENDED") == 0 &&
            count == 2 && enabled[0] == L'1';
        if (active)
        {
            // Each statically linked CRT owns its own reporting state.
            SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
            _set_error_mode(_OUT_TO_STDERR);
            _set_abort_behavior(0, _CALL_REPORTFAULT);
            for (int kind = _CRT_WARN; kind <= _CRT_ASSERT; ++kind)
            {
                _CrtSetReportMode(kind, _CRTDBG_MODE_FILE);
                _CrtSetReportFile(kind, _CRTDBG_FILE_STDERR);
            }
            _CrtSetReportHook(FatalCrtReport);
        }
        SetLastError(error);
    }
};
UnattendedReporting UnattendedReports;
}

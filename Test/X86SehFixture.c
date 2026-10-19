#include <windows.h>

int (__cdecl* DetouristAbnormalTermination)(void);
void* DetouristExceptHandler3;

__declspec(naked) void __cdecl _except_handler3(void)
{
    __asm jmp dword ptr [DetouristExceptHandler3]
}

int DetouristSehProbe(int abnormal)
{
    int result = -1;

    // Compiler-generated SEH3 frames exercise both normal completion and exception unwinding.
    __try
    {
        __try
        {
            if (abnormal) RaiseException(0xe0123456, 0, 0, NULL);
        }
        __finally
        {
            result = DetouristAbnormalTermination();
        }
    }
    __except (GetExceptionCode() == 0xe0123456 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
    }
    return result;
}

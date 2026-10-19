#pragma once

namespace Detourist
{
struct X86FloatingState
{
#ifndef _WIN64
    static constexpr size_t FxsaveBufferBytes = 512;
    alignas(16) byte state[FxsaveBufferBytes];
    X86FloatingState() { proc_save_fpstate(state); }
    ~X86FloatingState() { proc_restore_fpstate(state); }

    uint64_t Read(uint32_t bytes)
    {
        uint64_t value = 0;
        auto saved = state;
        __asm
        {
            mov eax, saved
            fninit
            fld TBYTE PTR [eax+32]
        }
        if (bytes == 4) __asm fstp DWORD PTR value
        else __asm fstp QWORD PTR value
        return value;
    }

    void Write(uint64_t value, uint32_t bytes, bool push = false)
    {
        proc_restore_fpstate(state);
        if (!push) __asm fstp ST(0)
        if (bytes == 4) __asm fld DWORD PTR value
        else __asm fld QWORD PTR value
        proc_save_fpstate(state);
    }
#endif
};
}

#pragma once
#include <cstdint>
#include <cstddef>

namespace Detourist
{
// Integer and pointer arguments use normalized prefix values followed by the untouched native tail.
extern "C" uint64_t InvokeIntegerArguments(void* function, const uint64_t* prefix, size_t prefixCount,
    const uint64_t* tail, size_t tailCount);

struct NativeCallResult
{
    uint64_t integer, floating;
};

// Slots contain Win64 register positions or x86 DWORD stack entries, including hidden return buffers.
extern "C" void InvokeNativeArguments(void* function, const uint64_t* arguments, size_t count,
    NativeCallResult* result, uint32_t floatingBytes = 0, const uint32_t* registers = nullptr);
}

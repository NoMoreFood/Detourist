#include "InvokeArguments.h"
#include <windows.h>
#include <bit>
#include <cstdio>
#include <cstdarg>
#include <initializer_list>
#include <cstring>

using namespace Detourist;

struct EntryFrame
{
    const uint32_t* stack;
    NativeCallResult result;
    uint32_t cleanup, floatingBytes;
    uint32_t integer[2];
};
struct EntryDescriptor { void* bypass; bool callerCleans, floating, fastcall = false; };
extern "C" void ExportHookEntry();
extern "C" void AsyncCallbackGateway();

extern "C" void* DispatchExportHook(const EntryDescriptor* descriptor, EntryFrame* frame)
{
    if (descriptor->bypass) return descriptor->bypass;
    if (descriptor->fastcall)
    {
        frame->cleanup = 8;
        frame->floatingBytes = 0;
        frame->result.integer = frame->integer[0] ^ (uint64_t{frame->integer[1]} << 32) ^
            frame->stack[1] ^ (uint64_t{frame->stack[2]} << 32);
        return nullptr;
    }
    frame->cleanup = descriptor->callerCleans ? 0 : 16;
    frame->floatingBytes = descriptor->floating ? 8 : 0;
    if (descriptor->floating) frame->result.floating = std::bit_cast<uint64_t>(-5.25);
    else frame->result.integer = ((uint64_t{frame->stack[3]} << 32) | frame->stack[2]) ^
        (uint64_t{frame->stack[1]} << 32) ^ frame->stack[4];
    return nullptr;
}

struct CallbackDescriptor
{
    uint64_t identity, original;
    void* next;
    uint32_t kind;
};
static_assert(offsetof(CallbackDescriptor, kind) == 20);
uint64_t CallbackObserved = 0;
uint32_t CallbackFourth = 0;

extern "C" void AsyncCallbackDispatch(uint64_t first, uint64_t second, uint64_t third, uint64_t fourth,
    const CallbackDescriptor* descriptor)
{
    CallbackObserved = first ^ (second << 16) ^ (third << 32);
    CallbackFourth = static_cast<uint32_t>(fourth);
    if (descriptor->kind == 3)
        reinterpret_cast<void (WINAPI*)(DWORD, DWORD, DWORD, DWORD)>(descriptor->original)(
            static_cast<DWORD>(first), static_cast<DWORD>(second), static_cast<DWORD>(third),
            static_cast<DWORD>(fourth));
}

void WINAPI Callback(DWORD first, DWORD second, DWORD third, DWORD fourth)
{
    CallbackObserved ^= uint64_t{first} | (uint64_t{second} << 16) | (uint64_t{third} << 32);
    CallbackFourth ^= fourth;
}

void* Thunk(void* entry, void* descriptor)
{
    auto memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!memory) return nullptr;
    const unsigned char code[]{0xB8, 0, 0, 0, 0, 0xE9, 0, 0, 0, 0};
    memcpy(memory, code, sizeof(code));
    memcpy(memory + 1, &descriptor, sizeof(descriptor));
    const auto displacement = reinterpret_cast<uintptr_t>(entry) - reinterpret_cast<uintptr_t>(memory + 10);
    memcpy(memory + 6, &displacement, sizeof(displacement));
    DWORD previous = 0;
    if (!VirtualProtect(memory, 32, PAGE_EXECUTE_READ, &previous) ||
        !FlushInstructionCache(GetCurrentProcess(), memory, 32))
    {
        VirtualFree(memory, 0, MEM_RELEASE);
        return nullptr;
    }
    return memory;
}

__declspec(noinline) uint64_t __stdcall Standard(uint32_t first, uint64_t second, uint32_t third)
{
    return second ^ (uint64_t{first} << 32) ^ third;
}

__declspec(noinline) uint64_t __cdecl Cdecl(uint32_t first, uint64_t second, uint32_t third)
{
    return Standard(first, second, third);
}

__declspec(noinline) uint64_t __fastcall Fastcall(uint32_t first, uint32_t second, uint32_t third, uint32_t fourth)
{
    return first ^ (uint64_t{second} << 32) ^ third ^ (uint64_t{fourth} << 32);
}

__declspec(noinline) double __cdecl Floating(double first, uint32_t second, double third)
{
    return first + second + third;
}

__declspec(noinline) float __stdcall Single(float first, uint32_t second)
{
    return first + static_cast<float>(second);
}

__declspec(noinline) uint32_t __cdecl Variable(uint32_t count, ...)
{
    va_list values;
    va_start(values, count);
    uint32_t sum = 0;
    for (uint32_t index = 0; index < count; ++index) sum += va_arg(values, uint32_t);
    va_end(values);
    return sum;
}

int main()
{
    EntryDescriptor entry{};
    auto observer = Thunk(reinterpret_cast<void*>(&ExportHookEntry), &entry);
    CallbackDescriptor callback{0, reinterpret_cast<uint64_t>(&Callback), nullptr, 1};
    auto gateway = Thunk(reinterpret_cast<void*>(&AsyncCallbackGateway), &callback);
    if (!observer || !gateway) return 5;

    // Repeated mixed-width calls expose both incorrect stack cleanup and lost high DWORDs.
    for (uint32_t iteration = 0; iteration < 1000; ++iteration)
    {
        uint64_t arguments[]{0x1234, 0x76543210, 0xFEDCBA98, 0x5678};
        NativeCallResult result{};
        for (auto function : {reinterpret_cast<void*>(&Standard), reinterpret_cast<void*>(&Cdecl)})
        {
            InvokeNativeArguments(function, arguments, 4, &result);
            if (result.integer != Standard(0x1234, 0xFEDCBA9876543210, 0x5678)) return 1;
        }
        const auto first = std::bit_cast<uint64_t>(3.25), third = std::bit_cast<uint64_t>(-17.5);
        uint64_t floating[]{static_cast<uint32_t>(first), first >> 32, 9,
            static_cast<uint32_t>(third), third >> 32};
        InvokeNativeArguments(reinterpret_cast<void*>(&Floating), floating, 5, &result, 8);
        if (std::bit_cast<double>(result.floating) != -5.25) return 2;
        uint64_t single[]{std::bit_cast<uint32_t>(2.5f), 4};
        InvokeNativeArguments(reinterpret_cast<void*>(&Single), single, 2, &result, 4);
        if (std::bit_cast<float>(static_cast<uint32_t>(result.floating)) != 6.5f) return 3;
        uint64_t prefix[]{6, 11, 22};
        uint32_t tail[]{33, 44, 55, 66};
        if (static_cast<uint32_t>(InvokeIntegerArguments(reinterpret_cast<void*>(&Variable), prefix, 3,
            reinterpret_cast<const uint64_t*>(tail), 4)) != 231) return 4;

        // Export entries preserve bypassed arguments and use the callee's own cleanup convention.
        for (bool bypass : {false, true})
        {
            entry = {bypass ? reinterpret_cast<void*>(&Standard) : nullptr, false, false};
            if (reinterpret_cast<decltype(&Standard)>(observer)(0x1234, 0xFEDCBA9876543210, 0x5678) !=
                Standard(0x1234, 0xFEDCBA9876543210, 0x5678)) return 6;
            entry = {bypass ? reinterpret_cast<void*>(&Cdecl) : nullptr, true, false};
            if (reinterpret_cast<decltype(&Cdecl)>(observer)(0x1234, 0xFEDCBA9876543210, 0x5678) !=
                Standard(0x1234, 0xFEDCBA9876543210, 0x5678)) return 7;
            entry = {bypass ? reinterpret_cast<void*>(&Fastcall) : nullptr, false, false, true};
            if (reinterpret_cast<decltype(&Fastcall)>(observer)(0x1234, 0xfedcba98, 0x5678, 0x76543210) !=
                Fastcall(0x1234, 0xfedcba98, 0x5678, 0x76543210)) return 10;
        }
        uint32_t registers[]{0x1234, 0xfedcba98};
        uint64_t stack[]{0x5678, 0x76543210};
        InvokeNativeArguments(reinterpret_cast<void*>(&Fastcall), stack, 2, &result, 0, registers);
        if (result.integer != Fastcall(0x1234, 0xfedcba98, 0x5678, 0x76543210)) return 11;
        entry = {nullptr, true, true};
        if (reinterpret_cast<decltype(&Floating)>(observer)(3.25, 9, -17.5) != -5.25) return 8;
        for (uint32_t kind : {1u, 2u, 3u})
        {
            callback.kind = kind;
            if (kind == 3) reinterpret_cast<decltype(&Callback)>(gateway)(7, 9, 11, 13);
            else reinterpret_cast<void (WINAPI*)(DWORD, DWORD, DWORD)>(gateway)(7, 9, 11);
            if (CallbackObserved != (kind == 3 ? 0 : uint64_t{7} ^ (uint64_t{9} << 16) ^ (uint64_t{11} << 32)) ||
                CallbackFourth) return 9;
        }
    }
    VirtualFree(observer, 0, MEM_RELEASE);
    VirtualFree(gateway, 0, MEM_RELEASE);
    std::puts("PASS: x86 call and export ABIs, x87 results, variadic tails and callback gateways.");
    return 0;
}

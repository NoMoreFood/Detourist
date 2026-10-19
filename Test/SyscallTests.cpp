#include "TestSupport.h"

using namespace Detourist::Tests;


using namespace Detourist;

enum class ContextRestoration { Full, Partial, Edits };

std::atomic<uint32_t> SingleStepPhase = 0;
BYTE* SingleStepCode = nullptr;
constexpr DWORD SingleStepResult = 0x19A4B83C;
DWORD64 SingleStepExpectedResult = SingleStepResult;
uint32_t SingleStepKind = 0;
DWORD64 SingleStepAfter = 0;
DWORD64 SingleStepStack = 0;
DWORD64 SingleStepActual = 0;
DWORD64 SingleStepActualStack = 0;
DWORD SingleStepThread = 0;
bool SingleStepWritable = false;
alignas(16) CONTEXT SingleStepOriginal{};
BYTE SingleStepOpcode = 0;

LONG WINAPI ContinueSingleStep(EXCEPTION_POINTERS* exception)
{
    auto code = exception->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT && SingleStepPhase == 0 &&
        exception->ExceptionRecord->ExceptionAddress == SingleStepCode)
    {
        SingleStepPhase = 1;
        if (SingleStepKind >= 10)
        {
            if (SingleStepWritable) *SingleStepCode = SingleStepOpcode;
            else
            {
                DWORD protection = 0, ignored = 0;
                if (!VirtualProtect(SingleStepCode, 1, PAGE_EXECUTE_READWRITE, &protection))
                    return EXCEPTION_CONTINUE_SEARCH;
                *SingleStepCode = SingleStepOpcode;
                if (!VirtualProtect(SingleStepCode, 1, protection, &ignored) ||
                    !FlushInstructionCache(GetCurrentProcess(), SingleStepCode, 1)) return EXCEPTION_CONTINUE_SEARCH;
            }
        }
        else ++exception->ContextRecord->Rip;
        SingleStepStack = exception->ContextRecord->Rsp;
        if (SingleStepKind == 3 || SingleStepKind == 4)
        {
            SingleStepAfter = *reinterpret_cast<const DWORD64*>(SingleStepStack);
            SingleStepStack += sizeof(DWORD64) + (SingleStepKind == 4 ? 16 : 0);
        }
        else if (SingleStepKind == 10)
            SingleStepAfter = reinterpret_cast<DWORD64>(SingleStepCode + 5);
        else if (SingleStepKind >= 13)
            SingleStepAfter = reinterpret_cast<DWORD64>(SingleStepCode + 7);
        else if (SingleStepKind == 8 || SingleStepKind == 9 || SingleStepKind == 11)
        {
            SingleStepAfter = reinterpret_cast<DWORD64>(SingleStepCode +
                (SingleStepKind == 8 || SingleStepKind == 11 ? 2 : 3));
            SingleStepStack -= sizeof(DWORD64);
        }
        else if (SingleStepKind >= 5)
        {
            SingleStepAfter = reinterpret_cast<DWORD64>(SingleStepCode + (SingleStepKind == 5 ? 9 : 3));
            if (SingleStepKind == 5) exception->ContextRecord->EFlags |= 0x40;
            else exception->ContextRecord->EFlags &= ~DWORD{0x40};
        }
        else
        {
            SingleStepAfter = reinterpret_cast<DWORD64>(SingleStepCode +
                (SingleStepKind == 0 ? 6 : SingleStepKind == 1 ? 8 : 16));
            if (SingleStepKind == 2) SingleStepStack -= sizeof(DWORD64);
        }
        exception->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == EXCEPTION_SINGLE_STEP && SingleStepPhase == 1)
    {
        if (SingleStepKind == 7 && GetCurrentThreadId() != SingleStepThread) return EXCEPTION_CONTINUE_SEARCH;
        SingleStepActual = exception->ContextRecord->Rip;
        SingleStepActualStack = exception->ContextRecord->Rsp;
        auto phase = exception->ContextRecord->Rip == SingleStepAfter &&
            exception->ContextRecord->Rsp == SingleStepStack &&
            ((SingleStepKind != 0 && SingleStepKind != 3 && SingleStepKind != 4 && SingleStepKind != 7 &&
                SingleStepKind != 10 && SingleStepKind < 13) ||
                exception->ContextRecord->Rax == SingleStepExpectedResult) ? 2 : 3;
        if (SingleStepKind == 7) *exception->ContextRecord = SingleStepOriginal;
        exception->ContextRecord->EFlags &= ~DWORD{0x100};
        SingleStepPhase = phase;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int ExerciseSingleStep(int iterations, bool writable)
{
    // Resume a breakpoint with the trap flag and preserve the first application instruction's result.
    SingleStepWritable = writable;
    auto code = static_cast<BYTE*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!code) return 26;
    std::array<BYTE, 7> move{0xCC, 0xB8, 0, 0, 0, 0, 0xC3};
    std::array<BYTE, 14> jump{0xCC, 0xEB, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 0, 0, 0, 0, 0xC3};
    std::array<BYTE, 22> call{0xCC, 0xE8, 0x0A, 0, 0, 0, 0xC3, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 0, 0, 0, 0, 0xC3};
    std::array<BYTE, 7> leave{0xB8, 0, 0, 0, 0, 0xCC, 0xC3};
    std::array<BYTE, 9> release{0xB8, 0, 0, 0, 0, 0xCC, 0xC2, 0x10, 0};
    std::array<BYTE, 15> conditional{0xCC, 0x74, 0x06, 0xB8, 0, 0, 0, 0, 0xC3,
        0xB8, 0, 0, 0, 0, 0xC3};
    std::array<BYTE, 10> wrapper{0x48, 0x83, 0xEC, 0x10, 0xE8, 0xD7, 0xFF, 0xFF, 0xFF, 0xC3};
    std::array<BYTE, 9> push{0xCC, 0x55, 0xB8, 0, 0, 0, 0, 0x5D, 0xC3};
    std::array<BYTE, 11> pushExtended{0xCC, 0x41, 0x54, 0xB8, 0, 0, 0, 0, 0x41, 0x5C, 0xC3};
    std::array<BYTE, 9> patchedPush{0x40, 0x53, 0xB8, 0, 0, 0, 0, 0x5B, 0xC3};
    std::array<BYTE, 9> patchedTest{0x48, 0x85, 0xDB, 0xB8, 0, 0, 0, 0, 0xC3};
    std::array<BYTE, 13> patchedAddress{0x48, 0x8D, 0x05, 0xF9, 0xFF, 0xFF, 0xFF,
        0xB8, 0, 0, 0, 0, 0xC3};
    std::array<BYTE, 32> patchedLoad{0x48, 0x8B, 0x05, 0x11, 0, 0, 0, 0xB8, 0, 0, 0, 0, 0xC3};
    constexpr DWORD64 loadedValue = 0x0123456789ABCDEF;
    memcpy(move.data() + 2, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(jump.data() + 9, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(call.data() + 17, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(leave.data() + 1, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(release.data() + 1, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(conditional.data() + 4, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(conditional.data() + 10, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(push.data() + 3, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(pushExtended.data() + 4, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(patchedPush.data() + 3, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(patchedTest.data() + 4, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(patchedAddress.data() + 8, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(patchedLoad.data() + 8, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(patchedLoad.data() + 24, &loadedValue, sizeof(loadedValue));
    memcpy(code, move.data(), move.size());
    memcpy(code + 32, jump.data(), jump.size());
    memcpy(code + 64, call.data(), call.size());
    memcpy(code + 96, leave.data(), leave.size());
    memcpy(code + 128, release.data(), release.size());
    memcpy(code + 160, wrapper.data(), wrapper.size());
    memcpy(code + 192, conditional.data(), conditional.size());
    memcpy(code + 224, conditional.data(), conditional.size());
    memcpy(code + 256, push.data(), push.size());
    memcpy(code + 288, pushExtended.data(), pushExtended.size());
    memcpy(code + 320, move.data() + 1, move.size() - 1);
    memcpy(code + 352, patchedPush.data(), patchedPush.size());
    memcpy(code + 384, patchedTest.data(), patchedTest.size());
    memcpy(code + 416, patchedAddress.data(), patchedAddress.size());
    memcpy(code + 448, patchedLoad.data(), patchedLoad.size());
    DWORD protection = 0;
    if (!VirtualProtect(code, 4096, writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), code, 480))
    {
        VirtualFree(code, 0, MEM_RELEASE);
        return 27;
    }
    auto handler = AddVectoredExceptionHandler(TRUE, ContinueSingleStep);
    if (!handler)
    {
        VirtualFree(code, 0, MEM_RELEASE);
        return 28;
    }
    int result = 0;
    for (int iteration = 0; iteration < iterations; ++iteration)
    {
        for (auto kind : {0u, 1u, 2u, 3u, 4u, 5u, 6u, 8u, 9u, 10u, 11u, 12u, 13u, 14u})
        {
            SingleStepKind = kind;
            auto offset = (kind + (kind >= 5 && kind < 8 ? 1 : 0)) * 32;
            SingleStepCode = code + offset + (kind == 3 || kind == 4 ? 5 : 0);
            SingleStepExpectedResult = kind == 13 ? reinterpret_cast<DWORD64>(SingleStepCode) :
                kind == 14 ? loadedValue : SingleStepResult;
            auto step = reinterpret_cast<DWORD (WINAPI*)()>(code + (kind == 4 ? 160 : offset));
            SingleStepPhase = 0;
            SingleStepActual = SingleStepActualStack = 0;

            // Restore a debugger patch after the original instruction has already executed in the cache.
            if (kind >= 10)
            {
                SingleStepOpcode = *SingleStepCode;
                if (step() != SingleStepResult)
                {
                    result = 49;
                    break;
                }
                if (writable) *SingleStepCode = 0xCC;
                else
                {
                    DWORD patchProtection = 0, ignored = 0;
                    if (!VirtualProtect(SingleStepCode, 1, PAGE_EXECUTE_READWRITE, &patchProtection))
                    {
                        result = 27;
                        break;
                    }
                    *SingleStepCode = 0xCC;
                    if (!VirtualProtect(SingleStepCode, 1, patchProtection, &ignored) ||
                        !FlushInstructionCache(GetCurrentProcess(), SingleStepCode, 1))
                    {
                        result = 27;
                        break;
                    }
                }
            }
            auto value = step();
            if (SingleStepPhase != 2 || value != SingleStepResult)
            {
                std::fprintf(stderr, "Single step failed: instruction=%u phase=%u rip=%llx expected=%llx "
                    "rsp=%llx expected=%llx value=%lx\n", kind, SingleStepPhase.load(), SingleStepActual,
                    SingleStepAfter, SingleStepActualStack, SingleStepStack, value);
                result = 40 + static_cast<int>(kind);
                break;
            }
        }
        if (result) break;
    }
    if (!RemoveVectoredExceptionHandler(handler) || !VirtualFree(code, 0, MEM_RELEASE)) return 30;
    SingleStepCode = nullptr;
    SingleStepWritable = false;
    SingleStepExpectedResult = SingleStepResult;
    return result;
}

int ExerciseThreadSingleStep(int iterations)
{
    // Step an already translated instruction through a context edit on an established worker.
    auto code = static_cast<BYTE*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!code) return 26;
    std::array<BYTE, 6> move{0xB8, 0, 0, 0, 0, 0xC3};
    memcpy(move.data() + 1, &SingleStepResult, sizeof(SingleStepResult));
    memcpy(code, move.data(), move.size());
    DWORD protection = 0;
    if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), code, move.size()))
    {
        VirtualFree(code, 0, MEM_RELEASE);
        return 27;
    }
    auto warm = reinterpret_cast<DWORD (WINAPI*)()>(code);
    if (warm() != SingleStepResult)
    {
        VirtualFree(code, 0, MEM_RELEASE);
        return 47;
    }
    auto handler = AddVectoredExceptionHandler(TRUE, ContinueSingleStep);
    if (!handler)
    {
        VirtualFree(code, 0, MEM_RELEASE);
        return 28;
    }
    std::atomic<uint64_t> progress = 0;
    std::jthread worker([&](std::stop_token stop)
    {
        while (!stop.stop_requested())
        {
            progress.fetch_add(1, std::memory_order_relaxed);
            YieldProcessor();
        }
    });
    SingleStepKind = 7;
    SingleStepThread = GetThreadId(worker.native_handle());
    SingleStepAfter = reinterpret_cast<DWORD64>(code + 5);
    int result = 0;
    auto deadline = GetTickCount64() + 5000;
    while (!progress.load() && GetTickCount64() < deadline) Sleep(1);
    if (!progress.load()) result = 23;
    for (int iteration = 0; iteration < iterations && !result; ++iteration)
    {
        auto thread = worker.native_handle();
        if (SuspendThread(thread) == MAXDWORD)
        {
            result = 17;
            break;
        }
        SingleStepOriginal = {};
        SingleStepOriginal.ContextFlags = CONTEXT_FULL;
        auto read = GetThreadContext(thread, &SingleStepOriginal);
        auto previousProgress = progress.load();
        auto context = SingleStepOriginal;
        context.Rip = reinterpret_cast<DWORD64>(code);
        context.Rax = 0;
        context.EFlags |= 0x100;
        SingleStepStack = context.Rsp;
        SingleStepActual = SingleStepActualStack = 0;
        SingleStepPhase = 1;
        auto restored = read && SetThreadContext(thread, &context);
        auto resumed = ResumeThread(thread);
        if (!restored || resumed == MAXDWORD)
        {
            result = 18;
            break;
        }
        deadline = GetTickCount64() + 5000;

        // Let exception dispatch release its locks before suspending the worker for another step.
        while ((SingleStepPhase == 1 || (SingleStepPhase == 2 && progress == previousProgress)) &&
            GetTickCount64() < deadline) Sleep(1);
        if (SingleStepPhase != 2 || progress == previousProgress)
        {
            std::fprintf(stderr, "Thread single step failed: phase=%u rip=%llx expected=%llx "
                "rsp=%llx expected=%llx\n", SingleStepPhase.load(), SingleStepActual, SingleStepAfter,
                SingleStepActualStack, SingleStepStack);
            result = 48;
        }
    }
    worker.request_stop();
    worker.join();
    SingleStepThread = 0;
    if (!RemoveVectoredExceptionHandler(handler) || !VirtualFree(code, 0, MEM_RELEASE)) return 30;
    return result;
}

int ExerciseThreadContexts(int iterations, ContextRestoration mode)
{
    // Recompile a translated code page while an application context edit is pending.
    auto releaseCode = [](BYTE* memory)
    {
        if (memory) VirtualFree(memory, 0, MEM_RELEASE);
    };
    std::unique_ptr<BYTE, decltype(releaseCode)> code(mode == ContextRestoration::Edits ?
        static_cast<BYTE*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) : nullptr,
        releaseCode);
    if (mode == ContextRestoration::Edits)
    {
        DWORD previous = 0;
        if (!code) return 26;
        code.get()[0] = 0xC3;
        if (!VirtualProtect(code.get(), 4096, PAGE_EXECUTE_READ, &previous) ||
            !FlushInstructionCache(GetCurrentProcess(), code.get(), 1)) return 27;
    }

    // Preserve running workers' integer and floating-point state through context restoration.
    std::atomic<uint64_t> progress[2]{};
    std::atomic<int> failure = 0;
    std::vector<std::jthread> workers;
    for (size_t index = 0; index < std::size(progress); ++index)
    {
        workers.emplace_back([&, index](std::stop_token stop)
        {
            double value = 0;
            while (!stop.stop_requested())
            {
                value += 1.25;
                auto count = progress[index].fetch_add(1, std::memory_order_relaxed) + 1;
                if (value != count * 1.25) failure = 16;
                Sleep(0);
            }
        });
    }

    // Exercise established workers after their CRT and loader initialization has completed.
    auto readyBy = GetTickCount64() + 5000;
    while ((!progress[0].load() || !progress[1].load()) && GetTickCount64() < readyBy) Sleep(1);
    if (!progress[0].load() || !progress[1].load()) return 23;
    for (int iteration = 0; iteration < iterations && !failure; ++iteration)
    {
        for (auto& worker : workers)
        {
            auto thread = worker.native_handle();
            if (SuspendThread(thread) == MAXDWORD) return 17;
            struct alignas(16) ContextBuffer
            {
                CONTEXT context{};
                std::array<uint64_t, 256> guard;
            } snapshot;
            constexpr uint64_t guardValue = 0xA0B1C2D3E4F50617;
            snapshot.guard.fill(guardValue);
            auto& context = snapshot.context;
            context.ContextFlags = CONTEXT_FULL;
            auto read = GetThreadContext(thread, &context);
            auto intact = std::all_of(snapshot.guard.begin(), snapshot.guard.end(),
                [](uint64_t value) { return value == guardValue; });

            // Restore only the requested register groups while other worker state stays live.
            if (mode != ContextRestoration::Full)
            {
                ContextBuffer selected;
                selected.guard.fill(guardValue);
                selected.context.ContextFlags = mode == ContextRestoration::Edits ? CONTEXT_INTEGER :
                    iteration % 2 ? CONTEXT_INTEGER | CONTEXT_FLOATING_POINT : CONTEXT_CONTROL;
                read &= GetThreadContext(thread, &selected.context) != FALSE;
                if (mode == ContextRestoration::Edits) selected.context.R15 ^= 0x1020304050607080;
                auto unchanged = selected.context;
                read &= SetThreadContext(thread, &selected.context) != FALSE;
                intact &= !memcmp(&selected.context, &unchanged, sizeof(unchanged));
                intact &= std::all_of(selected.guard.begin(), selected.guard.end(),
                    [](uint64_t value) { return value == guardValue; });

                // A queued context edit must be visible before the worker resumes.
                if (mode == ContextRestoration::Edits)
                {
                    reinterpret_cast<void (*)()>(code.get())();
                    DWORD previous = 0;
                    auto changed = VirtualProtect(code.get(), 4096, PAGE_READWRITE, &previous);
                    if (changed)
                    {
                        code.get()[0] = 0xC3;
                        changed = VirtualProtect(code.get(), 4096, PAGE_EXECUTE_READ, &previous) &&
                            FlushInstructionCache(GetCurrentProcess(), code.get(), 1);
                    }
                    if (!changed) failure = 27;
                    CONTEXT observed{};
                    observed.ContextFlags = CONTEXT_INTEGER;
                    read &= GetThreadContext(thread, &observed) != FALSE;
                    if (observed.R15 != selected.context.R15) failure = 24;
                }
            }

            // Partial context queries must stay within the caller's context buffer.
            if (iteration == 0)
            {
                ContextBuffer registers;
                registers.guard.fill(guardValue);
                registers.context.ContextFlags = CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
                read &= GetThreadContext(thread, &registers.context) != FALSE;
                intact &= std::all_of(registers.guard.begin(), registers.guard.end(),
                    [](uint64_t value) { return value == guardValue; });
            }
            auto unchanged = context;
            auto restored = read && intact && (mode == ContextRestoration::Partial ||
                SetThreadContext(thread, &context));
            intact &= !memcmp(&context, &unchanged, sizeof(unchanged));
            auto resumed = ResumeThread(thread);
            if (!intact) return 22;
            if (!restored || resumed == MAXDWORD) return 18;
        }
        Sleep(1);
    }
    for (auto& worker : workers) worker.request_stop();
    workers.clear();
    for (const auto& count : progress) if (!count.load()) return 19;
    return failure;
}

DWORD SyscallNumber(const std::byte* image, const char* name)
{
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + dos->e_lfanew);
    auto exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        image + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto names = reinterpret_cast<const DWORD*>(image + exports->AddressOfNames);
    auto ordinals = reinterpret_cast<const WORD*>(image + exports->AddressOfNameOrdinals);
    auto functions = reinterpret_cast<const DWORD*>(image + exports->AddressOfFunctions);
    for (DWORD index = 0; index < exports->NumberOfNames; ++index)
    {
        if (strcmp(reinterpret_cast<const char*>(image + names[index]), name)) continue;
        auto code = reinterpret_cast<const BYTE*>(image + functions[ordinals[index]]);
        for (uint32_t offset = 0; offset + 5 < 32; ++offset)
        {
            if (code[offset] != 0xB8) continue;
            DWORD number = 0;
            memcpy(&number, code + offset + 1, sizeof(number));
            return number;
        }
    }
    throw std::runtime_error("The system call number is unavailable.");
}

int ExerciseInvalidContexts(LPCWSTR resultPath)
{
    // Unreadable application contexts must retain the kernel's validation result and cannot fault the monitor.
    using SetContext = NTSTATUS (NTAPI*)(HANDLE, CONTEXT*);
    auto set = reinterpret_cast<SetContext>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetContextThread"));
    auto pages = static_cast<BYTE*>(VirtualAlloc(nullptr, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    DWORD previous = 0;
    if (!set || !pages || !VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &previous)) return 60;
    auto partial = reinterpret_cast<CONTEXT*>(pages + 4096 - offsetof(CONTEXT, ContextFlags) - sizeof(DWORD));
    partial->ContextFlags = CONTEXT_INTEGER;
    std::array<NTSTATUS, 6> results{};
    uint32_t index = 0;
    for (auto handle : {reinterpret_cast<HANDLE>(0x12345678), GetCurrentThread()})
        for (auto context : {static_cast<CONTEXT*>(nullptr), reinterpret_cast<CONTEXT*>(pages + 4096), partial})
            results[index++] = set(handle, context);
    bool valid = std::ranges::all_of(results, [](auto result) { return result < 0; });
    VirtualFree(pages, 0, MEM_RELEASE);
    if (resultPath)
    {
        Handle output(CreateFileW(resultPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
        DWORD written = 0;
        valid &= output && WriteFile(output.get(), results.data(), sizeof(results), &written, nullptr) &&
            written == sizeof(results);
    }
    return valid ? 0 : 61;
}

int ExerciseGraphicsSyscalls()
{
    // Compare SDK thunks, named exports and private syscall stubs without changing display state.
    auto module = LoadLibraryExW(L"win32u.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return 70;
    wchar_t imagePath[32768]{};
    if (!GetModuleFileNameW(module, imagePath, std::size(imagePath))) return 70;
    Handle file(CreateFileW(imagePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr));
    Handle mapping(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
    std::unique_ptr<const std::byte, decltype(&UnmapViewOfFile)> image(
        static_cast<const std::byte*>(MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0)), UnmapViewOfFile);
    if (!image) return 70;
    auto code = static_cast<BYTE*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!code) return 71;
    const char* names[]{"NtGdiDdDDIEnumAdapters2", "NtGdiDdDDIQueryAdapterInfo", "NtGdiDdDDIQueryStatistics"};
    std::array<BYTE, 11> stub{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3};
    for (size_t index = 0; index < std::size(names); ++index)
    {
        auto number = SyscallNumber(image.get(), names[index]);
        memcpy(stub.data() + 4, &number, sizeof(number));
        memcpy(code + index * 32, stub.data(), stub.size());
    }
    DWORD protection = 0;
    if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), code, 4096)) return 72;
    auto publicModule = LoadLibraryExW(L"gdi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!publicModule) return 73;
    bool valid = true;
    for (int route = 0; route < 3; ++route)
    {
        auto address = [&](size_t index, const char* publicName)
        {
            return route == 2 ? reinterpret_cast<FARPROC>(code + index * 32) :
                GetProcAddress(route == 0 ? publicModule : module, route == 0 ? publicName : names[index]);
        };
        auto enumerate = reinterpret_cast<decltype(&D3DKMTEnumAdapters2)>(address(0, "D3DKMTEnumAdapters2"));
        auto query = reinterpret_cast<decltype(&D3DKMTQueryAdapterInfo)>(address(1, "D3DKMTQueryAdapterInfo"));
        auto statistics = reinterpret_cast<decltype(&D3DKMTQueryStatistics)>(address(2, "D3DKMTQueryStatistics"));
        if (!enumerate || !query || !statistics) { valid = false; break; }
        D3DKMT_ADAPTERINFO adapters[64]{};
        D3DKMT_ENUMADAPTERS2 enumeration{std::size(adapters), adapters};
        D3DKMT_QUERYADAPTERINFO information{};
        information.hAdapter = 0x7FFFFFFF;
        BYTE privateData[256];
        memset(privateData, 0xAC, sizeof(privateData));
        information.pPrivateDriverData = privateData;
        information.PrivateDriverDataSize = sizeof(privateData);
        D3DKMT_QUERYSTATISTICS counts{};
        counts.Type = static_cast<D3DKMT_QUERYSTATISTICS_TYPE>(0x7FFFFFFF);
        auto enumerated = enumerate(&enumeration);
        auto queried = query(&information);
        auto counted = statistics(&counts);
        information.pPrivateDriverData = reinterpret_cast<void*>(1);
        auto rejected = query(&information);
        information.pPrivateDriverData = privateData;
        information.PrivateDriverDataSize = sizeof(D3DKMT_ADAPTERTYPE);
        information.Type = KMTQAITYPE_ADAPTERTYPE;
        if (enumeration.NumAdapters) information.hAdapter = adapters[0].hAdapter;
        auto described = query(&information);
        printf("Graphics route=%d enumerate=%08X adapters=%u query=%08X statistics=%08X\n", route,
            static_cast<unsigned>(enumerated), enumeration.NumAdapters,
            static_cast<unsigned>(queried), static_cast<unsigned>(counted));
        valid &= enumerated >= 0 && enumeration.NumAdapters <= std::size(adapters) && queried < 0 && counted < 0 &&
            rejected < 0 && described >= 0;
    }
    VirtualFree(code, 0, MEM_RELEASE);
    FreeLibrary(publicModule);
    FreeLibrary(module);
    return valid ? 0 : 74;
}

int ExerciseWindowGraphicsSyscalls()
{
    // Named exports and private stubs exercise SDK-compatible contracts without creating a visible window.
    auto module = LoadLibraryExW(L"win32u.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto publicModule = LoadLibraryExW(L"gdi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto code = static_cast<BYTE*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!module || !publicModule || !code) return 75;

    // Resolve private service IDs from a clean image while the loaded exports remain observable.
    wchar_t imagePath[32768]{};
    if (!GetModuleFileNameW(module, imagePath, std::size(imagePath))) return 75;
    Handle file(CreateFileW(imagePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr));
    Handle mapping(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
    std::unique_ptr<const std::byte, decltype(&UnmapViewOfFile)> image(
        static_cast<const std::byte*>(MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0)), UnmapViewOfFile);
    if (!image) return 75;
    const char* names[]{"NtGdiCreateCompatibleDC", "NtGdiGetRgnBox", "NtGdiMoveTo", "NtGdiLineTo",
        "NtGdiGetPath", "NtGdiSetBrushOrg", "NtUserPostThreadMessage"};
    std::array<BYTE, 11> stub{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3};
    for (size_t index = 0; index < std::size(names); ++index)
    {
        auto number = SyscallNumber(image.get(), names[index]);
        memcpy(stub.data() + 4, &number, sizeof(number));
        memcpy(code + index * 32, stub.data(), stub.size());
    }
    DWORD protection = 0;
    if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), code, 4096)) return 76;
    auto beginPath = reinterpret_cast<decltype(&BeginPath)>(GetProcAddress(publicModule, "BeginPath"));
    auto endPath = reinterpret_cast<decltype(&EndPath)>(GetProcAddress(publicModule, "EndPath"));
    auto deleteObject = reinterpret_cast<decltype(&DeleteObject)>(GetProcAddress(publicModule, "DeleteObject"));
    auto deleteDC = reinterpret_cast<decltype(&DeleteDC)>(GetProcAddress(publicModule, "DeleteDC"));
    auto publicRegion = reinterpret_cast<decltype(&CreateRectRgn)>(GetProcAddress(publicModule, "CreateRectRgn"));
    if (!beginPath || !endPath || !deleteObject || !deleteDC || !publicRegion) return 77;
    bool valid = true;
    for (int route = 0; route < 2; ++route)
    {
        auto address = [&](size_t index)
        {
            return route ? reinterpret_cast<FARPROC>(code + index * 32) : GetProcAddress(module, names[index]);
        };
        auto createDC = reinterpret_cast<decltype(&CreateCompatibleDC)>(address(0));
        auto regionBox = reinterpret_cast<decltype(&GetRgnBox)>(address(1));
        auto move = reinterpret_cast<decltype(&MoveToEx)>(address(2));
        auto line = reinterpret_cast<decltype(&LineTo)>(address(3));
        auto path = reinterpret_cast<decltype(&GetPath)>(address(4));
        auto brushOrigin = reinterpret_cast<decltype(&SetBrushOrgEx)>(address(5));
        auto post = reinterpret_cast<decltype(&PostThreadMessageW)>(address(6));
        if (!createDC || !regionBox || !move || !line || !path || !brushOrigin || !post)
            return 78;
        auto dc = createDC(nullptr);
        auto region = publicRegion(5, 7, 29, 31);
        if (!dc || !region) return 79;
        RECT bounds{};
        POINT previous{}, brush{};
        POINT points[10]{};
        BYTE types[10]{};

        // Rejected handles and an empty path distinguish failures from valid zero-valued queries.
        auto rejectedDC = createDC(reinterpret_cast<HDC>(1));
        auto rejectedRegion = regionBox(nullptr, &bounds);
        auto rejectedMove = move(nullptr, 13, 17, &previous);
        auto rejectedLine = line(nullptr, 19, 23);
        auto rejectedPath = path(nullptr, points, types, std::size(points));
        auto rejectedBrush = brushOrigin(nullptr, 3, 5, &brush);
        auto rejectedPost = post(0xFFFFFFFC, WM_APP + 123, 0x12345678, 0x23456789);
        valid &= !rejectedDC && !rejectedRegion && !rejectedMove && !rejectedLine && rejectedPath == -1 &&
            !rejectedBrush && !rejectedPost;
        auto emptyStarted = beginPath(dc);
        auto emptyEnded = endPath(dc);
        auto emptyCount = path(dc, nullptr, nullptr, 0);
        valid &= emptyStarted && emptyEnded && emptyCount == 0;
        printf("Rejected=%d,%d,%d,%d,%d,%d,%d empty=%d\n", rejectedDC == nullptr, rejectedRegion,
            rejectedMove, rejectedLine, rejectedPath, rejectedBrush, rejectedPost, emptyCount);
        auto boxed = regionBox(region, &bounds);
        valid &= boxed == SIMPLEREGION && bounds.left == 5 && bounds.top == 7 &&
            bounds.right == 29 && bounds.bottom == 31;
        auto brushed = brushOrigin(dc, 3, 5, &brush);
        auto started = beginPath(dc);
        auto moved = move(dc, 13, 17, &previous);
        auto lined = line(dc, 19, 23);
        auto ended = endPath(dc);
        valid &= brushed && started && moved && lined && ended;
        auto count = path(dc, points, types, std::size(points));
        valid &= count == 2 && points[0].x == 13 && points[0].y == 17 && points[1].x == 19 && points[1].y == 23;
        MSG message{};
        PeekMessageW(&message, nullptr, 0, 0, PM_NOREMOVE);
        constexpr UINT messageId = WM_APP + 123;
        auto posted = post(GetCurrentThreadId(), messageId, 0x12345678, 0x23456789);
        auto peeked = PeekMessageW(&message, nullptr, messageId, messageId, PM_REMOVE);
        valid &= posted && peeked && message.message == messageId &&
            message.wParam == 0x12345678 && message.lParam == 0x23456789;
        printf("Window graphics route=%d path=%d region=%ld,%ld,%ld,%ld valid=%d\n", route, count,
            bounds.left, bounds.top, bounds.right, bounds.bottom, valid);
        printf("Results=%d,%d,%d,%d,%d,%d,%d,%d points=%ld,%ld,%ld,%ld message=%X,%llX,%llX\n", boxed,
            brushed, started, moved, lined, ended, posted, peeked, points[0].x, points[0].y, points[1].x,
            points[1].y, message.message, static_cast<unsigned long long>(message.wParam),
            static_cast<unsigned long long>(message.lParam));
        deleteObject(region);
        deleteDC(dc);
    }
    VirtualFree(code, 0, MEM_RELEASE);
    FreeLibrary(publicModule);
    FreeLibrary(module);
    return valid ? 0 : 80;
}

int ExerciseSdkForwarders()
{
    // SDK calls, native exports and private syscalls share bounded input and graphics contracts.
    auto module = LoadLibraryExW(L"win32u.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto user = LoadLibraryExW(L"user32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto graphics = LoadLibraryExW(L"gdi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto code = static_cast<BYTE*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!module || !user || !graphics || !code) return 81;

    // Read service numbers from an independent image so installed export detours cannot alter the fixture.
    wchar_t path[32768]{};
    if (!GetModuleFileNameW(module, path, std::size(path))) return 82;
    Handle file(
        CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    Handle mapping(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
    std::unique_ptr<const std::byte, decltype(&UnmapViewOfFile)> image(
        static_cast<const std::byte*>(MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0)), UnmapViewOfFile);
    if (!image) return 82;
    const char* names[]{"NtUserGetKeyboardState", "NtUserGetKeyboardLayoutList", "NtGdiGetTextCharsetInfo"};
    FARPROC publicCalls[]{GetProcAddress(user, "GetKeyboardState"), GetProcAddress(user, "GetKeyboardLayoutList"),
        GetProcAddress(graphics, "GetTextCharsetInfo")};
    std::array<BYTE, 11> stub{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3};
    for (size_t index = 0; index < std::size(names); ++index)
    {
        auto number = SyscallNumber(image.get(), names[index]);
        if (!number || !publicCalls[index]) return 82;
        memcpy(stub.data() + 4, &number, sizeof(number));
        memcpy(code + index * 32, stub.data(), stub.size());
    }
    DWORD protection = 0;
    if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), code, 4096)) return 83;
    auto dc = CreateCompatibleDC(nullptr);
    auto fontHandle = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_TT_ONLY_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    auto previousFont = dc && fontHandle ? SelectObject(dc, fontHandle) : nullptr;
    BYTE initial[256]{};
    if (!dc || !fontHandle || !previousFont || !GetKeyboardState(initial)) return 84;
    bool valid = true;
    for (int route = 0; route < 3; ++route)
    {
        auto address = [&](size_t index)
        {
            return route == 0 ? publicCalls[index] : route == 1 ? GetProcAddress(module, names[index]) :
                reinterpret_cast<FARPROC>(code + index * 32);
        };
        auto keyboard = reinterpret_cast<decltype(&GetKeyboardState)>(address(0));
        auto layouts = reinterpret_cast<decltype(&GetKeyboardLayoutList)>(address(1));
        auto charset = reinterpret_cast<decltype(&GetTextCharsetInfo)>(address(2));
        BYTE keys[256]{};
        HKL handles[16]{};
        FONTSIGNATURE font{};
        auto keyed = keyboard(keys);
        auto available = layouts(0, nullptr);
        auto counted = layouts(std::size(handles), handles);
        auto characterSet = charset(dc, &font, 0);
        valid &= keyed && available > 0 && counted > 0 && counted <= std::size(handles) &&
            characterSet != DEFAULT_CHARSET && handles[0] != nullptr;
        printf("SDK route=%d keys=%d layouts=%d/%d charset=%d font=%08lX,%08lX,%08lX,%08lX,%08lX,%08lX\n",
            route, keyed, counted, available, characterSet, font.fsUsb[0], font.fsUsb[1], font.fsUsb[2],
            font.fsUsb[3], font.fsCsb[0], font.fsCsb[1]);
    }
    SelectObject(dc, previousFont);
    DeleteObject(fontHandle);
    DeleteDC(dc);
    VirtualFree(code, 0, MEM_RELEASE);
    FreeLibrary(graphics);
    FreeLibrary(user);
    FreeLibrary(module);
    return valid ? 0 : 85;
}

struct Win32uContext
{
    HMODULE module = LoadLibraryExW(L"win32u.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    HDC dc = GetDC(nullptr);

    Win32uContext() = default;
    Win32uContext(const Win32uContext&) = delete;
    Win32uContext& operator=(const Win32uContext&) = delete;

    ~Win32uContext()
    {
        if (dc) ReleaseDC(nullptr, dc);
        if (module) FreeLibrary(module);
    }

    FARPROC Find(const char* name) const { return module ? GetProcAddress(module, name) : nullptr; }
};

int ExerciseNativeTextExtent()
{
    // Exercise the installed native graphics export with a real DC and a bounded output structure.
    Win32uContext context;
    auto procedure = context.Find("NtGdiGetTextExtent");
    if (!procedure || !context.dc) return 101;
    using GetExtent = BOOL (WINAPI*)(HDC, LPWSTR, int, LPSIZE, UINT);
    wchar_t text[] = L"Coverage native";
    SIZE extent{};
    auto result = reinterpret_cast<GetExtent>(procedure)(context.dc, text, static_cast<int>(std::size(text) - 1),
        &extent, 0);
    printf("native_text_extent=%ld,%ld\n", extent.cx, extent.cy);
    return result && extent.cx > 0 && extent.cy > 0 ? 0 : 102;
}

int ExerciseNativeFontId()
{
    // Query a real display context so the native output fields can be inspected under both capture engines.
    struct UniversalFontId { ULONG CheckSum, Index; };
    Win32uContext context;
    auto procedure = context.Find("NtGdiGetUFI");
    if (!procedure || !context.dc) return 105;
    using GetUfi = BOOL (WINAPI*)(HDC, UniversalFontId*, void*, ULONG*, ULONG*, ULONG*);
    UniversalFontId id{};
    ULONG designBytes = 0, baseCheckSum = 0, flags = 0;
    auto result = reinterpret_cast<GetUfi>(procedure)(context.dc, &id, nullptr, &designBytes, &baseCheckSum, &flags);
    printf("native_ufi=%lu,%lu,%lu,%lu,%lu\n", id.CheckSum, id.Index, designBytes, baseCheckSum, flags);
    return result && id.CheckSum && id.Index ? 0 : 106;
}

int ExerciseNativeScalarQueries()
{
    // Exercise installed zero- and one-argument native graphics queries with valid display context state.
    Win32uContext context;
    if (!context.module || !context.dc) return 107;
    auto linked = reinterpret_cast<BOOL (WINAPI*)()>(context.Find("NtGdiAnyLinkedFonts"));
    auto uniqueness = reinterpret_cast<ULONG (WINAPI*)()>(
        context.Find("NtGdiDdQueryVisRgnUniqueness"));
    auto width = reinterpret_cast<LONG (WINAPI*)(HDC)>(context.Find("NtGdiGetDeviceWidth"));
    auto embed = reinterpret_cast<ULONG (WINAPI*)()>(context.Find("NtGdiGetEmbedFonts"));
    auto cookie = reinterpret_cast<ULONG (WINAPI*)()>(
        context.Find("NtGdiGetPublicFontTableChangeCookie"));
    if (!linked || !uniqueness || !width || !embed || !cookie) return 108;
    auto hasLinked = linked();
    auto generation = uniqueness();
    auto deviceWidth = width(context.dc);
    auto embedded = embed();
    auto fontTableCookie = cookie();
    printf("native_scalar=%ld,%lu,%ld,%lu,%lu\n", hasLinked, generation, deviceWidth, embedded,
        fontTableCookie);
    return generation && deviceWidth > 0 ? 0 : 109;
}

int ExerciseProvisionalNative()
{
    // Exercise a raw native export whose historical declaration supplies display labels only.
    Win32uContext context;
    auto procedure = context.Find("NtGdiGetCharSet");
    if (!procedure || !context.dc) return 103;
    using GetCharSet = ULONG (WINAPI*)(HDC);
    auto result = reinterpret_cast<GetCharSet>(procedure)(context.dc);
    printf("native_provisional_charset=%lu\n", result);
    return result > 0 && result < 65536 ? 0 : 104;
}

int ExerciseSdkLeafThunks()
{
    // Leaf SDK thunks, their native exports and private stubs return the same guarded output regions.
    auto module = LoadLibraryExW(L"win32u.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto user = LoadLibraryExW(L"user32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto graphics = LoadLibraryExW(L"gdi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto releaseCode = [](BYTE* value) { VirtualFree(value, 0, MEM_RELEASE); };
    std::unique_ptr<BYTE, decltype(releaseCode)> code(static_cast<BYTE*>(VirtualAlloc(nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)), releaseCode);
    if (!module || !user || !graphics || !code) return 86;

    // Resolve service numbers from a clean image before routing calls through executable private code.
    wchar_t path[32768]{};
    if (!GetModuleFileNameW(module, path, std::size(path))) return 87;
    Handle file(
        CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    Handle mapping(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
    std::unique_ptr<const std::byte, decltype(&UnmapViewOfFile)> image(
        static_cast<const std::byte*>(MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0)), UnmapViewOfFile);
    if (!image) return 87;
    const char* names[]{"NtGdiGetBitmapDimension", "NtGdiGetMiterLimit", "NtGdiGetColorAdjustment",
        "NtUserGetKeyNameText", "NtUserGetPriorityClipboardFormat", "NtUserCreateCaret"};
    FARPROC publicCalls[]{GetProcAddress(graphics, "GetBitmapDimensionEx"), GetProcAddress(graphics, "GetMiterLimit"),
        GetProcAddress(graphics, "GetColorAdjustment"), GetProcAddress(user, "GetKeyNameTextW"),
        GetProcAddress(user, "GetPriorityClipboardFormat"), GetProcAddress(user, "CreateCaret")};
    std::array<BYTE, 11> stub{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3};
    for (size_t index = 0; index < std::size(names); ++index)
    {
        auto number = SyscallNumber(image.get(), names[index]);
        if (!number || !publicCalls[index] || !GetProcAddress(module, names[index])) return 87;
        memcpy(stub.data() + 4, &number, sizeof(number));
        memcpy(code.get() + index * 32, stub.data(), stub.size());
    }
    DWORD protection = 0;
    if (!VirtualProtect(code.get(), 4096, PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), code.get(), 4096)) return 88;
    std::unique_ptr<std::remove_pointer_t<HDC>, decltype(&DeleteDC)> dc(CreateCompatibleDC(nullptr), DeleteDC);
    auto deleteBitmap = [](HBITMAP value) { DeleteObject(value); };
    std::unique_ptr<std::remove_pointer_t<HBITMAP>, decltype(deleteBitmap)> bitmap(
        CreateBitmap(2, 2, 1, 32, nullptr), deleteBitmap);
    if (!dc || !bitmap || !SetBitmapDimensionEx(bitmap.get(), 23, 47, nullptr) ||
        !SetMiterLimit(dc.get(), 3.5f, nullptr)) return 89;
    std::unique_ptr<std::remove_pointer_t<HWND>, decltype(&DestroyWindow)> window(
        CreateWindowExW(WS_EX_NOACTIVATE, L"STATIC", L"", WS_POPUP, 0, 0, 1, 1, nullptr, nullptr, nullptr, nullptr),
        DestroyWindow);
    if (!window) return 89;
    std::array<UINT, 32> formats{};
    constexpr UINT requested[]{CF_UNICODETEXT, CF_TEXT, CF_DIB, CF_DIBV5};
    for (size_t index = 0; index < formats.size(); ++index) formats[index] = requested[index % std::size(requested)];
    auto key = static_cast<LONG>(MapVirtualKeyW(VK_F12, MAPVK_VK_TO_VSC) << 16);
    bool valid = true;
    for (int route = 0; route < 3; ++route)
    {
        auto address = [&](size_t index)
        {
            return route == 0 ? publicCalls[index] : route == 1 ? GetProcAddress(module, names[index]) :
                reinterpret_cast<FARPROC>(code.get() + index * 32);
        };
        SIZE dimension{};
        FLOAT miter = 0;
        COLORADJUSTMENT color{};
        color.caSize = static_cast<WORD>(sizeof(color));
        struct
        {
            std::array<wchar_t, 32> text{};
            DWORD guard = 0x19A4B83C;
        } keyName;
        valid &= reinterpret_cast<decltype(&GetBitmapDimensionEx)>(address(0))(bitmap.get(), &dimension) != FALSE;
        valid &= reinterpret_cast<decltype(&GetMiterLimit)>(address(1))(dc.get(), &miter) != FALSE;
        valid &= reinterpret_cast<decltype(&GetColorAdjustment)>(address(2))(dc.get(), &color) != FALSE;
        valid &= reinterpret_cast<decltype(&GetKeyNameTextW)>(address(3))(key, keyName.text.data(),
            static_cast<int>(keyName.text.size())) > 0;
        auto priority = reinterpret_cast<decltype(&GetPriorityClipboardFormat)>(address(4))(
            formats.data(), static_cast<int>(formats.size()));
        valid &= priority >= -1;
        valid &= reinterpret_cast<decltype(&CreateCaret)>(address(5))(window.get(), nullptr, 3, 5) != FALSE;
        valid &= DestroyCaret() != FALSE;
        valid &= dimension.cx == 23 && dimension.cy == 47 && miter == 3.5f &&
            color.caSize == sizeof(color) && keyName.text[0] != 0 && keyName.guard == 0x19A4B83C;
        printf("leaf=%d size=%ld,%ld color=", route, dimension.cx, dimension.cy);
        for (size_t index = 0; index < sizeof(color); ++index)
            printf("%02X", reinterpret_cast<const unsigned char*>(&color)[index]);
        printf(" key=");
        for (size_t index = 0; index < sizeof(keyName.text); ++index)
            printf("%02X", reinterpret_cast<const unsigned char*>(keyName.text.data())[index]);
        printf("\n");
    }
    FreeLibrary(graphics);
    FreeLibrary(user);
    FreeLibrary(module);
    return valid ? 0 : 90;
}

int ExerciseUnknownSyscalls(LPCWSTR resultPath)
{
    // Invalid service slots verify observation without invoking an undocumented service contract.
    constexpr DWORD numbers[]{0x2FFF, 0x7FFFFFFF, 0xFFFFFFFF};
    auto release = [](BYTE* value) { VirtualFree(value, 0, MEM_RELEASE); };
    std::unique_ptr<BYTE, decltype(release)> code(static_cast<BYTE*>(
        VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)), release);
    if (!code) return 1;
    std::array<BYTE, 11> stub{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3};
    for (size_t index = 0; index < std::size(numbers); ++index)
    {
        memcpy(stub.data() + 4, &numbers[index], sizeof(DWORD));
        memcpy(code.get() + index * 32, stub.data(), stub.size());
    }
    DWORD protection = 0;
    if (!VirtualProtect(code.get(), 4096, PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), code.get(), 4096)) return 2;
    std::array<BYTE, 128> buffer{};
    for (size_t index = 0; index < buffer.size(); ++index) buffer[index] = static_cast<BYTE>(index ^ 0xA3);
    std::array<NTSTATUS, 96> results{};
    std::atomic<uint32_t> ready = 0;
    std::atomic<bool> start = false;
    std::vector<std::jthread> workers;
    for (size_t worker = 0; worker < 4; ++worker)
    {
        workers.emplace_back([&, worker]()
        {
            ++ready;
            while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
            using Call = NTSTATUS (NTAPI*)(const void*, DWORD, const void*, ULONG);
            for (size_t iteration = 0; iteration < 8; ++iteration)
            {
                for (size_t index = 0; index < std::size(numbers); ++index)
                {
                    auto call = reinterpret_cast<Call>(code.get() + index * 32);
                    results[worker * 24 + iteration * 3 + index] = call(buffer.data(), 128, buffer.data(), 128);
                }
            }
        });
    }
    while (ready != 4) std::this_thread::yield();
    start.store(true, std::memory_order_release);
    workers.clear();
    if (!std::all_of(results.begin(), results.end(), [](NTSTATUS status)
        { return status == static_cast<NTSTATUS>(0xC000001C); })) return 3;
    printf("Unknown syscall slots: %zu rejected calls across four threads.\n", results.size());
    if (!resultPath) return 0;
    Handle output(CreateFileW(resultPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
    DWORD written = 0;
    return output && WriteFile(output.get(), results.data(), sizeof(results), &written, nullptr) &&
        written == sizeof(results) ? 0 : 4;
}

int ExercisePendingRead()
{
    wchar_t system[MAX_PATH];
    if (!GetSystemDirectoryW(system, MAX_PATH)) return 1;
    auto path = std::wstring(system) + L"\\ntdll.dll";
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, 0, nullptr));
    Handle mapping(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
    auto image = static_cast<const std::byte*>(MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0));
    if (!image) return 2;
    auto number = SyscallNumber(image, "NtReadFile");
    UnmapViewOfFile(image);
    auto release = [](BYTE* value) { VirtualFree(value, 0, MEM_RELEASE); };
    std::unique_ptr<BYTE, decltype(release)> code(static_cast<BYTE*>(
        VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)), release);
    if (!code) return 3;
    std::array<BYTE, 11> stub{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3};
    memcpy(stub.data() + 4, &number, sizeof(number));
    memcpy(code.get(), stub.data(), stub.size());
    DWORD protection = 0;
    if (!VirtualProtect(code.get(), 4096, PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), code.get(), 4096)) return 4;
    auto name = L"\\\\.\\pipe\\DetouristPendingRead." + std::to_wstring(GetCurrentProcessId());
    Handle server(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT, 1, 128, 128, 0, nullptr));
    Handle client(CreateFileW(name.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    Handle completed(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!server || !client || !completed) return 5;
    std::array<BYTE, 128> buffer;
    buffer.fill(0xCD);
    IO_STATUS_BLOCK status{};
    status.Information = buffer.size();
    using Read = NTSTATUS (NTAPI*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
        PVOID, ULONG, PLARGE_INTEGER, PULONG);
    auto read = reinterpret_cast<Read>(code.get());
    auto result = read(server.get(), completed.get(), nullptr, nullptr, &status, buffer.data(),
        static_cast<ULONG>(buffer.size()), nullptr, nullptr);
    if (result != static_cast<NTSTATUS>(0x103)) return 6;
    std::array<BYTE, 128> expected;
    expected.fill(0x6B);
    DWORD written = 0;
    if (!WriteFile(client.get(), expected.data(), static_cast<DWORD>(expected.size()), &written, nullptr) ||
        written != expected.size() || WaitForSingleObject(completed.get(), 5000) != WAIT_OBJECT_0)
    {
        CancelIoEx(server.get(), nullptr);
        WaitForSingleObject(completed.get(), INFINITE);
        return 7;
    }
    return status.Status == 0 && status.Information == expected.size() && buffer == expected ? 0 : 8;
}

int ExerciseHandlePointers()
{
    // Readable user memory makes an accidental HBITMAP dereference visible in the trace.
    auto release = [](BYTE* value) { VirtualFree(value, 0, MEM_RELEASE); };
    std::unique_ptr<BYTE, decltype(release)> fake(static_cast<BYTE*>(VirtualAlloc(nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)), release);
    if (!fake) return 1;
    memset(fake.get(), 0xA5, 4096);
    auto graphics = LoadLibraryExW(L"win32u.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!graphics) return 2;
    using GetDimension = BOOL (NTAPI*)(HBITMAP, LPSIZE);
    using SetDimension = BOOL (NTAPI*)(HBITMAP, INT, INT, LPSIZE);
    using CreateCaret = BOOL (NTAPI*)(HWND, HBITMAP, INT, INT);
    auto get = reinterpret_cast<GetDimension>(GetProcAddress(graphics, "NtGdiGetBitmapDimension"));
    auto set = reinterpret_cast<SetDimension>(GetProcAddress(graphics, "NtGdiSetBitmapDimension"));
    auto caret = reinterpret_cast<CreateCaret>(GetProcAddress(graphics, "NtUserCreateCaret"));
    if (!get || !set || !caret) { FreeLibrary(graphics); return 3; }
    SIZE dimension{};
    auto bitmap = reinterpret_cast<HBITMAP>(fake.get());
    auto read = get(bitmap, &dimension);
    auto write = set(bitmap, 10, 20, &dimension);
    auto create = caret(nullptr, bitmap, 3, 5);
    FreeLibrary(graphics);
    printf("Opaque handle results: %d,%d,%d\n", read, write, create);
    return read || write || create ? 4 : 0;
}

int TargetMain(int argc, wchar_t** argv)
{
    try
    {
        if (argc > 1 && !_wcsicmp(argv[1], L"--handle-pointers")) return ExerciseHandlePointers();
        if (argc > 1 && !_wcsicmp(argv[1], L"--pending-read")) return ExercisePendingRead();
        if (argc > 2 && !_wcsicmp(argv[1], L"--unknown-attach"))
        {
            // Repeated sessions reuse the same process while each capture owns its sparse service cache.
            auto sessions = argc > 3 ? std::clamp(_wtoi(argv[3]), 1, 3) : 3;
            for (int index = 0; index < sessions; ++index)
            {
                auto prefix = std::wstring(argv[2]) + L"." + std::to_wstring(index);
                Handle ready(CreateFileW((prefix + L".ready").c_str(), GENERIC_WRITE, 0, nullptr,
                    CREATE_ALWAYS, 0, nullptr));
                if (!ready) return 5;
                ready.reset();
                while (GetFileAttributesW((prefix + L".go").c_str()) == INVALID_FILE_ATTRIBUTES) Sleep(10);
                auto result = ExerciseUnknownSyscalls((prefix + L".bin").c_str());
                if (result) return result;
                while (GetFileAttributesW((prefix + L".release").c_str()) == INVALID_FILE_ATTRIBUTES) Sleep(10);
            }
            return 0;
        }
        if (argc > 1 && !_wcsicmp(argv[1], L"--unknown-services"))
            return ExerciseUnknownSyscalls(argc > 2 ? argv[2] : nullptr);
        if (argc > 1 && !_wcsicmp(argv[1], L"--native-text-extent")) return ExerciseNativeTextExtent();
        if (argc > 1 && !_wcsicmp(argv[1], L"--native-ufi")) return ExerciseNativeFontId();
        if (argc > 1 && !_wcsicmp(argv[1], L"--native-scalar")) return ExerciseNativeScalarQueries();
        if (argc > 1 && !_wcsicmp(argv[1], L"--native-provisional")) return ExerciseProvisionalNative();
        if (argc > 1 && !_wcsicmp(argv[1], L"--sdk-leaf")) return ExerciseSdkLeafThunks();
        if (argc > 1 && !_wcsicmp(argv[1], L"--sdk-forwarders")) return ExerciseSdkForwarders();
        if (argc > 1 && !_wcsicmp(argv[1], L"--graphics")) return ExerciseGraphicsSyscalls();
        if (argc > 1 && !_wcsicmp(argv[1], L"--window-graphics")) return ExerciseWindowGraphicsSyscalls();
        if (argc > 1 && !_wcsicmp(argv[1], L"--invalid-contexts"))
            return ExerciseInvalidContexts(argc > 2 ? argv[2] : nullptr);
        auto iterations = argc > 2 ? _wtoi(argv[2]) : 16;
        auto threadStep = argc > 1 && !_wcsicmp(argv[1], L"--single-step-context");
        auto writableStep = argc > 1 && !_wcsicmp(argv[1], L"--single-step-writable");
        auto singleStep = threadStep || writableStep || (argc > 1 && !_wcsicmp(argv[1], L"--single-step"));
        auto contextMode = argc > 1 && !_wcsicmp(argv[1], L"--contexts-edits")     ? ContextRestoration::Edits
                           : argc > 1 && !_wcsicmp(argv[1], L"--contexts-partial") ? ContextRestoration::Partial
                                                                                   : ContextRestoration::Full;
        if (singleStep || contextMode != ContextRestoration::Full ||
            (argc > 1 && !_wcsicmp(argv[1], L"--contexts")))
        {
            // A readiness gate lets context restoration run after attaching to an independently started process.
            if (argc > 4 && !_wcsicmp(argv[4], L"--wait"))
            {
                auto ready = std::wstring(argv[3]) + L".ready";
                auto proceed = std::wstring(argv[3]) + L".go";
                Handle signal(CreateFileW(ready.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, nullptr));
                if (!signal) return 21;
                signal.reset();
                while (GetFileAttributesW(proceed.c_str()) == INVALID_FILE_ATTRIBUTES) Sleep(10);
            }
            auto result = threadStep ? ExerciseThreadSingleStep(iterations) : singleStep ?
                ExerciseSingleStep(iterations, writableStep) : ExerciseThreadContexts(iterations, contextMode);
            if (argc > 3)
            {
                Handle output(CreateFileW(argv[3], GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
                DWORD written = 0;
                if (!output || !WriteFile(output.get(), &result, sizeof(result), &written, nullptr) ||
                    written != sizeof(result)) return 20;
                if (singleStep && result)
                {
                    std::array<DWORD64, 5> context{SingleStepPhase.load(), SingleStepActual, SingleStepAfter,
                        SingleStepActualStack, SingleStepStack};
                    if (!WriteFile(output.get(), context.data(), sizeof(context), &written, nullptr) ||
                        written != sizeof(context)) return 20;
                }
            }
            return result;
        }
        bool paced = argc > 1 && !_wcsicmp(argv[1], L"--paced");
        wchar_t system[MAX_PATH];
        if (!GetSystemDirectoryW(system, MAX_PATH)) return 1;
        auto path = std::wstring(system) + L"\\ntdll.dll";
        Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, 0, nullptr));
        Handle mapping(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
        auto image = static_cast<const std::byte*>(MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0));
        if (!image) return 2;
        auto writeNumber = SyscallNumber(image, "NtWriteFile");
        auto queryNumber = SyscallNumber(image, "NtQueryInformationProcess");
        auto delayNumber = SyscallNumber(image, "NtDelayExecution");
        UnmapViewOfFile(image);

        // Initialize the window subsystem and resolve its service from the machine's clean image.
        RECT initialClip{};
        if (!GetClipCursor(&initialClip)) return 9;
        path = std::wstring(system) + L"\\win32u.dll";
        file.reset(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, 0, nullptr));
        mapping.reset(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
        image = static_cast<const std::byte*>(MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0));
        if (!image) return 10;
        auto cursorNumber = SyscallNumber(image, "NtUserGetClipCursor");
        UnmapViewOfFile(image);

        // Calls execute in private code with no DLL export address that a detour can intercept.
        auto code = static_cast<BYTE*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!code) return 3;
        std::array<BYTE, 11> stub{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3};
        memcpy(stub.data() + 4, &writeNumber, sizeof(writeNumber));
        memcpy(code, stub.data(), stub.size());
        memcpy(stub.data() + 4, &queryNumber, sizeof(queryNumber));
        memcpy(code + 32, stub.data(), stub.size());
        memcpy(stub.data() + 4, &cursorNumber, sizeof(cursorNumber));
        memcpy(code + 64, stub.data(), stub.size());
        memcpy(stub.data() + 4, &delayNumber, sizeof(delayNumber));
        memcpy(code + 96, stub.data(), stub.size());
        DWORD protection = 0;
        if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &protection)) return 4;
        FlushInstructionCache(GetCurrentProcess(), code, 4096);
        using Write = NTSTATUS (NTAPI*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
            PVOID, ULONG, PLARGE_INTEGER, PULONG);
        using Query = NTSTATUS (NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        using Cursor = BOOL (NTAPI*)(LPRECT);
        using Delay = NTSTATUS (NTAPI*)(BOOLEAN, PLARGE_INTEGER);
        auto write = reinterpret_cast<Write>(code);
        auto query = reinterpret_cast<Query>(code + 32);
        auto cursor = reinterpret_cast<Cursor>(code + 64);

        // APC delivery suspends an alertable syscall while the callback makes another private syscall.
        bool apcBreak = argc > 1 && !_wcsicmp(argv[1], L"--apc-break");
        bool nestedApc = argc > 1 && !_wcsicmp(argv[1], L"--apc-nested");
        if (apcBreak || nestedApc || (argc > 1 && !_wcsicmp(argv[1], L"--apc")))
        {
            struct ApcState
            {
                Query query;
                Delay delay;
                PAPCFUNC callback;
                uint32_t remaining, completed;
                bool failed;
            } state{query, reinterpret_cast<Delay>(code + 96), nullptr, nestedApc ? 1u : 0u, 0, false};
            auto callback = [](ULONG_PTR argument)
            {
                auto& state = *reinterpret_cast<ApcState*>(argument);
                PROCESS_BASIC_INFORMATION information{};
                ULONG length = 0;
                if (state.query(GetCurrentProcess(), ProcessBasicInformation, &information,
                    sizeof(information), &length) == 0 && length == sizeof(information) &&
                    information.UniqueProcessId == GetCurrentProcessId()) ++state.completed;
                else state.failed = true;
                if (!state.remaining) return;
                --state.remaining;
                LARGE_INTEGER interval{};
                interval.QuadPart = -100000;
                if (!QueueUserAPC(state.callback, GetCurrentThread(), argument) ||
                    state.delay(TRUE, &interval) != 0xC0) state.failed = true;
            };
            state.callback = callback;
            if (!QueueUserAPC(callback, GetCurrentThread(), reinterpret_cast<ULONG_PTR>(&state))) return 14;
            LARGE_INTEGER interval{};
            interval.QuadPart = -100000;
            auto delayed = state.delay(TRUE, &interval);
            PROCESS_BASIC_INFORMATION information{};
            ULONG length = 0;
            auto queried = query(GetCurrentProcess(), ProcessBasicInformation, &information,
                sizeof(information), &length);
            VirtualFree(code, 0, MEM_RELEASE);
            return delayed == (apcBreak ? 0x10293847 : 0xC0) && !state.failed &&
                state.completed == (nestedApc ? 2u : 1u) && queried == 0 && length == sizeof(information) &&
                information.UniqueProcessId == GetCurrentProcessId() ? 0 : 15;
        }

        // A return breakpoint can replace the kernel's error before the caller observes it.
        if (argc > 1 && !_wcsicmp(argv[1], L"--cursor-break"))
        {
            SetLastError(0x31415926);
            auto rejected = cursor(nullptr);
            auto error = GetLastError();
            VirtualFree(code, 0, MEM_RELEASE);
            return !rejected && error == 0x27182818 ? 0 : 13;
        }
        std::atomic<int> failure = 0;
        std::atomic<DWORD> cursorFailureError = 0;
        std::vector<std::jthread> threads;
        for (int index = 0; index < 4; ++index)
        {
            threads.emplace_back([&, index]()
            {
                wchar_t temporary[MAX_PATH];
                GetTempPathW(MAX_PATH, temporary);
                auto name = std::wstring(temporary) + L"Detourist.Syscall." + std::to_wstring(GetCurrentProcessId()) +
                    L"." + std::to_wstring(index) + L".tmp";
                Handle output(CreateFileW(name.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr));
                if (!output)
                {
                    fwprintf(stderr, L"CreateFileW failed (%lu): %s\n", GetLastError(), name.c_str());
                    failure = 5;
                    return;
                }
                std::array<char, 256> buffer;
                buffer.fill(static_cast<char>('A' + index));
                for (int iteration = 0; iteration < iterations; ++iteration)
                {
                    IO_STATUS_BLOCK status{};
                    SetLastError(0x31415926);
                    auto written = write(output.get(), nullptr, nullptr, nullptr, &status, buffer.data(),
                        static_cast<ULONG>(buffer.size()), nullptr, nullptr);
                    auto writeError = GetLastError();
                    if (written < 0 || status.Information != buffer.size() || writeError != 0x31415926)
                    {
                        fprintf(stderr, "Private write failed: status=%08X bytes=%llu error=%08lX\n",
                            static_cast<unsigned>(written), status.Information, writeError);
                        failure = 6;
                        break;
                    }
                    PROCESS_BASIC_INFORMATION information{};
                    ULONG length = 0;
                    auto queried = query(GetCurrentProcess(), ProcessBasicInformation, &information,
                        sizeof(information), &length);
                    auto queryError = GetLastError();
                    if (queried < 0 || length != sizeof(information) ||
                        information.UniqueProcessId != GetCurrentProcessId() || queryError != 0x31415926)
                    {
                        fprintf(stderr, "Private query failed: status=%08X bytes=%lu pid=%llu error=%08lX\n",
                            static_cast<unsigned>(queried), length, information.UniqueProcessId, queryError);
                        failure = 7;
                        break;
                    }
                    RECT clip{LONG_MIN, LONG_MIN, LONG_MIN, LONG_MIN};
                    auto positioned = cursor(&clip);
                    auto cursorError = GetLastError();
                    if (!positioned || clip.left == LONG_MIN || clip.top == LONG_MIN ||
                        clip.right <= clip.left || clip.bottom <= clip.top || cursorError != 0x31415926)
                    {
                        fprintf(stderr, "Private cursor clip failed: result=%d error=%08lX\n",
                            positioned, cursorError);
                        failure = 11;
                        break;
                    }
                    if (cursor(nullptr))
                    {
                        failure = 12;
                        break;
                    }
                    cursorFailureError = GetLastError();
                    if (paced) Sleep(4);
                }
            });
        }
        threads.clear();
        VirtualFree(code, 0, MEM_RELEASE);
        if (!failure) printf("Private syscall fixture passed. cursor_failure_error=%u\n", cursorFailureError.load());
        return failure;
    }
    catch (...) { return 8; }
}

struct SyscallCapture
{
    explicit SyscallCapture(const Context& value)
        : context(value), collector(value.collector, value.directory), hello(collector.Call("hello"))
    {
    }
    void Start(const std::wstring& arguments = L"", std::optional<uint64_t> mask = {}, uint32_t limit = 64,
               bool instructions = true, Json overrides = Json::object())
    {
        database = Launch(collector, context,
                          {.arguments = arguments, .limit = limit, .instructions = instructions, .apiMask = mask},
                          std::move(overrides));
    }
    Json Finish(bool exited = true, uint32_t exitCode = 0)
    {
        status = collector.Wait([](const Json& value) { return value["finished"] == true; });
        Require(exitCode || !status["message"].get<std::string>().contains("nonzero exit code"),
                "Syscall target failed", status);
        if (exited)
        {
            auto targets = collector.Call("page", {{"database", Text(database)}, {"limit", 1}})["targets"];
            Require(!targets.empty(), "Syscall capture has no targets", status);
            char expected[32] = "Exited";
            if (exitCode) sprintf_s(expected, "Exited (0x%08X)", exitCode);
            for (const auto& target : targets)
                Require(target["state"] == expected, "Syscall target exit differs", target);
        }
        return status;
    }
    void Collect(const std::wstring& arguments = L"", std::optional<uint64_t> mask = {}, uint32_t limit = 64,
                 bool instructions = true)
    {
        Start(arguments, mask, limit, instructions);
        Finish();
    }
    Json Calls(const std::string& name) const
    {
        auto rows =
            Query(database,
                  "SELECT c.*,COALESCE(d.name,a.name) name FROM calls c "
                  "LEFT JOIN apis a ON a.target=0 AND a.id=c.api LEFT JOIN apis d ON d.target=c.target AND d.id=c.api "
                  "WHERE COALESCE(d.name,a.name)=? ORDER BY c.id",
                  Json::array({name}));
        for (const auto& row : rows)
            Require(!row["ended"].is_null(), "Syscall call is incomplete", row);
        return rows;
    }
    Json Item(const std::string& name)
    {
        auto rows = collector.Call("page", {{"database", Text(database)}, {"api", name}, {"limit", 1}})["calls"];
        Require(!rows.empty(), "Syscall page is missing: " + name);
        return rows[0];
    }
    Json Details(const std::string& name)
    {
        auto row = Item(name);
        return collector.Call("details",
                              {{"database", Text(database)}, {"target", row["target"]}, {"callId", row["id"]}});
    }
    Json Stopped()
    {
        return collector.Wait([](const Json& value)
        { return value["breakpoint"] == true || value["finished"] == true; });
    }
    void Attach(const TargetProcess& target, uint64_t mask, uint32_t limit = 64)
    {
        database = context.directory / ("attach-" + std::to_string(GetTickCount64()) + ".sqlite");
        collector.Call("attach", {{"database", Text(database)},
                                  {"pid", target.Pid()},
                                  {"instructionEngine", true},
                                  {"apiMask", mask},
                                  {"bufferLimit", limit},
                                  {"followChildren", false}});
    }
    const Context& context;
    Collector collector;
    Json hello, status;
    Path database;
};

Bytes SyscallFile(const Path& path)
{
    auto bytes = ReadLog(path);
    return {bytes.begin(), bytes.end()};
}

void Touch(const Path& path)
{
    std::ofstream stream(path);
    Require(bool(stream), "Create syscall target signal: " + Text(path));
}

void AwaitFile(const TargetProcess& target, const Path& path, std::optional<uint64_t> size = {})
{
    // File length can be visible before the producer closes its exclusive handle.
    auto deadline = GetTickCount64() + 20000;
    while (!std::filesystem::exists(path) || (size && std::filesystem::file_size(path) != *size) ||
        !std::ifstream(path, std::ios::binary))
    {
        Require(target.Running() && GetTickCount64() < deadline, "Syscall target signal timed out: " + Text(path));
        Sleep(20);
    }
}

Value SyscallValue(const Json& payload, uint32_t parameter)
{
    // Independent wire decoding checks the same snapshot fields across syscall routes.
    return Only(Regions(payload, {.parameter = parameter}));
}

void UnknownSyscalls(SyscallCapture& capture)
{
    const auto& context = capture.context;
    RunTarget(context, L"--unknown-services");
    auto mask = Number(capture.hello["syscallMask"]);
    std::array names{"Syscall 12287", "Syscall 2147483647", "Syscall 4294967295"};
    Bytes wanted(128), results;
    for (size_t index = 0; index < wanted.size(); ++index)
        wanted[index] = static_cast<uint8_t>(index ^ 0xa3);
    for (size_t index = 0; index < 96; ++index)
    {
        auto result = Integer(0xc000001c, 4);
        results.insert(results.end(), result.begin(), result.end());
    }
    Json checks = Json::array(), selected;
    for (int scenario = 0; scenario < 3; ++scenario)
    {
        uint32_t limit = scenario ? 64 : 16;
        auto output = context.directory / L"unknown.bin";
        capture.Start(L"--unknown-services " + Quote(output), mask, limit, true,
                      {{"excludedApis", scenario == 2 ? Json::array({names[0]}) : Json::array()}});
        capture.Finish();
        Require(SyscallFile(output) == results, "Sparse syscall native results differ");
        for (auto name : names)
        {
            auto rows = capture.Calls(name);
            if (scenario == 2 && name == names[0])
            {
                Require(rows.empty(), "Excluded sparse syscall retained records", rows);
                continue;
            }
            std::set<uint64_t> threads;
            Require(rows.size() == 32, "Sparse syscall call count differs", rows.size());
            for (const auto& row : rows)
            {
                threads.insert(Number(row["tid"]));
                Require((row["flags"].get<uint32_t>() & 256) && Data(row["arguments"]).size() == 160 &&
                            uint32_t(Number(row["result"])) == 0xc000001c && Read<uint64_t>(row["arguments"], 8) == 128,
                        "Sparse syscall ABI or result differs", row);
                for (auto direction : {"input", "output"})
                    for (uint32_t parameter : {0u, 2u})
                    {
                        auto value = SyscallValue(row[direction], parameter);
                        Require(value.original == limit && value.data == Prefix(wanted, limit),
                                "Sparse syscall raw memory differs", row);
                    }
            }
            Require(threads.size() == 4, "Sparse syscall concurrent first calls missing");
            auto detail = capture.Details(name);
            Require(detail["arguments"].size() == 20 &&
                        detail["parameters"].get<std::string>().contains("Raw syscall argument slots"),
                    "Sparse syscall raw detail differs", detail);
            if (name == names[0]) selected = capture.Item(name)["api"];
            checks.push_back(
                {{"name", name}, {"limit", limit}, {"calls", rows.size()}, {"threads", 4}, {"rawArguments", 20}});
        }
    }

    // Sparse identities can stop at either boundary while their record filter is disabled.
    for (bool leaving : {false, true})
    {
        auto output = context.directory / L"unknown-break.bin";
        capture.Start(L"--unknown-services " + Quote(output), 0, 16, true,
                      {{leaving ? "exitApi" : "entryApi", selected}});
        auto state = capture.Stopped();
        Require(state["breakpoint"] == true && state["leaving"] == leaving &&
                    state["stoppedCall"]["name"] == names[0] && state["stoppedCall"]["arguments"].size() == 20,
                "Sparse syscall breakpoint differs", state);
        if (leaving)
            Require(uint32_t(Number(state["stoppedCall"]["result"], 16)) == 0xc000001c,
                    "Sparse syscall return breakpoint result differs", state);
        capture.collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
        capture.collector.Call("continue", {{"callId", state["stoppedCall"]["id"]}});
        capture.Finish();
        Require(SyscallFile(output) == results && capture.Calls(names[0]).empty(),
                "Filtered syscall breakpoint changed native results or retained records");
    }

    // Detach and reattach retire sparse bindings while an independently owned process remains alive.
    constexpr int sessions = 3;
    auto stem = context.directory / L"unknown-attach";
    TargetProcess target(context, L"--unknown-attach " + Quote(stem) + L" " + std::to_wstring(sessions));
    for (int index = 0; index < sessions; ++index)
    {
        auto prefix = Path(stem.wstring() + L"." + std::to_wstring(index));
        AwaitFile(target, prefix.wstring() + L".ready");
        capture.Attach(target, mask, 16);
        capture.collector.Wait([](const Json& value) { return value["capturing"] == true; });
        Touch(prefix.wstring() + L".go");
        auto output = Path(prefix.wstring() + L".bin");
        AwaitFile(target, output, 384);
        Require(SyscallFile(output) == results, "Reattached sparse syscall results differ");
        capture.collector.Call("stop");
        capture.Finish(false);
        Require(target.Running(), "Detaching terminated the independently launched syscall target");
        for (auto name : names)
            Require(capture.Calls(name).size() == 32, "Reattached sparse syscall count differs");
        Touch(prefix.wstring() + L".release");
    }
    Require(target.Wait() == 0, "Reattached sparse syscall workload failed");
    if (context.Has(L"--unknown-report"))
        WriteJson(context.Option(L"--unknown-report"), {{"checks", checks},
                                                        {"entryBreakpoint", true},
                                                        {"exitBreakpoint", true},
                                                        {"filteredBreakpoints", true},
                                                        {"targetResultsPreserved", true},
                                                        {"attachDetachSessions", sessions}});
}

void SdkLeafSyscalls(SyscallCapture& capture)
{
    auto baseline = RunTarget(capture.context, L"--sdk-leaf");
    std::regex pattern("leaf=(\\d+) size=23,47 color=([0-9A-F]+) key=([0-9A-F]+)");
    std::vector<std::pair<Bytes, Bytes>> outputs;
    for (std::sregex_iterator it(baseline.begin(), baseline.end(), pattern), end; it != end; ++it)
        outputs.emplace_back(Unhex((*it)[2]), Unhex((*it)[3]));
    Require(outputs.size() == 3 && outputs[0] == outputs[1] && outputs[0] == outputs[2] &&
                outputs[0].first.size() == 24 && outputs[0].second.size() == 64,
            "SDK leaf native baseline differs");
    struct Leaf
    {
        const char* native;
        const char* sdk;
        uint32_t count;
        const char* parameter;
        uint32_t output;
        Bytes wanted;
    };
    Bytes priorities;
    for (int repeat = 0; repeat < 8; ++repeat)
        for (uint32_t value : {13u, 1u, 8u, 17u})
        {
            auto bytes = Integer(value, 4);
            priorities.insert(priorities.end(), bytes.begin(), bytes.end());
        }
    std::array leaves{
        Leaf{"NtGdiGetBitmapDimension", "GetBitmapDimensionEx", 2, "lpsize", 1, {23, 0, 0, 0, 47, 0, 0, 0}},
        Leaf{"NtGdiGetMiterLimit", "GetMiterLimit", 2, "plimit", 1, Integer(std::bit_cast<uint32_t>(3.5f), 4)},
        Leaf{"NtGdiGetColorAdjustment", "GetColorAdjustment", 2, "lpca", 1, outputs[0].first},
        Leaf{"NtUserGetKeyNameText", "GetKeyNameTextW", 3, "lpString", 1, outputs[0].second},
        Leaf{"NtUserGetPriorityClipboardFormat", "GetPriorityClipboardFormat", 2, "paFormatPriorityList", 0,
             priorities}};
    Json details = Json::array();
    for (bool instructions : {false, true})
        for (uint32_t limit : {16u, 64u})
        {
            capture.Collect(L"--sdk-leaf", {}, limit, instructions);
            for (const auto& leaf : leaves)
            {
                std::vector<std::string> names{leaf.sdk, leaf.native};
                if (instructions) names.push_back(std::string(leaf.native) + " [syscall]");
                for (const auto& name : names)
                {
                    auto rows = capture.Calls(name);
                    Require(!rows.empty(), "SDK leaf route missing: " + name);
                    for (const auto& row : rows)
                    {
                        Require(!(row["flags"].get<uint32_t>() & 256) &&
                                    Data(row["arguments"]).size() == leaf.count * 8,
                                "SDK leaf ABI differs", row);
                        auto value = SyscallValue(row[leaf.output ? "output" : "input"], leaf.output);
                        Require(value.original == leaf.wanted.size() && value.data == Prefix(leaf.wanted, limit) &&
                                    bool(value.flags & 1) == (leaf.wanted.size() > limit),
                                "SDK leaf bounded snapshot differs", row);
                    }
                }
                auto detail = capture.Details(instructions ? leaf.native : leaf.sdk);
                Require(detail["parameters"].get<std::string>().contains(leaf.parameter),
                        "SDK leaf parameter name missing", detail);
                if (instructions && limit == 64) details.push_back(detail);
            }
            for (auto name : instructions ? std::vector<std::string>{"CreateCaret", "NtUserCreateCaret",
                                                                     "NtUserCreateCaret [syscall]"}
                                          : std::vector<std::string>{"CreateCaret", "NtUserCreateCaret"})
            {
                auto rows = capture.Calls(name);
                Require(!rows.empty(), "Caret syscall route missing: " + name);
                for (const auto& row : rows)
                    Require(row["result"] != 0 && Data(row["arguments"]).size() == 32 &&
                                Read<uint64_t>(row["arguments"], 8) == 0 && Read<uint64_t>(row["arguments"], 16) == 3 &&
                                Read<uint64_t>(row["arguments"], 24) == 5,
                            "Caret syscall ABI differs", row);
            }
        }
    if (capture.context.Has(L"--sdk-leaf-details")) WriteJson(capture.context.Option(L"--sdk-leaf-details"), details);
}

void GraphicsSyscalls(SyscallCapture& capture)
{
    const auto& context = capture.context;

    // Inferred jump-only aliases preserve typed output through public, exported, and private routes.
    auto baseline = RunTarget(context, L"--sdk-forwarders");
    std::regex fontPattern("font=([0-9A-F,]+)");
    std::vector<std::string> fonts;
    for (std::sregex_iterator it(baseline.begin(), baseline.end(), fontPattern), end; it != end; ++it)
        fonts.push_back((*it)[1]);
    Require(fonts.size() == 3 && fonts[0] == fonts[1] && fonts[0] == fonts[2], "SDK font forwarder baseline differs");
    Bytes font;
    auto fields = Split(fonts[0], ',');
    Require(fields.size() == 6, "SDK font signature is incomplete");
    for (const auto& field : fields)
    {
        auto bytes = Integer(std::stoul(field, nullptr, 16), 4);
        font.insert(font.end(), bytes.begin(), bytes.end());
    }
    capture.Collect(L"--sdk-forwarders");
    for (auto [native, sdk, count, routes] :
         {std::tuple{"NtUserGetKeyboardState", "GetKeyboardState", 1u, std::array{2u, 3u, 4u}},
          {"NtUserGetKeyboardLayoutList", "GetKeyboardLayoutList", 2u, std::array{2u, 4u, 6u}},
          {"NtGdiGetTextCharsetInfo", "GetTextCharsetInfo", 3u, std::array{1u, 2u, 3u}}})
    {
        std::array<std::string, 3> names{sdk, native, std::string(native) + " [syscall]"};
        for (size_t route = 0; route < names.size(); ++route)
        {
            auto rows = capture.Calls(names[route]);
            Require(rows.size() == routes[route], "SDK forwarder route count differs: " + names[route], rows.size());
            for (const auto& row : rows)
            {
                Require(!(row["flags"].get<uint32_t>() & 256) && Data(row["arguments"]).size() == count * 8,
                        "SDK forwarder ABI differs", row);
                if (std::string_view(native) == "NtUserGetKeyboardState")
                {
                    auto value = SyscallValue(row["output"], 0);
                    Require(row["result"] != 0 && value.original == 256 && value.data.size() == 64 && (value.flags & 1),
                            "Keyboard state output differs", row);
                }
                else if (std::string_view(native) == "NtUserGetKeyboardLayoutList" &&
                         Read<uint64_t>(row["arguments"]) == 16)
                {
                    auto value = SyscallValue(row["output"], 1);
                    auto size = Number(row["result"]) * 8;
                    Require(size > 0 && value.original == size && value.data.size() == std::min<uint64_t>(size, 64) &&
                                bool(value.flags & 1) == (size > 64) && Read<uint64_t>(value.data) != 0,
                            "Keyboard layout array differs", row);
                }
                else if (std::string_view(native) == "NtGdiGetTextCharsetInfo")
                {
                    auto value = SyscallValue(row["output"], 1);
                    Require(value.original == 24 && value.data == font, "Font signature output differs", row);
                }
            }
        }
    }
    auto signature = capture.Details("NtGdiGetTextCharsetInfo");
    Require(signature["parameters"].get<std::string>().contains("FONTSIGNATURE") &&
                signature["parameters"].get<std::string>().contains("lpSig"),
            "Font signature parameter layout missing", signature);

    // SDK aliases share structure, array, and message plans through both native routes.
    RunTarget(context, L"--window-graphics");
    capture.Collect(L"--window-graphics");
    for (auto [base, count] : {std::pair{"NtGdiCreateCompatibleDC", 1u},
                               {"NtGdiGetRgnBox", 2u},
                               {"NtGdiMoveTo", 4u},
                               {"NtGdiLineTo", 3u},
                               {"NtGdiGetPath", 4u},
                               {"NtGdiSetBrushOrg", 4u},
                               {"NtUserPostThreadMessage", 4u}})
        for (bool syscall : {false, true})
        {
            auto name = std::string(base) + (syscall ? " [syscall]" : "");
            auto rows = capture.Calls(name);
            Require(rows.size() >= (syscall ? 2 : 1), "Window graphics route missing: " + name);
            size_t rejected = 0, accepted = 0;
            bool zeroPath = false;
            for (const auto& row : rows)
            {
                Require(!(row["flags"].get<uint32_t>() & 256) && Data(row["arguments"]).size() == count * 8,
                        "Window graphics ABI differs", row);
                bool failed = std::string_view(base) == "NtGdiGetPath" ? uint32_t(Number(row["result"])) == UINT32_MAX
                                                                       : row["result"] == 0;
                if (failed)
                {
                    ++rejected;
                    Require((row["flags"].get<uint32_t>() & 1) && Data(row["output"]).empty(),
                            "Failed window graphics output was captured", row);
                    continue;
                }
                ++accepted;
                Require(!(row["flags"].get<uint32_t>() & 1), "Successful graphics return was marked failed", row);
                if (std::string_view(base) == "NtGdiGetRgnBox")
                    Require(SyscallValue(row["output"], 1).data ==
                                    Bytes{5, 0, 0, 0, 7, 0, 0, 0, 29, 0, 0, 0, 31, 0, 0, 0} &&
                                row["result"] == 2,
                            "Region rectangle output differs", row);
                else if (std::string_view(base) == "NtGdiMoveTo" || std::string_view(base) == "NtGdiSetBrushOrg")
                    Require(SyscallValue(row["output"], 3).data.size() == 8 && row["result"] == 1,
                            "Graphics point output differs", row);
                else if (std::string_view(base) == "NtGdiGetPath")
                {
                    zeroPath |= row["result"] == 0;
                    if (row["result"] != 0)
                    {
                        auto points = SyscallValue(row["output"], 1), kinds = SyscallValue(row["output"], 2);
                        Require(points.original == 80 && points.data.size() == 64 && (points.flags & 1) &&
                                    row["result"] == 2 &&
                                    Starts(points.data, Bytes{13, 0, 0, 0, 17, 0, 0, 0, 19, 0, 0, 0, 23, 0, 0, 0}) &&
                                    kinds.original == 10 && Starts(kinds.data, Bytes{6, 2}),
                                "Graphics path output differs", row);
                    }
                }
                else if (std::string_view(base) == "NtUserPostThreadMessage")
                    Require(Read<uint64_t>(row["arguments"], 8) == 0x807b &&
                                Read<uint64_t>(row["arguments"], 16) == 0x12345678 &&
                                Read<uint64_t>(row["arguments"], 24) == 0x23456789 && row["result"] == 1,
                            "Graphics message arguments differ", row);
            }
            Require(rejected && accepted && (std::string_view(base) != "NtGdiGetPath" || zeroPath),
                    "Window graphics accepted/rejected coverage incomplete: " + name);
        }
    if (context.Has(L"--window-graphics-details"))
        WriteJson(context.Option(L"--window-graphics-details"), capture.Details("NtGdiGetRgnBox [syscall]"));

    RunTarget(context, L"--graphics");
    capture.Collect(L"--graphics");
    Json enumerationApi;
    struct Graphics
    {
        const char* suffix;
        uint32_t width;
        std::optional<bool> failed;
    };
    for (auto [suffix, width, failed] :
         {Graphics{"EnumAdapters2", 16, false}, {"QueryAdapterInfo", 24, {}}, {"QueryStatistics", 0, true}})
        for (bool syscall : {false, true})
        {
            auto name = std::string("NtGdiDdDDI") + suffix + (syscall ? " [syscall]" : "");
            auto rows = capture.Calls(name);
            Require(rows.size() >= (syscall ? 3 : 2), "Graphics thunk route missing: " + name);
            bool success = false, failure = false, readable = false, unreadable = false;
            for (const auto& row : rows)
            {
                auto flags = row["flags"].get<uint32_t>();
                Require(!(flags & 256) && (!failed || bool(flags & 1) == *failed) && Data(row["arguments"]).size() == 8,
                        "Graphics thunk ABI differs", row);
                success |= !(flags & 1);
                failure |= bool(flags & 1);
                auto before = SyscallValue(row["input"], 0);
                Require(before.data.size() == (width ? width : 64), "Graphics input structure size differs", row);
                if (width)
                    Require(SyscallValue(row["output"], 0).data.size() == width,
                            "Graphics output structure size differs", row);
                else
                    Require(Data(row["output"]).empty() && before.original > 64 && (before.flags & 1),
                            "Input-only graphics statistics capture differs", row);
                if (std::string_view(suffix) == "QueryAdapterInfo")
                {
                    auto member = SyscallValue(row["input"], 9u << 8);
                    readable |= member.data == Bytes(64, 0xac) && member.original == 256 && (member.flags & 17) == 17;
                    unreadable |= (member.flags & 18) == 18 && member.data.empty();
                }
                if (std::string_view(suffix) == "EnumAdapters2")
                {
                    auto array = SyscallValue(row["output"], 9u << 8);
                    auto count = Read<uint32_t>(SyscallValue(row["output"], 0).data);
                    Require(array.original == count * 20 && array.data.size() == std::min(64u, count * 20) &&
                                (array.flags & 16),
                            "Graphics adapter array differs", row);
                }
            }
            if (std::string_view(suffix) == "QueryAdapterInfo")
                Require(success && failure && readable && unreadable,
                        "Graphics adapter guarded coverage incomplete: " + name);
            auto detail = capture.Details(name);
            Require(detail["arguments"].size() == 1, "Graphics thunk argument detail differs", detail);
            if (std::string_view(suffix) == "EnumAdapters2" && syscall)
            {
                enumerationApi = capture.Item(name)["api"];
                if (context.Has(L"--graphics-details")) WriteJson(context.Option(L"--graphics-details"), detail);
            }
        }

    // A debugger edit cannot expand an array beyond the caller's entry capacity.
    capture.Start(L"--graphics", {}, 64, true, {{"exitApi", enumerationApi}});
    auto stopped = capture.collector.Wait([](const Json& value)
    { return value["finished"] == true || (value["breakpoint"] == true && value["leaving"] == true); });
    Require(stopped["breakpoint"] == true, "Graphics capacity return breakpoint missing", stopped);
    capture.collector.Call("writeMemory", {{"address", stopped["stoppedCall"]["arguments"][0]}, {"bytes", "e8030000"}});
    capture.collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
    capture.collector.Call("continue", {{"callId", stopped["stoppedCall"]["id"]}});
    capture.Finish(true, 74);
    auto edited = Only(Select(capture.Calls("NtGdiDdDDIEnumAdapters2 [syscall]"), [](const Json& row)
    { return Read<uint32_t>(SyscallValue(row["output"], 0).data) == 1000; }));
    auto array = SyscallValue(edited["output"], 9u << 8);
    Require(array.original == 64 * 20 && array.data.size() == 64 && (array.flags & 17) == 17,
            "Edited graphics count exceeded entry capacity", edited);
}

void PrivateSyscalls(SyscallCapture& capture, uint64_t cursorError)
{
    auto mask = Number(capture.hello["syscallMask"]);
    capture.Collect(L"", mask);
    Require(capture.status["calls"] == 256, "Private syscall event count differs", capture.status);
    auto writes = capture.Calls("NtWriteFile [syscall]"),
         queries = capture.Calls("NtQueryInformationProcess [syscall]");
    auto cursors = capture.Calls("NtUserGetClipCursor [syscall]");
    Require(writes.size() == 64 && queries.size() == 64 && cursors.size() == 128, "Private syscall API counts differ");
    std::set<uint64_t> threads;
    for (const auto& row : writes)
    {
        threads.insert(Number(row["tid"]));
        auto input = SyscallValue(row["input"], 5), output = SyscallValue(row["output"], 4);
        Require((row["flags"].get<uint32_t>() & 128) && !(row["flags"].get<uint32_t>() & 1) && row["result"] == 0 &&
                    input.original == 256 && input.data.size() == 64 && input.data[0] >= 'A' && input.data[0] <= 'D' &&
                    input.data == Bytes(64, input.data[0]) && output.data.size() == 16 &&
                    Read<uint64_t>(output.data, 8) == 256,
                "Private write arguments or output differ", row);
    }
    Require(threads.size() == 4, "Private syscall worker threads missing");
    for (const auto& row : queries)
        Require(row["result"] == 0 && SyscallValue(row["output"], 2).data.size() == 48 &&
                    std::ranges::any_of(writes, [&](const Json& write)
        { return Number(row["caller"]) - Number(write["caller"]) == 32; }),
                "Private query output or caller differs", row);
    size_t successfulCursors = 0;
    for (const auto& row : cursors)
    {
        auto flags = row["flags"].get<uint32_t>();
        Require((flags & 128) && std::ranges::any_of(writes, [&](const Json& write)
        { return Number(row["caller"]) - Number(write["caller"]) == 64; }),
                "Private cursor caller differs", row);
        if (row["result"] != 0)
        {
            ++successfulCursors;
            auto value = SyscallValue(row["output"], 0);
            Require(!(flags & 1) && row["error"] == 0x31415926 && value.original == 16 && value.data.size() == 16 &&
                        !value.flags && Read<int32_t>(value.data, 8) > Read<int32_t>(value.data) &&
                        Read<int32_t>(value.data, 12) > Read<int32_t>(value.data, 4),
                    "Private cursor success snapshot differs", row);
        }
        else
            Require((flags & 1) && row["error"] == cursorError && Data(row["output"]).empty(),
                    "Private cursor failure result differs", row);
    }
    Require(successfulCursors == 64, "Private cursor success count differs");
    auto detail = capture.Details("NtWriteFile [syscall]");
    Require(detail["arguments"].size() == 9 && detail["text"].get<std::string>().contains("64 of 256"),
            "Private write detail differs", detail);

    // Window-system return edits must update the target thread's restored error state.
    auto cursorApi = capture.Item("NtUserGetClipCursor [syscall]")["api"];
    capture.Start(L"--cursor-break", mask, 64, true, {{"exitApi", cursorApi}});
    auto state = capture.Stopped();
    if (state["breakpoint"] == true && Number(state["stoppedCall"]["arguments"][0], 16))
    {
        auto warmup = state["stoppedCall"]["id"];
        capture.collector.Call("continue", {{"callId", warmup}});
        state = capture.collector.Wait([&](const Json& value)
        { return value["finished"] == true || (value["breakpoint"] == true && value["stoppedCall"]["id"] != warmup); });
    }
    Require(state["breakpoint"] == true && state["leaving"] == true && state["stoppedCall"]["error"] == cursorError,
            "Cursor return breakpoint error differs", state);
    capture.collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
    capture.collector.Call("continue", {{"callId", state["stoppedCall"]["id"]}, {"error", 0x27182818}});
    capture.Finish();
    auto edited = Only(capture.Calls("NtUserGetClipCursor [syscall]"));
    Require((edited["flags"].get<uint32_t>() & 16) && edited["error"] == 0x27182818,
            "Cursor error edit was not retained", edited);

    // Alertable waits retain their returns across APCs that invoke further private syscalls.
    for (auto mode : {L"--apc", L"--apc-nested"})
    {
        RunTarget(capture.context, mode);
        capture.Collect(mode, mask);
        bool nested = std::wstring_view(mode) == L"--apc-nested";
        Require(capture.status["calls"] == (nested ? 5 : 3), "APC syscall count differs", capture.status);
        auto delayed = capture.Calls("NtDelayExecution [syscall]");
        queries = capture.Calls("NtQueryInformationProcess [syscall]");
        Require(delayed.size() == (nested ? 2 : 1) && queries.size() == (nested ? 3 : 2), "APC nesting count differs");
        uint64_t lastDelay = 0, lastQuery = 0;
        for (const auto& row : delayed)
        {
            Require(row["result"] == 0xc0 && !(row["flags"].get<uint32_t>() & 5), "APC wait result differs", row);
            lastDelay = std::max(lastDelay, Number(row["ended"]));
        }
        for (const auto& row : queries)
        {
            Require(row["result"] == 0 && SyscallValue(row["output"], 2).data.size() == 48,
                    "Nested APC query output differs", row);
            lastQuery = std::max(lastQuery, Number(row["ended"]));
        }
        Require(lastQuery > lastDelay, "APC query completion preceded its resumed wait");
    }
    auto delayApi = capture.Item("NtDelayExecution [syscall]")["api"];
    capture.Start(L"--apc-break", mask, 64, true, {{"exitApi", delayApi}});
    state = capture.Stopped();
    Require(state["breakpoint"] == true && state["leaving"] == true &&
                Number(state["stoppedCall"]["result"], 16) == 0xc0,
            "APC resumed return breakpoint differs", state);
    capture.collector.Call("breakApi", {{"entryApi", -1}, {"exitApi", -1}});
    capture.collector.Call("continue", {{"callId", state["stoppedCall"]["id"]}, {"result", "0x10293847"}});
    capture.Finish();
    edited = Only(capture.Calls("NtDelayExecution [syscall]"));
    Require(edited["result"] == 0x10293847 && (edited["flags"].get<uint32_t>() & 16),
            "APC return edit was not retained", edited);
    queries = capture.Calls("NtQueryInformationProcess [syscall]");
    Require(queries.size() == 2, "Edited APC query count differs");
    for (const auto& row : queries)
        Require(row["result"] == 0, "APC return edit changed a nested query", row);
}

void ContextSyscalls(SyscallCapture& capture)
{
    const auto& context = capture.context;
    std::set<uint64_t> masks;
    std::set<std::string> names{"GetThreadContext", "SetThreadContext", "NtGetContextThread", "NtSetContextThread"};
    for (const auto& api : capture.hello["catalog"])
        if (names.contains(api["name"].get<std::string>())) masks.insert(Number(api["mask"]));
    uint64_t mask = 0;
    for (auto value : masks)
        mask += value;

    // Kernel validation remains authoritative for null, unreadable, and partial context pointers.
    auto baseline = context.directory / L"invalid-baseline.bin", report = context.directory / L"invalid-traced.bin";
    RunTarget(context, L"--invalid-contexts " + Quote(baseline));
    capture.Collect(L"--invalid-contexts " + Quote(report), mask);
    Require(SyscallFile(report) == SyscallFile(baseline),
            "Context pointer validation differs from the untraced kernel result");
    auto rejected = capture.Calls("NtSetContextThread [syscall]");
    Require(rejected.size() == 6, "Invalid context call count differs");
    for (const auto& row : rejected)
        Require(row["flags"].get<uint32_t>() & 1, "Invalid context result lacks failure flag", row);
    for (auto [mode, iterations, gets, sets] : {std::tuple{L"--contexts", 128, 258u, 256u},
                                                {L"--contexts-partial", 128, 514u, 256u},
                                                {L"--contexts-edits", 64, 386u, 256u}})
    {
        auto arguments = std::wstring(mode) + L" " + std::to_wstring(iterations);
        RunTarget(context, arguments);
        capture.Collect(arguments + L" " + Quote(report), mask);
        Require(SyscallFile(report) == Bytes(4), "Native context restoration failed");
        for (auto [name, result] : {std::pair{"GetThreadContext", 1},
                                    {"SetThreadContext", 1},
                                    {"NtGetContextThread", 0},
                                    {"NtSetContextThread", 0},
                                    {"NtGetContextThread [syscall]", 0},
                                    {"NtSetContextThread [syscall]", 0}})
        {
            auto completed = Select(capture.Calls(name), [&](const Json& row)
            { return row["result"] == result && !(row["flags"].get<uint32_t>() & 5); });
            Require(completed.size() == (std::string_view(name).contains("Get") ? gets : sets),
                    "Restored context count differs: " + std::string(name), completed.size());
        }
    }

    // Continuations and cross-thread edits preserve stepped instructions through launch and attach.
    for (auto mode : {L"--single-step", L"--single-step-context", L"--single-step-writable"})
    {
        auto arguments = std::wstring(mode) + L" 32";
        RunTarget(context, arguments);
        for (auto [instructions, enabled] : {std::pair{false, true}, {true, true}, {true, false}})
        {
            auto selected = enabled ? Number(capture.hello["allApis"]) : 0;
            capture.Collect(arguments + L" " + Quote(report), selected, 64, instructions);
            Require(SyscallFile(report) == Bytes(4) && (capture.status["calls"] > 0) == enabled,
                    "Stepped instruction state or capture filter differs", capture.status);
            auto targets =
                capture.collector.Call("page", {{"database", Text(capture.database)}, {"limit", 1}})["targets"];
            for (const auto& target : targets)
                Require(target["moduleRefreshError"] == 0, "Stepped target module refresh failed", target);
        }
        auto attached = context.directory / L"step-attach.bin";
        std::filesystem::remove(attached.wstring() + L".ready");
        std::filesystem::remove(attached.wstring() + L".go");
        TargetProcess target(context, arguments + L" " + Quote(attached) + L" --wait");
        AwaitFile(target, attached.wstring() + L".ready");
        capture.Attach(target, Number(capture.hello["allApis"]));
        auto state = capture.collector.Wait([](const Json& value)
        { return value["capturing"] == true || value["finished"] == true; });
        Require(state["capturing"] == true, "Single-step attachment did not start", state);
        Touch(attached.wstring() + L".go");
        Require(target.Wait(30000) == 0 && SyscallFile(attached) == Bytes(4),
                "Attached single-step target lost its state");
        capture.Finish();
    }

    // Stopping instruction tracing leaves the independently launched paced process alive.
    TargetProcess target(context, L"--paced 800");
    capture.Attach(target, Number(capture.hello["syscallMask"]));
    capture.collector.Wait([](const Json& value) { return value["capturing"] == true && value["calls"] >= 64; });
    capture.collector.Call("stop");
    auto status = capture.Finish(false);
    auto message = status["message"].get<std::string>();
    std::ranges::transform(message, message.begin(), [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    Require(target.Running() && !message.contains("stopped:") && target.Wait() == 0 &&
                !capture.Calls("NtWriteFile [syscall]").empty() &&
                !capture.Calls("NtUserGetClipCursor [syscall]").empty(),
            "Stopping tracing changed the independent workload lifetime", status);
}

void Syscall(const Context& context)
{
    auto baseline = RunTarget(context);
    std::smatch cursor;
    Require(std::regex_search(baseline, cursor, std::regex("cursor_failure_error=(\\d+)")),
            "Syscall cursor baseline missing");
    auto cursorError = std::stoull(cursor[1]);
    Require(cursorError != 0x31415926, "Native cursor failure did not change last error");
    SyscallCapture capture(context);
    RunTarget(context, L"--pending-read");
    capture.Collect(L"--pending-read", Number(capture.hello["syscallMask"]));

    // An observed completion replaces the pending state with the data delivered to the submitted buffer.
    auto pending =
        Only(Select(capture.Calls("NtReadFile [syscall]"), [](const Json& row) { return row["result"] == 0x103; }));
    auto flags = pending["flags"].get<uint32_t>();
    auto buffer = Regions(pending["output"], {.parameter = 5});
    Require((flags & (1u << 18)) && !(flags & (1 | 8 | 256)) && buffer.size() == 1 && !buffer[0].data.empty() &&
                std::ranges::all_of(buffer[0].data, [](uint8_t value) { return value == 0x6B; }),
            "Pending syscall did not record its completed output", pending);
    UnknownSyscalls(capture);
    if (!context.Has(L"--unknown-only"))
    {
        SdkLeafSyscalls(capture);
        if (!context.Has(L"--sdk-leaf-only"))
        {
            GraphicsSyscalls(capture);
            PrivateSyscalls(capture, cursorError);
            ContextSyscalls(capture);
        }
    }
    capture.collector.Close();
}

int wmain(int argc, wchar_t** argv) { return Run<TargetMain>(argc, argv, Syscall); }

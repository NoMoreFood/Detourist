#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "Agent.h"
#include <algorithm>

extern "C" IMAGE_DOS_HEADER __ImageBase;
extern "C" __declspec(dllexport) volatile LONG64 DetouristStackImageEpoch = 1;

namespace Detourist
{
void InvalidateStackImageCache() noexcept
{
    InterlockedIncrement64(&DetouristStackImageEpoch);
}

constexpr uint32_t MaxWalkDepth = MaximumStack * 3;
constexpr size_t CachedStackImageCount = 32;
#ifdef _WIN64
constexpr size_t DynamicStackTableCapacity = 256;
constexpr size_t CallbackStackFunctionCapacity = 512;
constexpr uint32_t MaxFunctionTableScan = 4096;
constexpr LONG MaxDosHeaderOffset = 1024 * 1024;
constexpr size_t UnorderedScanBatch = 32;
constexpr uint32_t UnorderedScanLimit = 1024;
constexpr size_t MaxUnwindChainDepth = 64;
constexpr size_t MaxUnwindCodeBytes = 512;
constexpr size_t StackImageCacheSize = 8;
// The pinned observer's query bounds remain usable when its image headers are protected by the application.
const auto StackObserverImage = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
    reinterpret_cast<const uint8_t*>(&__ImageBase) + __ImageBase.e_lfanew)->OptionalHeader;

struct DynamicStackTable
{
    void* key;
    PRUNTIME_FUNCTION functions;
    uint64_t base;
    uint32_t count, bytes;
    bool growable;
};
struct CallbackStackFunction
{
    void* key;
    uint64_t base;
    RUNTIME_FUNCTION function;
};
DynamicStackTable DynamicStackTables[DynamicStackTableCapacity]{};
CallbackStackFunction CallbackStackFunctions[CallbackStackFunctionCapacity]{};
uint32_t NextCallbackStackFunction = 0;
volatile LONG64 DynamicStackGeneration = 0;
SRWLOCK DynamicStackLock = SRWLOCK_INIT;
[[msvc::no_tls_guard]] constinit thread_local bool RetiringDynamicStack = false;
decltype(&RtlLookupFunctionEntry) OriginalRtlLookupFunctionEntry = &RtlLookupFunctionEntry;
bool ReadStackMemory(const void* source, void* destination, size_t bytes);
decltype(&RtlAddFunctionTable) OriginalRtlAddFunctionTable = &RtlAddFunctionTable;
decltype(&RtlDeleteFunctionTable) OriginalRtlDeleteFunctionTable = &RtlDeleteFunctionTable;
decltype(&RtlAddGrowableFunctionTable) OriginalRtlAddGrowableFunctionTable = &RtlAddGrowableFunctionTable;
decltype(&RtlGrowFunctionTable) OriginalRtlGrowFunctionTable = &RtlGrowFunctionTable;
decltype(&RtlDeleteGrowableFunctionTable) OriginalRtlDeleteGrowableFunctionTable = &RtlDeleteGrowableFunctionTable;

void RegisterStackTable(DynamicStackTable table)
{
    AcquireSRWLockExclusive(&DynamicStackLock);
    auto entry = std::find_if(std::begin(DynamicStackTables), std::end(DynamicStackTables), [&](const auto& value)
    {
        return value.key == table.key && value.growable == table.growable;
    });
    if (entry == std::end(DynamicStackTables))
        entry = std::find_if(std::begin(DynamicStackTables), std::end(DynamicStackTables),
            [](const auto& value) { return !value.key; });
    if (entry != std::end(DynamicStackTables)) *entry = table;
    ReleaseSRWLockExclusive(&DynamicStackLock);
}

void RetireStackTable(void* key, bool growable)
{
    // Wait for active walks before the application can free its registered metadata.
    InterlockedIncrement64(&DynamicStackGeneration);
    for (auto& entry : DynamicStackTables)
        if (entry.key == key && entry.growable == growable) entry = {};
    if (!growable)
        for (auto& entry : CallbackStackFunctions)
            if (entry.key == key) entry = {};
}

BOOLEAN NTAPI HookRtlAddFunctionTable(PRUNTIME_FUNCTION functions, DWORD count, DWORD64 base)
{
    const auto result = OriginalRtlAddFunctionTable(functions, count, base);
    if (result) RegisterStackTable({functions, functions, base, count, UINT32_MAX, false});
    return result;
}

BOOLEAN NTAPI HookRtlDeleteFunctionTable(PRUNTIME_FUNCTION functions)
{
    // Native deletion can re-enter a table-deletion hook while this thread already owns the retirement lock.
    const bool nested = RetiringDynamicStack;
    if (!nested) AcquireSRWLockExclusive(&DynamicStackLock);
    RetiringDynamicStack = true;
    BOOLEAN result = FALSE;
    __try
    {
        RetireStackTable(functions, false);
        result = OriginalRtlDeleteFunctionTable(functions);
    }
    __finally
    {
        RetiringDynamicStack = nested;
        if (!nested) ReleaseSRWLockExclusive(&DynamicStackLock);
    }
    return result;
}

DWORD NTAPI HookRtlAddGrowableFunctionTable(void** handle, PRUNTIME_FUNCTION functions,
    DWORD count, DWORD maximum, ULONG_PTR base, ULONG_PTR end)
{
    const auto result = OriginalRtlAddGrowableFunctionTable(handle, functions, count, maximum, base, end);
    void* key = nullptr;
    if (!result && end > base && ReadCaptureMemory(handle, &key, sizeof(key)) && key)
        RegisterStackTable({key, functions, base, count,
            static_cast<uint32_t>(std::min<uint64_t>(end - base, UINT32_MAX)), true});
    return result;
}

void NTAPI HookRtlGrowFunctionTable(void* handle, DWORD count)
{
    OriginalRtlGrowFunctionTable(handle, count);
    AcquireSRWLockExclusive(&DynamicStackLock);
    for (auto& entry : DynamicStackTables)
        if (entry.key == handle && entry.growable) entry.count = count;
    ReleaseSRWLockExclusive(&DynamicStackLock);
}

void NTAPI HookRtlDeleteGrowableFunctionTable(void* handle)
{
    const bool nested = RetiringDynamicStack;
    if (!nested) AcquireSRWLockExclusive(&DynamicStackLock);
    RetiringDynamicStack = true;
    __try
    {
        RetireStackTable(handle, true);
        OriginalRtlDeleteGrowableFunctionTable(handle);
    }
    __finally
    {
        RetiringDynamicStack = nested;
        if (!nested) ReleaseSRWLockExclusive(&DynamicStackLock);
    }
}

PRUNTIME_FUNCTION NTAPI HookRtlLookupFunctionEntry(DWORD64 pc, PDWORD64 image, PUNWIND_HISTORY_TABLE history)
{
    const auto generation = InterlockedCompareExchange64(&DynamicStackGeneration, 0, 0);
    const auto result = OriginalRtlLookupFunctionEntry(pc, image, history);
    if (!NativeThreadReady() || ObserverActive || RetiringDynamicStack ||
        !TryAcquireSRWLockExclusive(&DynamicStackLock)) return result;
    const auto error = GetLastError();
    const auto status = NativeThreadStatus();
    ObserverActive = true;
    __try
    {
        // Observe only completed application lookups, without holding our lock over application callbacks.
        if (generation != InterlockedCompareExchange64(&DynamicStackGeneration, 0, 0)) __leave;
        const auto head = RtlGetFunctionTableListHead();
        LIST_ENTRY links{};
        auto cursor = head && ReadStackMemory(head, &links, sizeof(links)) ? links.Flink : nullptr;
        for (uint32_t attempt = 0; cursor && cursor != head && attempt < MaxFunctionTableScan; ++attempt)
        {
            DYNAMIC_FUNCTION_TABLE table{};
            if (!ReadStackMemory(cursor, &table, offsetof(DYNAMIC_FUNCTION_TABLE, TreeNodeMin))) break;
            const auto previous = cursor;
            cursor = table.ListEntry.Flink;
            LIST_ENTRY next{};
            if (!cursor || !ReadStackMemory(cursor, &next, sizeof(next)) || next.Blink != previous) break;
            if (table.Type != RF_CALLBACK || !table.FunctionTable || pc < table.MinimumAddress ||
                pc >= table.MaximumAddress || table.BaseAddress > table.MinimumAddress ||
                table.MaximumAddress - table.BaseAddress > UINT32_MAX) continue;

            // A null or changed lookup invalidates any cached entry covering this instruction.
            uint64_t base = 0;
            RUNTIME_FUNCTION function{};
            const auto valid = result && ReadStackMemory(image, &base, sizeof(base)) && base == table.BaseAddress &&
                ReadStackMemory(result, &function, sizeof(function)) && function.BeginAddress < function.EndAddress &&
                function.BeginAddress <= pc - base && pc - base < function.EndAddress &&
                function.EndAddress <= table.MaximumAddress - base;
            for (auto& entry : CallbackStackFunctions)
                if (entry.key == table.FunctionTable && entry.base == table.BaseAddress &&
                    (pc - entry.base >= entry.function.BeginAddress && pc - entry.base < entry.function.EndAddress ||
                    valid && function.BeginAddress < entry.function.EndAddress &&
                        entry.function.BeginAddress < function.EndAddress)) entry = {};
            if (valid)
            {
                auto slot = std::find_if(std::begin(CallbackStackFunctions), std::end(CallbackStackFunctions),
                    [](const auto& entry) { return !entry.key; });
                if (slot == std::end(CallbackStackFunctions))
                    slot = &CallbackStackFunctions[NextCallbackStackFunction++ % std::size(CallbackStackFunctions)];
                *slot = {table.FunctionTable, base, function};
            }
            break;
        }
    }
    __finally
    {
        ReleaseSRWLockExclusive(&DynamicStackLock);
        ObserverActive = false;
        SetLastError(error);
        RestoreNativeThreadStatus(status);
    }
    return result;
}

bool IsStackHook(void* observer)
{
    return observer == reinterpret_cast<void*>(&HookRtlLookupFunctionEntry) ||
        observer == reinterpret_cast<void*>(&HookRtlAddFunctionTable) ||
        observer == reinterpret_cast<void*>(&HookRtlDeleteFunctionTable) ||
        observer == reinterpret_cast<void*>(&HookRtlAddGrowableFunctionTable) ||
        observer == reinterpret_cast<void*>(&HookRtlGrowFunctionTable) ||
        observer == reinterpret_cast<void*>(&HookRtlDeleteGrowableFunctionTable);
}

void AddStackHooks(std::vector<HookDefinition>& hooks)
{
    // Table registrations and application lookups are observed without initiating callback execution.
#define STACK_HOOK(name) hooks.push_back({Api::Count, reinterpret_cast<void**>(&Original##name), \
    reinterpret_cast<void*>(&Hook##name)});
    STACK_HOOK(RtlLookupFunctionEntry)
    STACK_HOOK(RtlAddFunctionTable)
    STACK_HOOK(RtlDeleteFunctionTable)
    STACK_HOOK(RtlAddGrowableFunctionTable)
    STACK_HOOK(RtlGrowFunctionTable)
    STACK_HOOK(RtlDeleteGrowableFunctionTable)
#undef STACK_HOOK
}

bool ReadStackMemory(const void* source, void* destination, size_t bytes)
{
    return ReadGuardedCaptureMemory(source, destination, bytes);
}

bool ReadStackImage(uint64_t pc, uint64_t& base, uint32_t& bytes, IMAGE_DATA_DIRECTORY& functions,
    MEMORY_BASIC_INFORMATION& region)
{
    if (pc - reinterpret_cast<uint64_t>(region.BaseAddress) >= region.RegionSize)
    {
        // Query the pinned observer's code from its start so earlier callers reuse the same checked region.
        const auto self = reinterpret_cast<uint64_t>(&__ImageBase);
        if (pc - self < StackObserverImage.SizeOfImage &&
            !VirtualQuery(reinterpret_cast<void*>(self + StackObserverImage.BaseOfCode), &region, sizeof(region)))
            region = {};
    }
    if ((pc - reinterpret_cast<uint64_t>(region.BaseAddress) >= region.RegionSize &&
        !VirtualQuery(reinterpret_cast<void*>(pc), &region, sizeof(region))) || region.State != MEM_COMMIT ||
        region.Protect & (PAGE_GUARD | PAGE_NOACCESS) ||
        !(region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    if (region.Type != MEM_IMAGE) { base = 0; return true; }
    const auto allocation = reinterpret_cast<uint64_t>(region.AllocationBase);
    if (base == allocation && pc - base < bytes) return true;
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 image{};
    if (!ReadCaptureMemory(region.AllocationBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < 0 || dos.e_lfanew > MaxDosHeaderOffset ||
        !ReadCaptureMemory(reinterpret_cast<void*>(allocation + dos.e_lfanew), &image, sizeof(image)) ||
        image.Signature != IMAGE_NT_SIGNATURE || image.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        image.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        image.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION ||
        pc - allocation >= image.OptionalHeader.SizeOfImage) return false;
    base = allocation;
    bytes = image.OptionalHeader.SizeOfImage;
    functions = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    return functions.VirtualAddress <= bytes && functions.Size <= bytes - functions.VirtualAddress &&
        functions.Size % sizeof(RUNTIME_FUNCTION) == 0;
}

bool StackFunction(uint64_t pc, uint64_t base, uint32_t bytes, uint64_t functions, uint32_t count,
    RUNTIME_FUNCTION& function, bool& leaf, bool guarded = false, bool unordered = false, bool* pureRspOut = nullptr)
{
    if (pureRspOut) *pureRspOut = true;
    auto read = [guarded](const void* source, void* destination, size_t length)
    {
        return guarded ? ReadStackMemory(source, destination, length) : ReadCaptureMemory(source, destination, length);
    };
    auto low = 0u;
    auto high = count;
    const auto offset = pc - base;
    leaf = true;
    while (low < high)
    {
        auto middle = low + (high - low) / 2;
        const auto address = functions + uint64_t{middle} * sizeof(function);
        if (address < functions || !read(reinterpret_cast<void*>(address), &function, sizeof(function)))
            return false;
        if (offset < function.BeginAddress) high = middle;
        else if (offset >= function.EndAddress) low = middle + 1;
        else { leaf = false; break; }
    }
    if (leaf && unordered)
    {
        // Fixed tables can be unsorted; bound the fallback so arbitrary metadata cannot stall observation.
        RUNTIME_FUNCTION entries[UnorderedScanBatch];
        const auto limit = std::min(count, UnorderedScanLimit);
        for (uint32_t index = 0; leaf && index < limit; index += static_cast<uint32_t>(std::size(entries)))
        {
            const auto length = std::min<uint32_t>(limit - index, static_cast<uint32_t>(std::size(entries)));
            const auto address = functions + uint64_t{index} * sizeof(function);
            if (address < functions || !read(reinterpret_cast<void*>(address), entries, length * sizeof(function)))
                return false;
            for (uint32_t entry = 0; entry < length; ++entry)
                if (offset >= entries[entry].BeginAddress && offset < entries[entry].EndAddress)
                {
                    function = entries[entry];
                    leaf = false;
                    break;
                }
        }
    }
    if (leaf) return true;

    // Validate unwind chains before entering ntdll; registered lookup callbacks are never invoked.
    uint32_t visited[MaxUnwindChainDepth]{};
    for (uint32_t depth = 0; depth < std::size(visited); ++depth)
    {
        if (function.BeginAddress >= function.EndAddress || function.EndAddress > bytes) return false;
        if (!(function.UnwindData & 1)) break;
        auto indirect = function.UnwindData & ~1u;
        if (indirect > bytes || sizeof(function) > bytes - indirect) return false;
        for (uint32_t index = 0; index < depth; ++index) if (visited[index] == indirect) return false;
        visited[depth] = indirect;
        if (!read(reinterpret_cast<void*>(base + indirect), &function, sizeof(function))) return false;
        if (depth + 1 == std::size(visited)) return false;
    }
    auto unwind = function.UnwindData;
    for (uint32_t depth = 0; depth < std::size(visited); ++depth)
    {
        if (unwind > bytes || 4 > bytes - unwind) return false;
        for (uint32_t index = 0; index < depth; ++index) if (visited[index] == unwind) return false;
        visited[depth] = unwind;
        uint8_t header[4]{};
        if (!read(reinterpret_cast<void*>(base + unwind), header, sizeof(header)) ||
            (header[0] & 7) < 1 || (header[0] & 7) > 2) return false;
        if (pureRspOut && (header[3] & 0x0Fu)) *pureRspOut = false;
        const auto tail = uint64_t{unwind} + 4 + ((header[2] + 1u) & ~1u) * 2;
        if (tail > bytes) return false;
        const auto codeBytes = static_cast<size_t>(tail - unwind - 4);
        if (guarded || (pureRspOut && *pureRspOut && codeBytes))
        {
            uint8_t codes[MaxUnwindCodeBytes];
            if (!read(reinterpret_cast<void*>(base + unwind + 4), codes, codeBytes))
            {
                if (guarded) return false;
                if (pureRspOut) *pureRspOut = false;
            }
            else if (pureRspOut && *pureRspOut)
            {
                for (uint32_t codeIndex = 0; codeIndex < header[2]; ++codeIndex)
                {
                    const auto op = codes[codeIndex * 2 + 1] & 0x0Fu;
                    if (op == 3 || op == 10) { *pureRspOut = false; break; }
                    if (op == 1) codeIndex += (codes[codeIndex * 2 + 1] >> 4) ? 2u : 1u;
                    else if (op == 4 || op == 8) ++codeIndex;
                    else if (op == 5 || op == 9) codeIndex += 2u;
                }
            }
        }
        if (!(header[0] >> 3 & UNW_FLAG_CHAININFO)) return true;
        RUNTIME_FUNCTION chained{};
        if (sizeof(chained) > bytes - tail ||
            !read(reinterpret_cast<void*>(base + tail), &chained, sizeof(chained)) ||
            chained.BeginAddress >= chained.EndAddress || chained.EndAddress > bytes || chained.UnwindData & 1)
            return false;
        unwind = chained.UnwindData;
    }
    return false;
}

bool UnwindStackTable(CONTEXT& context, const DynamicStackTable& table)
{
    if (!table.key || context.Rip < table.base || context.Rip - table.base >= table.bytes) return false;
    RUNTIME_FUNCTION function{};
    bool leaf = false;
    if (!StackFunction(context.Rip, table.base, table.bytes, reinterpret_cast<uint64_t>(table.functions),
        table.count, function, leaf, true, !table.growable) || leaf) return false;
    void* handler = nullptr;
    DWORD64 establisher = 0;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, table.base, context.Rip, &function, &context,
        &handler, &establisher, nullptr);
    return true;
}

bool UnwindDynamicStack(CONTEXT& context)
{
    if (!TryAcquireSRWLockShared(&DynamicStackLock)) return false;
    bool unwound = false;
    __try
    {
        for (const auto& table : DynamicStackTables)
            if (UnwindStackTable(context, table)) { unwound = true; break; }
        if (!unwound)
        {
            // Discover registrations made before attachment without executing application lookup callbacks.
            const auto head = RtlGetFunctionTableListHead();
            LIST_ENTRY links{};
            auto cursor = head && ReadStackMemory(head, &links, sizeof(links)) ? links.Flink : nullptr;
            for (uint32_t attempt = 0; cursor && cursor != head && attempt < MaxFunctionTableScan; ++attempt)
            {
                DYNAMIC_FUNCTION_TABLE entry{};
                if (!ReadStackMemory(cursor, &entry, offsetof(DYNAMIC_FUNCTION_TABLE, TreeNodeMin))) break;
                const auto previous = cursor;
                cursor = entry.ListEntry.Flink;
                LIST_ENTRY next{};
                if (!cursor || !ReadStackMemory(cursor, &next, sizeof(next)) || next.Blink != previous) break;
                if (entry.Type == RF_CALLBACK && entry.FunctionTable && entry.MinimumAddress <= context.Rip &&
                    context.Rip < entry.MaximumAddress && entry.BaseAddress <= entry.MinimumAddress &&
                    entry.MaximumAddress - entry.BaseAddress <= UINT32_MAX)
                {
                    // Reuse returned metadata only while its callback table remains registered.
                    for (auto& cached : CallbackStackFunctions)
                    {
                        if (cached.key != entry.FunctionTable || cached.base != entry.BaseAddress) continue;
                        const DynamicStackTable table{cached.key, &cached.function, cached.base, 1,
                            static_cast<uint32_t>(entry.MaximumAddress - entry.BaseAddress), false};
                        if (UnwindStackTable(context, table)) { unwound = true; break; }
                    }
                    if (unwound) break;
                }
                if ((entry.Type != RF_SORTED && entry.Type != RF_UNSORTED && entry.Type != RF_KERNEL_DYNAMIC) ||
                    !entry.FunctionTable || !entry.EntryCount || entry.MinimumAddress > context.Rip ||
                    entry.MaximumAddress <= context.Rip || entry.BaseAddress > entry.MinimumAddress ||
                    entry.MaximumAddress - entry.BaseAddress > UINT32_MAX) continue;
                const DynamicStackTable table{entry.FunctionTable, entry.FunctionTable, entry.BaseAddress,
                    entry.EntryCount, UINT32_MAX, entry.Type != RF_UNSORTED};
                if (UnwindStackTable(context, table)) { unwound = true; break; }
            }
        }
    }
    __finally { ReleaseSRWLockShared(&DynamicStackLock); }
    return unwound;
}

constexpr size_t CachedStackFunctionCount = 256;
struct StackImage
{
    uint64_t base = 0;
    uint32_t bytes = 0;
    IMAGE_DATA_DIRECTORY functions{};
    MEMORY_BASIC_INFORMATION region{};
};
struct CachedStackFunction
{
    uint64_t pc = 0;
    uint64_t base = 0;
    RUNTIME_FUNCTION function{};
    bool leaf = false;
    bool pureRsp = false;
};
struct CachedWalkFrame
{
    uint64_t rip = 0;
    uint64_t rsp = 0;
    uint64_t nextRip = 0;
    uint64_t nextRsp = 0;
    bool pureRsp = false;
    bool pureTail = false;
};
struct ThreadStackCache
{
    LONG64 epoch = 0;
    void* tibStackBase = nullptr;
    MEMORY_BASIC_INFORMATION stack{};
    StackImage images[CachedStackImageCount]{};
    uint32_t nextImage = 0;
    CachedStackFunction functions[CachedStackFunctionCount]{};
    CachedWalkFrame walk[MaximumStack]{};
    uint32_t walkCount = 0;
};
[[msvc::no_tls_guard]] constinit thread_local ThreadStackCache CachedStackState{};

uint32_t WalkStaticStack(CONTEXT context, uint64_t caller, uint64_t* frames, uint32_t limit, uint32_t& flags)
{
    // Reuse validated image unwind directories, function entries, and verified pure-RSP stack suffixes.
    const auto currentEpoch = ActiveTransport ? ReadShared64(DetouristStackImageEpoch) : 0;
    if (currentEpoch && CachedStackState.epoch != currentEpoch)
    {
        CachedStackState = {};
        CachedStackState.epoch = currentEpoch;
    }
    StackImage images[StackImageCacheSize];
    uint32_t count = 0, nextImage = 0;
    const auto& tib = NtCurrentTeb()->NtTib;
    const bool tebStack = currentEpoch != 0 &&
        context.Rsp >= reinterpret_cast<uint64_t>(tib.StackLimit) &&
        context.Rsp < reinterpret_cast<uint64_t>(tib.StackBase);
    MEMORY_BASIC_INFORMATION stack{};
    if (tebStack && CachedStackState.tibStackBase == tib.StackBase &&
        context.Rsp - reinterpret_cast<uint64_t>(CachedStackState.stack.BaseAddress) <
            CachedStackState.stack.RegionSize)
        stack = CachedStackState.stack;
    else
    {
        if (!VirtualQuery(reinterpret_cast<void*>(context.Rsp), &stack, sizeof(stack)) ||
            stack.State != MEM_COMMIT || stack.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return 0;
        if (tebStack)
        {
            CachedStackState.tibStackBase = tib.StackBase;
            CachedStackState.stack = stack;
            CachedStackState.walkCount = 0;
        }
    }
    const auto allocation = stack.AllocationBase;
    bool recording = !caller;
    bool canCacheWalk = currentEpoch != 0 && tebStack;
    bool reusedSuffix = false;
    uint32_t matchedSuffix = 0;
    CachedWalkFrame currentWalk[MaximumStack];
    uint32_t currentWalkCount = 0;
    __try
    {
        for (uint32_t depth = 0; context.Rip && depth < MaxWalkDepth; ++depth)
        {
            recording |= context.Rip == caller;
            if (recording && canCacheWalk && !flags && CachedStackState.walkCount > 0)
            {
                const auto topNextRsp = CachedStackState.walk[CachedStackState.walkCount - 1].nextRsp;
                if (topNextRsp >= context.Rsp + sizeof(uint64_t) &&
                    topNextRsp <= reinterpret_cast<uint64_t>(tib.StackBase) &&
                    topNextRsp - sizeof(uint64_t) - reinterpret_cast<uint64_t>(stack.BaseAddress) < stack.RegionSize)
                {
                    for (uint32_t match = 0; match < CachedStackState.walkCount; ++match)
                    {
                        const auto& entry = CachedStackState.walk[match];
                        if (!entry.pureTail || entry.rip != context.Rip || entry.rsp != context.Rsp) continue;
                        bool verified = true;
                        for (uint32_t verify = match; verify < CachedStackState.walkCount; ++verify)
                        {
                            const auto& step = CachedStackState.walk[verify];
                            const auto slotAddr = reinterpret_cast<const uint64_t*>(step.nextRsp - sizeof(uint64_t));
                            if (*slotAddr != step.nextRip) { verified = false; break; }
                        }
                        if (!verified) break;
                        for (uint32_t copy = match; copy < CachedStackState.walkCount; ++copy)
                        {
                            if (count == limit) { flags |= Truncated; break; }
                            frames[count++] = CachedStackState.walk[copy].rip;
                        }
                        reusedSuffix = true;
                        matchedSuffix = match;
                        break;
                    }
                    if (reusedSuffix) break;
                }
            }
            StackImage* cached = nullptr;
            if (currentEpoch)
            {
                auto hit = std::find_if(std::begin(CachedStackState.images), std::end(CachedStackState.images),
                    [&](const auto& entry)
                {
                    return entry.base && context.Rip - entry.base < entry.bytes &&
                        context.Rip - reinterpret_cast<uint64_t>(entry.region.BaseAddress) < entry.region.RegionSize;
                });
                if (hit != std::end(CachedStackState.images)) cached = hit;
            }
            if (!cached)
            {
                auto local = std::find_if(std::begin(images), std::end(images), [&](const auto& entry)
                {
                    return context.Rip - reinterpret_cast<uint64_t>(entry.region.BaseAddress) <
                        entry.region.RegionSize;
                });
                cached = local != std::end(images) ? local : &images[nextImage++ % std::size(images)];
                if (!ReadStackImage(context.Rip, cached->base, cached->bytes, cached->functions, cached->region))
                { flags |= Truncated; break; }
                if (currentEpoch && cached->base)
                    CachedStackState.images[CachedStackState.nextImage++ % std::size(CachedStackState.images)] =
                        *cached;
            }
            const auto image = cached->base;
            const auto& functions = cached->functions;
            if (recording)
            {
                if (count == limit) { flags |= Truncated; break; }
                frames[count++] = context.Rip;
            }
            const auto stepRip = context.Rip;
            const auto previous = context.Rsp;
            RUNTIME_FUNCTION function{};
            bool leaf = false;
            bool pureRsp = false;
            if (image)
            {
                auto* funcSlot = currentEpoch ?
                    &CachedStackState.functions[(stepRip >> 2) & (CachedStackFunctionCount - 1)] : nullptr;
                if (funcSlot && funcSlot->pc == stepRip && funcSlot->base == image)
                {
                    function = funcSlot->function;
                    leaf = funcSlot->leaf;
                    pureRsp = funcSlot->pureRsp;
                }
                else
                {
                    if (!StackFunction(stepRip, image, cached->bytes, image + functions.VirtualAddress,
                        functions.Size / static_cast<uint32_t>(sizeof(RUNTIME_FUNCTION)), function, leaf,
                        false, false, &pureRsp))
                    { flags |= Truncated; break; }
                    if (funcSlot) *funcSlot = {stepRip, image, function, leaf, pureRsp};
                }
            }
            if (!image)
            {
                if (!UnwindDynamicStack(context)) { flags |= Truncated; break; }
            }
            else if (leaf)
            {
                if (!ReadCaptureMemory(reinterpret_cast<void*>(context.Rsp), &context.Rip, sizeof(context.Rip)))
                { flags |= Truncated; break; }
                context.Rsp += sizeof(uint64_t);
            }
            else
            {
                void* handler = nullptr;
                DWORD64 establisher = 0;
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, context.Rip, &function, &context,
                    &handler, &establisher, nullptr);
            }
            if (recording && canCacheWalk)
            {
                if (context.Rsp > previous && currentWalkCount < MaximumStack)
                {
                    uint64_t slotValue = UINT64_MAX;
                    const bool stepPure = image != 0 && pureRsp &&
                        ReadCaptureMemory(reinterpret_cast<const void*>(context.Rsp - sizeof(uint64_t)),
                            &slotValue, sizeof(slotValue)) && slotValue == context.Rip;
                    currentWalk[currentWalkCount++] = {stepRip, previous, context.Rip, context.Rsp, stepPure, false};
                }
                else canCacheWalk = false;
            }
            if (!context.Rip) break;
            if (context.Rsp <= previous) { flags |= Truncated; break; }
            if (context.Rsp - reinterpret_cast<uint64_t>(stack.BaseAddress) >= stack.RegionSize)
            {
                if (!VirtualQuery(reinterpret_cast<void*>(context.Rsp), &stack, sizeof(stack)))
                { flags |= Truncated; break; }
                if (tebStack && stack.State == MEM_COMMIT && stack.AllocationBase == allocation &&
                    !(stack.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                    context.Rsp < reinterpret_cast<uint64_t>(tib.StackBase))
                    CachedStackState.stack = stack;
            }
            if (stack.State != MEM_COMMIT || stack.AllocationBase != allocation ||
                stack.Protect & (PAGE_GUARD | PAGE_NOACCESS))
            { flags |= Truncated; break; }
            if (depth + 1 == MaxWalkDepth) flags |= Truncated;
        }
        if (canCacheWalk && !flags)
        {
            if (reusedSuffix && matchedSuffix > 0 &&
                currentWalkCount + (CachedStackState.walkCount - matchedSuffix) <= MaximumStack)
            {
                const auto tailCount = CachedStackState.walkCount - matchedSuffix;
                memmove(&CachedStackState.walk[currentWalkCount], &CachedStackState.walk[matchedSuffix],
                    tailCount * sizeof(CachedWalkFrame));
                if (currentWalkCount)
                    memcpy(CachedStackState.walk, currentWalk, currentWalkCount * sizeof(CachedWalkFrame));
                CachedStackState.walkCount = currentWalkCount + tailCount;
            }
            else if (!reusedSuffix && !context.Rip && currentWalkCount > 0)
            {
                memcpy(CachedStackState.walk, currentWalk, currentWalkCount * sizeof(CachedWalkFrame));
                CachedStackState.walkCount = currentWalkCount;
            }
            else if (!reusedSuffix) CachedStackState.walkCount = 0;
            bool tailPure = true;
            for (uint32_t index = CachedStackState.walkCount; index-- > 0;)
            {
                tailPure = tailPure && CachedStackState.walk[index].pureRsp;
                CachedStackState.walk[index].pureTail = tailPure;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { flags |= Truncated | Unreadable; }
    return count;
}

#else
struct ThreadStackCache
{
    LONG64 epoch = 0;
    void* tibStackBase = nullptr;
    MEMORY_BASIC_INFORMATION stack{};
    MEMORY_BASIC_INFORMATION images[CachedStackImageCount]{};
    uint32_t nextImage = 0;
};
[[msvc::no_tls_guard]] constinit thread_local ThreadStackCache CachedStackState{};

void AddStackHooks(std::vector<HookDefinition>&) {}
bool IsStackHook(void*) { return false; }

uint32_t WalkStaticStack(CONTEXT context, uint64_t caller, uint64_t* frames, uint32_t limit, uint32_t& flags)
{
    const auto currentEpoch = ActiveTransport ? ReadShared64(DetouristStackImageEpoch) : 0;
    if (currentEpoch && CachedStackState.epoch != currentEpoch)
    {
        CachedStackState = {};
        CachedStackState.epoch = currentEpoch;
    }
    uint32_t count = 0;
    auto frame = uintptr_t{context.Ebp};
    const auto& tib = NtCurrentTeb()->NtTib;
    const auto esp = uintptr_t{context.Esp};
    const bool tebStack = currentEpoch != 0 &&
        esp >= reinterpret_cast<uintptr_t>(tib.StackLimit) &&
        esp < reinterpret_cast<uintptr_t>(tib.StackBase);
    MEMORY_BASIC_INFORMATION stack{};
    if (tebStack && CachedStackState.tibStackBase == tib.StackBase &&
        esp - reinterpret_cast<uintptr_t>(CachedStackState.stack.BaseAddress) < CachedStackState.stack.RegionSize)
        stack = CachedStackState.stack;
    else
    {
        if (!VirtualQuery(reinterpret_cast<void*>(esp), &stack, sizeof(stack)) ||
            stack.State != MEM_COMMIT || stack.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return 0;
        if (tebStack)
        {
            CachedStackState.tibStackBase = tib.StackBase;
            CachedStackState.stack = stack;
        }
    }
    const auto allocation = stack.AllocationBase;
    bool recording = !caller;
    auto pc = uintptr_t{context.Eip};
    MEMORY_BASIC_INFORMATION code{};

    // Frame-pointer chains stop at omitted frames, other stack allocations and unreadable memory.
    for (uint32_t depth = 0; pc && depth < MaxWalkDepth; ++depth)
    {
        if (pc - reinterpret_cast<uintptr_t>(code.BaseAddress) >= code.RegionSize)
        {
            const MEMORY_BASIC_INFORMATION* hit = nullptr;
            if (currentEpoch)
            {
                auto found = std::find_if(std::begin(CachedStackState.images), std::end(CachedStackState.images),
                    [&](const auto& entry)
                {
                    return entry.Type == MEM_IMAGE &&
                        pc - reinterpret_cast<uintptr_t>(entry.BaseAddress) < entry.RegionSize;
                });
                if (found != std::end(CachedStackState.images)) hit = found;
            }
            if (hit) code = *hit;
            else
            {
                if (!VirtualQuery(reinterpret_cast<void*>(pc), &code, sizeof(code)) || code.State != MEM_COMMIT ||
                    code.Protect & (PAGE_GUARD | PAGE_NOACCESS) || !(code.Protect &
                        (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) break;
                if (currentEpoch && code.Type == MEM_IMAGE)
                    CachedStackState.images[CachedStackState.nextImage++ % std::size(CachedStackState.images)] = code;
            }
        }
        recording |= pc == caller;
        if (recording)
        {
            if (count == limit) break;
            frames[count++] = pc;
        }
        if (code.Type != MEM_IMAGE) break;
        if (frame < context.Esp || frame % sizeof(uintptr_t)) break;
        if (frame - reinterpret_cast<uintptr_t>(stack.BaseAddress) >= stack.RegionSize)
        {
            if (!VirtualQuery(reinterpret_cast<void*>(frame), &stack, sizeof(stack))) break;
            if (tebStack && stack.State == MEM_COMMIT && stack.AllocationBase == allocation &&
                !(stack.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                frame < reinterpret_cast<uintptr_t>(tib.StackBase))
                CachedStackState.stack = stack;
        }
        if (stack.State != MEM_COMMIT || stack.AllocationBase != allocation ||
            stack.Protect & (PAGE_GUARD | PAGE_NOACCESS) || stack.RegionSize < sizeof(uintptr_t) * 2 ||
            frame - reinterpret_cast<uintptr_t>(stack.BaseAddress) > stack.RegionSize - sizeof(uintptr_t) * 2) break;
        uintptr_t next[2]{};
        if (!ReadCaptureMemory(reinterpret_cast<void*>(frame), next, sizeof(next)) || next[0] <= frame) break;
        context.Esp = static_cast<DWORD>(frame + sizeof(next));
        frame = next[0];
        pc = next[1];
    }
    if (!count && caller && limit) frames[count++] = caller;
    flags |= Truncated;
    return count;
}
#endif

extern "C" __declspec(dllexport) uint32_t WINAPI DetouristCaptureStack(const CONTEXT* source, uint64_t caller,
    uint64_t* frames, uint32_t limit, uint32_t* flags)
{
    if (!source || !frames || !flags || !limit || !NativeThreadReady()) return 0;
    ObserverScope observer;
    uint32_t count = 0;
    *flags = 0;
    CONTEXT context{};
    if (NativeStackSafe() && ReadCaptureMemory(source, &context, sizeof(context)))
        count = WalkStaticStack(context, caller, frames, std::min(limit, MaximumStack), *flags);
    return count;
}

void CaptureCallStack(Call& call, Slot* slot)
{
    auto header = call.transport->Header();
    if (!header->stackDepth) return;
    bool captured = false;
    for (uint32_t position = 0; slot->event.payloadBytes - position >= sizeof(Value);)
    {
        Value value;
        memcpy(&value, Transport::Payload(slot) + position, sizeof(value));
        position += sizeof(value);
        if (value.capturedBytes > slot->event.payloadBytes - position) break;
        captured |= value.kind == ValueKind::Stack && value.capturedBytes != 0;
        position += value.capturedBytes;
    }
    if (!captured && call.event.caller && !IsManagedApi(call.event.api))
    {
        CONTEXT context{};
        RtlCaptureContext(&context);
        uint64_t frames[MaximumStack]{};
        uint32_t flags = 0;
        auto count = DetouristCaptureStack(&context, call.event.caller, frames, header->stackDepth, &flags);
        auto position = slot->event.payloadBytes;
        if (count) CopyValue(slot, header, UINT32_MAX, ValueKind::Stack,
            reinterpret_cast<uint64_t>(frames), count * sizeof(uint64_t));
        if (slot->event.payloadBytes > position)
        {
            auto value = reinterpret_cast<Value*>(Transport::Payload(slot) + position);
            value->flags |= flags;
            captured = value->capturedBytes >= sizeof(uint64_t);
        }
    }
    if (!captured) call.event.flags |= StackUnavailable;
    else call.event.flags &= ~StackUnavailable;
    slot->event.flags = call.event.flags;
}
}

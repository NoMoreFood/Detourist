#pragma warning(push, 0)
#include <winsock2.h>
#include <mswsock.h>
#include <phnt_windows.h>
#include <phnt.h>
#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#pragma warning(pop)
#include "InstructionCapture.h"
#include <algorithm>

namespace Detourist
{
#ifdef _WIN64
constexpr uint InstructionWrapConvention = static_cast<uint>(DRWRAP_CALLCONV_MICROSOFT_X64);
#else
constexpr uint InstructionWrapConvention = static_cast<uint>(DRWRAP_CALLCONV_CDECL);
#endif
constexpr uint32_t ExportBuckets = 8192;
constexpr size_t DiscoveredExportImagesCapacity = 1024;
constexpr uint32_t MaxForwarderDepth = 8;
constexpr uint32_t MaxRpcMarshalDefinitions = 4096;
constexpr uint32_t MarshalThunkStride = 16;
constexpr size_t MarshalThunkTargetOffset = 8;
constexpr DWORD MaxExportDirectoryEntries = 1000000;
constexpr GUID MsgServiceAdminIid{0x0002030f, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
constexpr uint32_t MsgServiceAdminRegisterSlot = 10;
uint16_t ApiNames[ExportBuckets]{}, NextApiName[static_cast<uint32_t>(Api::Count)]{};
InstructionDefinition* Exports[ExportBuckets]{};
InstructionDefinition* AllExports = nullptr;
std::array<app_pc, DiscoveredExportImagesCapacity> DiscoveredExportImages{};
uint32_t NextExportId = ExportApiStart;
uint32_t NextInterfaceId = InterfaceApiStart;
uintptr_t ObserverRanges[4]{};
BOOL (WINAPI* ObserverQuery)(ObserverContext*) = nullptr;
void (WINAPI* ObserverUpdate)(const ObserverContext*) = nullptr;
uint64_t (WINAPI* AsyncCallbackFactory)(uint64_t, uint64_t, uint32_t, uint64_t*) = nullptr;
uint32_t (WINAPI* NativeStackCapture)(const CONTEXT*, uint64_t, uint64_t*, uint32_t, uint32_t*) = nullptr;
uint32_t (WINAPI* NativeRpcSerialization)(uint64_t) = nullptr;
void (WINAPI* NativeRpcSerializationObserver)(uint32_t, const uint64_t*, uint64_t, BOOL) = nullptr;
uint64_t (WINAPI* NativeRpcMarshalerOriginal)(uint64_t) = nullptr;
BOOL (WINAPI* NativeRpcMarshalerOwns)(uint32_t, uint64_t) = nullptr;
InstructionDefinition* RpcMarshalDefinitions = nullptr;
uint32_t RpcMarshalDefinitionCount = 0;
volatile LONG64* NativeHookAddresses = nullptr;
volatile LONG* NativeHookApis = nullptr;
volatile LONG64* InternalCallerRanges = nullptr;
constexpr const char* InternalCallerImages[]{"DetouristAgent.dll", "DetouristInstructions.dll",
    "dynamorio.dll", "drmgr.dll", "drwrap.dll", "drcontainers.dll", "DetouristProfiler.dll"};
static_assert(std::size(InternalCallerImages) == InternalNativeImageCount);
uint32_t AvailableReferences[static_cast<uint32_t>(Api::Count)]{};
uint32_t InstalledReferences[static_cast<uint32_t>(Api::Count)]{};

// Ignore parameter names when comparing capture plans for exports that share one implementation.
bool EquivalentExportParameterTypes(const wchar_t* left, const wchar_t* right)
{
    if (!left || !right) return false;
    auto next = [](const wchar_t*& cursor, const wchar_t*& begin, const wchar_t*& end)
    {
        begin = cursor;
        int depth = 0;
        while (*cursor)
        {
            if (*cursor == L'(') ++depth;
            else if (*cursor == L')' && depth) --depth;
            else if (*cursor == L',' && !depth) break;
            ++cursor;
        }
        end = cursor;
        while (end > begin && end[-1] == L' ') --end;
        auto name = end;
        while (name > begin && ((name[-1] >= L'a' && name[-1] <= L'z') ||
            (name[-1] >= L'A' && name[-1] <= L'Z') ||
            (name[-1] >= L'0' && name[-1] <= L'9') || name[-1] == L'_')) --name;
        if (name > begin && name < end && name[-1] == L' ')
        {
            end = name;
            while (end > begin && end[-1] == L' ') --end;
        }
    };
    for (;;)
    {
        const wchar_t *leftBegin, *leftEnd, *rightBegin, *rightEnd;
        next(left, leftBegin, leftEnd);
        next(right, rightBegin, rightEnd);
        if (leftEnd - leftBegin != rightEnd - rightBegin ||
            !std::equal(leftBegin, leftEnd, rightBegin)) return false;
        if (!*left || !*right) return !*left && !*right;
        ++left;
        ++right;
    }
}

const char* ImageFileName(const module_data_t* module)
{
    // The PE export-directory name can differ from the DLL file that the process loaded.
    const auto path = module->full_path;
    if (!path || !*path) return dr_module_preferred_name(module);
    auto name = path;
    for (auto cursor = path; *cursor; ++cursor)
        if (*cursor == '\\' || *cursor == '/') name = cursor + 1;
    return *name ? name : dr_module_preferred_name(module);
}

uint32_t WINAPI LookupRpcSerialization(uint64_t handle)
{
    if (!NativeRpcSerialization) return 0;
    auto context = dr_get_current_drcontext();
    dr_switch_to_app_state(context);
    const auto result = NativeRpcSerialization(handle);
    dr_switch_to_dr_state(context);
    return result;
}

void ObserveRpcSerializationCall(Api api, const uint64_t* arguments, uint64_t result, bool leaving)
{
    if (!NativeRpcSerializationObserver) return;
    auto context = dr_get_current_drcontext();
    dr_switch_to_app_state(context);
    NativeRpcSerializationObserver(static_cast<uint32_t>(api), arguments, result, leaving);
    dr_switch_to_dr_state(context);
}

void WINAPI ObserveRpcMarshaler(uint64_t table, uint32_t index, uint32_t bytes);

void ObserverModule(const module_data_t* module)
{
    const auto name = dr_module_preferred_name(module);
    if (!name) return;
    int index = !_stricmp(name, "DetouristAgent.dll") ? 0 : !_stricmp(name, "DetouristProfiler.dll") ? 2 : -1;
    if (index >= 0)
    {
        ObserverRanges[index] = reinterpret_cast<uintptr_t>(module->start);
        ObserverRanges[index + 1] = reinterpret_cast<uintptr_t>(module->end);
        if (!index)
        {
            ObserverQuery = reinterpret_cast<decltype(ObserverQuery)>(
                dr_get_proc_address(module->handle, "DetouristGetObserverContext"));
            ObserverUpdate = reinterpret_cast<decltype(ObserverUpdate)>(
                dr_get_proc_address(module->handle, "DetouristSetObserverContext"));
            AsyncCallbackFactory = reinterpret_cast<decltype(AsyncCallbackFactory)>(
                dr_get_proc_address(module->handle, "DetouristAsyncCallback"));
            NativeStackCapture = reinterpret_cast<decltype(NativeStackCapture)>(
                dr_get_proc_address(module->handle, "DetouristCaptureStack"));
            NativeRpcSerialization = reinterpret_cast<decltype(NativeRpcSerialization)>(
                dr_get_proc_address(module->handle, "DetouristRpcSerializationOperation"));
            RpcSerializationLookup = LookupRpcSerialization;
            NativeRpcSerializationObserver = reinterpret_cast<decltype(NativeRpcSerializationObserver)>(
                dr_get_proc_address(module->handle, "DetouristObserveRpcSerialization"));
            NativeRpcMarshalerOriginal = reinterpret_cast<decltype(NativeRpcMarshalerOriginal)>(
                dr_get_proc_address(module->handle, "DetouristRpcMarshalerOriginal"));
            NativeRpcMarshalerOwns = reinterpret_cast<decltype(NativeRpcMarshalerOwns)>(
                dr_get_proc_address(module->handle, "DetouristRpcMarshalerOwns"));
            RpcMarshalObserver = ObserveRpcMarshaler;
            NativeHookAddresses = reinterpret_cast<volatile LONG64*>(
                dr_get_proc_address(module->handle, "DetouristNativeHookAddresses"));
            NativeHookApis = reinterpret_cast<volatile LONG*>(
                dr_get_proc_address(module->handle, "DetouristNativeHookApis"));
            InternalCallerRanges = reinterpret_cast<volatile LONG64*>(
                dr_get_proc_address(module->handle, "DetouristInternalCallerRanges"));
        }
    }
    if (InternalCallerRanges)
        for (uint32_t slot = 0; slot < InternalNativeImageCount; ++slot)
            if (!_stricmp(name, InternalCallerImages[slot]))
            {
                auto range = InternalCallerRanges + slot * 2;
                InterlockedExchange64(range, 0);
                InterlockedExchange64(range + 1, reinterpret_cast<LONG64>(module->end));
                InterlockedExchange64(range, reinterpret_cast<LONG64>(module->start));
                break;
            }
}

bool NativeOwnsAddress(const InstructionDefinition& definition)
{
    if (!NativeHookAddresses) return false;
    auto address = definition.address;
    for (uint32_t depth = 0; depth < MaxForwarderDepth; ++depth)
    {
        auto value = reinterpret_cast<LONG64>(address);
        auto bucket = (static_cast<uint64_t>(value) >> 4) % NativeHookCapacity;
        for (uint32_t step = 0; step < NativeHookCapacity; ++step)
        {
            auto index = (bucket + step) % NativeHookCapacity;
            auto current = NativeHookAddresses[index];
            if (current == value)
                return NativeHookApis && (NativeHookApis[index] == static_cast<LONG>(definition.typed) ||
                    definition.nativeImportAlias && NativeHookApis[index] == static_cast<LONG>(Api::AVISave));
            if (!current) break;
        }
        if (!definition.known) return false;

        // Forwarders with the same API identity share a record; public facades retain their distinct native calls.
        byte code[7]{};
        if (!ReadCaptureMemory(address, code, sizeof(code))) return false;
        auto start = static_cast<const byte*>(address);
        int32_t displacement = 0;
        auto prefix = sizeof(void*) == 8 && code[0] == 0x48 ? 1 : 0;
        if (code[prefix] == 0xFF && code[prefix + 1] == 0x25)
        {
            memcpy(&displacement, code + prefix + 2, sizeof(displacement));
#ifdef _WIN64
            auto slot = start + prefix + 6 + displacement;
#else
            auto slot = reinterpret_cast<const BYTE*>(static_cast<uint32_t>(displacement));
#endif
            if (!ReadCaptureMemory(slot, &address, sizeof(address))) return false;
        }
        else if (code[0] == 0xE9)
        {
            memcpy(&displacement, code + 1, sizeof(displacement));
            address = const_cast<byte*>(start + 5 + displacement);
        }
        else if (code[0] == 0xEB) address = const_cast<byte*>(start + 2 + static_cast<int8_t>(code[1]));
        else return false;
    }
    return false;
}

bool NativeOwnsCall(const InstructionDefinition& definition, const ObserverContext& observer)
{
    // The agent records this typed API when its hook owns the address or this call comes from that hook.
    return (observer.flags & ObserverNativeReady) && (NativeOwnsAddress(definition) ||
        (definition.typed != Api::Count && observer.api == static_cast<uint32_t>(definition.typed)) ||
        (definition.marshalSlot && NativeRpcMarshalerOwns && NativeRpcMarshalerOwns(observer.api,
            reinterpret_cast<uint64_t>(definition.marshalSlot))));
}

bool InstructionObserver(void* context, uint64_t caller, ObserverContext* observer)
{
    for (int index = 0; index < 4; index += 2)
        if (caller >= ObserverRanges[index] && caller < ObserverRanges[index + 1]) return true;
    if (!ObserverQuery) return false;
    ObserverContext value{};
    dr_switch_to_app_state(context);
    ObserverQuery(&value);
    dr_switch_to_dr_state(context);
    if (observer) *observer = value;
    return (value.flags & ObserverRecording) != 0;
}

void SetInstructionObserver(void* context, const ObserverContext& observer)
{
    if (!ObserverUpdate) return;
    dr_switch_to_app_state(context);
    ObserverUpdate(&observer);
    dr_switch_to_dr_state(context);
}

void CaptureInstructionStack(void* context, InstructionFrame& frame, const dr_mcontext_t& machine, bool atCaller)
{
    const auto depth = frame.transport->Header()->stackDepth;
    if (!depth || !NativeStackCapture || atCaller && !frame.event.caller ||
        frame.definition->entryOnly || frame.definition->stackProbe) return;

    // Seed the walk from application registers while the runtime owns a separate observer stack.
    CONTEXT application{};
    application.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#ifdef _WIN64
    application.Rip = atCaller ? frame.event.caller : reinterpret_cast<uint64_t>(machine.pc);
    application.Rsp = machine.xsp + (atCaller ? sizeof(uint64_t) : 0);
    application.Rbp = machine.xbp;
    application.Rax = machine.xax;
    application.Rbx = machine.xbx;
    application.Rcx = machine.xcx;
    application.Rdx = machine.xdx;
    application.Rsi = machine.xsi;
    application.Rdi = machine.xdi;
    application.R8 = machine.r8;
    application.R9 = machine.r9;
    application.R10 = machine.r10;
    application.R11 = machine.r11;
    application.R12 = machine.r12;
    application.R13 = machine.r13;
    application.R14 = machine.r14;
    application.R15 = machine.r15;
#else
    application.Eip = atCaller ? static_cast<DWORD>(frame.event.caller) : reinterpret_cast<DWORD>(machine.pc);
    application.Esp = machine.xsp + (atCaller ? sizeof(void*) : 0);
    application.Ebp = machine.xbp;
    application.Eax = machine.xax;
    application.Ebx = machine.xbx;
    application.Ecx = machine.xcx;
    application.Edx = machine.xdx;
    application.Esi = machine.xsi;
    application.Edi = machine.xdi;
#endif
    application.EFlags = static_cast<DWORD>(machine.xflags);
    dr_switch_to_app_state(context);
    frame.stackCount = NativeStackCapture(&application, 0, frame.stack, depth, &frame.stackFlags);
    dr_switch_to_dr_state(context);
    if (frame.stackCount) frame.event.flags &= ~StackUnavailable;
}

uint64_t ReadInstructionArgument(const dr_mcontext_t& machine, const ExportSignature& signature, uint32_t index)
{
    uint64_t value = 0;
#ifdef _WIN64
    const uint64_t registers[]{machine.xcx, machine.xdx, machine.r8, machine.r9};
    if (index < 4) return signature.floatingArguments & (1u << index) ? machine.simd[index].u64[0] : registers[index];
    dr_safe_read(reinterpret_cast<void*>(machine.xsp + (index + 1ull) * sizeof(void*)), sizeof(value), &value, nullptr);
#else
    if (signature.callingConvention == ExportCallingConvention::Fastcall && index < 2)
        return index ? machine.xdx : machine.xcx;
    const auto address = machine.xsp + sizeof(void*) + ExportStackBytes(signature, index);
    auto bytes = std::max(4u, uint32_t{signature.argumentBytes[index]});
    if (bytes > sizeof(value)) return address;
    dr_safe_read(reinterpret_cast<void*>(address), bytes, &value, nullptr);
#endif
    return value;
}

bool WriteInstructionArgument(void* wrapped, dr_mcontext_t& machine, const ExportSignature& signature,
    uint32_t index, uint64_t value)
{
#ifdef _WIN64
    if (index < 4 && (signature.floatingArguments & (1u << index)))
    {
        machine.simd[index].u64[0] = value;
        return drwrap_set_mcontext(wrapped);
    }
    return drwrap_set_arg(wrapped, static_cast<int>(index), reinterpret_cast<void*>(value));
#else
    if (signature.callingConvention == ExportCallingConvention::Fastcall && index < 2)
    {
        (index ? machine.xdx : machine.xcx) = static_cast<reg_t>(value);
        return drwrap_set_mcontext(wrapped);
    }
    const auto address = machine.xsp + sizeof(void*) + ExportStackBytes(signature, index);
    auto bytes = std::max(4u, uint32_t{signature.argumentBytes[index]});
    BYTE record[MaximumExportArgumentBytes]{};
    const void* source = &value;
    if (bytes > sizeof(value))
    {
        if (bytes > sizeof(record) || !ReadCaptureMemory(reinterpret_cast<void*>(value), record, bytes)) return false;
        source = record;
    }
    return dr_safe_write(reinterpret_cast<void*>(address), bytes, source, nullptr);
#endif
}

uint64_t PrepareAsyncCallback(void* context, InstructionFrame& frame, uint32_t& parameter)
{
    AsyncCallbackKind kind;
    parameter = AsyncCallbackParameter(frame.asyncRole, kind);
    if (parameter == UINT32_MAX || !frame.event.arguments[parameter]) return 0;
    const auto original = frame.event.arguments[parameter];
    auto result = original;
    if (AsyncCallbackFactory)
    {
        dr_switch_to_app_state(context);
        result = AsyncCallbackFactory(frame.transport->Header()->captureIdentity, original,
            static_cast<uint32_t>(kind), &frame.event.arguments[parameter]);
        dr_switch_to_dr_state(context);
    }
    if (result == frame.event.arguments[parameter])
        InterlockedIncrement64(&frame.transport->Header()->asyncCallbackErrors);
    return result;
}

uint32_t NameHash(const char* name)
{
    uint32_t hash = Fnv1aOffsetBasis32;
    while (*name) { hash = (hash ^ static_cast<uint8_t>(*name++)) * Fnv1aPrime32; }
    return hash % ExportBuckets;
}

void InitializeExports()
{
    auto header = InstructionTransport.Header();
    header->installedNativeCount = header->availableNativeCount = 0;
    header->installedWin32Count = header->availableWin32Count = 0;
    header->installedComCount = header->installedExportCount = 0;
    header->installedApis = 0;
    for (uint16_t index = 0; index < std::size(ApiDefinitions); ++index)
    {
        auto bucket = NameHash(ApiDefinitions[index].name);
        NextApiName[index] = ApiNames[bucket];
        ApiNames[bucket] = index + 1;
    }
}

void CountExportCoverage(InstructionDefinition& definition, bool adding)
{
    if (definition.coverageCounted == adding) return;
    definition.coverageCounted = adding;
    auto header = InstructionTransport.Header();
    auto change = adding ? 1 : -1;
    if (definition.wrapped)
    {
        if (definition.interfaceTable || IsComApi(definition.typed))
            InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(&header->installedComCount), change);
        if (!definition.interfaceTable)
            InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(&header->installedExportCount), change);
        if (adding) InterlockedOr64(&header->installedApis, definition.mask);
    }
    if (!definition.known || definition.interfaceTable || IsComApi(definition.typed)) return;
    auto index = static_cast<uint32_t>(definition.typed);
    auto& available = IsNativeApi(definition.typed) ? header->availableNativeCount : header->availableWin32Count;
    auto& installed = IsNativeApi(definition.typed) ? header->installedNativeCount : header->installedWin32Count;

    // Multiple export bodies and forwarders contribute one catalog identity until its final image unloads.
    if (adding ? AvailableReferences[index]++ == 0 : --AvailableReferences[index] == 0)
        InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(&available), change);
    if (definition.wrapped && (adding ? InstalledReferences[index]++ == 0 : --InstalledReferences[index] == 0))
        InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(&installed), change);
}

Api FindExportType(const char* module, const char* name)
{
    for (auto entry = ApiNames[NameHash(name)]; entry; entry = NextApiName[entry - 1])
    {
        const auto& api = ApiDefinitions[entry - 1];
        if (strcmp(api.name, name)) continue;
        bool matches = !_stricmp(module, api.module) ||
            (!_stricmp(module, "kernelbase.dll") &&
                (!_stricmp(api.module, "kernel32.dll") || !_stricmp(api.module, "advapi32.dll"))) ||
            (!_stricmp(module, "sechost.dll") && !_stricmp(api.module, "advapi32.dll")) ||
            (!_stricmp(module, "combase.dll") && !_stricmp(api.module, "ole32.dll")) ||
            (!_stricmp(module, "gdi32full.dll") && !_stricmp(api.module, "gdi32.dll")) ||
            (name[0] == '?' &&
                ((!_stricmp(module, "msvcr120_clr0400.dll") && !_stricmp(api.module, "msvcr120.dll")) ||
                 (!_stricmp(module, "msvcp120_clr0400.dll") && !_stricmp(api.module, "msvcp120.dll"))));
        if (matches) return api.id;
    }
    return Api::Count;
}

InstructionDefinition* ExportDefinitionAt(void* address)
{
    auto bucket = (reinterpret_cast<uintptr_t>(address) >> 4) % ExportBuckets;
    dr_mutex_lock(DefinitionLock);
    auto definition = Exports[bucket];
    while (definition && (definition->address != address || definition->retired)) definition = definition->next;
    dr_mutex_unlock(DefinitionLock);
    return definition;
}

bool NonImageExportAddress(app_pc address)
{
    // Runtime and client code cannot supply application exports outside their provider image.
    dr_mem_info_t region{};
    return address && !dr_memory_is_dr_internal(address) && !dr_memory_is_in_client(address) &&
        dr_query_memory_ex(address, &region) && region.type == DR_MEMTYPE_DATA &&
        (region.prot & DR_MEMPROT_EXEC) && !(region.prot & DR_MEMPROT_GUARD);
}

app_pc ForwardAddress(const char* text, uint32_t depth = 0)
{
    if (depth == MaxForwarderDepth) return nullptr;
    char name[512]{};
    ReadInstructionString(text, name, std::size(name));
    auto separator = strrchr(name, '.');
    if (!separator) return nullptr;
    *separator++ = 0;
    char library[512]{};
    dr_snprintf(library, std::size(library), "%s%s", name, strstr(name, ".dll") ? "" : ".dll");
    auto module = dr_lookup_module_by_name(library);
    if (!module) return nullptr;
    app_pc address = nullptr;
    if (*separator != '#') address = reinterpret_cast<app_pc>(dr_get_proc_address(module->handle, separator));
    else
    {
        uint64_t ordinal = 0;
        auto digit = separator + 1;
        for (; *digit >= '0' && *digit <= '9' && ordinal <= UINT32_MAX; ++digit)
            ordinal = ordinal * 10 + static_cast<uint32_t>(*digit - '0');
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS image{};
        IMAGE_EXPORT_DIRECTORY exports{};
        auto extent = static_cast<uint64_t>(module->end - module->start);
        if (digit != separator + 1 && !*digit && ordinal <= UINT32_MAX &&
            ReadCaptureMemory(module->start, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
            dos.e_lfanew > 0 && uint64_t{static_cast<uint32_t>(dos.e_lfanew)} + sizeof(image) <= extent &&
            ReadCaptureMemory(module->start + dos.e_lfanew, &image, sizeof(image)) &&
            image.Signature == IMAGE_NT_SIGNATURE)
        {
            const auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            DWORD function = 0;
            if (directory.VirtualAddress && uint64_t{directory.VirtualAddress} + sizeof(exports) <= extent &&
                ReadCaptureMemory(module->start + directory.VirtualAddress, &exports, sizeof(exports)) &&
                ordinal >= exports.Base && ordinal - exports.Base < exports.NumberOfFunctions &&
                uint64_t{exports.AddressOfFunctions} + (ordinal - exports.Base + 1) * sizeof(DWORD) <= extent &&
                ReadCaptureMemory(module->start + exports.AddressOfFunctions +
                    (ordinal - exports.Base) * sizeof(DWORD), &function, sizeof(function)) &&
                function && function <= UINTPTR_MAX - reinterpret_cast<uintptr_t>(module->start) &&
                (function < extent || NonImageExportAddress(module->start + function)))
            {
                address = module->start + function;
                if (function < extent && function >= directory.VirtualAddress && uint64_t{function} <
                    uint64_t{directory.VirtualAddress} + directory.Size)
                    address = ForwardAddress(reinterpret_cast<const char*>(address), depth + 1);
            }
        }
    }
    dr_free_module_data(module);
    return address;
}

InstructionDefinition* ResolveInterfaceDefinition(InstructionDefinition* definition, uint64_t instance, uint32_t slot)
{
    // An object argument alone does not establish a vtable call to a shared export address.
    if (!definition->interfaceTable && slot == UINT32_MAX) return definition;
    void* table = nullptr;
    for (uint32_t attempt = 0; attempt < 2; ++attempt)
    {
        auto variants = static_cast<InstructionDefinition*>(InterlockedCompareExchangePointer(
            reinterpret_cast<void* volatile*>(&definition->variants), nullptr, nullptr));
        if (!variants && !definition->interfaceTable) return definition;
        if (!table && (instance < MinimumUserAddress ||
            !ReadCaptureMemory(reinterpret_cast<void*>(instance), &table, sizeof(table))))
            return definition->interfaceTable ? nullptr : definition;
        auto selected = definition->interfaceTable == table && !definition->retired ? definition : nullptr;
        bool selectedVariant = false;
        for (auto variant = variants; variant; variant = variant->nextVariant)
        {
            if (variant->retired || variant->interfaceTable != table) continue;
            auto exact = variant->interfaceSlot == slot;
            auto previousExact = selected && selected->interfaceSlot == slot;
            if (!selected || (exact && !previousExact) ||
                (exact == previousExact && (variant->interfaceGeneration > selected->interfaceGeneration ||
                (variant->interfaceGeneration == selected->interfaceGeneration && !selectedVariant))))
            {
                selected = variant;
                selectedVariant = true;
            }
        }
        if (!selected || (selected->interfaceGeneration &&
            !ValidateComGeneration(table, selected->interfaceGeneration)))
            return definition->interfaceTable ? nullptr : definition;
        auto locator = InterlockedCompareExchangePointer(&selected->rttiLocator, nullptr, nullptr);
        if (!locator) return selected;
        if (locator == reinterpret_cast<void*>(1)) return definition->interfaceTable ? nullptr : definition;

        // Resolve a virtual COM base before selecting a signature or capturing the first call's arguments.
        if (!ResolveImageInterface(table, instance, locator))
        {
            InterlockedExchangePointer(&selected->rttiLocator, reinterpret_cast<void*>(1));
            return definition->interfaceTable ? nullptr : definition;
        }
    }
    return nullptr;
}

void InstallInterfaceWrap(InstructionDefinition& definition)
{
    // Competing discoveries can register the same wrapper before entering the target.
    auto wrapped = drwrap_wrap_ex(static_cast<app_pc>(definition.address), &ExportEntered, &ExportLeft,
        &definition, InstructionWrapConvention);
    dr_mutex_lock(DefinitionLock);
    if (wrapped)
    {
        definition.wrapped = true;
        definition.interfaceWrapPending = false;
    }
    else if (definition.interfaceWrapPending) InstructionTransport.Header()->moduleRefreshError = ERROR_NOT_SUPPORTED;
    dr_mutex_unlock(DefinitionLock);
}

void ObserveInterfaceMethod(void* address, void* table, const GUID& iid, uint32_t slot, Api typed,
    const RuntimeInterface* contract, bool provisional, const char* typeName, void* rttiLocator, bool queryProbe,
    uint64_t generation)
{
    auto method = contract ? RuntimeInterfaceMethod(*contract, slot) : nullptr;
    auto runtime = method && method->signature.supported ? method : nullptr;
    auto module = dr_lookup_module(static_cast<app_pc>(address));
    auto bucket = (reinterpret_cast<uintptr_t>(address) >> 4) % ExportBuckets;
    dr_mutex_lock(DefinitionLock);
    auto primary = Exports[bucket];
    while (primary && primary->address != address) primary = primary->next;
    bool shared = false;
    for (auto existing = primary; existing; existing = existing == primary ? primary->variants : existing->nextVariant)
    {
        shared |= existing->interfaceTable == table && existing->interfaceSlot != slot && !existing->retired;
        if (existing->interfaceTable != table || existing->interfaceSlot != slot || existing->retired ||
            (generation && existing->interfaceGeneration != generation)) continue;
        bool update = (existing->rttiLocator && !rttiLocator) || (runtime && !existing->runtime) ||
            (existing->provisional && !provisional && (!existing->runtime || runtime));
        if (existing->known || (typed == Api::Count && !update))
        {
            if (primary->interfaceWrapPending)
            {
                // drwrap can flush translated code and must run outside the definition lock.
                dr_mutex_unlock(DefinitionLock);
                InstallInterfaceWrap(*primary);
                dr_mutex_lock(DefinitionLock);
            }
            if (!queryProbe)
            {
                InterlockedExchange(&existing->queryProbe, 0);
                CountExportCoverage(*existing, true);
            }
            dr_mutex_unlock(DefinitionLock);
            if (module) dr_free_module_data(module);
            return;
        }
    }
    auto definition = static_cast<InstructionDefinition*>(dr_global_alloc(sizeof(InstructionDefinition)));
    memset(definition, 0, sizeof(*definition));
    definition->typed = typed;
    definition->known = typed != Api::Count;
    definition->provisional = provisional;
    definition->queryProbe = queryProbe;
    definition->id = definition->known ? typed : static_cast<Api>(NextInterfaceId++);
    definition->mask = ComApis;
    definition->runtime = definition->known ? nullptr : runtime;
    definition->signature = definition->runtime ? definition->runtime->signature : ComSignature(typed);
    definition->interfaceInputs = PublicInterfaceInputs(typed);
    definition->address = address;
    definition->module = module ? module->start : nullptr;
    definition->interfaceTable = table;
    definition->interfaceSlot = slot;
    definition->callbackRegistration = slot == MsgServiceAdminRegisterSlot &&
        !memcmp(&iid, &MsgServiceAdminIid, sizeof(iid));
    definition->interfaceGeneration = generation;
    definition->rttiLocator = rttiLocator;
    if (definition->known)
    {
        const auto& api = Definition(typed);
        definition->metadata.argumentCount = api.argumentCount;
        dr_snprintf(definition->metadata.module, std::size(definition->metadata.module), "%s", api.module);
        dr_snprintf(definition->metadata.name, std::size(definition->metadata.name), "%s", api.name);
        CopyDescription(definition->metadata.parameters, std::size(definition->metadata.parameters), api.parameters);
    }
    else if (definition->runtime)
    {
        definition->metadata.argumentCount = runtime->CapturedArgumentCount();
        dr_snprintf(definition->metadata.module, std::size(definition->metadata.module), "COM");
        dr_snprintf(definition->metadata.name, std::size(definition->metadata.name), "%s::%s",
            contract->name, runtime->name);
        CopyDescription(definition->metadata.parameters, std::size(definition->metadata.parameters), runtime->description);
    }
    else
    {
        definition->metadata.argumentCount = RawArgumentCount;
        auto name = module ? dr_module_preferred_name(module) : nullptr;
        dr_snprintf(definition->metadata.module, std::size(definition->metadata.module), "%s", name ? name : "COM");
        if (typeName)
            dr_snprintf(definition->metadata.name, std::size(definition->metadata.name),
                "%.320s [RTTI]::slot %u", typeName, slot);
        else
            dr_snprintf(definition->metadata.name, std::size(definition->metadata.name),
                "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}::slot %u", iid.Data1, iid.Data2, iid.Data3,
                iid.Data4[0], iid.Data4[1], iid.Data4[2], iid.Data4[3], iid.Data4[4], iid.Data4[5], iid.Data4[6],
                iid.Data4[7], slot);
        constexpr wchar_t description[] = L"instance and raw native argument slots; interface signature unavailable";
        memcpy(definition->metadata.parameters, description, sizeof(description));
    }

    RpcCaptureState proxy;
    if (!rttiLocator && typed == Api::Count &&
        PrepareRpcProxyCapture(proxy, reinterpret_cast<uint64_t>(table), &iid, slot, &definition->signature))
    {
        definition->rpcProxy = true;
        definition->runtime = nullptr;
        definition->metadata.argumentCount = proxy.info.argumentCount;
        dr_snprintf(definition->metadata.module, std::size(definition->metadata.module), "COM");
        dr_snprintf(definition->metadata.name, std::size(definition->metadata.name),
            "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}::%s %u", iid.Data1, iid.Data2, iid.Data3,
            iid.Data4[0], iid.Data4[1], iid.Data4[2], iid.Data4[3],
            iid.Data4[4], iid.Data4[5], iid.Data4[6], iid.Data4[7], slot & 1 ? "Begin" : "Finish",
            (slot - UnknownSlotCount) / 2);
        CopyDescription(definition->metadata.parameters, std::size(definition->metadata.parameters),
            L"instance and NDR-described arguments -> HRESULT");
    }

    // Raw slot labels do not establish an API category until a typed contract is known.
    definition->metadata.category = definition->known || definition->runtime ?
        ClassifyApi(definition->metadata.module, definition->metadata.name) : ApiCategory::Unclassified;
    definition->categoryMask = CategoryMask(definition->metadata.category);
    definition->nameHash = ApiNameHash(definition->metadata.name);
    definition->asyncRole = AsyncRole(definition->metadata.module, definition->metadata.name);
    definition->nextAll = AllExports;
    AllExports = definition;
    if (primary)
    {
        if (shared) InterlockedExchange(&primary->sharedComAddress, 1);
        definition->nextVariant = primary->variants;
        InterlockedExchangePointer(reinterpret_cast<void* volatile*>(&primary->variants), definition);
    }
    else
    {
        definition->interfaceWrapPending = true;
        definition->next = Exports[bucket];
        Exports[bucket] = definition;
    }
    auto pending = !primary ? definition : primary->interfaceWrapPending ? primary : nullptr;
    dr_mutex_unlock(DefinitionLock);
    if (module) dr_free_module_data(module);

    // Match the receiver's vtable for both image implementations and runtime-generated executable thunks.
    if (pending) InstallInterfaceWrap(*pending);
    dr_mutex_lock(DefinitionLock);
    if (!rttiLocator && !queryProbe)
    {
        if (primary && primary->rttiLocator) CountExportCoverage(*primary, true);
        CountExportCoverage(*definition, true);
    }
    dr_mutex_unlock(DefinitionLock);
}

void ObserveExtensionPointer(void* address, const char* name, uint32_t count, ExportSignature signature,
    const char* contractModule = "mswsock.dll")
{
    uint protection = 0;
    if (!address || count > MaximumArguments ||
        !dr_query_memory(static_cast<const byte*>(address), nullptr, nullptr, &protection) ||
        !(protection & DR_MEMPROT_EXEC)) return;
    auto module = dr_lookup_module(static_cast<app_pc>(address));
    if (!module) return;
    auto provider = dr_module_preferred_name(module);
    if (!provider) { dr_free_module_data(module); return; }

    // Providers can return executable entry points absent from their export tables.
    auto bucket = (reinterpret_cast<uintptr_t>(address) >> 4) % ExportBuckets;
    dr_mutex_lock(DefinitionLock);
    auto existing = Exports[bucket];
    while (existing && (existing->address != address || existing->retired)) existing = existing->next;
    if (existing)
    {
        dr_mutex_unlock(DefinitionLock);
        dr_free_module_data(module);
        return;
    }
    auto definition = static_cast<InstructionDefinition*>(dr_global_alloc(sizeof(InstructionDefinition)));
    memset(definition, 0, sizeof(*definition));
    definition->typed = Api::Count;
    definition->id = static_cast<Api>(NextExportId++);
    definition->mask = Win32Apis;
    definition->runtime = RuntimeDefinitionFor(provider, name);
    if (!definition->runtime && _stricmp(provider, contractModule))
        definition->runtime = RuntimeDefinitionFor(contractModule, name);
    definition->signature = definition->runtime ? definition->runtime->signature : signature;
    definition->address = address;
    definition->module = module->start;
    dr_snprintf(definition->metadata.module, std::size(definition->metadata.module), "%s", provider);
    dr_snprintf(definition->metadata.name, std::size(definition->metadata.name), "%s", name);
    definition->metadata.argumentCount = definition->runtime ? definition->runtime->argumentCount : count;
    if (definition->runtime)
        CopyDescription(definition->metadata.parameters, std::size(definition->metadata.parameters),
            definition->runtime->description);
    else
        CopyDescription(definition->metadata.parameters, std::size(definition->metadata.parameters),
            L"Extension pointer; raw arguments, parameter types unavailable");
    definition->metadata.category = ClassifyApi(provider, name);
    definition->categoryMask = CategoryMask(definition->metadata.category);
    definition->nameHash = ApiNameHash(name);
    definition->asyncRole = AsyncRole(definition->metadata.module, definition->metadata.name);
    definition->sourceNameHash = definition->nameHash;
    definition->next = Exports[bucket];
    Exports[bucket] = definition;
    definition->nextAll = AllExports;
    AllExports = definition;
    dr_mutex_unlock(DefinitionLock);
    dr_free_module_data(module);

    // Register before the application resumes from its lookup and can invoke the returned entry point.
    definition->wrapped = drwrap_wrap_ex(static_cast<app_pc>(address), &ExportEntered, &ExportLeft,
        definition, InstructionWrapConvention);
    if (!definition->wrapped)
    {
        definition->retired = true;
        InstructionTransport.Header()->moduleRefreshError = ERROR_NOT_SUPPORTED;
        return;
    }
    dr_mutex_lock(DefinitionLock);
    CountExportCoverage(*definition, true);
    dr_mutex_unlock(DefinitionLock);
}

bool ReplaceRpcMarshalSlot(void** slot, void* expected, void* replacement)
{
    MEMORY_BASIC_INFORMATION region{};
    if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), slot, MemoryBasicInformation,
        &region, sizeof(region), nullptr)) || region.State != MEM_COMMIT ||
        region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    const auto writable = region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    void* base = slot;
    SIZE_T length = sizeof(void*);
    ULONG protection = 0, ignored = 0;
    if (!NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &base, &length, writable, &protection))) return false;
    bool changed = false;
    DR_TRY_EXCEPT(dr_get_current_drcontext(),
        { changed = InterlockedCompareExchangePointer(slot, replacement, expected) == expected; },
        { changed = false; });
    NtProtectVirtualMemory(NtCurrentProcess(), &base, &length, protection, &ignored);
    return changed;
}

void RestoreRpcMarshaler(InstructionDefinition& definition)
{
    if (!definition.marshalSlot) return;

    // Cached pointers remain callable after detach, including a preceding native capture's observer entry.
    auto entry = static_cast<byte*>(definition.address);
    ReplaceRpcMarshalSlot(reinterpret_cast<void**>(entry + MarshalThunkTargetOffset),
        definition.marshalTarget, definition.marshalOriginal);
    ReplaceRpcMarshalSlot(definition.marshalSlot, definition.address, definition.marshalOriginal);
}

void WINAPI ObserveRpcMarshaler(uint64_t routines, uint32_t index, uint32_t bytes)
{
    if (!routines || routines % alignof(void*) || index > UINT16_MAX || !bytes ||
        routines > UINTPTR_MAX - (uint64_t{index} + 1) * sizeof(void*) * 4) return;
    auto table = reinterpret_cast<void**>(routines) + index * 4;
    byte* code = nullptr;
    uint32_t used = 0;
    for (uint32_t operation : {1u, 2u})
    for (uint32_t attempt = 0; attempt < 3; ++attempt)
    {
        void* previous = nullptr;
        uint protection = 0;
        auto slot = table + operation;
        if (!ReadCaptureMemory(slot, &previous, sizeof(previous)) || !previous ||
            !dr_query_memory(static_cast<byte*>(previous), nullptr, nullptr, &protection) ||
            !(protection & DR_MEMPROT_EXEC)) break;
        auto original = NativeRpcMarshalerOriginal ?
            reinterpret_cast<void*>(NativeRpcMarshalerOriginal(reinterpret_cast<uint64_t>(previous))) : previous;
        dr_mutex_lock(DefinitionLock);
        auto existing = RpcMarshalDefinitions;
        for (; existing; existing = existing->nextVariant)
            if (!existing->retired && existing->marshalSlot == slot &&
                (existing->address == previous || existing->address == original)) break;
        if (existing && static_cast<uint32_t>(existing->marshalBytes) != bytes)
            InterlockedExchange(&existing->marshalBytes, 0);
        const bool full = RpcMarshalDefinitionCount >= MaxRpcMarshalDefinitions;
        dr_mutex_unlock(DefinitionLock);
        if (existing)
        {
            // Reuse a client entry underneath a native wrapper without making its fallback point back to itself.
            if (previous == existing->address || ReplaceRpcMarshalSlot(slot, previous, existing->address)) break;
            continue;
        }
        if (full) break;

        if (!code) code = static_cast<byte*>(dr_raw_mem_alloc(dr_page_size(),
            DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC, nullptr));
        if (!code) { InstructionTransport.Header()->moduleRefreshError = ERROR_NOT_ENOUGH_MEMORY; break; }
        auto entry = code + used;
        used += MarshalThunkStride;

        // Each table slot has a distinct, ABI-preserving tail jump in process-lifetime application memory.
        entry[0] = 0xFF;
        entry[1] = 0x25;
#ifdef _WIN64
        const uint32_t operand = 2;
#else
        const auto operand = reinterpret_cast<uint32_t>(entry + MarshalThunkTargetOffset);
#endif
        memcpy(entry + 2, &operand, sizeof(operand));
        memcpy(entry + MarshalThunkTargetOffset, &original, sizeof(original));
        auto module = dr_lookup_module(static_cast<app_pc>(original));
        auto definition = static_cast<InstructionDefinition*>(dr_global_alloc(sizeof(InstructionDefinition)));
        memset(definition, 0, sizeof(*definition));
        definition->typed = Api::Count;
        definition->mask = Win32Apis;
        definition->signature.supported = true;
        definition->signature.resultBytes = sizeof(void*);
        definition->signature.callingConvention = ExportCallingConvention::Stdcall;
        std::fill_n(definition->signature.argumentBytes, 3, static_cast<uint8_t>(sizeof(void*)));
        definition->address = entry;
        definition->module = module ? module->start : nullptr;
        definition->marshalSlot = slot;
        definition->marshalOriginal = previous;
        definition->marshalTarget = original;
        definition->marshalOperation = operation;
        definition->marshalBytes = static_cast<LONG>(bytes);
        definition->metadata.argumentCount = 3;
        definition->metadata.category = ApiCategory::Ipc;
        definition->categoryMask = CategoryMask(ApiCategory::Ipc);
        dr_snprintf(definition->metadata.module, std::size(definition->metadata.module), "RPC");
        dr_snprintf(definition->metadata.name, std::size(definition->metadata.name),
            operation == 1 ? "RPC user marshal #%u" : "RPC user unmarshal #%u", index);
        CopyDescription(definition->metadata.parameters, std::size(definition->metadata.parameters),
            L"ULONG* flags, BYTE* wire, void* nativeValue -> BYTE*");
        definition->nameHash = ApiNameHash(definition->metadata.name);
        definition->sourceNameHash = definition->nameHash;
        if (module) dr_free_module_data(module);
        dr_mutex_lock(DefinitionLock);
        definition->id = static_cast<Api>(NextExportId++);
        definition->nextAll = AllExports;
        AllExports = definition;
        definition->nextVariant = RpcMarshalDefinitions;
        RpcMarshalDefinitions = definition;
        ++RpcMarshalDefinitionCount;
        const auto bucket = (reinterpret_cast<uintptr_t>(entry) >> 4) % ExportBuckets;
        definition->next = Exports[bucket];
        Exports[bucket] = definition;
        dr_mutex_unlock(DefinitionLock);

        // Register the fresh entry before publishing it; another observer may concurrently replace the slot.
        definition->wrapped = drwrap_wrap_ex(entry, &ExportEntered, &ExportLeft, definition, InstructionWrapConvention);
        if (definition->wrapped && ReplaceRpcMarshalSlot(slot, previous, entry))
        {
            dr_mutex_lock(DefinitionLock);
            CountExportCoverage(*definition, true);
            dr_mutex_unlock(DefinitionLock);
            break;
        }
        definition->retired = true;
        if (definition->wrapped) drwrap_unwrap(entry, &ExportEntered, &ExportLeft);
        else { InstructionTransport.Header()->moduleRefreshError = ERROR_NOT_SUPPORTED; break; }
    }
    if (code)
    {
        void* base = code;
        SIZE_T length = dr_page_size();
        ULONG protection = 0;
        NtProtectVirtualMemory(NtCurrentProcess(), &base, &length, PAGE_EXECUTE_READ, &protection);
    }
}

void DiscoverWglExtension(const InstructionFrame& call)
{
    if (call.event.flags & (Failed | Skipped | Unwound) || call.event.result <= 3 ||
        call.event.result == UINT64_MAX) return;
    char name[128]{};
    auto address = call.event.arguments[0];
    if (!address) return;

    // The resolver supplies the extension identity; the executable image supplies its provider and lifetime.
    for (size_t index = 0; index < std::size(name); ++index)
    {
        if (!ReadCaptureMemory(reinterpret_cast<void*>(address + index), name + index, 1)) return;
        if (name[index]) continue;
        if (!strncmp(name, "wgl", 3) || !strncmp(name, "gl", 2))
            ObserveExtensionPointer(reinterpret_cast<void*>(call.event.result), name, RawArgumentCount,
                {}, "opengl32.dll");
        return;
    }
}

void DiscoverWinsockExtensions(const InstructionFrame& call)
{
    const auto& arguments = call.event.arguments;
    auto code = static_cast<DWORD>(arguments[1]);
    if (call.event.result || arguments[3] < sizeof(GUID) || !arguments[4] || !arguments[6]) return;
    DWORD returned = 0;
    GUID identity{};
    if (!ReadCaptureMemory(reinterpret_cast<void*>(arguments[2]), &identity, sizeof(identity)) ||
        !ReadCaptureMemory(reinterpret_cast<void*>(arguments[6]), &returned, sizeof(returned))) return;
    returned = static_cast<DWORD>(std::min<uint64_t>(returned, arguments[5]));

    // A single extension GUID yields a function pointer, including callbacks absent from DLL exports.
    if (code == SIO_GET_EXTENSION_FUNCTION_POINTER && returned >= sizeof(void*))
    {
        struct Extension
        {
            GUID identity;
            const char* name;
            uint32_t count;
            ExportSignature signature;
        };
        static const Extension extensions[] =
        {
            {WSAID_TRANSMITFILE, "TransmitFile", 7, ExportFunction<LPFN_TRANSMITFILE>::Signature()},
            {WSAID_ACCEPTEX, "AcceptEx", 8, ExportFunction<LPFN_ACCEPTEX>::Signature()},
            {WSAID_GETACCEPTEXSOCKADDRS, "GetAcceptExSockaddrs", 8,
                ExportFunction<LPFN_GETACCEPTEXSOCKADDRS>::Signature()},
            {WSAID_TRANSMITPACKETS, "TransmitPackets", 6,
                ExportFunction<LPFN_TRANSMITPACKETS>::Signature()},
            {WSAID_CONNECTEX, "ConnectEx", 7, ExportFunction<LPFN_CONNECTEX>::Signature()},
            {WSAID_DISCONNECTEX, "DisconnectEx", 4, ExportFunction<LPFN_DISCONNECTEX>::Signature()},
            {WSAID_WSARECVMSG, "WSARecvMsg", 5, ExportFunction<LPFN_WSARECVMSG>::Signature()},
            {WSAID_WSASENDMSG, "WSASendMsg", 6, ExportFunction<LPFN_WSASENDMSG>::Signature()},
            {WSAID_WSAPOLL, "WSAPoll", 3, ExportFunction<LPFN_WSAPOLL>::Signature()},
        };
        void* pointer = nullptr;
        if (!ReadCaptureMemory(reinterpret_cast<void*>(arguments[4]), &pointer, sizeof(pointer))) return;
        for (const auto& extension : extensions)
            if (!memcmp(&identity, &extension.identity, sizeof(identity)))
            {
                ObserveExtensionPointer(pointer, extension.name, extension.count, extension.signature);
                return;
            }
        return;
    }

    // Registered I/O returns a table of distinct internal callbacks rather than named exports.
    static const GUID rioIdentity = WSAID_MULTIPLE_RIO;
    if (code != SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER ||
        memcmp(&identity, &rioIdentity, sizeof(identity)) || returned < sizeof(RIO_EXTENSION_FUNCTION_TABLE)) return;
    RIO_EXTENSION_FUNCTION_TABLE table{};
    if (!ReadCaptureMemory(reinterpret_cast<void*>(arguments[4]), &table, sizeof(table)) ||
        table.cbSize < sizeof(table)) return;
    struct RioExtension
    {
        size_t offset;
        const char* name;
        uint32_t count;
        ExportSignature signature;
    };
#define RIO_EXTENSION(name, count) \
    {offsetof(RIO_EXTENSION_FUNCTION_TABLE, name), #name, count, \
        ExportFunction<decltype(RIO_EXTENSION_FUNCTION_TABLE::name)>::Signature()}
    static const RioExtension rio[] =
    {
        RIO_EXTENSION(RIOReceive, 5), RIO_EXTENSION(RIOReceiveEx, 9),
        RIO_EXTENSION(RIOSend, 5), RIO_EXTENSION(RIOSendEx, 9),
        RIO_EXTENSION(RIOCloseCompletionQueue, 1), RIO_EXTENSION(RIOCreateCompletionQueue, 2),
        RIO_EXTENSION(RIOCreateRequestQueue, 8), RIO_EXTENSION(RIODequeueCompletion, 3),
        RIO_EXTENSION(RIODeregisterBuffer, 1), RIO_EXTENSION(RIONotify, 1),
        RIO_EXTENSION(RIORegisterBuffer, 2), RIO_EXTENSION(RIOResizeCompletionQueue, 2),
        RIO_EXTENSION(RIOResizeRequestQueue, 3),
    };
#undef RIO_EXTENSION
    for (const auto& extension : rio)
    {
        void* pointer = nullptr;
        memcpy(&pointer, reinterpret_cast<const byte*>(&table) + extension.offset, sizeof(pointer));
        ObserveExtensionPointer(pointer, extension.name, extension.count, extension.signature);
    }
}

void DiscoverReturnedExtensions(InstructionFrame& frame)
{
    if (frame.definition->typed == Api::WSAIoctl && !(frame.event.flags & (Failed | Skipped)))
        DiscoverWinsockExtensions(frame);
    if (frame.definition->callbackRegistration) DiscoverRegisteredCallbacks(frame);
    if (frame.definition->wglLookup) DiscoverWglExtension(frame);
}

void DiscoverExports(const module_data_t* module)
{
    const auto name = ImageFileName(module);
    if (!name || !_stricmp(name, "DetouristAgent.dll") || !_stricmp(name, "DetouristProfiler.dll") ||
        !_stricmp(name, "DetouristInstructions.dll") || !_stricmp(name, "dynamorio.dll") ||
        !_stricmp(name, "drmgr.dll") || !_stricmp(name, "drwrap.dll") || !_stricmp(name, "drconfiglib.dll") ||
        !_stricmp(name, "clr.dll") || !_stricmp(name, "coreclr.dll") ||
        !_stricmp(name, "clrjit.dll") || !_stricmp(name, "mscorjit.dll")) return;
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS image{};
    IMAGE_EXPORT_DIRECTORY exports{};
    auto extent = static_cast<uint64_t>(module->end - module->start);
    if (!ReadCaptureMemory(module->start, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || uint64_t{static_cast<uint32_t>(dos.e_lfanew)} + sizeof(image) > extent ||
        !ReadCaptureMemory(module->start + dos.e_lfanew, &image, sizeof(image)) ||
        image.Signature != IMAGE_NT_SIGNATURE)
        return;

    // Export forwarder passes reuse immutable RTTI data until the image unloads.
    bool firstPass = true;
    dr_mutex_lock(DefinitionLock);
    auto empty = DiscoveredExportImages.end();
    for (auto scanned = DiscoveredExportImages.begin(); scanned != DiscoveredExportImages.end(); ++scanned)
    {
        if (*scanned == module->start) { firstPass = false; break; }
        if (!*scanned && empty == DiscoveredExportImages.end()) empty = scanned;
    }
    if (firstPass && empty != DiscoveredExportImages.end()) *empty = module->start;
    dr_mutex_unlock(DefinitionLock);

    if (firstPass) DiscoverImageInterfaces(module, uint64_t{static_cast<uint32_t>(dos.e_lfanew)} +
        offsetof(IMAGE_NT_HEADERS, OptionalHeader) + image.FileHeader.SizeOfOptionalHeader,
        image.FileHeader.NumberOfSections);
    const auto& directory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto observe = [&](const char* symbolName, DWORD functionRva, DWORD ordinal,
        const RuntimeExport* callback = nullptr)
    {
        if (!functionRva || functionRva > UINTPTR_MAX - reinterpret_cast<uintptr_t>(module->start) ||
            (callback && functionRva >= extent)) return;
        auto address = module->start + functionRva;
        const bool nonImageEntry = functionRva >= extent && NonImageExportAddress(address);
        if (functionRva >= extent && !nonImageEntry) return;
        char exportName[MaximumApiNameBytes]{};
        if (symbolName) ReadInstructionString(symbolName, exportName, std::size(exportName));
        else
        {
            auto alias = InstructionTransport.catalog.OrdinalName(name, ordinal);
            if (alias) dr_snprintf(exportName, std::size(exportName), "%s", alias);
            else dr_snprintf(exportName, std::size(exportName), "Ordinal #%llu", static_cast<uint64_t>(ordinal));
        }
        if (!*exportName) return;
        auto typed = callback ? Api::Count : FindExportType(name, exportName);
        if (!callback && functionRva < extent && directory.VirtualAddress && functionRva >= directory.VirtualAddress &&
            uint64_t{functionRva} < uint64_t{directory.VirtualAddress} + directory.Size)
        {
            address = ForwardAddress(reinterpret_cast<const char*>(address));
        }
        uint protection = 0;
        if (!address || !dr_query_memory(address, nullptr, nullptr, &protection) ||
            !(protection & DR_MEMPROT_EXEC)) return;
        if (!_stricmp(name, "ntdll.dll") && exportName[0] == 'Z' && exportName[1] == 'w')
        {
            exportName[0] = 'N';
            exportName[1] = 't';
        }
        auto registered = RegisteredCallbackFor(name, exportName);
        bool conflictingCallback = registered && !registered->argumentCount;
        auto runtime = conflictingCallback ? nullptr : callback ? callback : registered ? registered :
            RuntimeDefinitionFor(name, exportName);
        if (conflictingCallback) typed = Api::Count;
        auto bucket = (reinterpret_cast<uintptr_t>(address) >> 4) % ExportBuckets;
        dr_mutex_lock(DefinitionLock);
        auto existing = Exports[bucket];
        while (existing && existing->address != address) existing = existing->next;
        bool namedOrdinal = existing && symbolName && !callback &&
            !strncmp(existing->metadata.name, "Ordinal #", 9);
        bool typedRuntime = existing && runtime && (!existing->runtime || registered && existing->runtime != runtime);
        uint32_t argumentCount = typed != Api::Count ? Definition(typed).argumentCount :
            runtime ? runtime->CapturedArgumentCount() : RawArgumentCount;

        // A forwarded name cannot redefine the identity of its physical provider's executable address.
        bool physicalAlias = existing && existing->module == module->start &&
            (nonImageEntry || (address >= module->start && address < module->end));

        // Compatible signatures still need the imported name to distinguish folded exports.
        bool distinctAlias = physicalAlias && !namedOrdinal && strcmp(existing->metadata.name, exportName);
        if (distinctAlias)
            InterlockedExchange(&existing->sharedExport, 1);
        auto previousParameters = existing && existing->runtime ? existing->runtime->description :
            existing && existing->known ? Definition(existing->typed).parameters : nullptr;
        auto candidateParameters = runtime ? runtime->description :
            typed != Api::Count ? Definition(typed).parameters : nullptr;
        bool incompatibleTypes = physicalAlias && previousParameters && *previousParameters &&
            candidateParameters && *candidateParameters &&
            !EquivalentExportParameterTypes(previousParameters, candidateParameters);
        bool ambiguousAlias = conflictingCallback || distinctAlias && !symbolName ||
            physicalAlias && (existing->known || existing->runtime) && (typed != Api::Count || runtime) &&
            (existing->metadata.argumentCount != argumentCount || incompatibleTypes ||
                existing->runtime && runtime && existing->runtime->resultCaptureKind != runtime->resultCaptureKind);
        if (existing && (existing->ambiguousExport ||
            !ambiguousAlias && (existing->known || (typed == Api::Count && !namedOrdinal && !typedRuntime))))
        {
            dr_mutex_unlock(DefinitionLock);
            return;
        }
        if (!existing && !nonImageEntry && (address < module->start || address >= module->end))
        {
            dr_mutex_unlock(DefinitionLock);
            return;
        }
        auto definition = static_cast<InstructionDefinition*>(dr_global_alloc(sizeof(InstructionDefinition)));
        memset(definition, 0, sizeof(*definition));
        if (ambiguousAlias)
            dr_snprintf(exportName, std::size(exportName), "Shared export RVA 0x%X", functionRva);
        definition->typed = ambiguousAlias ? Api::Count : typed;
        definition->known = definition->typed != Api::Count;
        definition->id = definition->known ? definition->typed : static_cast<Api>(NextExportId++);
        definition->mask = definition->known ? ApiMask(definition->typed) :
            !_stricmp(name, "ntdll.dll") ? NativeApis : !_stricmp(name, "win32u.dll") ? Win32uApis : Win32Apis;
        definition->runtime = ambiguousAlias ? nullptr : runtime;
        definition->wglLookup = !_stricmp(name, "opengl32.dll") && !strcmp(exportName, "wglGetProcAddress");
        definition->ambiguousExport = ambiguousAlias;
        definition->sharedExport = ambiguousAlias || existing && existing->sharedExport;
        definition->signature = definition->runtime ? definition->runtime->signature : SignatureFor(definition->typed);
        definition->interfaceInputs = PublicInterfaceInputs(definition->typed);
        definition->entryOnly = !_stricmp(name, "ntdll.dll") && !strcmp(exportName, "KiUserCallbackDispatcher");
        definition->continuation = definition->entryOnly || !strcmp(exportName, "NtContinue") ||
            !strcmp(exportName, "NtContinueEx") ||
            !strcmp(exportName, "NtCallbackReturn") || !strcmp(exportName, "NtRaiseException") ||
            !strcmp(exportName, "NtTerminateProcess") || !strcmp(exportName, "NtTerminateThread") ||
            !strcmp(exportName, "RtlUserThreadStart") || !strcmp(exportName, "BaseThreadInitThunk") ||
            !strcmp(exportName, "RtlExitUserProcess") || !strcmp(exportName, "RtlExitUserThread") ||
            !strcmp(exportName, "ExitProcess") || !strcmp(exportName, "ExitThread") || !strcmp(exportName, "FatalExit");
        definition->address = address;
        definition->module = existing ? existing->module : module->start;
        dr_snprintf(definition->metadata.module, std::size(definition->metadata.module), "%s", name);
        dr_snprintf(definition->metadata.name, std::size(definition->metadata.name), "%s", exportName);
        if (definition->known)
        {
            const auto& api = Definition(definition->typed);
            definition->metadata.argumentCount = api.argumentCount;
            CopyDescription(definition->metadata.parameters, std::size(definition->metadata.parameters), api.parameters);
        }
        else if (definition->runtime)
        {
            definition->metadata.argumentCount = definition->runtime->CapturedArgumentCount();
            CopyDescription(definition->metadata.parameters, std::size(definition->metadata.parameters),
                definition->runtime->description);
            definition->optionalMode = !definition->runtime->rawTailStart &&
                (!_strnicmp(name, "msvcr", 5) || !_stricmp(name, "ucrtbase.dll")) &&
                ((!strcmp(exportName, "_open") || !strcmp(exportName, "_wopen")) &&
                    definition->runtime->argumentCount == 3 ||
                 (!strcmp(exportName, "_sopen") || !strcmp(exportName, "_wsopen")) &&
                    definition->runtime->argumentCount == 4);
        }
        else
        {
            auto rawCount = !_stricmp(name, "win32u.dll") ? RawWin32uArguments(exportName) : 0;
            definition->metadata.argumentCount = rawCount ? rawCount : RawArgumentCount;
            constexpr wchar_t inferred[] =
                L"Raw native slots; stack extent from win32k; types unknown";
            constexpr wchar_t unknown[] = L"Raw native argument slots; signature unavailable";
            if (rawCount) memcpy(definition->metadata.parameters, inferred, sizeof(inferred));
            else memcpy(definition->metadata.parameters, unknown, sizeof(unknown));
        }

        // Shared implementations cannot identify the invoked export, so expose their named candidates.
        if (ambiguousAlias && exports.NumberOfNames && address == module->start + functionRva)
        {
            constexpr wchar_t heading[] = L"Raw native slots; shared executable address; possible named exports: ";
            auto& description = definition->metadata.parameters;
            memcpy(description, heading, sizeof(heading));
            size_t length = std::size(heading) - 1;
            bool appended = false;
            bool truncated = false;
            for (DWORD index = 0; index < exports.NumberOfNames; ++index)
            {
                DWORD nameRva = 0, candidateRva = 0;
                WORD ordinalIndex = 0;
                if (!ReadCaptureMemory(module->start + exports.AddressOfNames + uint64_t{index} * sizeof(DWORD),
                        &nameRva, sizeof(nameRva)) ||
                    nameRva >= extent ||
                    !ReadCaptureMemory(module->start + exports.AddressOfNameOrdinals + uint64_t{index} * sizeof(WORD),
                        &ordinalIndex, sizeof(ordinalIndex)) ||
                    ordinalIndex >= exports.NumberOfFunctions ||
                    !ReadCaptureMemory(
                        module->start + exports.AddressOfFunctions + uint64_t{ordinalIndex} * sizeof(DWORD),
                        &candidateRva, sizeof(candidateRva)) ||
                    candidateRva != functionRva)
                    continue;
                char candidate[128]{};
                ReadInstructionString(reinterpret_cast<const char*>(module->start + nameRva),
                    candidate, std::size(candidate));
                auto size = strlen(candidate);
                if (!size) continue;
                if (length + size + (appended ? 2 : 0) + 6 >= std::size(description))
                {
                    truncated = true;
                    continue;
                }
                if (appended)
                {
                    description[length++] = L';';
                    description[length++] = L' ';
                }
                for (size_t offset = 0; offset < size; ++offset)
                    description[length++] = static_cast<unsigned char>(candidate[offset]);
                description[length] = 0;
                appended = true;
            }
            if (truncated && length + 5 < std::size(description))
            {
                memcpy(description + length, L"; ...", sizeof(L"; ..."));
            }
        }
        definition->stackProbe = definition->metadata.argumentCount == 1 && !strcmp(exportName, "__chkstk");

        // Provider aliases and API-set facades use their catalog identity for category filtering.
        auto categorySource = registered ? registered->categorySource : nullptr;
        definition->metadata.category = categorySource ? ClassifyApi(categorySource->module, categorySource->name) :
            definition->known ?
            ClassifyApi(Definition(definition->typed).module, Definition(definition->typed).name) :
            ClassifyApi(definition->metadata.module, definition->metadata.name);
        definition->categoryMask = CategoryMask(definition->metadata.category);
        definition->nameHash = ApiNameHash(definition->metadata.name);
        definition->asyncRole = AsyncRole(definition->metadata.module, definition->metadata.name);
        if (existing)
        {
            // Active invocations retain their immutable metadata while a named forwarder replaces the raw identity.
            definition->variants = existing->variants;
            if (existing->interfaceTable)
            {
                existing->nextVariant = definition->variants;
                definition->variants = existing;
            }
            CountExportCoverage(*existing, false);
            existing->wrapped = false;
        }
        definition->next = Exports[bucket];
        Exports[bucket] = definition;
        definition->nextAll = AllExports;
        AllExports = definition;
        dr_mutex_unlock(DefinitionLock);

        // Wrapping can flush translated code, so no client lock may be held here.
        definition->wrapped = drwrap_wrap_ex(address, &ExportEntered,
            definition->entryOnly ? nullptr : &ExportLeft, definition,
            InstructionWrapConvention);
        if (!definition->wrapped) InstructionTransport.Header()->moduleRefreshError = ERROR_NOT_SUPPORTED;
        dr_mutex_lock(DefinitionLock);
        CountExportCoverage(*definition, true);
        dr_mutex_unlock(DefinitionLock);
    };

    // The loader calls image entry points and TLS callbacks even in DLLs without exported functions.
    if (image.FileHeader.Characteristics & IMAGE_FILE_DLL)
        observe("DllMain", image.OptionalHeader.AddressOfEntryPoint, 0, RuntimeDefinitionFor(name, "DllMain"));
    const auto& tlsDirectory = image.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    IMAGE_TLS_DIRECTORY tls{};
    if (tlsDirectory.VirtualAddress && tlsDirectory.Size >= sizeof(tls) &&
        uint64_t{tlsDirectory.VirtualAddress} + sizeof(tls) <= extent &&
        ReadCaptureMemory(module->start + tlsDirectory.VirtualAddress, &tls, sizeof(tls)))
    {
        auto base = reinterpret_cast<uintptr_t>(module->start);
        auto table = tls.AddressOfCallBacks;
        for (uint32_t index = 0; table >= base && table - base + sizeof(uintptr_t) <= extent; ++index)
        {
            uintptr_t address = 0;
            if (!ReadCaptureMemory(reinterpret_cast<void*>(table), &address, sizeof(address)) || !address) break;
            if (address >= base && address - base < extent)
            {
                char callbackName[64];
                dr_snprintf(callbackName, std::size(callbackName), "TlsCallback #%u", index + 1);
                observe(callbackName, static_cast<DWORD>(address - base), 0, RuntimeDefinitionFor(name, "TlsCallback"));
            }
            table += sizeof(uintptr_t);
        }
    }

    // Validate the export tables independently of loader callbacks.
    if (!directory.VirtualAddress || uint64_t{directory.VirtualAddress} + sizeof(exports) > extent ||
        !ReadCaptureMemory(module->start + directory.VirtualAddress, &exports, sizeof(exports)) ||
        !exports.NumberOfFunctions) return;
    if (exports.NumberOfFunctions > MaxExportDirectoryEntries || exports.NumberOfNames > MaxExportDirectoryEntries ||
        uint64_t{exports.AddressOfFunctions} + uint64_t{exports.NumberOfFunctions} * sizeof(DWORD) > extent ||
        uint64_t{exports.AddressOfNames} + uint64_t{exports.NumberOfNames} * sizeof(DWORD) > extent ||
        uint64_t{exports.AddressOfNameOrdinals} + uint64_t{exports.NumberOfNames} * sizeof(WORD) > extent)
    {
        InstructionTransport.Header()->moduleRefreshError = ERROR_INVALID_DATA;
        return;
    }

    // Read the complete export address table so ordinal-only APIs receive the same tracing as named exports.
    auto named = static_cast<byte*>(dr_global_alloc(exports.NumberOfFunctions));
    memset(named, 0, exports.NumberOfFunctions);
    for (DWORD index = 0; index < exports.NumberOfNames; ++index)
    {
        DWORD nameRva = 0, functionRva = 0;
        WORD ordinalIndex = 0;
        if (!ReadCaptureMemory(module->start + exports.AddressOfNames + uint64_t{index} * sizeof(DWORD),
                &nameRva, sizeof(nameRva)) || nameRva >= extent ||
            !ReadCaptureMemory(module->start + exports.AddressOfNameOrdinals + uint64_t{index} * sizeof(WORD),
                &ordinalIndex, sizeof(ordinalIndex)) || ordinalIndex >= exports.NumberOfFunctions ||
            !ReadCaptureMemory(module->start + exports.AddressOfFunctions + uint64_t{ordinalIndex} * sizeof(DWORD),
                &functionRva, sizeof(functionRva))) continue;
        named[ordinalIndex] = 1;
        observe(reinterpret_cast<const char*>(module->start + nameRva), functionRva, exports.Base + ordinalIndex);
    }
    for (DWORD index = 0; index < exports.NumberOfFunctions; ++index)
    {
        DWORD functionRva = 0;
        if (!named[index] &&
            ReadCaptureMemory(module->start + exports.AddressOfFunctions + uint64_t{index} * sizeof(DWORD),
                &functionRva, sizeof(functionRva)))
            observe(nullptr, functionRva, exports.Base + index);
    }
    dr_global_free(named, exports.NumberOfFunctions);
}

void RemoveExports(const module_data_t* module)
{
    if (InternalCallerRanges)
        for (uint32_t slot = 0; slot < InternalNativeImageCount; ++slot)
            InterlockedCompareExchange64(InternalCallerRanges + slot * 2, 0,
                reinterpret_cast<LONG64>(module->start));
    if (NativeHookAddresses)
    {
        auto start = reinterpret_cast<LONG64>(module->start);
        auto end = reinterpret_cast<LONG64>(module->end);
        for (uint32_t index = 0; index < NativeHookCapacity; ++index)
        {
            auto address = NativeHookAddresses[index];
            if (address >= start && address < end)
                InterlockedCompareExchange64(&NativeHookAddresses[index], 1, address);
        }
    }
    dr_mutex_lock(DefinitionLock);
    for (auto& image : DiscoveredExportImages)
        if (image == module->start) image = nullptr;
    auto head = AllExports;
    dr_mutex_unlock(DefinitionLock);
    for (auto definition = head; definition; definition = definition->nextAll)
    {
        const auto table = reinterpret_cast<app_pc>(definition->marshalSlot);
        if (definition->retired || definition->module != module->start &&
            (!table || table < module->start || table >= module->end)) continue;
        dr_mutex_lock(DefinitionLock);
        definition->retired = true;
        CountExportCoverage(*definition, false);
        auto bucket = (reinterpret_cast<uintptr_t>(definition->address) >> 4) % ExportBuckets;
        auto link = &Exports[bucket];
        while (*link && *link != definition) link = &(*link)->next;
        if (*link) *link = definition->next;
        dr_mutex_unlock(DefinitionLock);
        RestoreRpcMarshaler(*definition);
        if (definition->wrapped)
            drwrap_unwrap(static_cast<app_pc>(definition->address), &ExportEntered,
                definition->entryOnly ? nullptr : &ExportLeft);
    }
}

void FreeExports()
{
    DiscoveredExportImages.fill(nullptr);
    FreeRegisteredCallbacks();
    if (InternalCallerRanges)
        for (uint32_t slot = 0; slot < InternalNativeImageCount; ++slot)
            InterlockedExchange64(InternalCallerRanges + slot * 2, 0);
    while (AllExports)
    {
        auto definition = AllExports;
        AllExports = definition->nextAll;
        RestoreRpcMarshaler(*definition);
        dr_global_free(definition, sizeof(*definition));
    }
    RpcMarshalDefinitions = nullptr;
    RpcMarshalDefinitionCount = 0;
}
}

#include "ComLayout.h"
#pragma warning(push, 0)
#include <windows.h>
#include <objbase.h>
#include <oaidl.h>
#include <roapi.h>
#include <winstring.h>
#include "dr_api.h"
#include "drmgr.h"
#pragma warning(pop)
#include "InstructionCapture.h"
#include "ComCaptureValues.h"
#include <algorithm>
#include <atomic>

namespace Detourist
{
constexpr size_t ObservedComTableCapacity = 8192;
constexpr uint32_t MaxRttiBases = 1024;
constexpr size_t MaxPeSections = 96;
constexpr size_t RttiCandidateBuckets = 256;
constexpr uint64_t MaxMultiQiCount = 65536;

struct ObservedComTable
{
    void** table = nullptr;
    GUID iid{};
    uint32_t declared = 0;
    std::array<void*, UnknownSlotCount> prefix{};
    uint64_t generation = 0;
};
std::array<ObservedComTable, ObservedComTableCapacity> ObservedComTables{};
std::atomic<uint64_t> NextComGeneration = 0;

ObservedComTable FindObservedComTable(void* table)
{
    auto hash = (reinterpret_cast<uintptr_t>(table) >> 3) % ObservedComTables.size();
    ObservedComTable observed{};
    dr_mutex_lock(DefinitionLock);
    for (size_t index = 0; index < ObservedComTables.size(); ++index)
    {
        const auto& current = ObservedComTables[(hash + index) % ObservedComTables.size()];
        if (!current.table) break;
        if (current.table == table) { observed = current; break; }
    }
    dr_mutex_unlock(DefinitionLock);
    return observed;
}

bool PlainObservedTable(void** table)
{
    auto observed = FindObservedComTable(table);
    auto contract = observed.table ? RuntimeInterfaceFor(observed.iid) : nullptr;
    return contract && !contract->comPrefix;
}

void ForgetComTables(const module_data_t* module)
{
    // Tombstones preserve lookup chains when an image's table addresses become available for reuse.
    dr_mutex_lock(DefinitionLock);
    for (auto& value : ObservedComTables)
        if (reinterpret_cast<app_pc>(value.table) >= module->start &&
            reinterpret_cast<app_pc>(value.table) < module->end)
            value.table = reinterpret_cast<void**>(1);
    dr_mutex_unlock(DefinitionLock);
}

bool ReadComMemory(uint64_t address, void* destination, size_t bytes)
{
    if (!address || address > UINTPTR_MAX - bytes) return false;
    auto cursor = static_cast<uintptr_t>(address);
    const auto end = cursor + bytes;

    // Speculative interface probes must not consume the application's guard-page exception.
    while (cursor < end)
    {
        dr_mem_info_t region{};
        if (!dr_query_memory_ex(reinterpret_cast<const byte*>(cursor), &region) ||
            !(region.prot & DR_MEMPROT_READ) || (region.prot & DR_MEMPROT_GUARD)) return false;
        const auto base = reinterpret_cast<uintptr_t>(region.base_pc);
        if (region.size > UINTPTR_MAX - base || base + region.size <= cursor) return false;
        cursor = std::min<uintptr_t>(end, base + region.size);
    }
    return ReadCaptureMemory(reinterpret_cast<void*>(address), destination, bytes);
}

template<class Type> bool ComValue(uint64_t address, Type& value)
{
    return ReadComMemory(address, &value, sizeof(value));
}

bool ComMethod(void** table, uint32_t slot, dr_mem_info_t& entries, dr_mem_info_t& code, void*& method)
{
    // Successive slots and their methods usually share one data and one code region, so each is queried once.
    auto covers = [](const dr_mem_info_t& region, const void* address, size_t bytes)
    {
        auto offset = reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(region.base_pc);
        return offset <= region.size && bytes <= region.size - offset;
    };
    auto entry = table + slot;
    method = nullptr;
    if (!covers(entries, entry, sizeof(method)) && (!dr_query_memory_ex(reinterpret_cast<const byte*>(entry),
        &entries) || !(entries.prot & DR_MEMPROT_READ) || (entries.prot & DR_MEMPROT_GUARD) ||
        !covers(entries, entry, sizeof(method)))) return false;
    if (!ReadCaptureMemory(entry, &method, sizeof(method)) || !method) return false;
    return covers(code, method, 1) ||
        (dr_query_memory_ex(static_cast<const byte*>(method), &code) && (code.prot & DR_MEMPROT_EXEC));
}

bool ComTablePrefix(void* table, uint32_t slots, std::array<void*, UnknownSlotCount>& prefix)
{
    return slots && ReadComMemory(reinterpret_cast<uint64_t>(table), prefix.data(),
        std::min<size_t>(slots, prefix.size()) * sizeof(void*));
}

ExportSignature ComSignature(Api api)
{
#define COM_EXPORT(name) ExportFunction<decltype(&::name)>::Signature(),
#define COM_METHOD(id, owner, slot, ...) ExportFunction<__VA_ARGS__>::Signature(),
    static constexpr ExportSignature signatures[] =
    {
#include "ComCatalog.inc"
    };
#undef COM_EXPORT
#undef COM_METHOD
    return IsComApi(api) ? signatures[static_cast<uint32_t>(api) - ComApiStart] : ExportSignature{};
}

Api InterfaceApi(const GUID& iid, uint32_t slot)
{
    if (slot < UnknownSlotCount)
    {
        if (auto contract = RuntimeInterfaceFor(iid); contract && !contract->comPrefix) return Api::Count;
    }

    // Normalize inherited slots before selecting the catalog's method identity.
    const GUID* owner = slot < UnknownSlotCount ? &__uuidof(IUnknown) :
        iid == __uuidof(IActivationFactory) && slot < 6 ? &__uuidof(IInspectable) : &iid;
    struct Entry { const GUID* owner; uint32_t slot; Api api; };
    static const Entry methods[] =
    {
#define COM_EXPORT(name)
#define COM_METHOD(id, owner, slot, ...) {&__uuidof(owner), slot, Api::id},
#include "ComCatalog.inc"
#undef COM_EXPORT
#undef COM_METHOD
    };
    for (const auto& method : methods)
        if (slot == method.slot && *owner == *method.owner) return method.api;
    return Api::Count;
}

void ObserveInstructionTable(void** table, const GUID& iid, bool provisional = false,
    const char* typeName = nullptr, uint32_t limit = 0, void* rttiLocator = nullptr)
{
    auto count = iid == __uuidof(IUnknown) ? UnknownSlotCount : iid == __uuidof(IClassFactory) ? 5u :
        iid == __uuidof(IDispatch) || iid == __uuidof(IActivationFactory) || iid == __uuidof(IEnumVARIANT) ? 7u :
        iid == __uuidof(IInspectable) ? 6u : MaxComVtableSlots;

    // A known contract bounds discovery to its inherited methods, including output interface pointers.
    auto contract = RuntimeInterfaceFor(iid);
    if (contract) count = contract->slotCount;
    if (limit) count = rttiLocator ? std::min(limit, MaxComVtableSlots) : limit;
    if (rttiLocator || (contract && iid == KsPropertySetIid && !IsSystemDirectSound(table))) contract = nullptr;

    // Unknown contracts retain callable slots without changing the object's vtable or reference count.
    dr_mem_info_t entries{}, code{};
    for (uint32_t slot = 0; slot < count; ++slot)
    {
        void* address = nullptr;
        if (!ComMethod(table, slot, entries, code, address)) break;
        ObserveInterfaceMethod(address, table, iid, slot, rttiLocator ? Api::Count : InterfaceApi(iid, slot),
            contract, provisional, typeName, rttiLocator);
    }
}

void ObserveInstructionInterface(void* instance, const GUID& iid)
{
    void** table = nullptr;
    if (!instance || !ComValue(reinterpret_cast<uint64_t>(instance), table) || !table) return;
    if (iid == __uuidof(IUnknown) && PlainObservedTable(table)) return;
    auto contract = RuntimeInterfaceFor(iid);
    auto count = contract ? contract->slotCount : iid == __uuidof(IUnknown) ? UnknownSlotCount : 0u;

    // NDR descriptors establish the bounds of generated proxy interfaces absent from the SDK catalog.
    if (!count)
    {
        RpcCaptureState proxy;
        for (uint32_t slot = UnknownSlotCount; slot < MaxComVtableSlots &&
            PrepareRpcProxyCapture(proxy, reinterpret_cast<uint64_t>(table), &iid, slot); ++slot)
            count = slot + 1;
    }
    ObserveInstructionTable(table, iid, false, nullptr, count);
    if (!count) return;
    std::array<void*, UnknownSlotCount> prefix{};
    if (!ComTablePrefix(table, count, prefix))
        return;

    // Only a confirmed interface boundary admits its receiver table to call-site discovery.
    auto hash = (reinterpret_cast<uintptr_t>(table) >> 3) % ObservedComTables.size();
    dr_mutex_lock(DefinitionLock);
    ObservedComTable* available = nullptr;
    bool found = false;
    for (size_t index = 0; index < ObservedComTables.size(); ++index)
    {
        auto& current = ObservedComTables[(hash + index) % ObservedComTables.size()];
        if (current.table == table)
        {
            if (count >= current.declared || prefix != current.prefix)
                current = {table, iid, count, prefix, prefix == current.prefix ?
                    current.generation : ++NextComGeneration};
            available = nullptr;
            found = true;
            break;
        }
        if (current.table == reinterpret_cast<void**>(1)) { if (!available) available = &current; continue; }
        if (current.table) continue;
        if (!available) available = &current;
        break;
    }
    if (available) *available = {table, iid, count, prefix, ++NextComGeneration};
    else if (!found) InstructionTransport.Header()->moduleRefreshError = ERROR_NOT_ENOUGH_MEMORY;
    dr_mutex_unlock(DefinitionLock);
}

bool ValidateComGeneration(void* table, uint64_t generation)
{
    // An existing wrapper may authorize calls only for its confirmed table lifetime and base methods.
    auto observed = FindObservedComTable(table);
    std::array<void*, UnknownSlotCount> prefix{};
    return observed.table && observed.generation == generation &&
        ComTablePrefix(table, observed.declared, prefix) && prefix == observed.prefix;
}

void DiscoverComCall(void* target, uintptr_t instance, uintptr_t base, uint32_t slot, uintptr_t caller)
{
    if (!(InstructionTransport.Header()->enabledFilters & ComApis) || instance < MinimumUserAddress) return;

    // Register dispatch needs an established interface before probing arbitrary receiver memory.
    if (!base && !NextComGeneration.load(std::memory_order_relaxed)) return;
    auto existing = ExportDefinitionAt(target);
    void** table = nullptr;
    if (!ComValue(instance, table) || !table) return;

    // A non-vtable base cannot establish the slot of an indirect dispatch.
    if (base && base != reinterpret_cast<uintptr_t>(table)) { base = 0; slot = UINT32_MAX; }
    auto observed = FindObservedComTable(table);

    // A copied pointer retains its slot only when the established table confirms the loaded method.
    if (!base && observed.table && slot < observed.declared)
    {
        void* method = nullptr;
        if (ComValue(reinterpret_cast<uint64_t>(table + slot), method) && method == target)
            base = reinterpret_cast<uintptr_t>(table);
    }

    // A validated NDR proxy thunk identifies its method even when a helper call obscures the pointer copy.
    if (!base && observed.table && slot == UINT32_MAX && existing &&
        !InterlockedCompareExchange(&existing->sharedComAddress, 0, 0))
    {
        uint32_t matches = 0;
        for (uint32_t candidate = UnknownSlotCount; candidate < observed.declared; ++candidate)
        {
            void* method = nullptr;
            if (!ComValue(reinterpret_cast<uint64_t>(table + candidate), method)) return;
            if (method == target) { slot = candidate; ++matches; }
        }
        auto proxy = matches == 1 ? ResolveInterfaceDefinition(existing, instance, slot) : nullptr;
        if (proxy && proxy->rpcProxy && slot == proxy->interfaceSlot) base = reinterpret_cast<uintptr_t>(table);
        else slot = UINT32_MAX;
    }
    if (existing && !existing->interfaceTable && !base) return;
    if (!observed.table && !base) return;
    std::array<void*, UnknownSlotCount> prefix{};
    if (observed.table && (!ComTablePrefix(table, observed.declared, prefix) || prefix != observed.prefix)) return;

    // Only shared addresses and newly discovered slots need a call-site hint.
    if (base && caller && slot < MaxComVtableSlots && (observed.table && slot >= observed.declared ||
        (existing && (!existing->interfaceTable || InterlockedCompareExchange(&existing->sharedComAddress, 0, 0)))))
    {
        void* method = nullptr;
        if (ComValue(reinterpret_cast<uint64_t>(table + slot), method) && method == target)
        {
            auto thread = static_cast<InstructionThread*>(drmgr_get_tls_field(dr_get_current_drcontext(), ThreadSlot));
            if (thread)
            {
                thread->comTarget = target;
                thread->comInstance = instance;
                thread->comCaller = caller;
                thread->comSlot = slot;
            }
        }
    }
    if (!observed.table) return;
    if (existing)
    {
        auto bound = ResolveInterfaceDefinition(existing, instance, base ? slot : UINT32_MAX);
        if (existing->wrapped && bound && bound->interfaceTable == table &&
            (!base || bound->interfaceSlot == slot) && !bound->provisional && !bound->retired) return;
    }

    // A memory dispatch identifies its actual slot; register dispatches search only an established table.
    if (!base)
    {
        dr_mem_info_t entries{}, code{};
        for (slot = 0; slot < MaxComVtableSlots; ++slot)
        {
            void* method = nullptr;
            if (!ComMethod(table, slot, entries, code, method)) return;
            if (method == target) break;
        }
    }
    if (slot < observed.declared || slot >= MaxComVtableSlots) return;
    void* method = nullptr;
    uint protection = 0;
    if (!ComValue(reinterpret_cast<uint64_t>(table + slot), method) || method != target ||
        !dr_query_memory(static_cast<app_pc>(target), nullptr, nullptr, &protection) ||
        !(protection & DR_MEMPROT_EXEC)) return;
    ObserveInterfaceMethod(target, table, observed.iid, slot, Api::Count, nullptr,
        false, nullptr, nullptr, false, observed.generation);
}

void DiscoverQueryInterface(void* target, uintptr_t instance, uintptr_t identity, uintptr_t output)
{
    if (!(InstructionTransport.Header()->enabledFilters & ComApis) ||
        instance < MinimumUserAddress || identity < MinimumUserAddress || output < MinimumUserAddress) return;
    void** table = nullptr;
    void* methods[UnknownSlotCount]{}, *previous = nullptr;
    GUID iid{};
    if (!ComValue(instance, table) || !table || !ComValue(reinterpret_cast<uint64_t>(table), methods) ||
        methods[0] != target || !ComValue(identity, iid) || !ComValue(output, previous)) return;
    for (auto method : methods)
    {
        uint protection = 0;
        if (!method || !dr_query_memory(static_cast<app_pc>(method), nullptr, nullptr, &protection) ||
            !(protection & DR_MEMPROT_EXEC)) return;
    }
    if (PlainObservedTable(table)) return;

    // Bootstrap from the application's real interface query without calling into an undiscovered object.
    ObserveInterfaceMethod(target, table, __uuidof(IUnknown), 0, Api::ComQueryInterface, nullptr,
        false, nullptr, nullptr, true);
}

bool ConfirmQueryInterface(InstructionFrame& call)
{
    if (!InterlockedCompareExchange(&call.definition->queryProbe, 0, 0)) return true;
    if (call.event.flags & (Failed | Unwound)) return false;
    void* instance = nullptr;
    void** table = nullptr;
    void* methods[UnknownSlotCount]{};
    if (!ComValue(call.event.arguments[2], instance) || !instance ||
        !ComValue(reinterpret_cast<uint64_t>(instance), table) || !table ||
        !ComValue(reinterpret_cast<uint64_t>(table), methods)) return false;
    for (auto method : methods)
    {
        uint protection = 0;
        if (!method || !dr_query_memory(static_cast<app_pc>(method), nullptr, nullptr, &protection) ||
            !(protection & DR_MEMPROT_EXEC)) return false;
    }

    // A successful query establishes the contract before any candidate is published as COM.
    InterlockedExchange(&call.definition->queryProbe, 0);
    ObserveInstructionInterface(reinterpret_cast<void*>(call.event.arguments[0]), __uuidof(IUnknown));
    return true;
}

bool ReadRttiTypeName(const module_data_t* module, uint64_t extent, uint32_t type, char* name, size_t capacity)
{
    // Resolve qualified interfaces and C++/WinRT ABI projections without loading symbols or calling target code.
    auto rva = uint64_t{type} + 2 * sizeof(void*);
    char decorated[MaximumApiNameBytes]{};
    if (rva + 5 >= extent || !ReadCaptureMemory(module->start + rva, decorated,
        static_cast<size_t>(std::min<uint64_t>(sizeof(decorated) - 1, extent - rva))) ||
        strncmp(decorated, ".?A", 3) || (decorated[3] != 'V' && decorated[3] != 'U')) return false;
    auto cursor = decorated + 4;
    bool projected = !strncmp(cursor, "type@?$abi@", 11) && (cursor[11] == 'V' || cursor[11] == 'U');

    // Match SDK-generated closed interfaces directly, avoiding template parsing or target-side reflection.
    auto& catalog = InstructionTransport.catalog;
    for (uint32_t entry = 0; projected && entry < catalog.Header()->interfaceCount; ++entry)
    {
        const auto& contract = catalog.Interfaces()[entry];
        auto spelling = contract.rttiName ? catalog.Text(contract.rttiName) : nullptr;
        if (!spelling || strcmp(spelling, decorated)) continue;
        auto label = catalog.Text(contract.name);
        if (!label || strlen(label) >= capacity) return false;
        memcpy(name, label, strlen(label) + 1);
        return true;
    }
    char* parts[32]{};
    size_t count = 0, used = 0;
    if (projected) cursor += 12;
    while (*cursor && count < std::size(parts))
    {
        auto first = cursor;
        while ((*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
            (*cursor >= '0' && *cursor <= '9') || *cursor == '_') ++cursor;
        if (cursor == first || *cursor != '@') return false;
        parts[count++] = first;
        *cursor++ = 0;
        if (*cursor != '@') continue;
        if (projected)
        {
            // Projection ABI specializations share the SDK contract, including the root COM interfaces.
            if ((strcmp(cursor + 1, "X@impl@winrt@@") && strcmp(cursor + 1, "@impl@winrt@@")) ||
                strcmp(parts[count - 1], "winrt")) return false;
            --count;
            if (count == 3 && !strcmp(parts[2], "Windows") && !strcmp(parts[1], "Foundation") &&
                (!strcmp(parts[0], "IUnknown") || !strcmp(parts[0], "IInspectable")))
                return dr_snprintf(name, capacity, "%s", parts[0]) > 0;
            if (capacity < 5) return false;
            memcpy(name, "ABI", 3);
            used = 3;
        }
        else if (cursor[1]) return false;
        while (count)
        {
            auto part = parts[--count];
            auto bytes = strlen(part);
            if (used + bytes + (used ? 2 : 0) >= capacity) return false;
            if (used) { name[used++] = ':'; name[used++] = ':'; }
            memcpy(name + used, part, bytes);
            used += bytes;
        }
        name[used] = 0;
        return true;
    }
    return false;
}

struct RttiLocator
{
    uint32_t signature, offset, constructorOffset, type, hierarchy, self;
};

struct RttiHierarchy
{
    uint32_t signature, attributes, count, bases;
};

struct RttiBase
{
    uint32_t type, contained;
    int32_t offset, virtualTable, virtualBase;
    uint32_t attributes, hierarchy;
};

enum class RttiInterface { None, Deferred, Resolved };

RttiInterface IdentifyImageInterface(const module_data_t* module, uint64_t extent, const RttiLocator& locator,
    uint64_t instance, GUID& iid, char* typeName, size_t capacity)
{
    RttiHierarchy hierarchy{};
    if (uint64_t{locator.hierarchy} + sizeof(hierarchy) > extent ||
        !ReadCaptureMemory(module->start + locator.hierarchy, &hierarchy, sizeof(hierarchy)) ||
        hierarchy.signature || !hierarchy.count || hierarchy.count > MaxRttiBases ||
        uint64_t{hierarchy.bases} + hierarchy.count * sizeof(uint32_t) > extent) return RttiInterface::None;
    uint64_t complete = instance;
    if (instance)
    {
        int32_t displacement = 0;
        if (locator.constructorOffset && (instance < locator.constructorOffset ||
            !ComValue(instance - locator.constructorOffset, displacement))) return RttiInterface::None;
        complete -= int64_t{locator.offset} + displacement;
        if (complete < MinimumUserAddress) return RttiInterface::None;
    }
    bool unknown = false, deferred = false;
    const CatalogInterface* selected = nullptr;
    auto& catalog = InstructionTransport.catalog;

    // Match the receiver's subobject using the same PMD and construction offsets as the MSVC runtime.
    for (uint32_t index = 0; index < hierarchy.count; ++index)
    {
        uint32_t rva = 0;
        RttiBase base{};
        char name[MaximumApiNameBytes]{};
        if (!ReadCaptureMemory(module->start + hierarchy.bases + index * sizeof(rva), &rva, sizeof(rva)) ||
            uint64_t{rva} + sizeof(base) > extent ||
            !ReadCaptureMemory(module->start + rva, &base, sizeof(base)) ||
            !ReadRttiTypeName(module, extent, base.type, name, std::size(name))) continue;
        bool match = false;
        if (instance)
        {
            int64_t offset = base.offset;
            if (base.virtualTable >= 0)
            {
                uint64_t table = 0;
                int32_t displacement = 0;
                if (!ComValue(complete + base.virtualTable, table) ||
                    !ComValue(table + int64_t{base.virtualBase}, displacement)) continue;
                offset += int64_t{base.virtualTable} + displacement;
            }
            match = complete + offset == instance;
        }
        else
        {
            match = base.virtualTable == -1 && base.offset >= 0 &&
                static_cast<uint32_t>(base.offset) == locator.offset && !locator.constructorOffset;
            deferred |= !strcmp(name, "IUnknown") && (base.virtualTable >= 0 || locator.constructorOffset);
        }
        if (!match) continue;
        unknown |= !strcmp(name, "IUnknown");
        for (uint32_t entry = 0; entry < catalog.Header()->interfaceCount; ++entry)
        {
            const auto& contract = catalog.Interfaces()[entry];
            auto label = catalog.Text(contract.name);
            if (label && !strcmp(label, name) && (!selected || contract.slotCount > selected->slotCount))
                selected = &contract;
        }
    }
    if (!unknown && !deferred) return RttiInterface::None;
    iid = selected ? selected->iid : __uuidof(IUnknown);
    if (!ReadRttiTypeName(module, extent, locator.type, typeName, capacity))
        dr_snprintf(typeName, capacity, "RTTI class +0x%x", locator.type);
    return unknown ? RttiInterface::Resolved : RttiInterface::Deferred;
}

bool ResolveImageInterface(void* table, uint64_t instance, void* location)
{
    auto module = dr_lookup_module(static_cast<app_pc>(location));
    if (!module) return false;
    RttiLocator locator{};
    GUID iid{};
    char name[MaximumApiNameBytes]{};
    auto extent = static_cast<uint64_t>(module->end - module->start);
    bool resolved = ComValue(reinterpret_cast<uint64_t>(location), locator) && locator.signature == 1 &&
        uint64_t{locator.self} + sizeof(locator) <= extent && module->start + locator.self == location &&
        IdentifyImageInterface(module, extent, locator, instance, iid, name, std::size(name)) ==
            RttiInterface::Resolved;
    dr_free_module_data(module);
    if (resolved) ObserveInstructionTable(static_cast<void**>(table), iid, true, name, MaxComVtableSlots);
    return resolved;
}

void DiscoverImageInterfaces(const module_data_t* module, uint64_t sections, uint16_t count)
{
    struct Candidate
    {
        Candidate* next;
        uintptr_t address;
        GUID iid;
        char name[MaximumApiNameBytes];
        bool deferred;
    };
    auto extent = static_cast<uint64_t>(module->end - module->start);
    IMAGE_SECTION_HEADER ranges[MaxPeSections]{};
    if (!count || count > std::size(ranges) || sections + count * sizeof(*ranges) > extent ||
        !ReadCaptureMemory(module->start + sections, ranges, count * sizeof(*ranges))) return;
    constexpr size_t chunk = 65536;
    auto buffer = static_cast<std::byte*>(dr_global_alloc(chunk + sizeof(RttiLocator)));
    Candidate* candidates[RttiCandidateBuckets]{};
    bool available = false;

    // Scan immutable image data in bounded chunks and defer virtual-base identification until a receiver is available.
    for (uint32_t pass = 0; pass < 2 && (!pass || available); ++pass)
    {
        for (uint32_t range = 0; range < count; ++range)
        {
            const auto& section = ranges[range];
            if (!(section.Characteristics & IMAGE_SCN_MEM_READ) ||
                (section.Characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) ||
                !(section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)) continue;
            auto size = uint64_t{section.Misc.VirtualSize};
            if (uint64_t{section.VirtualAddress} + size > extent) continue;
            for (uint64_t offset = 0; offset < size; offset += chunk)
            {
                auto bytes = static_cast<size_t>(std::min<uint64_t>(size - offset, chunk + sizeof(RttiLocator)));
                auto address = module->start + section.VirtualAddress + offset;
                if (!ReadCaptureMemory(address, buffer, bytes)) continue;
                for (size_t position = 0; position < chunk && position + (pass ? sizeof(uintptr_t) :
                    sizeof(RttiLocator)) <= bytes; position += pass ? sizeof(uintptr_t) : sizeof(uint32_t))
                {
                    if (!pass)
                    {
                        RttiLocator locator;
                        memcpy(&locator, buffer + position, sizeof(locator));
                        if (locator.signature != 1 ||
                            locator.self != section.VirtualAddress + offset + position) continue;
                        Candidate discovered{};
                        auto identity = IdentifyImageInterface(module, extent, locator, 0, discovered.iid,
                            discovered.name, std::size(discovered.name));
                        if (identity == RttiInterface::None) continue;
                        discovered.deferred = identity == RttiInterface::Deferred;
                        auto value = static_cast<Candidate*>(dr_global_alloc(sizeof(Candidate)));
                        *value = discovered;
                        value->address = reinterpret_cast<uintptr_t>(address + position);
                        auto bucket = (value->address >> 2) % std::size(candidates);
                        value->next = candidates[bucket];
                        candidates[bucket] = value;
                        available = true;
                    }
                    else
                    {
                        uintptr_t pointer = 0;
                        memcpy(&pointer, buffer + position, sizeof(pointer));
                        auto bucket = (pointer >> 2) % std::size(candidates);
                        for (auto candidate = candidates[bucket]; candidate; candidate = candidate->next)
                            if (candidate->address == pointer && size - offset - position >= 4 * sizeof(uintptr_t))
                                ObserveInstructionTable(reinterpret_cast<void**>(address + position +
                                    sizeof(uintptr_t)), candidate->iid, true, candidate->name,
                                    static_cast<uint32_t>((size - offset - position - sizeof(uintptr_t)) /
                                        sizeof(uintptr_t)), candidate->deferred ?
                                        reinterpret_cast<void*>(candidate->address) : nullptr);
                    }
                }
            }
        }
    }
    for (auto candidate : candidates)
    {
        while (candidate)
        {
            auto next = candidate->next;
            dr_global_free(candidate, sizeof(*candidate));
            candidate = next;
        }
    }
    dr_global_free(buffer, chunk + sizeof(RttiLocator));
}

void ObserveInstructionOutput(uint64_t output, const GUID& iid)
{
    void* instance = nullptr;
    if (ComValue(output, instance)) ObserveInstructionInterface(instance, iid);
}

void ObserveInstructionMultiQi(uint64_t count, uint64_t address)
{
    // Activation can return distinct interfaces and individual HRESULTs in one output array.
    count = std::min<uint64_t>(count, MaxMultiQiCount);
    if (!address || address > UINT64_MAX - count * sizeof(MULTI_QI)) return;
    for (uint64_t index = 0; index < count; ++index)
    {
        MULTI_QI requested{};
        GUID iid{};
        if (!ComValue(address + index * sizeof(MULTI_QI), requested)) break;
        if (SUCCEEDED(requested.hr) && requested.pItf &&
            ComValue(reinterpret_cast<uint64_t>(requested.pIID), iid))
            ObserveInstructionInterface(requested.pItf, iid);
    }
}

void DiscoverRuntimeInterfaces(InstructionFrame& call, bool leaving)
{
    auto definition = call.definition->runtime;
    if (!definition || !definition->interfaceParameters) return;
    for (uint32_t index = 0; index < definition->argumentCount; ++index)
    {
        auto& parameter = definition->parameters[index];
        auto address = call.event.arguments[index];
        if (!address) continue;
        auto iid = RuntimeInterfaceIdentity(parameter.interfaceIndex);
        GUID queried{};
        if (!iid && definition->signature.interfaceOutputIndex == index + 1 &&
            definition->signature.interfaceIdIndex && ComValue(
                call.event.arguments[definition->signature.interfaceIdIndex - 1], queried)) iid = &queried;
        auto variant = (parameter.flags & ExportAutomationVariant) != 0;
        if (variant && (call.definition->typed == Api::ComInvoke ||
            call.definition->typed == Api::ComEnumVariantNext)) continue;
        if (!iid && !variant) continue;
        if (!(parameter.flags & ExportInterfaceArray) && !variant)
        {
            bool output = (parameter.flags & 2) != 0;
            if (output != leaving) continue;
            if (output) ObserveInstructionOutput(address, *iid);
            else ObserveInstructionInterface(reinterpret_cast<void*>(address), *iid);
            continue;
        }

        // Keep the caller's capacity even when this API's event is filtered, then walk only completed pointers.
        uint64_t length = parameter.bytes;
        if (parameter.extentIndex >= 0)
        {
            length = call.event.arguments[parameter.extentIndex];
            if (parameter.indirectBytes)
            {
                uint64_t value = 0;
                if (!ReadCaptureMemory(reinterpret_cast<void*>(length), &value, parameter.indirectBytes)) continue;
                length = value;
            }
            if (length > UINT64_MAX / parameter.multiplier) continue;
            length *= parameter.multiplier;
        }
        if (!leaving)
            call.captureLimits[index] = parameter.flags & ExportReturnedBuffer ? UINT64_MAX : length;
        if (!(parameter.flags & (leaving ? 2u : 1u))) continue;
        if (leaving)
        {
            length = std::min(length, call.captureLimits[index]);
            if (parameter.actualIndex)
            {
                auto actual = parameter.actualIndex == ExportActualReturn ? call.event.result :
                    call.event.arguments[parameter.actualIndex - 1];
                if (parameter.actualIndirectBytes)
                {
                    uint64_t value = 0;
                    if (!RuntimeImplicitArrayCount(call, index, value) &&
                        !ReadCaptureMemory(reinterpret_cast<void*>(actual), &value,
                            parameter.actualIndirectBytes)) continue;
                    actual = value;
                }
                if (actual > UINT64_MAX / parameter.multiplier) continue;
                length = std::min(length, actual * parameter.multiplier);
            }
        }
        if (parameter.flags & ExportReturnedBuffer)
            if (!ComValue(address, address)) continue;
        if (!length || !address || address > UINT64_MAX - length) continue;

        // Automation contracts expose nested interfaces independently of the captured byte limit.
        if (variant)
        {
            ForEachAutomationElement(address, length / sizeof(VARIANT), [](void* instance, const GUID& identity)
            {
                ObserveInstructionInterface(instance, identity);
            }, parameter.kind == ExportValueKind::PropertyVariant);
            continue;
        }

        // Discovery uses bounded temporary storage independently of the captured buffer byte limit.
        void* instances[128];
        auto count = length / sizeof(void*);
        for (uint64_t offset = 0; offset < count;)
        {
            auto batch = std::min<uint64_t>(count - offset, std::size(instances));
            if (!ReadCaptureMemory(reinterpret_cast<void*>(address + offset * sizeof(void*)),
                instances, static_cast<size_t>(batch) * sizeof(void*))) break;
            for (uint64_t item = 0; item < batch; ++item)
                if (instances[item]) ObserveInstructionInterface(instances[item], *iid);
            offset += batch;
        }
    }
}

void DiscoverInstructionCom(InstructionFrame& call)
{
    DiscoverRuntimeInterfaces(call, true);

    // A typed pointer result can introduce a vtable without an IUnknown prefix.
    if (auto runtime = call.definition->runtime; runtime && runtime->resultInterfaceIndex && call.event.result)
        if (auto iid = RuntimeInterfaceIdentity(runtime->resultInterfaceIndex))
            ObserveInstructionInterface(reinterpret_cast<void*>(call.event.result), *iid);
    const auto& args = call.event.arguments;
    auto& signature = call.definition->signature;
    // Discover every typed output; an SDK factory can return more than one interface.
    auto outputs = PublicInterfaceOutputs(call.definition->typed);
    for (uint32_t index = 0; outputs; ++index, outputs >>= 1)
    {
        if (!(outputs & 1)) continue;
        if (signature.interfaceIdIndex && signature.interfaceOutputIndex == index + 1) continue;
        if (auto iid = PublicInterfaceOutput(call.definition->typed, index))
            ObserveInstructionOutput(args[index], *iid);
    }
    if (signature.interfaceIdIndex && signature.interfaceOutputIndex)
    {
        if (call.definition->runtime && call.definition->runtime->parameters[
            signature.interfaceOutputIndex - 1].flags & ExportInterfaceArray) return;
        GUID iid = call.queryIdentity;
        if (call.queryTimestamp || ComValue(args[signature.interfaceIdIndex - 1], iid))
            ObserveInstructionOutput(args[signature.interfaceOutputIndex - 1], iid);
        return;
    }
    switch (call.definition->typed)
    {
    case Api::CoCreateInstanceEx: case Api::CoCreateInstanceFromApp:
        ObserveInstructionMultiQi(args[4], args[5]); break;
    case Api::CoGetInstanceFromFile:
        ObserveInstructionMultiQi(args[6], args[7]); break;
    case Api::CoGetInstanceFromIStorage:
        ObserveInstructionMultiQi(args[5], args[6]); break;
    case Api::RoActivateInstance: case Api::ComActivateInstance:
        ObserveInstructionOutput(args[1], __uuidof(IInspectable)); break;
    case Api::ComGetTypeInfo:
        ObserveInstructionOutput(args[3], __uuidof(ITypeInfo)); break;
    case Api::ComEnumVariantClone:
        ObserveInstructionOutput(args[1], __uuidof(IEnumVARIANT)); break;
    case Api::ComEnumVariantNext:
    {
        auto count = AutomationFetched(args[1], args[3], call.event.result);
        ForEachAutomationElement(args[2], count, [](void* instance, const GUID& iid)
        {
            ObserveInstructionInterface(instance, iid);
        });
        break;
    }
    case Api::ComInvoke:
    {
        ForEachAutomationInterface(args[6], [](void* instance, const GUID& iid)
        {
            ObserveInstructionInterface(instance, iid);
        });
        break;
    }
    default: break;
    }
}

void DiscoverInstructionInputs(InstructionFrame& call)
{
    // Input interfaces can expose callbacks before the receiving API executes, even when its record is filtered.
    DiscoverRuntimeInterfaces(call, false);
    if (call.definition->typed == Api::ComInvoke)
        ForEachAutomationInput(call.event.arguments[5], [](void* instance, const GUID& iid)
        {
            ObserveInstructionInterface(instance, iid);
        });
    auto inputs = call.definition->interfaceInputs;
    for (uint32_t index = 0; inputs && index < call.definition->metadata.argumentCount; ++index, inputs >>= 1)
    {
        if (!(inputs & 1)) continue;
        auto identity = PublicInterfaceInput(call.definition->typed, index);
        if (identity) ObserveInstructionInterface(reinterpret_cast<void*>(call.event.arguments[index]), *identity);
    }
}

void CaptureComGuid(InstructionFrame& call, Slot* slot, uint32_t parameter, uint64_t address)
{
    GUID iid{};
    if (!ComValue(address, iid))
    {
        CopyValue(slot, call.transport->Header(), parameter, ValueKind::Bytes, address, sizeof(GUID));
        return;
    }
    wchar_t text[40]{};
    dr_snwprintf(text, std::size(text), L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
        iid.Data1, iid.Data2, iid.Data3, iid.Data4[0], iid.Data4[1], iid.Data4[2], iid.Data4[3],
        iid.Data4[4], iid.Data4[5], iid.Data4[6], iid.Data4[7]);
    CopyValue(slot, call.transport->Header(), parameter, ValueKind::Utf16,
        reinterpret_cast<uint64_t>(text), 38 * sizeof(wchar_t));
}

void CaptureComString(InstructionFrame& call, Slot* slot, uint32_t parameter, HSTRING value)
{
    HStringHeader string{};
    if (ComValue(reinterpret_cast<uint64_t>(value), string))
        CopyValue(slot, call.transport->Header(), parameter, ValueKind::Utf16,
            string.data, uint64_t{string.length} * sizeof(wchar_t));
}

void CaptureComVariant(InstructionFrame& call, Slot* slot, uint32_t parameter, uint64_t address)
{
    auto header = call.transport->Header();
    CopyValue(slot, header, parameter, ValueKind::Bytes, address, sizeof(VARIANT));
    VARIANT value{};
    if (!ComValue(address, value)) return;
    if (value.vt & VT_ARRAY || value.vt == (VT_VARIANT | VT_BYREF))
        CaptureAutomationArrays(slot, header, parameter, address);
    CaptureComVariantReference(slot, header, parameter, value);
}

void CaptureInstructionCom(InstructionFrame& call, Slot* slot, bool leaving)
{
    auto identity = call.queryTimestamp ? reinterpret_cast<uint64_t>(&call.queryIdentity) : call.event.arguments[1];
    CaptureComValues(call, slot, call.definition->typed, leaving, identity);
}
}

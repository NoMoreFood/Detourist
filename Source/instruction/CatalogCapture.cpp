#include "InstructionCapture.h"
#include <cstring>

namespace Detourist
{
RuntimeExport** PlanCache = nullptr;
RuntimeInterface** InterfaceCache = nullptr;

void InitializeCaptureCatalog()
{
    auto header = InstructionTransport.catalog.Header();
    PlanCache = static_cast<RuntimeExport**>(dr_global_alloc(header->planCount * sizeof(RuntimeExport*)));
    InterfaceCache =
        static_cast<RuntimeInterface**>(dr_global_alloc(header->interfaceCount * sizeof(RuntimeInterface*)));
    memset(PlanCache, 0, header->planCount * sizeof(RuntimeExport*));
    memset(InterfaceCache, 0, header->interfaceCount * sizeof(RuntimeInterface*));
}

const RuntimeExport* CapturePlan(uint32_t index)
{
    auto& catalog = InstructionTransport.catalog;
    if (index >= catalog.Header()->planCount) return nullptr;
    auto entry = reinterpret_cast<void* volatile*>(PlanCache + index);
    if (auto cached = InterlockedCompareExchangePointer(entry, nullptr, nullptr))
        return static_cast<RuntimeExport*>(cached);
    const auto& source = catalog.Plans()[index];
    if (sizeof(void*) == 4 && !source.signature.supported) return nullptr;
    auto parameters = catalog.Parameters(source);
    auto members = catalog.Members(source);
    auto successes = catalog.SuccessValues(source);
    auto name = catalog.Text(source.name), module = catalog.Text(source.module);
    auto description = catalog.WideText(source.description);
    if (!parameters || !members || !successes || !name || !module || !description) return nullptr;

    // Resolve a plan only when an executable export or interface slot needs it; calls retain its stable pointer.
    auto value = static_cast<RuntimeExport*>(dr_global_alloc(sizeof(RuntimeExport)));
    memset(value, 0, sizeof(*value));
    value->name = name;
    value->module = module;
    value->description = description;
    value->argumentCount = source.argumentCount;
    value->signature = source.signature;
    memcpy(value->parameters, parameters, source.argumentCount * sizeof(ExportParameter));
    value->resultRule = source.resultRule;
    value->resultSuccessCount = source.resultSuccessCount;
    value->resultSuccesses = successes;
    value->interfaceParameters = source.interfaceParameters;
    value->countedResultBytes = source.countedResultBytes;
    value->resultInterfaceIndex = source.resultInterfaceIndex;
    value->members = members;
    value->memberCount = source.memberCount;
    value->rawTailStart = source.rawTailStart;
    value->resultCaptureKind = source.resultCaptureKind;
    if (auto existing = InterlockedCompareExchangePointer(entry, value, nullptr))
    {
        dr_global_free(value, sizeof(*value));
        return static_cast<RuntimeExport*>(existing);
    }
    return value;
}

const RuntimeExport* RuntimeDefinitionFor(const char* module, const char* name)
{
    auto& catalog = InstructionTransport.catalog;
    bool crt = !_stricmp(module, "ucrtbase.dll") || !_stricmp(module, "msvcrt.dll") ||
        !_strnicmp(module, "msvcr", 5) || !_strnicmp(module, "vcruntime", 9) || !_stricmp(module, "ntdll.dll");
    if (crt && !strncmp(name, "_o_", 3)) name += 3;
    uint32_t first = 0, last = catalog.Header()->exportCount;
    while (first < last)
    {
        auto middle = first + (last - first) / 2;
        auto compare = strcmp(catalog.Text(catalog.Plans()[middle].name), name);
        if (compare < 0) first = middle + 1;
        else last = middle;
    }
    auto canonical = catalog.CanonicalModule(module);
    uint32_t alias = catalog.Header()->exportCount, family = alias, fallback = alias;
    for (; first < catalog.Header()->exportCount; ++first)
    {
        const auto& plan = catalog.Plans()[first];
        if (strcmp(catalog.Text(plan.name), name)) break;
        auto origin = catalog.Text(plan.module);
        bool generic = !strcmp(origin, "$image") || (!strcmp(origin, "$crt") && crt);
        if (generic) fallback = first;
        bool matches = !_stricmp(module, origin) || (!_stricmp(module, "kernelbase.dll") &&
                (!_stricmp(origin, "kernel32.dll") || !_stricmp(origin, "advapi32.dll"))) ||
            (!_stricmp(module, "sechost.dll") && !_stricmp(origin, "advapi32.dll")) ||
            (!_stricmp(module, "combase.dll") && !_stricmp(origin, "ole32.dll")) ||
            (!_stricmp(module, "gdi32full.dll") && !_stricmp(origin, "gdi32.dll")) ||
            (name[0] == '?' &&
                ((!_stricmp(module, "msvcr120_clr0400.dll") && !_stricmp(origin, "msvcr120.dll")) ||
                 (!_stricmp(module, "msvcp120_clr0400.dll") && !_stricmp(origin, "msvcp120.dll"))));
        if (matches) return CapturePlan(first);
        if (!_stricmp(origin, canonical)) alias = first;
        if (CatalogModuleMatches(origin, module)) family = first;
    }
    if (alias < catalog.Header()->exportCount) return CapturePlan(alias);
    if (family < catalog.Header()->exportCount) return CapturePlan(family);
    return fallback < catalog.Header()->exportCount ? CapturePlan(fallback) : nullptr;
}

const RuntimeInterface* RuntimeInterfaceFor(const GUID& iid)
{
    auto& catalog = InstructionTransport.catalog;
    uint32_t first = 0, last = catalog.Header()->interfaceCount;
    while (first < last)
    {
        auto middle = first + (last - first) / 2;
        const auto& source = catalog.Interfaces()[middle];
        auto compare = memcmp(&iid, &source.iid, sizeof(iid));
        if (compare > 0) first = middle + 1;
        else if (compare < 0) last = middle;
        else
        {
            auto entry = reinterpret_cast<void* volatile*>(InterfaceCache + middle);
            if (auto cached = InterlockedCompareExchangePointer(entry, nullptr, nullptr))
                return static_cast<RuntimeInterface*>(cached);
            auto name = catalog.Text(source.name);
            if (!name || uint64_t{source.firstSlot} + source.slotCount > catalog.Header()->slotCount) return nullptr;
            auto value = static_cast<RuntimeInterface*>(dr_global_alloc(sizeof(RuntimeInterface)));
            bool comPrefix = source.slotCount >= UnknownSlotCount;
            constexpr const char* methods[]{"QueryInterface", "AddRef", "Release"};
            for (uint32_t slot = 0; comPrefix && slot < UnknownSlotCount; ++slot)
            {
                auto plan = catalog.Slots()[source.firstSlot + slot];
                auto method = plan < catalog.Header()->planCount ? catalog.Text(catalog.Plans()[plan].name) : nullptr;
                comPrefix = method && !strcmp(method, methods[slot]);
            }
            *value = {source.iid, name, source.firstSlot, source.slotCount, comPrefix};
            if (auto existing = InterlockedCompareExchangePointer(entry, value, nullptr))
            {
                dr_global_free(value, sizeof(*value));
                return static_cast<RuntimeInterface*>(existing);
            }
            return value;
        }
    }
    return nullptr;
}

const RuntimeExport* RuntimeInterfaceMethod(const RuntimeInterface& contract, uint32_t slot)
{
    return slot < contract.slotCount ? CapturePlan(InstructionTransport.catalog.Slots()[contract.firstSlot + slot]) :
        nullptr;
}

const GUID* RuntimeInterfaceIdentity(uint16_t index)
{
    auto& catalog = InstructionTransport.catalog;
    return index && index <= catalog.Header()->interfaceCount ? &catalog.Interfaces()[index - 1].iid : nullptr;
}

void FreeCaptureCatalog()
{
    auto header = InstructionTransport.catalog.Header();
    for (uint32_t index = 0; index < header->planCount; ++index)
        if (PlanCache[index]) dr_global_free(PlanCache[index], sizeof(RuntimeExport));
    for (uint32_t index = 0; index < header->interfaceCount; ++index)
        if (InterfaceCache[index]) dr_global_free(InterfaceCache[index], sizeof(RuntimeInterface));
    dr_global_free(PlanCache, header->planCount * sizeof(RuntimeExport*));
    dr_global_free(InterfaceCache, header->interfaceCount * sizeof(RuntimeInterface*));
    PlanCache = nullptr;
    InterfaceCache = nullptr;
}
}

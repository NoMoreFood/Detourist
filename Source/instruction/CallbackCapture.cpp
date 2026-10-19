#pragma warning(push, 0)
#include <phnt_windows.h>
#include <phnt.h>
#pragma warning(pop)
#include "InstructionCapture.h"
#include <atomic>
#include <cstring>

namespace Detourist
{
constexpr uint32_t MapiUnicodeFlag = 0x80000000;
constexpr size_t CallbackPathCapacity = 384;
constexpr size_t CallbackExportCapacity = 128;

struct RegisteredCallback
{
    RegisteredCallback* next;
    RuntimeExport plan;
    char module[CallbackPathCapacity], name[CallbackExportCapacity];
};
std::atomic<RegisteredCallback*> RegisteredCallbacks{};

const RuntimeExport* RegisteredCallbackFor(const char* module, const char* name)
{
    // Registrations are immutable and remain available across provider unloads.
    auto current = RegisteredCallbacks.load(std::memory_order_acquire);
    for (; current; current = current->next)
        if (!_stricmp(current->module, module) && !strcmp(current->name, name)) return &current->plan;
    return nullptr;
}

template<class Character, size_t Count>
bool ReadCallbackName(uint64_t address, Character (&output)[Count])
{
    if (!address) return false;
    for (size_t index = 0; index < Count; ++index)
    {
        if (!ReadCaptureMemory(reinterpret_cast<void*>(address + index * sizeof(Character)),
            output + index, sizeof(Character))) return false;
        if (!output[index]) return index != 0;
    }
    return false;
}

void DiscoverRegisteredCallbacks(InstructionFrame& call)
{
    if (!call.definition->callbackRegistration || call.event.flags & (Failed | Skipped | Unwound)) return;
    char module[CallbackPathCapacity]{}, exports[2][CallbackExportCapacity]{};
    if (call.event.arguments[6] & MapiUnicodeFlag)
    {
        wchar_t path[CallbackPathCapacity]{};
        if (!ReadCallbackName(call.event.arguments[3], path)) return;
        auto leaf = path;
        for (auto current = path; *current; ++current)
            if (*current == L'\\' || *current == L'/') leaf = current + 1;
        auto bytes = dr_snprintf(module, std::size(module), "%ls", leaf);
        if (bytes < 0 || bytes >= static_cast<int>(std::size(module))) return;
    }
    else
    {
        char path[CallbackPathCapacity]{};
        if (!ReadCallbackName(call.event.arguments[3], path)) return;
        auto leaf = path;
        for (auto current = path; *current; ++current)
            if (*current == '\\' || *current == '/') leaf = current + 1;
        wchar_t wide[CallbackPathCapacity]{};
        ULONG converted = 0;
        if (!NT_SUCCESS(RtlMultiByteToUnicodeN(wide, sizeof(wide) - sizeof(wchar_t), &converted,
            leaf, static_cast<ULONG>(strlen(leaf))))) return;
        auto bytes = dr_snprintf(module, std::size(module), "%ls", wide);
        if (bytes < 0 || bytes >= static_cast<int>(std::size(module))) return;
    }
    auto length = strlen(module);
    if (!length) return;
    if (!strchr(module, '.'))
    {
        if (length + 4 >= std::size(module)) return;
        memcpy(module + length, ".dll", 5);
    }

    // Use the provider's selected names with the authoritative callback contracts.
    constexpr const char* contracts[]{"PreprocessMessage", "RemovePreprocessInfo"};
    bool added = false;
    for (uint32_t index = 0; index < std::size(contracts); ++index)
    {
        if (!ReadCallbackName(call.event.arguments[4 + index], exports[index])) continue;
        auto source = RuntimeDefinitionFor("$mapi-callback", contracts[index]);
        if (!source) continue;
        auto value = static_cast<RegisteredCallback*>(dr_global_alloc(sizeof(RegisteredCallback)));
        memset(value, 0, sizeof(*value));
        memcpy(value->module, module, strlen(module) + 1);
        memcpy(value->name, exports[index], strlen(exports[index]) + 1);
        value->plan = *source;
        value->plan.name = value->name;
        value->plan.module = value->module;
        value->plan.categorySource = source;
        dr_mutex_lock(DefinitionLock);
        auto previous = RegisteredCallbackFor(module, exports[index]);
        if (previous && (!previous->argumentCount || previous->argumentCount == source->argumentCount))
        {
            dr_mutex_unlock(DefinitionLock);
            dr_global_free(value, sizeof(*value));
            continue;
        }
        if (previous) value->plan.argumentCount = 0;
        value->next = RegisteredCallbacks.load(std::memory_order_relaxed);
        RegisteredCallbacks.store(value, std::memory_order_release);
        dr_mutex_unlock(DefinitionLock);
        added = true;
    }
    if (!added) return;

    // Upgrade an already loaded provider before the application can invoke its callbacks.
    auto iterator = dr_module_iterator_start();
    while (dr_module_iterator_hasnext(iterator))
    {
        auto image = dr_module_iterator_next(iterator);
        auto path = image->full_path;
        auto leaf = path;
        if (path)
            for (auto current = path; *current; ++current)
                if (*current == '\\' || *current == '/') leaf = current + 1;
        if (leaf && !_stricmp(module, leaf)) DiscoverExports(image);
        dr_free_module_data(image);
    }
    dr_module_iterator_stop(iterator);
}

void FreeRegisteredCallbacks()
{
    auto current = RegisteredCallbacks.exchange(nullptr);
    while (current)
    {
        auto next = current->next;
        dr_global_free(current, sizeof(*current));
        current = next;
    }
}
}

#include "CatalogView.h"
#include <cstring>

namespace Detourist
{
ApiDefinition ApiDefinitions[static_cast<uint32_t>(Api::Count)]{};

bool PublicFailure(Api api, uint64_t result)
{
    enum class Failure { None, Zero, InvalidHandle, Status, Negative, InvalidDword, MinusOne };
    static constexpr Failure core[] =
    {
#define CORE_API(name, failure) Failure::failure,
#include "CoreCatalog.inc"
#undef CORE_API
    };
    if (IsWin32Api(api))
    {
        const auto& definition = ApiDefinitions[static_cast<uint32_t>(api)];
        auto plan = definition.plan;
        return plan && ExportResultFailed(plan->resultRule, plan->signature.resultBytes, result,
            definition.resultSuccesses, plan->resultSuccessCount);
    }
    if (IsComApi(api))
        return api != Api::ComAddRef && api != Api::ComRelease && static_cast<int32_t>(result) < 0;
    auto index = static_cast<uint32_t>(api);
    if (index >= std::size(core)) return false;
    switch (core[index])
    {
    case Failure::Zero: return result == 0;
    case Failure::InvalidHandle: return static_cast<uintptr_t>(result) == UINTPTR_MAX;
    case Failure::Status: return static_cast<uint32_t>(result) != ERROR_SUCCESS;
    case Failure::Negative: return static_cast<int32_t>(result) < 0;
    case Failure::InvalidDword: case Failure::MinusOne: return static_cast<uint32_t>(result) == UINT32_MAX;
    default: return false;
    }
}

bool CatalogModuleMatches(const char* pattern, const char* module)
{
    // A module family keeps its literal prefix and suffix around one version wildcard.
    auto wildcard = strchr(pattern, '*');
    if (!wildcard) return !_stricmp(pattern, module);
    auto prefix = static_cast<size_t>(wildcard - pattern), suffix = strlen(wildcard + 1);
    auto bytes = strlen(module);
    return bytes >= prefix + suffix && !_strnicmp(pattern, module, prefix) &&
        !_stricmp(wildcard + 1, module + bytes - suffix);
}

bool CatalogView::Open(const void* data, size_t bytes, uint32_t pointerSize)
{
    if (!data || bytes < sizeof(CatalogHeader)) return false;
    auto header = static_cast<const CatalogHeader*>(data);
    if (header->magic != CatalogMagic || header->version != CatalogVersion || header->bytes > bytes ||
        header->pointerSize != pointerSize ||
        header->bytes > CatalogBudget || header->bytes < sizeof(*header) ||
        header->builtinCount != static_cast<uint32_t>(Api::Count) || header->exportCount > header->planCount ||
        header->interfaceCount > UINT16_MAX || header->moduleAliasCount > MaxModuleAliasCount ||
        header->categoryCount != static_cast<uint32_t>(ApiCategory::Count))
        return false;
    auto valid = [header](uint32_t offset, uint64_t count, size_t width)
    {
        return offset >= sizeof(*header) && offset % CatalogTableAlignment == 0 &&
            uint64_t{offset} + count * width <= header->bytes;
    };
    if (!valid(header->builtinOffset, header->builtinCount, sizeof(CatalogApi)) ||
        !valid(header->planOffset, header->planCount, sizeof(CatalogPlan)) ||
        !valid(header->interfaceOffset, header->interfaceCount, sizeof(CatalogInterface)) ||
        !valid(header->slotOffset, header->slotCount, sizeof(uint32_t)) ||
        !valid(header->ordinalOffset, header->ordinalCount, sizeof(CatalogOrdinal)) ||
        !valid(header->moduleAliasOffset, header->moduleAliasCount, sizeof(CatalogModuleAlias)) ||
        !valid(header->categoryOffset, header->categoryCount, sizeof(CatalogCategory)) ||
        !valid(header->categoryRuleOffset, header->categoryRuleCount, sizeof(CatalogCategoryRule))) return false;
    data_ = static_cast<const std::byte*>(data);
    header_ = header;
    for (uint32_t index = 0; index < header_->moduleAliasCount; ++index)
        if (!Text(ModuleAliases()[index].alias) || !Text(ModuleAliases()[index].module))
        {
            data_ = nullptr;
            header_ = nullptr;
            return false;
        }
    return true;
}

const CatalogApi* CatalogView::Builtins() const
{
    return reinterpret_cast<const CatalogApi*>(data_ + header_->builtinOffset);
}
const CatalogPlan* CatalogView::BuiltinPlan(Api api) const
{
    auto index = static_cast<uint32_t>(api);
    if (index >= header_->builtinCount) return nullptr;
    auto plan = Builtins()[index].planIndex;
    return plan < header_->exportCount ? Plans() + plan : nullptr;
}
const CatalogPlan* CatalogView::Plans() const
{
    return reinterpret_cast<const CatalogPlan*>(data_ + header_->planOffset);
}
const CatalogInterface* CatalogView::Interfaces() const
{
    return reinterpret_cast<const CatalogInterface*>(data_ + header_->interfaceOffset);
}

const CatalogOrdinal* CatalogView::Ordinals() const
{
    return reinterpret_cast<const CatalogOrdinal*>(data_ + header_->ordinalOffset);
}

const CatalogModuleAlias* CatalogView::ModuleAliases() const
{
    return reinterpret_cast<const CatalogModuleAlias*>(data_ + header_->moduleAliasOffset);
}

const char* CatalogView::CanonicalModule(const char* module) const
{
    for (uint32_t index = 0; index < header_->moduleAliasCount; ++index)
    {
        const auto& alias = ModuleAliases()[index];
        if (!_stricmp(Text(alias.alias), module)) return Text(alias.module);
    }
    return module;
}

const CatalogCategory* CatalogView::Categories() const
{
    return reinterpret_cast<const CatalogCategory*>(data_ + header_->categoryOffset);
}

const CatalogCategoryRule* CatalogView::CategoryRules() const
{
    return reinterpret_cast<const CatalogCategoryRule*>(data_ + header_->categoryRuleOffset);
}

const char* CatalogView::OrdinalName(const char* module, uint32_t ordinal) const
{
    // Ordinal aliases are resolved once per module export, outside call interception.
    uint32_t first = 0, last = header_->ordinalCount;
    while (first < last)
    {
        auto middle = first + (last - first) / 2;
        const auto& entry = Ordinals()[middle];
        auto knownModule = Text(entry.module);
        if (!knownModule) return nullptr;
        auto compare = _stricmp(knownModule, module);
        if (!compare) compare = entry.ordinal < ordinal ? -1 : entry.ordinal > ordinal ? 1 : 0;
        if (compare < 0) first = middle + 1;
        else last = middle;
    }
    if (first >= header_->ordinalCount) return nullptr;
    const auto& entry = Ordinals()[first];
    auto knownModule = Text(entry.module);
    return knownModule && !_stricmp(knownModule, module) && entry.ordinal == ordinal ? Text(entry.name) : nullptr;
}

uint32_t CatalogView::NameOrdinal(const char* module, const char* name) const
{
    // Search ordinal aliases when resolving plans without an exported symbol name.
    for (uint32_t index = 0; index < header_->ordinalCount; ++index)
    {
        const auto& entry = Ordinals()[index];
        auto knownModule = Text(entry.module);
        auto knownName = Text(entry.name);
        if (knownModule && knownName && !_stricmp(knownModule, module) && !strcmp(knownName, name))
            return entry.ordinal;
    }
    return 0;
}

const uint32_t* CatalogView::Slots() const
{
    return reinterpret_cast<const uint32_t*>(data_ + header_->slotOffset);
}
const char* CatalogView::Text(uint32_t offset) const
{
    if (offset >= header_->bytes || !memchr(data_ + offset, 0, header_->bytes - offset)) return nullptr;
    return reinterpret_cast<const char*>(data_ + offset);
}
const wchar_t* CatalogView::WideText(uint32_t offset) const
{
    if (offset >= header_->bytes || offset % sizeof(wchar_t)) return nullptr;
    auto text = reinterpret_cast<const wchar_t*>(data_ + offset);
    for (auto index = offset; index + sizeof(wchar_t) <= header_->bytes; index += sizeof(wchar_t))
        if (!text[(index - offset) / sizeof(wchar_t)]) return text;
    return nullptr;
}
const ExportParameter* CatalogView::Parameters(const CatalogPlan& plan) const
{
    if (plan.argumentCount > MaximumArguments || plan.parameters % alignof(ExportParameter) ||
        uint64_t{plan.parameters} + plan.argumentCount * sizeof(ExportParameter) > header_->bytes) return nullptr;
    return reinterpret_cast<const ExportParameter*>(data_ + plan.parameters);
}

const ExportMember* CatalogView::Members(const CatalogPlan& plan) const
{
    if (plan.argumentCount > MaximumArguments || plan.memberCount > MaximumArguments - plan.argumentCount ||
        plan.members % alignof(ExportMember) ||
        uint64_t{plan.members} + plan.memberCount * sizeof(ExportMember) > header_->bytes) return nullptr;
    return reinterpret_cast<const ExportMember*>(data_ + plan.members);
}

const uint32_t* CatalogView::SuccessValues(const CatalogPlan& plan) const
{
    if (plan.resultSuccessCount > MaxResultSuccessCount || plan.resultSuccesses % alignof(uint32_t) ||
        uint64_t{plan.resultSuccesses} + plan.resultSuccessCount * sizeof(uint32_t) > header_->bytes) return nullptr;
    return reinterpret_cast<const uint32_t*>(data_ + plan.resultSuccesses);
}

bool BindApiDefinitions(const CatalogView& catalog)
{
    // Recording requires a complete calling contract for every built-in hook.
    for (uint32_t index = 0; index < catalog.Header()->builtinCount; ++index)
    {
        const auto& source = catalog.Builtins()[index];
        auto plan = catalog.BuiltinPlan(static_cast<Api>(index));
        if ((IsWin32Api(static_cast<Api>(index)) || IsNativeApi(static_cast<Api>(index)) ||
            IsWin32uApi(static_cast<Api>(index))) && (!plan || sizeof(void*) == 8 && !plan->signature.supported ||
            plan->argumentCount != source.argumentCount &&
                (!plan->rawTailStart || plan->argumentCount > source.argumentCount) ||
            !catalog.Parameters(*plan) || !catalog.Members(*plan)))
            return false;
    }
    return BindApiMetadata(catalog);
}

bool BindApiMetadata(const CatalogView& catalog)
{
    // Validate all display fields before publishing pointers into the new snapshot.
    for (uint32_t index = 0; index < catalog.Header()->builtinCount; ++index)
    {
        const auto& source = catalog.Builtins()[index];
        if (source.id != index || source.argumentCount > MaximumArguments || !catalog.Text(source.module) ||
            !catalog.Text(source.name) || !catalog.WideText(source.description) || !catalog.Text(source.nativeName))
            return false;
    }
    if (!BindApiCategories(catalog)) return false;
    for (uint32_t index = 0; index < catalog.Header()->builtinCount; ++index)
    {
        const auto& source = catalog.Builtins()[index];
        auto plan = catalog.BuiltinPlan(static_cast<Api>(index));
        ApiDefinitions[index] = {static_cast<Api>(index), catalog.Text(source.module), catalog.Text(source.name),
            catalog.WideText(source.description), source.argumentCount, source.hookFlags,
            catalog.Text(source.nativeName), plan, plan ? catalog.SuccessValues(*plan) : nullptr};
    }
    return true;
}
}

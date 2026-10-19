#include "SqliteCatalog.h"
#include "ApiCatalog.h"
#include "TraceStore.h"
#include "WinSupport.h"
#include <sqlite3.h>
#include <algorithm>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Detourist
{
struct CatalogCache
{
    Handle mapping;
    std::unique_ptr<void, decltype(&UnmapViewOfFile)> view{nullptr, UnmapViewOfFile};
    std::wstring name, path;
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> watcher{nullptr, sqlite3_close};
    int version = 0;
};
CatalogCache CaptureCatalogs[2];
std::mutex CatalogGate;

std::wstring ArchitectureDirectory(uint32_t pointerSize)
{
    auto directory = ModuleDirectory();
    if (pointerSize == sizeof(void*)) return directory;
    auto hasComponents = [](const std::filesystem::path& candidate)
    {
        return GetFileAttributesW((candidate / L"DetouristAgent.dll").c_str()) != INVALID_FILE_ATTRIBUTES;
    };
    std::filesystem::path current(directory);
    if (pointerSize == 4)
    {
        if (auto nested = current / L"x86"; hasComponents(nested)) return nested.wstring();
    }
    else if (_wcsicmp(current.filename().c_str(), L"x86") == 0)
    {
        if (auto parent = current.parent_path(); hasComponents(parent)) return parent.wstring();
    }
    for (auto ancestor = current.parent_path(); !ancestor.empty() && ancestor != ancestor.parent_path();
        ancestor = ancestor.parent_path())
    {
        if (_wcsicmp(ancestor.filename().c_str(), pointerSize == 4 ? L"x64" : L"x86") != 0) continue;
        auto sibling = ancestor.parent_path() / (pointerSize == 4 ? L"x86" : L"x64");
        for (const auto& config : {current.filename(), current.parent_path().filename()})
            if (auto candidate = sibling / L"bin" / config; hasComponents(candidate))
                return candidate.wstring();
    }
    return (pointerSize == 4 ? current / L"x86" : current.parent_path()).wstring();
}

// Shared strings and parameter arrays can be looked up without allocating temporary keys.
struct CatalogTextHash
{
    using is_transparent = void;
    size_t operator()(std::string_view value) const noexcept { return std::hash<std::string_view>{}(value); }
};

int ApiCatalogDataVersion(sqlite3* database)
{
    Statement version(database, "PRAGMA data_version");
    if (!version.Next()) throw std::runtime_error("Cannot inspect API catalog changes.");
    return sqlite3_column_int(version.value, 0);
}

bool InvalidCaptureRule(const ExportParameter& value, uint32_t pointerSize, uint32_t interfaceCount)
{
    using Kind = ExportValueKind;
    if (value.extentIndex < -2 || value.extentIndex >= static_cast<int>(MaximumArguments) ||
        value.actualIndex > MaximumArguments && value.actualIndex != ExportActualReturn ||
        value.actualIndex == ExportActualReturn && value.actualIndirectBytes || value.kind > Kind::PrinterPayload ||
        !value.multiplier && value.flags || value.interfaceIndex > interfaceCount) return true;

    // A returned buffer must be an output of a kind that supports the extra pointer indirection.
    if ((value.flags & ExportReturnedBuffer) && (!(value.flags & ExportOutput) ||
        value.kind != Kind::IndirectBytes && value.kind != Kind::SamRidEnumeration &&
        value.kind != Kind::SamSidEnumeration && value.kind != Kind::Utf16StringArray &&
        value.kind != Kind::Utf16MultiString && value.kind != Kind::Utf16StringPairs &&
        (value.kind != Kind::PropertyVariant || !(value.flags & ExportAutomationVariant)) &&
        value.kind != Kind::BstrArray && value.kind != Kind::MapiAddressList && value.kind != Kind::MapiPropertyArray &&
        value.kind != Kind::X509Certificate && value.kind != Kind::ReplicaInformation &&
        value.kind != Kind::Utf16 && value.kind != Kind::Ansi && (value.kind < Kind::BerValue ||
            value.kind > Kind::NetApiRecords && value.kind != Kind::BerValues))) return true;

    const bool fixed = value.extentIndex == -1 && !value.indirectBytes && value.multiplier == 1;
    const bool extra = value.actualIndex || value.actualIndirectBytes || value.interfaceIndex || value.prefixBytes;
    switch (value.kind)
    {
    case Kind::SoundAnsi:
    case Kind::SoundUtf16:
        return value.bytes || value.extentIndex < 0 || value.indirectBytes || value.multiplier != 1 ||
            value.flags != ExportInput || extra;
    case Kind::X509Certificate:
        return value.bytes != (pointerSize == 8 ? 64u : 52u) || !fixed ||
            value.flags != ExportInput && value.flags != (ExportOutput | ExportReturnedBuffer) || extra;
    case Kind::ReturnedSpan:
        return value.bytes || !fixed || value.flags != ExportOutput || extra;
    case Kind::RequiredSize:
        return value.bytes != 4 || !fixed || value.flags != ExportOutput || extra;
    case Kind::RequiredSizeLastError:
        return value.bytes != pointerSize || !fixed || value.flags != ExportOutput || extra;
    case Kind::Utf16MultiString:
        return value.bytes != UINT32_MAX || !fixed ||
            value.flags != (ExportInput | ExportTerminated) &&
            value.flags != (ExportOutput | ExportTerminated | ExportReturnedBuffer) || extra;
    case Kind::Utf16StringArray:
        return value.bytes || value.extentIndex < 0 || value.multiplier < pointerSize || (value.flags != ExportInput ||
            value.indirectBytes) && (value.flags != ExportOutput ||
            value.indirectBytes != 0 && value.indirectBytes != 4) &&
            (value.flags != (ExportOutput | ExportReturnedBuffer) || value.indirectBytes != 4) ||
            value.actualIndex && (value.flags != ExportOutput || value.actualIndirectBytes != 4) ||
            !value.actualIndex && value.actualIndirectBytes || value.interfaceIndex || value.prefixBytes;
    case Kind::Utf16StringPairs:
        return (value.flags & ExportReturnedBuffer) && (value.bytes || value.extentIndex < 0 ||
            value.indirectBytes != 4 || value.multiplier != pointerSize * 2 ||
            value.flags != (ExportOutput | ExportReturnedBuffer) || extra);
    case Kind::AuthzOperations:
        return value.bytes != 4 || !fixed || value.flags != ExportInput || !value.actualIndex ||
            value.actualIndirectBytes != 4 || value.interfaceIndex || value.prefixBytes;
    case Kind::PrintDocumentEvent:
        return value.bytes || value.extentIndex < 0 || value.indirectBytes || value.multiplier != 1 ||
            value.flags != ExportInput && value.flags != (ExportInput | ExportOutput) || !value.actualIndex ||
            value.actualIndirectBytes || value.interfaceIndex || !value.prefixBytes ||
            value.prefixBytes > MaximumArguments;
    case Kind::FailureEapError:
        return value.bytes != (pointerSize == 8 ? 88u : 80u) || !fixed || value.flags != 2 || extra;
    case Kind::RtmBuffer:
        return value.indirectBytes || value.multiplier != 1 || value.actualIndirectBytes || value.interfaceIndex ||
            value.prefixBytes || value.bytes > 12;
    case Kind::PrinterPayload:
        return value.bytes > 2 || value.indirectBytes || value.multiplier != 1 || extra ||
            value.bytes == 0 && (value.extentIndex != 2 || value.flags != 1) ||
            value.bytes == 1 && (value.extentIndex != 3 || value.flags != 3) ||
            value.bytes == 2 && (value.extentIndex != -1 || value.flags != 1);
    case Kind::SamRidEnumeration:
    case Kind::SamSidEnumeration:
        return value.bytes || value.extentIndex < 0 || value.indirectBytes != 4 ||
            value.multiplier != (pointerSize == 8 ? 24 : 12) || value.flags != (2 | ExportReturnedBuffer) || extra;
    default: return false;
    }
}

void PrepareApiCatalog(bool refresh, uint32_t pointerSize)
{
    if (pointerSize != 4 && pointerSize != 8)
        throw std::runtime_error("Invalid target pointer width.");
    std::lock_guard lock(CatalogGate);
    auto& catalog = CaptureCatalogs[pointerSize == 4 ? 0 : 1];
    if (catalog.mapping && !refresh) return;
    wchar_t overridePath[32768];
    auto characters = pointerSize == 4 ?
        GetEnvironmentVariableW(L"DETOURIST_API_CATALOG_X86", overridePath, std::size(overridePath)) : 0;
    if (!characters)
        characters = GetEnvironmentVariableW(L"DETOURIST_API_CATALOG", overridePath, std::size(overridePath));
    auto directory = std::filesystem::path(ModuleDirectory());
    auto defaultPath = directory / L"ApiCatalog.sqlite";
    if (GetFileAttributesW(defaultPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        defaultPath = directory.parent_path() / L"ApiCatalog.sqlite";
    auto path = characters && characters < std::size(overridePath) ?
        std::wstring(overridePath) : defaultPath.wstring();
    if (catalog.mapping && catalog.path == path &&
        ApiCatalogDataVersion(catalog.watcher.get()) == catalog.version) return;
    // Compile a replacement privately; active observers retain their immutable capture image.
    CatalogCache snapshot;
    snapshot.path = path;
    auto openCatalog = [&]()
    {
        sqlite3* database = nullptr;
        auto status = sqlite3_open_v2(Utf8(path).c_str(), &database, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
            nullptr);
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> owner(database, sqlite3_close);
        if (status != SQLITE_OK) throw std::runtime_error("API catalog is unavailable: " +
            std::string(database ? sqlite3_errmsg(database) : "Cannot open SQLite catalog."));
        constexpr int CatalogBusyTimeoutMs = 1000;
        sqlite3_busy_timeout(database, CatalogBusyTimeoutMs);
        return owner;
    };
    snapshot.watcher = openCatalog();
    snapshot.version = ApiCatalogDataVersion(snapshot.watcher.get());
    auto owner = openCatalog();
    auto database = owner.get();
    sqlite3_progress_handler(database, SqliteProgressInterval, QueryWork::Interrupt, nullptr);
    if (SelectCatalogArchitecture(database, pointerSize) != SQLITE_OK)
        throw std::runtime_error("Cannot select the API catalog architecture.");
    if (sqlite3_exec(database, "PRAGMA query_only=ON; PRAGMA cache_size=-2048; PRAGMA mmap_size=268435456; BEGIN",
        nullptr, nullptr, nullptr) != SQLITE_OK) throw std::runtime_error("Cannot read the API catalog.");
    auto step = [](Statement& statement)
    {
        if (QueryWork::Interrupt(nullptr)) throw std::runtime_error("Query interrupted.");
        return statement.Next();
    };
    Statement counts(database, "SELECT (SELECT count(*) FROM builtin_apis), (SELECT count(*) FROM plans WHERE kind=0),"
        " (SELECT count(*) FROM plans), (SELECT count(*) FROM interfaces),"
        " (SELECT count(*) FROM interface_methods), (SELECT count(*) FROM ordinal_exports),"
        " (SELECT user_version FROM pragma_user_version), (SELECT count(*) FROM module_aliases)");
    Statement categoryCounts(database,
        "SELECT (SELECT count(*) FROM categories), (SELECT count(*) FROM category_rules)");
    if (!step(counts) || sqlite3_column_int(counts.value, 6) != ApiCatalogSchemaVersion || !step(categoryCounts))
        throw std::runtime_error("Unsupported API catalog schema.");
    CatalogHeader header{CatalogMagic, CatalogVersion};
    Statement architecture(database, "SELECT json_extract(layout,'$.size') FROM types WHERE name='SIZE_T'");
    if (!step(architecture) || sqlite3_column_int(architecture.value, 0) != static_cast<int>(pointerSize))
        throw std::runtime_error("The API catalog does not match this collector's pointer width.");
    header.pointerSize = pointerSize;
    header.builtinCount = sqlite3_column_int(counts.value, 0);
    header.exportCount = sqlite3_column_int(counts.value, 1);
    header.planCount = sqlite3_column_int(counts.value, 2);
    header.interfaceCount = sqlite3_column_int(counts.value, 3);
    header.slotCount = sqlite3_column_int(counts.value, 4);
    header.ordinalCount = sqlite3_column_int(counts.value, 5);
    header.moduleAliasCount = sqlite3_column_int(counts.value, 7);
    header.categoryCount = sqlite3_column_int(categoryCounts.value, 0);
    header.categoryRuleCount = sqlite3_column_int(categoryCounts.value, 1);
    constexpr uint32_t MaxCatalogPlans = 262144;
    constexpr uint32_t MaxCatalogSlots = 1048576;
    constexpr uint32_t MaxCatalogOrdinals = 65536;
    constexpr uint32_t MaxCatalogCategoryRules = 32768;
    if (header.builtinCount != static_cast<uint32_t>(Api::Count) || header.planCount > MaxCatalogPlans ||
        header.interfaceCount > UINT16_MAX || header.slotCount > MaxCatalogSlots ||
        header.ordinalCount > MaxCatalogOrdinals || header.moduleAliasCount > MaxModuleAliasCount ||
        header.categoryCount != static_cast<uint32_t>(ApiCategory::Count) ||
        header.categoryRuleCount > MaxCatalogCategoryRules)
        throw std::runtime_error("API catalog does not match this capture engine.");
    header.builtinOffset = sizeof(header);
    header.planOffset = header.builtinOffset + header.builtinCount * sizeof(CatalogApi);
    header.interfaceOffset = header.planOffset + header.planCount * sizeof(CatalogPlan);
    header.slotOffset = header.interfaceOffset + header.interfaceCount * sizeof(CatalogInterface);
    header.ordinalOffset = header.slotOffset + header.slotCount * sizeof(uint32_t);
    header.moduleAliasOffset = header.ordinalOffset + header.ordinalCount * sizeof(CatalogOrdinal);
    header.categoryOffset = header.moduleAliasOffset + header.moduleAliasCount * sizeof(CatalogModuleAlias);
    header.categoryRuleOffset = header.categoryOffset + header.categoryCount * sizeof(CatalogCategory);
    std::vector<std::byte> image(
        header.categoryRuleOffset + header.categoryRuleCount * sizeof(CatalogCategoryRule));
    auto append = [&image](const void* bytes, size_t count, size_t alignment)
    {
        auto offset = (image.size() + alignment - 1) & ~(alignment - 1);
        if (offset + count > CatalogBudget)
            throw std::runtime_error("API capture catalog exceeds its memory limit.");
        image.resize(offset + count);
        if (count) memcpy(image.data() + offset, bytes, count);
        return static_cast<uint32_t>(offset);
    };
    using InternedData = std::unordered_map<std::string, uint32_t, CatalogTextHash, std::equal_to<>>;
    InternedData texts, descriptions;
    auto intern = [&](std::string_view string, bool wide = false)
    {
        auto& cache = wide ? descriptions : texts;
        if (auto found = cache.find(string); found != cache.end()) return found->second;
        uint32_t offset;
        if (wide)
        {
            auto unicode = Wide(std::string(string));
            offset = append(unicode.c_str(), (unicode.size() + 1) * sizeof(wchar_t), sizeof(wchar_t));
        }
        else offset = append(string.data(), string.size() + 1, 1);
        cache.emplace(string, offset);
        return offset;
    };
    auto text = [&](sqlite3_stmt* row, int column, bool wide = false)
    {
        const auto value = sqlite3_column_text(row, column);
        if (!value) throw std::runtime_error("API catalog contains missing metadata.");
        std::string_view string(reinterpret_cast<const char*>(value), sqlite3_column_bytes(row, column));
        return intern(string, wide);
    };

    // Category names and ordered matching rules travel with every immutable capture snapshot.
    Statement categories(database, "SELECT id,name,description FROM categories ORDER BY id");
    uint32_t index = 0;
    while (step(categories))
    {
        CatalogCategory value{static_cast<uint32_t>(sqlite3_column_int(categories.value, 0)),
            text(categories.value, 1), text(categories.value, 2)};
        if (value.id != index || index >= header.categoryCount)
            throw std::runtime_error("Invalid API category identity.");
        memcpy(image.data() + header.categoryOffset + index++ * sizeof(value), &value, sizeof(value));
    }
    Statement categoryRules(database,
        "SELECT category_id,CASE target WHEN 'name' THEN 0 WHEN 'module' THEN 1 ELSE 2 END,"
        "CASE match WHEN 'prefix' THEN 0 WHEN 'contains' THEN 1 WHEN 'exact' THEN 2 ELSE 3 END,pattern,replacement"
        " FROM category_rules ORDER BY position");
    index = 0;
    while (step(categoryRules))
    {
        auto category = sqlite3_column_type(categoryRules.value, 0) == SQLITE_NULL ?
            static_cast<int64_t>(ApiCategory::Count) : sqlite3_column_int64(categoryRules.value, 0);
        if (category < 0 || category > static_cast<int64_t>(ApiCategory::Count) ||
            index >= header.categoryRuleCount) throw std::runtime_error("Invalid API category rule.");
        CatalogCategoryRule value{static_cast<ApiCategory>(category),
            static_cast<CategoryTarget>(sqlite3_column_int(categoryRules.value, 1)),
            static_cast<CategoryMatch>(sqlite3_column_int(categoryRules.value, 2)),
            text(categoryRules.value, 3), static_cast<uint32_t>(sqlite3_column_bytes(categoryRules.value, 3))};
        if (sqlite3_column_type(categoryRules.value, 4) != SQLITE_NULL)
        {
            value.replacement = text(categoryRules.value, 4);
            value.replacementBytes = static_cast<uint32_t>(sqlite3_column_bytes(categoryRules.value, 4));
        }
        memcpy(image.data() + header.categoryRuleOffset + index++ * sizeof(value), &value, sizeof(value));
    }
    // Exact aliases retain module identity without scanning unrelated providers for every export.
    Statement moduleAliases(database, "SELECT alias,module FROM module_aliases ORDER BY alias");
    std::unordered_set<std::string> aliasNames;
    std::vector<std::string> aliasTargets;
    auto literalModule = [](std::string_view value)
    {
        return value.size() > 4 && value.ends_with(".dll") &&
            std::all_of(value.begin(), value.end(), [](unsigned char character)
        {
            return character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
                character == '.' || character == '_' || character == '-';
        });
    };
    index = 0;
    while (step(moduleAliases))
    {
        auto aliasText = sqlite3_column_text(moduleAliases.value, 0);
        auto moduleText = sqlite3_column_text(moduleAliases.value, 1);
        if (!aliasText || !moduleText || index >= header.moduleAliasCount)
            throw std::runtime_error("Invalid API module alias.");
        std::string alias(reinterpret_cast<const char*>(aliasText), sqlite3_column_bytes(moduleAliases.value, 0));
        std::string module(reinterpret_cast<const char*>(moduleText), sqlite3_column_bytes(moduleAliases.value, 1));
        if (!literalModule(alias) || !literalModule(module) || alias == module || !aliasNames.insert(alias).second)
            throw std::runtime_error("Invalid API module alias.");
        aliasTargets.push_back(module);
        CatalogModuleAlias value{intern(alias), intern(module)};
        memcpy(image.data() + header.moduleAliasOffset + index++ * sizeof(value), &value, sizeof(value));
    }
    if (index != header.moduleAliasCount || std::any_of(aliasTargets.begin(), aliasTargets.end(),
        [&](const auto& module) { return aliasNames.contains(module); }))
        throw std::runtime_error("Invalid API module alias chain.");
    std::vector<sqlite3_int64> builtinFunctions(header.builtinCount);
    Statement builtin(database, "SELECT b.id,f.module,f.name,f.description,b.argument_count,b.function_id,"
                         "coalesce(h.flags,0),coalesce(h.native_name,'') FROM builtin_apis b"
                         " JOIN functions f ON f.id=b.function_id LEFT JOIN builtin_hook_policies h ON "
                         "h.function_id=f.id ORDER BY b.id");
    index = 0;
    while (step(builtin))
    {
        CatalogApi value{static_cast<uint32_t>(sqlite3_column_int(builtin.value, 0)),
            text(builtin.value, 1), text(builtin.value, 2), text(builtin.value, 3, true),
            static_cast<uint32_t>(sqlite3_column_int(builtin.value, 4))};
        if (index >= header.builtinCount) throw std::runtime_error("Invalid built-in API count.");
        builtinFunctions[index] = sqlite3_column_int64(builtin.value, 5);
        value.hookFlags = sqlite3_column_int(builtin.value, 6);
        value.nativeName = text(builtin.value, 7);
        if (value.hookFlags > AllHookFlagsMask ||
            (value.hookFlags & NativeHookFlagsMask) && !IsNativeApi(static_cast<Api>(value.id)) ||
            (value.hookFlags & HookProcessTermination) && !value.argumentCount)
            throw std::runtime_error("Invalid built-in hook policy.");
        if (value.id != index || value.argumentCount > MaximumArguments)
            throw std::runtime_error("Invalid built-in API identity.");
        memcpy(image.data() + header.builtinOffset + index++ * sizeof(value), &value, sizeof(value));
    }

    // Keep ordinal labels in the shared snapshot so observers never query SQLite during tracing.
    Statement ordinals(database, "SELECT lower(module),ordinal,name FROM ordinal_exports"
        " ORDER BY lower(module),ordinal");
    index = 0;
    while (step(ordinals))
    {
        auto ordinal = sqlite3_column_int(ordinals.value, 1);
        if (ordinal < 1 || ordinal > 65535 || index >= header.ordinalCount)
            throw std::runtime_error("Invalid ordinal export identity.");
        CatalogOrdinal value{text(ordinals.value, 0), static_cast<uint32_t>(ordinal), text(ordinals.value, 2)};
        memcpy(image.data() + header.ordinalOffset + index++ * sizeof(value), &value, sizeof(value));
    }

    // Sort GUIDs independently of database row IDs so imported contracts keep binary-search lookup.
    std::unordered_map<sqlite3_int64, uint16_t> interfaceIndices;
    std::unordered_map<std::string, uint16_t> interfaceNames;
    Statement contracts(database, "SELECT i.id,i.iid,i.name,"
        "(SELECT count(*) FROM interface_methods m WHERE m.interface_id=i.id),i.rtti FROM interfaces i"
        " ORDER BY i.iid");
    index = 0;
    uint32_t slot = 0;
    while (step(contracts))
    {
        CatalogInterface value{};
        if (sqlite3_column_bytes(contracts.value, 1) != 16 || index >= header.interfaceCount)
            throw std::runtime_error("Invalid COM interface identity.");
        interfaceIndices.emplace(sqlite3_column_int64(contracts.value, 0), static_cast<uint16_t>(index + 1));
        memcpy(&value.iid, sqlite3_column_blob(contracts.value, 1), sizeof(GUID));
        value.name = text(contracts.value, 2);
        auto [named, unique] = interfaceNames.emplace(
            reinterpret_cast<const char*>(sqlite3_column_text(contracts.value, 2)),
            static_cast<uint16_t>(index + 1));
        if (!unique) named->second = 0;
        if (sqlite3_column_type(contracts.value, 4) != SQLITE_NULL) value.rttiName = text(contracts.value, 4);
        value.firstSlot = slot;
        value.slotCount = sqlite3_column_int(contracts.value, 3);
        slot += value.slotCount;
        memcpy(image.data() + header.interfaceOffset + index++ * sizeof(value), &value, sizeof(value));
    }

    // Capture rules are shared by many plans; an invalid rule fails only where a plan references it.
    std::unordered_map<sqlite3_int64, std::pair<ExportParameter, const char*>> rules;
    Statement shared(database, "SELECT id,bytes,extent_index,indirect_bytes,multiplier,flags,kind,actual_index,"
        "actual_indirect_bytes,interface_index,prefix_bytes FROM capture_rules");
    while (step(shared))
    {
        ExportParameter value{static_cast<uint32_t>(sqlite3_column_int64(shared.value, 1)),
            static_cast<int8_t>(sqlite3_column_int(shared.value, 2)),
            static_cast<uint8_t>(sqlite3_column_int(shared.value, 3)),
            static_cast<uint16_t>(sqlite3_column_int(shared.value, 4)),
            static_cast<uint8_t>(sqlite3_column_int(shared.value, 5)),
            static_cast<ExportValueKind>(sqlite3_column_int(shared.value, 6)),
            static_cast<uint8_t>(sqlite3_column_int(shared.value, 7)),
            static_cast<uint8_t>(sqlite3_column_int(shared.value, 8)),
            0,
            static_cast<uint16_t>(sqlite3_column_int(shared.value, 10))};
        const char* error = nullptr;
        if (auto interfaceIdentity = sqlite3_column_int64(shared.value, 9))
        {
            auto found = interfaceIndices.find(interfaceIdentity);
            if (found == interfaceIndices.end()) error = "Invalid COM parameter identity.";
            else value.interfaceIndex = found->second;
        }
        if (!error && InvalidCaptureRule(value, pointerSize, header.interfaceCount))
            error = "Invalid API buffer capture rule.";
        rules.emplace(sqlite3_column_int64(shared.value, 0), std::pair{value, error});
    }

    // Plans are ordered by kind, name and identity; a COM plan is named by its method alone.
    std::unordered_map<sqlite3_int64, uint32_t> planIndices;
    planIndices.reserve(header.planCount);
    std::vector<CatalogPlan> planValues;
    std::vector<std::tuple<int, std::string, sqlite3_int64, uint32_t>> planOrder;
    planValues.reserve(header.planCount);
    planOrder.reserve(header.planCount);
    std::unordered_map<std::string, std::pair<uint32_t, uint32_t>, CatalogTextHash, std::equal_to<>> parameterLists;
    struct ParameterExtent { uint32_t ordinal, product, prefix, offset; };
    std::unordered_map<sqlite3_int64, std::vector<ParameterExtent>> parameterExtents;
    Statement extended(database, "SELECT function_id,ordinal,product_index,actual_prefix_bytes,actual_offset "
        "FROM capture_parameter_extents ORDER BY function_id,ordinal");
    while (step(extended))
    {
        auto ordinal = sqlite3_column_int(extended.value, 1), product = sqlite3_column_int(extended.value, 2);
        auto prefix = sqlite3_column_int(extended.value, 3);
        auto offset = sqlite3_column_int(extended.value, 4);
        if (ordinal < 0 || ordinal >= static_cast<int>(MaximumArguments) || product < 0 ||
            product > static_cast<int>(MaximumArguments) ||
            prefix < 0 || prefix > UINT16_MAX || offset < 0 || offset > UINT16_MAX)
            throw std::runtime_error("Invalid API capture extent.");
        parameterExtents[sqlite3_column_int64(extended.value, 0)].push_back(
            {static_cast<uint32_t>(ordinal), static_cast<uint32_t>(product), static_cast<uint32_t>(prefix),
                static_cast<uint32_t>(offset)});
    }
    std::vector<ExportParameter> values;

    // Per-function overrides are small; index them once instead of seeking each one for every plan.
    auto overrides = [&](const char* sql)
    {
        std::unordered_map<sqlite3_int64, int> entries;
        Statement rows(database, sql);
        while (step(rows))
            entries.emplace(sqlite3_column_int64(rows.value, 0), sqlite3_column_int(rows.value, 1));
        return entries;
    };
    auto overridden = [](const auto& entries, sqlite3_int64 identity, int value)
    {
        auto found = entries.find(identity);
        return found == entries.end() ? value : found->second;
    };
    auto resultRules = overrides("SELECT function_id,rule FROM function_rules");
    auto variadicPrefixes = overrides("SELECT function_id,fixed_count FROM variadic_prefixes");
    auto resultCaptures = overrides("SELECT function_id,kind FROM result_captures");
    auto conventions = pointerSize == 4 ? overrides("SELECT function_id,convention FROM function_abis") :
        decltype(resultRules){};
    std::string description;
    Statement plans(database, "SELECT p.function_id,f.name,f.module,f.summary,p.argument_count,p.argument_bytes,"
        "p.floating_arguments,p.result_bytes,p.floating_result,p.supported,p.interface_id_index,"
        "p.interface_output_index,p.return_buffer_bytes,p.status_result,p.interface_parameters,"
        "p.counted_result_bytes,f.result,f.signature,p.kind,p.capture_rules"
        " FROM plans p JOIN functions f ON f.id=p.function_id");
    index = 0;
    while (step(plans))
    {
        CatalogPlan value{};
        auto identity = sqlite3_column_int64(plans.value, 0);
        auto kind = sqlite3_column_int(plans.value, 18);
        auto qualified = sqlite3_column_text(plans.value, 1);
        if (!qualified) throw std::runtime_error("API catalog contains missing metadata.");
        std::string name(reinterpret_cast<const char*>(qualified), sqlite3_column_bytes(plans.value, 1));
        if (auto scope = name.rfind("::"); kind && scope != std::string::npos) name.erase(0, scope + 2);
        value.name = intern(name);
        value.module = text(plans.value, 2);

        // Without a summary, a plan is described by its declared parameters, as the description column is.
        if (sqlite3_column_type(plans.value, 3) != SQLITE_NULL) value.description = text(plans.value, 3, true);
        else
        {
            auto declared = reinterpret_cast<const char*>(sqlite3_column_text(plans.value, 17));
            if (!declared) throw std::runtime_error("API catalog contains missing metadata.");
            description.clear();
            for (auto character : std::string_view(declared, sqlite3_column_bytes(plans.value, 17)))
                if (character == '\t') description += ' ';
                else if (character == '\n') description += ", ";
                else description += character;
            value.description = intern(description, true);
        }
        value.argumentCount = sqlite3_column_int(plans.value, 4);
        auto widths = sqlite3_column_bytes(plans.value, 5);
        if (value.argumentCount > MaximumArguments || widths != static_cast<int>(value.argumentCount) ||
            index >= header.planCount)
            throw std::runtime_error("Invalid API argument layout.");
        if (widths) memcpy(value.signature.argumentBytes, sqlite3_column_blob(plans.value, 5), widths);
        value.signature.floatingArguments = static_cast<uint8_t>(sqlite3_column_int(plans.value, 6));
        value.signature.resultBytes = static_cast<uint8_t>(sqlite3_column_int(plans.value, 7));
        value.signature.floatingResult = sqlite3_column_int(plans.value, 8) != 0;
        value.signature.supported = sqlite3_column_int(plans.value, 9) != 0;
        value.signature.callingConvention =
            static_cast<ExportCallingConvention>(overridden(conventions, identity, 0));
        value.signature.interfaceIdIndex = static_cast<uint8_t>(sqlite3_column_int(plans.value, 10));
        value.signature.interfaceOutputIndex = static_cast<uint8_t>(sqlite3_column_int(plans.value, 11));
        value.signature.returnBufferBytes = sqlite3_column_int(plans.value, 12);
        auto resultRule = overridden(resultRules, identity, sqlite3_column_int(plans.value, 13));
        if (resultRule < 0 || resultRule > static_cast<int>(ExportResultRule::NonPositive))
            throw std::runtime_error("Invalid API result rule.");
        value.resultRule = static_cast<ExportResultRule>(resultRule);
        value.interfaceParameters = sqlite3_column_int(plans.value, 14);
        value.countedResultBytes = sqlite3_column_int(plans.value, 15);
        auto resultCapture = overridden(resultCaptures, identity, 0);
        if (resultCapture && (resultCapture != static_cast<int>(ExportValueKind::BerValue) &&
                                     resultCapture != static_cast<int>(ExportValueKind::BerValues) &&
                                     resultCapture != static_cast<int>(ExportValueKind::Ansi) &&
                                     resultCapture != static_cast<int>(ExportValueKind::Utf16) ||
                                 value.signature.resultBytes != pointerSize || value.signature.floatingResult ||
                                 !value.signature.supported))
            throw std::runtime_error("Invalid API result capture rule.");
        value.resultCaptureKind = static_cast<ExportValueKind>(resultCapture);
        value.rawTailStart = static_cast<uint16_t>(overridden(variadicPrefixes, identity, 0));
        if (value.rawTailStart && (value.rawTailStart != value.argumentCount ||
            value.rawTailStart >= RawArgumentCount))
            throw std::runtime_error("Invalid variadic API prefix.");

        // A named interface pointer result discovers the returned object's own vtable.
        auto result = std::string(reinterpret_cast<const char*>(sqlite3_column_text(plans.value, 16)));
        auto star = result.find_last_not_of(" \t");
        if (star != std::string::npos && result[star] == '*')
        {
            result.resize(star);
            auto end = result.find_last_not_of(" \t");
            if (end != std::string::npos)
            {
                result.resize(end + 1);
                if (auto found = interfaceNames.find(result); found != interfaceNames.end())
                    value.resultInterfaceIndex = found->second;
            }
        }

        // Each argument names its capture rule; plans listing the same rules share one parameter array.
        auto list = sqlite3_column_text(plans.value, 19);
        std::string_view listed(list ? reinterpret_cast<const char*>(list) : "",
            static_cast<size_t>(sqlite3_column_bytes(plans.value, 19)));
        auto extents = parameterExtents.find(identity);
        std::string parameterKey(listed);
        if (extents != parameterExtents.end())
            for (const auto& extent : extents->second)
                parameterKey += ":" + std::to_string(extent.ordinal) + "," + std::to_string(extent.product) +
                    "," + std::to_string(extent.prefix) + "," + std::to_string(extent.offset);
        auto entry = parameterLists.find(parameterKey);
        if (entry == parameterLists.end())
        {
            values.clear();
            auto cursor = listed.data(), end = cursor + listed.size();
            auto valid = cursor != end && *cursor++ == '[';
            while (valid && cursor != end && *cursor != ']')
            {
                sqlite3_int64 rule = 0;
                auto parsed = std::from_chars(cursor, end, rule);
                auto found = parsed.ec == std::errc{} ? rules.find(rule) : rules.end();
                valid = found != rules.end() && values.size() < MaximumArguments;
                if (!valid) break;
                if (found->second.second) throw std::runtime_error(found->second.second);
                values.push_back(found->second.first);
                cursor = parsed.ptr;
                if (cursor != end && *cursor == ',') ++cursor;
            }
            if (!valid || cursor == end || cursor + 1 != end)
                throw std::runtime_error("Invalid API capture parameters.");
            for (uint32_t ordinal = 0; ordinal < values.size(); ++ordinal)
            {
                const auto& parameter = values[ordinal];
                if ((parameter.kind == ExportValueKind::PrintDocumentEvent &&
                        (parameter.extentIndex >= static_cast<int>(values.size()) ||
                         parameter.actualIndex > values.size() || parameter.prefixBytes > values.size())) ||
                    (parameter.kind == ExportValueKind::AuthzOperations && parameter.actualIndex > values.size()) ||
                    (parameter.kind == ExportValueKind::Utf16StringArray &&
                        (parameter.extentIndex >= static_cast<int>(values.size()) ||
                            parameter.actualIndex > values.size())) ||
                    (parameter.kind == ExportValueKind::PrinterPayload &&
                        (values.size() <= (parameter.bytes == 1 ? 4u : 3u) ||
                            ordinal != (parameter.bytes == 1 ? 4u : 3u))))
                    throw std::runtime_error("Invalid API capture parameter reference.");
            }
            if (extents != parameterExtents.end())
                for (const auto& extent : extents->second)
                {
                    if (extent.ordinal >= values.size() || extent.product > values.size())
                        throw std::runtime_error("Invalid API capture extent.");
                    auto& parameter = values[extent.ordinal];
                    if (extent.product && parameter.extentIndex < 0 || extent.prefix && !parameter.actualIndex ||
                        (parameter.kind == ExportValueKind::RtmBuffer ||
                            parameter.kind == ExportValueKind::PrinterPayload) &&
                            (extent.product || extent.prefix || extent.offset) ||
                        parameter.kind == ExportValueKind::Utf16StringArray &&
                            (uint64_t{extent.offset} + pointerSize > parameter.multiplier ||
                                extent.offset && parameter.actualIndex) ||
                        extent.offset && (!parameter.actualIndex || !parameter.actualIndirectBytes) &&
                            parameter.kind != ExportValueKind::Utf16StringArray &&
                            (parameter.kind != ExportValueKind::CountedBytes ||
                                uint64_t{extent.offset} + sizeof(uint32_t) > parameter.bytes))
                        throw std::runtime_error("Invalid API capture extent.");
                    parameter.productIndex = static_cast<uint8_t>(extent.product);
                    parameter.actualPrefixBytes = static_cast<uint16_t>(extent.prefix);
                    parameter.actualOffset = static_cast<uint16_t>(extent.offset);
                }
            auto offset = values.empty() ? 0 :
                append(values.data(), values.size() * sizeof(ExportParameter), alignof(ExportParameter));
            entry = parameterLists.emplace(parameterKey,
                std::pair{offset, static_cast<uint32_t>(values.size())}).first;
        }
        if (entry->second.second != value.argumentCount)
            throw std::runtime_error("Incomplete API capture parameters.");
        value.parameters = entry->second.first;
        for (uint32_t ordinal = 0; ordinal < value.argumentCount; ++ordinal)
        {
            ExportParameter parameter{};
            memcpy(&parameter, image.data() + value.parameters + ordinal * sizeof(parameter), sizeof(parameter));
            if (parameter.kind != ExportValueKind::RtmBuffer &&
                parameter.kind != ExportValueKind::PrinterPayload) continue;
            auto module = reinterpret_cast<const char*>(sqlite3_column_text(plans.value, 2));
            if (!module) throw std::runtime_error("Invalid special API buffer contract.");
            const std::string_view fullName(reinterpret_cast<const char*>(qualified),
                static_cast<size_t>(sqlite3_column_bytes(plans.value, 1)));
            if (parameter.kind == ExportValueKind::RtmBuffer)
            {
                // Each route mode fixes its argument, selector and direction before using shared rule lists.
                constexpr struct { int8_t selector; uint8_t ordinal, flags, actual; } routeContracts[] =
                {
                    {0, 2, 3, 0}, {0, 1, 1, 0}, {0, 2, 1, 2}, {0, 2, 2, 0},
                    {-1, 1, 1, 0}, {-1, 1, 1, 0}, {1, 2, 1, 0}, {3, 4, 2, 0},
                    {3, 5, 2, 0}, {2, 3, 2, 0}, {1, 2, 2, 0}, {1, 3, 2, 0}, {-1, 1, 2, 0}
                };
                if (parameter.bytes >= 13) throw std::runtime_error("Invalid routing API buffer contract.");
                const auto& contract = routeContracts[parameter.bytes];
                if (ordinal != contract.ordinal || parameter.extentIndex != contract.selector ||
                    parameter.extentIndex >= static_cast<int>(value.argumentCount) ||
                    parameter.actualIndex != contract.actual ||
                    parameter.flags != contract.flags && !(parameter.bytes == 2 && parameter.flags == 3))
                    throw std::runtime_error("Invalid routing API buffer contract.");
            }
            auto valid = parameter.kind == ExportValueKind::RtmBuffer ? std::string_view(module) == "rtm.dll" &&
                ((fullName == "RtmCreateEnumerationHandle" && parameter.bytes == 2 && parameter.flags == 1) ||
                 (fullName == "RtmGetFirstRoute" && parameter.bytes == 2 && parameter.flags == 3) ||
                 (fullName == "RtmGetNextRoute" && parameter.bytes == 0) ||
                 (fullName == "RtmIsRoute" && (parameter.bytes == 1 || parameter.bytes == 3)) ||
                 (fullName == "RtmAddRoute" &&
                    (parameter.bytes == 4 || parameter.bytes == 7 || parameter.bytes == 8)) ||
                 (fullName == "RtmDeleteRoute" && (parameter.bytes == 5 || parameter.bytes == 9)) ||
                 (fullName == "RtmBlockDeleteRoutes" && parameter.bytes == 6) ||
                 (fullName == "RtmDequeueRouteChangeMessage" &&
                    (parameter.bytes == 10 || parameter.bytes == 11)) ||
                 (fullName == "RtmEnumerateGetNextRoute" && parameter.bytes == 12)) :
                (std::string_view(module) == "COM" &&
                    (parameter.bytes == 0 &&
                        (fullName == "IPrintOemUI::DriverEvent" || fullName == "IPrintOemUI2::DriverEvent") ||
                     parameter.bytes == 1 && fullName == "IPrintOemUI2::QueryJobAttributes")) ||
                (std::string_view(module) == "spoolss.dll" && parameter.bytes == 2 &&
                    fullName == "ReplyPrinterChangeNotification");
            if (!valid) throw std::runtime_error("Invalid special API buffer contract.");
        }

        // Declared interface outputs and queried factories supply identities absent from capture rules.
        auto signature = sqlite3_column_text(plans.value, 17);
        std::string_view declarations(signature ? reinterpret_cast<const char*>(signature) : "",
            static_cast<size_t>(sqlite3_column_bytes(plans.value, 17)));
        auto parameters = reinterpret_cast<const ExportParameter*>(image.data() + value.parameters);
        std::vector<ExportParameter> bound;
        auto inferQuery = result == "HRESULT" && value.signature.resultBytes == 4 &&
            !value.signature.floatingResult && value.resultRule == ExportResultRule::Negative &&
            !value.signature.interfaceIdIndex && !value.signature.interfaceOutputIndex;
        uint32_t queryId = 0, queryOutput = 0, queryIds = 0, queryOutputs = 0;
        for (uint32_t ordinal = 0; value.signature.supported && ordinal < value.argumentCount &&
            !declarations.empty(); ++ordinal)
        {
            auto end = declarations.find('\n');
            auto declaration = declarations.substr(0, end);
            declarations.remove_prefix(end == std::string_view::npos ? declarations.size() : end + 1);
            const auto& parameter = parameters[ordinal];
            auto separator = declaration.find('\t');
            if (separator == std::string_view::npos) continue;
            std::string type(declaration.substr(0, separator));
            std::erase_if(type, [](char letter) { return letter == ' ' || letter == '\t'; });

            // An unambiguous IID input and scalar void output define a queried HRESULT factory.
            if (inferQuery)
            {
                auto scalar = !parameter.interfaceIndex && parameter.extentIndex == -1 &&
                    !parameter.prefixBytes && !parameter.actualIndex &&
                    value.signature.argumentBytes[ordinal] == pointerSize;
                if (type == "IID&" || type == "constIID&" || type == "REFIID" || type == "constIID*")
                {
                    ++queryIds;
                    if (scalar && parameter.bytes == sizeof(GUID) && parameter.flags == 1 &&
                        parameter.kind == ExportValueKind::Bytes) queryId = ordinal + 1;
                }
                if (type == "void**")
                {
                    ++queryOutputs;
                    if (scalar && parameter.bytes == pointerSize && parameter.flags == 2 &&
                        parameter.kind == ExportValueKind::Scalar) queryOutput = ordinal + 1;
                }
            }
            if (parameter.interfaceIndex || parameter.kind != ExportValueKind::Scalar ||
                parameter.bytes != pointerSize || parameter.extentIndex != -1 ||
                parameter.flags != 2 && parameter.flags != 3 || parameter.prefixBytes || parameter.actualIndex ||
                value.signature.argumentBytes[ordinal] != pointerSize ||
                value.signature.interfaceIdIndex && value.signature.interfaceOutputIndex == ordinal + 1) continue;
            if (!type.ends_with("**")) continue;
            type.resize(type.size() - 2);
            auto known = interfaceNames.find(type);
            if (known == interfaceNames.end() || !known->second) continue;
            if (bound.empty()) bound.assign(parameters, parameters + value.argumentCount);
            bound[ordinal].interfaceIndex = known->second;
            value.interfaceParameters |= 1u << ordinal;
            parameterKey += "|" + std::to_string(ordinal) + ":" + std::to_string(known->second);
        }
        if (queryIds == 1 && queryOutputs == 1 && queryId && queryOutput)
        {
            value.signature.interfaceIdIndex = static_cast<uint8_t>(queryId);
            value.signature.interfaceOutputIndex = static_cast<uint8_t>(queryOutput);
            value.interfaceParameters |= 1u << (queryOutput - 1);
        }
        if (!bound.empty())
        {
            auto found = parameterLists.find(parameterKey);
            if (found == parameterLists.end())
            {
                auto offset = append(bound.data(), bound.size() * sizeof(ExportParameter),
                    alignof(ExportParameter));
                found = parameterLists.emplace(std::move(parameterKey),
                    std::pair{offset, value.argumentCount}).first;
            }
            value.parameters = found->second.first;
        }
        planOrder.emplace_back(kind, std::move(name), identity, index++);
        planValues.push_back(value);
    }
    if (index != header.planCount) throw std::runtime_error("Incomplete API capture plans.");
    std::sort(planOrder.begin(), planOrder.end());
    for (uint32_t position = 0; position < planOrder.size(); ++position)
    {
        planIndices.emplace(std::get<2>(planOrder[position]), position);
        memcpy(image.data() + header.planOffset + position * sizeof(CatalogPlan),
            &planValues[std::get<3>(planOrder[position])], sizeof(CatalogPlan));
    }

    // Resolve built-in plans once; hooks only index the immutable snapshot while capturing calls.
    for (uint32_t position = 0; position < header.builtinCount; ++position)
    {
        auto found = planIndices.find(builtinFunctions[position]);
        auto offset = header.builtinOffset + position * sizeof(CatalogApi);
        CatalogApi value;
        memcpy(&value, image.data() + offset, sizeof(value));
        if (found != planIndices.end()) value.planIndex = found->second;
        if ((IsWin32Api(static_cast<Api>(position)) || IsNativeApi(static_cast<Api>(position)) ||
            IsWin32uApi(static_cast<Api>(position))) && (found == planIndices.end() ||
            pointerSize == 8 && !planValues[std::get<3>(planOrder[found->second])].signature.supported))
            throw std::runtime_error("Missing built-in API capture plan.");
        memcpy(image.data() + offset, &value, sizeof(value));
    }

    // Materialize bounded successful status values beside their plans, outside intercepted calls.
    Statement successes(database, "SELECT function_id,value FROM result_success_values ORDER BY function_id,value");
    sqlite3_int64 previous = -1;
    std::vector<uint32_t> successValues;
    auto finishSuccesses = [&]()
    {
        if (previous < 0) return;
        auto position = header.planOffset + planIndices.at(previous) * sizeof(CatalogPlan);
        CatalogPlan value;
        memcpy(&value, image.data() + position, sizeof(value));
        if (!value.signature.supported || value.signature.floatingResult ||
            value.signature.resultBytes != 1 && value.signature.resultBytes != 2 &&
            value.signature.resultBytes != 4 && value.signature.resultBytes != 8 ||
            successValues.size() > MaxResultSuccessCount)
            throw std::runtime_error("Invalid API successful status values.");
        auto mask = value.signature.resultBytes == 1 ? UINT64_C(0xff) :
            value.signature.resultBytes == 2 ? UINT64_C(0xffff) : UINT64_C(0xffffffff);
        if (std::any_of(successValues.begin(), successValues.end(),
            [mask](auto result) { return result > mask; }))
            throw std::runtime_error("Invalid API successful status width.");
        value.resultSuccesses = append(successValues.data(), successValues.size() * sizeof(uint32_t), 4);
        value.resultSuccessCount = static_cast<uint8_t>(successValues.size());
        memcpy(image.data() + position, &value, sizeof(value));
    };
    while (step(successes))
    {
        auto function = sqlite3_column_int64(successes.value, 0);
        auto result = sqlite3_column_int64(successes.value, 1);
        if (!planIndices.contains(function) || result < 0 || result > UINT32_MAX)
            throw std::runtime_error("Invalid API successful status identity.");
        if (function != previous)
        {
            finishSuccesses();
            previous = function;
            successValues.clear();
        }
        if (successValues.size() == MaxResultSuccessCount)
            throw std::runtime_error("API successful status limit exceeded.");
        successValues.push_back(static_cast<uint32_t>(result));
    }
    finishSuccesses();

    // Compile referenced structure buffers into fixed offset rules shared by all observer processes.
    Statement members(database, "SELECT m.function_id,m.ordinal,m.parameter,m.pointer_offset,m.extent_offset,m.extent_bytes,"
              "m.multiplier,m.flags,coalesce(e.product_offset,0),coalesce(e.product_bytes,0),"
              "coalesce(e.condition_index,0),coalesce(e.condition_mask,0) FROM capture_members m"
              " LEFT JOIN capture_member_extents e ON e.function_id=m.function_id AND e.ordinal=m.ordinal"
              " ORDER BY m.function_id,m.ordinal");
    std::vector<ExportMember> memberValues;
    previous = -1;
    auto finishMembers = [&]()
    {
        if (previous < 0) return;
        auto position = header.planOffset + planIndices.at(previous) * sizeof(CatalogPlan);
        CatalogPlan value;
        memcpy(&value, image.data() + position, sizeof(value));
        if (memberValues.size() + value.argumentCount > MaximumArguments)
            throw std::runtime_error("Too many referenced API buffers.");
        for (const auto& member : memberValues)
            if (member.parameter >= value.argumentCount || member.conditionIndex > value.argumentCount ||
                (member.flags & ExportInlineRecord) &&
                    (value.signature.argumentBytes[member.parameter] > sizeof(uint64_t) ||
                     uint64_t{member.pointerOffset} + pointerSize >
                        value.signature.argumentBytes[member.parameter] ||
                     uint64_t{member.extentOffset} + member.extentBytes >
                        value.signature.argumentBytes[member.parameter] ||
                     uint64_t{member.productOffset} + member.productBytes >
                        value.signature.argumentBytes[member.parameter]))
                throw std::runtime_error("Invalid referenced API parameter.");
        value.memberCount = static_cast<uint32_t>(memberValues.size());
        value.members = append(memberValues.data(), memberValues.size() * sizeof(ExportMember),
            alignof(ExportMember));
        memcpy(image.data() + position, &value, sizeof(value));
        memberValues.clear();
    };
    while (step(members))
    {
        auto identity = sqlite3_column_int64(members.value, 0);
        if (identity != previous) { finishMembers(); previous = identity; }
        if (sqlite3_column_int(members.value, 1) != static_cast<int>(memberValues.size()))
            throw std::runtime_error("Invalid referenced API buffer order.");
        for (int column = 2; column <= 6; ++column)
            if (sqlite3_column_int64(members.value, column) < 0 ||
                sqlite3_column_int64(members.value, column) > UINT16_MAX)
                throw std::runtime_error("Invalid referenced API buffer offset.");
        auto width = sqlite3_column_int(members.value, 5), flags = sqlite3_column_int(members.value, 7);
        auto ordinary = flags & ~(ExportInlineRecord | ExportIndirectRecord | ExportIndirectSelector);
        constexpr int ExportInputOutput = ExportInput | ExportOutput;
        auto terminated = ordinary >= (ExportInput | ExportTerminated) &&
            ordinary <= (ExportInputOutput | ExportTerminated);
        if ((flags & ExportInlineRecord) &&
            (flags & (ExportOutput | ExportAdvancingBuffer | ExportReturnedBuffer | ExportIndirectRecord)))
            throw std::runtime_error("Invalid inline API buffer direction.");
        if (terminated ? width != 0 || sqlite3_column_int(members.value, 4) != 0 :
            (width != 1 && width != 2 && width != 4 && width != 8) || ordinary < ExportInput ||
                (ordinary > ExportInputOutput && ordinary != (ExportOutput | ExportReturnedBuffer) &&
                    ordinary != (ExportOutput | ExportAdvancingBuffer) &&
                    !(ordinary == (ExportInputOutput | ExportReturnedBuffer) && (flags & ExportIndirectRecord))))
            throw std::runtime_error("Invalid referenced API buffer extent.");
        ExportMember value{static_cast<uint16_t>(sqlite3_column_int(members.value, 2)),
            static_cast<uint16_t>(sqlite3_column_int(members.value, 3)),
            static_cast<uint16_t>(sqlite3_column_int(members.value, 4)),
            static_cast<uint16_t>(sqlite3_column_int(members.value, 6)),
            static_cast<uint8_t>(sqlite3_column_int(members.value, 5)),
            static_cast<uint8_t>(sqlite3_column_int(members.value, 7)),
            static_cast<uint16_t>(sqlite3_column_int(members.value, 8)),
            static_cast<uint8_t>(sqlite3_column_int(members.value, 9)),
            static_cast<uint8_t>(sqlite3_column_int(members.value, 10)), 0,
            static_cast<uint32_t>(sqlite3_column_int64(members.value, 11))};
        auto productOffset = sqlite3_column_int64(members.value, 8);
        auto productBytes = sqlite3_column_int(members.value, 9);
        auto conditionIndex = sqlite3_column_int(members.value, 10);
        auto conditionMask = sqlite3_column_int64(members.value, 11);
        if ((flags & ExportIndirectSelector) && (!conditionIndex || (flags & ExportInput)))
            throw std::runtime_error("Invalid referenced API selector.");
        if (productOffset < 0 || productOffset > UINT16_MAX ||
            (productBytes != 0 && productBytes != 1 && productBytes != 2 && productBytes != 4 &&
                productBytes != 8) ||
            !productBytes && productOffset || conditionIndex < 0 || conditionIndex > MaximumArguments ||
            conditionMask < 0 || conditionMask > UINT32_MAX || bool(conditionIndex) != bool(conditionMask))
            throw std::runtime_error("Invalid referenced API product or condition.");
        if (!value.multiplier || terminated && (value.multiplier > 2 || productBytes))
            throw std::runtime_error("Invalid referenced API buffer extent.");
        memberValues.push_back(value);
    }
    finishMembers();
    Statement methods(database, "SELECT m.interface_id,m.slot,m.function_id FROM interface_methods m"
        " JOIN interfaces i ON i.id=m.interface_id ORDER BY i.iid,m.slot");
    index = 0;
    while (step(methods))
    {
        auto contractIndex = interfaceIndices.at(sqlite3_column_int64(methods.value, 0)) - 1;
        auto contract = reinterpret_cast<const CatalogInterface*>(image.data() + header.interfaceOffset) +
            contractIndex;
        if (sqlite3_column_int(methods.value, 1) != static_cast<int>(index - contract->firstSlot) ||
            index >= header.slotCount)
            throw std::runtime_error("Invalid COM interface slot order.");
        auto position = planIndices.at(sqlite3_column_int64(methods.value, 2));
        memcpy(image.data() + header.slotOffset + index++ * sizeof(position), &position, sizeof(position));
    }
    header.bytes = static_cast<uint32_t>(image.size());
    memcpy(image.data(), &header, sizeof(header));
    snapshot.name = L"Local\\Detourist.Catalog." + std::to_wstring(GetCurrentProcessId()) + L"." +
        std::to_wstring(pointerSize) + L"." + std::to_wstring(Clock());
    snapshot.mapping.reset(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        header.bytes, snapshot.name.c_str()));
    Check(static_cast<bool>(snapshot.mapping), "Create API catalog snapshot");
    snapshot.view.reset(MapViewOfFile(snapshot.mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, header.bytes));
    Check(static_cast<bool>(snapshot.view), "Map API catalog snapshot");
    memcpy(snapshot.view.get(), image.data(), header.bytes);
    DWORD protection;
    Check(VirtualProtect(snapshot.view.get(), header.bytes, PAGE_READONLY, &protection) != FALSE,
        "Protect API catalog snapshot");
    CatalogView view;
    if (!view.Open(snapshot.view.get(), header.bytes, pointerSize))
        throw std::runtime_error("Invalid API catalog snapshot.");
    if (pointerSize == sizeof(void*) && !BindApiDefinitions(view))
        throw std::runtime_error("Invalid API catalog metadata or category policy.");
    catalog = std::move(snapshot);
}

const std::wstring& CaptureCatalogName(uint32_t pointerSize)
{
    PrepareApiCatalog(false, pointerSize);
    return CaptureCatalogs[pointerSize == 4 ? 0 : 1].name;
}
}

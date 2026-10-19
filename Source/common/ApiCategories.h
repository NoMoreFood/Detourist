#pragma once
#include <cstdint>
#include <array>

namespace Detourist
{
enum class ApiCategory : uint32_t
{
    Memory, Files, Registry, Processes, Synchronization, Windows, Input, Graphics, Networking, Security,
    Services, Components, Shell, Devices, Time, Diagnostics, Runtime, Text, Configuration, Media, Data, Ipc,
    Objects, Unclassified, Count
};

struct CategoryDefinition
{
    ApiCategory id;
    const char* name;
    const char* description;
};

extern std::array<CategoryDefinition, static_cast<uint32_t>(ApiCategory::Count)> CategoryDefinitions;

constexpr uint64_t AllCategories = (uint64_t{1} << static_cast<uint32_t>(ApiCategory::Count)) - 1;
constexpr uint64_t CategoryMask(ApiCategory category) { return uint64_t{1} << static_cast<uint32_t>(category); }
inline const CategoryDefinition& Category(ApiCategory category)
{
    auto index = static_cast<uint32_t>(category);
    return CategoryDefinitions[index < std::size(CategoryDefinitions) ? index :
        static_cast<uint32_t>(ApiCategory::Unclassified)];
}
ApiCategory ClassifyApi(const char* module, const char* name);
class CatalogView;
bool BindApiCategories(const CatalogView& catalog);
}

#include "CatalogView.h"
#include <algorithm>
#include <atomic>
#include <cstring>

namespace Detourist
{
std::array<CategoryDefinition, static_cast<uint32_t>(ApiCategory::Count)> CategoryDefinitions{};
CatalogView CategoryCatalog;
std::atomic_flag CategoryCatalogGate = ATOMIC_FLAG_INIT;

bool BindApiCategories(const CatalogView& catalog)
{
    // Validate the complete policy before replacing pointers held by the current capture.
    for (uint32_t index = 0; index < catalog.Header()->categoryCount; ++index)
    {
        const auto& source = catalog.Categories()[index];
        auto name = catalog.Text(source.name), description = catalog.Text(source.description);
        if (source.id != index || !name || !*name || !description) return false;
    }
    auto normalized = [](const char* text)
    {
        for (; *text; ++text)
            if (*text >= 'A' && *text <= 'Z') return false;
        return true;
    };
    for (uint32_t index = 0; index < catalog.Header()->categoryRuleCount; ++index)
    {
        const auto& rule = catalog.CategoryRules()[index];
        auto pattern = catalog.Text(rule.pattern);
        auto replacement = rule.replacement ? catalog.Text(rule.replacement) : nullptr;
        auto capacity = rule.target == CategoryTarget::Name ? MaximumApiNameBytes : MaximumApiModuleBytes;
        if (rule.target > CategoryTarget::Module || rule.match > CategoryMatch::Exact ||
            rule.category > ApiCategory::Count || !pattern || !rule.patternBytes ||
            rule.patternBytes >= capacity || strlen(pattern) != rule.patternBytes || !normalized(pattern) ||
            (rule.category == ApiCategory::Count ?
                !replacement || rule.match != CategoryMatch::Prefix || rule.replacementBytes >= capacity ||
                strlen(replacement) != rule.replacementBytes || !normalized(replacement) :
                rule.replacement || rule.replacementBytes)) return false;
    }

    // Finish concurrent discovery before publishing the replacement snapshot.
    while (CategoryCatalogGate.test_and_set(std::memory_order_acquire)) YieldProcessor();
    for (uint32_t index = 0; index < catalog.Header()->categoryCount; ++index)
    {
        const auto& source = catalog.Categories()[index];
        CategoryDefinitions[index] = {static_cast<ApiCategory>(index),
            catalog.Text(source.name), catalog.Text(source.description)};
    }
    CategoryCatalog = catalog;
    CategoryCatalogGate.clear(std::memory_order_release);
    return true;
}

ApiCategory CatalogView::ClassifyApi(const char* module, const char* name) const
{
    if (!header_) return ApiCategory::Unclassified;

    // Classification runs at discovery; captured calls retain their category mask.
    char symbol[MaximumApiNameBytes]{}, library[MaximumApiModuleBytes]{};
    auto normalize = [](char* output, size_t capacity, const char* input)
    {
        size_t index = 0;
        while (input && input[index] && index + 1 < capacity)
        {
            auto character = input[index];
            output[index++] = static_cast<char>(character >= 'A' && character <= 'Z' ?
                character + ('a' - 'A') : character);
        }
    };
    normalize(symbol, std::size(symbol), name);
    normalize(library, std::size(library), module);
    char* values[]{symbol, library};
    const size_t capacities[]{std::size(symbol), std::size(library)};
    uint32_t pairs[2][26]{};
    bool pairsReady[2]{};
    for (uint32_t index = 0; index < header_->categoryRuleCount; ++index)
    {
        const auto& rule = CategoryRules()[index];
        auto target = static_cast<uint32_t>(rule.target);
        auto value = values[target];
        auto pattern = reinterpret_cast<const char*>(data_ + rule.pattern);
        if (rule.match == CategoryMatch::Contains)
        {
            // Reject impossible substrings without changing the catalog's rule precedence.
            if (!pairsReady[target])
            {
                for (auto position = value; position[0] && position[1]; ++position)
                {
                    auto first = static_cast<uint32_t>(static_cast<unsigned char>(position[0])) - 'a';
                    auto second = static_cast<uint32_t>(static_cast<unsigned char>(position[1])) - 'a';
                    if (first < 26 && second < 26) pairs[target][first] |= uint32_t{1} << second;
                }
                pairsReady[target] = true;
            }
            if (rule.patternBytes >= 2)
            {
                auto first = static_cast<uint32_t>(static_cast<unsigned char>(pattern[0])) - 'a';
                auto second = static_cast<uint32_t>(static_cast<unsigned char>(pattern[1])) - 'a';
                if (first < 26 && second < 26 && !(pairs[target][first] & (uint32_t{1} << second))) continue;
            }
            if (!strstr(value, pattern)) continue;
        }
        else if (rule.match == CategoryMatch::Exact ? strcmp(value, pattern) :
            strncmp(value, pattern, rule.patternBytes)) continue;
        if (rule.category != ApiCategory::Count) return rule.category;

        // Prefix rewrites share the ordered policy and can change either identity field.
        auto replacement = reinterpret_cast<const char*>(data_ + rule.replacement);
        auto tail = std::min(strlen(value + rule.patternBytes), capacities[target] - rule.replacementBytes - 1);
        memmove(value + rule.replacementBytes, value + rule.patternBytes, tail);
        memcpy(value, replacement, rule.replacementBytes);
        value[rule.replacementBytes + tail] = 0;
        std::fill(std::begin(pairs[target]), std::end(pairs[target]), 0);
        pairsReady[target] = false;
    }
    return ApiCategory::Unclassified;
}

ApiCategory ClassifyApi(const char* module, const char* name)
{
    // Synchronize discovery without entering traced synchronization APIs.
    while (CategoryCatalogGate.test_and_set(std::memory_order_acquire)) YieldProcessor();
    auto category = CategoryCatalog.ClassifyApi(module, name);
    CategoryCatalogGate.clear(std::memory_order_release);
    return category;
}
}

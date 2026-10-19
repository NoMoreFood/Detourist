#pragma once
#include <sqlite3.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace Detourist
{
constexpr int SqliteProgressInterval = 4096;

inline int SelectCatalogArchitecture(sqlite3* database, uint32_t pointerSize, bool writable = false)
{
    if (pointerSize != 4 && pointerSize != 8) return SQLITE_MISUSE;
    if (pointerSize == 8) return SQLITE_OK;

    // Scoped views select stored records without deriving or copying catalog data.
    sqlite3_stmt* statement = nullptr;
    auto result = sqlite3_prepare_v2(database,
        "SELECT sql FROM sqlite_schema WHERE type='view' OR (? AND type='trigger' AND "
        "tbl_name IN (SELECT name FROM sqlite_schema WHERE type='view')) ORDER BY type DESC,name",
        -1, &statement, nullptr);
    if (result != SQLITE_OK) return result;
    sqlite3_bind_int(statement, 1, writable);
    std::vector<std::string> definitions;
    while ((result = sqlite3_step(statement)) == SQLITE_ROW)
        definitions.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)));
    sqlite3_finalize(statement);
    if (result != SQLITE_DONE) return result;

    // Writable connections retain the catalog's edit and constraint behavior for their selected architecture.
    constexpr std::string_view createPrefix = "CREATE ";
    constexpr std::string_view architectureMarker = "/*architecture*/8";
    for (auto sql : definitions)
    {
        sql.insert(createPrefix.size(), "TEMP ");
        for (auto position = sql.find(architectureMarker); position != std::string::npos;
            position = sql.find(architectureMarker, position + 1))
            sql.replace(position, architectureMarker.size(), "4");
        if (auto configured = sqlite3_exec(database, sql.c_str(), nullptr, nullptr, nullptr); configured != SQLITE_OK)
            return configured;
    }
    return SQLITE_OK;
}
}

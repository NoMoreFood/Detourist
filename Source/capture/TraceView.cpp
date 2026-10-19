#include "TraceStore.h"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstring>
#include <map>
#include <string_view>

namespace Detourist
{
// Lowercases ASCII so API and text patterns compare without locale rules.
std::string Lower(std::string_view text)
{
    std::string result(text);
    for (auto& character : result)
        if (character >= 'A' && character <= 'Z') character = static_cast<char>(character + 32);
    return result;
}

// Substring match unless the pattern is exact or uses '*' to span any run of characters.
bool PatternMatch(std::string_view pattern, std::string_view text, bool exact)
{
    if (pattern.empty()) return true;
    if (exact) return pattern == text;
    if (pattern.find('*') == std::string_view::npos) return text.find(pattern) != std::string_view::npos;
    size_t position = 0, cursor = 0, star = std::string_view::npos, mark = 0;
    while (cursor < text.size())
    {
        if (position < pattern.size() && pattern[position] == '*') { star = position++; mark = cursor; }
        else if (position < pattern.size() && pattern[position] == text[cursor]) { ++position; ++cursor; }
        else if (star != std::string_view::npos) { position = star + 1; cursor = ++mark; }
        else return false;
    }
    while (position < pattern.size() && pattern[position] == '*') ++position;
    return position == pattern.size();
}

std::vector<std::string> SplitAlternatives(const std::string& text)
{
    std::vector<std::string> parts(1);
    for (char character : text)
    {
        if (character == '|') parts.emplace_back();
        else parts.back() += character;
    }
    return parts;
}

uint64_t FilterNumber(std::string_view text, const std::string& key)
{
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) { text.remove_prefix(2); base = 16; }
    uint64_t value = 0;
    auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
        throw std::runtime_error("Filter term '" + key + "' expects a number.");
    return value;
}

bool ContainsFolded(const uint8_t* bytes, size_t size, const std::string& needle)
{
    if (needle.empty() || needle.size() > size) return false;
    auto fold = [](uint8_t value) { return value >= 'A' && value <= 'Z' ? static_cast<uint8_t>(value + 32) : value; };
    auto first = static_cast<uint8_t>(needle[0]);
    auto upper = first >= 'a' && first <= 'z' ? static_cast<uint8_t>(first - 32) : first;

    // Search each spelling of the first byte with the runtime's vectorized memory scan.
    for (auto leading : {first, upper})
    {
        auto cursor = bytes;
        auto remaining = size - needle.size() + 1;
        while (remaining)
        {
            auto start = static_cast<const uint8_t*>(memchr(cursor, leading, remaining));
            if (!start) break;
            size_t offset = 1;
            while (offset < needle.size() && fold(start[offset]) == static_cast<uint8_t>(needle[offset])) ++offset;
            if (offset == needle.size()) return true;
            auto skipped = static_cast<size_t>(start - cursor) + 1;
            cursor += skipped;
            remaining -= skipped;
        }
        if (first == upper) break;
    }
    return false;
}

void TraceView::MatchApi(sqlite3_context* context, int, sqlite3_value** values)
{
    // Runtime definitions are scoped to their target; catalog definitions are shared by every target.
    auto view = static_cast<TraceView*>(sqlite3_user_data(context));
    auto slot = static_cast<size_t>(sqlite3_value_int(values[0]));
    if (slot > view->marks_.size()) return sqlite3_result_error(context, "Invalid trace filter.", -1);
    const auto& filter = slot ? view->marks_[slot - 1] : view->filter_;
    auto api = static_cast<uint32_t>(sqlite3_value_int64(values[2]));
    auto found = filter.apis.find((static_cast<uint64_t>(sqlite3_value_int64(values[1])) << 32) | api);
    if (found == filter.apis.end()) found = filter.apis.find(api);
    sqlite3_result_int(context, found == filter.apis.end() ? filter.unknownApi : found->second);
}

void TraceView::MatchText(sqlite3_context* context, int, sqlite3_value** values)
{
    auto view = static_cast<TraceView*>(sqlite3_user_data(context));
    auto index = static_cast<size_t>(sqlite3_value_int(values[2]));
    if (index >= view->textPatterns_.size()) return sqlite3_result_error(context, "Invalid trace filter.", -1);
    const auto& pattern = view->textPatterns_[index];
    bool found = false;
    for (int column = 0; column < 2 && !found; ++column)
    {
        auto bytes = static_cast<const uint8_t*>(sqlite3_value_blob(values[column]));
        auto size = static_cast<size_t>(sqlite3_value_bytes(values[column]));
        found = ContainsFolded(bytes, size, pattern.first) || ContainsFolded(bytes, size, pattern.second);
    }
    sqlite3_result_int(context, found);
}

void TraceView::MatchArgument(sqlite3_context* context, int, sqlite3_value** values)
{
    auto bytes = static_cast<const uint8_t*>(sqlite3_value_blob(values[0]));
    auto count = static_cast<size_t>(sqlite3_value_bytes(values[0])) / sizeof(uint64_t);
    auto expected = static_cast<uint64_t>(sqlite3_value_int64(values[1]));
    bool found = false;
    for (size_t index = 0; index < count && !found; ++index)
    {
        uint64_t argument;
        memcpy(&argument, bytes + index * sizeof(argument), sizeof(argument));
        found = argument == expected;
    }
    sqlite3_result_int(context, found);
}

void TraceView::MatchModule(sqlite3_context* context, int, sqlite3_value** values)
{
    auto view = static_cast<TraceView*>(sqlite3_user_data(context));
    auto index = static_cast<size_t>(sqlite3_value_int(values[3]));
    if (index >= view->ranges_.size()) return sqlite3_result_error(context, "Invalid trace filter.", -1);
    const auto& ranges = view->ranges_[index];
    sqlite3_result_int(context, CallerModule(ranges, sqlite3_value_int64(values[0]),
        static_cast<uint64_t>(sqlite3_value_int64(values[1])),
        static_cast<uint64_t>(sqlite3_value_int64(values[2]))) != nullptr);
}

// Bounds each read transaction to one operation so an idle or frozen view never pins the write-ahead log.
struct ReadTransaction
{
    sqlite3* database = nullptr;
    explicit ReadTransaction(sqlite3* raw) : database(sqlite3_get_autocommit(raw) ? raw : nullptr)
    {
        if (database) SqlCheck(sqlite3_exec(database, "BEGIN", nullptr, nullptr, nullptr), database);
    }
    ~ReadTransaction()
    {
        if (database && !sqlite3_get_autocommit(database))
            sqlite3_exec(database, "COMMIT", nullptr, nullptr, nullptr);
    }
};

const TraceView::PendingCall* TraceView::FindPending(int64_t row) const
{
    auto found = std::ranges::lower_bound(pending_, row, {}, &PendingCall::row);
    return found != pending_.end() && found->row == row ? &*found : nullptr;
}

void TraceView::SnapshotMatch(sqlite3_context* context, int, sqlite3_value** values)
{
    auto view = static_cast<TraceView*>(sqlite3_user_data(context));
    auto call = view->FindPending(sqlite3_value_int64(values[0]));
    sqlite3_result_int(context, call ? call->matched : sqlite3_value_int(values[1]) != 0);
}

void TraceView::SnapshotEnded(sqlite3_context* context, int, sqlite3_value** values)
{
    auto view = static_cast<TraceView*>(sqlite3_user_data(context));
    auto call = view->FindPending(sqlite3_value_int64(values[0]));
    if (call && call->duration < 0) sqlite3_result_null(context);
    else sqlite3_result_value(context, values[1]);
}

void TraceView::SnapshotFlags(sqlite3_context* context, int, sqlite3_value** values)
{
    auto view = static_cast<TraceView*>(sqlite3_user_data(context));
    if (auto call = view->FindPending(sqlite3_value_int64(values[0])))
        sqlite3_result_int64(context, call->flags);
    else sqlite3_result_value(context, values[1]);
}

// Orders calls from longest to shortest, earliest first among equals.
bool Longer(const std::pair<int64_t, int64_t>& first, const std::pair<int64_t, int64_t>& second)
{
    return first.first != second.first ? first.first > second.first : first.second < second.second;
}

TraceView::TraceView(const std::wstring& path, const ViewQuery& query) : database_(OpenTrace(path, page_))
{
    try
    {
        // Internal filter callbacks may only run in statements issued by this view.
        constexpr int functionFlags = SQLITE_UTF8 | SQLITE_DIRECTONLY;
        SqlCheck(sqlite3_create_function(database_, "api_match", 3, functionFlags, this, MatchApi, nullptr, nullptr),
            database_);
        SqlCheck(sqlite3_create_function(database_, "has_text", 3, functionFlags, this, MatchText, nullptr, nullptr),
            database_);
        SqlCheck(sqlite3_create_function(database_, "has_argument", 2, functionFlags, this, MatchArgument, nullptr,
            nullptr), database_);
        SqlCheck(sqlite3_create_function(database_, "in_module", 4, functionFlags, this, MatchModule, nullptr, nullptr),
            database_);
        SqlCheck(sqlite3_create_function(database_, "snapshot_match", 2, functionFlags, this, SnapshotMatch, nullptr,
            nullptr), database_);
        SqlCheck(sqlite3_create_function(database_, "snapshot_ended", 2, functionFlags, this, SnapshotEnded, nullptr,
            nullptr), database_);
        SqlCheck(sqlite3_create_function(database_, "snapshot_flags", 2, functionFlags, this, SnapshotFlags, nullptr,
            nullptr), database_);

        // Capture the initial bound and unfinished calls in a short transaction so indexing never holds the WAL.
        ReadTransaction transaction(database_);
        LoadModules();
        order_ = query.order;
        thread_ = query.thread;
        filter_ = Compile(query, 0);
        viewPatterns_ = textPatterns_.size();
        viewRanges_ = ranges_.size();

        LoadApis();
        {
            Statement bound(database_, "SELECT max(rowid) FROM calls");
            if (bound.Next()) bound_ = sqlite3_column_int64(bound.value, 0);
        }
        {
            Statement version(database_, "PRAGMA data_version");
            if (version.Next()) dataVersion_ = sqlite3_column_int64(version.value, 0);
        }
        Snapshot();
    }
    catch (...)
    {
        sqlite3_close(database_);
        throw;
    }
}

TraceView::~TraceView()
{
    sqlite3_close(database_);
}

bool TraceView::Before(const Key& first, const Key& second) const
{
    return order_ == ViewOrder::Oldest ? first < second : second < first;
}

TraceView::Key TraceView::ColumnKey(sqlite3_stmt* statement, int first)
{
    return {sqlite3_column_int64(statement, first), sqlite3_column_int64(statement, first + 1),
        static_cast<uint64_t>(sqlite3_column_int64(statement, first + 2))};
}

void TraceView::BindKey(sqlite3_stmt* statement, int first, const Key& key) const
{
    sqlite3_bind_int64(statement, first, std::get<0>(key));
    sqlite3_bind_int64(statement, first + 1, std::get<1>(key));
    sqlite3_bind_int64(statement, first + 2, static_cast<int64_t>(std::get<2>(key)));
}

// Images outside the Windows directory that do not belong to the capture runtime.
bool ApplicationModule(const std::string& path)
{
    if (path.empty()) return false;
    static const std::string windows = []
    {
        wchar_t directory[MAX_PATH];
        auto length = GetWindowsDirectoryW(directory, MAX_PATH);
        return Lower(Utf8(std::wstring(directory, length))) + "\\";
    }();
    auto normalized = Lower(path);
    auto name = FileName(normalized);
    bool runtime = name == "detouristagent.dll" || name == "detouristprofiler.dll" ||
        name == "detouristinstructions.dll" || name == "detouristsqlite.dll" ||
        name == "detouristspy32.dll" || name == "detouristspy64.dll" ||
        name == "dynamorio.dll" || name == "drmgr.dll" || name == "drwrap.dll";
    return !runtime && !normalized.starts_with(windows) && normalized.find(":\\windows\\") != 1;
}

TraceView::Filter TraceView::Compile(const ViewQuery& query, size_t slot)
{
    Filter filter;
    filter.category = query.category;
    filter.returnDependent = query.failuresOnly;
    if (query.target) filter.indexed += " AND c.target=" + std::to_string(query.target);
    if (query.thread) filter.indexed += " AND c.tid=" + std::to_string(query.thread);
    std::string residual;
    if (query.failuresOnly) filter.indexed += " AND (c.flags & " + std::to_string(Failed) + ") != 0";

    // Spaces separate terms; quotes keep spaces inside one term.
    std::vector<std::string> terms(1);
    bool quoted = false;
    for (char character : query.filter)
    {
        if (character == '"') quoted = !quoted;
        else if (!quoted && (character == ' ' || character == '\t'))
        {
            if (!terms.back().empty()) terms.emplace_back();
        }
        else terms.back() += character;
    }
    if (quoted) throw std::runtime_error("Filter has an unmatched quote.");
    static constexpr std::string_view keys[] = {"tid", "pid", "id", "result", "error", "depth", "caller", "text",
        "arg", "duration", "adjusted", "module", "name", "value", "from", "after", "before", "under", "parent"};
    for (auto term : terms)
    {
        if (term.empty()) continue;
        bool negated = term.size() > 1 && term[0] == '-';
        if (negated) term.erase(0, 1);
        auto split = term.find_first_of(":<>");
        auto key = split == std::string::npos ? std::string{} : Lower(term.substr(0, split));
        bool keyed = std::find(std::begin(keys), std::end(keys), key) != std::end(keys) &&
            term.compare(split, 2, "::") != 0;
        auto value = keyed ? term.substr(split + 1) : term;
        if (!keyed || key == "module" || key == "name")
        {
            // API terms are evaluated once per definition instead of once per recorded call.
            ApiTerm api{negated, {}};
            for (const auto& alternative : SplitAlternatives(value))
            {
                auto separator = keyed ? std::string::npos : alternative.find('!');
                ApiPattern pattern{key == "module" ? Lower(alternative) : separator == std::string::npos ?
                    std::string{} : Lower(alternative.substr(0, separator)), key == "module" ? std::string{} :
                    Lower(alternative.substr(separator == std::string::npos ? 0 : separator + 1)), false};
                if (pattern.name.starts_with('='))
                {
                    pattern.exact = true;
                    pattern.name.erase(0, 1);
                }
                if (pattern.module.empty() && pattern.name.empty()) throw std::runtime_error("Filter term is empty.");
                api.patterns.push_back(std::move(pattern));
            }
            filter.apiTerms.push_back(std::move(api));
            continue;
        }
        if (key == "text" || key == "duration" || key == "adjusted" ||
            key == "result" || key == "error" || key == "value")
            filter.returnDependent = true;
        char operation = term[split];
        bool ranged = key == "duration" || key == "adjusted" || key == "depth";
        if (operation == ':' && ranged && !value.empty() && (value[0] == '<' || value[0] == '>'))
        {
            operation = value[0];
            value.erase(0, 1);
        }
        if (value.empty()) throw std::runtime_error("Filter term '" + key + "' needs a value.");
        if (operation != ':' && !ranged) throw std::runtime_error("Filter term '" + key + "' uses ':'.");
        std::string clause;
        if (key == "text")
        {
            // Captured strings are searched as UTF-8 or ANSI bytes and as UTF-16 code units.
            auto narrow = Lower(value);
            std::string wide;
            for (wchar_t character : Wide(value))
            {
                wide += static_cast<char>(character & 0xFF);
                wide += static_cast<char>(character >> 8);
            }
            clause = "has_text(c.input,c.output," + std::to_string(textPatterns_.size()) + ")";
            textPatterns_.emplace_back(std::move(narrow), Lower(wide));
        }
        else if (key == "duration" || key == "adjusted")
        {
            // Durations accept us, ms or s and compare against returned calls only.
            double amount = 0;
            auto parsed = std::from_chars(value.data(), value.data() + value.size(), amount);
            std::string_view unit(parsed.ptr, value.data() + value.size() - parsed.ptr);
            double scale = unit.empty() || unit == "us" ? 1 : unit == "ms" ? 1000 : unit == "s" ? 1000000 : 0;
            auto ticks = amount * scale * static_cast<double>(page_.frequency) / 1000000;
            if (parsed.ec != std::errc{} || operation == ':' || !scale || amount < 0 ||
                !std::isfinite(ticks) || ticks >= static_cast<double>(INT64_MAX))
                throw std::runtime_error("Filter term '" + key + "' uses >N or <N with us, ms or s.");
            clause = std::string(key == "adjusted" ? "c.adjusted_duration IS NOT NULL AND c.adjusted_duration" :
                "c.ended IS NOT NULL AND c.ended-c.started") +
                std::string(1, operation) +
                std::to_string(static_cast<int64_t>(ticks));
        }
        else if (key == "after" || key == "before")
        {
            // Times count from the start of the capture in seconds, or in ms or us when suffixed.
            double amount = 0;
            auto parsed = std::from_chars(value.data(), value.data() + value.size(), amount);
            std::string_view unit(parsed.ptr, value.data() + value.size() - parsed.ptr);
            double scale = unit.empty() || unit == "s" ? 1 : unit == "ms" ? 0.001 : unit == "us" ? 0.000001 : 0;
            auto ticks = amount * scale * static_cast<double>(page_.frequency);
            ticks = key == "after" ? std::floor(ticks) : std::ceil(ticks);
            if (parsed.ec != std::errc{} || !scale || amount < 0 || !std::isfinite(ticks) ||
                ticks >= static_cast<double>(INT64_MAX) ||
                page_.startClock > INT64_MAX - static_cast<int64_t>(ticks))
                throw std::runtime_error("Filter term '" + key + "' expects seconds since the capture started.");
            clause = (key == "after" ? "c.started>=" : "c.started<=") +
                std::to_string(page_.startClock + static_cast<int64_t>(ticks));
            if (!negated)
            {
                filter.indexed += " AND " + clause;
                continue;
            }
        }
        else if (key == "under" || key == "parent")
        {
            // A call's thread and time span bound the calls nested inside it.
            auto dot = value.find('.');
            auto call = FilterNumber(std::string_view(value).substr(dot == std::string::npos ? 0 : dot + 1), key);
            auto owner = dot == std::string::npos ? query.target :
                static_cast<int64_t>(FilterNumber(std::string_view(value).substr(0, dot), key));
            Statement anchors(database_, "SELECT c.target,c.tid,c.started,c.ended,c.depth FROM targets t "
                "JOIN calls c ON c.target=t.id AND c.id=?1 WHERE ?2=0 OR t.id=?2");
            anchors.Bind(call, owner);
            std::vector<std::pair<std::string, std::string>> spans;
            while (anchors.Next())
            {
                auto identity = std::to_string(static_cast<int64_t>(call));
                auto target = std::to_string(sqlite3_column_int64(anchors.value, 0));
                auto span = "c.started>=" + std::to_string(sqlite3_column_int64(anchors.value, 2));

                // Read a running anchor's end in each query snapshot so later siblings stay outside its span.
                if (sqlite3_column_type(anchors.value, 3) != SQLITE_NULL)
                    span += " AND c.started<=" + std::to_string(sqlite3_column_int64(anchors.value, 3));
                else
                {
                    filter.returnDependent = true;
                    span += " AND c.started<=COALESCE((SELECT snapshot_ended(rowid,ended) FROM calls WHERE target=" +
                        target + " AND id=" + identity + "),9223372036854775807)";
                }
                auto thread = "+c.target=" + target +
                    " AND +c.tid=" + std::to_string(sqlite3_column_int64(anchors.value, 1));
                spans.emplace_back(std::move(span), thread + (key == "parent" ? " AND c.parent=" + identity :
                    " AND (c.depth>" + std::to_string(sqlite3_column_int(anchors.value, 4)) + " OR c.id=" + identity +
                    ")"));
            }
            if (spans.size() == 1 && !negated)
            {
                filter.indexed += " AND " + spans[0].first;
                clause = spans[0].second;
            }
            else for (const auto& [span, nested] : spans)
                clause += (clause.empty() ? "(" : " OR (") + span + " AND " + nested + ")";
            if (clause.empty()) clause = "0";
        }
        else if (key == "from")
        {
            // Callers are matched against the address ranges of the images recorded so far.
            moduleFilter_ = true;
            auto alternatives = SplitAlternatives(Lower(value));
            std::vector<ModuleRow> ranges;
            for (const auto& module : page_.modules)
            {
                auto path = Lower(module.path);
                bool matched = false;
                for (const auto& alternative : alternatives)
                    matched = matched || (alternative == "app" ? ApplicationModule(path) :
                        PatternMatch(alternative, FileName(path), false));
                if (matched) ranges.push_back({module.target, module.base, module.size, {},
                    module.firstEpoch, module.lastEpoch});
            }
            clause = "in_module(c.target,c.caller,c.module_epoch," + std::to_string(ranges_.size()) + ")";
            ranges_.push_back(std::move(ranges));
        }
        else if (key == "caller")
        {
            auto dash = value.find('-');
            auto first = FilterNumber(std::string_view(value).substr(0, dash), key);
            auto last = dash == std::string::npos ? first : FilterNumber(std::string_view(value).substr(dash + 1), key);
            clause = "c.caller BETWEEN " + std::to_string(static_cast<int64_t>(first)) + " AND " +
                std::to_string(static_cast<int64_t>(last));
        }
        else if (key == "depth" && operation != ':')
            clause = "c.depth" + std::string(1, operation) + std::to_string(FilterNumber(value, key));
        else
        {
            // Each remaining key accepts alternatives separated by '|'.
            auto alternatives = SplitAlternatives(value);
            if (key == "tid" && !negated && alternatives.size() == 1 && !query.thread && !slot)
            {
                // A thread owned by one process is read through the per-thread time index.
                auto thread = FilterNumber(alternatives[0], key);
                Statement owners(database_, "SELECT target FROM threads WHERE tid=?1 AND (?2=0 OR target=?2)");
                owners.Bind(thread, query.target);
                std::vector<int64_t> targets;
                while (owners.Next())
                    targets.push_back(sqlite3_column_int64(owners.value, 0));
                if (targets.size() == 1 && thread <= MAXDWORD)
                {
                    filter.indexed += " AND c.target=" + std::to_string(targets[0]) + " AND c.tid=" +
                        std::to_string(thread);
                    thread_ = static_cast<uint32_t>(thread);
                    continue;
                }
            }
            bool expression = key == "result" || key == "arg" || key == "value";
            for (const auto& alternative : alternatives)
            {
                auto number = FilterNumber(alternative, key);
                auto literal = std::to_string(static_cast<int64_t>(number));
                auto result = number <= UINT32_MAX ? "(c.result & 4294967295)=" + literal : "c.result=" + literal;
                if (!clause.empty()) clause += expression ? " OR " : ",";
                if (key == "result") clause += result;
                else if (key == "arg") clause += "has_argument(c.arguments," + literal + ")";
                else if (key == "value") clause += "has_argument(c.arguments," + literal + ") OR " + result;
                else clause += literal;
            }
            if (key == "pid")
            {
                // Process identifiers resolve to targets once; the unary plus keeps the time-ordered index.
                Statement processes(database_, ("SELECT id FROM targets WHERE pid IN (" + clause + ")").c_str());
                clause = "0";
                while (processes.Next())
                    clause += "," + std::to_string(sqlite3_column_int64(processes.value, 0));
                clause = "+c.target IN (" + clause + ")";
            }
            else if (!expression) clause = "+c." + key + " IN (" + clause + ")";
        }
        residual += std::string(negated ? " AND NOT (" : " AND (") + clause + ")";
    }
    if (!filter.apiTerms.empty() || filter.category >= 0)
        residual += " AND api_match(" + std::to_string(slot) + ",c.target,c.api)";
    if (!residual.empty()) filter.residual = residual.substr(5);
    filter.where = filter.indexed + (filter.residual.empty() ? "" : " AND (" + filter.residual + ")");
    return filter;
}

void TraceView::LoadApis()
{
    std::vector<Filter*> filters;
    if (!filter_.apiTerms.empty() || filter_.category >= 0) filters.push_back(&filter_);
    for (auto& mark : marks_)
        if (!mark.apiTerms.empty() || mark.category >= 0) filters.push_back(&mark);
    if (filters.empty()) return;
    Statement count(database_, "SELECT count(*) FROM apis");
    if (!count.Next() || sqlite3_column_int64(count.value, 0) == apiCount_) return;
    apiCount_ = sqlite3_column_int64(count.value, 0);
    auto matches = [](const Filter& filter, const std::string& module, const std::string& name, int category)
    {
        if (filter.category >= 0 && category != filter.category) return false;
        for (const auto& term : filter.apiTerms)
        {
            bool any = false;
            for (const auto& pattern : term.patterns)
                any = any || (PatternMatch(pattern.module, module, false) &&
                    PatternMatch(pattern.name, name, pattern.exact));
            if (any == term.negated) return false;
        }
        return true;
    };
    for (auto filter : filters) filter->apis.clear();
    Statement apis(database_, "SELECT target,id,module,name,category FROM apis");
    while (apis.Next())
    {
        auto key = (static_cast<uint64_t>(sqlite3_column_int64(apis.value, 0)) << 32) |
            static_cast<uint32_t>(sqlite3_column_int64(apis.value, 1));
        auto module = Lower(ColumnUtf8(apis.value, 2));
        auto name = Lower(ColumnUtf8(apis.value, 3));
        auto category = sqlite3_column_int(apis.value, 4);
        for (auto filter : filters) filter->apis[key] = matches(*filter, module, name, category);
    }
    for (auto filter : filters)
        filter->unknownApi = matches(*filter, {}, "unknown api", static_cast<int>(ApiCategory::Unclassified));
}

void TraceView::LoadModules()
{
    // Images load throughout a capture; a filter compiled against an earlier list is rebuilt by its owner.
    Statement count(database_, "SELECT count(*) FROM modules");
    if (!count.Next() || sqlite3_column_int64(count.value, 0) == moduleCount_) return;
    if (moduleCount_ >= 0 && moduleFilter_) stale_ = true;
    moduleCount_ = sqlite3_column_int64(count.value, 0);
    page_.modules = ReadModules(database_);
}

void TraceView::Mark(const std::vector<std::string>& filters)
{
    // Marks tag listed calls that match further filters without changing which calls are listed.
    ReadTransaction transaction(database_);
    ++revision_;
    if (filters.size() > MarkLimit) throw std::runtime_error("Filter marks exceed the supported count.");
    marks_.clear();
    markSql_ = "0";
    textPatterns_.resize(viewPatterns_);
    ranges_.resize(viewRanges_);
    std::vector<Filter> marks;
    std::string sql;
    for (const auto& text : filters)
    {
        // An empty filter keeps its position among the marks and tags nothing.
        ViewQuery query;
        query.filter = text;
        marks.push_back(Compile(query, marks.size() + 1));
        bool blank = text.find_first_not_of(" \t") == std::string::npos;
        sql += (sql.empty() ? "(" : "|(") + (blank ? std::string("0") : "(1=1" + marks.back().where + ")<<" +
            std::to_string(marks.size() - 1)) + ")";
    }
    marks_ = std::move(marks);
    markSql_ = sql.empty() ? "0" : "(" + sql + ")";
    apiCount_ = -1;
    LoadApis();
    if (!pending_.empty())
    {
        Statement marked(database_, ("SELECT " + markSql_ + " FROM calls c WHERE c.rowid=?1").c_str());
        for (auto& call : pending_)
        {
            marked.Bind(call.row);
            if (marked.Next())
                call.marks = static_cast<uint32_t>(sqlite3_column_int(marked.value, 0));
            SqlCheck(sqlite3_reset(marked.value), database_);
        }
    }
}

std::string TraceView::SnapshotResidual() const
{
    if (!pending_.empty() && filter_.returnDependent)
        return "snapshot_match(c.rowid," + (filter_.residual.empty() ? std::string("1") : filter_.residual) + ")";
    return filter_.residual;
}

std::string TraceView::SnapshotWhere() const
{
    auto residual = SnapshotResidual();
    return filter_.indexed + (residual.empty() ? "" : " AND (" + residual + ")");
}

std::string TraceView::ScanSql(const std::string& range) const
{
    // Calls on the heartbeat surface even when filtered out, bounding the work hidden inside one step.
    std::string heartbeat = "(c.rowid & 4095)=0";
    auto residual = SnapshotResidual();
    auto matched = residual.empty() ? std::string("1") :
        "CASE WHEN " + heartbeat + " THEN (" + residual + ") ELSE 1 END";
    auto where = residual.empty() ? std::string{} : " AND ((" + residual + ") OR " + heartbeat + ")";
    if (order_ == ViewOrder::Slowest)
    {
        std::string ended = pending_.empty() ? "c.ended" : "snapshot_ended(c.rowid,c.ended)";
        return "SELECT c.rowid," + ended + "-c.started,0," + matched +
            " FROM calls c NOT INDEXED WHERE c.rowid>?2 AND c.rowid<=?1 AND " + ended + " IS NOT NULL" +
            filter_.indexed + where;
    }

    // The unary plus keeps the snapshot bound from displacing the time-ordered index.
    std::string direction = order_ == ViewOrder::Oldest ? "" : " DESC";
    return "SELECT c.started,c.target,c.id," + matched + ",c.rowid FROM calls c WHERE +c.rowid<=?1" + filter_.indexed +
        range + where + " ORDER BY c.started" + direction + ",c.target" + direction + ",c.id" + direction;
}

void TraceView::Append(const Key& key, int64_t row)
{
    // Small views keep every call's identity; larger ones thin to evenly spaced checkpoints.
    if (checkpoints_.empty() || count_ - checkpoints_.back().index >= stride_)
        checkpoints_.push_back({key, count_, row});
    ++count_;
    if (stride_ == 1 && checkpoints_.size() > ExactLimit) Thin();
}

void TraceView::Thin()
{
    std::erase_if(checkpoints_, [](const Checkpoint& checkpoint) { return checkpoint.index % Stride != 0; });
    checkpoints_.shrink_to_fit();
    stride_ = Stride;
}

bool TraceView::Advance(uint32_t budgetMilliseconds, bool extend)
{
    changedFrom_ = count_;
    if (!complete_)
    {
        ++revision_;
        return Scan(budgetMilliseconds);
    }

    // Open a short read transaction only while reconciling the view against new database commits.
    ReadTransaction transaction(database_);
    auto modules = moduleCount_;
    LoadModules();

    // An unchanged snapshot needs no pending-call reconciliation.
    {
        Statement version(database_, "PRAGMA data_version");
        if (version.Next())
        {
            auto current = sqlite3_column_int64(version.value, 0);
            if (current == dataVersion_ && (!extend || extended_) && modules == moduleCount_) return false;
            dataVersion_ = current;
        }
    }

    // Module updates invalidate visible caller labels even when no calls entered or left the list.
    bool moduleChanged = modules != moduleCount_;
    if (moduleChanged) changedFrom_ = 0;
    bool extended = Extend(extend);
    extended_ = extend;
    if (!moduleChanged && !extended && !stale_) return false;
    ++revision_;
    return true;
}

bool TraceView::Scan(uint32_t budgetMilliseconds)
{
    // Yield between slices once the budget is spent so other requests and WAL checkpoints stay unblocked.
    ReadTransaction transaction(database_);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budgetMilliseconds);
    std::string range;
    if (hasScanKey_ && order_ != ViewOrder::Slowest)
        range = order_ == ViewOrder::Oldest ? " AND (c.started,c.target,c.id)>(?2,?3,?4)" :
            " AND (c.started,c.target,c.id)<(?2,?3,?4)";
    Statement scan(database_, ScanSql(range).c_str());
    scan.Bind(bound_);
    if (order_ == ViewOrder::Slowest) sqlite3_bind_int64(scan.value, 2, scanRow_);
    else if (hasScanKey_) BindKey(scan.value, 2, scanKey_);
    for (uint32_t step = 1; scan.Next(); ++step)
    {
        ++scanned_;
        if (order_ == ViewOrder::Slowest) scanRow_ = sqlite3_column_int64(scan.value, 0);
        else
        {
            scanKey_ = ColumnKey(scan.value);
            hasScanKey_ = true;
        }
        bool matched = sqlite3_column_int(scan.value, 3) != 0;
        if (matched)
        {
            if (order_ != ViewOrder::Slowest) Append(scanKey_, sqlite3_column_int64(scan.value, 4));
            else if (slowest_.size() < SlowestLimit || sqlite3_column_int64(scan.value, 1) > slowest_.front().first)
            {
                // A bounded heap retains the longest calls, earliest first among equals, without a full sort.
                if (slowest_.size() == SlowestLimit)
                {
                    std::pop_heap(slowest_.begin(), slowest_.end(), Longer);
                    slowest_.pop_back();
                }
                slowest_.emplace_back(sqlite3_column_int64(scan.value, 1), scanRow_);
                std::push_heap(slowest_.begin(), slowest_.end(), Longer);
            }
        }
        if ((!matched || !(step & 15)) && std::chrono::steady_clock::now() >= deadline) return true;
    }
    if (order_ == ViewOrder::Slowest)
    {
        std::sort(slowest_.begin(), slowest_.end(), Longer);
        count_ = slowest_.size();
    }
    complete_ = true;
    return true;
}

void TraceView::Snapshot()
{
    // Later calls and returns are measured against the newest recorded call and every unfinished one.
    Statement edge(database_, "SELECT started,target,id FROM calls WHERE rowid<=?1 "
        "ORDER BY started DESC,target DESC,id DESC LIMIT 1");
    edge.Bind(bound_);
    hasEdge_ = edge.Next();
    if (hasEdge_) edge_ = ColumnKey(edge.value);
    pending_.clear();
    Statement pending(database_, ("SELECT c.rowid,c.started,c.target,c.id,c.ended,c.adjusted_duration,"
        "c.result,c.error,c.flags,(1=1" + filter_.where + ")," + markSql_ + " FROM calls c "
        "INDEXED BY calls_pending WHERE (c.ended IS NULL OR (c.flags & " + std::to_string(AsyncPending) +
        ")!=0) AND (c.flags & " + std::to_string(Continuation) + ")=0 AND c.rowid<=?1").c_str());
    pending.Bind(bound_);
    while (pending.Next())
    {
        auto key = ColumnKey(pending.value, 1);
        auto duration = sqlite3_column_type(pending.value, 4) == SQLITE_NULL ? -1 :
            sqlite3_column_int64(pending.value, 4) - std::get<0>(key);
        auto adjusted = sqlite3_column_type(pending.value, 5) == SQLITE_NULL ? -1 :
            sqlite3_column_int64(pending.value, 5);
        pending_.push_back({sqlite3_column_int64(pending.value, 0), key, duration, adjusted,
            sqlite3_column_int64(pending.value, 6),
            static_cast<uint32_t>(sqlite3_column_int(pending.value, 7)),
            static_cast<uint32_t>(sqlite3_column_int(pending.value, 8)),
            static_cast<uint32_t>(sqlite3_column_int(pending.value, 10)),
            sqlite3_column_int(pending.value, 9) != 0});
    }
    std::sort(pending_.begin(), pending_.end(),
        [](const PendingCall& first, const PendingCall& second) { return first.row < second.row; });
}

void TraceView::ApplyPending(CallRow& row) const
{
    auto found = FindPending(row.row);
    if (!found) return;
    row.duration = found->duration;
    row.adjustedDuration = found->adjustedDuration;
    row.result = found->result;
    row.error = found->error;
    row.flags = found->flags;
    row.marks = found->marks;
}

bool TraceView::Extend(bool includeNew)
{
    if (order_ == ViewOrder::Slowest || stale_) return false;
    LoadApis();
    int64_t bound = bound_;
    if (includeNew)
    {
        Statement latest(database_, "SELECT max(rowid) FROM calls");
        if (latest.Next()) bound = sqlite3_column_int64(latest.value, 0);
    }

    // A long gap is cheaper to index again than to merge call by call.
    constexpr int64_t MaxIncrementalExtendRows = 2000000;
    if (bound - bound_ > MaxIncrementalExtendRows)
    {
        stale_ = true;
        return true;
    }

    // Calls that return or terminate can enter or leave the view once their final state exists.
    std::vector<Change> changes;
    bool returned = false;
    auto previous = std::move(pending_);
    if (!previous.empty())
    {
        Statement check(database_, ("SELECT (c.ended IS NULL OR (c.flags & " + std::to_string(AsyncPending) +
            ")!=0) AND (c.flags & " + std::to_string(Continuation) + ")=0,"
            "(1=1" + filter_.where + ") FROM calls c WHERE c.rowid=?1").c_str());
        std::erase_if(previous, [&](const PendingCall& call)
        {
            check.Bind(call.row);
            bool finished = check.Next() && !sqlite3_column_int(check.value, 0);
            if (finished)
            {
                returned = true;
                if ((sqlite3_column_int(check.value, 1) != 0) != call.matched)
                    changes.push_back({call.key, call.row, call.matched ? -1 : 1});
            }
            SqlCheck(sqlite3_reset(check.value), database_);
            return finished;
        });
    }

    // Calls recorded after the snapshot can begin before its newest call; those shift later positions.
    if (bound > bound_ && hasEdge_)
    {
        Statement late(database_, ("SELECT c.started,c.target,c.id,c.rowid FROM calls c NOT INDEXED "
            "WHERE c.rowid>?5 AND c.rowid<=?1 AND (c.started,c.target,c.id)<=(?2,?3,?4)" + filter_.where).c_str());
        late.Bind(bound);
        BindKey(late.value, 2, edge_);
        sqlite3_bind_int64(late.value, 5, bound_);
        while (late.Next())
            changes.push_back({ColumnKey(late.value), sqlite3_column_int64(late.value, 3), 1});
    }
    if (changes.empty() && bound == bound_)
    {
        pending_ = std::move(previous);
        return returned;
    }
    std::sort(changes.begin(), changes.end(), [this](const Change& first, const Change& second)
    {
        return Before(first.key, second.key);
    });
    if (!changes.empty())
    {
        // Positions before the checkpoint preceding the earliest change keep their calls.
        auto after = std::upper_bound(checkpoints_.begin(), checkpoints_.end(), changes.front().key,
            [this](const Key& value, const Checkpoint& checkpoint) { return Before(value, checkpoint.key); });
        changedFrom_ = std::min(changedFrom_, after == checkpoints_.begin() ? 0 : (after - 1)->index);
    }
    if (stride_ == 1 && !changes.empty())
    {
        // Merge ordered changes once so delayed calls do not repeatedly move the entire view.
        std::vector<Checkpoint> merged;
        merged.reserve(checkpoints_.size() + changes.size());
        size_t current = 0, change = 0;
        while (current < checkpoints_.size() || change < changes.size())
        {
            if (change == changes.size() || (current < checkpoints_.size() &&
                Before(checkpoints_[current].key, changes[change].key)))
            {
                auto checkpoint = checkpoints_[current++];
                checkpoint.index = merged.size();
                merged.push_back(checkpoint);
                continue;
            }
            const auto& item = changes[change++];
            if (item.delta > 0) merged.push_back({item.key, merged.size(), item.row});
            else if (current < checkpoints_.size() && checkpoints_[current].key == item.key) ++current;
        }
        checkpoints_.swap(merged);
        count_ = checkpoints_.size();
        if (checkpoints_.size() > ExactLimit) Thin();
    }
    else if (stride_ > 1)
    {
        // A checkpoint's index is the number of matching calls ahead of it, so changes shift those behind them.
        int64_t net = 0;
        size_t change = 0;
        for (auto& checkpoint : checkpoints_)
        {
            while (change < changes.size() && Before(changes[change].key, checkpoint.key))
                net += changes[change++].delta;
            checkpoint.index = static_cast<uint64_t>(static_cast<int64_t>(checkpoint.index) + net);
        }
        for (; change < changes.size(); ++change) net += changes[change].delta;
        count_ = static_cast<uint64_t>(static_cast<int64_t>(count_) + net);
    }

    // Calls beyond the previous newest call append in ascending order and lead in descending order.
    if (bound > bound_)
    {
        Statement fresh(database_, ScanSql(hasEdge_ ? " AND (c.started,c.target,c.id)>(?2,?3,?4)" : "").c_str());
        fresh.Bind(bound);
        if (hasEdge_) BindKey(fresh.value, 2, edge_);
        std::vector<Checkpoint> leading;
        uint64_t added = 0;
        while (fresh.Next())
        {
            if (!sqlite3_column_int(fresh.value, 3)) continue;
            auto key = ColumnKey(fresh.value);
            if (order_ == ViewOrder::Oldest) Append(key, sqlite3_column_int64(fresh.value, 4));
            else if (added++ % stride_ == 0) leading.push_back({key, added - 1, sqlite3_column_int64(fresh.value, 4)});
        }
        if (added)
        {
            for (auto& checkpoint : checkpoints_) checkpoint.index += added;
            checkpoints_.insert(checkpoints_.begin(), leading.begin(), leading.end());
            count_ += added;
            changedFrom_ = 0;
            if (stride_ == 1 && checkpoints_.size() > ExactLimit) Thin();

            // Merge the short gap where the new run meets the previous one.
            for (size_t index = 0; stride_ > 1 && index + 2 < checkpoints_.size() && index <= leading.size();)
            {
                if (checkpoints_[index + 2].index - checkpoints_[index].index <= Stride)
                    checkpoints_.erase(checkpoints_.begin() + index + 1);
                else ++index;
            }
        }
        bound_ = bound;
        Snapshot();
    }
    else pending_ = std::move(previous);
    return true;
}

std::vector<CallRow> TraceView::Fetch(const std::vector<int64_t>& identifiers, bool includeSummary)
{
    // Reuse one row lookup and build the requested order without an intermediate table of calls.
    std::vector<CallRow> rows;
    if (identifiers.empty()) return rows;
    ReadTransaction transaction(database_);
    rows.reserve(identifiers.size());
    Statement calls(database_, (CallSelect(false, includeSummary, thread_ != 0, markSql_) +
        "WHERE c.rowid=?1").c_str());
    sqlite3_bind_int(calls.value, 11, static_cast<int>(ApiCategory::Unclassified));
    for (auto identifier : identifiers)
    {
        calls.Bind(identifier);
        if (calls.Next())
        {
            rows.push_back(ReadCall(database_, calls.value, false));
            ApplyPending(rows.back());
            ResolveCaller(page_.modules, rows.back());
        }
        SqlCheck(sqlite3_reset(calls.value), database_);
    }
    return rows;
}

std::vector<CallRow> TraceView::Rows(uint64_t index, uint32_t limit, bool includeSummary)
{
    if (index >= count_ || !limit) return {};
    limit = static_cast<uint32_t>(std::min<uint64_t>(limit, count_ - index));
    if (order_ == ViewOrder::Slowest || stride_ == 1)
    {
        std::vector<int64_t> identifiers;
        identifiers.reserve(limit);
        for (uint64_t position = index; position < index + limit; ++position)
            identifiers.push_back(order_ == ViewOrder::Slowest ? slowest_[static_cast<size_t>(position)].second :
                checkpoints_[static_cast<size_t>(position)].row);
        return Fetch(identifiers, includeSummary);
    }

    // Seek to the nearest checkpoint at or before the index, then skip the remainder of its gap.
    ReadTransaction transaction(database_);
    auto next = std::upper_bound(checkpoints_.begin(), checkpoints_.end(), index,
        [](uint64_t value, const Checkpoint& checkpoint) { return value < checkpoint.index; });
    bool seek = next != checkpoints_.begin();
    std::string direction = order_ == ViewOrder::Oldest ? "" : " DESC";
    auto sql = CallSelect(false, includeSummary, thread_ != 0, markSql_) + "WHERE +c.rowid<=?1" + SnapshotWhere();
    if (seek) sql += order_ == ViewOrder::Oldest ? " AND (c.started,c.target,c.id)>=(?2,?3,?4)" :
        " AND (c.started,c.target,c.id)<=(?2,?3,?4)";
    sql += " ORDER BY c.started" + direction + ",c.target" + direction + ",c.id" + direction + " LIMIT ?8 OFFSET ?9";
    Statement calls(database_, sql.c_str());
    calls.Bind(bound_);
    if (seek) BindKey(calls.value, 2, (next - 1)->key);
    sqlite3_bind_int64(calls.value, 8, limit);
    sqlite3_bind_int64(calls.value, 9, static_cast<int64_t>(index - (seek ? (next - 1)->index : 0)));
    sqlite3_bind_int(calls.value, 11, static_cast<int>(ApiCategory::Unclassified));
    std::vector<CallRow> rows;
    rows.reserve(limit);
    while (calls.Next()) rows.push_back(ReadCall(database_, calls.value, false));
    for (auto& row : rows)
    {
        ApplyPending(row);
        ResolveCaller(page_.modules, row);
    }
    return rows;
}

uint64_t TraceView::Rank(const Key& key)
{
    // Counts the listed calls ahead of a position, starting from the nearest checkpoint before it.
    if (stride_ == 1)
        return std::lower_bound(checkpoints_.begin(), checkpoints_.end(), key,
            [this](const Checkpoint& checkpoint, const Key& value) { return Before(checkpoint.key, value); }) -
            checkpoints_.begin();
    ReadTransaction transaction(database_);
    auto next = std::upper_bound(checkpoints_.begin(), checkpoints_.end(), key,
        [this](const Key& value, const Checkpoint& checkpoint) { return Before(value, checkpoint.key); });
    bool seek = next != checkpoints_.begin();
    std::string sql = "SELECT count(*) FROM calls c WHERE +c.rowid<=?1" + SnapshotWhere();
    sql += order_ == ViewOrder::Oldest ? " AND (c.started,c.target,c.id)<(?5,?6,?7)" :
        " AND (c.started,c.target,c.id)>(?5,?6,?7)";
    if (seek) sql += order_ == ViewOrder::Oldest ? " AND (c.started,c.target,c.id)>=(?2,?3,?4)" :
        " AND (c.started,c.target,c.id)<=(?2,?3,?4)";
    Statement rank(database_, sql.c_str());
    rank.Bind(bound_);
    if (seek) BindKey(rank.value, 2, (next - 1)->key);
    BindKey(rank.value, 5, key);
    if (!rank.Next()) return 0;
    return (seek ? (next - 1)->index : 0) + static_cast<uint64_t>(sqlite3_column_int64(rank.value, 0));
}

int64_t TraceView::Locate(int64_t target, uint64_t callId)
{
    ReadTransaction transaction(database_);
    Statement call(database_, ("SELECT c.started,c.rowid FROM calls c WHERE c.target=?2 AND c.id=?3 "
        "AND c.rowid<=?1" + SnapshotWhere()).c_str());
    call.Bind(bound_, target, callId);
    if (!call.Next()) return -1;
    if (order_ == ViewOrder::Slowest)
    {
        auto row = sqlite3_column_int64(call.value, 1);
        auto found = std::find_if(slowest_.begin(), slowest_.end(),
            [row](const std::pair<int64_t, int64_t>& entry) { return entry.second == row; });
        return !complete_ || found == slowest_.end() ? -1 : found - slowest_.begin();
    }
    Key key{sqlite3_column_int64(call.value, 0), target, callId};
    if (stride_ == 1)
    {
        auto rank = Rank(key);
        return rank < checkpoints_.size() && checkpoints_[static_cast<size_t>(rank)].key == key ?
            static_cast<int64_t>(rank) : -1;
    }

    // An unfinished scan has ranked only the calls ahead of its last checkpoint.
    if (!complete_ && (checkpoints_.empty() || !Before(key, checkpoints_.back().key))) return -1;
    return static_cast<int64_t>(Rank(key));
}

int64_t TraceView::LocateTime(int64_t clock)
{
    // The first listed call at or after a moment in ascending order, or at or before it in descending order.
    if (!count_ || order_ == ViewOrder::Slowest) return -1;
    auto rank = Rank(order_ == ViewOrder::Oldest ? Key{clock, 0, 0} :
        Key{clock, INT64_MAX, static_cast<uint64_t>(INT64_MAX)});
    return static_cast<int64_t>(std::min(rank, count_ - 1));
}

TraceView::Match TraceView::Seek(int64_t target, uint64_t callId, bool forward)
{
    // Steps to the listed call after or before a given call, which need not be listed itself; the ends wrap.
    if (!complete_ || !count_) return {};
    ReadTransaction transaction(database_);
    uint64_t index = forward ? 0 : count_ - 1;
    Statement call(database_, "SELECT started,rowid,ended-started FROM calls WHERE target=?1 AND id=?2 AND rowid<=?3");
    call.Bind(target, callId, bound_);
    if (callId && call.Next())
    {
        uint64_t rank = 0;
        bool listed = false;
        if (order_ == ViewOrder::Slowest)
        {
            std::pair entry{sqlite3_column_int64(call.value, 2), sqlite3_column_int64(call.value, 1)};
            auto position = std::lower_bound(slowest_.begin(), slowest_.end(), entry, Longer);
            rank = position - slowest_.begin();
            listed = position != slowest_.end() && *position == entry;
        }
        else
        {
            rank = Rank({sqlite3_column_int64(call.value, 0), target, callId});
            auto rows = Rows(rank, 1, false);
            listed = !rows.empty() && rows[0].target == target && rows[0].id == callId;
        }
        index = forward ? (rank + listed) % count_ : (rank + count_ - 1) % count_;
    }
    auto rows = Rows(index, 1, false);
    if (rows.empty()) return {};
    return {static_cast<int64_t>(index), rows[0].target, rows[0].id};
}

bool TraceView::Summarize(uint32_t budgetMilliseconds, bool restart)
{
    // Totals accumulate over bounded row ranges so a long pass shares the connection with other requests.
    ReadTransaction transaction(database_);
    bool sparse = order_ != ViewOrder::Slowest && complete_ && stride_ == 1 &&
        count_ * 4 < static_cast<uint64_t>(bound_);
    if (restart || summaryRevision_ != revision_)
    {
        summaryRevision_ = revision_;
        totals_.clear();
        summaryRow_ = 0;
        summaryBound_ = sparse ? static_cast<int64_t>(count_) :
            order_ == ViewOrder::Slowest ? static_cast<int64_t>(slowest_.size()) : bound_;
        LoadApis();
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budgetMilliseconds);
    if (order_ == ViewOrder::Slowest || sparse)
    {
        // Sparse views and capped rankings summarize their known identities without scanning discarded calls.
        Statement call(database_, ("SELECT c.target,c.api,snapshot_flags(c.rowid,c.flags)," +
            std::string(sparse ? "snapshot_ended(c.rowid,c.ended)-c.started" : "NULL") +
            " FROM calls c WHERE c.rowid=?").c_str());
        while (summaryRow_ < summaryBound_)
        {
            auto position = static_cast<size_t>(summaryRow_);
            auto row = sparse ? checkpoints_[position].row : slowest_[position].second;
            call.Bind(row);
            if (call.Next())
            {
                auto& totals = totals_[(static_cast<uint64_t>(sqlite3_column_int64(call.value, 0)) << 32) |
                    static_cast<uint32_t>(sqlite3_column_int64(call.value, 1))];
                ++totals.calls;
                totals.failed += (sqlite3_column_int64(call.value, 2) & 1) != 0;
                if (!sparse || sqlite3_column_type(call.value, 3) != SQLITE_NULL)
                {
                    auto duration = sparse ? sqlite3_column_int64(call.value, 3) : slowest_[position].first;
                    ++totals.returned;
                    totals.total += duration;
                    totals.longest = std::max(totals.longest, duration);
                }
            }
            SqlCheck(sqlite3_reset(call.value), database_);
            ++summaryRow_;
            if ((summaryRow_ & 255) == 0 && std::chrono::steady_clock::now() >= deadline) break;
        }
        return summaryRow_ >= summaryBound_;
    }
    std::string ended = pending_.empty() ? "c.ended" : "snapshot_ended(c.rowid,c.ended)";
    std::string flags = pending_.empty() ? "c.flags" : "snapshot_flags(c.rowid,c.flags)";
    Statement range(database_, ("SELECT c.target,c.api,count(*),sum((" + flags + " & 1)!=0),count(" + ended + "),"
        "sum(" + ended + "-c.started),max(" + ended + "-c.started) FROM calls c NOT INDEXED "
        "WHERE c.rowid>?1 AND c.rowid<=?2" + SnapshotWhere() + " GROUP BY c.target,c.api").c_str());
    while (summaryRow_ < summaryBound_)
    {
        auto last = std::min(summaryBound_, summaryRow_ + 32768);
        range.Bind(summaryRow_, last);
        while (range.Next())
        {
            auto& totals = totals_[(static_cast<uint64_t>(sqlite3_column_int64(range.value, 0)) << 32) |
                static_cast<uint32_t>(sqlite3_column_int64(range.value, 1))];
            totals.calls += sqlite3_column_int64(range.value, 2);
            totals.failed += sqlite3_column_int64(range.value, 3);
            totals.returned += sqlite3_column_int64(range.value, 4);
            totals.total += sqlite3_column_int64(range.value, 5);
            totals.longest = std::max(totals.longest, sqlite3_column_int64(range.value, 6));
        }
        SqlCheck(sqlite3_reset(range.value), database_);
        summaryRow_ = last;
        if (std::chrono::steady_clock::now() >= deadline) break;
    }
    return summaryRow_ >= summaryBound_;
}

double TraceView::SummaryProgress() const
{
    return summaryBound_ ? static_cast<double>(summaryRow_) / static_cast<double>(summaryBound_) : 1;
}

std::vector<ApiSummary> TraceView::Summary()
{
    // Calls from every process and runtime definition of one API are reported together.
    ReadTransaction transaction(database_);
    std::map<std::pair<std::string, std::string>, ApiSummary> merged;
    Statement identity(database_, "SELECT COALESCE(d.module,a.module,''),COALESCE(d.name,a.name,'Unknown API'),"
        "COALESCE(d.category,a.category,?3) FROM (SELECT 1) LEFT JOIN apis a ON a.target=0 AND a.id=?2 "
        "LEFT JOIN apis d ON d.target=?1 AND d.id=?2");
    sqlite3_bind_int(identity.value, 3, static_cast<int>(ApiCategory::Unclassified));
    for (const auto& [key, totals] : totals_)
    {
        identity.Bind(static_cast<int64_t>(key >> 32), static_cast<int64_t>(key & 0xFFFFFFFF));
        if (identity.Next())
        {
            auto module = ColumnUtf8(identity.value, 0);
            auto name = ColumnUtf8(identity.value, 1);
            auto& entry = merged[{module, name}];
            entry.module = std::move(module);
            entry.name = std::move(name);
            entry.category = static_cast<ApiCategory>(sqlite3_column_int(identity.value, 2));
            entry.calls += totals.calls;
            entry.failed += totals.failed;
            entry.returned += totals.returned;
            entry.total += totals.total;
            entry.longest = std::max(entry.longest, totals.longest);
        }
        SqlCheck(sqlite3_reset(identity.value), database_);
    }
    std::vector<ApiSummary> result;
    for (auto& [key, entry] : merged) result.push_back(std::move(entry));
    return result;
}

TraceView::Density TraceView::Timeline(uint32_t buckets, uint32_t budgetMilliseconds)
{
    // The strip spans the whole capture so positions stay comparable from one filter to the next.
    Density density;
    if (order_ == ViewOrder::Slowest || !buckets || checkpoints_.empty()) return density;
    ReadTransaction transaction(database_);
    {
        Statement first(database_, "SELECT min(started) FROM calls");
        if (!first.Next() || sqlite3_column_type(first.value, 0) == SQLITE_NULL)
            return density;
        density.begin = sqlite3_column_int64(first.value, 0);
    }
    density.end = std::max({hasEdge_ ? std::get<0>(edge_) : density.begin, std::get<0>(checkpoints_.front().key),
        std::get<0>(checkpoints_.back().key)}) + 1;
    density.calls.assign(buckets, 0);
    auto scale = static_cast<double>(buckets) / static_cast<double>(density.end - density.begin);
    auto slot = [&](int64_t time)
    {
        return std::min<size_t>(buckets - 1, static_cast<size_t>(std::max(0.0,
            static_cast<double>(time - density.begin) * scale)));
    };
    for (size_t index = 0; index < checkpoints_.size(); ++index)
    {
        // A thinned view spreads the calls between neighboring checkpoints over the time separating them.
        auto time = std::get<0>(checkpoints_[index].key);
        bool last = index + 1 == checkpoints_.size();
        auto next = stride_ == 1 ? time : !last ? std::get<0>(checkpoints_[index + 1].key) :
            order_ == ViewOrder::Oldest ? density.end : density.begin;
        auto calls = static_cast<double>((last ? count_ : checkpoints_[index + 1].index) - checkpoints_[index].index);
        auto low = slot(std::min(time, next)), high = slot(std::max(time, next));
        for (auto bucket = low; bucket <= high; ++bucket)
            density.calls[bucket] += calls / static_cast<double>(high - low + 1);
    }
    if (!complete_) return density;

    // Broad views favor the failure index; selective process or thread views keep their narrower access path.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budgetMilliseconds);
    sqlite3_progress_handler(database_, SqliteProgressInterval, [](void* context) -> int
    {
        return QueryWork::Interrupt(nullptr) ||
            std::chrono::steady_clock::now() >= *static_cast<std::chrono::steady_clock::time_point*>(context);
    }, &deadline);
    {
        auto pending = pending_.empty() ? std::string{} : " AND snapshot_flags(c.rowid,NULL) IS NULL";
        auto index = count_ >= static_cast<uint64_t>(bound_) / 4 ? " INDEXED BY calls_failed" : "";
        Statement failed(database_, (std::string("SELECT c.started FROM calls c") + index +
            " WHERE (c.flags & " + std::to_string(Failed) + ") != 0 AND +c.rowid<=?1" +
            pending + SnapshotWhere() + " ORDER BY c.started").c_str());
        failed.Bind(bound_);
        density.failures.assign(buckets, 0);

        // Pending calls contribute their published flags even when their current result has changed.
        for (const auto& call : pending_)
            if (call.matched && (call.flags & Failed)) ++density.failures[slot(std::get<0>(call.key))];
        int status;
        while ((status = sqlite3_step(failed.value)) == SQLITE_ROW)
            ++density.failures[slot(sqlite3_column_int64(failed.value, 0))];
        if (status != SQLITE_DONE) density.failures.clear();
    }
    sqlite3_progress_handler(database_, SqliteProgressInterval, QueryWork::Interrupt, nullptr);
    return density;
}

TracePage TraceView::Metadata()
{
    ReadTransaction transaction(database_);
    TracePage page = page_;
    Statement session(database_, "SELECT total_calls FROM session");
    if (session.Next()) page.totalCalls = sqlite3_column_int64(session.value, 0);
    ReadTargets(database_, page);
    Statement threads(database_, "SELECT target,tid FROM threads ORDER BY tid,target");
    while (threads.Next())
        page.traceThreads.push_back({sqlite3_column_int64(threads.value, 0),
            static_cast<uint32_t>(sqlite3_column_int64(threads.value, 1))});

    // Saved traces identify skipped children by the diagnostic's recorded PID prefix.
    Statement diagnostics(database_, "SELECT target,message,message GLOB 'Child [0-9]*: *' "
        "FROM diagnostics ORDER BY timestamp,rowid");
    while (diagnostics.Next())
    {
        page.diagnostics.push_back({sqlite3_column_int64(diagnostics.value, 0), ColumnUtf8(diagnostics.value, 1)});
        if (sqlite3_column_int(diagnostics.value, 2)) ++page.skippedChildren;
    }
    return page;
}
}

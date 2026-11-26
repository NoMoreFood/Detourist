#pragma once
#include "Transport.h"
#include "SqliteCatalog.h"
#include <sqlite3.h>
#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <tuple>
#include <unordered_set>
#include <unordered_map>

namespace Detourist
{
constexpr int TraceApplicationId = 0x44545252;
constexpr int TraceSchemaVersion = 11;
// Query work carries its cancellation and deadline across every SQLite connection on its worker.
struct QueryWork
{
    std::atomic<bool> cancelled = false;
    std::chrono::steady_clock::time_point deadline;
    bool Interrupted() const { return cancelled || std::chrono::steady_clock::now() >= deadline; }
    static thread_local QueryWork* current;
    static int Interrupt(void*) { return current && current->Interrupted(); }
};

struct AsyncCompletionRow
{
    int64_t observed = 0;
    uint64_t control = 0, observer = 0, transferred = 0;
    uint32_t thread = 0, status = 0, flags = 0, ioFlags = 0;
    AsyncIoDomain domain{};
    AsyncIoSource source{};
    std::vector<AsyncIoBufferSnapshot> buffers;
};

struct ModuleRow;
struct ResolvedSymbol
{
    std::string name, source, pdb, state;
    uint64_t displacement = 0;
    uint32_t line = 0;
};
struct ResolvedFrame
{
    uint64_t address = 0, offset = 0;
    std::string module, path;
    ResolvedSymbol symbol;
};
ResolvedSymbol ResolveSymbol(const ModuleRow& module, uint64_t address);
void SetSymbolDirectories(const std::vector<std::wstring>& directories);

struct CallRow
{
    int64_t target = 0;
    int64_t row = 0;
    uint64_t id = 0;
    uint64_t parent = 0;
    uint32_t processId = 0;
    uint32_t threadId = 0;
    uint32_t depth = 0;
    Api api{};
    std::string module;
    std::string name;
    std::wstring parameters;
    std::string layout;
    uint32_t argumentCount = 0;
    uint32_t rawArgumentCount = 0;
    ApiCategory category = ApiCategory::Unclassified;
    int64_t timestamp = 0;
    int64_t duration = -1;
    int64_t adjustedDuration = -1;
    int64_t delta = 0;
    uint64_t result = 0;
    uint64_t caller = 0;
    uint64_t moduleEpoch = 0;
    uint32_t pointerSize = 8;
    std::string callerModule;
    std::string callerPath;
    uint64_t callerOffset = 0;
    ResolvedSymbol callerSymbol;
    std::vector<ResolvedFrame> stack;
    uint32_t marks = 0;
    uint32_t error = 0;
    uint32_t flags = 0;
    uint64_t arguments[MaximumArguments]{};
    std::vector<std::byte> input;
    std::vector<std::byte> output;
    AsyncCompletionRow completion;
};

struct TargetRow
{
    int64_t id;
    uint32_t processId;
    std::wstring image;
    std::wstring state;
    uint32_t installedNative = 0;
    uint32_t availableNative = 0;
    uint32_t catalogNative = 0;
    uint32_t nativeExports = 0;
    std::string unknownExports;
    uint32_t installedWin32 = 0;
    uint32_t availableWin32 = 0;
    uint32_t installedCom = 0;
    uint32_t managedState = 0;
    uint32_t managedApiCount = 0;
    uint32_t moduleRefreshError = 0;
    uint32_t instructionState = 0;
    uint32_t installedExports = 0;
    uint32_t pointerSize = 8;
};

struct ThreadRow
{
    int64_t target;
    uint32_t threadId;
};

struct TraceDiagnostic
{
    int64_t target;
    std::string message;
};

struct ModuleRow
{
    int64_t target;
    uint64_t base;
    uint64_t size;
    std::string path;
    uint64_t firstEpoch = 0, lastEpoch = UINT64_MAX;
    ModuleIdentity identity{};
};

struct ApiSummary
{
    std::string module;
    std::string name;
    ApiCategory category = ApiCategory::Unclassified;
    uint64_t calls = 0;
    uint64_t failed = 0;
    uint64_t returned = 0;
    int64_t total = 0;
    int64_t longest = 0;
};

struct Query
{
    int64_t target = 0;
    uint32_t thread = 0;
    std::string api;
    int32_t category = -1;
    bool failuresOnly = false;
    uint32_t offset = 0;
    uint32_t limit = 200;
    uint64_t callId = 0;
    bool includePayload = false;
    bool includeSummary = false;
    int64_t newestTimestamp = 0;
    int64_t newestTarget = 0;
    uint64_t newestCallId = 0;
    int64_t beforeTimestamp = 0;
    int64_t beforeTarget = 0;
    uint64_t beforeCallId = 0;
    bool includeMetadata = true;
};

struct TracePage
{
    std::vector<CallRow> calls;
    std::vector<TargetRow> targets;
    std::vector<uint32_t> threads;
    std::vector<ThreadRow> traceThreads;
    std::vector<ModuleRow> modules;
    std::vector<TraceDiagnostic> diagnostics;
    int64_t frequency = 1;
    int64_t startClock = 0;
    uint64_t startUtc = 0;
    uint64_t totalCalls = 0;
    uint32_t skippedChildren = 0;
};

class TraceStore
{
public:
    explicit TraceStore(const std::wstring& path);
    ~TraceStore();
    int64_t AddTarget(uint32_t processId, const std::wstring& image, int64_t parent, uint64_t installedMask,
        uint32_t pointerSize = sizeof(void*));
    void AddCoverage(int64_t target, uint32_t installed, uint32_t available,
        uint32_t exports, const char* unknownExports);
    void UpdateCoverage(int64_t target, const SharedHeader& header);
    void TargetState(int64_t target, const std::wstring& state, bool exited = false);
    void AddModule(int64_t target, uint64_t base, uint64_t size, const std::wstring& path,
        uint64_t epoch = 0, bool loaded = true, const ModuleIdentity& identity = {});
    void Add(int64_t target, const RecordView& record);
    void Flush();
    void Finish();
    bool HasDefinition(int64_t target, Api api) const;
    bool HasUnfinishedCalls(int64_t target);
    void Diagnostic(int64_t target, const std::wstring& message);
    uint64_t Count() const { return count_; }
    static TracePage ReadPage(const std::wstring& path, const Query& query);
    static ApiDefinition ReadApi(const std::wstring& path, uint32_t processId, Api api,
        DynamicApiMetadata& metadata);
private:
    struct CallKey
    {
        int64_t target;
        uint64_t id;
        bool operator==(const CallKey&) const = default;
    };
    struct CallHash
    {
        size_t operator()(const CallKey& key) const
        {
            return static_cast<size_t>(key.id ^ (static_cast<uint64_t>(key.target) << 48));
        }
    };
    void Execute(const char* sql);
    void Begin();
    void WriteEntry(int64_t target, const RecordView& entry, const RecordView* leaving = nullptr);
    sqlite3* database_ = nullptr;
    sqlite3* checkpointDatabase_ = nullptr;
    std::future<void> checkpoint_;
    int walFrames_ = 0, lastCheckpointFrame_ = 0;
    sqlite3_stmt* enter_ = nullptr;
    sqlite3_stmt* leave_ = nullptr;
    uint32_t pending_ = 0;
    uint64_t count_ = 0;
    size_t cachedBytes_ = 0;
    struct PendingLayout
    {
        Api api;
        uint32_t totalBytes;
        std::string bytes;
    };
    std::unordered_map<int64_t, PendingLayout> layouts_;
    using Entries = std::unordered_map<CallKey, Record, CallHash>;
    void RecycleEntry(Entries::iterator entry);
    Entries entries_;
    std::array<Entries::node_type, 32> reusableEntries_;
    size_t reusableCount_ = 0, reusableBytes_ = 0;
    std::unordered_set<uint64_t> threads_;
    std::unordered_map<uint64_t, uint32_t> argumentCounts_;
    std::unordered_map<int64_t, std::array<uint32_t, 11>> coverage_;
};
std::wstring DescribeCall(const CallRow& call, int64_t frequency);

// Statement lifetime and row readers shared by the page and view queries.
void SqlCheck(int status, sqlite3* database);

class Statement
{
public:
    Statement(sqlite3* db, const char* sql)
    {
        if (sqlite3_prepare_v2(db, sql, -1, &value, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(db));
    }
    ~Statement() { sqlite3_finalize(value); }

    template<class... Args> void Bind(const Args&... args)
    {
        auto* database = sqlite3_db_handle(value);
        int index = 0;
        (SqlCheck(BindValue(++index, args), database), ...);
    }

    template<class... Args> void Exec(const Args&... args)
    {
        if constexpr (sizeof...(Args) > 0) Bind(args...);
        SqlCheck(sqlite3_step(value), sqlite3_db_handle(value));
    }

    bool Next()
    {
        auto status = sqlite3_step(value);
        if (status != SQLITE_ROW && status != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(sqlite3_db_handle(value)));
        return status == SQLITE_ROW;
    }
    sqlite3_stmt* value = nullptr;

private:
    int BindValue(int index, sqlite3_int64 number) { return sqlite3_bind_int64(value, index, number); }
    int BindValue(int index, const char* text) { return sqlite3_bind_text(value, index, text, -1, SQLITE_TRANSIENT); }
    int BindValue(int index, const std::string& text) { return BindValue(index, text.c_str()); }
};
std::wstring ColumnText(sqlite3_stmt* statement, int column);
std::string ColumnUtf8(sqlite3_stmt* statement, int column);
sqlite3* OpenTrace(const std::wstring& path, TracePage& page);
void ReadTargets(sqlite3* raw, TracePage& page);
std::vector<ModuleRow> ReadModules(sqlite3* raw);
std::string_view FileName(std::string_view path);
void ResolveCaller(const std::vector<ModuleRow>& modules, CallRow& call);
bool ApplicationModule(const std::string& path);
const ModuleRow* CallerModule(const std::vector<ModuleRow>& modules, int64_t target,
    uint64_t caller, uint64_t epoch);
std::string CallSelect(bool payload, bool summary, bool threadDelta, const std::string& marks = "0");
CallRow ReadCall(sqlite3* raw, sqlite3_stmt* calls, bool payload);

enum class ViewOrder { Oldest, Newest, Slowest };

struct ViewQuery
{
    int64_t target = 0;
    uint32_t thread = 0;
    std::string filter;
    int32_t category = -1;
    bool failuresOnly = false;
    ViewOrder order = ViewOrder::Newest;
};

// A filtered, ordered window over a capture that addresses calls by display index without loading them.
class TraceView
{
public:
    TraceView(const std::wstring& path, const ViewQuery& query);
    ~TraceView();
    TraceView(const TraceView&) = delete;
    TraceView& operator=(const TraceView&) = delete;
    struct Match
    {
        int64_t index = -1;
        int64_t target = 0;
        uint64_t id = 0;
    };
    struct Density
    {
        int64_t begin = 0;
        int64_t end = 0;
        std::vector<double> calls;
        std::vector<double> failures;
    };
    bool Advance(uint32_t budgetMilliseconds, bool extend = true);
    std::vector<CallRow> Rows(uint64_t index, uint32_t limit, bool includeSummary);
    int64_t Locate(int64_t target, uint64_t callId);
    int64_t LocateTime(int64_t clock);
    Match Seek(int64_t target, uint64_t callId, bool forward);
    void Mark(const std::vector<std::string>& filters);
    bool Summarize(uint32_t budgetMilliseconds, bool restart);
    double SummaryProgress() const;
    std::vector<ApiSummary> Summary();
    Density Timeline(uint32_t buckets, uint32_t budgetMilliseconds);
    TracePage Metadata();
    const TracePage& Trace() const { return page_; }
    uint64_t Count() const { return count_; }
    uint64_t Scanned() const { return scanned_; }
    uint64_t ChangedFrom() const { return changedFrom_; }
    bool Complete() const { return complete_; }
    bool Stale() const { return stale_; }
    uint64_t Revision() const { return revision_; }
    static constexpr uint32_t Stride = 256;
    static constexpr size_t ExactLimit = 65536;
    static constexpr size_t SlowestLimit = 100000;
    static constexpr size_t MarkLimit = 8;
private:
    using Key = std::tuple<int64_t, int64_t, uint64_t>;
    struct Checkpoint
    {
        Key key;
        uint64_t index;
        int64_t row;
    };
    struct Change
    {
        Key key;
        int64_t row;
        int delta;
    };
    struct PendingCall
    {
        int64_t row = 0;
        Key key{};
        int64_t duration = -1;
        int64_t adjustedDuration = -1;
        int64_t result = 0;
        uint32_t error = 0;
        uint32_t flags = 0;
        uint32_t marks = 0;
        bool matched = false;
    };
    struct ApiPattern
    {
        std::string module;
        std::string name;
        bool exact;
    };
    struct ApiTerm
    {
        bool negated;
        std::vector<ApiPattern> patterns;
    };
    struct Filter
    {
        std::vector<ApiTerm> apiTerms;
        std::unordered_map<uint64_t, bool> apis;
        int32_t category = -1;
        bool unknownApi = true;
        bool returnDependent = false;
        std::string indexed;
        std::string residual;
        std::string where;
    };
    struct Totals
    {
        uint64_t calls = 0;
        uint64_t failed = 0;
        uint64_t returned = 0;
        int64_t total = 0;
        int64_t longest = 0;
    };
    static void MatchApi(sqlite3_context* context, int count, sqlite3_value** values);
    static void MatchText(sqlite3_context* context, int count, sqlite3_value** values);
    static void MatchArgument(sqlite3_context* context, int count, sqlite3_value** values);
    static void MatchModule(sqlite3_context* context, int count, sqlite3_value** values);
    static void SnapshotMatch(sqlite3_context* context, int count, sqlite3_value** values);
    static void SnapshotEnded(sqlite3_context* context, int count, sqlite3_value** values);
    static void SnapshotFlags(sqlite3_context* context, int count, sqlite3_value** values);
    Filter Compile(const ViewQuery& query, size_t slot);
    void LoadApis();
    void LoadModules();
    uint64_t Rank(const Key& key);
    bool Before(const Key& first, const Key& second) const;
    std::string SnapshotResidual() const;
    std::string SnapshotWhere() const;
    std::string ScanSql(const std::string& range) const;
    static Key ColumnKey(sqlite3_stmt* statement, int first = 0);
    void BindKey(sqlite3_stmt* statement, int first, const Key& key) const;
    void Append(const Key& key, int64_t row);
    void Thin();
    bool Scan(uint32_t budgetMilliseconds);
    bool Extend(bool includeNew);
    void Snapshot();
    const PendingCall* FindPending(int64_t row) const;
    void ApplyPending(CallRow& row) const;
    std::vector<CallRow> Fetch(const std::vector<int64_t>& identifiers, bool includeSummary);
    TracePage page_;
    sqlite3* database_ = nullptr;
    ViewOrder order_ = ViewOrder::Newest;
    uint32_t thread_ = 0;
    Filter filter_;
    std::vector<Filter> marks_;
    std::string markSql_ = "0";
    std::vector<std::pair<std::string, std::string>> textPatterns_;
    size_t viewPatterns_ = 0;
    std::vector<std::vector<ModuleRow>> ranges_;
    size_t viewRanges_ = 0;
    int64_t apiCount_ = -1;
    int64_t moduleCount_ = -1;
    int64_t dataVersion_ = -1;
    bool moduleFilter_ = false;
    std::unordered_map<uint64_t, Totals> totals_;
    int64_t summaryRow_ = 0;
    int64_t summaryBound_ = 0;
    uint64_t summaryRevision_ = 0;
    std::vector<Checkpoint> checkpoints_;
    std::vector<PendingCall> pending_;
    std::vector<std::pair<int64_t, int64_t>> slowest_;
    Key edge_{};
    bool hasEdge_ = false;
    Key scanKey_{};
    bool hasScanKey_ = false;
    int64_t scanRow_ = 0;
    int64_t bound_ = 0;
    uint32_t stride_ = 1;
    uint64_t count_ = 0;
    uint64_t scanned_ = 0;
    uint64_t changedFrom_ = 0;
    bool complete_ = false;
    bool stale_ = false;
    bool extended_ = true;
    uint64_t revision_ = 1;
};
}

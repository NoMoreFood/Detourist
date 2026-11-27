#include "TraceStore.h"
#include "RpcCapture.h"
#include "ApiCatalog.h"
#include <algorithm>
#include <charconv>
#include <cstring>
#include <format>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string_view>

namespace Detourist
{
constexpr int TraceWriteBusyTimeoutMs = 1000;
constexpr int TraceReadBusyTimeoutMs = 250;
constexpr int CheckpointIntervalPages = 512;
constexpr int ForegroundCheckpointPages = 4096;
constexpr size_t MaxCachedEntryBytes = 8 * 1024 * 1024;
constexpr size_t MaxCachedEntries = 4096;
constexpr size_t MaxPendingTransactionOps = 16384;
constexpr size_t MaxReusableEntryBytes = 256 * 1024;
constexpr uint32_t MaxPageQueryLimit = 1000;
constexpr uint32_t AsyncLeaveClearMask = Failed | AsyncPending | AsyncCompleted | AsyncCancelled;
constexpr uint32_t AsyncLeaveKeepMask = Failed | AsyncCompleted | AsyncCancelled;

thread_local QueryWork* QueryWork::current = nullptr;

void SqlCheck(int status, sqlite3* database)
{
    if (status != SQLITE_OK && status != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(database));
}

static uint64_t HashSnapshotBytes(std::string_view bytes)
{
    uint64_t hash = Fnv1aOffsetBasis64;
    size_t index = 0;
    for (; index + sizeof(uint64_t) <= bytes.size(); index += sizeof(uint64_t))
    {
        uint64_t word = 0;
        memcpy(&word, bytes.data() + index, sizeof(word));
        hash = (hash ^ word) * Fnv1aPrime64;
    }
    for (; index < bytes.size(); ++index)
        hash = (hash ^ static_cast<uint8_t>(bytes[index])) * Fnv1aPrime64;
    return hash;
}

bool TraceStore::NextBuffer(std::string_view& remaining, SnapshotBuffer& buffer)
{
    Value header;
    if (remaining.size() < sizeof(header)) return false;
    memcpy(&header, remaining.data(), sizeof(header));
    if (header.capturedBytes > remaining.size() - sizeof(header)) return false;
    auto data = remaining.substr(sizeof(header), header.capturedBytes);
    buffer = {remaining.substr(0, sizeof(header)), data, HashSnapshotBytes(data)};
    remaining.remove_prefix(sizeof(header) + header.capturedBytes);
    return true;
}

template<class T> static void AppendNumber(std::string& text, T value)
{
    char digits[24];
    text.append(digits, std::to_chars(digits, std::end(digits), value).ptr);
}

static void AppendRange(std::string& text, sqlite3_int64 start, size_t length)
{
    text += '[';
    AppendNumber(text, start);
    text += ',';
    AppendNumber(text, length);
    text += "],";
}

void TraceStore::PackReturn(sqlite3_context* context, int, sqlite3_value** values)
{
    // Keep the original SQLite value for absent, malformed or incompressible snapshots.
    sqlite3_result_value(context, values[1]);
    const auto outputSize = sqlite3_value_bytes(values[1]);
    const auto inputSize = sqlite3_value_bytes(values[0]);
    if (!outputSize || !inputSize) return;
    const auto* before = static_cast<const char*>(sqlite3_value_blob(values[0]));
    const auto* after = static_cast<const char*>(sqlite3_value_blob(values[1]));
    if (!before || !after) { sqlite3_result_error_nomem(context); return; }
    const std::string_view input(before, inputSize), output(after, outputSize);
    if (input == output)
    {
        sqlite3_result_zeroblob(context, 0);
        return;
    }

    try
    {
        auto* store = static_cast<TraceStore*>(sqlite3_user_data(context));
        std::vector<SnapshotBuffer> localBuffers;
        std::vector<std::pair<int, int>> localRanges;
        std::string localPacked;
        auto& buffers = store ? store->packBuffers_ : localBuffers;
        auto& ranges = store ? store->packRanges_ : localRanges;
        auto& packed = store ? store->packedReturn_ : localPacked;
        buffers.clear();
        ranges.clear();

        // Hash and size narrow candidate matches before comparing full byte slices.
        SnapshotBuffer buffer{};
        for (auto remaining = input; !remaining.empty();)
        {
            if (!NextBuffer(remaining, buffer)) return;
            buffers.push_back(buffer);
        }
        std::ranges::sort(buffers, {}, &SnapshotBuffer::Key);

        // Positive offsets refer to entry bytes. Keep literal return ranges in their original order.
        auto literal = after;
        int literalBytes = 0;
        auto appendLiteral = [&](const char* end)
        {
            if (literal == end) return;
            auto length = static_cast<int>(end - literal);
            ranges.emplace_back(-1 - static_cast<int>(literal - after), length);
            literalBytes += length;
        };
        for (auto remaining = output; !remaining.empty();)
        {
            if (!NextBuffer(remaining, buffer)) return;
            auto found = std::ranges::lower_bound(buffers, buffer.Key(), {}, &SnapshotBuffer::Key);
            if (found == buffers.end() || found->hash != buffer.hash || found->data != buffer.data)
            {
                if (found == buffers.begin()) continue;
                --found;
                if (found->hash != buffer.hash || found->data != buffer.data) continue;
            }
            const auto headerBytes = found->header == buffer.header ? sizeof(Value) : 0;
            auto length = static_cast<int>(headerBytes + buffer.data.size());
            if (!length) continue;
            appendLiteral(buffer.data.data() - headerBytes);
            auto offset = 1 + static_cast<int>(found->data.data() - headerBytes - before);
            if (!ranges.empty() && ranges.back().first > 0 && ranges.back().first + ranges.back().second == offset)
                ranges.back().second += length;
            else ranges.emplace_back(offset, length);
            literal = buffer.data.data() + buffer.data.size();
        }
        if (ranges.empty()) return;
        appendLiteral(after + outputSize);

        // A NUL terminates the JSON ranges. Negative SQLite offsets address literal bytes from the end of the blob.
        packed.assign(1, '[');
        int tail = -literalBytes;
        for (auto [offset, length] : ranges)
        {
            AppendRange(packed, offset > 0 ? offset : tail, length);
            if (offset < 0) tail += length;
        }
        packed.back() = ']';
        packed += '\0';
        if (packed.size() + literalBytes >= output.size()) return;
        packed.reserve(packed.size() + literalBytes);
        for (auto [offset, length] : ranges)
            if (offset < 0) packed.append(after + (-1 - offset), length);
        sqlite3_result_blob64(context, packed.data(), packed.size(), SQLITE_TRANSIENT);
    }
    catch (const std::bad_alloc&) { sqlite3_result_error_nomem(context); }
    catch (const std::length_error&) { sqlite3_result_error_toobig(context); }
}

TraceStore::TraceStore(const std::wstring& path)
{
    PrepareApiCatalog();
    // Reserve a new filename atomically and prevent its replacement while the schema is initialized.
    Handle file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file)
    {
        if (GetLastError() == ERROR_FILE_EXISTS || GetLastError() == ERROR_ALREADY_EXISTS)
            throw std::runtime_error("Choose a new database filename for this capture.");
        Check(false, "Create capture database");
    }
    auto name = Utf8(path);
    auto result = sqlite3_open_v2(name.c_str(), &database_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, nullptr);
    if (result != SQLITE_OK)
    {
        std::string error = database_ ? sqlite3_errmsg(database_) : "Cannot open capture database.";
        sqlite3_close(database_);
        database_ = nullptr;
        throw std::runtime_error(error);
    }
    try
    {
        sqlite3_busy_timeout(database_, TraceWriteBusyTimeoutMs);
        SqlCheck(sqlite3_create_function_v2(database_, "pack_return", 2,
            SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_DIRECTONLY, this, PackReturn, nullptr, nullptr, nullptr),
            database_);

        // Grow the trace to each checkpoint's final extent before copying its pages on Windows.
        int pageBytes = 8192;
        SqlCheck(sqlite3_file_control(database_, "main", SQLITE_FCNTL_CHUNK_SIZE, &pageBytes), database_);
        auto schema = "PRAGMA page_size=" + std::to_string(pageBytes) +
            "; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-8192;"
            "PRAGMA application_id=" + std::to_string(TraceApplicationId) +
            "; PRAGMA user_version=" + std::to_string(TraceSchemaVersion) + ";"
            "CREATE TABLE session(frequency INTEGER, start_clock INTEGER, start_utc INTEGER, total_calls INTEGER);"
            "CREATE TABLE apis(target INTEGER, id INTEGER, module TEXT, name TEXT, parameters TEXT,"
            " argument_count INTEGER, category INTEGER, PRIMARY KEY(target,id)) WITHOUT ROWID;"
            "CREATE TABLE api_layouts(target INTEGER, api INTEGER, layout TEXT, PRIMARY KEY(target,api)) WITHOUT ROWID;"
            "CREATE TABLE targets(id INTEGER PRIMARY KEY, pid INTEGER, image TEXT, parent INTEGER,"
            " installed_mask INTEGER, state TEXT, pointer_size INTEGER NOT NULL);"
            "CREATE TABLE coverage(target INTEGER PRIMARY KEY, installed_native INTEGER, "
            "available_native INTEGER, catalog_native INTEGER, native_exports INTEGER, unknown_exports TEXT,"
            " installed_win32 INTEGER DEFAULT 0, available_win32 INTEGER DEFAULT 0, installed_com INTEGER DEFAULT 0,"
            " managed_state INTEGER DEFAULT 0, managed_apis INTEGER DEFAULT 0, module_error INTEGER DEFAULT 0,"
            " instruction_state INTEGER DEFAULT 0, installed_exports INTEGER DEFAULT 0);"
            "CREATE TABLE call_records(target INTEGER NOT NULL, id INTEGER NOT NULL, tid INTEGER, api INTEGER,"
            " started INTEGER,"
            " ended INTEGER, parent INTEGER, depth INTEGER, caller INTEGER, arguments BLOB, result INTEGER,"
            " error INTEGER, flags INTEGER, input BLOB, output BLOB, module_epoch INTEGER NOT NULL DEFAULT 0,"
            " adjusted_duration INTEGER, output_length INTEGER, input_parts TEXT,"
            " PRIMARY KEY(target,id));"
            "CREATE TABLE input_blocks(id INTEGER PRIMARY KEY,data BLOB NOT NULL);"
            "CREATE INDEX calls_time ON call_records(started,target,id,api);"
            "CREATE INDEX calls_process ON call_records(target,started,id,api);"
            "CREATE INDEX calls_thread ON call_records(target,tid,started,id,api);"
            "CREATE INDEX calls_failed ON call_records(started,target,id,api) WHERE (flags & " +
            std::to_string(Failed) + ") != 0;"
            "CREATE INDEX calls_pending ON call_records(target,id) WHERE (ended IS NULL OR (flags & " +
            std::to_string(AsyncPending) + ")!=0) AND (flags & " + std::to_string(Continuation) + ")=0;"
            "CREATE TABLE async_completions(target INTEGER,id INTEGER,observed INTEGER,control INTEGER,"
            " observer INTEGER,tid INTEGER,transferred INTEGER,status INTEGER,domain INTEGER,source INTEGER,"
            " flags INTEGER,io_flags INTEGER,buffers BLOB,PRIMARY KEY(target,id)) WITHOUT ROWID;"
            "CREATE TABLE threads(target INTEGER,tid INTEGER,PRIMARY KEY(target,tid)) WITHOUT ROWID;"
            "CREATE TABLE modules(target INTEGER, base INTEGER, size INTEGER, path TEXT, epoch INTEGER, loaded INTEGER,"
            " identity BLOB,"
            " PRIMARY KEY(target,base,epoch)) WITHOUT ROWID;"
            "CREATE TABLE diagnostics(target INTEGER, timestamp INTEGER, message TEXT);";
        Execute(schema.c_str());

        // Expose the original entry and return blobs to ordinary SQLite readers, including binary and empty values.
        Execute(std::format(R"sql(
            CREATE VIEW call_inputs AS
            SELECT r.rowid AS rowid,r.*,
                CASE WHEN input_parts IS NULL THEN input ELSE
                    (SELECT CAST(group_concat(CASE
                        WHEN p.atom IS NULL AND (p.value->>0)=0 THEN zeroblob(p.value->>1)
                        WHEN p.atom IS NULL AND (p.value->>0)<0 THEN substr(r.input,-(p.value->>0),p.value->>1)
                        ELSE (SELECT substr(data,1+(coalesce(p.atom,p.value->>0)-1)%{0}*{1},
                                 CASE WHEN p.atom IS NULL THEN p.value->>1 ELSE {1} END)
                              FROM input_blocks WHERE id=(coalesce(p.atom,p.value->>0)-1)/{0}) END,'' ORDER BY p.key)
                        AS BLOB)
                     FROM json_each(r.input_parts) p)
                END AS entry
            FROM call_records r;

            CREATE VIEW calls AS
            SELECT target,id,tid,api,started,ended,parent,depth,caller,arguments,result,error,flags,entry AS input,
                CASE WHEN output_length IS NULL OR length(output)=output_length THEN output
                     WHEN length(output)=0 THEN entry
                     ELSE (WITH original(data) AS MATERIALIZED (SELECT r.entry)
                           SELECT CAST(group_concat(substr(CASE WHEN (p.value->>0)>0 THEN original.data ELSE r.output
                               END,p.value->>0,p.value->>1),'' ORDER BY p.key) AS BLOB)
                           FROM original,json_each(CAST(substr(r.output,1,instr(r.output,x'00')-1) AS TEXT)) p)
                END AS output,module_epoch,adjusted_duration,rowid AS rowid
            FROM call_inputs r;

            CREATE TRIGGER calls_insert INSTEAD OF INSERT ON calls BEGIN
                INSERT INTO call_records(rowid,target,id,tid,api,started,ended,parent,depth,caller,arguments,result,
                    error,flags,input,output,module_epoch,adjusted_duration)
                VALUES(NEW.rowid,NEW.target,NEW.id,NEW.tid,NEW.api,NEW.started,NEW.ended,NEW.parent,NEW.depth,
                    NEW.caller,NEW.arguments,NEW.result,NEW.error,NEW.flags,NEW.input,NEW.output,
                    coalesce(NEW.module_epoch,0),NEW.adjusted_duration);
            END;
            CREATE TRIGGER calls_update INSTEAD OF UPDATE ON calls BEGIN
                UPDATE call_records SET rowid=NEW.rowid,target=NEW.target,id=NEW.id,tid=NEW.tid,api=NEW.api,
                    started=NEW.started,ended=NEW.ended,parent=NEW.parent,depth=NEW.depth,caller=NEW.caller,
                    arguments=NEW.arguments,result=NEW.result,error=NEW.error,flags=NEW.flags,
                    input=CASE WHEN NEW.input IS OLD.input THEN input ELSE NEW.input END,
                    input_parts=CASE WHEN NEW.input IS OLD.input THEN input_parts END,
                    output=CASE WHEN NEW.input IS OLD.input AND NEW.output IS OLD.output
                        THEN output ELSE NEW.output END,
                    output_length=CASE WHEN NEW.input IS OLD.input AND NEW.output IS OLD.output THEN output_length END,
                    module_epoch=NEW.module_epoch,adjusted_duration=NEW.adjusted_duration WHERE rowid=OLD.rowid;
            END;
            CREATE TRIGGER calls_delete INSTEAD OF DELETE ON calls BEGIN
                DELETE FROM call_records WHERE rowid=OLD.rowid;
            END;
        )sql", BlocksPerPage, InputBlockBytes).c_str());
        LARGE_INTEGER frequency;
        QueryPerformanceFrequency(&frequency);
        FILETIME utc;
        GetSystemTimePreciseAsFileTime(&utc);
        Statement session(database_, "INSERT INTO session VALUES(?,?,?,0)");
        session.Exec(frequency.QuadPart, Clock(), (uint64_t{utc.dwHighDateTime} << 32) | utc.dwLowDateTime);
        // Seed the complete API catalog in one transaction before accepting capture records.
        Execute("BEGIN IMMEDIATE");
        Statement api(database_, "INSERT INTO apis VALUES(0,?,?,?,?,?,?)");
        for (const auto& definition : ApiDefinitions)
        {
            sqlite3_bind_int(api.value, 1, static_cast<int>(definition.id));
            sqlite3_bind_text(api.value, 2, definition.module, -1, SQLITE_STATIC);
            sqlite3_bind_text(api.value, 3, definition.name, -1, SQLITE_STATIC);
            auto parameters = Utf8(definition.parameters);
            sqlite3_bind_text(api.value, 4, parameters.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(api.value, 5, definition.argumentCount);
            sqlite3_bind_int(api.value, 6, static_cast<int>(ClassifyApi(definition.module, definition.name)));
            api.Exec();
            sqlite3_reset(api.value);
        }
        Execute("COMMIT");
        SqlCheck(sqlite3_prepare_v2(database_, "INSERT INTO input_blocks(id,data) VALUES(?,?)",
            -1, &insertBlock_, nullptr), database_);
        SqlCheck(sqlite3_prepare_v2(database_, "INSERT OR IGNORE INTO apis VALUES(?,?,?,?,?,?,?)",
            -1, &insertApi_, nullptr), database_);
        SqlCheck(sqlite3_prepare_v2(database_, "INSERT OR IGNORE INTO threads VALUES(?,?)",
            -1, &insertThread_, nullptr), database_);
        SqlCheck(sqlite3_prepare_v2(database_, "UPDATE session SET total_calls=?",
            -1, &updateTotals_, nullptr), database_);
        sqlite3_rollback_hook(database_, [](void* context)
        {
            auto& store = *static_cast<TraceStore*>(context);
            for (auto& group : store.inputBlocks_)
            {
                if (!group) continue;
                for (auto& block : *group) block.id = 0;
            }
            store.blockPage_.clear();
            ++store.blockPageId_;
        }, this);
        SqlCheck(sqlite3_prepare_v2(database_, "INSERT INTO call_records(target,id,tid,api,started,parent,depth,caller,"
            "arguments,flags,input,ended,result,error,output,module_epoch,adjusted_duration,output_length,input_parts) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,coalesce(?18,?11),?12,?13,?14,"
            "CASE WHEN length(?11)>0 AND length(?15)>0 THEN pack_return(?11,?15) ELSE ?15 END,"
            "?16,?17,length(?15),?19)",
            -1, &enter_, nullptr), database_);
        auto leaveSql = std::string("UPDATE call_records SET ended=?1, result=?2, error=?3,"
            " flags=CASE WHEN (flags & ") + std::to_string(AsyncCompleted) + ")!=0 THEN (?4 & ~" +
            std::to_string(AsyncLeaveClearMask) + ")|(flags & " + std::to_string(AsyncLeaveKeepMask) +
            ") ELSE ?4 END, output=CASE WHEN (flags & " + std::to_string(AsyncCompleted) +
            ")!=0 THEN output WHEN length(?5)>0 THEN "
            "pack_return((SELECT entry FROM call_inputs WHERE rowid=call_records.rowid),?5) ELSE ?5 END,"
            " output_length=CASE WHEN (flags & " +
            std::to_string(AsyncCompleted) + ")!=0 THEN output_length ELSE length(?5) END,"
            " adjusted_duration=?8 WHERE target=?6 AND id=?7";
        SqlCheck(sqlite3_prepare_v2(database_, leaveSql.c_str(), -1, &leave_, nullptr), database_);

        // A second connection can copy committed WAL pages while the writer accepts the next batch.
        result = sqlite3_open_v2(name.c_str(), &checkpointDatabase_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX,
            nullptr);
        SqlCheck(result, checkpointDatabase_);
        SqlCheck(sqlite3_file_control(checkpointDatabase_, "main", SQLITE_FCNTL_CHUNK_SIZE, &pageBytes),
            checkpointDatabase_);
        SqlCheck(sqlite3_exec(checkpointDatabase_, "PRAGMA synchronous=NORMAL; SELECT 1 FROM sqlite_schema LIMIT 1",
            nullptr, nullptr, nullptr), checkpointDatabase_);
        sqlite3_wal_hook(database_, [](void* context, sqlite3*, const char*, int frames)
        {
            *static_cast<int*>(context) = frames;
            return SQLITE_OK;
        }, &walFrames_);
    }
    catch (...)
    {
        sqlite3_close(checkpointDatabase_);
        sqlite3_finalize(insertBlock_);
        sqlite3_finalize(insertApi_);
        sqlite3_finalize(insertThread_);
        sqlite3_finalize(updateTotals_);
        sqlite3_finalize(enter_);
        sqlite3_finalize(leave_);
        sqlite3_close(database_);
        throw;
    }
}

TraceStore::~TraceStore()
{
    if (checkpoint_.valid()) checkpoint_.wait();
    sqlite3_close(checkpointDatabase_);
    sqlite3_finalize(insertBlock_);
    sqlite3_finalize(insertApi_);
    sqlite3_finalize(insertThread_);
    sqlite3_finalize(updateTotals_);
    sqlite3_finalize(enter_);
    sqlite3_finalize(leave_);
    if (database_) sqlite3_close(database_);
}

void TraceStore::Execute(const char* sql)
{
    SqlCheck(sqlite3_exec(database_, sql, nullptr, nullptr, nullptr), database_);
}
void TraceStore::Begin()
{
    if (!pending_) Execute("BEGIN IMMEDIATE");
    ++pending_;
}
bool TraceStore::HasDefinition(int64_t target, Api api) const
{
    // Breakpoints require received metadata even when the bounded argument-count cache is full.
    if (!IsDynamicApi(api) || argumentCounts_.contains((static_cast<uint64_t>(target) << 32) |
        static_cast<uint32_t>(api))) return true;
    Statement definition(database_, "SELECT 1 FROM apis WHERE target=? AND id=? LIMIT 1");
    definition.Bind(target, static_cast<uint32_t>(api));
    return definition.Next();
}

bool TraceStore::HasUnfinishedCalls(int64_t target)
{
    // Transport references also cover filtered observers; only recorded returns determine call completeness.
    Flush();
    auto sql = "SELECT 1 FROM calls WHERE target=? AND ended IS NULL AND (flags & " +
        std::to_string(Continuation) + ")=0 LIMIT 1";
    Statement statement(database_, sql.c_str());
    statement.Bind(target);
    return statement.Next();
}

static void PassiveCheckpoint(sqlite3* database)
{
    auto result = sqlite3_wal_checkpoint_v2(database, "main", SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
    if (result != SQLITE_BUSY) SqlCheck(result, database);
}

void TraceStore::Flush()
{
    // Publish unfinished calls on the same timer as completed calls, with a bounded staging budget.
    while (!entries_.empty())
    {
        auto entry = entries_.begin();
        WriteEntry(entry->first.target, entry->second);
        RecycleEntry(entry);
    }
    if (pending_)
    {
        FlushInputBlocks();
        SqlCheck(sqlite3_bind_int64(updateTotals_, 1, static_cast<sqlite3_int64>(count_)), database_);
        SqlCheck(sqlite3_step(updateTotals_), database_);
        SqlCheck(sqlite3_reset(updateTotals_), database_);
        Execute("COMMIT");
        pending_ = 0;
    }

    // Space attempts by WAL growth so a reader holding an older snapshot cannot trigger work on every commit.
    if (walFrames_ < lastCheckpointFrame_) lastCheckpointFrame_ = 0;
    if (walFrames_ - lastCheckpointFrame_ < CheckpointIntervalPages) return;
    // Let the writer catch up at 32 MiB when continuous commits prevent the WAL from restarting.
    const bool catchUp = walFrames_ >= ForegroundCheckpointPages;
    if (checkpoint_.valid())
    {
        if (!catchUp && checkpoint_.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;
        checkpoint_.get();
    }
    lastCheckpointFrame_ = walFrames_;
    if (catchUp) PassiveCheckpoint(database_);
    else checkpoint_ = std::async(std::launch::async, PassiveCheckpoint, checkpointDatabase_);
}

void TraceStore::Finish()
{
    Flush();
    if (checkpoint_.valid()) checkpoint_.get();
    PassiveCheckpoint(database_);
}

int64_t TraceStore::AddTarget(uint32_t processId, const std::wstring& image, int64_t parent, uint64_t installedMask,
    uint32_t pointerSize)
{
    Statement statement(database_, "INSERT INTO targets(pid,image,parent,installed_mask,state,pointer_size) "
        "VALUES(?,?,?,?, 'Capturing',?)");
    statement.Exec(processId, Utf8(image), parent, installedMask, static_cast<int>(pointerSize));
    return sqlite3_last_insert_rowid(database_);
}

void TraceStore::TargetState(int64_t target, const std::wstring& state, bool exited)
{
    // A signaled process has no surviving calls; retain interrupted entries without inventing returns.
    if (exited)
    {
        Flush();
        Begin();
        auto sql = "UPDATE call_records SET flags=flags|" + std::to_string(Continuation) +
            " WHERE target=? AND ended IS NULL AND (flags & " + std::to_string(Continuation) + ")=0";
        Statement interrupted(database_, sql.c_str());
        interrupted.Exec(target);
    }
    layouts_.erase(target);
    coverage_.erase(target);
    Statement statement(database_, "UPDATE targets SET state=? WHERE id=?");
    statement.Exec(Utf8(state), target);
}

void TraceStore::AddModule(int64_t target, uint64_t base, uint64_t size, const std::wstring& path,
    uint64_t epoch, bool loaded, const ModuleIdentity& identity)
{
    Begin();

    // An unload supplies the initial identity when an image disappeared before the first controller snapshot.
    if (!loaded && epoch)
    {
        Statement initial(database_, "INSERT OR REPLACE INTO modules SELECT ?1,?2,?3,?4,0,1,?6 "
            "WHERE NOT EXISTS(SELECT 1 FROM modules "
            "WHERE target=?1 AND base=?2 AND epoch>0 AND epoch<?5 AND loaded=1)");
        initial.Bind(target, base, size, Utf8(path), epoch);
        sqlite3_bind_blob(initial.value, 6, &identity, sizeof(identity), SQLITE_STATIC);
        initial.Exec();
    }
    Statement statement(database_, epoch ? "INSERT OR REPLACE INTO modules VALUES(?,?,?,?,?,?,?)" :
        "INSERT INTO modules SELECT ?1,?2,?3,?4,?5,?6,?7 "
        "WHERE NOT EXISTS(SELECT 1 FROM modules WHERE target=?1 AND base=?2)");
    statement.Bind(target, base, size, Utf8(path), epoch, loaded);
    sqlite3_bind_blob(statement.value, 7, &identity, sizeof(identity), SQLITE_STATIC);
    statement.Exec();
}

void TraceStore::AddCoverage(int64_t target, uint32_t installed, uint32_t available,
    uint32_t exports, const char* unknownExports)
{
    Statement statement(database_, "INSERT INTO coverage(target,installed_native,available_native,catalog_native,"
        "native_exports,unknown_exports) VALUES(?,?,?,?,?,?)");
    statement.Exec(target, static_cast<int>(installed), static_cast<int>(available), NativeApiEnd - NativeApiStart,
        static_cast<int>(exports), unknownExports);
}

void TraceStore::UpdateCoverage(int64_t target, const SharedHeader& header)
{
    // Publish coverage only when its counters change, avoiding idle database writes.
    const std::array<uint32_t, 11> values{header.installedWin32Count, header.availableWin32Count,
        header.installedComCount, static_cast<uint32_t>(header.managedState), header.managedApiCount,
        header.moduleRefreshError, static_cast<uint32_t>(header.instructionState), header.installedExportCount,
        header.installedNativeCount, header.availableNativeCount, header.nativeExportCount};
    if (auto found = coverage_.find(target); found != coverage_.end() && found->second == values) return;
    Statement statement(database_, "UPDATE coverage SET installed_win32=?,available_win32=?,installed_com=?,"
        "managed_state=?,managed_apis=?,module_error=?,instruction_state=?,installed_exports=?,"
        "installed_native=?,available_native=?,native_exports=? WHERE target=?");
    for (size_t index = 0; index < values.size(); ++index)
        sqlite3_bind_int(statement.value, static_cast<int>(index + 1), values[index]);
    sqlite3_bind_int64(statement.value, 12, target);
    statement.Exec();
    coverage_[target] = values;
}

void TraceStore::Diagnostic(int64_t target, const std::wstring& message)
{
    Statement statement(database_, "INSERT INTO diagnostics VALUES(?,?,?)");
    statement.Exec(target, Clock(), Utf8(message));
}

void TraceStore::Add(int64_t target, const RecordView& record)
{
    const auto& event = record.event;
    if (event.kind == EventKind::AsyncCompletion)
    {
        const auto bytes = event.arguments[6] * sizeof(AsyncIoBufferSnapshot);
        if (event.arguments[6] > MaximumArguments || bytes > record.payload.size() ||
            !IsValidAsyncIoDomain(event.arguments[4]) || !IsValidAsyncIoSource(event.arguments[5]) ||
            !(event.flags & AsyncCompleted)) throw std::runtime_error("Invalid asynchronous completion record.");

        // A completion can race the submitting API's return; materialize its entry before merging final outputs.
        if (auto found = entries_.find({target, event.callId}); found != entries_.end())
        {
            WriteEntry(target, found->second);
            RecycleEntry(found);
        }
        Begin();
        Statement completion(database_, "INSERT INTO async_completions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");
        completion.Bind(target, event.callId, event.timestamp, event.arguments[0], event.arguments[1], event.threadId,
            event.arguments[2], event.arguments[3], event.arguments[4], event.arguments[5], event.arguments[7],
            event.arguments[8]);
        sqlite3_bind_blob64(completion.value, 13, record.payload.data(), bytes, SQLITE_STATIC);
        completion.Exec();
        if (record.payload.size() > bytes) FlushInputBlocks();
        Statement update(database_, "UPDATE call_records SET flags=(flags & ?1)|?2,"
            "output=CASE WHEN length(?3)>0 THEN "
            "pack_return((SELECT entry FROM call_inputs WHERE rowid=call_records.rowid),?3) ELSE ?3 END,"
            "output_length=length(?3) WHERE target=?4 AND id=?5");
        update.Bind(~static_cast<int64_t>(Failed | AsyncPending | AsyncCancelled));
        sqlite3_bind_int(update.value, 2, event.flags & (AsyncCompleted | AsyncCancelled | Failed));
        sqlite3_bind_blob64(
            update.value, 3, record.payload.data() + bytes, record.payload.size() - bytes, SQLITE_STATIC);
        sqlite3_bind_int64(update.value, 4, target);
        sqlite3_bind_int64(update.value, 5, event.callId);
        update.Exec();
        if (sqlite3_changes(database_) != 1) throw std::runtime_error("Asynchronous submission was not found.");
        return;
    }
    if (event.kind == EventKind::ModuleLoad || event.kind == EventKind::ModuleUnload)
    {
        // Module identity is ordered by loader generation, even when delivery follows the calls it describes.
        if (!event.arguments[0] || !event.arguments[1] || !event.moduleEpoch ||
            record.payload.size() < sizeof(ModuleIdentity) || record.payload.size() % 2)
            throw std::runtime_error("Invalid module history record.");
        ModuleIdentity identity;
        memcpy(&identity, record.payload.data(), sizeof(identity));
        std::wstring path((record.payload.size() - sizeof(identity)) / 2, L'\0');
        if (!path.empty()) memcpy(path.data(), record.payload.data() + sizeof(identity), path.size() * 2);
        AddModule(target, event.arguments[0], event.arguments[1], path, event.moduleEpoch,
            event.kind == EventKind::ModuleLoad, identity);
        return;
    }
    if (event.kind == EventKind::ApiLayout)
    {
        // Save only complete descriptors; interrupted publications must never expose partial JSON to readers.
        if (!IsDynamicApi(event.api) || record.payload.size() <= sizeof(ApiLayoutFragment))
            throw std::runtime_error("Invalid API layout record.");
        ApiLayoutFragment fragment;
        memcpy(&fragment, record.payload.data(), sizeof(fragment));
        auto bytes = record.payload.size() - sizeof(fragment);
        if (!fragment.totalBytes || fragment.totalBytes > static_cast<uint32_t>(
            sqlite3_limit(database_, SQLITE_LIMIT_LENGTH, -1)) || fragment.offset > fragment.totalBytes ||
            bytes > fragment.totalBytes - fragment.offset)
            throw std::runtime_error("Invalid API layout record.");
        if (!fragment.offset) layouts_[target] = {event.api, fragment.totalBytes, {}};
        auto found = layouts_.find(target);
        if (found == layouts_.end() || found->second.api != event.api ||
            found->second.totalBytes != fragment.totalBytes || found->second.bytes.size() != fragment.offset)
            throw std::runtime_error("Invalid API layout sequence.");
        auto& layout = found->second.bytes;
        layout.append(reinterpret_cast<const char*>(record.payload.data() + sizeof(fragment)), bytes);
        if (layout.size() == fragment.totalBytes)
        {
            Begin();
            Statement statement(database_, "INSERT OR IGNORE INTO api_layouts VALUES(?,?,?)");
            statement.Bind(target, static_cast<uint32_t>(event.api));
            sqlite3_bind_text(statement.value, 3, layout.data(), static_cast<int>(layout.size()), SQLITE_TRANSIENT);
            statement.Exec();
            layouts_.erase(found);
        }
        return;
    }
    if (event.kind == EventKind::ApiMetadata)
    {
        if (!IsDynamicApi(event.api) || record.payload.size() != sizeof(DynamicApiMetadata))
            throw std::runtime_error("Invalid API metadata record.");
        DynamicApiMetadata metadata;
        memcpy(&metadata, record.payload.data(), sizeof(metadata));
        metadata.module[std::size(metadata.module) - 1] = 0;
        metadata.name[std::size(metadata.name) - 1] = 0;
        metadata.parameters[std::size(metadata.parameters) - 1] = 0;
        metadata.layout[std::size(metadata.layout) - 1] = 0;
        if (metadata.category >= ApiCategory::Count) throw std::runtime_error("Invalid API category.");
        Begin();
        auto parameters = Utf8(metadata.parameters);
        sqlite3_bind_int64(insertApi_, 1, target);
        sqlite3_bind_int(insertApi_, 2, static_cast<int>(event.api));
        sqlite3_bind_text(insertApi_, 3, metadata.module, -1, SQLITE_STATIC);
        sqlite3_bind_text(insertApi_, 4, metadata.name, -1, SQLITE_STATIC);
        sqlite3_bind_text(insertApi_, 5, parameters.c_str(), static_cast<int>(parameters.size()), SQLITE_STATIC);
        sqlite3_bind_int(insertApi_, 6, static_cast<int>(std::min(metadata.argumentCount, MaximumArguments)));
        sqlite3_bind_int(insertApi_, 7, static_cast<int>(metadata.category));
        SqlCheck(sqlite3_step(insertApi_), database_);
        SqlCheck(sqlite3_reset(insertApi_), database_);
        if (metadata.layout[0])
        {
            Statement layout(database_, "INSERT OR IGNORE INTO api_layouts VALUES(?,?,?)");
            layout.Exec(target, static_cast<uint32_t>(event.api), metadata.layout);
        }
        if (argumentCounts_.size() < 131072)
            argumentCounts_[(static_cast<uint64_t>(target) << 32) | static_cast<uint32_t>(event.api)] =
                std::min(metadata.argumentCount, MaximumArguments);
        return;
    }
    if ((event.api >= Api::Count && !IsDynamicApi(event.api)) ||
        (event.kind != EventKind::Enter && event.kind != EventKind::Leave))
        throw std::runtime_error("Unsupported capture record.");

    // Merge short calls before their scheduled commit, retaining entry visibility for held or blocked calls.
    if (event.kind == EventKind::Enter)
    {
        Entries::iterator entry;
        if (!reusableCount_)
        {
            Record captured{event, {record.payload.begin(), record.payload.end()}};
            auto inserted = entries_.emplace(CallKey{target, event.callId}, std::move(captured));
            if (!inserted.second) throw std::runtime_error("Duplicate capture call.");
            entry = inserted.first;
        }
        else
        {
            auto node = std::move(reusableEntries_[--reusableCount_]);
            reusableBytes_ -= sizeof(Record) + node.mapped().payload.capacity();
            node.key() = {target, event.callId};
            node.mapped().event = event;
            node.mapped().payload.assign(record.payload.begin(), record.payload.end());
            auto inserted = entries_.insert(std::move(node));
            if (!inserted.inserted) throw std::runtime_error("Duplicate capture call.");
            entry = inserted.position;
        }
        cachedBytes_ += sizeof(Record) + entry->second.payload.capacity();
        ++count_;
        if (cachedBytes_ >= MaxCachedEntryBytes || entries_.size() >= MaxCachedEntries) Flush();
        return;
    }
    if (auto found = entries_.find({target, event.callId}); found != entries_.end())
    {
        WriteEntry(target, found->second, &record);
        RecycleEntry(found);
    }
    else
    {
        Begin();
        if (!record.payload.empty()) FlushInputBlocks();
        auto statement = leave_;
        sqlite3_bind_int64(statement, 1, event.timestamp);
        sqlite3_bind_int64(statement, 2, event.result);
        sqlite3_bind_int(statement, 3, event.error);
        sqlite3_bind_int(statement, 4, event.flags);
        sqlite3_bind_blob64(statement, 5, record.payload.data(), record.payload.size(), SQLITE_STATIC);
        sqlite3_bind_int64(statement, 6, target);
        sqlite3_bind_int64(statement, 7, event.callId);
        if (event.flags & DurationMeasured) sqlite3_bind_int64(statement, 8, event.adjustedDuration);
        else sqlite3_bind_null(statement, 8);
        SqlCheck(sqlite3_step(statement), database_);
        SqlCheck(sqlite3_reset(statement), database_);
    }
    // Bound transaction size without forcing a commit for every queue batch.
    if (pending_ >= MaxPendingTransactionOps) Flush();
}

void TraceStore::RecycleEntry(Entries::iterator entry)
{
    // Reuse short-call storage without retaining a burst of large or deeply nested snapshots.
    const auto bytes = sizeof(Record) + entry->second.payload.capacity();
    cachedBytes_ -= bytes;
    auto node = entries_.extract(entry);
    if (reusableCount_ < reusableEntries_.size() && bytes <= MaxReusableEntryBytes - reusableBytes_)
    {
        reusableEntries_[reusableCount_++] = std::move(node);
        reusableBytes_ += bytes;
    }
}

void TraceStore::FlushInputBlocks()
{
    // Publish each immutable group before its calls become visible or a late return reads the entry.
    if (blockPage_.empty()) return;
    SqlCheck(sqlite3_bind_int64(insertBlock_, 1, blockPageId_), database_);
    SqlCheck(sqlite3_bind_blob64(insertBlock_, 2, blockPage_.data(), blockPage_.size(), SQLITE_TRANSIENT), database_);
    SqlCheck(sqlite3_step(insertBlock_), database_);
    SqlCheck(sqlite3_reset(insertBlock_), database_);
    blockPage_.clear();
    ++blockPageId_;
}

sqlite3_int64 TraceStore::InputBlockId(const std::byte* data)
{
    // A hash selects a cache slot. Only an exact byte comparison can publish a reference.
    uint64_t hash = Fnv1aOffsetBasis64, bits = 0;
    for (size_t index = 0; index < InputBlockBytes; index += sizeof(uint64_t))
    {
        uint64_t word;
        memcpy(&word, data + index, sizeof(word));
        hash = (hash ^ word) * Fnv1aPrime64;
        bits |= word;
    }
    if (!bits) return 0;

    // Small recordings touch only a fraction of the dictionary's hash slots.
    constexpr size_t slots = 8 * 1024 * 1024 / InputBlockBytes;
    constexpr auto groupSize = std::tuple_size_v<InputBlockGroup>;
    if (inputBlocks_.empty()) inputBlocks_.resize(slots / groupSize);
    const auto slot = static_cast<size_t>(hash ^ (hash >> 32)) & (slots - 1);
    auto& group = inputBlocks_[slot / groupSize];
    if (!group) group = std::make_unique<InputBlockGroup>();
    auto& block = (*group)[slot % groupSize];
    if (block.hash != hash || memcmp(data, block.bytes.data(), InputBlockBytes) != 0)
    {
        block.hash = hash;
        block.id = 0;
        memcpy(block.bytes.data(), data, InputBlockBytes);
        return -1;
    }
    if (block.id) return block.id;

    // A spare block leaves room for SQLite's row header and separates consecutive pages' ranges.
    if (blockPage_.size() == (BlocksPerPage - 1) * InputBlockBytes) FlushInputBlocks();
    auto index = static_cast<sqlite3_int64>(blockPage_.size() / InputBlockBytes);
    blockPage_.append(reinterpret_cast<const char*>(data), InputBlockBytes);
    block.id = blockPageId_ * BlocksPerPage + index + 1;
    return block.id;
}

bool TraceStore::BindInputBlocks(std::span<const std::byte> input)
{
    if (input.size() < InputBlockBytes) return false;

    // A negative range selects literal bytes. Zero fills a range, and a positive ID selects a dictionary block.
    inputParts_ = "[";
    inputLiterals_.clear();
    size_t firstLiteral = 0;
    auto appendLiteral = [&](size_t end)
    {
        if (firstLiteral == end) return;
        AppendRange(inputParts_, -1 - static_cast<sqlite3_int64>(inputLiterals_.size()), end - firstLiteral);
        inputLiterals_.append(reinterpret_cast<const char*>(input.data() + firstLiteral), end - firstLiteral);
    };
    sqlite3_int64 range = 0, next = 0;
    size_t rangeBytes = 0;
    auto appendShared = [&]
    {
        if (range > 0 && rangeBytes == InputBlockBytes)
        {
            AppendNumber(inputParts_, range);
            inputParts_ += ',';
        }
        else AppendRange(inputParts_, range, rangeBytes);
    };
    for (size_t offset = 0; offset + InputBlockBytes <= input.size(); offset += InputBlockBytes)
    {
        auto id = InputBlockId(input.data() + offset);
        if (id < 0) continue;
        if (rangeBytes && firstLiteral == offset && id == next) rangeBytes += InputBlockBytes;
        else
        {
            if (rangeBytes) appendShared();
            appendLiteral(offset);
            range = id;
            rangeBytes = InputBlockBytes;
        }
        next = id ? id + 1 : 0;
        firstLiteral = offset + InputBlockBytes;
    }
    if (!rangeBytes) return false;
    appendShared();
    appendLiteral(input.size());
    inputParts_.back() = ']';
    if (inputParts_.size() + inputLiterals_.size() >= input.size()) return false;
    SqlCheck(sqlite3_bind_blob64(enter_, 18, inputLiterals_.data(), inputLiterals_.size(), SQLITE_STATIC), database_);
    SqlCheck(sqlite3_bind_text64(enter_, 19, inputParts_.data(), inputParts_.size(), SQLITE_STATIC, SQLITE_UTF8),
        database_);
    return true;
}

void TraceStore::WriteEntry(int64_t target, const RecordView& entry, const RecordView* leaving)
{
    Begin();
    const auto& event = entry.event;
    uint64_t threadKey = (static_cast<uint64_t>(target) << 32) | event.threadId;
    if (!threads_.contains(threadKey))
    {
        sqlite3_bind_int64(insertThread_, 1, target);
        sqlite3_bind_int64(insertThread_, 2, event.threadId);
        SqlCheck(sqlite3_step(insertThread_), database_);
        SqlCheck(sqlite3_reset(insertThread_), database_);
        if (threads_.size() < 65536) threads_.insert(threadKey);
    }
    auto statement = enter_;
    sqlite3_bind_int64(statement, 1, target);
    sqlite3_bind_int64(statement, 2, event.callId);
    sqlite3_bind_int64(statement, 3, event.threadId);
    sqlite3_bind_int(statement, 4, static_cast<int>(event.api));
    sqlite3_bind_int64(statement, 5, event.timestamp);
    sqlite3_bind_int64(statement, 6, event.parentId);
    sqlite3_bind_int(statement, 7, event.depth);
    sqlite3_bind_int64(statement, 8, event.caller);

    // Omit unused argument slots and insert both snapshots without growing an existing database row.
    auto argumentCount = RawArgumentCount;
    if (event.api < Api::Count) argumentCount = Definition(event.api).argumentCount;
    else if (auto found = argumentCounts_.find((static_cast<uint64_t>(target) << 32) |
        static_cast<uint32_t>(event.api)); found != argumentCounts_.end()) argumentCount = found->second;
    if (argumentCount && event.flags & OptionalArgumentAbsent) --argumentCount;
    sqlite3_bind_blob(statement, 9, event.arguments, static_cast<int>(argumentCount * sizeof(uint64_t)), SQLITE_STATIC);
    sqlite3_bind_int(statement, 10, leaving ? leaving->event.flags : event.flags);
    sqlite3_bind_blob64(statement, 11, entry.payload.data(), entry.payload.size(), SQLITE_STATIC);
    if (!BindInputBlocks(entry.payload))
    {
        sqlite3_bind_null(statement, 18);
        sqlite3_bind_null(statement, 19);
    }
    sqlite3_bind_int64(statement, 16, static_cast<sqlite3_int64>(event.moduleEpoch));
    if (leaving)
    {
        sqlite3_bind_int64(statement, 12, leaving->event.timestamp);
        if (leaving->event.flags & DurationMeasured)
            sqlite3_bind_int64(statement, 17, leaving->event.adjustedDuration);
        else sqlite3_bind_null(statement, 17);
        sqlite3_bind_int64(statement, 13, leaving->event.result);
        sqlite3_bind_int(statement, 14, leaving->event.error);
        sqlite3_bind_blob64(statement, 15, leaving->payload.data(), leaving->payload.size(), SQLITE_STATIC);
    }
    else
    {
        sqlite3_bind_null(statement, 12);
        sqlite3_bind_null(statement, 13);
        sqlite3_bind_null(statement, 14);
        sqlite3_bind_null(statement, 15);
        sqlite3_bind_null(statement, 17);
    }
    SqlCheck(sqlite3_step(statement), database_);
    SqlCheck(sqlite3_reset(statement), database_);
}

std::wstring ColumnText(sqlite3_stmt* statement, int column)
{
    auto value = sqlite3_column_text(statement, column);
    return value ? Wide(reinterpret_cast<const char*>(value)) : L"";
}

std::string ColumnUtf8(sqlite3_stmt* statement, int column)
{
    auto value = sqlite3_column_text(statement, column);
    return value ? reinterpret_cast<const char*>(value) : "";
}

static auto OpenTraceReadOnly(const std::wstring& path)
{
    sqlite3* raw = nullptr;
    auto result = sqlite3_open_v2(Utf8(path).c_str(), &raw, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(raw, sqlite3_close);
    SqlCheck(result, raw);
    sqlite3_busy_timeout(raw, TraceReadBusyTimeoutMs);
    return database;
}

ApiDefinition TraceStore::ReadApi(const std::wstring& path, uint32_t processId, Api api,
    DynamicApiMetadata& metadata)
{
    if (!IsDynamicApi(api)) return Definition(api);
    metadata = {};
    memcpy(metadata.name, "Discovered API", sizeof("Discovered API"));
    metadata.argumentCount = RawArgumentCount;
    auto database = OpenTraceReadOnly(path);
    auto raw = database.get();

    // Runtime definitions are scoped to their target because discovered IDs can repeat in different processes.
    Statement definition(raw, "SELECT a.module,a.name,a.parameters,a.argument_count FROM apis a "
        "JOIN targets t ON t.id=a.target WHERE t.pid=? AND a.id=? LIMIT 1");
    definition.Bind(processId, static_cast<uint32_t>(api));
    auto status = sqlite3_step(definition.value);
    if (status == SQLITE_ROW)
    {
        for (int column = 0; column < 2; ++column)
        {
            auto destination = column ? metadata.name : metadata.module;
            auto capacity = column ? std::size(metadata.name) : std::size(metadata.module);
            auto text = reinterpret_cast<const char*>(sqlite3_column_text(definition.value, column));
            auto bytes = static_cast<size_t>(sqlite3_column_bytes(definition.value, column));
            if (bytes) memcpy(destination, text, std::min(bytes, capacity - 1));
            destination[std::min(bytes, capacity - 1)] = 0;
        }
        auto parameters = ColumnText(definition.value, 2);
        std::copy_n(parameters.data(), std::min(parameters.size(), std::size(metadata.parameters) - 1),
            metadata.parameters);
        metadata.argumentCount = static_cast<uint32_t>(std::clamp(sqlite3_column_int(definition.value, 3),
            0, static_cast<int>(MaximumArguments)));
    }
    else SqlCheck(status, raw);
    return {api, metadata.module, metadata.name, metadata.parameters, metadata.argumentCount};
}

// Opens a capture for reading and loads its session clock after validating identity and format.
sqlite3* OpenTrace(const std::wstring& path, TracePage& page)
{
    auto database = OpenTraceReadOnly(path);
    auto raw = database.get();

    // Trace schemas cannot invoke application callbacks while ordinary tables are being read.
    SqlCheck(sqlite3_db_config(raw, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr), raw);
    sqlite3_progress_handler(raw, SqliteProgressInterval, QueryWork::Interrupt, nullptr);
    Statement identity(raw, "PRAGMA application_id");
    if (!identity.Next() || sqlite3_column_int(identity.value, 0) != TraceApplicationId)
        throw std::runtime_error("This is not a Detourist capture database.");
    Statement version(raw, "PRAGMA user_version");
    if (!version.Next() || sqlite3_column_int(version.value, 0) != TraceSchemaVersion)
        throw std::runtime_error("This capture database uses an unsupported format. Create a new capture.");
    Statement session(raw, "SELECT frequency,start_clock,start_utc,total_calls FROM session");
    if (!session.Next()) throw std::runtime_error("Missing session metadata.");
    page.frequency = sqlite3_column_int64(session.value, 0);
    page.startClock = sqlite3_column_int64(session.value, 1);
    page.startUtc = sqlite3_column_int64(session.value, 2);
    page.totalCalls = sqlite3_column_int64(session.value, 3);
    if (page.frequency <= 0) throw std::runtime_error("Invalid trace clock.");
    return database.release();
}

void ReadTargets(sqlite3* raw, TracePage& page)
{
    Statement targets(raw, "SELECT t.id,t.pid,t.image,t.state,c.installed_native,c.available_native,"
        "c.catalog_native,c.native_exports,c.unknown_exports,c.installed_win32,c.available_win32,c.installed_com,"
        "c.managed_state,c.managed_apis,c.module_error,c.instruction_state,c.installed_exports,t.pointer_size "
        "FROM targets t LEFT JOIN coverage c ON c.target=t.id "
        "ORDER BY t.id");
    while (targets.Next())
        page.targets.push_back({sqlite3_column_int64(targets.value, 0),
            static_cast<uint32_t>(sqlite3_column_int64(targets.value, 1)), ColumnText(targets.value, 2),
            ColumnText(targets.value, 3), static_cast<uint32_t>(sqlite3_column_int(targets.value, 4)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 5)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 6)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 7)), ColumnUtf8(targets.value, 8),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 9)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 10)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 11)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 12)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 13)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 14)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 15)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 16)),
            static_cast<uint32_t>(sqlite3_column_int(targets.value, 17))});
}

// Image lifetimes are ordered by target, base address and loader generation.
std::vector<ModuleRow> ReadModules(sqlite3* raw)
{
    std::vector<ModuleRow> modules;
    Statement rows(raw, "SELECT target,base,size,path,epoch,loaded,identity FROM modules ORDER BY target,base,epoch");
    while (rows.Next())
    {
        auto target = sqlite3_column_int64(rows.value, 0);
        auto base = static_cast<uint64_t>(sqlite3_column_int64(rows.value, 1));
        auto epoch = static_cast<uint64_t>(sqlite3_column_int64(rows.value, 4));
        if (!modules.empty() && modules.back().target == target && modules.back().base == base)
            modules.back().lastEpoch = std::min(modules.back().lastEpoch, epoch);
        if (sqlite3_column_int(rows.value, 5))
        {
            modules.push_back({target, base, static_cast<uint64_t>(sqlite3_column_int64(rows.value, 2)),
                ColumnUtf8(rows.value, 3), epoch});
            if (sqlite3_column_bytes(rows.value, 6) != sizeof(ModuleIdentity))
                throw std::runtime_error("Invalid module identity data.");
            memcpy(&modules.back().identity, sqlite3_column_blob(rows.value, 6), sizeof(ModuleIdentity));
            modules.back().identity.pdbName[sizeof(ModuleIdentity::pdbName) - 1] = 0;
        }
    }
    return modules;
}

std::string_view FileName(std::string_view path)
{
    auto separator = path.find_last_of("\\/");
    return separator == std::string_view::npos ? path : path.substr(separator + 1);
}

// Address reuse is resolved against the image lifetime observed by the call's producer.
const ModuleRow* CallerModule(const std::vector<ModuleRow>& modules, int64_t target, uint64_t caller, uint64_t epoch)
{
    if (epoch == UINT64_MAX) return nullptr;
    auto next = std::upper_bound(modules.begin(), modules.end(), std::pair{target, caller},
        [](const std::pair<int64_t, uint64_t>& value, const ModuleRow& module)
        {
            return value < std::pair{module.target, module.base};
        });
    while (next != modules.begin())
    {
        const auto& module = *--next;
        if (module.target != target) break;
        if (caller - module.base < module.size && module.firstEpoch <= epoch && epoch < module.lastEpoch)
            return &module;
    }
    return nullptr;
}

void ResolveCaller(const std::vector<ModuleRow>& modules, CallRow& call)
{
    call.callerPath.clear();
    call.callerModule.clear();
    call.callerOffset = 0;
    call.callerSymbol = {.state = "module_unavailable"};
    call.stack.clear();
    if (auto module = CallerModule(modules, call.target, call.caller, call.moduleEpoch))
    {
        call.callerPath = module->path;
        call.callerModule = FileName(module->path);
        call.callerOffset = call.caller - module->base;
        call.callerSymbol = ResolveSymbol(*module, call.caller);
    }

    // Saved stack addresses use the same historical image identity as the call's immediate caller.
    for (size_t position = 0; call.input.size() - position >= sizeof(Value);)
    {
        Value value;
        memcpy(&value, call.input.data() + position, sizeof(value));
        position += sizeof(value);
        if (value.capturedBytes > call.input.size() - position) break;
        if (value.kind == ValueKind::Stack)
            for (uint32_t index = 0; index < std::min(value.capturedBytes / 8u, MaximumStack); ++index)
            {
                ResolvedFrame frame;
                memcpy(&frame.address, call.input.data() + position + index * sizeof(uint64_t), sizeof(uint64_t));
                frame.symbol.state = "module_unavailable";
                if (auto module = CallerModule(modules, call.target, frame.address, call.moduleEpoch))
                {
                    frame.module = FileName(module->path);
                    frame.path = module->path;
                    frame.offset = frame.address - module->base;
                    frame.symbol = ResolveSymbol(*module, frame.address);
                }
                call.stack.push_back(std::move(frame));
            }
        position += value.capturedBytes;
    }
}

// Columns and joins shared by page, detail and view queries; ?11 supplies the unclassified category.
std::string CallSelect(bool payload, bool summary, bool threadDelta, const std::string& marks)
{
    // Find predecessor timestamps before applying display filters, keeping deltas stable.
    std::string sql = "SELECT c.target,c.id,t.pid,c.tid,c.api,c.started,c.ended,c.result,c.error,c.flags,c.arguments,";
    sql += payload ? "c.input,c.output," : summary ? "substr(c.input,1,768),substr(c.output,1,768)," : "NULL,NULL,";
    sql += "c.started-(SELECT p.started FROM calls p WHERE p.target=c.target ";
    if (threadDelta) sql += "AND p.tid=c.tid ";
    sql += "AND (p.started,p.id)<(c.started,c.id)"
        " ORDER BY p.started DESC,p.id DESC LIMIT 1),c.caller,COALESCE(d.module,a.module,''),"
        "COALESCE(d.name,a.name,'Unknown API'),COALESCE(d.parameters,a.parameters,''),"
        "COALESCE(d.argument_count,a.argument_count,0),COALESCE(d.category,a.category,?11),"
        "c.parent,c.depth,c.rowid," + marks + ",c.module_epoch,t.pointer_size,c.adjusted_duration "
        "FROM calls c JOIN targets t ON t.id=c.target "
        "LEFT JOIN apis a ON a.target=0 AND a.id=c.api "
        "LEFT JOIN apis d ON d.target=c.target AND d.id=c.api ";
    return sql;
}

CallRow ReadCall(sqlite3* raw, sqlite3_stmt* calls, bool payload)
{
    CallRow row;
    row.target = sqlite3_column_int64(calls, 0);
    row.id = sqlite3_column_int64(calls, 1);
    row.processId = static_cast<uint32_t>(sqlite3_column_int64(calls, 2));
    row.threadId = static_cast<uint32_t>(sqlite3_column_int64(calls, 3));
    row.api = static_cast<Api>(sqlite3_column_int(calls, 4));
    row.module = ColumnUtf8(calls, 15);
    row.name = ColumnUtf8(calls, 16);
    row.parameters = ColumnText(calls, 17);
    row.argumentCount = static_cast<uint32_t>(sqlite3_column_int(calls, 18));
    row.category = static_cast<ApiCategory>(sqlite3_column_int(calls, 19));
    row.parent = sqlite3_column_int64(calls, 20);
    row.depth = static_cast<uint32_t>(sqlite3_column_int(calls, 21));
    row.row = sqlite3_column_int64(calls, 22);
    row.marks = static_cast<uint32_t>(sqlite3_column_int(calls, 23));
    row.timestamp = sqlite3_column_int64(calls, 5);
    row.duration = sqlite3_column_type(calls, 6) == SQLITE_NULL ? -1 :
        sqlite3_column_int64(calls, 6) - row.timestamp;
    row.adjustedDuration = sqlite3_column_type(calls, 26) == SQLITE_NULL ? -1 : sqlite3_column_int64(calls, 26);
    row.result = sqlite3_column_int64(calls, 7);
    row.caller = sqlite3_column_int64(calls, 14);
    row.moduleEpoch = static_cast<uint64_t>(sqlite3_column_int64(calls, 24));
    row.pointerSize = static_cast<uint32_t>(sqlite3_column_int(calls, 25));
    if (row.pointerSize != 4 && row.pointerSize != 8) throw std::runtime_error("Invalid target pointer width.");
    row.error = static_cast<uint32_t>(sqlite3_column_int(calls, 8));
    row.flags = static_cast<uint32_t>(sqlite3_column_int(calls, 9));
    auto argumentBytes = static_cast<uint32_t>(sqlite3_column_bytes(calls, 10));
    if (row.argumentCount && row.flags & OptionalArgumentAbsent) --row.argumentCount;
    if (row.argumentCount > MaximumArguments || argumentBytes < row.argumentCount * sizeof(uint64_t) ||
        argumentBytes > sizeof(row.arguments) || argumentBytes % sizeof(uint64_t))
        throw std::runtime_error("Invalid argument data.");
    if (argumentBytes) memcpy(row.arguments, sqlite3_column_blob(calls, 10), argumentBytes);
    row.rawArgumentCount = row.argumentCount;
    if ((row.flags & (RawArguments | FormattedArguments)) == (RawArguments | FormattedArguments))
    {
        auto consumed = (row.flags & FormattedArgumentMask) >> FormattedArgumentShift;
        if (consumed && consumed <= row.argumentCount) row.argumentCount = consumed;
        if (RpcDecoderFor(row.module.c_str(), row.name.c_str()) != RpcDecoder::None)
            row.rawArgumentCount = row.argumentCount;
    }
    for (int column = 11; column <= 12; ++column)
    {
        auto bytes = static_cast<const std::byte*>(sqlite3_column_blob(calls, column));
        auto size = sqlite3_column_bytes(calls, column);
        if (size > static_cast<int>((MaximumBufferLimit + sizeof(Value)) * 2 * MaximumArguments +
            MaximumStack * sizeof(uint64_t))) throw std::runtime_error("Invalid payload size.");
        auto& output = column == 11 ? row.input : row.output;
        if (size) output.assign(bytes, bytes + size);
    }
    row.delta = sqlite3_column_int64(calls, 13);
    if (payload && row.flags & AsyncCompleted)
    {
        Statement completed(raw,
            "SELECT observed,control,observer,tid,transferred,status,domain,source,flags,io_flags,buffers "
            "FROM async_completions WHERE target=? AND id=?");
        completed.Bind(row.target, row.id);
        if (!completed.Next()) throw std::runtime_error("Completion data is unavailable.");
        auto& completion = row.completion;
        completion.observed = sqlite3_column_int64(completed.value, 0);
        completion.control = sqlite3_column_int64(completed.value, 1);
        completion.observer = sqlite3_column_int64(completed.value, 2);
        completion.thread = static_cast<uint32_t>(sqlite3_column_int64(completed.value, 3));
        completion.transferred = sqlite3_column_int64(completed.value, 4);
        completion.status = static_cast<uint32_t>(sqlite3_column_int64(completed.value, 5));
        completion.domain = static_cast<AsyncIoDomain>(sqlite3_column_int(completed.value, 6));
        completion.source = static_cast<AsyncIoSource>(sqlite3_column_int(completed.value, 7));
        completion.flags = static_cast<uint32_t>(sqlite3_column_int(completed.value, 8));
        completion.ioFlags = static_cast<uint32_t>(sqlite3_column_int(completed.value, 9));
        auto size = sqlite3_column_bytes(completed.value, 10);
        if (size < 0 || size > MaximumArguments * sizeof(AsyncIoBufferSnapshot) ||
            size % sizeof(AsyncIoBufferSnapshot)) throw std::runtime_error("Invalid completion buffer data.");
        completion.buffers.resize(size / sizeof(AsyncIoBufferSnapshot));
        if (size) memcpy(completion.buffers.data(), sqlite3_column_blob(completed.value, 10), size);
    }
    if (payload && IsManagedApi(row.api))
    {
        Statement layout(raw, "SELECT layout FROM api_layouts WHERE target=? AND api=?");
        layout.Bind(row.target, static_cast<uint32_t>(row.api));
        if (layout.Next()) row.layout = ColumnUtf8(layout.value, 0);
    }
    return row;
}

TracePage TraceStore::ReadPage(const std::wstring& path, const Query& query)
{
    TracePage page;
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(OpenTrace(path, page), sqlite3_close);
    auto raw = database.get();
    if (query.includeMetadata)
    {
        ReadTargets(raw, page);
        Statement threads(raw, "SELECT tid FROM threads WHERE target=? ORDER BY tid");
        threads.Bind(query.target);
        while (threads.Next())
            page.threads.push_back(static_cast<uint32_t>(sqlite3_column_int64(threads.value, 0)));
    }
    auto sql = CallSelect(query.includePayload, query.includeSummary, query.thread != 0) + "WHERE 1=1 ";
    if (query.target) sql += "AND c.target=?1 ";
    if (query.thread) sql += "AND c.tid=?2 ";
    if (query.callId) sql += "AND c.id=?6 ";

    // A seek cursor is always older than the anchor, so one bound keeps the index seek exact.
    bool anchored = query.newestCallId && !query.beforeCallId;
    if (anchored) sql += "AND (c.started,c.target,c.id)<=(?7,?8,?9) ";
    if (query.beforeCallId) sql += "AND (c.started,c.target,c.id)<(?12,?13,?14) ";
    if (!query.api.empty()) sql += "AND COALESCE(d.name,a.name) LIKE ?3 ESCAPE '\\' ";
    if (query.category >= 0)
    {
        // Reject unrelated identities from the time index before loading call payloads or resolving metadata.
        if (query.category != static_cast<int32_t>(ApiCategory::Unclassified))
            sql += "AND c.api IN(SELECT id FROM apis WHERE category=?10) ";
        sql += "AND COALESCE(d.category,a.category,?11)=?10 ";
    }
    if (query.failuresOnly) sql += "AND (c.flags & " + std::to_string(Failed) + ") != 0 ";
    sql += "ORDER BY c.started DESC,c.target DESC,c.id DESC LIMIT ?4 OFFSET ?5";
    Statement calls(raw, sql.c_str());
    sqlite3_bind_int(calls.value, 11, static_cast<int>(ApiCategory::Unclassified));
    if (query.target) sqlite3_bind_int64(calls.value, 1, query.target);
    if (query.thread) sqlite3_bind_int64(calls.value, 2, query.thread);
    if (query.category >= 0) sqlite3_bind_int(calls.value, 10, query.category);
    if (query.callId) sqlite3_bind_int64(calls.value, 6, query.callId);
    if (anchored)
    {
        sqlite3_bind_int64(calls.value, 7, query.newestTimestamp);
        sqlite3_bind_int64(calls.value, 8, query.newestTarget);
        sqlite3_bind_int64(calls.value, 9, query.newestCallId);
    }
    if (query.beforeCallId)
    {
        sqlite3_bind_int64(calls.value, 12, query.beforeTimestamp);
        sqlite3_bind_int64(calls.value, 13, query.beforeTarget);
        sqlite3_bind_int64(calls.value, 14, query.beforeCallId);
    }
    std::string pattern = "%";
    for (char character : query.api)
    {
        if (character == '%' || character == '_' || character == '\\') pattern += '\\';
        pattern += character;
    }
    pattern += '%';
    if (!query.api.empty()) sqlite3_bind_text(calls.value, 3, pattern.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(calls.value, 4, static_cast<int>(std::min(query.limit, MaxPageQueryLimit)));
    sqlite3_bind_int64(calls.value, 5, query.offset);
    while (calls.Next())
        page.calls.push_back(ReadCall(raw, calls.value, query.includePayload));
    if (query.callId)
    {
        auto modules = ReadModules(raw);
        for (auto& call : page.calls) ResolveCaller(modules, call);
    }
    return page;
}

void DescribeValues(std::wostringstream& output, const std::vector<std::byte>& payload, uint32_t pointerSize)
{
    size_t position = 0;
    while (payload.size() - position >= sizeof(Value))
    {
        Value value;
        memcpy(&value, payload.data() + position, sizeof(value));
        if (value.kind == ValueKind::ManagedArray)
            value.originalBytes = (value.originalBytes >> 32) * static_cast<uint32_t>(value.originalBytes);
        position += sizeof(value);
        if (value.capturedBytes > payload.size() - position) { output << L"Invalid snapshot\r\n"; return; }
        if (value.kind == ValueKind::RpcCall && value.capturedBytes == sizeof(RpcCallInfo))
        {
            RpcCallInfo info{};
            memcpy(&info, payload.data() + position, sizeof(info));
            output << L"RPC procedure " << std::dec << info.procedure << L" · " <<
                (info.flags & RpcNdr64 ? L"NDR64" : L"NDR32");
            if (!(info.flags & RpcDescriptorValid)) output << L" · descriptor unavailable";
            else if (info.flags & RpcPartial) output << L" · partial decoding";
            if (info.flags & RpcOutputsDeferred) output << L" · outputs deferred";
            output << L"\r\n";
            position += value.capturedBytes;
            continue;
        }
        if (value.kind == ValueKind::RpcValue && value.capturedBytes >= sizeof(RpcValueInfo))
        {
            RpcValueInfo info{};
            memcpy(&info, payload.data() + position, sizeof(info));
            output << L"RPC node " << std::dec << info.node << L" (" << Wide(RpcTypeName(info.type)) << L") ";
            position += sizeof(info);
            value.capturedBytes -= sizeof(info);
            if (info.type == RpcValueType::Utf16) value.kind = ValueKind::Utf16;
        }
        if (value.kind == ValueKind::AutomationLink)
        {
            position += value.capturedBytes;
            continue;
        }
        auto bytes = payload.data() + position;
        auto field = [&](uint32_t offset, uint32_t width)
        {
            uint64_t result = 0;
            memcpy(&result, bytes + offset, width);
            return result;
        };
        if (value.kind == ValueKind::Stack) output << L"Stack";
        else if (value.parameter == UINT32_MAX) output << L"Return value";
        else if (value.flags & LdapData)
            output << L"Parameter " << std::dec << UnpackValueParameter(value.parameter) << L" modification " <<
                UnpackMemberOffset(value.parameter) << L" part " <<
                ((value.flags >> ValueSubIndexShift) & ValueNibbleMask) <<
                L" element " << (value.flags >> ValueDetailShift);
        else if ((value.flags & SyncAllData) && !(value.flags & LdapData))
            output << L"Parameter " << std::dec << UnpackValueParameter(value.parameter) << L" error " <<
                UnpackMemberOffset(value.parameter) << L" part " <<
                ((value.flags >> ValueSyncAllShift) & ValueNibbleMask);
        else if (value.flags & MemberData)
            output << L"Parameter " << std::dec << UnpackValueParameter(value.parameter) << L" field +0x" << std::hex <<
                (UnpackMemberOffset(value.parameter) - 1u) << std::dec;
        else if (value.kind == ValueKind::SafeArray || value.kind == ValueKind::SafeArrayData ||
            value.kind == ValueKind::PropertyVector || value.kind == ValueKind::PropertyVectorData ||
            value.flags & (AutomationElement | StringArrayElement))
        {
            output << L"Parameter " << std::dec << UnpackValueParameter(value.parameter) << L" array " <<
                UnpackMemberOffset(value.parameter);
            if (value.flags & (AutomationElement | StringArrayElement))
                output << L" element " << (value.flags >> ValueDetailShift);
        }
        else output << L"Parameter " << std::dec << value.parameter;
        output << L": " << std::dec << value.capturedBytes;
        if (value.originalBytes) output << L" of " << value.originalBytes;
        output << L" bytes";
        if (value.flags & Truncated) output << L" (truncated)";
        if (value.flags & Unreadable) output << L" (unreadable)";
        output << L"\r\n";
        if (value.kind == ValueKind::Utf16)
        {
            std::wstring text(value.capturedBytes / sizeof(wchar_t), L'\0');
            memcpy(text.data(), bytes, text.size() * sizeof(wchar_t));
            if (!(value.flags & AutomationElement) && !text.empty() && !text.back()) text.pop_back();
            output << L"  " << text << L"\r\n";
        }
        else if (value.kind == ValueKind::FindData && value.capturedBytes >= sizeof(WIN32_FIND_DATAW))
        {
            WIN32_FIND_DATAW data;
            memcpy(&data, bytes, sizeof(data));
            data.cFileName[MAX_PATH - 1] = 0;
            output << L"  File: " << data.cFileName << L"\r\n  Attributes: 0x" << std::hex << data.dwFileAttributes
                << L"\r\n  Size: " << std::dec << ((uint64_t{data.nFileSizeHigh} << 32) | data.nFileSizeLow) << L"\r\n";
        }
        else if (value.kind == ValueKind::Scalar && value.capturedBytes && value.capturedBytes <= sizeof(uint64_t))
        {
            uint64_t scalar = 0;
            memcpy(&scalar, bytes, value.capturedBytes);
            output << L"  " << std::dec << scalar << L" (0x" << std::hex << scalar << L")\r\n";
        }
        else if (value.kind == ValueKind::Stack)
        {
            for (uint32_t frame = 0; frame < value.capturedBytes / sizeof(uint64_t); ++frame)
            {
                uint64_t address;
                memcpy(&address, bytes + frame * sizeof(uint64_t), sizeof(address));
                output << L"  #" << std::dec << frame << L" 0x" << std::hex << address << L"\r\n";
            }
        }
        else if (value.kind == ValueKind::ProcessInformation && value.capturedBytes >= pointerSize * 2 + 8)
        {
            output << L"  Process: " << std::dec << field(pointerSize * 2, 4) << L"   Thread: "
                << field(pointerSize * 2 + 4, 4) << L"\r\n  Process handle: 0x" << std::hex
                << field(0, pointerSize) << L"   Thread handle: 0x" << field(pointerSize, pointerSize) << L"\r\n";
        }
        else if (value.kind == ValueKind::IoStatus && value.capturedBytes >= pointerSize * 2)
        {
            output << L"  Status: 0x" << std::hex << field(0, 4)
                << L"\r\n  Information: " << std::dec << field(pointerSize, pointerSize) << L"\r\n";
        }
        else if (value.kind == ValueKind::ObjectAttributes && value.capturedBytes >= pointerSize * 6)
        {
            output << L"  Root directory: 0x" << std::hex << field(pointerSize, pointerSize)
                << L"\r\n  Name pointer: 0x" << field(pointerSize * 2, pointerSize) << L"\r\n  Attributes: 0x"
                << field(pointerSize * 3, 4) << L"\r\n  Security descriptor: 0x"
                << field(pointerSize * 4, pointerSize) << L"\r\n";
        }
        else
        {
            for (uint32_t index = 0; index < value.capturedBytes; ++index)
            {
                if (index % 16 == 0)
                    output << L"  " << std::hex << std::setw(4) << std::setfill(L'0') << index << L"  ";
                output << std::setw(2) << std::to_integer<unsigned>(bytes[index]) << L' ';
                if (index % 16 == 15 || index + 1 == value.capturedBytes) output << L"\r\n";
            }
        }
        position += value.capturedBytes;
    }
}

std::wstring DescribeCall(const CallRow& call, int64_t frequency)
{
    std::wostringstream output;
    output << Wide(call.module) << L"!" << Wide(call.name) << L"\r\n"
        << L"Process " << call.processId << L"   Thread " << call.threadId << L"   Call " << call.id << L"\r\n"
        << L"Category: " << Wide(Category(call.category).name) << L"\r\n"
        << L"Caller: 0x" << std::hex << call.caller << std::dec << L"\r\n"
        << L"Parameters: " << call.parameters << L"\r\n\r\n";
    if (!call.callerSymbol.name.empty())
    {
        output << L"Caller symbol: " << Wide(call.callerModule) << L"!" << Wide(call.callerSymbol.name)
            << L"+0x" << std::hex << call.callerSymbol.displacement << std::dec << L"\r\n";
        if (!call.callerSymbol.source.empty())
            output << Wide(call.callerSymbol.source) << L":" << call.callerSymbol.line << L"\r\n";
    }
    if (!call.stack.empty())
    {
        output << L"\r\nCALL STACK\r\n";
        for (const auto& frame : call.stack)
        {
            output << L"0x" << std::hex << frame.address << L"  " << Wide(frame.module);
            if (!frame.symbol.name.empty())
                output << L"!" << Wide(frame.symbol.name) << L"+0x" << frame.symbol.displacement;
            else if (!frame.module.empty()) output << L"+0x" << frame.offset;
            output << std::dec << L"\r\n";
        }
    }
    for (uint32_t index = 0; index < call.argumentCount; ++index)
        output << L"  [" << std::dec << index << L"] 0x" << std::hex << call.arguments[index] << L"\r\n";
    output << L"\r\nINPUT\r\n";
    if (call.flags & StackUnavailable)
        output << L"Full stack unavailable at this runtime or loader call site.\r\n";
    DescribeValues(output, call.input, call.pointerSize);
    output << L"\r\nOUTPUT\r\n";
    if (call.flags & Continuation)
        output << L"Context transfer or termination: entry captured; return observation is unavailable.\r\n";
    else if (call.duration < 0) output << L"Call has not returned.\r\n";
    else
    {
        output << L"Return: 0x" << std::hex << call.result;
        if (static_cast<uint32_t>(call.api) < NativeApiStart || IsWin32Api(call.api))
            output << L"   LastError: " << std::dec << call.error;
        output
            << L"\r\nElapsed duration: " << std::fixed << std::setprecision(1)
            << static_cast<double>(call.duration) * 1000000 / static_cast<double>(frequency) << L" us\r\n";
        if (call.adjustedDuration >= 0)
            output << L"Adjusted duration: " << static_cast<double>(call.adjustedDuration) * 1000000 /
                static_cast<double>(frequency) << L" us\r\n";
        if (call.flags & AsyncPending) output << L"Asynchronous operation pending.\r\n";
        if (call.flags & Unwound) output << L"Call unwound without a normal return.\r\n";
        if (call.flags & Skipped) output << L"Original call skipped by debugger.\r\n";
        if (call.flags & Edited) output << L"Arguments or return values were edited at a breakpoint.\r\n";
        DescribeValues(output, call.output, call.pointerSize);
    }
    if (call.completion.observed)
    {
        const auto& completion = call.completion;
        output << L"\r\nASYNCHRONOUS COMPLETION\r\nStatus: 0x" << std::hex << completion.status << std::dec;
        if (completion.domain != AsyncIoDomain::Rpc) output << L"   Bytes transferred: " << completion.transferred;
        output << L"\r\nObserved after: " << std::fixed << std::setprecision(1)
            << static_cast<double>(completion.observed - call.timestamp) * 1000000 / static_cast<double>(frequency)
            << L" us   Thread: " << completion.thread << L"\r\n";
        if (call.flags & AsyncCancelled) output << L"Operation cancelled.\r\n";
        if (completion.flags & Truncated) output << L"Buffer descriptors exceed the capture limit.\r\n";
        if (completion.flags & Unreadable) output << L"Some submission buffer descriptors were unreadable.\r\n";
    }
    return output.str();
}
}

using System.IO;
using System.Text.Json;
using static Detourist.Desktop.SqliteNative;

namespace Detourist.Desktop;

public sealed class CatalogDatabase : IDisposable
{
    private readonly object gate = new();
    private readonly Dictionary<(string Name, string Module, string Description), ApiSignature?> functions = [];
    private readonly Dictionary<string, TypeLayout?> types = [];
    private readonly Queue<(string Name, string Module, string Description)> functionOrder = [];
    private readonly Queue<string> typeOrder = [];
    private static readonly JsonSerializerOptions json = new() { PropertyNameCaseInsensitive = true };
    private nint database, functionQuery, typeQuery, changeQuery;
    private int version;
    private long queries;
    public (int Functions, int Types, long Queries) Statistics
    {
        get { lock (gate) return (functions.Count, types.Count, queries); }
    }

    public CatalogDatabase(string? catalogPath = null, int pointerSize = 8)
    {
        var configuredPath = Environment.GetEnvironmentVariable(pointerSize == 4 ?
            "DETOURIST_API_CATALOG_X86" : "DETOURIST_API_CATALOG");
        var path = catalogPath ?? (string.IsNullOrEmpty(configuredPath) ? null : configuredPath);
        if (path is null)
        {
            var x86 = Path.Combine(AppContext.BaseDirectory, "x86", "ApiCatalog.sqlite");
            path = pointerSize == 4 && File.Exists(x86) ? x86 :
                Path.Combine(AppContext.BaseDirectory, "ApiCatalog.sqlite");
        }
        try
        {
            Check(Open(path, out database, OpenReadOnlyUri, 0));
            Check(SelectArchitecture(database, pointerSize));
            var configured = Exec(database, "PRAGMA query_only=ON; PRAGMA cache_size=-2048; PRAGMA mmap_size=268435456;",
                0, 0, out var error);
            if (error != 0) Free(error);
            Check(configured);
            Check(Prepare(database, "PRAGMA user_version", -1, out var version, 0));
            try
            {
                if (!Row(version) || Integer(version, 0) != Protocol.ApiCatalogSchemaVersion)
                    throw new IOException("Unsupported API catalog schema.");
            }
            finally { FinalizeStatement(version); }
            Check(Prepare(database, "SELECT f.module,f.result,f.signature,f.description,f.variant " +
                "FROM functions f WHERE f.name=?1 UNION ALL " +
                "SELECT a.alias,f.result,f.signature,f.description,f.variant FROM functions f " +
                "JOIN module_aliases a ON a.module=f.module WHERE f.name=?1 AND f.variant='' AND NOT EXISTS " +
                "(SELECT 1 FROM functions e WHERE e.module=a.alias AND e.name=f.name AND e.variant='') " +
                "ORDER BY 1,5", -1, out functionQuery, 0));
            Check(Prepare(database, "SELECT layout FROM types WHERE name=?", -1, out typeQuery, 0));
            Check(Prepare(database, "PRAGMA data_version", -1, out changeQuery, 0));
            Refresh();
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public bool Refresh()
    {
        lock (gate)
        {
            int current;
            try
            {
                if (!Row(changeQuery)) throw new IOException("Cannot inspect API catalog changes.");
                current = Integer(changeQuery, 0);
            }
            finally { Reset(changeQuery); }
            if (current == version) return false;

            // Invalidate cached misses and layouts only at an explicit view or capture boundary.
            functions.Clear();
            types.Clear();
            functionOrder.Clear();
            typeOrder.Clear();
            version = current;
            return true;
        }
    }

    public ApiSignature? Function(string name, string module, string description = "")
    {
        lock (gate)
        {
            var key = (name, module, description);
            if (functions.TryGetValue(key, out var cached)) return cached;

            // Fetch only the selected signature; module identity disambiguates functions with matching names.
            ApiSignature? result = null;
            (string Result, string Declarations, string Origin)? shared = null;
            var agreed = true;
            try
            {
                Check(BindText(functionQuery, 1, name, -1, -1));
                ++queries;
                while (Row(functionQuery))
                {
                    var origin = Text(functionQuery, 0);
                    if (!ApiMetadata.MatchesModule(origin, module, name)) continue;
                    (string Result, string Declarations, string Origin) declared =
                        (Text(functionQuery, 1), Text(functionQuery, 2), origin);
                    if (origin.Equals("COM", StringComparison.OrdinalIgnoreCase) && description.Length > 0 &&
                        Text(functionQuery, 3) != description)
                    {
                        // A description that no COM plan matches falls back to the declaration all of them share.
                        agreed &= shared is null || shared == declared;
                        shared ??= declared;
                        continue;
                    }
                    result = Signature(declared);
                    if (origin.Equals(module, StringComparison.OrdinalIgnoreCase)) break;
                }
            }
            finally { Reset(functionQuery); }
            if (result is null && agreed && shared is { } fallback) result = Signature(fallback);
            if (functions.Count >= 4096) functions.Remove(functionOrder.Dequeue());
            functions[key] = result;
            functionOrder.Enqueue(key);
            return result;
        }
    }

    public TypeLayout? Type(string name)
    {
        lock (gate)
        {
            if (types.TryGetValue(name, out var cached)) return cached;
            TypeLayout? result;
            try
            {
                Check(BindText(typeQuery, 1, name, -1, -1));
                ++queries;
                result = Row(typeQuery) ? JsonSerializer.Deserialize<TypeLayout>(Text(typeQuery, 0), json) : null;
            }
            finally { Reset(typeQuery); }
            if (types.Count >= 8192) types.Remove(typeOrder.Dequeue());
            types[name] = result;
            typeOrder.Enqueue(name);
            return result;
        }
    }

    private bool Row(nint statement)
    {
        var result = Step(statement);
        if (result is not SqliteRow and not SqliteDone) Check(result);
        return result == SqliteRow;
    }

    private void Check(int result) => SqliteNative.Check(database, result);

    // Stored declarations hold one type and name per line, separated by a tab.
    private static ApiSignature Signature((string Result, string Declarations, string Origin) declared) =>
        new(declared.Declarations.Length == 0 ? [] : [.. declared.Declarations.Split('\n')
            .Select(line => line.Split('\t', 2)).Select(parts => new ApiParameter(parts[^1], parts[0]))],
            declared.Result, declared.Origin);

    public void Dispose()
    {
        lock (gate)
        {
        if (functionQuery != 0) FinalizeStatement(functionQuery);
        if (typeQuery != 0) FinalizeStatement(typeQuery);
        if (changeQuery != 0) FinalizeStatement(changeQuery);
            if (database != 0) Close(database);
            database = functionQuery = typeQuery = changeQuery = 0;
        }
        GC.SuppressFinalize(this);
    }

    ~CatalogDatabase() => Dispose();
}

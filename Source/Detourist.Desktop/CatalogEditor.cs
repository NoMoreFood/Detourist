using Microsoft.Win32;
using System.Data;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using static Detourist.Desktop.SqliteNative;

namespace Detourist.Desktop;

// Stored declaration and result-rule state of one function row, as the catalog records it.
public sealed record FunctionState(string Result, string Signature, string? Summary, int? Override, string? Source,
    int? Status)
{
    public int Rule => Override ?? Status ?? 0;
}

public sealed record CatalogFunction(long Id, string Module, string Name, string Variant, FunctionState State,
    int? Arguments, byte[]? Widths, int? ResultBytes, bool FloatingResult, string? AliasSource, int Aliases)
{
    public string Result => State.Result;
    public string Plan => Arguments is null ? "" : $"{Arguments} arg{(Arguments == 1 ? "" : "s")}";
}

public sealed record CatalogType(string Name, string Kind, long Size);

public sealed class CatalogConflictException(string message) : Exception(message);

public sealed class CatalogStore : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    private readonly object gate = new();
    private nint database;
    public string Path { get; }
    public bool ReadOnly { get; }
    public int PointerSize { get; }
    public static readonly string[] Rules =
    [
        "No failure convention", "Fails when negative (HRESULT, NTSTATUS)", "Fails when zero (BOOL, handles)",
        "Fails when all bits are set (-1)", "Fails when non-zero (error codes)", "Fails when zero or negative"
    ];

    // An alias follows its source's declaration unless the alias's own plan expects another argument count.
    private const string InheritAliases = """
        UPDATE functions SET result=source.result,signature=source.signature,
            summary=nullif(functions.description,replace(replace(source.signature,char(9),' '),char(10),', '))
            FROM sdk_aliases a JOIN functions source ON source.module=a.source_module AND source.name=a.source_name
                AND source.variant='' WHERE functions.module=a.module AND functions.name=a.name AND functions.variant=''
            AND (source.signature<>'' OR source.result<>'uintptr_t')
            AND (functions.result IS NOT source.result OR functions.signature IS NOT source.signature)
            AND NOT EXISTS (SELECT 1 FROM plans p WHERE p.function_id=functions.id AND p.argument_count<>CASE
                source.signature WHEN '' THEN 0
                    ELSE length(source.signature)-length(replace(source.signature,char(10),''))+1
                END)
        """;
    private const string FunctionColumns = """
        f.id,f.module,f.name,f.variant,f.result,f.signature,f.summary,r.rule,s.text,p.status_result,p.argument_count,
        p.argument_bytes,p.result_bytes,p.floating_result,
        (SELECT a.source_module||'!'||a.source_name FROM sdk_aliases a WHERE a.module=f.module AND a.name=f.name),
        (SELECT count(*) FROM sdk_aliases a WHERE a.source_module=f.module AND a.source_name=f.name)
        FROM functions f LEFT JOIN plans p ON p.function_id=f.id LEFT JOIN function_rules r ON r.function_id=f.id
        LEFT JOIN sources s ON s.id=r.source
        """;

    public CatalogStore(string path, int pointerSize = 8)
    {
        Path = System.IO.Path.GetFullPath(path);
        if (!File.Exists(Path)) throw new FileNotFoundException("The API catalog does not exist.", Path);
        var writable = (File.GetAttributes(Path) & FileAttributes.ReadOnly) == 0;
        if (!writable || Open(Path, out database, OpenReadWriteUri, 0) != 0 || DatabaseReadOnly(database, "main") == 1)
        {
            if (database != 0) Close(database);
            Check(Open(Path, out database, OpenReadOnlyUri, 0));
            ReadOnly = true;
        }
        BusyTimeout(database, 5000);
        try
        {
            if (Query("PRAGMA user_version") is not [[(long)Protocol.ApiCatalogSchemaVersion]])
                throw new IOException("Unsupported API catalog schema.");
            Check(SelectArchitecture(database, pointerSize, !ReadOnly));
            PointerSize = Query("SELECT json_extract(layout,'$.size') FROM types WHERE name='SIZE_T'") switch
            {
                [[4L]] => 4, [[8L]] => 8, _ => throw new IOException("The catalog has no valid pointer width.")
            };
            Execute("PRAGMA foreign_keys=ON");
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    // Declarations persist as type<TAB>name lines; their text form matches the catalog's description column.
    public static string Declared(string signature) => signature.Replace('\t', ' ').Replace("\n", ", ");

    public List<CatalogFunction> Functions(string search, int limit)
    {
        var (module, name) = search.Split('!', 2) is [var left, var right] ? (left.Trim(), right.Trim()) :
            ("", search.Trim());
        var aliases = "EXISTS (SELECT 1 FROM module_aliases a WHERE a.module=f.module AND a.alias LIKE ";
        var filter = module.Length > 0 ? $"WHERE (f.module LIKE ?1 OR {aliases}?1)) AND f.name LIKE ?2" :
            name.Length > 0 ? $"WHERE f.name LIKE ?2 OR f.module LIKE ?2 OR {aliases}?2)" : "";
        return [.. Query($"SELECT {FunctionColumns} {filter} ORDER BY f.name,f.module,f.variant LIMIT {limit}",
            module.Length > 0 ? ["%" + module + "%", "%" + name + "%"] :
                name.Length > 0 ? [null, "%" + name + "%"] : [])
            .Select(Function)];
    }

    public CatalogFunction? Function(long id) =>
        Query($"SELECT {FunctionColumns} WHERE f.id=?", id).Select(Function).FirstOrDefault();

    private static CatalogFunction Function(object?[] row) => new((long)row[0]!, (string)row[1]!, (string)row[2]!,
        (string)row[3]!, new((string)row[4]!, (string)row[5]!, (string?)row[6], (int?)(long?)row[7], (string?)row[8],
            (int?)(long?)row[9]), (int?)(long?)row[10], (byte[]?)row[11], (int?)(long?)row[12], row[13] is 1L,
        (string?)row[14], (int)(long)row[15]!);

    public static (FunctionState? State, string? Error) Desired(CatalogFunction function, string result,
        string parameters, string summary, int rule, string source)
    {
        // Parameters are written one per line as a type followed by its name.
        result = Regex.Replace(result.Trim(), @"\s+", " ");
        var declared = new List<(string Type, string Name)>();
        foreach (var (line, index) in parameters.Split('\n').Select((line, index) => (line.Trim(), index + 1))
            .Where(item => item.Item1.Length > 0))
        {
            if (line == "...")
            {
                declared.Add(("...", "..."));
                continue;
            }
            if (Regex.Match(line, @"^(.*\S)\s+([A-Za-z_]\w*)$") is not { Success: true } match)
                return (null, $"Parameter line {index}: write the type followed by the parameter name.");
            declared.Add((Regex.Replace(match.Groups[1].Value, @"\s+", " "), match.Groups[2].Value));
        }
        var outside = Regex.Replace(result, @"<[^<>]*>|\([^()]*\)", "");
        if (result.Length == 0 || result.Contains('\t'))
            return (null, "Enter the result type, such as BOOL, HRESULT or void.");
        if (Regex.IsMatch(outside, @"\b(extern|static|inline|WINAPI|APIENTRY|CALLBACK|NTAPI|PASCAL|STDMETHODCALLTYPE|" +
            @"STDAPICALLTYPE|__stdcall|__cdecl|_ACRTIMP|_DCRTIMP|_CRTIMP|DECLSPEC_IMPORT|EXTERN_C)\b"))
            return (null, "Remove calling-convention and linkage macros from the result type.");
        foreach (var (type, name) in declared.Where(item => item.Type != "..."))
        {
            if (Regex.IsMatch(type, @"[""\\\t+/=;{}]|->|\bsizeof\b|^[(&]") ||
                type.Count(character => character == '(') != type.Count(character => character == ')') ||
                type.Count(character => character == '<') != type.Count(character => character == '>'))
                return (null, $"The type of {name} is not a C declaration.");
            if (Regex.IsMatch(type, @"\b__RPC__\w+|\b__(in|out|inout)(_\w+)?\b|\b_(In|Out|Inout|Outptr|Deref)\w*_"))
                return (null, $"Remove SAL annotations from the type of {name}.");
            if (Regex.IsMatch(type, @"\w\.\w"))
                return (null, $"The type of {name} uses a projected name; use the C type name.");
            if (name is "int" or "long" or "short" or "char" or "unsigned" or "signed" or "void" or "const")
                return (null, $"\"{type} {name}\" lacks a parameter name.");
        }
        var fixedCount = declared.Count - (declared.Count > 0 && declared[^1].Type == "..." ? 1 : 0);
        if (function.Arguments is { } arguments && fixedCount != arguments)
            return (null, $"The capture plan passes {arguments} argument{(arguments == 1 ? "" : "s")}; " +
                "declare the same number.");
        if (rule != 0 && function.ResultBytes == 0)
            return (null, "The capture plan records no result, so the function cannot have a failure rule.");
        if (rule != function.State.Rule && function.Variant.Length == 0 && source.Trim().Length == 0)
            return (null, "Enter where the failure rule comes from, such as its documentation.");

        // A summary matching the declared parameters is not stored, so the description follows later edits.
        var signature = string.Join('\n', declared.Select(item => item.Type + '\t' + item.Name));
        summary = summary.Trim();
        var stored = summary.Length == 0 || summary == Declared(signature) ? null : summary;
        if (stored is not null && (stored.Contains('\n') || stored.Contains('\t')))
            return (null, "Keep the summary on one line.");
        var state = function.State with { Result = result, Signature = signature, Summary = stored };
        if (rule != function.State.Rule || function.Variant.Length == 0 && state.Override is not null &&
            source.Trim() != state.Source)
        {
            state = function.Variant.Length == 0 || state.Override is not null ?
                state with { Override = rule, Source = source.Trim().Length > 0 ? source.Trim() : state.Source } :
                state with { Status = rule };
        }
        return (state, null);
    }

    public FunctionState? State(long id) => Query(
        "SELECT f.result,f.signature,f.summary,r.rule,s.text,p.status_result " +
        "FROM functions f LEFT JOIN plans p ON p.function_id=f.id LEFT JOIN function_rules r ON r.function_id=f.id " +
        "LEFT JOIN sources s ON s.id=r.source WHERE f.id=?", id).Select(row => new FunctionState((string)row[0]!,
        (string)row[1]!, (string?)row[2], (int?)(long?)row[3], (string?)row[4], (int?)(long?)row[5])).FirstOrDefault();

    // Writes a declaration only when the row still holds what the editor loaded; aliases then follow it.
    public void Save(long id, FunctionState expected, FunctionState desired) => Transaction(() =>
    {
        if (State(id) != expected)
            throw new CatalogConflictException("The function changed in the catalog since it was loaded. Reload it.");
        Execute("UPDATE functions SET result=?,signature=?,summary=? WHERE id=?", desired.Result, desired.Signature,
            desired.Summary, id);
        if (desired.Override is null) Execute("DELETE FROM function_rules WHERE function_id=?", id);
        else
        {
            Execute("INSERT OR IGNORE INTO sources(text) VALUES(?)", desired.Source ?? "");
            Execute("INSERT OR REPLACE INTO function_rules VALUES(?,?,(SELECT id FROM sources WHERE text=?))", id,
                desired.Override, desired.Source ?? "");
        }
        if (desired.Status is { } status) Execute("UPDATE plans SET status_result=? WHERE function_id=?", status, id);
        for (var pass = 0; pass < 8 && Execute(InheritAliases) > 0; ++pass) { }
        Execute("DELETE FROM sources WHERE id NOT IN (SELECT source FROM function_rules) " +
            "AND id NOT IN (SELECT source FROM pending_rules)");
    });

    public List<CatalogType> Types(string search, int limit) => [.. Query("SELECT name,coalesce(json_extract(layout," +
        $"'$.kind'),''),coalesce(json_extract(layout,'$.size'),0) FROM types WHERE name LIKE ? " +
        $"ORDER BY name LIMIT {limit}",
        "%" + search.Trim() + "%").Select(row => new CatalogType((string)row[0]!, row[1]?.ToString() ?? "",
            row[2] is long size ? size : 0))];

    public string? Layout(string name) => Query("SELECT layout FROM types WHERE name=?", name) is [[string layout]] ?
        layout : null;

    public int References(string name) => (int)(long)Query("SELECT count(*) FROM functions WHERE instr(signature,?) " +
        "OR instr(result,?)", name, name)[0][0]!;

    public static (string? Layout, string? Error) ValidateLayout(string name, string text, int pointerSize = 8)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(text);
        }
        catch (JsonException invalid)
        {
            return (null, "The layout is not valid JSON: " + invalid.Message);
        }
        if (node is not JsonObject layout || layout["kind"]?.GetValueKind() != JsonValueKind.String)
            return (null, "A layout is a JSON object with a \"kind\".");
        var kind = (string)layout["kind"]!;
        long Number(JsonNode? value) => value?.GetValueKind() == JsonValueKind.Number &&
            value.GetValue<JsonElement>().TryGetInt64(out var number) ? number : -1;
        bool Text(JsonNode? value) => value?.GetValueKind() == JsonValueKind.String && ((string)value!).Length > 0;
        var size = Number(layout["size"]);

        // Demangled C++/CX handles carry the target's native pointer width.
        var pointerBytes = Regex.IsMatch(name, @"\^\s+__ptr(?:32|64)$") ? pointerSize :
            name.Contains("__ptr32") ? 4 : name.Contains("__ptr64") ? 8 : pointerSize;
        if (size < 0) return (null, "\"size\" must be a byte count of zero or more.");
        var error = kind switch
        {
            "Pointer" when size != pointerBytes || !Text(layout["element"]) =>
                $"A pointer layout names its \"element\" and is {pointerBytes} bytes.",
            "Alias" or "Array" when !Text(layout["element"]) =>
                $"An {kind.ToLowerInvariant()} layout names its \"element\".",
            "Array" when Number(layout["count"]) < 0 => "An array layout records its element \"count\".",
            "Integer" or "Enum" when size is not (1 or 2 or 4 or 8) =>
                $"An {kind.ToLowerInvariant()} is 1, 2, 4 or 8 bytes.",
            "Enum" when layout["choices"] is not JsonArray choices ||
                choices.Any(choice => choice is not JsonObject item ||
                !Text(item["name"]) || item["value"]?.GetValueKind() != JsonValueKind.Number) ||
                ((JsonArray)layout["choices"]!).Select(choice => (string)choice!["name"]!).Distinct().Count() !=
                ((JsonArray)layout["choices"]!).Count => "Enum \"choices\" need unique names and numeric values.",
            // A field starts inside its structure; only a flexible array member may start at its end.
            "Structure" or "Union" when layout["fields"] is not JsonArray fields || fields.Any(field =>
                field is not JsonObject item || !Text(item["name"]) || !Text(item["type"]) ||
                Number(item["offset"]) < 0 || Number(item["offset"]) + Math.Max(Number(item["bits"]),
                    Regex.IsMatch((string)item["type"]!, @"\[0?\]$") ? 0 : 1) > size * 8) =>
                "Fields need a name, a type and a bit offset inside the structure.",
            "Structure" or "Union" or "Pointer" or "Alias" or "Array" or "Integer" or "Enum" or "Float32" or
                "Float64" or
                "Boolean" or "Void" or "Unknown" => null,
            _ => $"\"{kind}\" is not a layout kind the inspector understands."
        };
        return error is null ? (layout.ToJsonString(JsonOptions), null) : (null, error);
    }

    // A plain pointer layout follows from its name, so storing it is redundant; saving one removes the row.
    public void SaveType(string name, string? expected, string? layout) => Transaction(() =>
    {
        if (Layout(name) != expected)
            throw new CatalogConflictException("The type changed in the catalog since it was loaded. Reload it.");
        var derived = name.EndsWith('*') || name.EndsWith('&') ?
            $$"""{"kind":"Pointer","size":{{PointerSize}},"element":{{JsonSerializer.Serialize(name[..^1].Trim(),
                JsonOptions)}}}""" : null;
        if (layout is null || layout == derived) Execute("DELETE FROM types WHERE name=?", name);
        else Execute("INSERT OR REPLACE INTO types VALUES(?,?)", name, layout);
    });

    public string[] Tables() => [.. Query("SELECT name FROM sqlite_schema WHERE type IN ('table','view') " +
        "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'catalog_%' ORDER BY name").Select(row => (string)row[0]!)];

    public DataTable Browse(string table, string filter, int limit)
    {
        var columns = Query($"SELECT name FROM pragma_table_info('{table.Replace("'", "''")}')")
            .Select(row => (string)row[0]!).ToArray();
        var quoted = columns.Select(column => '"' + column.Replace("\"", "\"\"") + '"').ToArray();
        var where = filter.Trim().Length == 0 ? "" :
            " WHERE " + string.Join(" OR ", quoted.Select(column => $"CAST({column} AS TEXT) LIKE ?1"));
        var data = new DataTable(table);
        foreach (var column in columns) data.Columns.Add(column, typeof(string));
        foreach (var row in Query($"SELECT {string.Join(',', quoted)} FROM \"{table.Replace("\"", "\"\"")}\"{where} " +
            $"LIMIT {limit}", where.Length > 0 ? ["%" + filter.Trim() + "%"] : []))
            data.Rows.Add([.. row.Select(value => value switch
            {
                null => "NULL",
                byte[] bytes => bytes.Length <= 32 ? "x'" + Convert.ToHexString(bytes) + "'" :
                    $"x'{Convert.ToHexString(bytes, 0, 32)}…' ({bytes.Length:N0} bytes)",
                string text => text.Replace('\t', ' ').Replace("\n", " ⏎ "),
                _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture)
            })]);
        return data;
    }

    public void Optimize(IProgress<string>? progress = null)
    {
        // Maintenance owns the connection, but VACUUM must run outside a transaction.
        lock (gate)
        {
            if (ReadOnly) throw new IOException("This catalog is read-only. Open a writable copy to optimize it.");
            progress?.Report("Rebuilding catalog indexes…");
            Execute("REINDEX");
            progress?.Report("Compacting the catalog…");
            Execute("VACUUM");
            progress?.Report("Updating query statistics…");
            Execute("PRAGMA optimize=0x10002");
            progress?.Report("Checking catalog integrity…");
            if (Query("PRAGMA integrity_check") is not [["ok"]] || Query("PRAGMA foreign_key_check").Count != 0)
                throw new IOException("Catalog integrity or foreign-key validation failed.");

            // A busy checkpoint returns a result row instead of a SQLite error.
            progress?.Report("Reclaiming journal space…");
            if (Query("PRAGMA wal_checkpoint(TRUNCATE)") is [[1L, ..]])
                throw new IOException("The catalog was optimized, but its write-ahead log is still in use. " +
                    "Close other catalog connections and try again.");
        }
    }

    private void Transaction(Action body)
    {
        lock (gate)
        {
            if (ReadOnly) throw new IOException("This catalog is read-only. Open a writable copy to edit it.");
            Execute("BEGIN IMMEDIATE");
            try
            {
                body();
                Execute("COMMIT");
            }
            catch
            {
                Execute("ROLLBACK");
                throw;
            }
        }
    }

    private int Execute(string sql, params object?[] values)
    {
        lock (gate)
        {
            // RETURNING reports matched view rows, including updates routed through edit triggers.
            var mutation = Regex.IsMatch(sql, @"^\s*(INSERT|UPDATE|DELETE)\b", RegexOptions.IgnoreCase);
            var rows = Query(mutation ? sql.TrimEnd().TrimEnd(';') + " RETURNING 1" : sql, values);
            return mutation ? rows.Count : Changes(database);
        }
    }

    private List<object?[]> Query(string sql, params object?[] values)
    {
        lock (gate)
        {
            Check(Prepare(database, sql, -1, out var statement, 0));
            try
            {
                for (var index = 0; index < values.Length; ++index)
                {
                    Check(values[index] switch
                    {
                        null => BindNull(statement, index + 1),
                        string text => BindText(statement, index + 1, text, -1, -1),
                        int number => BindInteger(statement, index + 1, number),
                        long number => BindInteger(statement, index + 1, number),
                        _ => throw new ArgumentException("Unsupported catalog value.")
                    });
                }
                var rows = new List<object?[]>();
                for (int result; (result = Step(statement)) != SqliteDone;)
                {
                    if (result != SqliteRow) Check(result);
                    var row = new object?[ColumnCount(statement)];
                    for (var column = 0; column < row.Length; ++column)
                    {
                        row[column] = ColumnType(statement, column) switch
                        {
                            ColumnTypeInteger => ColumnInteger(statement, column),
                            ColumnTypeFloat => ColumnDouble(statement, column),
                            ColumnTypeText => Text(statement, column),
                            ColumnTypeBlob => Blob(statement, column),
                            _ => null
                        };
                    }
                    rows.Add(row);
                }
                return rows;
            }
            finally
            {
                FinalizeStatement(statement);
            }
        }
    }

    private static byte[] Blob(nint statement, int column)
    {
        var bytes = new byte[ColumnBytes(statement, column)];
        if (bytes.Length > 0) Marshal.Copy(ColumnBlob(statement, column), bytes, 0, bytes.Length);
        return bytes;
    }

    private void Check(int result) => SqliteNative.Check(database, result);

    public void Dispose()
    {
        lock (gate)
        {
            if (database != 0) Close(database);
            database = 0;
        }
        GC.SuppressFinalize(this);
    }

    ~CatalogStore() => Dispose();
}

public static class CatalogValidator
{
    // The capture engine compiles a catalog in a short-lived collector, exactly as it does before every capture.
    public static async Task<string?> Check(string path, int pointerSize = 8)
    {
        try
        {
            using var catalog = new CatalogDatabase(path, pointerSize);
            var width = catalog.Type("SIZE_T")?.Size;
            if (width is not (4 or 8)) return "The catalog has no valid pointer width.";
            await using var client = new CollectorClient(width.Value, path);
            await client.Send("hello");
            return null;
        }
        catch (Exception error) when (error is IOException or JsonException or
            System.ComponentModel.Win32Exception or InvalidOperationException or KeyNotFoundException)
        {
            return "The capture engine could not check the catalog: " + error.Message;
        }
    }
}

public sealed class CatalogEditorWindow : ToolWindow
{
    private const int Limit = 500;
    private CatalogStore? store;
    private bool engineChecks;
    private CatalogFunction? function;
    private string? typeName, typeLayout;
    private bool loading;
    private readonly TextBlock file = new() { TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment =
        VerticalAlignment.Center };
    private readonly TextBlock engine = new()
    {
        TextWrapping = TextWrapping.Wrap, Margin = new(0, 4, 0, 0), FontSize = 12
    };
    private readonly TextBox functionSearch = new(), typeSearch = new(), tableFilter = new();
    private readonly DataGrid functions = new() { SelectionMode = DataGridSelectionMode.Single };
    private readonly DataGrid types = new() { SelectionMode = DataGridSelectionMode.Single };
    private readonly DataGrid rows = new() { AutoGenerateColumns = true, IsReadOnly = true };
    private readonly ComboBox tables = new() { Width = 260, Margin = new(0, 0, 10, 0) };
    private readonly TextBlock functionTitle = new() { FontWeight = FontWeights.SemiBold, TextTrimming =
        TextTrimming.CharacterEllipsis }, functionInfo = new() { TextWrapping = TextWrapping.Wrap, FontSize = 12 },
        typeTitle = new() { FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis },
        typeInfo = new() { TextWrapping = TextWrapping.Wrap, FontSize = 12 },
        functionCount = new(), typeCount = new(), rowCount = new();
    private readonly TextBox result = new(), parameters = Code(), summary = new(), source = new(), layout = Code(),
        newType = new() { Width = 260 };
    private readonly ComboBox architecture = new()
    {
        ItemsSource = new[] { "x64", "x86" }, SelectedIndex = 0, MinWidth = 72, VerticalAlignment = VerticalAlignment.Center
    };
    private readonly ComboBox rule = new() { ItemsSource = CatalogStore.Rules };
    private readonly Button saveFunction = new() { Content = "_Save", MinWidth = 80 },
        revertFunction = new() { Content = "_Revert", MinWidth = 80, Margin = new(8, 0, 0, 0) },
        saveType = new() { Content = "_Save", MinWidth = 80 },
        revertType = new() { Content = "_Revert", MinWidth = 80, Margin = new(8, 0, 0, 0) },
        deleteType = new() { Content = "_Delete", MinWidth = 80, Margin = new(8, 0, 0, 0) },
        addType = new() { Content = "_Add", MinWidth = 70, Margin = new(8, 0, 0, 0) };
    private readonly DispatcherTimer searchDelay = new() { Interval = TimeSpan.FromMilliseconds(Protocol.UiDebounceMs) };
    private readonly TabControl tabs = new();
    private readonly Button optimize = new()
    {
        Content = "O_ptimize", Margin = new(10, 0, 0, 0), Visibility = Visibility.Collapsed,
        ToolTip = "Rebuild indexes, reclaim unused space, update query statistics and verify catalog integrity"
    };

    public static string DefaultPath => Environment.GetEnvironmentVariable("DETOURIST_API_CATALOG") is { Length: > 0 }
        path ? path : Path.Combine(AppContext.BaseDirectory, "ApiCatalog.sqlite");
    public string CatalogPath => store?.Path ?? "";

    public CatalogEditorWindow(string path) : base("API catalog",
        "Browse every catalog table and edit declarations, failure rules and type layouts. " +
        "Captures use saved changes from their next session.", 1240, 780)
    {
        // The list and the form sit side by side, so the window keeps room for both.
        MinWidth = 920;
        MinHeight = 560;
        SetRows(Body, GridLength.Auto, Fill);
        var header = new DockPanel { Margin = new(0, 0, 0, 10) };
        var open = new Button { Content = "_Open catalog…", Margin = new(10, 0, 0, 0) };
        DockPanel.SetDock(open, Dock.Right);
        header.Children.Add(open);
        DockPanel.SetDock(optimize, Dock.Right);
        header.Children.Add(optimize);
        var target = new StackPanel { Orientation = Orientation.Horizontal, Margin = new(10, 0, 0, 0) };
        target.Children.Add(new Label { Content = "_Architecture:", Target = architecture, Foreground = Foreground,
            VerticalAlignment = VerticalAlignment.Center });
        target.Children.Add(architecture);
        DockPanel.SetDock(target, Dock.Right);
        header.Children.Add(target);
        Accessible(architecture, "Architecture");
        architecture.SelectionChanged += (_, _) =>
        {
            if (store is null || store.PointerSize == (architecture.SelectedIndex == 1 ? 4 : 8)) return;
            if (Discard()) Load(store.Path);
            else architecture.SelectedIndex = store.PointerSize == 4 ? 1 : 0;
        };
        Accessible(optimize, "Optimize catalog");
        optimize.Click += async (_, _) => await Optimize();
        var location = new StackPanel();
        location.Children.Add(file);
        location.Children.Add(engine);
        header.Children.Add(location);
        Body.Children.Add(header);
        Grid.SetRow(tabs, 1);
        Body.Children.Add(tabs);
        tabs.Items.Add(new TabItem { Header = "_Functions", Content = FunctionsTab() });
        tabs.Items.Add(new TabItem { Header = "_Types", Content = TypesTab() });
        tabs.Items.Add(new TabItem { Header = "Ta_bles", Content = TablesTab() });
        engine.Foreground = file.Foreground = (Brush)FindResource("MutedBrush");
        AddAction("_Close", true, (_, _) => Close()).IsCancel = true;
        open.Click += (_, _) =>
        {
            var picker = new OpenFileDialog
            {
                Title = "Open API catalog", Filter = "API catalog (*.sqlite)|*.sqlite|All files|*.*",
                InitialDirectory = Path.GetDirectoryName(CatalogPath)
            };
            if (picker.ShowDialog(this) == true && Discard()) Load(picker.FileName);
        };
        searchDelay.Tick += (_, _) =>
        {
            searchDelay.Stop();
            if (tabs.SelectedIndex == 0) SearchFunctions();
            else if (tabs.SelectedIndex == 1) SearchTypes();
            else BrowseTable();
        };
        Closing += (_, e) => e.Cancel = !IsEnabled || !Discard();
        Closed += (_, _) => store?.Dispose();
        Load(path);
    }

    private static TextBox Code() => new()
    {
        AcceptsReturn = true, AcceptsTab = false, TextWrapping = TextWrapping.NoWrap, FontFamily = new("Consolas"),
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
        VerticalContentAlignment = VerticalAlignment.Top
    };

    private void Load(string path)
    {
        // A catalog the engine already rejects is still editable, but saves cannot be checked against it.
        try
        {
            var opened = new CatalogStore(path, architecture.SelectedIndex == 1 ? 4 : 8);
            store?.Dispose();
            store = opened;
        }
        catch (Exception error) when (error is IOException or DllNotFoundException or UnauthorizedAccessException)
        {
            Error.Text = error.Message;
            if (store is null) file.Text = path;
            return;
        }
        file.Text = store.Path + (store.ReadOnly ? "  (read-only)" : "");
        optimize.Visibility = store.ReadOnly ? Visibility.Collapsed : Visibility.Visible;
        engineChecks = false;
        engine.Text = "Checking the catalog with the capture engine…";
        Error.Text = "";
        ShowFunction(null);
        ShowType(null, null);
        tables.ItemsSource = store.Tables();
        tables.SelectedIndex = Array.IndexOf((string[])tables.ItemsSource, "functions");
        SearchFunctions();
        SearchTypes();
        var checking = store;
        _ = Dispatcher.InvokeAsync(async () =>
        {
            var problem = await CatalogValidator.Check(checking.Path, checking.PointerSize);
            if (store != checking) return;
            engineChecks = problem is null;
            engine.Text = problem is null ? "The capture engine accepts this catalog and checks each save." :
                $"The capture engine does not load this catalog ({problem}). Saves are not checked against it.";
        });
    }

    private Grid FunctionsTab()
    {
        var tab = SplitTab(functionSearch, "Search functions by name, or module!name", functions, functionCount,
            out var form, out var actions, out _);
        functions.Columns.Add(Column("MODULE", nameof(CatalogFunction.Module), 130));
        functions.Columns.Add(Filling("FUNCTION", nameof(CatalogFunction.Name)));
        functions.Columns.Add(Column("RESULT", nameof(CatalogFunction.Result), 100));
        functions.Columns.Add(Column("PLAN", nameof(CatalogFunction.Plan), 72));
        form.Children.Add(functionTitle);
        form.Children.Add(Spaced(functionInfo, 12));
        Label(form, "Result type");
        form.Children.Add(Spaced(result, 10));
        Label(form, "Parameters", "One per line: the type, then the name.");
        parameters.Height = 150;
        form.Children.Add(Spaced(parameters, 10));
        Label(form, "Summary", "Leave empty to describe calls by their parameters.");
        form.Children.Add(Spaced(summary, 10));
        Label(form, "Failure rule");
        form.Children.Add(Spaced(rule, 10));
        Label(form, "Rule source", "Documentation or header the failure rule comes from.");
        form.Children.Add(Spaced(source, 4));
        actions.Children.Add(saveFunction);
        actions.Children.Add(revertFunction);
        Accessible(saveFunction, "Save function");
        Accessible(revertFunction, "Revert function");
        Accessible(result, "Result type");
        Accessible(parameters, "Parameters");
        Accessible(summary, "Summary");
        Accessible(rule, "Failure rule");
        Accessible(source, "Rule source");
        foreach (var box in new[] { result, parameters, summary, source })
            box.TextChanged += (_, _) => FunctionEdited();
        rule.SelectionChanged += (_, _) => FunctionEdited();
        functionSearch.TextChanged += (_, _) => searchDelay.Start();
        SelectMatch<CatalogFunction>(functions, item => item.Id == function?.Id,
            item => ShowFunction(store!.Function(item.Id)));
        saveFunction.Click += async (_, _) => await SaveFunction();
        revertFunction.Click += (_, _) => ShowFunction(function is null ? null : store!.Function(function.Id));
        return tab;
    }

    private Grid TypesTab()
    {
        var layoutTab = SplitTab(typeSearch, "Search types by name", types, typeCount, out var form, out var actions,
            out var footer);
        types.Columns.Add(Filling("TYPE", nameof(CatalogType.Name)));
        types.Columns.Add(Column("KIND", nameof(CatalogType.Kind), 90));
        types.Columns.Add(Column("BYTES", nameof(CatalogType.Size), 70));
        form.Children.Add(typeTitle);
        form.Children.Add(Spaced(typeInfo, 12));
        Label(form, "Layout", "JSON as the inspector reads it. Field offsets are in bits.");
        layout.Height = 400;
        form.Children.Add(Spaced(layout, 4));
        foreach (var button in new[] { saveType, revertType, deleteType }) actions.Children.Add(button);
        Accessible(saveType, "Save type");
        Accessible(revertType, "Revert type");
        Accessible(deleteType, "Delete type");
        Accessible(addType, "Add type");
        var adding = new StackPanel { Orientation = Orientation.Horizontal, Margin = new(12, 6, 0, 0) };
        newType.Width = 230;
        adding.Children.Add(Hinted(newType, "New type name"));
        adding.Children.Add(addType);
        DockPanel.SetDock(adding, Dock.Right);
        footer.Children.Insert(0, adding);
        Accessible(layout, "Type layout");
        Accessible(newType, "New type name");
        layout.TextChanged += (_, _) => TypeEdited();
        typeSearch.TextChanged += (_, _) => searchDelay.Start();
        SelectMatch<CatalogType>(types, item => item.Name == typeName,
            item => ShowType(item.Name, store!.Layout(item.Name)));
        saveType.Click += async (_, _) => await SaveType(false);
        deleteType.Click += async (_, _) => await SaveType(true);
        revertType.Click += (_, _) => ShowType(typeName, typeName is null ? null : store!.Layout(typeName));
        addType.Click += (_, _) =>
        {
            var name = newType.Text.Trim();
            if (name.Length == 0 || !Discard()) return;
            if (store!.Layout(name) is { } existing)
            {
                ShowType(name, existing);
                Error.Text = $"{name} already has a layout; it is open for editing.";
                return;
            }
            ShowType(name, null);
            layout.Text = "{\n  \"kind\": \"Structure\",\n  \"size\": 0,\n  \"fields\": []\n}";
            newType.Clear();
            layout.Focus();
        };
        return layoutTab;
    }

    private Grid TablesTab()
    {
        var grid = new Grid();
        SetRows(grid, GridLength.Auto, Fill, GridLength.Auto);
        var bar = new DockPanel { Margin = new(0, 10, 0, 10) };
        bar.Children.Add(tables);
        bar.Children.Add(Hinted(tableFilter, "Show rows with any column containing this text"));
        tableFilter.ToolTip = "Show rows with any column containing this text";
        Accessible(tables, "Catalog table");
        Accessible(tableFilter, "Row filter");
        grid.Children.Add(bar);
        Grid.SetRow(rows, 1);
        grid.Children.Add(rows);
        rows.AutoGeneratingColumn += (_, e) =>
        {
            if (e.Column is DataGridTextColumn column)
            {
                column.ElementStyle = CellText;
                column.MaxWidth = 420;
            }
        };
        Grid.SetRow(rowCount, 2);
        rowCount.Margin = new(0, 8, 0, 0);
        rowCount.Foreground = (Brush)FindResource("MutedBrush");
        grid.Children.Add(rowCount);
        tables.SelectionChanged += (_, _) => BrowseTable();
        tableFilter.TextChanged += (_, _) => searchDelay.Start();
        return grid;
    }

    private Grid SplitTab(TextBox search, string hint, DataGrid list, TextBlock count, out StackPanel form,
        out StackPanel actions, out DockPanel footer)
    {
        // The searchable list keeps its width while the form scrolls above actions that stay in view.
        var grid = new Grid { Margin = new(0, 10, 0, 0) };
        grid.ColumnDefinitions.Add(new() { Width = new(1.15, GridUnitType.Star), MinWidth = 380 });
        grid.ColumnDefinitions.Add(new() { Width = new(16) });
        grid.ColumnDefinitions.Add(new() { Width = new(1, GridUnitType.Star), MinWidth = 360 });
        var left = new Grid();
        SetRows(left, GridLength.Auto, Fill, GridLength.Auto);
        search.ToolTip = hint;
        Accessible(search, hint);
        left.Children.Add(Spaced(Hinted(search, hint), 8));
        list.IsReadOnly = true;
        Grid.SetRow(list, 1);
        left.Children.Add(list);
        footer = new DockPanel { LastChildFill = true };
        count.Margin = new(0, 8, 0, 0);
        count.VerticalAlignment = VerticalAlignment.Center;
        count.Foreground = (Brush)FindResource("MutedBrush");
        footer.Children.Add(count);
        Grid.SetRow(footer, 2);
        left.Children.Add(footer);
        grid.Children.Add(left);
        var right = new Grid();
        SetRows(right, Fill, GridLength.Auto);
        form = new StackPanel { Margin = new(0, 0, 8, 0) };
        right.Children.Add(Scroll(form));
        actions = new StackPanel { Orientation = Orientation.Horizontal, Margin = new(0, 10, 0, 0) };
        Grid.SetRow(actions, 1);
        right.Children.Add(actions);
        Grid.SetColumn(right, 2);
        grid.Children.Add(right);
        return grid;
    }

    private static Grid Hinted(TextBox box, string hint)
    {
        // Empty-field hints yield to the caret while the field is being edited.
        var host = new Grid();
        var text = new TextBlock
        {
            Text = hint, Margin = new(9, 0, 7, 0), VerticalAlignment = VerticalAlignment.Center,
            IsHitTestVisible = false, TextTrimming = TextTrimming.CharacterEllipsis,
            Foreground = (Brush)Application.Current.FindResource("MutedBrush")
        };
        void UpdateHint() => text.Visibility = box.Text.Length == 0 && !box.IsKeyboardFocusWithin ?
            Visibility.Visible : Visibility.Collapsed;
        box.TextChanged += (_, _) => UpdateHint();
        box.IsKeyboardFocusWithinChanged += (_, _) => UpdateHint();
        UpdateHint();
        host.Children.Add(box);
        host.Children.Add(text);
        return host;
    }

    private static DataGridTextColumn Filling(string title, string binding) => new()
    {
        Header = title, Binding = new System.Windows.Data.Binding(binding), ElementStyle = CellText,
        Width = new(1, DataGridLengthUnitType.Star), MinWidth = 160
    };

    private static T Spaced<T>(T element, double below) where T : FrameworkElement
    {
        element.Margin = new(0, 0, 0, below);
        return element;
    }

    private static void Accessible(DependencyObject element, string name) =>
        System.Windows.Automation.AutomationProperties.SetName(element, name);

    private void SelectMatch<T>(DataGrid grid, Func<T, bool> isCurrent, Action<T> show)
    {
        grid.SelectionChanged += (_, _) =>
        {
            if (loading || grid.SelectedItem is not T item || isCurrent(item)) return;
            if (Discard()) show(item);
            else
            {
                loading = true;
                grid.SelectedItem = grid.Items.OfType<T>().FirstOrDefault(isCurrent);
                loading = false;
            }
        };
    }

    private void SearchFunctions() => ShowMatches(store?.Functions(functionSearch.Text, Limit + 1),
        functions, functionCount, item => item.Id == function?.Id);

    private void SearchTypes() => ShowMatches(store?.Types(typeSearch.Text, Limit + 1),
        types, typeCount, item => item.Name == typeName);

    private void ShowMatches<T>(List<T>? found, DataGrid grid, TextBlock count, Func<T, bool> selected)
    {
        if (found is null) return;
        loading = true;
        grid.ItemsSource = found.Take(Limit).ToArray();
        grid.SelectedItem = found.FirstOrDefault(selected);
        loading = false;
        count.Text = found.Count > Limit ? $"First {Limit:N0} matches; refine the search to see others." :
            $"{found.Count:N0} match{(found.Count == 1 ? "" : "es")}";
    }

    private async void BrowseTable()
    {
        if (store is null || tables.SelectedItem is not string table) return;
        var (filter, current) = (tableFilter.Text, store);
        rowCount.Text = "Reading rows…";
        try
        {
            var data = await Task.Run(() => current.Browse(table, filter, Limit + 1));
            if (current != store || tables.SelectedItem as string != table || tableFilter.Text != filter) return;
            var shown = data.Rows.Count > Limit;
            if (shown) data.Rows.RemoveAt(Limit);
            rows.ItemsSource = data.DefaultView;
            rowCount.Text = shown ?
                $"First {Limit:N0} rows{(filter.Trim().Length > 0 ? " matching the filter" : "")}." :
                $"{data.Rows.Count:N0} row{(data.Rows.Count == 1 ? "" : "s")}";
        }
        catch (IOException error)
        {
            rowCount.Text = error.Message;
        }
    }

    private void ShowFunction(CatalogFunction? selected)
    {
        loading = true;
        function = selected;
        functionTitle.Text = selected is null ? "Select a function" : selected.Variant.Length > 0 ?
            $"{selected.Name}  ·  COM variant {selected.Variant}" : $"{selected.Module}!{selected.Name}";
        result.Text = selected?.State.Result ?? "";
        parameters.Text = selected is null ? "" : string.Join(Environment.NewLine, selected.State.Signature
            .Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Replace('\t', ' ')));
        summary.Text = selected?.State.Summary ?? "";
        rule.SelectedIndex = selected?.State.Rule ?? -1;
        source.Text = selected?.State.Source ?? "";
        source.IsEnabled = selected is { Variant.Length: 0 };
        var inherits = selected?.AliasSource is not null;
        foreach (var box in new[] { result, parameters, summary }) box.IsEnabled = selected is not null && !inherits;
        rule.IsEnabled = selected is not null && (selected.Variant.Length == 0 || selected.Arguments is not null);
        functionInfo.Text = selected is null ? "Search for a function to see its declaration and capture plan." :
            string.Join(" ", new[]
            {
                selected.Arguments is { } count ? $"Capture plan: {count} argument{(count == 1 ? "" : "s")}" +
                    (selected.Widths is { Length: > 0 } widths ? $" ({string.Join(", ", widths)} bytes)" : "") +
                    (selected.ResultBytes is 0 ? ", no result." : $", {selected.ResultBytes}-byte " +
                    (selected.FloatingResult ? "floating-point " : "") + "result.") :
                    "No capture plan; the declaration describes captured calls only.",
                inherits ? $"The declaration follows {selected.AliasSource}; edit that function instead." : "",
                selected.Aliases > 0 ? $"{selected.Aliases} alias{(selected.Aliases == 1 ? "" : "es")} follow this " +
                    "declaration." : ""
            }.Where(text => text.Length > 0));
        loading = false;
        FunctionEdited();
    }

    private (FunctionState? State, string? Error) DesiredFunction() => function is null ? (null, null) :
        CatalogStore.Desired(function, result.Text, parameters.Text, summary.Text, Math.Max(rule.SelectedIndex, 0),
            source.Text);

    private bool FunctionChanged() => function is not null && DesiredFunction() is var (state, problem) &&
        (problem is not null || state != function.State);

    private void FunctionEdited()
    {
        if (loading) return;
        var changed = FunctionChanged();
        saveFunction.IsEnabled = changed && store is { ReadOnly: false };
        revertFunction.IsEnabled = changed;
    }

    private async Task SaveFunction()
    {
        if (function is not { } current || store is null) return;
        var (desired, problem) = DesiredFunction();
        if (desired is null)
        {
            Error.Text = problem;
            return;
        }
        await Saving(async () =>
        {
            store.Save(current.Id, current.State, desired);
            if (await Rejected(() => store.Save(current.Id, desired, current.State))) return;
            ShowFunction(store.Function(current.Id));
            SearchFunctions();
            Saved($"Saved {current.Name}.");
        });
    }

    private void ShowType(string? name, string? stored)
    {
        loading = true;
        typeName = name;
        typeLayout = stored;
        typeTitle.Text = name ?? "Select a type";
        layout.Text = stored is null ? "" : JsonNode.Parse(stored)!.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
        layout.IsEnabled = name is not null;
        typeInfo.Text = name is null ? "Search for a type to see its layout." : stored is null ?
            "New type; it is added when saved." : $"Named in {store!.References(name):N0} declarations.";
        loading = false;
        TypeEdited();
    }

    private void TypeEdited()
    {
        if (loading) return;
        var changed = typeName is not null && (typeLayout is null ||
            CatalogStore.ValidateLayout(typeName, layout.Text, store?.PointerSize ?? 8).Layout is not { } edited ||
            !JsonNode.DeepEquals(JsonNode.Parse(edited), JsonNode.Parse(typeLayout)));
        saveType.IsEnabled = changed && store is { ReadOnly: false };
        revertType.IsEnabled = changed && typeLayout is not null;
        deleteType.IsEnabled = typeLayout is not null && store is { ReadOnly: false };
    }

    private async Task SaveType(bool delete)
    {
        if (typeName is not { } name || store is null) return;
        var (compact, problem) = delete ? (null, null) : CatalogStore.ValidateLayout(name, layout.Text, store.PointerSize);
        if (!delete && compact is null)
        {
            Error.Text = problem;
            return;
        }
        if (delete && MessageBox.Show(this, $"Delete the layout of {name}? Declarations that name it show raw values.",
            "Delete type", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) !=
                MessageBoxResult.Yes)
            return;
        var before = typeLayout;
        await Saving(async () =>
        {
            store.SaveType(name, before, compact);
            var after = store.Layout(name);
            if (await Rejected(() => store.SaveType(name, after, before))) return;
            ShowType(after is null ? null : name, after);
            SearchTypes();
            Saved(after is null ? $"Removed the stored layout of {name}." : $"Saved {name}.");
        });
    }

    private async Task Optimize()
    {
        if (store is not { ReadOnly: false } current || !IsEnabled) return;

        // Pause delayed queries while maintenance runs, retaining selections and unsaved form values.
        var searching = searchDelay.IsEnabled;
        searchDelay.Stop();
        IsEnabled = false;
        Error.Foreground = (Brush)FindResource("MutedBrush");
        Error.Text = "Optimizing catalog…";
        var progress = new Progress<string>(message =>
        {
            if (!IsEnabled) Error.Text = message;
        });
        try
        {
            await Task.Run(() => current.Optimize(progress));
            Error.Text = "Catalog optimized. Indexes rebuilt, space reclaimed and integrity verified.";
        }
        catch (IOException error)
        {
            Error.Foreground = (Brush)FindResource("DangerBrush");
            Error.Text = error.Message;
        }
        finally
        {
            IsEnabled = true;
            if (searching) searchDelay.Start();
        }
    }

    private async Task Saving(Func<Task> save)
    {
        // Keep the form busy while the engine compiles the saved catalog.
        IsEnabled = false;
        Error.Foreground = (Brush)FindResource("MutedBrush");
        Error.Text = engineChecks ? "Saving and checking with the capture engine…" : "Saving…";
        try
        {
            await save();
        }
        catch (Exception error) when (error is IOException or CatalogConflictException)
        {
            Error.Foreground = (Brush)FindResource("DangerBrush");
            Error.Text = error.Message;
        }
        finally
        {
            IsEnabled = true;
        }
    }

    private async Task<bool> Rejected(Action undo)
    {
        // The engine compiles the saved catalog; a change it rejects is undone before anything captures with it.
        if (!engineChecks || await CatalogValidator.Check(store!.Path, store.PointerSize) is not { } problem) return false;
        undo();
        Error.Foreground = (Brush)FindResource("DangerBrush");
        Error.Text = $"The capture engine rejected the change, so it was undone: {problem}";
        return true;
    }

    private void Saved(string message)
    {
        if (string.Equals(store!.Path, Path.GetFullPath(DefaultPath), StringComparison.OrdinalIgnoreCase))
            ApiMetadata.Refresh();
        Error.Foreground = (Brush)FindResource("MutedBrush");
        Error.Text = message + " New captures use it.";
    }

    private bool Discard()
    {
        // Leaving a changed form asks before its edits are lost.
        var edited = FunctionChanged() ? function!.Name : typeName is not null && saveType.IsEnabled ? typeName : null;
        if (edited is null) return true;
        var discard = MessageBox.Show(this, $"Discard unsaved changes to {edited}?", "API catalog",
            MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes;
        if (discard)
        {
            ShowFunction(function);
            ShowType(typeName, typeLayout);
        }
        return discard;
    }
}

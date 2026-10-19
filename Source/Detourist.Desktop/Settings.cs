using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Detourist.Desktop;

public sealed record FilterItem(long Id, string Label, long Target = 0)
{
    public override string ToString() => Label;
}

public sealed record TraceDiagnostic(long Target, string Message);

public sealed record TargetCoverage(long Target, long Pid, string Image, string State, long Installed,
    long Available, long Catalog, long NativeExports, string[] UnknownExports, long Win32Installed,
    long Win32Available, long Win32Catalog, long ComHooks, long ManagedState, long ManagedApis, long ModuleRefreshError,
    long InstructionState, long InstalledExports)
{
    public string Name => Path.GetFileName(Image);
    public string Engine => (InstructionState)InstructionState == Desktop.InstructionState.Inactive ? "Typed hooks" :
        (InstructionState)InstructionState == Desktop.InstructionState.Failed ? "Unavailable" : "Broad coverage";
    public string NativeSummary => $"{Installed:N0} / {Available:N0}";
    public string Win32Summary => $"{Win32Installed:N0} / {Win32Available:N0}";
    public string ManagedSummary => (ManagedRuntimeState)ManagedState switch
    {
        ManagedRuntimeState.Active => "Active",
        ManagedRuntimeState.Failed => ManagedApis > 0 ? "Partial" : "Unavailable",
        ManagedRuntimeState.Attaching => "Preparing",
        _ => "Not active"
    };

    public static TargetCoverage FromJson(JsonElement target)
    {
        target.TryGetProperty("nativeCoverage", out var coverage);
        target.TryGetProperty("win32Coverage", out var win32);
        return new(target.Number("id"), target.Number("pid"), target.Text("image"), target.Text("state"),
            coverage.Number("installed"), coverage.Number("available"), coverage.Number("catalog"),
            coverage.Number("nativeExports"),
            coverage.Items("unknownExports").Select(item => item.ToString()).ToArray(),
            win32.Number("installed"), win32.Number("available"), win32.Number("catalog"), target.Number("comHooks"),
            target.Number("managedState"), target.Number("managedApis"), target.Number("moduleRefreshError"),
            target.Number("instructionState"), target.Number("installedExports"));
    }
}

public sealed record ApiInfo(int Id, string Module, string Name, string Parameters, ulong Mask,
    int CategoryId, string Category)
{
    public static ApiInfo FromJson(JsonElement item, IReadOnlyDictionary<int, string> categoryNames) =>
        new((int)item.Number("id"), item.Text("module"),
        item.Text("name"), item.Text("parameters"), ulong.Parse(item.Text("mask"), CultureInfo.InvariantCulture),
        (int)item.Number("category"), categoryNames.GetValueOrDefault((int)item.Number("category"), "Unclassified"));
}

public sealed record CategoryInfo(int Id, string Name, string Description, ulong Mask)
{
    public static CategoryInfo FromJson(JsonElement item) => new((int)item.Number("id"), item.Text("name"),
        item.Text("description"), ulong.Parse(item.Text("mask"), CultureInfo.InvariantCulture));
}

public sealed record ColumnLayout(bool Visible, double Width, int Position);

public sealed record NoiseProfileInfo(string Name, string Description, string[] Apis)
{
    public override string ToString() => Name;
}

public sealed record LaunchTarget(string Executable, string Arguments, string WorkingDirectory = "",
    string ExpectedExitCodes = "");

public sealed class CaptureSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    public int BufferLimit { get; set; } = Protocol.DefaultBufferLimit;
    public uint TraceStopMiB { get; set; }
    public bool Stacks { get; set; }
    public string[] SymbolDirectories { get; set; } = [];
    public bool FollowChildren { get; set; } = true;
    public bool InstructionEngine { get; set; } = true;
    public bool FromAppOnCapture { get; set; }
    public string[] ExcludedApis { get; set; } = [];
    [JsonIgnore] public NoiseProfileInfo[] NoiseProfiles { get; set; } = [];
    public string[] DisabledSources { get; set; } = [];
    public string[] DisabledCategories { get; set; } = [];
    public string Order { get; set; } = "newest";
    public bool IndentNested { get; set; }
    public double[]? Window { get; set; }
    public double InspectorWidth { get; set; }
    public Dictionary<string, ColumnLayout> Columns { get; set; } = [];
    public bool Timeline { get; set; } = true;
    public string TraceFolder { get; set; } = "";
    public string[] RecentTraces { get; set; } = [];
    public LaunchTarget[] RecentTargets { get; set; } = [];
    public string[] RecentFilters { get; set; } = [];
    public string[] SavedFilters { get; set; } = [];
    public string[] Highlights { get; set; } = [];
    [JsonIgnore] public ulong ApiMask { get; set; }
    [JsonIgnore] public ulong CategoryMask { get; set; }
    [JsonIgnore] public ulong AllApis { get; private set; }
    [JsonIgnore] public ulong AllCategories { get; private set; }
    [JsonIgnore] public int EntryApi { get; set; } = -1;
    [JsonIgnore] public int ExitApi { get; set; } = -1;
    [JsonIgnore] public Dictionary<ulong, string> Sources { get; private set; } = [];
    [JsonIgnore] public Dictionary<ulong, string> Categories { get; private set; } = [];

    // Captures are saved beside the application's other local data until another folder is chosen.
    [JsonIgnore] public string TraceDirectory => TraceFolder.Length > 0 ? TraceFolder : DefaultTraceDirectory;
    private static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Detourist");
    public static string DefaultTraceDirectory => Path.Combine(DataDirectory, "Traces");

    // Puts an entry at the front of a most-recent list, dropping its earlier position and the oldest overflow.
    public static T[] Recent<T>(T[] items, T item, int limit) =>
        [.. items.Where(other => !Equals(other, item)).Prepend(item).Take(limit)];

    // An empty DETOURIST_SETTINGS keeps choices for the running session only.
    private static string? Location => Environment.GetEnvironmentVariable("DETOURIST_SETTINGS") is { } path ?
        path.Length == 0 ? null : path : Path.Combine(DataDirectory, "Desktop.json");

    public static CaptureSettings Load()
    {
        try
        {
            if (Location is { } path && File.Exists(path))
                return JsonSerializer.Deserialize<CaptureSettings>(File.ReadAllText(path)) ?? new();
        }
        catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException)
        {
        }
        return new();
    }

    public void Save()
    {
        // Sources and categories are stored by name so those added by a later catalog start enabled.
        if (Sources.Count > 0)
        {
            DisabledSources = [.. Sources.Where(source => (ApiMask & source.Key) == 0).Select(source => source.Value)];
            DisabledCategories = [.. Categories.Where(category => (CategoryMask & category.Key) == 0)
                .Select(category => category.Value)];
        }
        try
        {
            if (Location is not { } path) return;
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOptions));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static ulong Mask(IEnumerable<KeyValuePair<ulong, string>> entries) =>
        entries.Aggregate(0UL, (mask, entry) => mask | entry.Key);

    public void Resolve(ApiInfo[] catalog, CategoryInfo[] categories, ulong allApis, ulong allCategories)
    {
        AllApis = allApis;
        AllCategories = allCategories;
        Sources = catalog.GroupBy(api => api.Mask).ToDictionary(group => group.Key, group => group.Key switch
        {
            (ulong)ApiSourceMask.Native => "System API exports",
            (ulong)ApiSourceMask.Win32 => "Windows API exports",
            (ulong)ApiSourceMask.Win32u => "Window and graphics system calls",
            (ulong)ApiSourceMask.Com => "COM and WinRT interfaces",
            _ => group.First().Name
        });
        Sources[(ulong)ApiSourceMask.Managed] = ".NET framework methods";
        Sources[(ulong)ApiSourceMask.DirectSyscalls] = "Direct syscall instructions";
        Categories = categories.ToDictionary(category => category.Mask, category => category.Name);
        ApiMask = allApis & ~Mask(Sources.Where(source => DisabledSources.Contains(source.Value)));
        CategoryMask = allCategories & ~Mask(Categories.Where(category => DisabledCategories.Contains(category.Value)));
    }

    public void ApplyMode(string mode)
    {
        // Modes replace capture scope; the individual settings remain editable afterwards.
        InstructionEngine = mode == "broad";
        Stacks = true;
        ApiMask = AllApis;
        CategoryMask = mode == "io" ? Mask(Categories.Where(category => category.Value is
            "Files and storage" or "Registry" or "Processes and threads" or "Networking")) : AllCategories;
        ExcludedApis = mode == "broad" ? [] : NoiseProfiles.FirstOrDefault(profile =>
            profile.Name == "Runtime helpers")?.Apis.ToArray() ?? [];
        FromAppOnCapture = mode == "triage";
    }
}

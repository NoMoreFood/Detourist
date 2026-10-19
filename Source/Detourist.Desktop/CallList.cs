using System.Collections;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace Detourist.Desktop;

public sealed class CallItem : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    public static bool IndentNested { get; set; }

    // Elapsed times count from the start of the capture until a call is chosen as the reference.
    public static long Frequency { get; set; } = 1;
    public static long StartClock { get; set; }
    public static long Reference { get; set; }
    internal CallList? List { get; init; }
    internal long Generation { get; init; }
    public int Index { get; init; } = -1;
    public bool Loaded { get; private set; }
    public long Id { get; private set; }
    public long Target { get; private set; }
    public long Started { get; private set; }
    public long Pid { get; private set; }
    public long Tid { get; private set; }
    public int Api { get; private set; }
    public int Depth { get; private set; }
    public long Parent { get; private set; }
    public int Marks { get; private set; }
    public string Caller { get; private set; } = "";
    public string Name { get; private set; } = "";
    public string Module { get; private set; } = "";
    public string Category { get; private set; } = "";
    public int CategoryId { get; private set; }
    public string Summary { get; private set; } = "";
    public string Time { get; private set; } = "";
    public string Result { get; set; } = "";
    public string State { get; set; } = "";
    public long Flags { get; set; }
    public long Error { get; set; }
    public string FailureSummary { get; private set; } = "";
    public double DurationUs { get; set; }
    public double AdjustedDurationUs { get; set; } = -1;
    public double DeltaUs { get; private set; }
    public string Identity => Loaded ? $"{Pid} / {Tid}" : "";
    public string Function => Module.Length == 0 ? Name : $"{Path.GetFileNameWithoutExtension(Module)}!{Name}";
    public string FunctionText => !Loaded ? "…" : IndentNested && Depth > 0 ?
        new string(' ', Math.Min(Depth, 16) * 2) + Function : Function;
    public bool EntryOnly => (Flags & (long)EventFlags.Continuation) != 0;
    public bool IsRaw => (Flags & (long)EventFlags.RawArguments) != 0;
    public bool IsFailure => (Flags & (long)EventFlags.Failed) != 0;
    public string ReturnSummary => !Loaded ? "" : $"{State} · {Result} · thread LastError {Error}" +
        (FailureSummary.Length > 0 ? $" · {FailureSummary}" : "");

    // The result column already reports calls that are running, unwound or entry only.
    public string CaptureState => IsFailure ? "Failed" : IsRaw && State == "Returned" ? "Raw" :
        State is "Returned" or "Running" or "Unwound" or "Entry only" ? "" : State;
    public bool IsPending => Loaded && (DurationUs < 0 || (Flags & (long)EventFlags.AsyncPending) != 0) && !EntryOnly;
    public string Duration => !Loaded ? "" : EntryOnly ? "—" : DurationUs < 0 ? "…" : DurationUs.ToString("N1");
    public string AdjustedDuration => !Loaded ? "" : AdjustedDurationUs < 0 ? "—" :
        AdjustedDurationUs.ToString("N1");
    public string ResultDisplay => !Loaded ? "" : EntryOnly ? "Entry only" :
        (Flags & (long)EventFlags.Unwound) != 0 ? "Unwound" :
        DurationUs < 0 ? "Running" : IsFailure ? Result + " !" +
            (FailureSummary.Length > 0 ? $" ({FailureSummary})" : "") : Result;
    public string Delta => Loaded ? DeltaUs.ToString("N1") : "";
    public string PidText => Loaded ? Pid.ToString() : "";
    public string TidText => Loaded ? Tid.ToString() : "";
    public string IdText => Loaded ? Id.ToString() : "";
    public string DepthText => Loaded ? Depth.ToString() : "";
    public double ElapsedSeconds => (Started - (Reference != 0 ? Reference : StartClock)) / (double)Frequency;
    public string Elapsed => Loaded ? ElapsedSeconds.ToString("N6") : "";

    // The find text takes the first mark; highlight rules follow in their saved order.
    public int MarkSlot => Marks == 0 ? 0 : BitOperations.TrailingZeroCount(Marks) + 1;

    public void Load(JsonElement item)
    {
        Id = item.Number("id");
        Target = item.Number("target");
        Started = item.Number("started");
        Pid = item.Number("pid");
        Tid = item.Number("tid");
        Api = (int)item.Number("api");
        Depth = (int)item.Number("depth");
        Parent = item.Number("parent");
        Marks = (int)item.Number("marks");
        Caller = item.Text("callerDisplay", item.Text("callerText"));
        Name = item.Text("name");
        Module = item.Text("module");
        Category = item.Text("categoryName");
        CategoryId = (int)item.Number("category");
        Time = item.Text("time");
        using (ApiMetadata.UsePointerSize((int)item.Number("pointerSize", 8)))
            Summary = ArgumentText.Decode(Name, Module, item.Text("summary"));
        Result = item.Text("result");
        State = item.Text("state");
        Flags = item.Number("flags");
        Error = item.Number("error");
        DurationUs = item.Decimal("durationUs", -1);
        AdjustedDurationUs = item.Decimal("adjustedDurationUs", -1);
        DeltaUs = item.Decimal("deltaUs");
        Loaded = true;
        DescribeFailure(item);
        Refresh();
    }

    public void DescribeFailure(JsonElement item)
    {
        // A failed status return takes precedence over LastError, which may belong to an earlier call.
        FailureSummary = "";
        if (!IsFailure || EntryOnly || DurationUs < 0 || (Flags & (long)EventFlags.Unwound) != 0) return;
        if (item.TryGetProperty("completion", out var completion))
        {
            if (completion.Number("domain") == (long)AsyncIoDomain.Rpc) return;
            FailureSummary = ApiMetadata.ErrorMessage(
                completion.Number("domain") == (long)AsyncIoDomain.NtStatus ? "NTSTATUS" : "DWORD",
                ParameterType.ParseHex(completion.Text("status")));
            return;
        }
        if ((Flags & (long)EventFlags.AsyncCompleted) != 0) return;
        string? type = null;
        try
        {
            using var architecture = ApiMetadata.UsePointerSize((int)item.Number("pointerSize", 8));
            type = ApiMetadata.Function(Name, Module, item.Text("parameters"))?.Result;
        }
        catch (Exception)
        {
        }
        if (type is "NTSTATUS" or "HRESULT" or "LSTATUS" or "WIN32_ERROR" or "NET_API_STATUS" or
            "RPC_STATUS" or "DNS_STATUS" or "SECURITY_STATUS")
        {
            if (ulong.TryParse(Result.AsSpan(Result.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? 2 : 0),
                NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code))
                FailureSummary = ApiMetadata.ErrorMessage(type, code);
        }
        else if (Error != 0) FailureSummary = ApiMetadata.ErrorMessage("DWORD", (ulong)Error);
    }

    // Carries an inspected call into a new position before that position's block has loaded.
    public void Copy(CallItem other)
    {
        (Id, Target, Started, Pid, Tid, Api, Depth) = (other.Id, other.Target, other.Started, other.Pid, other.Tid,
            other.Api, other.Depth);
        (Parent, Marks, Caller) = (other.Parent, other.Marks, other.Caller);
        (Name, Module, Category, CategoryId, Summary, Time) = (other.Name, other.Module, other.Category,
            other.CategoryId, other.Summary, other.Time);
        (Result, State, Flags, Error, DurationUs, DeltaUs) = (other.Result, other.State, other.Flags, other.Error,
            other.DurationUs, other.DeltaUs);
        AdjustedDurationUs = other.AdjustedDurationUs;
        FailureSummary = other.FailureSummary;
        Loaded = other.Loaded;
        Refresh();
    }

    public void Refresh() => PropertyChanged?.Invoke(this, new(string.Empty));

    public static CallItem FromJson(JsonElement item)
    {
        var call = new CallItem();
        call.Load(item);
        return call;
    }
}

// Presents a collector view as a list whose rows load in blocks when they are displayed.
public sealed class CallList : IList, INotifyCollectionChanged
{
    public const int BlockSize = 128;
    private const int RetainedBlocks = 64;
    private sealed class Block
    {
        public required CallItem[] Items;
        public long Used;
        public long Epoch;
    }
    private readonly Dictionary<int, Block> blocks = [];
    private readonly List<int> requests = [];
    private long generation;
    private long clock;
    private long epoch;
    public event NotifyCollectionChangedEventHandler? CollectionChanged;
    public event Action? BlockRequested;
    public int Count { get; private set; }
    public bool IsFixedSize => false;
    public bool IsReadOnly => true;
    public bool IsSynchronized => false;
    public object SyncRoot => this;

    // The inspected call keeps its identity when its block leaves the cache and loads again.
    public CallItem? Pinned { get; set; }
    public object? this[int index]
    {
        get => At(index);
        set => throw new NotSupportedException();
    }

    public CallItem At(int index) => (uint)index >= (uint)Count ? new() :
        Load(index / BlockSize, true).Items[index % BlockSize];

    // Reads a row only when it is already loaded, without asking for its block.
    public CallItem? Peek(int index) => (uint)index < (uint)Count &&
        blocks.TryGetValue(index / BlockSize, out var block) && block.Items[index % BlockSize].Loaded ?
        block.Items[index % BlockSize] : null;

    // Loads the displayed rows again in place; other cached rows reload when they are next shown.
    public void Reload(int first, int last)
    {
        ++epoch;
        for (var number = Math.Max(0, first) / BlockSize; number <= Math.Min(last, Count - 1) / BlockSize; ++number)
        {
            if (!blocks.TryGetValue(number, out var block)) continue;
            block.Epoch = epoch;
            Request(number);
        }
    }

    private Block Load(int number, bool request)
    {
        if (!blocks.TryGetValue(number, out var block))
        {
            // Rows appear immediately as placeholders and fill in place when their block arrives.
            block = new() { Items = new CallItem[BlockSize], Epoch = epoch };
            for (var slot = 0; slot < BlockSize; ++slot)
                block.Items[slot] = new() { List = this, Generation = generation, Index = number * BlockSize + slot };
            if (Pinned is { } pinned && pinned.List == this && pinned.Generation == generation &&
                pinned.Index / BlockSize == number) block.Items[pinned.Index % BlockSize] = pinned;
            if (blocks.Count >= RetainedBlocks) blocks.Remove(blocks.MinBy(pair => pair.Value.Used).Key);
            blocks[number] = block;
            if (request) Request(number);
        }
        else if (request && block.Epoch != epoch)
        {
            // Rows cached before the latest update reload in place when they are displayed again.
            block.Epoch = epoch;
            Request(number);
        }
        block.Used = ++clock;
        return block;
    }

    private void Request(int number)
    {
        requests.Remove(number);
        requests.Add(number);
        BlockRequested?.Invoke();
    }

    // The most recently displayed block loads first; blocks that left the cache are skipped.
    public int? NextRequest()
    {
        while (requests.Count > 0)
        {
            var number = requests[^1];
            requests.RemoveAt(requests.Count - 1);
            if (blocks.ContainsKey(number)) return number;
        }
        return null;
    }

    public void Fill(int number, JsonElement[] calls)
    {
        if (blocks.TryGetValue(number, out var block) && Fill(block, calls))
            CollectionChanged?.Invoke(this, new(NotifyCollectionChangedAction.Reset));
    }

    public void Retry(int number)
    {
        if (blocks.ContainsKey(number)) Request(number);
    }

    private bool Fill(Block block, JsonElement[] calls)
    {
        var replaced = false;
        for (var slot = 0; slot < Math.Min(calls.Length, BlockSize); ++slot)
        {
            // A position that now holds a different call gets a new item so a selection never changes identity.
            var current = block.Items[slot];
            if (current.Loaded && (current.Target != calls[slot].Number("target") ||
                current.Id != calls[slot].Number("id")))
            {
                current = block.Items[slot] = new() { List = this, Generation = generation, Index = current.Index };
                replaced = true;
            }
            current.Load(calls[slot]);
        }
        return replaced;
    }

    public CallItem Adopt(int index, CallItem call)
    {
        var item = At(index);
        if (item != call && !item.Loaded) item.Copy(call);
        return item;
    }

    // Appended calls keep loaded rows; any other change reloads them, and supplied blocks are in place first.
    public void Resize(int count, bool keep, Dictionary<int, JsonElement[]>? loaded = null)
    {
        var changed = !keep || count != Count;
        if (!keep)
        {
            ++generation;
            blocks.Clear();
            requests.Clear();
        }
        if (loaded is not null) ++epoch;
        Count = count;
        foreach (var (number, rows) in loaded ?? [])
        {
            if ((long)number * BlockSize >= count) continue;
            var block = Load(number, false);
            block.Epoch = epoch;
            requests.Remove(number);
            changed |= Fill(block, rows);
        }
        if (changed) CollectionChanged?.Invoke(this, new(NotifyCollectionChangedAction.Reset));
    }

    public int IndexOf(object? value) => value is CallItem call && call.List == this && call.Generation == generation &&
        call.Index < Count && (!blocks.TryGetValue(call.Index / BlockSize, out var block) ||
            block.Items[call.Index % BlockSize] == call) ? call.Index : -1;
    public bool Contains(object? value) => IndexOf(value) >= 0;

    // Enumeration reports loaded rows only; walking a large view must not request every block.
    public IEnumerator GetEnumerator() => blocks.OrderBy(pair => pair.Key).SelectMany(pair => pair.Value.Items)
        .Where(call => call.Loaded && call.Index < Count).ToArray().GetEnumerator();
    public void CopyTo(Array array, int index)
    {
        for (var position = 0; position < Count; ++position) array.SetValue(At(position), index + position);
    }
    public int Add(object? value) => throw new NotSupportedException();
    public void Clear() => throw new NotSupportedException();
    public void Insert(int index, object? value) => throw new NotSupportedException();
    public void Remove(object? value) => throw new NotSupportedException();
    public void RemoveAt(int index) => throw new NotSupportedException();
}

// One API's share of the listed calls.
public sealed record SummaryItem(string Module, string Name, string Category, long Calls, long Failed, long Returned,
    double TotalUs, double LongestUs, long Listed)
{
    public string Function => Module.Length == 0 ? Name : $"{Path.GetFileNameWithoutExtension(Module)}!{Name}";
    public double Share => Listed > 0 ? Calls * 100.0 / Listed : 0;
    public double TotalMs => TotalUs / 1000;
    public double AverageUs => Returned > 0 ? TotalUs / Returned : 0;
    public string CallsText => Calls.ToString("N0");
    public string ShareText => Share.ToString("N1");
    public string FailedText => Failed > 0 ? Failed.ToString("N0") : "";
    public string TotalText => Returned > 0 ? TotalMs.ToString("N1") : "";
    public string AverageText => Returned > 0 ? AverageUs.ToString("N1") : "";
    public string LongestText => Returned > 0 ? LongestUs.ToString("N1") : "";

    public static SummaryItem FromJson(JsonElement item, long listed) => new(item.Text("module"), item.Text("name"),
        item.Text("categoryName"), item.Number("calls"), item.Number("failed"), item.Number("returned"),
        item.Decimal("totalUs"), item.Decimal("longestUs"), listed);
}

// Names enumeration arguments in a call summary using the choices their signatures define.
public static class ArgumentText
{
    private static readonly Dictionary<(int, string, string), (string Prefix, EnumValue[] Choices)[]> known = [];
    private static long revision;

    public static string Decode(string name, string module, string summary)
    {
        if (summary.Length == 0) return summary;
        if (revision != ApiMetadata.Revision)
        {
            known.Clear();
            revision = ApiMetadata.Revision;
        }
        var key = (ApiMetadata.PointerSize, module, name);
        if (!known.TryGetValue(key, out var parameters))
        {
            // Each API's enumeration parameters are resolved once; an unavailable catalog leaves values numeric.
            try
            {
                parameters = [.. (ApiMetadata.Function(name, module)?.Parameters ?? [])
                    .Select(parameter => (Prefix: parameter.Name + "=0x", Type: ParameterType.Infer(parameter.Type)))
                    .Where(parameter => parameter.Type.Kind == "Enum" && parameter.Type.Choices.Length > 0)
                    .Select(parameter => (parameter.Prefix, parameter.Type.Choices))];
            }
            catch (Exception)
            {
                parameters = [];
            }
            known[key] = parameters;
        }
        foreach (var (prefix, choices) in parameters)
        {
            var start = summary.IndexOf(prefix, StringComparison.Ordinal);
            if (start < 0 || (start > 0 && !summary.AsSpan(0, start).EndsWith(", "))) continue;
            var digits = start + prefix.Length;
            var end = digits;
            while (end < summary.Length && Uri.IsHexDigit(summary[end])) ++end;
            if ((end < summary.Length && summary[end] != ',') || !ulong.TryParse(summary.AsSpan(digits, end - digits),
                NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value)) continue;
            if (choices.FirstOrDefault(choice => choice.Value == value) is { } choice)
                summary = string.Concat(summary.AsSpan(0, digits - 2), choice.Name, summary.AsSpan(end));
        }
        return summary;
    }
}

// Draws how densely listed calls fall across the capture, where they failed and which span is displayed.
public sealed class CallTimeline : FrameworkElement
{
    private static readonly Brush Bars = Frozen(new SolidColorBrush(Color.FromArgb(0xB0, 0x53, 0x9B, 0xDB)));
    private static readonly Brush Failures = Frozen(new SolidColorBrush(Color.FromRgb(0xF2, 0x8B, 0x82)));
    private static readonly Brush Span = Frozen(new SolidColorBrush(Color.FromArgb(0x30, 0xFF, 0xFF, 0xFF)));
    private static readonly Pen SpanEdge = Frozen(new Pen(new SolidColorBrush(Color.FromRgb(0xDA, 0xDC, 0xE0)), 1));
    private double[] calls = [];
    private double[] failures = [];
    private long begin;
    private long end;
    private long first;
    private long last;
    public event Action<long>? Seek;
    public bool HasData => calls.Length > 0 && end > begin;

    private static T Frozen<T>(T value) where T : Freezable
    {
        value.Freeze();
        return value;
    }

    public void Update(double[] density, double[] failed, long from, long to)
    {
        (calls, failures, begin, end) = (density, failed, from, to);
        InvalidateVisual();
    }

    // Marks the span between the first and last displayed call; zero clears the mark.
    public void Show(long from, long to)
    {
        if (first == from && last == to) return;
        (first, last) = (from, to);
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext context)
    {
        // The transparent ground makes the whole strip respond to the pointer.
        var (width, height) = (ActualWidth, ActualHeight);
        context.DrawRectangle(Brushes.Transparent, null, new(0, 0, width, height));
        if (!HasData || width < 4 || height < 8) return;
        var peak = calls.Max();
        var slot = width / calls.Length;
        for (var index = 0; index < calls.Length && peak > 0; ++index)
        {
            // A square-root scale keeps sparse stretches visible beside bursts.
            if (calls[index] > 0)
            {
                var bar = Math.Max(1.5, Math.Sqrt(calls[index] / peak) * (height - 5));
                context.DrawRectangle(Bars, null, new(index * slot, height - 3 - bar, Math.Max(1, slot - 0.5), bar));
            }
            if (index < failures.Length && failures[index] > 0)
                context.DrawRectangle(Failures, null, new(index * slot, height - 3, Math.Max(1, slot - 0.5), 3));
        }
        if (first == 0 || last == 0) return;
        double Position(long clock) => Math.Clamp((clock - begin) / (double)(end - begin), 0, 1) * width;
        var (left, right) = (Math.Min(Position(first), Position(last)), Math.Max(Position(first), Position(last)));
        context.DrawRectangle(Span, SpanEdge,
            new(Math.Min(left, width - 3) + 0.5, 0.5, Math.Max(2, right - left), height - 1));
    }

    private long Clock(MouseEventArgs e) => begin + (long)((end - begin) *
        Math.Clamp(e.GetPosition(this).X / Math.Max(1, ActualWidth), 0, 1));

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        if (HasData) Seek?.Invoke(Clock(e));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        if (!HasData) return;
        var index = Math.Clamp((int)(e.GetPosition(this).X / Math.Max(1, ActualWidth) * calls.Length), 0,
            calls.Length - 1);
        var seconds = (Clock(e) - CallItem.StartClock) / (double)CallItem.Frequency;
        ToolTip = $"{seconds:N3} s · about {calls[index]:N0} calls" + (index < failures.Length && failures[index] > 0 ?
            $" · {failures[index]:N0} failed" : "") + "\nClick to show the calls at this time.";
    }
}

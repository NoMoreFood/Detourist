using Microsoft.Win32;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace Detourist.Desktop;

public sealed record Suggestion(string Text, string Hint);
public sealed record StackFrameItem(int Index, string Address, string Display, string Path, string Source,
    long Line, bool Application)
{
    public string Location => Source.Length == 0 ? "" : $"{System.IO.Path.GetFileName(Source)}:{Line}";
}

internal static class ExportFile
{
    internal static async Task<bool> Write(string path, bool csv, Func<StreamWriter, Task> write,
        Func<bool>? complete = null)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        try
        {
            // Spreadsheet applications use the byte order mark to recognize UTF-8 CSV files.
            await using (var writer = new StreamWriter(stream, new UTF8Encoding(csv))) await write(writer);
            if (complete is not null && !complete()) return false;
            File.Move(temporary, path, true);
            return true;
        }
        finally { File.Delete(temporary); }
    }

    internal static string CsvField(string value)
    {
        // Spreadsheet applications can interpret formulas after leading whitespace.
        var content = value.AsSpan().TrimStart();
        if (!content.IsEmpty && content[0] is '=' or '+' or '-' or '@') value = "'" + value;
        return value.IndexOfAny([',', '"', '\n', '\r']) < 0 ? value : "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}

// Finding, highlighting, summarizing, exporting and navigating the listed calls.
public partial class MainWindow
{
    private static readonly string[] HighlightColors =
        ["#1F4A3A", "#4A2A4F", "#1F3F5C", "#5A3320", "#3F4A1F", "#4F2630"];
    private static readonly Suggestion[] FilterKeys =
    [
        new("tid:", "thread"), new("pid:", "process"), new("id:", "call"), new("result:", "return value"),
        new("error:", "thread LastError"), new("duration>", "elapsed time, in us, ms or s"),
        new("duration<", "shorter than, in us, ms or s"),
        new("adjusted>", "time excluding capture work, in us, ms or s"),
        new("adjusted<", "shorter adjusted time, in us, ms or s"), new("depth:", "nesting level"),
        new("caller:", "caller address or range"), new("text:", "captured strings"), new("arg:", "argument value"),
        new("value:", "argument or return value"), new("from:", "module that made the call"),
        new("from:app", "calls made by the application's own modules"),
        new("after:", "seconds since the capture started"), new("before:", "seconds since the capture started"),
        new("under:", "calls nested in a call"), new("parent:", "direct children of a call"),
        new("module:", "API module"), new("name:", "API name")
    ];
    private const int TimelineDebounceMs = 150;
    private const int RecentFilterLimit = 12;
    private const int SearchSuggestionLimit = 8;
    private readonly DispatcherTimer findTimer = new() { Interval = TimeSpan.FromMilliseconds(Protocol.UiDebounceMs) };
    private readonly DispatcherTimer timelineTimer = new() { Interval = TimeSpan.FromMilliseconds(TimelineDebounceMs) };
    private string[] apiNames = [];
    private string findError = "";
    private string summaryText = "";
    private CallView? foundView;
    private long findGeneration;
    private long modules;
    private bool summarizing;
    private bool exporting;
    private bool cancelExport;
    private DateTime nextTimeline;
    private DateTime nextSummary;
    private CallItem? compared;

    private void ResetTools()
    {
        ++findGeneration;
        foundView?.Dispose();
        foundView = null;
        findError = summaryText = FindStatus.Text = "";
        nextSummary = DateTime.MinValue;
        FindNextButton.IsEnabled = FindPreviousButton.IsEnabled = false;
        SummaryCheck.IsChecked = FromAppCheck.IsChecked = false;
        SummaryGrid.ItemsSource = null;
        SummaryGrid.Visibility = TimelinePanel.Visibility = Visibility.Collapsed;
        CallsGrid.Visibility = Visibility.Visible;
        Timeline.Update([], [], 0, 0);
        SuggestPopup.IsOpen = false;
        compared = null;
        CallItem.Reference = modules = 0;
        FromAppCheck.IsEnabled = false;
    }

    private async Task RefreshTools()
    {
        // Everything derived from the listed calls follows a newly indexed view.
        try
        {
            var text = ApiSearch.Text.Trim();
            if (text.Length > 0) settings.RecentFilters = CaptureSettings.Recent(settings.RecentFilters, text, RecentFilterLimit);
            await RefreshFind(false);
            await RefreshTimeline();
            await RefreshSummary();
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException)
        {
        }
    }

    // Splits a filter into its terms, keeping quoted spaces inside one term.
    private static List<string> Terms(string filter)
    {
        var terms = new List<string>();
        var term = new StringBuilder();
        var quoted = false;
        foreach (var character in filter + " ")
        {
            if (character == '"') quoted = !quoted;
            if (quoted || !char.IsWhiteSpace(character)) term.Append(character);
            else if (term.Length > 0)
            {
                terms.Add(term.ToString());
                term.Clear();
            }
        }
        return terms;
    }

    // Replaces the filter terms that begin with a key, or removes them when no replacement is given.
    private void SetTerm(string key, string? term)
    {
        var terms = Terms(ApiSearch.Text).Where(existing =>
            !existing.StartsWith(key, StringComparison.OrdinalIgnoreCase)).ToList();
        if (term is not null) terms.Add(term);
        ApiSearch.Text = string.Join(' ', terms);
    }

    private static string ExactApi(string name) => name.Contains(' ') ? $"\"={name}\"" : "=" + name;

    private void FromAppChanged(object sender, RoutedEventArgs e)
    {
        if (!updating && IsLoaded) SetTerm("from:app", FromAppCheck.IsChecked == true ? "from:app" : null);
    }

    private async Task ApplyMarks(bool reload)
    {
        // The find text and saved highlights tag rows in the collector; text that does not compile tags none.
        if (activeView is not { Id: not 0 } owner) return;
        string[] marks = [FindBar.Visibility == Visibility.Visible ? FindText.Text.Trim() : "", .. settings.Highlights];
        if (!reload && marks.All(mark => mark.Length == 0)) return;
        var generation = viewGeneration;
        findError = "";
        try
        {
            await owner.Mark(marks);
        }
        catch (IOException error) when (error.Message.StartsWith("Filter", StringComparison.Ordinal))
        {
            findError = error.Message;
        }
        if (generation != viewGeneration || !reload) return;
        var (first, last) = VisibleRange();
        calls.Reload(first - CallList.BlockSize, last + CallList.BlockSize);
    }

    private void OpenFind()
    {
        FindBar.Visibility = Visibility.Visible;
        FindText.Focus();
        FindText.SelectAll();
        if (FindText.Text.Length > 0) _ = RefreshFind(true);
    }

    private void ShowFind(object sender, RoutedEventArgs e) => OpenFind();

    private void CloseFind(object sender, RoutedEventArgs e)
    {
        FindBar.Visibility = Visibility.Collapsed;
        _ = RefreshFind(true);
        FocusCall();
    }

    private void FindChanged(object sender, TextChangedEventArgs e)
    {
        if (updating || !IsLoaded) return;
        findTimer.Stop();
        findTimer.Start();
    }

    private async Task RefreshFind(bool mark)
    {
        // Matches are counted and stepped through in a second view that adds the find text to the display filters.
        findTimer.Stop();
        var generation = ++findGeneration;
        foundView?.Dispose();
        foundView = null;
        FindNextButton.IsEnabled = FindPreviousButton.IsEnabled = false;
        try
        {
            if (mark) await ApplyMarks(true);
            if (generation != findGeneration) return;
            var text = FindBar.Visibility == Visibility.Visible ? FindText.Text.Trim() : "";
            FindStatus.Foreground = (Brush)FindResource(findError.Length > 0 ? "DangerBrush" : "MutedBrush");
            FindStatus.Text = findError;
            if (client is null || view == 0 || !viewComplete || text.Length == 0 || findError.Length > 0) return;
            var request = ViewRequest();
            request["filter"] = (ApiSearch.Text + " " + text).Trim();
            var owner = foundView = new CallView(client);
            var state = await owner.Open(request);
            while (!state.Flag("complete") && generation == findGeneration && !closing)
            {
                FindStatus.Text = $"{state.Number("count"):N0}+ matches…";
                state = await owner.Advance(metadata: false);
            }
            if (generation != findGeneration || closing)
            {
                owner.Dispose();
                return;
            }
            ShowMatches(state.Number("count"));
        }
        catch (IOException error)
        {
            if (generation != findGeneration) return;
            FindStatus.Foreground = (Brush)FindResource("DangerBrush");
            FindStatus.Text = error.Message;
        }
    }

    private void ShowMatches(long count)
    {
        FindStatus.Text = count == 0 ? "No matches" : $"{count:N0} {(count == 1 ? "match" : "matches")}";
        FindNextButton.IsEnabled = FindPreviousButton.IsEnabled = count > 0;
    }

    private async void FindNext(object sender, RoutedEventArgs e) => await Step(true);
    private async void FindPrevious(object sender, RoutedEventArgs e) => await Step(false);

    private async Task Step(bool forward)
    {
        // Typing is applied before stepping; a live capture first picks up the matches recorded since.
        if (client is null || view == 0) return;
        try
        {
            if (findTimer.IsEnabled) await RefreshFind(true);
            if (foundView is not { Id: not 0 } owner) return;
            var generation = findGeneration;
            if (live)
            {
                var state = await owner.Advance(extend: Order == "oldest" || Following, metadata: false);
                if (generation != findGeneration) return;
                ShowMatches(state.Number("count"));
            }
            var match = await owner.Query("seek", new
            {
                target = selected?.Target ?? 0, callId = selected?.Id ?? 0, forward
            });
            if (generation != findGeneration || !owner.IsCurrent(match) || match.Number("index", -1) < 0) return;
            if (await Reveal(match.Number("target"), match.Number("callId"), "That match is outside the listed calls."))
                FindStatus.Text = $"{match.Number("index") + 1:N0} of {match.Number("count"):N0}";
        }
        catch (IOException error)
        {
            ShowError(error.Message);
        }
    }

    private async Task<bool> Reveal(long target, long callId, string missing)
    {
        // Selects a call wherever it sits in the list; a call the display filters hide is reported instead.
        if (activeView is not { Id: not 0 } owner) return false;
        var generation = viewGeneration;
        var result = await owner.Query("locate", new { target, callId });
        if (generation != viewGeneration || !owner.IsCurrent(result)) return false;
        var index = (int)result.Number("index", -1);
        if (index < 0 || index >= calls.Count)
        {
            StatusText.Text = missing;
            return false;
        }
        var item = calls.At(index);
        CallsGrid.SelectedItem = item;
        CallsGrid.ScrollIntoView(item);
        return true;
    }

    private void ShowHighlights(object sender, RoutedEventArgs e)
    {
        // Each rule keeps its color for as long as it stays in the list.
        var menu = ToolbarMenu(HighlightButton);
        var text = FindText.Text.Trim();
        AddMenuItem(menu, "Highlight Find Text", () => SetHighlights([.. settings.Highlights, text]),
            text.Length > 0 && findError.Length == 0 && !settings.Highlights.Contains(text) &&
            settings.Highlights.Length < HighlightColors.Length);
        if (settings.Highlights.Length > 0) menu.Items.Add(new Separator());
        foreach (var (rule, index) in settings.Highlights.Select((rule, index) => (rule, index)))
        {
            var label = new StackPanel { Orientation = Orientation.Horizontal };
            label.Children.Add(new Border
            {
                Width = 12, Height = 12, Margin = new(0, 0, 8, 0), BorderThickness = new(1),
                Background = (Brush)new BrushConverter().ConvertFromString(HighlightColors[index])!,
                BorderBrush = (Brush)FindResource("MutedBrush")
            });
            label.Children.Add(new TextBlock { Text = "Remove: " + rule });
            var remove = new MenuItem { Header = label };
            remove.Click += (_, _) => SetHighlights([.. settings.Highlights.Where(other => other != rule)]);
            menu.Items.Add(remove);
        }
        menu.IsOpen = true;
    }

    private void SetHighlights(string[] rules)
    {
        settings.Highlights = rules;
        settings.Save();
        _ = ApplyMarks(true);
    }

    private void TimelineResized(object sender, SizeChangedEventArgs e)
    {
        timelineTimer.Stop();
        timelineTimer.Start();
    }

    private async Task RefreshTimeline()
    {
        // The strip follows the listed calls; a ranking by duration has no time order to draw.
        timelineTimer.Stop();
        var shown = settings.Timeline && view != 0 && Order != "slowest" && SummaryCheck.IsChecked != true &&
            calls.Count > 0;
        TimelinePanel.Visibility = shown ? Visibility.Visible : Visibility.Collapsed;
        if (!shown || activeView is not { } owner) return;
        nextTimeline = DateTime.UtcNow.AddSeconds(1);
        var generation = viewGeneration;
        var width = Timeline.ActualWidth > 0 ? Timeline.ActualWidth : CallsGrid.ActualWidth - 12;
        try
        {
            var density = await owner.Query("timeline", new { buckets = Math.Clamp((int)(width / 3), 40, 600) });
            if (generation != viewGeneration || !owner.IsCurrent(density)) return;
            Timeline.Update([.. density.Items("calls").Select(value => value.GetDouble())],
                [.. density.Items("failures").Select(value => value.GetDouble())], density.Number("begin"),
                density.Number("end"));
            ShowSpan();
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException)
        {
            if (generation == viewGeneration && !closing) ShowError(error.Message);
        }
    }

    private void ShowSpan()
    {
        // Mark the stretch of the capture that the displayed rows cover.
        if (TimelinePanel.Visibility != Visibility.Visible) return;
        var (first, last) = VisibleRange();
        var top = calls.Peek(first);
        Timeline.Show(top?.Started ?? 0, (calls.Peek(Math.Min(last, calls.Count) - 1) ?? top)?.Started ?? 0);
    }

    private async Task SeekTime(long clock)
    {
        // A chosen moment belongs to the current filters, including text still waiting to be applied.
        var ready = searchTimer.IsEnabled ? RefreshView() : openingView;
        var generation = viewGeneration;
        try
        {
            // Indexing and selection restoration finish before the chosen row is brought into view.
            await ready;
            if (generation != viewGeneration || activeView is not { Id: not 0 } owner || closing) return;
            var result = await owner.Query("locate", new { time = clock });
            var index = result.Number("index", -1);
            if (generation != viewGeneration || !owner.IsCurrent(result) || index < 0 || index >= calls.Count) return;
            PauseFollowing();
            CallsGrid.ScrollIntoView(calls.At((int)index));
        }
        catch (Exception error)
        {
            if (!closing) ShowError(error.Message);
        }
    }

    private async void SummaryChanged(object sender, RoutedEventArgs e)
    {
        if (updating || !IsLoaded) return;
        var shown = SummaryCheck.IsChecked == true;
        SummaryGrid.Visibility = shown ? Visibility.Visible : Visibility.Collapsed;
        CallsGrid.Visibility = shown ? Visibility.Collapsed : Visibility.Visible;
        summaryText = "";
        nextSummary = DateTime.MinValue;
        UpdateResults();
        try
        {
            await RefreshTimeline();
            await RefreshSummary();
        }
        catch (IOException error)
        {
            ShowError(error.Message);
        }
    }

    private async Task RefreshSummary()
    {
        // Totals cover every listed call; the collector visits them in slices so the window stays responsive.
        if (activeView is not { Id: not 0, Complete: true } owner || summarizing ||
            SummaryCheck.IsChecked != true || DateTime.UtcNow < nextSummary) return;
        summarizing = true;
        nextSummary = DateTime.UtcNow.AddSeconds(3);
        var generation = viewGeneration;
        try
        {
            var state = await owner.Summarize(progress =>
            {
                if (generation != viewGeneration || SummaryCheck.IsChecked != true || closing) return false;
                summaryText = $"Summarizing… {progress * 100:N0}%";
                UpdateResults();
                return true;
            });
            if (generation != viewGeneration || state.Number("view") != owner.Id ||
                SummaryCheck.IsChecked != true || !state.Flag("complete")) return;
            var items = state.Items("items");
            var listed = items.Sum(item => item.Number("calls"));
            var rows = items.Select(item => SummaryItem.FromJson(item, listed)).OrderByDescending(item => item.Calls)
                .ToList();

            // A refreshed summary keeps the chosen ordering and row.
            var sorting = SummaryGrid.Items.SortDescriptions.ToArray();
            var directions = SummaryGrid.Columns.Select(column => column.SortDirection).ToArray();
            var chosen = SummaryGrid.SelectedItem as SummaryItem;
            SummaryGrid.ItemsSource = rows;
            foreach (var description in sorting) SummaryGrid.Items.SortDescriptions.Add(description);
            for (var index = 0; index < directions.Length; ++index)
                SummaryGrid.Columns[index].SortDirection = directions[index];
            SummaryGrid.SelectedItem = rows.FirstOrDefault(row => row.Module == chosen?.Module &&
                row.Name == chosen.Name);
            summaryText = $"{rows.Count:N0} {(rows.Count == 1 ? "API" : "APIs")} · {listed:N0} calls";
            nextSummary = DateTime.UtcNow.AddSeconds(3);
        }
        finally
        {
            summarizing = false;
            UpdateResults();
            if (nextSummary == DateTime.MinValue) _ = RefreshSummary();
        }
    }

    private void SummarySorting(object sender, DataGridSortingEventArgs e)
    {
        // Numeric columns rank their largest values first on the first click.
        if (e.Column.SortDirection is not null || e.Column.SortMemberPath is "Function" or "Category") return;
        e.Handled = true;
        foreach (var column in SummaryGrid.Columns) column.SortDirection = null;
        SummaryGrid.Items.SortDescriptions.Clear();
        SummaryGrid.Items.SortDescriptions.Add(new(e.Column.SortMemberPath, ListSortDirection.Descending));
        e.Column.SortDirection = ListSortDirection.Descending;
    }

    private void ShowSummaryApi(bool hide)
    {
        // Narrowing to one API returns to its calls; hiding one keeps the summary open.
        if (SummaryGrid.SelectedItem is not SummaryItem item) return;
        var module = Path.GetFileNameWithoutExtension(item.Module);
        var term = (module.Length > 0 && !module.Contains(' ') ? module + "!=" : "=") + item.Name;
        if (term.Contains(' ')) term = $"\"{term}\"";
        ApiSearch.Text = (ApiSearch.Text.Trim() + (hide ? " -" : " ") + term).Trim();
        if (!hide) SummaryCheck.IsChecked = false;
    }

    private void SummaryActivated(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject source &&
            ItemsControl.ContainerFromElement(SummaryGrid, source) is DataGridRow) ShowSummaryApi(false);
    }

    private void SummaryKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        e.Handled = true;
        ShowSummaryApi(false);
    }

    private static ContextMenu ToolbarMenu(FrameworkElement target) =>
        new() { PlacementTarget = target, Placement = PlacementMode.Bottom };

    private static MenuItem AddMenuItem(ContextMenu menu, string header, Action action, bool enabled = true,
        string? tip = null)
    {
        var item = new MenuItem { Header = header.Replace("_", "__"), IsEnabled = enabled, ToolTip = tip };
        item.Click += (_, _) => action();
        menu.Items.Add(item);
        return item;
    }

    private void SummaryContextOpening(object sender, ContextMenuEventArgs e)
    {
        ToolWindow.SelectContextRow(sender, e);
        if (SummaryGrid.SelectedItem is not SummaryItem item)
        {
            e.Handled = true;
            return;
        }
        var menu = new ContextMenu();
        static string Line(SummaryItem row) => string.Join('\t', row.Function, row.Calls, row.Failed,
            row.TotalMs.ToString("F1", CultureInfo.InvariantCulture),
            row.AverageUs.ToString("F1", CultureInfo.InvariantCulture),
            row.LongestUs.ToString("F1", CultureInfo.InvariantCulture), row.Category);
        AddMenuItem(menu, $"Show Only API: {item.Name}", () => ShowSummaryApi(false));
        AddMenuItem(menu, $"Hide API: {item.Name}", () => ShowSummaryApi(true));
        menu.Items.Add(new Separator());
        AddMenuItem(menu, "Copy Row", () => Copy(Line(item)));
        AddMenuItem(menu, "Copy All Rows", () => Copy("Function\tCalls\tFailed\tTotal (ms)\tAverage (us)\tLongest (us)\tCategory\n" +
            string.Join('\n', SummaryGrid.Items.OfType<SummaryItem>().Select(Line))));
        SummaryGrid.ContextMenu = menu;
    }

    private async void ExportCalls()
    {
        if (client is null || view == 0 || !viewComplete || exporting || calls.Count == 0) return;
        var dialog = new SaveFileDialog
        {
            Title = "Export listed calls", Filter = "CSV (*.csv)|*.csv|JSON (*.json)|*.json", DefaultExt = ".csv",
            FileName = Path.GetFileNameWithoutExtension(database) + "-calls", AddExtension = true,
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) == true) await Export(dialog.FileName);
    }

    private async Task Export(string path)
    {
        // The listed calls are written in list order; rows are read in batches so the window stays responsive.
        if (activeView is not { Id: not 0 } owner || exporting) return;
        using var pinned = owner.Pin();
        var revision = owner.Revision;
        var json = path.EndsWith(".json", StringComparison.OrdinalIgnoreCase);
        var (generation, count, written) = (viewGeneration, calls.Count, 0);
        exporting = true;
        cancelExport = false;
        try
        {
            var complete = await ExportFile.Write(path, !json, async writer =>
            {
                await writer.WriteLineAsync(json ? "[" : "Time,Elapsed (s),PID,TID,Call ID,Depth,Module,Function," +
                    "Arguments,Result,Status,LastError,Elapsed (us),Adjusted (us),Category,Caller");
                while (written < count && generation == viewGeneration && owner.Revision == revision &&
                    !cancelExport && !closing)
                {
                    var result = await owner.Query("rows", new { index = (long)written, limit = 1000 });
                    if (generation != viewGeneration || !owner.IsCurrent(result) || owner.Revision != revision) break;
                    var rows = result.Items("calls");
                    if (rows.Length == 0) break;
                    foreach (var row in rows)
                    {
                        if (json) await writer.WriteLineAsync((written > 0 ? "," : "") + row.GetRawText());
                        else
                        {
                            var call = CallItem.FromJson(row);
                            await writer.WriteLineAsync(string.Join(',', new[]
                            {
                                call.Time, call.ElapsedSeconds.ToString("F6", CultureInfo.InvariantCulture),
                                call.PidText, call.TidText, call.IdText, call.DepthText, call.Module, call.Name,
                                call.Summary, call.Result, call.State, call.Error.ToString(),
                                call.DurationUs < 0 ? "" : call.DurationUs.ToString("F1", CultureInfo.InvariantCulture),
                                call.AdjustedDurationUs < 0 ? "" :
                                    call.AdjustedDurationUs.ToString("F1", CultureInfo.InvariantCulture),
                                call.Category, call.Caller
                            }.Select(ExportFile.CsvField)));
                        }
                        ++written;
                    }
                    StatusText.Text = $"Exporting… {written:N0} of {count:N0} calls · Esc cancels";
                }
                if (json) await writer.WriteLineAsync("]");
            }, () => written == count && generation == viewGeneration && owner.Revision == revision &&
                !cancelExport && !closing);
            StatusText.Text = complete ? $"Exported {written:N0} calls to {path}" :
                $"Export stopped after {written:N0} of {count:N0} calls";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            ShowError(error.Message);
        }
        finally { exporting = false; }
    }

    private async Task Compare(CallItem first, CallItem second)
    {
        if (client is null) return;
        try
        {
            var left = await client.Send("details", new { database, target = first.Target, callId = first.Id });
            var right = await client.Send("details", new { database, target = second.Target, callId = second.Id });
            new CompareWindow(left, right) { Owner = this }.Show();
        }
        catch (IOException error)
        {
            ShowError(error.Message);
        }
    }

    private void ShowRecentTraces(object sender, RoutedEventArgs e)
    {
        var menu = ToolbarMenu(RecentTracesButton);
        foreach (var path in settings.RecentTraces.Where(File.Exists))
            AddMenuItem(menu, Path.GetFileName(path), async () => await Run(() => LoadTrace(path)), tip: path);
        if (menu.Items.Count > 0) menu.Items.Add(new Separator());
        AddMenuItem(menu, "Open Trace Folder", () =>
        {
            // Explorer selects the open trace when it is still on disk, and otherwise shows the folder.
            try
            {
                Directory.CreateDirectory(settings.TraceDirectory);
                Process.Start("explorer.exe", File.Exists(database) ? $"/select,\"{database}\"" :
                    $"\"{settings.TraceDirectory}\"")?.Dispose();
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception)
            {
                ShowError(error.Message);
            }
        });
        menu.IsOpen = true;
    }

    private void ShowRecentTargets(object sender, RoutedEventArgs e)
    {
        var menu = ToolbarMenu(RecentTargetsButton);
        foreach (var (target, index) in settings.RecentTargets.Select((target, index) => (target, index)))
        {
            var item = AddMenuItem(menu, (Path.GetFileName(target.Executable) + " " + target.Arguments).Trim(),
                async () => await Launch(target.Executable, target.Arguments, target.WorkingDirectory,
                    target.ExpectedExitCodes), tip: target.Executable);
            item.InputGestureText = index == 0 ? "Ctrl+R" : "";
        }
        menu.IsOpen = true;
    }

    private void ShowFilterMenu(object sender, RoutedEventArgs e)
    {
        // Saved filters stay until removed; recent ones are the last filters that listed calls.
        var menu = ToolbarMenu(FilterMenuButton);
        foreach (var (label, filter, failures) in new[]
        {
            ("Slow calls (>1 ms)", "duration>1ms", false),
            ("Failures except buffer-size errors", "-error:122|234 -result:0xC0000023|0x80000005", true)
        })
        {
            AddMenuItem(menu, label, async () =>
            {
                updating = true;
                ApiSearch.Text = filter;
                FailuresCheck.IsChecked = failures;
                updating = false;
                await RefreshView();
            }, tip: filter);
        }
        menu.Items.Add(new Separator());
        var text = ApiSearch.Text.Trim();
        var saved = settings.SavedFilters.Contains(text);
        AddMenuItem(menu, saved ? "Remove Saved Filter" : "Save Filter", () =>
        {
            settings.SavedFilters = saved ? [.. settings.SavedFilters.Where(other => other != text)] :
                [.. settings.SavedFilters, text];
            settings.Save();
        }, text.Length > 0 && filterError.Length == 0);
        foreach (var (filters, mark) in new[] { (settings.SavedFilters, "★ "), (settings.RecentFilters.Where(recent =>
            !settings.SavedFilters.Contains(recent)).ToArray(), "") })
        {
            if (filters.Length > 0) menu.Items.Add(new Separator());
            foreach (var filter in filters)
            {
                AddMenuItem(menu, mark + filter, () =>
                {
                    ApiSearch.Text = filter;
                    ApiSearch.Focus();
                    ApiSearch.CaretIndex = filter.Length;
                });
            }
        }
        menu.IsOpen = true;
    }

    private (int Start, string Term) CurrentTerm()
    {
        var caret = Math.Min(ApiSearch.CaretIndex, ApiSearch.Text.Length);
        var start = caret;
        while (start > 0 && !char.IsWhiteSpace(ApiSearch.Text[start - 1])) --start;
        return (start, ApiSearch.Text[start..caret]);
    }

    private void UpdateSuggestions()
    {
        // Completion offers filter keys and API names for the term at the caret.
        var term = CurrentTerm().Term.TrimStart('-');
        var items = new List<Suggestion>();
        if (ApiSearch.IsKeyboardFocused && term.Length >= 2 && term.IndexOfAny(['"', '!', '|', '=', '*']) < 0)
        {
            items.AddRange(FilterKeys.Where(key => key.Text.Length > term.Length &&
                key.Text.StartsWith(term, StringComparison.OrdinalIgnoreCase)));
            if (term.IndexOfAny([':', '<', '>']) < 0)
                items.AddRange(apiNames.Where(name => name.StartsWith(term, StringComparison.OrdinalIgnoreCase))
                    .Concat(apiNames.Where(name => name.Contains(term, StringComparison.OrdinalIgnoreCase) &&
                        !name.StartsWith(term, StringComparison.OrdinalIgnoreCase)))
                    .Where(name => name.Length > term.Length).Take(SearchSuggestionLimit).Select(name => new Suggestion(name, "")));
        }
        SuggestList.ItemsSource = items;
        SuggestPopup.IsOpen = items.Count > 0;
    }

    private void AcceptSuggestion(Suggestion suggestion)
    {
        var (start, term) = CurrentTerm();
        var prefix = term.StartsWith('-') ? start + 1 : start;
        var caret = prefix + suggestion.Text.Length;
        ApiSearch.Text = ApiSearch.Text[..prefix] + suggestion.Text + ApiSearch.Text[(start + term.Length)..];
        ApiSearch.CaretIndex = caret;
        UpdateSuggestions();
    }

    private void SearchKeyDown(object sender, KeyEventArgs e)
    {
        if (!SuggestPopup.IsOpen) return;
        if (e.Key is Key.Down or Key.Up)
        {
            e.Handled = true;
            SuggestList.SelectedIndex = e.Key == Key.Down ?
                Math.Min(SuggestList.Items.Count - 1, SuggestList.SelectedIndex + 1) :
                Math.Max(-1, SuggestList.SelectedIndex - 1);
            if (SuggestList.SelectedItem is { } item) SuggestList.ScrollIntoView(item);
        }
        else if (e.Key is Key.Enter or Key.Tab && SuggestList.SelectedItem is Suggestion suggestion)
        {
            e.Handled = true;
            AcceptSuggestion(suggestion);
        }
        else if (e.Key == Key.Escape)
        {
            e.Handled = true;
            SuggestPopup.IsOpen = false;
        }
    }

    private void SearchLostFocus(object sender, KeyboardFocusChangedEventArgs e) => SuggestPopup.IsOpen = false;

    private void SuggestionClicked(object sender, MouseButtonEventArgs e)
    {
        // Accepting on the press keeps keyboard focus in the filter box.
        if ((e.OriginalSource as FrameworkElement)?.DataContext is not Suggestion suggestion) return;
        e.Handled = true;
        AcceptSuggestion(suggestion);
    }

    private ContextMenu CreateCallMenu(CallItem call)
    {
        // Capture exclusions match names across tracing engines, modules and followed processes.
        var name = call.Name.EndsWith(" [syscall]", StringComparison.Ordinal) ? call.Name[..^10] : call.Name;
        var menu = new ContextMenu();
        // Display filters narrow the list without changing what is recorded.
        var exact = ExactApi(call.Name);
        var module = Path.GetFileNameWithoutExtension(call.Module);
        var origin = call.Caller.Split('+')[0];
        AddMenuItem(menu, $"Show Only API: {call.Name}", () => ApiSearch.Text = exact);
        AddMenuItem(menu, $"Hide API: {call.Name}", () => ApiSearch.Text = (ApiSearch.Text + " -" + exact).Trim());
        if (module.Length > 0 && !module.Contains(' '))
            AddMenuItem(menu, $"Show Only Module: {module}", () => ApiSearch.Text = module + "!");
        AddMenuItem(menu, $"Show Only Thread {call.Tid}", () => SelectThread(call));
        AddMenuItem(menu, "Show Thread Around This Call", () => SelectThread(call, true),
            tip: "Clear display filters, keep this call selected and show its thread in time order (Ctrl+G).")
            .InputGestureText = "Ctrl+G";
        if (origin.Length > 0 && !origin.Contains(' '))
            AddMenuItem(menu, $"Show Only Caller: {origin}", () => SetTerm("from:", "from:" + origin),
                tip: "List the calls made from this module.");
        if (settings.Highlights.Contains(exact))
            AddMenuItem(menu, $"Remove Highlight: {call.Name}",
                () => SetHighlights([.. settings.Highlights.Where(rule => rule != exact)]));
        else AddMenuItem(menu, $"Highlight API: {call.Name}", () => SetHighlights([.. settings.Highlights, exact]),
            settings.Highlights.Length < HighlightColors.Length);
        menu.Items.Add(new Separator());

        // Navigation follows a call's nesting, its result and its place in time.
        var seconds = (call.Started - CallItem.StartClock) * 1000000.0 / CallItem.Frequency;
        var returned = !call.IsPending && !call.EntryOnly && ulong.TryParse(call.Result.AsSpan(
            call.Result.StartsWith("0x", StringComparison.Ordinal) ? 2 : 0), NumberStyles.HexNumber,
            CultureInfo.InvariantCulture, out var result) && result != 0;
        AddMenuItem(menu, "Go to Parent Call", async () => await Reveal(call.Target, call.Parent,
            "The parent call is hidden by the display filters."), call.Parent != 0);
        AddMenuItem(menu, "Show Nested Calls", () => SetTerm("under:", $"under:{call.Target}.{call.Id}"),
            tip: "List this call and every call made inside it.");
        AddMenuItem(menu, $"Follow Result: {call.Result}", () => SetTerm("value:", "value:" + call.Result), returned,
            "List the calls that received or returned this value.");
        AddMenuItem(menu, "Show Calls From Here", () => SetTerm("after:", "after:" +
            (Math.Floor(seconds) / 1000000).ToString("0.######", CultureInfo.InvariantCulture)));
        AddMenuItem(menu, "Show Calls Up to Here", () => SetTerm("before:", "before:" +
            (Math.Ceiling(seconds) / 1000000).ToString("0.######", CultureInfo.InvariantCulture)));
        AddMenuItem(menu, CallItem.Reference == call.Started ? "Clear Time Reference" : "Set Time Reference", () =>
        {
            CallItem.Reference = CallItem.Reference == call.Started ? 0 : call.Started;
            if (CallItem.Reference != 0) ElapsedColumn.Visibility = Visibility.Visible;
            foreach (CallItem item in calls) item.Refresh();
        }, tip: "Measure the Elapsed column from this call.");
        if (compared is not null && compared != call && (compared.Target != call.Target || compared.Id != call.Id))
            AddMenuItem(menu, $"Compare With Call {compared.Id}", async () => await Compare(compared, call));
        AddMenuItem(menu, "Select for Compare", () => compared = call);
        menu.Items.Add(new Separator());
        if (live && !Protocol.IsManagedApi(call.Api))
        {
            AddMenuItem(menu, "Break on Entry", async () => await SetBreakpoint(call, false));
            if (!call.EntryOnly) AddMenuItem(menu, "Break on Return", async () => await SetBreakpoint(call, true));
            menu.Items.Add(new Separator());
        }
        AddMenuItem(menu, "Copy Function", () => Copy(call.Function));
        AddMenuItem(menu, "Copy Arguments", () => Copy(call.Summary));
        AddMenuItem(menu, "Copy Row", () => Copy(string.Join('\t', call.Time, call.Pid, call.Tid, call.Function, call.Summary,
            call.ResultDisplay, call.Duration, call.AdjustedDuration, call.Id)));
        menu.Items.Add(new Separator());
        var api = AddMenuItem(menu, $"Exclude API: {name}", async () => await ApplyCaptureExclusion(name, null),
            !settings.ExcludedApis.Contains(name, StringComparer.Ordinal),
            "Stop recording this API name in every process and module. Existing calls are retained.");
        if (call.Name.EndsWith(" [syscall]", StringComparison.Ordinal))
            AddMenuItem(menu, "Exclude Syscall Events", async () => await ApplyCaptureExclusion(call.Name, null),
                api.IsEnabled && !settings.ExcludedApis.Contains(call.Name, StringComparer.Ordinal),
                "Stop recording this syscall's events. API calls and existing events are retained.");
        var category = categories.FirstOrDefault(item => item.Id == call.CategoryId);
        if (category is not null)
            AddMenuItem(menu, $"Exclude Category: {category.Name}", async () => await ApplyCaptureExclusion(null, category),
                (settings.CategoryMask & category.Mask) != 0,
                "Stop recording this category in every process. Existing calls are retained.");
        return menu;
    }

    private void ShowCaptureModes(object sender, RoutedEventArgs e)
    {
        if (live || busy || client is null) return;
        var menu = ToolbarMenu(CaptureModeButton);
        foreach (var (mode, label, description) in new[]
        {
            ("triage", "Fast triage", "Typed hooks, stacks, runtime helpers excluded; display calls from app modules."),
            ("io", "File / registry / network I/O", "Typed hooks, stacks, runtime helpers excluded; capture files, " +
                "registry, processes, threads and networking."),
            ("broad", "Broad trace", "Broad coverage, stacks, all sources and categories; no API exclusions.")
        })
        {
            AddMenuItem(menu, label, () =>
            {
                if (live || busy) return;
                settings.ApplyMode(mode);
                settings.Save();
                UpdateActions();
                StatusText.Text = $"Next capture: {label} · stacks on · " +
                    (settings.InstructionEngine ? "broad coverage" : "typed hooks");
            }, tip: description +
                " Replaces the engine, stack setting, source/category selections and API exclusions.");
        }
        menu.IsOpen = true;
    }

    private void ShowStack(JsonElement call)
    {
        StackGrid.ItemsSource = call.Items("stack").Select((frame, index) => new StackFrameItem(index,
            frame.Text("address"), frame.Text("display"), frame.Text("path"), frame.Text("source"),
            frame.Number("line"), frame.Flag("application"))).ToArray();
        var count = StackGrid.Items.Count;
        var partial = call.Items("input").Any(value => value.Number("kind") == (long)ValueKind.Stack &&
            (value.Number("flags") & (long)ValueFlags.Truncated) != 0);
        StackStatus.Text = count == 0 ? (call.Number("flags") & (long)EventFlags.StackUnavailable) != 0 ?
            "Full stack unavailable at this call site." : "No stack recorded. Enable stacks before capturing." :
            $"{count} frames{(partial ? " · partial stack" : "")} · app frames highlighted";
    }

    private void StackContextOpening(object sender, ContextMenuEventArgs e)
    {
        if (busy || StackGrid.SelectedItem is not StackFrameItem frame ||
            (e.CursorLeft >= 0 && (e.OriginalSource is not DependencyObject source ||
                ItemsControl.ContainerFromElement(StackGrid, source) is not DataGridRow)))
        {
            e.Handled = true;
            return;
        }
        var menu = new ContextMenu();
        if (frame.Source.Length > 0) AddMenuItem(menu, "Open Source", () => OpenStackSource(frame));
        AddMenuItem(menu, "Show Calls From This Address", () => SetTerm("caller:", "caller:" + frame.Address));
        var module = Path.GetFileName(frame.Path);
        if (module.Length > 0 && !module.Contains(' '))
            AddMenuItem(menu, "Show Calls From This Module", () => SetTerm("from:", "from:" + module));
        AddMenuItem(menu, "Copy Frame", () => Copy(frame.Display +
            (frame.Source.Length > 0 ? $" · {frame.Source}:{frame.Line}" : "")));
        StackGrid.ContextMenu = menu;
    }

    private void StackActivated(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject source &&
            ItemsControl.ContainerFromElement(StackGrid, source) is DataGridRow { Item: StackFrameItem frame } &&
            frame.Source.Length > 0) OpenStackSource(frame);
    }

    private void StackKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || StackGrid.SelectedItem is not StackFrameItem { Source.Length: > 0 } frame) return;
        e.Handled = true;
        OpenStackSource(frame);
    }

    private void OpenStackSource(StackFrameItem frame)
    {
        try
        {
            // Recorded paths are data: only local files are passed as arguments to a known editor.
            if (frame.Source.Length < 3 || frame.Source[1] != ':' || !Path.IsPathFullyQualified(frame.Source) ||
                new DriveInfo(Path.GetPathRoot(frame.Source)!).DriveType != DriveType.Fixed ||
                !File.Exists(frame.Source))
                throw new IOException("The source file is unavailable on this computer.");
            var code = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Programs", "Microsoft VS Code", "Code.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft VS Code", "Code.exe")
            }.FirstOrDefault(File.Exists);
            var start = new ProcessStartInfo(code ?? Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.System), "notepad.exe")) { UseShellExecute = false };
            if (code is not null) start.ArgumentList.Add("--goto");
            start.ArgumentList.Add(code is null ? frame.Source : $"{frame.Source}:{Math.Max(1, frame.Line)}");
            Process.Start(start)?.Dispose();
        }
        catch (Exception error) when (error is IOException or Win32Exception or ArgumentException)
        {
            ShowError(error.Message);
        }
    }
}

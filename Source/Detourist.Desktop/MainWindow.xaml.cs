using Microsoft.Win32;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace Detourist.Desktop;

public partial class MainWindow : Window
{
    private CollectorClient? client;
    private const int RecentTargetLimit = 8;
    private const int RecentTraceLimit = 10;
    private const int LoadWaitDelayMs = 15;
    private readonly DispatcherTimer pollTimer = new() { Interval = TimeSpan.FromMilliseconds(Protocol.UiDebounceMs) };
    private readonly DispatcherTimer searchTimer = new() { Interval = TimeSpan.FromMilliseconds(Protocol.UiDebounceMs) };
    private readonly CaptureSettings settings = CaptureSettings.Load();
    private readonly CallList calls = new();
    private Task openingView = Task.CompletedTask;
    private Task refreshingView = Task.CompletedTask;
    private ApiInfo[] catalog = [];
    private CategoryInfo[] categories = [];
    private TargetCoverage[] targetCoverage = [];
    private TraceDiagnostic[] traceDiagnostics = [];
    private long traceSkippedChildren;
    private FilterItem[] traceThreads = [];
    private string coverageNote = "";
    private string database = "";
    private string filterError = "";
    private long records = -1;
    private long totalCalls;
    private CallView? activeView;
    private long view => activeView?.Id ?? 0;
    private long viewGeneration;
    private long scanned => activeView?.Scanned ?? 0;
    private int opening;
    private int entryApi = -1;
    private int exitApi = -1;
    private bool live;
    private bool loadingSavedTrace;
    private bool paused;
    private bool updating;
    private bool polling;
    private bool busy;
    private bool closing;
    private bool closed;
    private bool showingBreakpoint;
    private bool viewComplete => activeView?.Complete == true;
    private bool pumping;
    private bool advanceWhenIndexed;
    private bool columnsCustomized;
    private CallItem? selected;
    private ScrollViewer? callScroll;

    public MainWindow()
    {
        InitializeComponent();
        RestoreLayout();
        updating = true;
        ProcessCombo.ItemsSource = new[] { new FilterItem(0, "All processes") };
        ThreadCombo.ItemsSource = new[] { new FilterItem(0, "All threads") };
        CategoryCombo.ItemsSource = new[] { new FilterItem(0, "All categories") };
        OrderCombo.ItemsSource = new[]
        {
            new FilterItem(0, "Newest first"), new FilterItem(1, "Oldest first"), new FilterItem(2, "Slowest first")
        };
        ProcessCombo.SelectedIndex = ThreadCombo.SelectedIndex = CategoryCombo.SelectedIndex = 0;
        OrderCombo.SelectedIndex = settings.Order == "oldest" ? 1 : 0;
        updating = false;
        CallItem.IndentNested = settings.IndentNested;
        calls.BlockRequested += () => Dispatcher.BeginInvoke(LoadBlocks, DispatcherPriority.Background);
        calls.CollectionChanged += (_, _) =>
        {
            // A list reset discards the focused cell; return keyboard focus so arrow keys keep working.
            if (Keyboard.FocusedElement is DataGridCell { DataContext: CallItem })
                Dispatcher.BeginInvoke(FocusCall, DispatcherPriority.Background);
        };
        CallsGrid.ItemsSource = calls;
        CallsGrid.AddHandler(Thumb.DragStartedEvent, new DragStartedEventHandler((_, e) =>
        {
            if (e.OriginalSource is Thumb { TemplatedParent: ScrollBar }) PauseFollowing();
        }));
        pollTimer.Tick += async (_, _) => await Poll();
        searchTimer.Tick += async (_, _) =>
        {
            searchTimer.Stop();
            await RefreshView();
        };
        findTimer.Tick += async (_, _) => await RefreshFind(true);
        timelineTimer.Tick += async (_, _) => await RefreshTimeline();
        CallsGrid.AddHandler(ScrollViewer.ScrollChangedEvent, new ScrollChangedEventHandler((_, _) => ShowSpan()));
        Timeline.Seek += async clock => await SeekTime(clock);
        Parameters.FollowRequested += value => SetTerm("value:", $"value:0x{value:X}");
        Deactivated += (_, _) => SuggestPopup.IsOpen = false;
        SourceInitialized += (_, _) => App.ApplyNativeTheme(this);
    }

    private void RestoreLayout()
    {
        // Reopen where the window was left when that position is still on a connected display.
        Width = Math.Min(Width, SystemParameters.WorkArea.Width - Protocol.WorkAreaMargin);
        Height = Math.Min(Height, SystemParameters.WorkArea.Height - Protocol.WorkAreaMargin);
        var (left, top) = (SystemParameters.VirtualScreenLeft, SystemParameters.VirtualScreenTop);
        if (settings.Window is { Length: 5 } bounds && bounds[2] >= MinWidth && bounds[3] >= MinHeight &&
            bounds[0] + bounds[2] > left + 120 && bounds[0] < left + SystemParameters.VirtualScreenWidth - 120 &&
            bounds[1] >= top && bounds[1] < top + SystemParameters.VirtualScreenHeight - 60)
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            (Left, Top, Width, Height) = (bounds[0], bounds[1], bounds[2], bounds[3]);
            if (bounds[4] != 0) WindowState = WindowState.Maximized;
        }
        if (settings.InspectorWidth >= InspectorColumn.MinWidth) InspectorColumn.Width = new(settings.InspectorWidth);
        foreach (var (column, layout) in CallsGrid.Columns.Select(column => (column,
            settings.Columns.GetValueOrDefault(column.Header.ToString()!))).Where(pair => pair.Item2 is not null)
            .OrderBy(pair => pair.Item2!.Position).ToArray())
        {
            column.Visibility = layout!.Visible ? Visibility.Visible : Visibility.Collapsed;
            if (layout.Width > 0 && !column.Width.IsStar) column.Width = layout.Width;
            column.DisplayIndex = Math.Clamp(layout.Position, 0, CallsGrid.Columns.Count - 1);
            columnsCustomized = true;
        }
    }

    private void SaveLayout()
    {
        settings.Window = [RestoreBounds.Left, RestoreBounds.Top, RestoreBounds.Width, RestoreBounds.Height,
            WindowState == WindowState.Maximized ? 1 : 0];
        if (WindowState == WindowState.Minimized || RestoreBounds.IsEmpty) settings.Window = null;
        settings.InspectorWidth = InspectorColumn.ActualWidth;
        settings.Order = Order == "oldest" ? "oldest" : "newest";
        settings.Columns = columnsCustomized ? CallsGrid.Columns.ToDictionary(column => column.Header.ToString()!,
            column => new ColumnLayout(column.Visibility == Visibility.Visible,
                column.Width.IsAbsolute ? column.Width.Value : 0, column.DisplayIndex)) : [];
        settings.Save();
    }

    private async void WindowLoaded(object sender, RoutedEventArgs e)
    {
        await Run(async () =>
        {
            client = new CollectorClient();
            var hello = await client.Send("hello");
            await client.Send("symbols", new { directories = settings.SymbolDirectories });
            categories = hello.Items("categories").Select(CategoryInfo.FromJson).ToArray();
            settings.NoiseProfiles = hello.Items("noiseProfiles").Select(item => new NoiseProfileInfo(
                item.Text("name"), item.Text("description"),
                item.Items("apis").Select(api => api.GetString()!).ToArray())).ToArray();
            var categoryNames = categories.ToDictionary(item => item.Id, item => item.Name);
            catalog = hello.Items("catalog").Select(item => ApiInfo.FromJson(item, categoryNames)).ToArray();
            apiNames = [.. catalog.Select(api => api.Name).Where(name => !name.Contains(' ')).Distinct()
                .OrderBy(name => name.Length).ThenBy(name => name, StringComparer.OrdinalIgnoreCase)];
            settings.Resolve(catalog, categories, ulong.Parse(hello.Text("allApis"), CultureInfo.InvariantCulture),
                ulong.Parse(hello.Text("allCategories"), CultureInfo.InvariantCulture));
            updating = true;
            SetFilterItems(CategoryCombo, categories.OrderBy(item => item.Name).Select(item =>
                new FilterItem(item.Id + 1, item.Name)).Prepend(new(0, "All categories")));
            updating = false;
            coverageNote = hello.Text("coverage",
                "Broad coverage discovers APIs at runtime. Universal coverage is incomplete.");
            ResetSession("", "No capture session");
            StatusText.Text = "Ready · launch a process or open a saved trace";
            pollTimer.Start();
            var argument = Environment.GetCommandLineArgs().Skip(1).FirstOrDefault(File.Exists);
            if (argument is not null) await LoadTrace(argument);
        });
    }

    private async Task Run(Func<Task> action)
    {
        if (busy || closing) return;
        busy = true;
        UpdateActions();
        try
        {
            ErrorBanner.Visibility = Visibility.Collapsed;
            await action();
        }
        catch (Exception error)
        {
            ShowError(error.Message);
        }
        finally
        {
            busy = false;
            UpdateActions();
        }
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorBanner.Visibility = Visibility.Visible;
        StatusText.Text = "Operation could not complete";
    }

    private void DismissError(object sender, RoutedEventArgs e) => ErrorBanner.Visibility = Visibility.Collapsed;

    private string Order => OrderCombo.SelectedIndex switch { 1 => "oldest", 2 => "slowest", _ => "newest" };
    private bool Filtered => ApiSearch.Text.Length > 0 || ProcessCombo.SelectedIndex > 0 ||
        ThreadCombo.SelectedIndex > 0 || CategoryCombo.SelectedIndex > 0 || FailuresCheck.IsChecked == true;
    private bool Following => live && FollowCheck.IsChecked == true && Order != "slowest";

    private void UpdateActions()
    {
        if (!IsInitialized) return;
        LaunchButton.Visibility = AttachButton.Visibility = live ? Visibility.Collapsed : Visibility.Visible;
        PauseButton.Visibility = StopButton.Visibility = live ? Visibility.Visible : Visibility.Collapsed;
        LaunchButton.IsEnabled = AttachButton.IsEnabled = OpenButton.IsEnabled = !busy && !live && client is not null;
        RecentTargetsButton.Visibility = LaunchButton.Visibility;
        CaptureModeButton.Visibility = LaunchButton.Visibility;
        CaptureModeButton.IsEnabled = LaunchButton.IsEnabled;
        RecentTargetsButton.IsEnabled = LaunchButton.IsEnabled && settings.RecentTargets.Length > 0;
        RecentTracesButton.IsEnabled = OpenButton.IsEnabled;
        SummaryCheck.IsEnabled = database.Length > 0;
        SettingsButton.IsEnabled = !busy && client is not null;
        PauseButton.IsEnabled = StopButton.IsEnabled = !busy;

        // Following applies only while calls are still arriving in time order.
        FollowCheck.Visibility = live && Order != "slowest" ? Visibility.Visible : Visibility.Collapsed;
        OrderCombo.IsEnabled = database.Length > 0;
        ResetFilterButton.Visibility = Filtered ? Visibility.Visible : Visibility.Collapsed;
        var nativeCall = selected is not null && !Protocol.IsManagedApi(selected.Api);
        EntryButton.IsEnabled = live && nativeCall && !busy;
        ReturnButton.IsEnabled = live && nativeCall && selected is { EntryOnly: false } && !busy;
        ReturnButton.ToolTip = selected is { EntryOnly: true } ?
            "This API transfers context or terminates execution; a return cannot be observed." : null;
        ClearBreaksButton.IsEnabled = live && (entryApi >= 0 || exitApi >= 0) && !busy;
        EntryButton.Visibility = live && nativeCall ? Visibility.Visible : Visibility.Collapsed;
        ReturnButton.Visibility = live && nativeCall && selected is { EntryOnly: false } ?
            Visibility.Visible : Visibility.Collapsed;
        ClearBreaksButton.Visibility = live && (entryApi >= 0 || exitApi >= 0) ?
            Visibility.Visible : Visibility.Collapsed;
        BreakActions.Visibility = EntryButton.Visibility == Visibility.Visible ||
            ClearBreaksButton.Visibility == Visibility.Visible ? Visibility.Visible : Visibility.Collapsed;

        // Capture restrictions stay visible because they decide which calls are recorded at all.
        var limits = new List<string>();
        var excluded = settings.ExcludedApis.Length;
        var categoriesOff = BitOperations.PopCount(settings.AllCategories & ~settings.CategoryMask);
        var sourcesOff = BitOperations.PopCount(settings.AllApis & ~settings.ApiMask);
        if (excluded > 0) limits.Add($"{excluded:N0} {(excluded == 1 ? "API" : "APIs")} excluded");
        if (categoriesOff > 0) limits.Add($"{categoriesOff} {(categoriesOff == 1 ? "category" : "categories")} off");
        if (sourcesOff > 0) limits.Add($"{sourcesOff} {(sourcesOff == 1 ? "source" : "sources")} off");
        var (entry, exit) = live ? (entryApi, exitApi) : (settings.EntryApi, settings.ExitApi);
        if (entry >= 0) limits.Add("break on entry: " + ApiName(entry));
        if (exit >= 0) limits.Add("break on return: " + ApiName(exit));
        CaptureFiltersText.Text = "Capture: " + string.Join(" · ", limits);
        CaptureFiltersButton.Visibility = limits.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private string ApiName(int api) => catalog.FirstOrDefault(item => item.Id == api)?.Name ??
        (selected?.Api == api ? selected.Name : $"API 0x{api:X}");

    private async void LaunchProcess(object sender, RoutedEventArgs e)
    {
        if (client is null || busy || live) return;
        var recent = settings.RecentTargets.FirstOrDefault();
        var dialog = new LaunchWindow(recent?.Executable ?? "", recent?.Arguments ?? "",
            recent?.WorkingDirectory ?? "", recent?.ExpectedExitCodes ?? "") { Owner = this };
        if (dialog.ShowDialog() == true)
            await Launch(dialog.Executable, dialog.Arguments, dialog.WorkingDirectory, dialog.ExpectedExitCodes);
    }

    private async Task Launch(string executable, string arguments, string workingDirectory = "",
        string expectedExitCodes = "")
    {
        if (client is null || busy || live) return;
        await Run(async () =>
        {
            var request = await PrepareCapture(CollectorClient.ExecutablePointerSize(executable), executable);
            request["executable"] = executable;
            request["arguments"] = arguments;
            request["workingDirectory"] = workingDirectory;
            request["expectedExitCodes"] = LaunchWindow.ParseExitCodes(expectedExitCodes);
            await client.Send("launch", request);
            live = true;
            settings.RecentTargets = CaptureSettings.Recent(settings.RecentTargets,
                new(executable, arguments, workingDirectory, expectedExitCodes), RecentTargetLimit);
            settings.RecentTraces = CaptureSettings.Recent(settings.RecentTraces, database, RecentTraceLimit);
            settings.Save();
            StateText.Text = "STARTING CAPTURE";
            StatusText.Text = "Preparing the target and installing capture hooks…";
        });
    }

    private async Task<Dictionary<string, object>> PrepareCapture(int pointerSize, string target)
    {
        await SelectCollector(pointerSize);
        ResetSession(NewDatabase(target), Path.GetFileName(target));
        if (settings.FromAppOnCapture) ApiSearch.Text = "from:app";
        return Options();
    }

    private async void AttachProcess(object sender, RoutedEventArgs e) => await Attach(null);

    private async Task Attach(ProcessItem? process)
    {
        if (client is null || busy || live) return;
        await Run(async () =>
        {
            if (process is null)
            {
                await SelectCollector(client.PointerSize);
                var dialog = new ProcessWindow(client) { Owner = this };
                if (dialog.ShowDialog() != true || dialog.Selected is null) return;
                process = dialog.Selected;
            }
            var request = await PrepareCapture(process.Architecture.Equals("x86", StringComparison.OrdinalIgnoreCase) ?
                4 : 8, process.Name);
            request["pid"] = process.Pid;
            await client.Send("attach", request);
            live = true;
            settings.RecentTraces = CaptureSettings.Recent(settings.RecentTraces, database, RecentTraceLimit);
            StateText.Text = "ATTACHING";
            StatusText.Text = "Attaching to the selected process…";
        });
    }

    private void OpenWindowSpy(object sender, RoutedEventArgs e)
    {
        // Reuse the owned inspector so its live message log stays attached to the same target.
        var existing = OwnedWindows.OfType<WindowSpyWindow>().FirstOrDefault();
        if (existing is not null)
        {
            if (existing.WindowState == WindowState.Minimized) existing.WindowState = WindowState.Normal;
            existing.Activate();
            return;
        }
        new WindowSpyWindow(Attach, () => client is not null && !busy && !live) { Owner = this }.Show();
    }

    private async Task SelectCollector(int pointerSize)
    {
        if (client is { IsConnected: true } && client.PointerSize == pointerSize) return;
        var replacement = new CollectorClient(pointerSize);
        try
        {
            await replacement.Send("hello");
            await replacement.Send("symbols", new { directories = settings.SymbolDirectories });
        }
        catch
        {
            await replacement.DisposeAsync();
            throw;
        }

        // Finish the previous view before its collector is replaced at the next capture boundary.
        ResetSession("", "No capture session");
        var previous = client;
        client = replacement;
        if (previous is not null) await previous.DisposeAsync();
    }

    private Dictionary<string, object> Options() => new()
    {
        ["database"] = database,
        ["bufferLimit"] = settings.BufferLimit,
        ["traceStopMiB"] = settings.TraceStopMiB,
        ["stackDepth"] = settings.Stacks ? Protocol.MaximumStack : 0,
        ["followChildren"] = settings.FollowChildren,
        ["apiMask"] = settings.ApiMask.ToString(CultureInfo.InvariantCulture),
        ["categoryMask"] = settings.CategoryMask.ToString(CultureInfo.InvariantCulture),
        ["excludedApis"] = settings.ExcludedApis,
        ["entryMask"] = "0",
        ["exitMask"] = "0",
        ["entryApi"] = settings.EntryApi,
        ["exitApi"] = settings.ExitApi,
        ["instructionEngine"] = settings.InstructionEngine
    };

    private string NewDatabase(string name)
    {
        // Captures are named after their target and start time in the trace folder.
        Directory.CreateDirectory(settings.TraceDirectory);
        var stem = string.Concat(Path.GetFileNameWithoutExtension(name).Select(character =>
            Path.GetInvalidFileNameChars().Contains(character) ? '_' : character)) + $"-{DateTime.Now:yyyyMMdd-HHmmss}";
        var path = Path.Combine(settings.TraceDirectory, stem + ".db");
        for (var copy = 2; File.Exists(path); ++copy) path = Path.Combine(settings.TraceDirectory, $"{stem}-{copy}.db");
        return path;
    }

    private async void OpenTrace(object sender, RoutedEventArgs e)
    {
        if (live || busy || client is null) return;
        var dialog = new OpenFileDialog
        {
            Title = "Open trace", Filter = "Detourist traces (*.db;*.sqlite)|*.db;*.sqlite|All files|*.*"
        };
        if (dialog.ShowDialog(this) == true) await Run(() => LoadTrace(dialog.FileName));
    }

    private async Task LoadTrace(string path)
    {
        await SelectCollector(client?.PointerSize ?? 8);
        ResetSession(path, Path.GetFileName(path));
        loadingSavedTrace = true;
        StatusText.Text = "Loading trace…";
        StateText.Text = "SAVED TRACE";
        QueueText.Text = WaitText.Text = "—";
        await OpenView();
    }

    private void ResetSession(string path, string title)
    {
        ApiMetadata.Refresh();
        searchTimer.Stop();
        ++viewGeneration;
        activeView?.Dispose();
        activeView = null;
        database = path;
        loadingSavedTrace = false;
        filterError = "";
        SessionTitle.Text = title;
        SessionSubtitle.Text = path.Length == 0 ? "Launch or attach a process to capture API calls." : path;
        SessionSubtitle.ToolTip = path.Length == 0 ? null : path;
        StateText.Text = "IDLE";
        StateDot.Fill = (Brush)FindResource("MutedBrush");
        entryApi = settings.EntryApi;
        exitApi = settings.ExitApi;
        paused = false;
        PauseButton.Content = "_Pause";
        records = -1;
        totalCalls = 0;
        targetCoverage = [];
        traceDiagnostics = [];
        traceSkippedChildren = 0;
        traceThreads = [];
        CoverageText.Text = path.Length == 0 ? $"{catalog.Length:N0} API signatures · native, COM, WinRT and .NET" :
            "Waiting for target coverage…";
        CoverageText.ToolTip = coverageNote;
        CoverageButton.Visibility = Visibility.Collapsed;
        updating = true;
        ProcessCombo.ItemsSource = new[] { new FilterItem(0, "All processes") };
        ThreadCombo.ItemsSource = new[] { new FilterItem(0, "All threads") };
        ProcessCombo.SelectedIndex = ThreadCombo.SelectedIndex = 0;
        CategoryCombo.SelectedIndex = 0;
        if (OrderCombo.SelectedIndex == 2) OrderCombo.SelectedIndex = 0;
        ApiSearch.Clear();
        FailuresCheck.IsChecked = false;
        FollowCheck.IsChecked = true;
        CallsGrid.SelectedItem = null;
        ResetTools();
        updating = false;
        calls.Pinned = selected = null;
        calls.Resize(0, false);
        ClearDetails();
        CallsText.Text = ProcessesText.Text = "0";
        QueueText.Text = "0";
        WaitText.Text = "0 ms";
        UpdateResults();
        UpdateActions();
    }

    private async void PauseCapture(object sender, RoutedEventArgs e)
    {
        if (client is null) return;
        await Run(async () =>
        {
            await client.Send("pause", new { paused = !paused });
            paused = !paused;
            PauseButton.Content = paused ? "_Resume" : "_Pause";
        });
    }

    private async void StopCapture(object sender, RoutedEventArgs e)
    {
        if (client is null) return;
        await Run(async () =>
        {
            await client.Send("stop");
            StatusText.Text = "Finishing queued calls and releasing targets…";
            StateText.Text = "STOPPING";
        });
    }

    private async Task Poll()
    {
        if (polling || client is null || closing || !live) return;
        polling = true;
        try
        {
            JsonElement status;
            try
            {
                status = await client.Send("status");
            }
            catch (Exception error)
            {
                // Only a failed status request means the capture service is gone.
                live = false;
                ShowError(error.Message);
                StateText.Text = "CAPTURE STOPPED";
                UpdateActions();
                return;
            }
            totalCalls = status.Number("calls");
            CallsText.Text = totalCalls.ToString("N0");
            ProcessesText.Text = status.Number("processes").ToString("N0");
            QueueText.Text = status.Number("queued").ToString("N0");
            WaitText.Text = status.Decimal("blockedMilliseconds").ToString("N1") + " ms";
            StatusText.Text = status.Text("message");
            var finished = status.Flag("finished");
            var partial = status.Flag("partial");
            StateText.Text = finished ? (partial ? "PARTIAL CAPTURE" : "CAPTURE ENDED") :
                status.Flag("breakpoint") ? "BREAKPOINT" : paused ? "CAPTURE PAUSED" :
                status.Flag("capturing") ? (partial ? "PARTIAL CAPTURE" : "CAPTURING") : "STARTING CAPTURE";
            StateDot.Fill = (Brush)FindResource(finished ? "MutedBrush" : "AccentBrush");
            var changed = records != status.Number("records");
            var diagnosticsChanged = traceSkippedChildren != status.Number("skippedChildren");
            records = status.Number("records");
            if (finished)
            {
                live = false;
                SessionSubtitle.Text = status.Text("message");
                UpdateActions();
            }
            // Coalesce display work independently so a slow query cannot delay status or a breakpoint dialog.
            if (!refreshingView.IsCompleted)
            {
                if (changed) records = -1;
                if (finished) advanceWhenIndexed = true;
            }
            else if (view == 0 && opening == 0 && filterError.Length == 0 &&
                (records > 0 || diagnosticsChanged || finished) && File.Exists(database))
                refreshingView = RefreshCaptureView(OpenView);
            else if (view != 0 && viewComplete && (changed || diagnosticsChanged || finished ||
                SummaryCheck.IsChecked == true && DateTime.UtcNow >= nextSummary))
                refreshingView = RefreshCaptureView(() => Advance(finished));
            else if (finished) advanceWhenIndexed = true;
            UpdateResults();
            if (status.Flag("breakpoint") && !showingBreakpoint)
            {
                showingBreakpoint = true;
                try
                {
                    var breakpoint = new BreakpointWindow(client, status,
                        (int)status.Number("bufferLimit", settings.BufferLimit)) { Owner = this };
                    breakpoint.ShowDialog();
                }
                finally
                {
                    showingBreakpoint = false;
                }
            }
        }
        finally
        {
            polling = false;
        }
    }

    private async Task RefreshView()
    {
        try
        {
            await OpenView();
        }
        catch (Exception error)
        {
            ShowError(error.Message);
        }
    }

    private async Task RefreshCaptureView(Func<Task> refresh)
    {
        var pending = refresh();
        var generation = viewGeneration;
        try
        {
            await pending;
            if (generation == viewGeneration && advanceWhenIndexed && viewComplete && !closing)
            {
                advanceWhenIndexed = false;
                await Advance(true);
            }
        }
        catch (Exception error)
        {
            if (generation == viewGeneration && !closing) ShowError(error.Message);
        }
    }

    private Task OpenView() => openingView = BuildView();

    private async Task BuildView()
    {
        // Each filter or order change indexes a new view; answers for a superseded view are discarded.
        if (client is null || database.Length == 0 || (live && !File.Exists(database))) return;
        searchTimer.Stop();
        var generation = ++viewGeneration;
        activeView?.Dispose();
        var owner = activeView = new CallView(client);
        owner.Published += update => { if (activeView == owner) ApplyView(update); };
        ++findGeneration;
        foundView?.Dispose();
        foundView = null;
        FindStatus.Text = "";
        FindNextButton.IsEnabled = FindPreviousButton.IsEnabled = false;
        SummaryGrid.ItemsSource = null;
        summaryText = "";
        nextSummary = DateTime.MinValue;
        Timeline.Update([], [], 0, 0);
        filterError = "";
        calls.Resize(0, false);
        UpdateResults();
        UpdateActions();
        ++opening;
        try
        {
            var state = await owner.Open(ViewRequest());
            if (generation != viewGeneration || closing)
            {
                owner.Dispose();
                return;
            }
            await ApplyMarks(false);
            if (generation != viewGeneration) return;

            // Indexing continues in short slices so the first rows and other requests are served meanwhile.
            while (!viewComplete)
            {
                state = await owner.Advance(metadata: false);
                if (generation != viewGeneration || closing) return;
            }
            await Reselect(generation);
            if (Following) ScrollToNewest();
            _ = RefreshTools();

            // A capture that ended while its view was being indexed still shows its final calls.
            if (advanceWhenIndexed && generation == viewGeneration)
            {
                advanceWhenIndexed = false;
                await Advance(true);
            }

            // Only the view that finishes opening the saved trace publishes its status and recent entry.
            if (!loadingSavedTrace || generation != viewGeneration || closing) return;
            loadingSavedTrace = false;
            settings.RecentTraces = CaptureSettings.Recent(settings.RecentTraces, database, RecentTraceLimit);
            if (traceSkippedChildren > 0)
            {
                StateText.Text = "PARTIAL CAPTURE";
                StatusText.Text = $"{traceSkippedChildren:N0} child " +
                    (traceSkippedChildren == 1 ? "process" : "processes") + " skipped · See Coverage for details";
            }
            else StatusText.Text = "Saved trace · display filters do not change recorded data";
        }
        catch (Exception error)
        {
            if (generation != viewGeneration) return;
            if (error is IOException && error.Message.StartsWith("Filter", StringComparison.Ordinal))
            {
                filterError = error.Message;
                UpdateResults();
                return;
            }
            if (loadingSavedTrace) ResetSession("", "No capture session");
            throw;
        }
        finally
        {
            --opening;
        }
    }

    private Dictionary<string, object> ViewRequest()
    {
        var thread = ThreadCombo.SelectedItem as FilterItem;
        var process = (ProcessCombo.SelectedItem as FilterItem)?.Id ?? 0;
        return new()
        {
            ["database"] = database,
            ["target"] = process != 0 ? process : thread?.Target ?? 0,
            ["thread"] = thread?.Id ?? 0,
            ["filter"] = ApiSearch.Text,
            ["category"] = ((CategoryCombo.SelectedItem as FilterItem)?.Id ?? 0) - 1,
            ["failuresOnly"] = FailuresCheck.IsChecked == true,
            ["order"] = Order
        };
    }

    private void ApplyView(CallView.Update update)
    {
        ApplyMetadata(update.State);
        updating = true;
        try
        {
            calls.Resize(activeView!.Count, update.Keep, update.Blocks);
            if (!update.Keep && update.Blocks is not null) callScroll?.ScrollToVerticalOffset(update.First);
            if (update.Changed)
            {
                Timeline.Update([], [], 0, 0);
                nextTimeline = DateTime.MinValue;
            }
        }
        finally { updating = false; }
        UpdateResults();
    }

    private void ApplyMetadata(JsonElement state)
    {
        if (!state.TryGetProperty("targets", out _)) return;
        updating = true;
        try
        {
            var targets = state.Items("targets");
            totalCalls = live ? Math.Max(totalCalls, state.Number("totalCalls")) : state.Number("totalCalls");
            CallItem.Frequency = Math.Max(1, state.Number("frequency", 1));
            CallItem.StartClock = state.Number("startClock");
            modules = state.Number("modules");
            FromAppCheck.IsEnabled = modules > 0;
            FromAppCheck.ToolTip = modules > 0 ?
                "Show only calls made directly by the application's own modules (from:app)." :
                "This trace has no record of loaded modules, so callers cannot be attributed.";
            if (!live)
            {
                CallsText.Text = totalCalls.ToString("N0");
                ProcessesText.Text = targets.Length.ToString("N0");
            }
            traceThreads = [.. state.Items("threads").Select(thread =>
                new FilterItem(thread.Number("tid"), "", thread.Number("target")))];
            traceDiagnostics = [.. state.Items("diagnostics").Select(item =>
                new TraceDiagnostic(item.Number("target"), item.Text("message")))];
            traceSkippedChildren = state.Number("skippedChildren");
            UpdateTargets(targets);
        }
        finally
        {
            updating = false;
        }
    }

    private async Task Advance(bool finished)
    {
        // A frozen or slowest-first view keeps its calls in place; finished captures reopen slowest-first once.
        if (activeView is not { } owner) return;
        if (finished && Order == "slowest")
        {
            await OpenView();
            return;
        }
        var generation = viewGeneration;
        var revision = owner.Revision;
        var extend = finished || Order == "oldest" || Following;
        var count = calls.Count;
        var refreshDetails = selected is { IsPending: true };
        var (first, last) = VisibleRange();
        var state = await owner.Advance(extend, first: first, last: last,
            following: Following, newest: Order == "newest");
        if (generation != viewGeneration) return;
        if (state.Flag("stale"))
        {
            await OpenView();
            return;
        }
        if (state.Number("changedFrom") < count) await Reselect(generation);
        if (Following) ScrollToNewest();
        if (refreshDetails && selected is { } call) await ReadDetails(call);
        if (state.Number("revision") != revision || finished)
        {
            if (FindBar.Visibility == Visibility.Visible && !findTimer.IsEnabled) await RefreshFind(false);
            if (DateTime.UtcNow >= nextTimeline) await RefreshTimeline();
        }
        if (finished) nextSummary = DateTime.MinValue;
        await RefreshSummary();
    }

    private (int First, int Last) VisibleRange()
    {
        callScroll ??= ToolWindow.Descendant<ScrollViewer>(CallsGrid);
        var first = (int)(callScroll?.VerticalOffset ?? 0);
        return (first, first + Math.Max(1, (int)(callScroll?.ViewportHeight ?? 40)));
    }

    private void FocusCall()
    {
        // Focus that moved to another control stays there; focus that fell out of the list returns to it.
        if (Keyboard.FocusedElement is not (null or MainWindow or DataGridCell { IsVisible: false })) return;
        if (CallsGrid.SelectedItem is { } item && CallsGrid.ItemContainerGenerator.ContainerFromItem(item) is
            DataGridRow row && ToolWindow.Descendant<DataGridCell>(row) is { } cell) cell.Focus();
        else CallsGrid.Focus();
    }

    private void ScrollToNewest()
    {
        callScroll ??= ToolWindow.Descendant<ScrollViewer>(CallsGrid);
        callScroll?.ScrollToVerticalOffset(Order == "oldest" ? calls.Count : 0);
    }

    private async void LoadBlocks()
    {
        // One request at a time loads the most recently displayed block first.
        if (pumping || client is null || closing) return;
        pumping = true;
        try
        {
            while (!closing && activeView is { Id: not 0 } owner && calls.NextRequest() is { } number)
            {
                var generation = viewGeneration;
                JsonElement rows;
                try
                {
                    rows = await owner.Query("rows", new
                    {
                        view, index = (long)number * CallList.BlockSize, limit = CallList.BlockSize
                    });
                }
                catch (Exception error)
                {
                    if (generation == viewGeneration && !closing) ShowError(error.Message);
                    return;
                }
                if (generation == viewGeneration)
                {
                    if (owner.IsCurrent(rows)) calls.Fill(number, rows.Items("calls"));
                    else
                    {
                        calls.Retry(number);
                        break;
                    }
                }
            }
            ShowSpan();
        }
        finally
        {
            pumping = false;
        }
    }

    private async Task Reselect(long generation)
    {
        // Keep the inspected call selected and in view when it is still part of the list.
        if (selected is not { } call || activeView is not { Id: not 0 } owner) return;
        var result = await owner.Query("locate", new { target = call.Target, callId = call.Id });
        if (generation != viewGeneration || selected != call || !owner.IsCurrent(result)) return;
        var index = (int)result.Number("index", -1);
        updating = true;
        try
        {
            if (index < 0 || index >= calls.Count)
            {
                calls.Pinned = null;
                CallsGrid.SelectedItem = null;
                return;
            }
            calls.Pinned = selected = calls.Adopt(index, call);
            CallsGrid.SelectedItem = selected;
            CallsGrid.ScrollIntoView(selected);
        }
        finally
        {
            updating = false;
        }
    }

    private void UpdateResults()
    {
        if (!IsInitialized) return;
        EmptyState.Visibility = calls.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (database.Length == 0 || filterError.Length > 0)
        {
            EmptyTitle.Text = database.Length == 0 ? "No trace loaded" : "Filter not understood";
            EmptyMessage.Text = database.Length == 0 ? "Launch, attach, or open a capture database." : filterError;
            ResultsText.Text = "";
            return;
        }
        var ranked = Order == "slowest";
        var waiting = view == 0 && opening == 0 && live;
        EmptyTitle.Text = waiting ? "Waiting for calls…" : viewComplete ? "No matching calls" :
            ranked ? "Ranking calls…" : "Loading calls…";
        EmptyMessage.Text = waiting ? "" : !viewComplete ? ranked && scanned > 0 ? $"{scanned:N0} calls examined" : "" :
            live ? "Waiting for calls that match the display filters." : "No recorded calls match the display filters.";
        ResultsText.Text = waiting ? "" : !viewComplete ? ranked ? "Ranking…" : $"{calls.Count:N0}+ · indexing…" :
            ranked ? $"{calls.Count:N0} slowest · {totalCalls:N0} total" :
            $"{calls.Count:N0} {(Filtered ? "matching" : "shown")} · {totalCalls:N0} total";
        if (SummaryCheck.IsChecked == true && summaryText.Length > 0 && viewComplete) ResultsText.Text = summaryText;
    }

    private static void SetFilterItems(ComboBox combo, IEnumerable<FilterItem> items)
    {
        var selection = combo.SelectedItem as FilterItem;
        var values = items.ToArray();
        if (combo.ItemsSource is IEnumerable<FilterItem> existing && existing.SequenceEqual(values)) return;
        combo.ItemsSource = values;
        combo.SelectedItem = values.FirstOrDefault(item => item.Id == selection?.Id &&
            item.Target == selection.Target) ?? values[0];
    }

    private void UpdateCoverage()
    {
        var target = (ProcessCombo.SelectedItem as FilterItem)?.Id ?? 0;
        var visible = targetCoverage.Where(item => target == 0 || item.Target == target).ToArray();
        CoverageButton.Visibility = visible.Length > 0 || traceDiagnostics.Length > 0 ?
            Visibility.Visible : Visibility.Collapsed;
        if (visible.Length == 0)
        {
            CoverageText.Text = traceDiagnostics.Length > 0 ? "Capture diagnostics available" :
                "Target coverage is not available yet";
            return;
        }
        var unsupported = visible.SelectMany(item => item.UnknownExports).Distinct().Count();
        CoverageText.Text = $"Native {visible.Sum(item => item.Installed):N0} · " +
            $"Win32 {visible.Sum(item => item.Win32Installed):N0} · COM {visible.Sum(item => item.ComHooks):N0} · " +
            $"CLR methods {visible.Sum(item => item.ManagedApis):N0}";
        var scope = target == 0 && visible.Length > 1 ? "Counts are summed across captured processes. " : "";
        CoverageText.ToolTip = scope + "Unsupported export names are counted once across the selected processes.\n" +
            $"{unsupported:N0} system exports without typed signatures. " +
            "Installed hooks are independent of capture filters.\n" + coverageNote;
    }

    private void UpdateTargets(JsonElement[] targets)
    {
        targetCoverage = targets.Select(TargetCoverage.FromJson).ToArray();
        var processItems = targets.Select(target => new FilterItem(target.Number("id"),
            $"{Path.GetFileName(target.Text("image"))} · {target.Number("pid")} · {target.Text("state")}"));
        SetFilterItems(ProcessCombo, processItems.Prepend(new(0, "All processes")));
        UpdateThreads();
        UpdateCoverage();
    }

    private void UpdateThreads()
    {
        // Threads of every process are offered until a process is chosen; several processes show their identifiers.
        var process = (ProcessCombo.SelectedItem as FilterItem)?.Id ?? 0;
        var pids = targetCoverage.ToDictionary(target => target.Target, target => target.Pid);
        SetFilterItems(ThreadCombo, traceThreads.Where(thread => process == 0 || thread.Target == process)
            .Select(thread => new FilterItem(thread.Id, $"Thread {thread.Id}" + (process == 0 && pids.Count > 1 ?
                $" · PID {pids.GetValueOrDefault(thread.Target)}" : ""), thread.Target))
            .Prepend(new(0, "All threads")));
    }

    private void ShowCoverage(object sender, RoutedEventArgs e)
    {
        if (targetCoverage.Length == 0 && traceDiagnostics.Length == 0) return;
        new CoverageWindow(targetCoverage, (ProcessCombo.SelectedItem as FilterItem)?.Id ?? 0, coverageNote,
            traceDiagnostics)
        {
            Owner = this
        }.ShowDialog();
    }

    private async void FilterChanged(object sender, SelectionChangedEventArgs e)
    {
        if (updating || !IsLoaded || database.Length == 0) return;
        if (sender == ProcessCombo)
        {
            updating = true;
            ThreadCombo.SelectedIndex = 0;
            UpdateThreads();
            updating = false;
            UpdateCoverage();
        }
        await RefreshView();
    }

    private async void OrderChanged(object sender, SelectionChangedEventArgs e)
    {
        if (updating || !IsLoaded) return;
        await RefreshView();
    }

    private void SearchChanged(object sender, TextChangedEventArgs e)
    {
        // The application-calls switch mirrors its filter term however the text was changed.
        if (!IsLoaded) return;
        var nested = updating;
        updating = true;
        FromAppCheck.IsChecked = Terms(ApiSearch.Text).Contains("from:app", StringComparer.OrdinalIgnoreCase);
        updating = nested;
        if (updating) return;
        UpdateSuggestions();
        UpdateActions();
        searchTimer.Stop();
        searchTimer.Start();
    }

    private void ClearApiSearch(object sender, RoutedEventArgs e)
    {
        ApiSearch.Clear();
        ApiSearch.Focus();
    }

    private async void ClearDisplayFilters(object sender, RoutedEventArgs e)
    {
        // Clear display choices together so only the final unfiltered view is requested.
        searchTimer.Stop();
        updating = true;
        ProcessCombo.SelectedIndex = ThreadCombo.SelectedIndex = CategoryCombo.SelectedIndex = 0;
        UpdateThreads();
        ApiSearch.Clear();
        FailuresCheck.IsChecked = false;
        updating = false;
        UpdateCoverage();
        await RefreshView();
    }

    private async void DisplayFilterChanged(object sender, RoutedEventArgs e)
    {
        if (updating || !IsLoaded) return;
        await RefreshView();
    }

    private void FollowChanged(object sender, RoutedEventArgs e)
    {
        // Resuming picks up the calls recorded while the list was held still on the next status update.
        if (!updating && Following) records = -1;
    }

    private void PauseFollowing()
    {
        if (live && FollowCheck.IsChecked == true) FollowCheck.IsChecked = false;
    }

    private void CallsScrolled(object sender, MouseWheelEventArgs e) => PauseFollowing();

    private async void CallSelected(object sender, SelectionChangedEventArgs e)
    {
        if (updating || CallsGrid.SelectedItem is not CallItem call || client is null) return;
        calls.Pinned = selected = call;
        PauseFollowing();
        while (!call.Loaded && selected == call) await Task.Delay(LoadWaitDelayMs);
        if (selected != call) return;
        DetailTitle.Text = call.Name;
        DetailSubtitle.Text = $"{call.Category} · {call.Module} · PID {call.Pid} · TID {call.Tid}";
        DetailContext.Text = $"Call {call.Id}";
        DetailSignature.Text = "";
        DetailSummary.Text = "Loading call details…";
        DetailText.Text = "Loading captured parameters…";
        Parameters.Clear("Loading parameters…");
        StackGrid.ItemsSource = null;
        StackStatus.Text = "Loading stack…";
        UpdateActions();
        try
        {
            await ReadDetails(call);
        }
        catch (Exception error)
        {
            if (selected != call) return;
            Parameters.Clear("Parameters unavailable");
            StackStatus.Text = "Stack unavailable";
            ShowError(error.Message);
        }
    }

    private void ClearDetails()
    {
        // Remove the previous inspector contents whenever its trace selection changes.
        DetailTitle.Text = "Call inspector";
        DetailSubtitle.Text = "No call selected";
        DetailContext.Text = DetailSignature.Text = "";
        DetailContext.ToolTip = null;
        DetailSummary.Text = "Select a trace row to inspect its parameters.";
        DetailText.Clear();
        Parameters.Clear();
        StackGrid.ItemsSource = null;
        StackStatus.Text = "No stack recorded.";
    }

    private async Task ReadDetails(CallItem call)
    {
        if (client is null) return;
        var result = await client.Send("details", new { database, target = call.Target, callId = call.Id });
        if (selected != call || closing) return;
        DetailText.Text = result.Text("text");
        Parameters.ShowCall(result);
        ShowStack(result);
        call.DurationUs = result.Decimal("durationUs", call.DurationUs);
        call.AdjustedDurationUs = result.Decimal("adjustedDurationUs", call.AdjustedDurationUs);
        call.Result = result.Text("result", call.Result);
        call.State = result.Text("state", call.State);
        call.Flags = result.Number("flags", call.Flags);
        call.Error = result.Number("error", call.Error);
        call.DescribeFailure(result);
        var signature = ApiMetadata.Function(call.Name, call.Module, result.Text("parameters"));
        DetailSignature.Text = signature is null ? result.Text("parameters") :
            $"{signature.Result} {call.Name}({string.Join(", ", signature.Parameters.Select(
                parameter => $"{parameter.Type} {parameter.Name}"))})";
        DetailContext.Text = $"Call {call.Id} · Caller {result.Text("caller")}" +
            (result.Text("callerDisplay", result.Text("callerText")) is { Length: > 0 } origin ? $" · {origin}" : "");
        DetailContext.ToolTip = result.Text("callerPath") is { Length: > 0 } image ? image : null;
        if (result.Text("callerSource") is { Length: > 0 } source)
            DetailContext.ToolTip += $"\n{source}:{result.Number("callerLine")}";
        DetailSummary.Text = call.EntryOnly ? "Entry only · return observation unavailable" :
            $"{call.State} · elapsed {call.Duration} µs · adjusted {call.AdjustedDuration} µs · " +
            $"result {call.ResultDisplay}";
        if (result.TryGetProperty("completion", out var completion))
            DetailSummary.Text += $"\nCompletion {completion.Text("status")} · " +
                (completion.Number("domain") == 4 ? "" : $"{completion.Number("transferred")} bytes · ") +
                $"observed after {completion.Decimal("elapsedUs"):N1} µs";
        if (call.IsRaw) DetailSummary.Text += signature is null ?
            " · raw arguments; signature unavailable" : " · raw arguments; layout unverified";
        if ((call.Flags & (long)EventFlags.StackUnavailable) != 0) DetailSummary.Text += " · caller-only stack";

        call.Refresh();
        UpdateActions();
    }

    private void GridRightClicked(object sender, MouseButtonEventArgs e) => ToolWindow.SelectContextRow(sender, e);

    private void CallContextOpening(object sender, ContextMenuEventArgs e)
    {
        if (busy || selected is not { Loaded: true } || client is null ||
            (e.CursorLeft >= 0 && (e.OriginalSource is not DependencyObject source ||
                ItemsControl.ContainerFromElement(CallsGrid, source) is not DataGridRow)))
        {
            e.Handled = true;
            return;
        }
        CallsGrid.ContextMenu = CreateCallMenu(selected);
    }

    private void Copy(string text)
    {
        try
        {
            Clipboard.SetText(text);
            StatusText.Text = "Copied to the clipboard";
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            ShowError("The clipboard is in use by another application.");
        }
    }

    private void SelectThread(CallItem call, bool context = false)
    {
        // Choosing the process lists its threads; both choices then request one view.
        updating = true;
        ProcessCombo.SelectedItem = (ProcessCombo.ItemsSource as IEnumerable<FilterItem>)?
            .FirstOrDefault(item => item.Id == call.Target) ?? ProcessCombo.SelectedItem;
        UpdateThreads();
        ThreadCombo.SelectedItem = (ThreadCombo.ItemsSource as IEnumerable<FilterItem>)?
            .FirstOrDefault(item => item.Id == call.Tid && item.Target == call.Target) ?? ThreadCombo.SelectedItem;
        if (context)
        {
            // A chronological thread view retains the inspected call while removing every hiding filter.
            searchTimer.Stop();
            ApiSearch.Clear();
            CategoryCombo.SelectedIndex = 0;
            FailuresCheck.IsChecked = SummaryCheck.IsChecked = false;
            if (OrderCombo.SelectedIndex == 2) OrderCombo.SelectedIndex = 0;
            calls.Pinned = selected = call;
            PauseFollowing();
        }
        updating = false;
        UpdateCoverage();
        _ = RefreshView();
    }

    private Task SendFilters(ulong categoryMask, string[] excludedApis) => client!.Send("filters", new
    {
        apiMask = settings.ApiMask.ToString(CultureInfo.InvariantCulture),
        categoryMask = categoryMask.ToString(CultureInfo.InvariantCulture), excludedApis
    });

    private async Task ApplyCaptureExclusion(string? api, CategoryInfo? category)
    {
        if (client is null || busy) return;
        var excluded = api is null ? settings.ExcludedApis :
            settings.ExcludedApis.Append(api).Distinct(StringComparer.Ordinal).ToArray();
        var mask = category is null ? settings.CategoryMask : settings.CategoryMask & ~category.Mask;
        await Run(async () =>
        {
            if (live) await SendFilters(mask, excluded);
            settings.ExcludedApis = excluded;
            settings.CategoryMask = mask;
            settings.Save();
            StatusText.Text = $"Excluded {api ?? category!.Name} from capture" + (live ? "" : " · next capture");
        });
    }

    private void ChooseColumns(object sender, RoutedEventArgs e)
    {
        // Column choices preserve the user's ordering and keep secondary metadata available on demand.
        var menu = new ContextMenu { PlacementTarget = ColumnsButton };
        foreach (var column in CallsGrid.Columns.OrderBy(column => column.DisplayIndex))
        {
            var item = new MenuItem
            {
                Header = column.Header, IsCheckable = true, IsChecked = column.Visibility == Visibility.Visible
            };
            item.Click += (_, _) =>
            {
                columnsCustomized = true;
                column.Visibility = item.IsChecked ? Visibility.Visible : Visibility.Collapsed;
            };
            menu.Items.Add(item);
        }
        menu.Items.Add(new Separator());
        var indent = new MenuItem
        {
            Header = "Indent Nested Calls", IsCheckable = true, IsChecked = settings.IndentNested
        };
        indent.Click += (_, _) =>
        {
            CallItem.IndentNested = settings.IndentNested = indent.IsChecked;
            foreach (CallItem call in calls) call.Refresh();
        };
        menu.Items.Add(indent);
        var strip = new MenuItem { Header = "Timeline", IsCheckable = true, IsChecked = settings.Timeline };
        strip.Click += async (_, _) =>
        {
            settings.Timeline = strip.IsChecked;
            await RefreshTimeline();
        };
        menu.Items.Add(strip);
        menu.Items.Add(new Separator());
        var export = new MenuItem { Header = "Export Listed Calls…", InputGestureText = "Ctrl+E" };
        export.Click += (_, _) => ExportCalls();
        menu.Items.Add(export);
        menu.IsOpen = true;
    }

    private void CallListResized(object sender, SizeChangedEventArgs e)
    {
        // Wrap display filters when their search field would become too narrow.
        if (FilterBar is null) return;
        var wrapped = e.NewSize.Width < 890;
        FilterBar.ColumnDefinitions[0].Width = wrapped ? new(1, GridUnitType.Star) : new(180);
        FilterBar.ColumnDefinitions[1].Width = new(wrapped ? 0 : 125);
        FilterBar.ColumnDefinitions[2].Width = wrapped ? new(0) : new(1, GridUnitType.Star);
        Grid.SetColumnSpan(ProcessCombo, wrapped ? 3 : 1);
        Grid.SetColumn(ThreadCombo, wrapped ? 3 : 1);
        ThreadCombo.Margin = new(0, 0, wrapped ? 0 : 5, 0);
        Grid.SetRow(SearchPanel, wrapped ? 1 : 0);
        Grid.SetColumn(SearchPanel, wrapped ? 0 : 2);
        Grid.SetColumnSpan(SearchPanel, wrapped ? 3 : 1);
        SearchPanel.Margin = new(0, wrapped ? 5 : 0, 5, 0);
        Grid.SetRow(DisplayFilters, wrapped ? 1 : 0);
        DisplayFilters.Margin = new(0, wrapped ? 5 : 0, 0, 0);

        // Keep identity, function, arguments and result visible in narrow views until columns are customized.
        if (columnsCustomized || TimeColumn is null) return;
        var width = e.NewSize.Width;
        var state = width >= 730 ? Visibility.Visible : Visibility.Collapsed;
        var minimum = width >= 900 ? 205 : 130;
        if (StateColumn.Visibility == state && TimeColumn.Visibility == state && FunctionColumn.MinWidth == minimum)
            return;
        StateColumn.Visibility = TimeColumn.Visibility = state;
        FunctionColumn.MinWidth = minimum;
        ArgumentsColumn.MinWidth = width >= 900 ? 180 : 100;

        // After layout, cycling the proportional columns recomputes every width squeezed during the resize.
        Dispatcher.BeginInvoke(() =>
        {
            if (columnsCustomized) return;
            FunctionColumn.Width = new(FunctionColumn.ActualWidth);
            ArgumentsColumn.Width = new(ArgumentsColumn.ActualWidth);
            FunctionColumn.Width = new(1.2, DataGridLengthUnitType.Star);
            ArgumentsColumn.Width = new(1.5, DataGridLengthUnitType.Star);
        }, DispatcherPriority.Loaded);
    }

    private async void WindowKeyDown(object sender, KeyEventArgs e)
    {
        var control = Keyboard.Modifiers == ModifierKeys.Control;
        if (control && e.Key == Key.F)
        {
            e.Handled = true;
            OpenFind();
        }
        else if (control && e.Key == Key.L)
        {
            e.Handled = true;
            ApiSearch.Focus();
            ApiSearch.SelectAll();
        }
        else if (control && e.Key == Key.O)
        {
            e.Handled = true;
            OpenTrace(sender, e);
        }
        else if (control && e.Key == Key.E)
        {
            e.Handled = true;
            ExportCalls();
        }
        else if (control && e.Key == Key.G && selected is { Loaded: true } call && !busy)
        {
            e.Handled = true;
            SelectThread(call, true);
        }
        else if (control && e.Key == Key.R && settings.RecentTargets.FirstOrDefault() is { } target)
        {
            e.Handled = true;
            await Launch(target.Executable, target.Arguments, target.WorkingDirectory, target.ExpectedExitCodes);
        }
        else if (e.Key == Key.F3 || (e.Key == Key.Enter && FindText.IsKeyboardFocused))
        {
            // The first press opens the find bar; later presses step through the matches.
            e.Handled = true;
            if (FindBar.Visibility != Visibility.Visible) OpenFind();
            else await Step(Keyboard.Modifiers != ModifierKeys.Shift);
        }
        else if (e.Key == Key.Escape && exporting)
        {
            e.Handled = true;
            cancelExport = true;
        }
        else if (e.Key == Key.Escape && FindText.IsKeyboardFocused)
        {
            e.Handled = true;
            CloseFind(sender, e);
        }
        else if (e.Key == Key.Escape && ApiSearch.IsKeyboardFocused && !SuggestPopup.IsOpen &&
            ApiSearch.Text.Length > 0)
        {
            e.Handled = true;
            ApiSearch.Clear();
        }
        else if (e.Key == Key.F5 && database.Length > 0)
        {
            e.Handled = true;
            await RefreshView();
        }
    }

    private async void OpenSettings(object sender, RoutedEventArgs e) => await ShowSettings(0);
    private async void OpenCaptureFilters(object sender, RoutedEventArgs e) => await ShowSettings(1);

    private async Task ShowSettings(int section)
    {
        if (client is null || busy) return;
        var dialog = new SettingsWindow(settings, catalog, categories, live, section) { Owner = this };
        if (dialog.ShowDialog() != true) return;
        settings.Save();
        UpdateActions();
        await Run(async () =>
        {
            await client.Send("symbols", new { directories = settings.SymbolDirectories });
            if (live) await SendFilters(settings.CategoryMask, settings.ExcludedApis);
            if (database.Length > 0) await OpenView();
        });
    }

    private async void BreakOnEntry(object sender, RoutedEventArgs e)
    {
        if (selected is { } call) await SetBreakpoint(call, false);
    }

    private async void BreakOnReturn(object sender, RoutedEventArgs e)
    {
        if (selected is { } call) await SetBreakpoint(call, true);
    }

    private async Task SetBreakpoint(CallItem call, bool leaving)
    {
        if (!live || busy || client is null || Protocol.IsManagedApi(call.Api) ||
            leaving && call.EntryOnly) return;
        if (leaving) exitApi = call.Api;
        else entryApi = call.Api;
        await ApplyBreakpoints();
    }

    private async void ClearBreakpoints(object sender, RoutedEventArgs e)
    {
        entryApi = exitApi = -1;
        await ApplyBreakpoints();
    }

    private async Task ApplyBreakpoints()
    {
        if (client is null) return;
        await Run(async () => await client.Send("breakApi", new { entryApi, exitApi }));
    }

    private void OpenCatalog(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        new CatalogEditorWindow(CatalogEditorWindow.DefaultPath) { Owner = this }.ShowDialog();
    }

    private async void InspectDll(object sender, RoutedEventArgs e)
    {
        if (client is null || busy) return;
        var dialog = new OpenFileDialog
        {
            Title = "Inspect DLL exports", Filter = "DLL files (*.dll)|*.dll|All files|*.*"
        };
        if (dialog.ShowDialog(this) != true) return;
        await Run(async () =>
        {
            StatusText.Text = "Reading DLL export table…";
            var result = await client.Send("exports", new { path = dialog.FileName });
            new ExportWindow(dialog.FileName, result) { Owner = this }.ShowDialog();
        });
    }

    private async void WindowDrop(object sender, DragEventArgs e)
    {
        if (live || client is null || e.Data.GetData(DataFormats.FileDrop) is not string[] paths ||
            paths.Length == 0) return;
        await Run(() => LoadTrace(paths[0]));
    }

    private async void WindowClosing(object? sender, CancelEventArgs e)
    {
        if (closed) return;
        e.Cancel = true;
        if (closing) return;
        closing = true;
        activeView?.Dispose();
        foundView?.Dispose();
        pollTimer.Stop();
        searchTimer.Stop();
        findTimer.Stop();
        timelineTimer.Stop();
        SaveLayout();
        IsEnabled = false;
        StatusText.Text = "Releasing capture targets…";
        if (client is not null)
        {
            try
            {
                await client.DisposeAsync();
            }
            catch (Exception error)
            {
                StatusText.Text = error.Message;
            }
        }
        closed = true;
        _ = Dispatcher.InvokeAsync(Close);
    }
}

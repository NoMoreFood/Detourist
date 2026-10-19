using Microsoft.Win32;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;

namespace Detourist.Desktop;

public sealed class WindowSpyWindow : ToolWindow
{
    private const int PollIntervalMs = 200;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly ComboBox view = new() { Width = 125, ItemsSource = new[] { "Windows", "Processes", "Threads" } };
    private readonly TextBox search = new() { Width = 260 };
    private readonly TreeView tree = new();
    private readonly DataGrid properties = new();
    private readonly Button finder = new()
    {
        Content = "⊕ _Find window",
        ToolTip = "Drag onto a window; Esc cancels. Alt+F inspects the window under the pointer."
    };
    private readonly Button highlight = new() { Content = "_Highlight" };
    private readonly Button refresh = new() { Content = "_Refresh", ToolTip = "Refresh all views (F5)" };
    private readonly ComboBox scope = new() { Width = 100 };
    private readonly CheckBox children = new() { Content = "_Children", IsChecked = true };
    private readonly Button start = new() { Content = "Start _logging" };
    private readonly Button stop = new() { Content = "_Stop" };
    private readonly Button clear = new() { Content = "Cl_ear" };
    private readonly Button export = new() { Content = "E_xport…" };
    private readonly TextBox messageFilter = new() { Width = 250 };
    private readonly ComboBox kind = new()
    {
        Width = 100, ItemsSource = new[] { "All types", "Sent", "Return", "Posted", "Peek" }
    };
    private readonly ComboBox category = new()
    {
        Width = 120, ItemsSource = new[] { "All messages", "Window", "Keyboard", "Mouse", "Control", "Application" }
    };
    private readonly CheckBox follow = new() { Content = "Follow _tail", IsChecked = true };
    private readonly DataGrid messages = new()
    {
        SelectionMode = DataGridSelectionMode.Extended, CanUserSortColumns = false
    };
    private readonly TextBox detail = new()
    {
        IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MinHeight = 54, MaxHeight = 95,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new(0, 6, 0, 0)
    };
    private readonly TextBlock status = new() { TextWrapping = TextWrapping.Wrap, Margin = new(0, 6, 0, 0) };
    private readonly TextBlock logTitle = new() { TextWrapping = TextWrapping.Wrap, Margin = new(0, 5, 0, 5) };
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromMilliseconds(PollIntervalMs) };
    private readonly DispatcherTimer filterTimer = new() { Interval = TimeSpan.FromMilliseconds(Protocol.UiDebounceMs) };
    private readonly List<WindowMessage> records = [];
    private readonly Func<ProcessItem, Task>? capture;
    private readonly Func<bool>? canCapture;
    private readonly Button captureButton;
    private CollectorClient? reader;
    private CollectorClient? logger;
    private JsonElement snapshot;
    private JsonElement picked;
    private SpyNode? selected;
    private WindowSpyHighlight? outline;
    private DateTime outlineUntil;
    private Task operation = Task.CompletedTask;
    private Task polling = Task.CompletedTask;
    private Task picking = Task.CompletedTask;
    private Task? cleanup;
    private long selectionGeneration;
    private long sequence;
    private long dropped;
    private long evicted;
    private string logTarget = "No message log";
    private string appliedSearch = "";
    private bool dragging;
    private Cursor? previousCursor;
    private bool busy;
    private bool closing;
    private bool closed;
    private bool rebuilding;
    private int pointerSize = 8;

    public WindowSpyWindow(Func<ProcessItem, Task>? capture = null, Func<bool>? canCapture = null) :
        base("Window Spy", "Inspect windows, processes and threads, or log the messages delivered to them.", 1240, 850)
    {
        this.capture = capture;
        this.canCapture = canCapture;
        MinWidth = 780;
        MinHeight = 600;

        // Keep both the inspection and logging controls usable when the tool is resized or text is scaled.
        SetRows(Body, GridLength.Auto, new(0.9, GridUnitType.Star), new(7), GridLength.Auto, Fill,
            GridLength.Auto, GridLength.Auto);
        var toolbar = new WrapPanel { Margin = new(0, 0, 0, 5) };
        foreach (var control in new FrameworkElement[] { view, search, finder, highlight, refresh })
        {
            control.Margin = new(0, 0, 7, 5);
            toolbar.Children.Add(control);
        }
        Body.Children.Add(toolbar);
        search.ToolTip = "Search by caption, class, handle, process name, PID or TID";
        AutomationProperties.SetName(view, "Object view");
        AutomationProperties.SetName(search, "Search windows, processes and threads");
        AutomationProperties.SetName(finder, "Drag to find a window");
        var inspection = new Grid();
        inspection.ColumnDefinitions.Add(new() { Width = new(1, GridUnitType.Star), MinWidth = 220 });
        inspection.ColumnDefinitions.Add(new() { Width = new(7) });
        inspection.ColumnDefinitions.Add(new() { Width = new(1.15, GridUnitType.Star), MinWidth = 250 });
        AddRow(Body, 1, inspection);
        tree.Background = (Brush)FindResource("PanelBrush");
        tree.Foreground = (Brush)FindResource("TextBrush");
        tree.BorderBrush = (Brush)FindResource("BorderBrush");
        tree.Resources[SystemColors.ControlBrushKey] = FindResource("PanelBrush");
        tree.Resources[SystemColors.InactiveSelectionHighlightBrushKey] =
            new SolidColorBrush(Color.FromRgb(41, 73, 100));
        tree.Resources[SystemColors.InactiveSelectionHighlightTextBrushKey] = FindResource("TextBrush");
        VirtualizingPanel.SetIsVirtualizing(tree, true);
        VirtualizingPanel.SetVirtualizationMode(tree, VirtualizationMode.Recycling);
        ScrollViewer.SetHorizontalScrollBarVisibility(tree, ScrollBarVisibility.Disabled);
        ScrollViewer.SetVerticalScrollBarVisibility(tree, ScrollBarVisibility.Visible);

        tree.ItemTemplate = (HierarchicalDataTemplate)FindResource("SpyNodeTemplate");
        tree.ItemContainerStyle = (Style)FindResource("SpyTreeItem");
        AutomationProperties.SetName(tree, "System objects");
        var objects = new DockPanel();
        var headings = new DockPanel { Margin = new(25, 0, SystemParameters.VerticalScrollBarWidth + 9, 0) };
        var idHeading = new TextBlock
        {
            Text = "HANDLE / ID", Width = 110, Margin = new(8, 0, 0, 0), FontSize = 11,
            Foreground = (Brush)FindResource("MutedBrush")
        };
        DockPanel.SetDock(idHeading, Dock.Right);
        headings.Children.Add(idHeading);
        headings.Children.Add(new TextBlock
        {
            Text = "OBJECT", FontSize = 11, Foreground = (Brush)FindResource("MutedBrush")
        });
        var objectHeader = new Border
        {
            Child = headings, Padding = new(0, 5, 0, 5), Background = (Brush)FindResource("RaisedBrush")
        };
        DockPanel.SetDock(objectHeader, Dock.Top);
        objects.Children.Add(objectHeader);
        objects.Children.Add(tree);
        inspection.Children.Add(objects);
        var vertical = new GridSplitter { Width = 5, HorizontalAlignment = HorizontalAlignment.Center };
        Grid.SetColumn(vertical, 1);
        inspection.Children.Add(vertical);
        properties.Columns.Add(Column("PROPERTY", "Name", 155));
        var value = Column("VALUE", "Value", 130);
        value.Width = new(1, DataGridLengthUnitType.Star);
        var wrapping = new Style(typeof(TextBlock), CellText);
        wrapping.Setters.Add(new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap));
        value.ElementStyle = wrapping;
        properties.Columns.Add(value);
        properties.RowHeight = double.NaN;
        Grid.SetColumn(properties, 2);
        inspection.Children.Add(properties);
        AutomationProperties.SetName(properties, "Selected object properties");
        var horizontal = new GridSplitter { Height = 5, HorizontalAlignment = HorizontalAlignment.Stretch };
        AddRow(Body, 2, horizontal);

        // Message filters affect the retained log and export without changing the hooked target.
        var logControls = new StackPanel();
        logControls.Children.Add(logTitle);
        var commands = new WrapPanel();
        foreach (var control in new FrameworkElement[] { scope, children, start, stop, clear, export, follow })
        {
            control.Margin = new(0, 0, 8, 5);
            control.VerticalAlignment = VerticalAlignment.Center;
            commands.Children.Add(control);
        }
        logControls.Children.Add(commands);
        var filters = new WrapPanel();
        foreach (var control in new FrameworkElement[] { messageFilter, kind, category })
        {
            control.Margin = new(0, 0, 8, 6);
            filters.Children.Add(control);
        }
        logControls.Children.Add(filters);
        AddRow(Body, 3, logControls);
        AutomationProperties.SetName(scope, "Message target scope");
        scope.ToolTip = "Log this window, its thread, or its process. New GUI threads are discovered every second.";
        AutomationProperties.SetName(messageFilter, "Filter messages");
        AutomationProperties.SetName(kind, "Message type");
        AutomationProperties.SetName(category, "Message category");
        messageFilter.ToolTip = "Filter message name, code, HWND, TID, parameters or decoded values";
        messages.Columns.Add(Column("TIME (s)", "Time", 100));
        messages.Columns.Add(Column("TYPE", "Kind", 65));
        messages.Columns.Add(Column("HWND", "Window", 100));
        messages.Columns.Add(Column("TID", "Tid", 65));
        messages.Columns.Add(Column("MESSAGE", "Name", 200));
        messages.Columns.Add(Column("CODE", "Code", 75));
        messages.Columns.Add(Column("WPARAM", "WParam", 130));
        messages.Columns.Add(Column("LPARAM", "LParam", 130));
        messages.Columns.Add(Column("RESULT", "ReturnValue", 130));
        messages.Columns.Add(Column("DECODED", "Decoded", 450));
        AddRow(Body, 4, messages);
        AddRow(Body, 5, detail);
        status.Foreground = (Brush)FindResource("MutedBrush");
        AddRow(Body, 6, status);
        AutomationProperties.SetName(messages, "Window messages");
        AutomationProperties.SetName(detail, "Selected message details");
        captureButton = AddAction("_Capture APIs", false, (_, _) =>
        {
            if (selected is { } node && capture is not null && canCapture?.Invoke() == true)
                Run(() => capture(new(node.Pid, node.ProcessName, node.Architecture)));
        });
        AddAction("_Close", false, (_, _) => Close());

        // Keep asynchronous reads tied to their selection, and stop native hooks before closing the tool.
        view.SelectionChanged += (_, _) => Rebuild();
        search.TextChanged += (_, _) => { filterTimer.Stop(); filterTimer.Start(); };
        filterTimer.Tick += (_, _) =>
        {
            filterTimer.Stop();
            if (appliedSearch != search.Text.Trim()) Rebuild();
            FilterMessages();
        };
        tree.SelectedItemChanged += async (_, _) =>
        {
            if (rebuilding) return;
            selected = tree.SelectedItem as SpyNode;
            Error.Text = "";
            UpdateScope();
            await ReadProperties();
        };
        tree.AddHandler(TreeViewItem.SelectedEvent, new RoutedEventHandler((_, args) =>
        {
            if (args.OriginalSource is TreeViewItem item) item.BringIntoView();
        }));
        var menu = new ContextMenu();
        foreach (var (label, all, expanded) in new[]
        {
            ("Expand branch", false, true), ("Collapse branch", false, false),
            ("Expand all", true, true), ("Collapse all", true, false)
        })
        {
            var item = new MenuItem { Header = label };
            item.Click += (_, _) => Expand(all ? tree.Items.Cast<SpyNode>() :
                selected is null ? [] : new[] { selected }, expanded);
            menu.Items.Add(item);
        }
        tree.ContextMenu = menu;
        tree.ContextMenuOpening += (_, _) =>
        {
            foreach (MenuItem item in menu.Items.Cast<MenuItem>().Take(2)) item.IsEnabled = selected is not null;
        };
        tree.PreviewMouseRightButtonDown += (_, args) =>
        {
            if ((args.OriginalSource as FrameworkElement)?.DataContext is SpyNode node) node.Selected = true;
        };
        refresh.Click += (_, _) => Run(Refresh);
        highlight.Click += (_, _) => Run(Highlight);
        scope.SelectionChanged += (_, _) => UpdateActions();
        start.Click += (_, _) => Run(StartLog);
        stop.Click += (_, _) => Run(StopLog);
        clear.Click += (_, _) => Run(ClearLog);
        export.Click += (_, _) => Run(Export);
        foreach (var selector in new[] { kind, category }) selector.SelectionChanged += (_, _) => FilterMessages();
        messageFilter.TextChanged += (_, _) => { filterTimer.Stop(); filterTimer.Start(); };
        messages.SelectionChanged += (_, _) => ShowMessage();
        finder.Click += (_, _) => { picked = default; Run(SelectPicked); };
        finder.PreviewMouseLeftButtonDown += (_, args) =>
        {
            if (busy || reader is null) return;
            dragging = true;
            picked = default;
            Mouse.Capture(finder);
            previousCursor = Mouse.OverrideCursor;
            Mouse.OverrideCursor = Cursors.Cross;
            status.Text = "Drag over a window, then release. Esc cancels.";
            args.Handled = true;
        };
        finder.PreviewMouseLeftButtonUp += (_, args) =>
        {
            if (!dragging) return;
            EndDrag();
            Run(SelectPicked);
            args.Handled = true;
        };
        finder.LostMouseCapture += (_, _) => { if (dragging) EndDrag(); };
        PreviewKeyDown += (_, args) =>
        {
            if (args.Key == Key.Escape && dragging) { EndDrag(); args.Handled = true; }
            else if (args.Key == Key.F5) { Run(Refresh); args.Handled = true; }
            else if (args.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control)
            {
                var input = messages.IsKeyboardFocusWithin || records.Count > 0 ? messageFilter : search;
                input.Focus();
                input.SelectAll();
                args.Handled = true;
            }
        };
        timer.Tick += (_, _) =>
        {
            UpdateActions();
            if (dragging && picking.IsCompleted) picking = Pick();
            if (!dragging && outline is not null && DateTime.UtcNow >= outlineUntil) HideOutline();
            if (logger is not null && !busy && polling.IsCompleted) polling = ReadLog();
        };
        Loaded += (_, _) => { timer.Start(); Run(Refresh); };
        Closing += CloseSpy;
        Closed += async (_, _) =>
        {
            closed = true;
            await (cleanup ??= ReleaseServices());
        };
        view.SelectedIndex = kind.SelectedIndex = category.SelectedIndex = 0;
        UpdateActions();
    }

    private void Run(Func<Task> action)
    {
        if (busy || closing) return;
        operation = Execute(action);
    }

    private async Task Execute(Func<Task> action)
    {
        busy = true;
        Error.Text = "";
        UpdateActions();
        try { await action(); }
        catch (Exception error)
        {
            if (!closing) Error.Text = error.Message;
        }
        finally { busy = false; if (!closing) UpdateActions(); }
    }

    private void UpdateActions()
    {
        var supported = selected?.Architecture is "x64" or "x86";
        var idle = !busy && !closing;
        refresh.IsEnabled = finder.IsEnabled = idle;
        highlight.Visibility = selected?.Kind == "Window" ? Visibility.Visible : Visibility.Collapsed;
        highlight.IsEnabled = idle;
        start.Visibility = logger is null ? Visibility.Visible : Visibility.Collapsed;
        start.IsEnabled = idle && supported && scope.SelectedItem is not null;
        stop.Visibility = logger is null ? Visibility.Collapsed : Visibility.Visible;
        stop.IsEnabled = idle;
        scope.IsEnabled = children.IsEnabled = idle && logger is null;
        children.Visibility = scope.SelectedItem as string == "Window" ? Visibility.Visible : Visibility.Collapsed;
        clear.IsEnabled = idle && (logger is not null || records.Count > 0);
        export.IsEnabled = idle && messages.Items.Count > 0;
        captureButton.Visibility = capture is not null && canCapture?.Invoke() == true && supported &&
            selected?.Pid != Environment.ProcessId ? Visibility.Visible : Visibility.Collapsed;
        captureButton.IsEnabled = idle;
        logTitle.Text = (logger is null ? "Messages · " : "Logging · ") + logTarget;
    }

    private void UpdateScope()
    {
        if (logger is not null) return;
        scope.ItemsSource = selected is null ? Array.Empty<string>() : selected.Kind == "Window" ?
            new[] { "Window", "Thread", "Process" } : selected.Kind == "Thread" ?
            new[] { "Thread", "Process" } : new[] { "Process" };
        scope.SelectedIndex = 0;
        UpdateActions();
    }

    private async Task Refresh()
    {
        status.Text = "Loading system objects…";
        properties.ItemsSource = null;
        ++selectionGeneration;

        // Swap before disposing so selection changes can already use the replacement reader.
        if (reader is not { IsConnected: true })
        {
            var previous = reader;
            reader = new CollectorClient();
            if (previous is not null) await previous.DisposeAsync();
        }
        snapshot = await reader.Send("spySnapshot");
        if (closing) return;
        Rebuild();
        if (logger is not null || records.Count > 0) FilterMessages();
        Error.Text = snapshot.Flag("truncated") ? "The system snapshot reached its display limit." : "";
    }

    private void Rebuild()
    {
        if (snapshot.ValueKind != JsonValueKind.Object || closing) return;
        var key = selected?.Key;
        rebuilding = true;
        appliedSearch = search.Text.Trim();
        var nodes = BuildTree(snapshot, view.SelectedIndex, appliedSearch);
        tree.ItemsSource = nodes;
        selected = key is null ? null : SelectNode(nodes, key);
        rebuilding = false;
        properties.ItemsSource = null;
        ++selectionGeneration;
        UpdateScope();
        _ = ReadProperties();
        _ = RevealSelection();
        if (logger is null && records.Count == 0)
            status.Text = $"{snapshot.Items("windows").Length:N0} windows · " +
                $"{snapshot.Items("processes").Length:N0} processes · {snapshot.Items("threads").Length:N0} threads";
    }

    public static List<SpyNode> BuildTree(JsonElement snapshot, int view, string search)
    {
        var processes = snapshot.Items("processes").ToDictionary(item => item.Number("pid"));
        var threads = snapshot.Items("threads");
        var windows = snapshot.Items("windows").DistinctBy(item => item.Text("window")).ToArray();
        SpyNode Node(string kind, JsonElement item)
        {
            var pid = item.Number("pid");
            var process = processes.GetValueOrDefault(pid);
            var name = process.ValueKind == JsonValueKind.Object ? process.Text("name") : "Unavailable";
            var architecture = process.ValueKind == JsonValueKind.Object ? process.Text("architecture") : "";
            var tid = kind == "Process" ? 0 : item.Number("tid");
            var window = kind == "Window" ? item.Text("window", "0x0") : "0x0";
            var title = kind == "Window" ? item.Text("title") : name;
            if (string.IsNullOrWhiteSpace(title)) title = item.Text("class", "Untitled window");
            return new()
            {
                Kind = kind, Pid = pid, Tid = tid, Window = window, ProcessName = name, Architecture = architecture,
                Key = kind == "Window" ? "w" + window : kind == "Thread" ? "t" + tid : "p" + pid,
                Title = title.Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' '),
                Label = kind == "Window" ? $"{window}  {item.Text("class")}  {item.Text("title")}  [{pid}:{tid}]" :
                    kind == "Thread" ? $"Thread {tid}  ·  {name} ({pid})" : $"{name} ({pid})  {architecture}"
            };
        }
        List<SpyNode> WindowTree(IEnumerable<JsonElement> items)
        {
            var source = items.ToDictionary(item => item.Text("window"));
            var nodes = source.ToDictionary(item => item.Key, item => Node("Window", item.Value));
            var roots = new List<SpyNode>();
            foreach (var (handle, item) in source.OrderBy(pair => nodes[pair.Key].Title,
                StringComparer.OrdinalIgnoreCase).ThenBy(pair => pair.Key, StringComparer.Ordinal))
            {
                var parent = item.Text("parent");
                var visited = new HashSet<string> { handle };
                var ancestor = parent;
                while (source.TryGetValue(ancestor, out var owner) && visited.Add(ancestor))
                    ancestor = owner.Text("parent");
                if (nodes.TryGetValue(parent, out var parentNode) && !visited.Contains(ancestor))
                    parentNode.Children.Add(nodes[handle]);
                else roots.Add(nodes[handle]);
            }
            return roots;
        }

        // Application groups keep the window hierarchy scannable without mixing in background threads.
        List<SpyNode> roots;
        if (view == 0)
        {
            var source = windows.ToDictionary(item => item.Text("window"));
            roots = WindowTree(windows).GroupBy(node => node.Pid).Select(group =>
            {
                var process = Node("Process", source[group.First().Window]);
                process.Children.AddRange(group);
                return process;
            }).OrderBy(node => node.ProcessName, StringComparer.OrdinalIgnoreCase).ThenBy(node => node.Pid).ToList();
        }
        else
        {
            var byThread = windows.ToLookup(item => item.Number("tid"));
            var threadNodes = threads.OrderBy(item => item.Number("tid")).Select(item =>
            {
                var node = Node("Thread", item);
                node.Children.AddRange(WindowTree(byThread[node.Tid]));
                return node;
            }).ToArray();
            if (view == 2) roots = [.. threadNodes.OrderBy(node => node.ProcessName,
                StringComparer.OrdinalIgnoreCase).ThenBy(node => node.Tid)];
            else
            {
                var byProcess = threadNodes.ToLookup(node => node.Pid);
                roots = processes.Values.Select(item =>
                {
                    var node = Node("Process", item);
                    node.Children.AddRange(byProcess[node.Pid]);
                    return node;
                }).OrderBy(node => node.ProcessName, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(node => node.Pid).ToList();
            }
        }
        if (search.Length == 0) return roots;
        bool Match(SpyNode node)
        {
            if (node.Label.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                node.ProcessName.Contains(search, StringComparison.OrdinalIgnoreCase)) return true;
            node.Children.RemoveAll(child => !Match(child));
            node.Expanded = node.Children.Count > 0;
            return node.Children.Count > 0;
        }
        roots.RemoveAll(node => !Match(node));
        return roots;
    }

    private static void Expand(IEnumerable<SpyNode> nodes, bool expanded)
    {
        foreach (var node in nodes) { node.Expanded = expanded; Expand(node.Children, expanded); }
    }

    private static SpyNode? SelectNode(IEnumerable<SpyNode> nodes, string key, List<SpyNode>? path = null)
    {
        foreach (var node in nodes)
        {
            if (node.Key == key) { node.Selected = true; path?.Add(node); return node; }
            if (SelectNode(node.Children, key, path) is not { } selected) continue;
            node.Expanded = true;
            path?.Insert(0, node);
            return selected;
        }
        return null;
    }

    private async Task RevealSelection()
    {
        // Materialize the path before scrolling; the finder can select a window outside the virtualized viewport.
        if (selected is not { } node) return;
        var path = new List<SpyNode>();
        SelectNode(tree.Items.Cast<SpyNode>(), node.Key, path);
        ItemsControl parent = tree;
        foreach (var ancestor in path)
        {
            await Dispatcher.Yield(DispatcherPriority.Loaded);
            if (closing || selected?.Key != node.Key) return;
            parent.UpdateLayout();
            if (parent.ItemContainerGenerator.ContainerFromItem(ancestor) is not TreeViewItem)
            {
                Descendant<VirtualizingPanel>(parent)?.BringIndexIntoViewPublic(parent.Items.IndexOf(ancestor));
                parent.UpdateLayout();
            }
            if (parent.ItemContainerGenerator.ContainerFromItem(ancestor) is not TreeViewItem item) return;
            item.BringIntoView();
            parent = item;
        }
    }

    private async Task ReadProperties()
    {
        var generation = ++selectionGeneration;
        properties.ItemsSource = null;
        if (selected is not { } node || reader is null || closing) return;
        try
        {
            var result = await reader.Send("spyProperties", new
            {
                pid = node.Pid, tid = node.Tid, window = node.Window
            });
            if (generation != selectionGeneration || closing) return;
            properties.ItemsSource = result.EnumerateArray().Select(item =>
                new SpyProperty(item.Text("name"), item.Text("value"))).ToArray();
        }
        catch (IOException error)
        {
            if (generation == selectionGeneration && !closing) Error.Text = error.Message;
        }
    }

    private async Task Pick()
    {
        try
        {
            var result = await reader!.Send("spyPick");
            if (!dragging || closing || result.ValueKind != JsonValueKind.Object ||
                result.Number("pid") == Environment.ProcessId) return;
            picked = result;
            status.Text = $"{result.Text("window")}  {result.Text("class")}  {result.Text("title")}";
            ShowOutline(result);
        }
        catch (IOException error) { EndDrag(); Error.Text = error.Message; }
    }

    private void EndDrag()
    {
        var captured = dragging;
        dragging = false;
        if (captured)
        {
            if (Mouse.Captured == finder) Mouse.Capture(null);
            Mouse.OverrideCursor = previousCursor;
            status.Text = "Window finder stopped.";
        }
        HideOutline();
        Error.Text = "";
    }

    private async Task SelectPicked()
    {
        await picking;
        if (reader is not null && !closing)
        {
            var last = await reader.Send("spyPick");
            if (last.ValueKind == JsonValueKind.Object && last.Number("pid") != Environment.ProcessId) picked = last;
        }
        if (picked.ValueKind != JsonValueKind.Object || closing) return;
        var handle = picked.Text("window");
        search.Text = "";
        view.SelectedIndex = 0;
        await Refresh();
        if (closing) return;
        selected = SelectNode(tree.Items.Cast<SpyNode>(), "w" + handle);
        if (selected is null) Error.Text = "The selected window closed before it could be inspected.";
        else { UpdateScope(); await RevealSelection(); await ReadProperties(); }
    }

    private async Task Highlight()
    {
        if (selected is not { Kind: "Window" } node || reader is null) return;
        var value = await reader.Send("spyWindow", new { pid = node.Pid, window = node.Window });
        if (closing) return;
        if (!value.Flag("visible")) { Error.Text = "This window is hidden."; return; }
        ShowOutline(value);
        outlineUntil = DateTime.UtcNow.AddSeconds(1);
    }

    private void ShowOutline(JsonElement window)
    {
        var width = window.Number("right") - window.Number("left");
        var height = window.Number("bottom") - window.Number("top");
        if (width <= 0 || height <= 0) { HideOutline(); return; }
        outline ??= new WindowSpyHighlight();
        outline.Mark((int)window.Number("left"), (int)window.Number("top"), (int)width, (int)height);
    }

    private void HideOutline() { outline?.Close(); outline = null; }

    private async Task StartLog()
    {
        if (selected is not { } node || scope.SelectedItem is not string target) return;
        pointerSize = node.Architecture == "x86" ? 4 : 8;
        logger = new CollectorClient(pointerSize);
        try
        {
            status.Text = "Installing message hooks…";
            await logger.Send("spyStart", new
            {
                pid = node.Pid, tid = target == "Thread" ? node.Tid : 0,
                window = target == "Window" ? node.Window : "0x0", children = children.IsChecked == true
            });
            if (closing) return;
            records.Clear();
            sequence = dropped = evicted = 0;
            logTarget = $"{node.ProcessName} ({node.Pid}) · {target.ToLowerInvariant()} " +
                (target == "Window" ? node.Window + (children.IsChecked == true ? " + children" : "") :
                    target == "Thread" ? node.Tid.ToString(CultureInfo.InvariantCulture) : "all threads");
            Error.Text = "";
            FilterMessages();
        }
        catch
        {
            var failed = logger;
            logger = null;
            await failed.DisposeAsync();
            throw;
        }
    }

    private async Task ReadLog()
    {
        if (logger is not { } service) return;
        try
        {
            var result = await service.Send("spyPoll");
            if (closing) return;
            Append(result);
            if (!result.Flag("running"))
            {
                logger = null;
                await service.DisposeAsync();
                Error.Text = (result.Text("warning") + " The message target exited. " +
                    "The retained log is still available.").Trim();
                UpdateScope();
            }
        }
        catch (IOException error)
        {
            logger = null;
            await service.DisposeAsync();
            if (!closing) { Error.Text = error.Message; UpdateScope(); }
        }
    }

    private void Append(JsonElement result)
    {
        var items = result.Items("messages");
        var changed = items.Length > 0 || dropped != result.Number("dropped");
        foreach (var item in items) records.Add(WindowMessage.FromJson(item, ++sequence));
        dropped = result.Number("dropped");
        if (records.Count > 10000)
        {
            var count = records.Count - 10000;
            records.RemoveRange(0, count);
            evicted += count;
        }
        if (result.Text("warning") is { Length: > 0 } warning) Error.Text = warning;
        if (changed) FilterMessages();
    }

    private async Task StopLog()
    {
        await polling;
        if (logger is not { } service) return;
        try { Append(await service.Send("spyStop")); }
        finally { logger = null; await service.DisposeAsync(); UpdateScope(); }
    }

    private async Task ClearLog()
    {
        await polling;
        if (logger is { } service)
        {
            var state = await service.Send("spyPoll");
            dropped = state.Number("dropped");
            if (!state.Flag("running"))
            {
                logger = null;
                await service.DisposeAsync();
                UpdateScope();
            }
        }
        records.Clear();
        evicted = 0;
        FilterMessages();
        status.Text = "Message log cleared.";
    }

    private void FilterMessages()
    {
        if (closing) return;
        var selected = messages.SelectedItem;
        var scrolling = Descendant<ScrollViewer>(messages);
        var offset = scrolling?.VerticalOffset ?? 0;
        var visible = records.Where(item => (kind.SelectedIndex <= 0 || item.Type == kind.SelectedIndex - 1) &&
            (category.SelectedIndex <= 0 || item.Category == category.SelectedItem as string) &&
            item.Matches(messageFilter.Text.Trim())).ToArray();
        messages.ItemsSource = visible;
        if (selected is WindowMessage row && visible.Contains(row)) messages.SelectedItem = row;
        if (follow.IsChecked == true && visible.Length > 0) messages.ScrollIntoView(visible[^1]);
        else scrolling?.ScrollToVerticalOffset(offset);
        ShowMessage();
        if (records.Count > 0 || logger is not null)
            status.Text = $"{visible.Length:N0} shown · {records.Count:N0} retained · " +
                $"{evicted:N0} older records removed · {dropped:N0} dropped by hooks";
        UpdateActions();
    }

    private void ShowMessage()
    {
        detail.Text = messages.SelectedItem is not WindowMessage item ? "" :
            $"{item.Name} ({item.Code}) · {item.Kind} · {item.Time} s · {item.Window} · " +
            $"{item.ClassName} · thread {item.Tid}\n" + item.Decoded +
            (item.Type == 1 ? $" · result={item.Result}" : "");
    }

    private async Task Export()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export listed messages", Filter = "JSON (*.json)|*.json|CSV (*.csv)|*.csv",
            FileName = "WindowMessages.json", DefaultExt = ".json"
        };
        if (dialog.ShowDialog(this) != true) return;
        var rows = messages.Items.Cast<WindowMessage>().ToArray();
        var csv = dialog.FilterIndex != 1;
        await ExportFile.Write(dialog.FileName, csv, async writer =>
        {
            if (!csv)
            {
                await writer.WriteAsync(JsonSerializer.Serialize(new { target = logTarget, pointerSize, dropped, evicted,
                    messages = rows }, JsonOptions));
                return;
            }
            await writer.WriteLineAsync("Time,Type,HWND,TID,Message,Code,wParam,lParam,Result,Class,Decoded");
            foreach (var item in rows)
                await writer.WriteLineAsync(string.Join(',', new[]
                {
                    item.Time, item.Kind, item.Window, item.Tid.ToString(CultureInfo.InvariantCulture), item.Name,
                    item.Code, item.WParam, item.LParam, item.ReturnValue, item.ClassName, item.Decoded
                }.Select(ExportFile.CsvField)));
        });
    }

    private async void CloseSpy(object? sender, CancelEventArgs args)
    {
        if (closed) return;
        args.Cancel = true;
        if (closing) return;
        try { await (cleanup ??= ReleaseServices()); }
        finally { closed = true; _ = Dispatcher.InvokeAsync(Close); }
    }

    private async Task ReleaseServices()
    {
        closing = true;
        ++selectionGeneration;
        timer.Stop();
        filterTimer.Stop();
        EndDrag();
        IsEnabled = false;
        await operation;
        await polling;
        await picking;
        if (logger is not null) await logger.DisposeAsync();
        if (reader is not null) await reader.DisposeAsync();
    }
}

public sealed class WindowSpyHighlight : Window
{
    private const int GwlExStyle = -20;
    private const int WsExTransparent = 0x00000020;
    private const int WsExToolWindow = 0x00000080;
    private const int WsExNoActivate = 0x08000000;
    private const int OverlayExStyle = WsExTransparent | WsExToolWindow | WsExNoActivate;
    private const int HwndTopMost = -1;
    private const uint SwpNoActivate = 0x0010;

    [DllImport("user32.dll")]
    private static extern bool SetWindowPos(nint window, nint after, int x, int y, int width, int height, uint flags);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongW")]
    private static extern int GetWindowLong(nint window, int index);
    [DllImport("user32.dll", EntryPoint = "SetWindowLongW")]
    private static extern int SetWindowLong(nint window, int index, int value);

    public WindowSpyHighlight()
    {
        // A transparent overlay highlights physical screen coordinates without painting into another application.
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        ShowInTaskbar = false;
        ShowActivated = false;
        Focusable = false;
        Topmost = true;
        Content = new Border { BorderBrush = Brushes.OrangeRed, BorderThickness = new(3) };
        SourceInitialized += (_, _) =>
        {
            var handle = new WindowInteropHelper(this).Handle;
            SetWindowLong(handle, GwlExStyle, GetWindowLong(handle, GwlExStyle) | OverlayExStyle);
        };
    }

    public void Mark(int left, int top, int width, int height)
    {
        if (!IsVisible) Show();
        SetWindowPos(new WindowInteropHelper(this).Handle, new(HwndTopMost), left, top, width, height, SwpNoActivate);
    }
}

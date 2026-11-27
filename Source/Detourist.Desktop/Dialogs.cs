using Microsoft.Win32;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;

namespace Detourist.Desktop;

public class ToolWindow : Window
{
    protected readonly Grid Body = new();
    protected readonly StackPanel Actions = new()
    {
        Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right
    };
    protected readonly TextBlock Error = new() { TextWrapping = TextWrapping.Wrap, Margin = new(0, 10, 0, 0) };

    protected ToolWindow(string title, string description, double width = 680, double height = 560)
    {
        Title = title + " — Detourist";
        Style = (Style)FindResource(typeof(Window));
        Width = width;
        Height = height;
        MinWidth = Math.Min(width, 550);
        MinHeight = Math.Min(height, 380);
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        var layout = new Grid { Margin = new(14) };
        SetRows(layout, GridLength.Auto, Fill, GridLength.Auto, GridLength.Auto);
        var header = new StackPanel { Margin = new(0, 0, 0, 12) };
        header.Children.Add(new TextBlock { Text = title, FontSize = 16, FontWeight = FontWeights.SemiBold });
        header.Children.Add(new TextBlock
        {
            Text = description, TextWrapping = TextWrapping.Wrap, Margin = new(0, 4, 0, 0),
            Foreground = (Brush)FindResource("MutedBrush")
        });
        layout.Children.Add(header);
        AddRow(layout, 1, Body);
        Error.Foreground = (Brush)FindResource("DangerBrush");
        AddRow(layout, 2, Error);
        Actions.Margin = new(0, 10, 0, 0);
        AddRow(layout, 3, Actions);
        Content = layout;
        SourceInitialized += (_, _) => App.ApplyNativeTheme(this);
        Loaded += (_, _) =>
        {
            MaxHeight = SystemParameters.WorkArea.Height - Protocol.WorkAreaMargin;
            MaxWidth = SystemParameters.WorkArea.Width - Protocol.WorkAreaMargin;
        };
    }

    protected static readonly GridLength Fill = new(1, GridUnitType.Star);

    protected static void SetRows(Grid grid, params GridLength[] heights)
    {
        foreach (var height in heights) grid.RowDefinitions.Add(new() { Height = height });
    }

    protected static void AddRow(Grid grid, int row, UIElement child)
    {
        Grid.SetRow(child, row);
        grid.Children.Add(child);
    }

    protected Button AddAction(string text, bool primary, RoutedEventHandler handler)
    {
        var button = new Button { Content = text, Margin = new(8, 0, 0, 0), MinWidth = 80 };
        if (primary) button.Style = (Style)FindResource("PrimaryButton");
        button.Click += handler;
        Actions.Children.Add(button);
        return button;
    }

    protected static void Label(Panel panel, string text, string? description = null)
    {
        panel.Children.Add(new TextBlock { Text = text, FontWeight = FontWeights.SemiBold, Margin = new(0, 0, 0, 5) });
        if (description is not null)
        {
            panel.Children.Add(new TextBlock
            {
                Text = description, TextWrapping = TextWrapping.Wrap, Margin = new(0, 0, 0, 10),
                Foreground = (Brush)Application.Current.FindResource("MutedBrush"), FontSize = 12
            });
        }
    }

    protected static TextBox Input(Panel panel, string value = "", string? automationName = null)
    {
        var input = new TextBox { Text = value, Margin = new(0, 0, 0, 10) };
        if (automationName is not null) System.Windows.Automation.AutomationProperties.SetName(input, automationName);
        panel.Children.Add(input);
        return input;
    }

    internal static T? Descendant<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); ++index)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match) return match;
            if (Descendant<T>(child) is { } nested) return nested;
        }
        return null;
    }

    internal static void SelectContextRow(object sender, RoutedEventArgs e)
    {
        if (sender is DataGrid grid && e.OriginalSource is DependencyObject source &&
            ItemsControl.ContainerFromElement(grid, source) is DataGridRow { IsSelected: false } row)
            grid.SelectedItem = row.Item;
    }

    protected static ScrollViewer Scroll(UIElement content, Thickness padding = default) => new()
    {
        Content = content, Padding = padding, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
    };

    protected static Style CellText => (Style)Application.Current.FindResource("CellText");
    protected static readonly DataGridLength FillColumn = new(1, DataGridLengthUnitType.Star);
    protected static DataGridTextColumn Column(string? title, string binding, DataGridLength width) =>
        new() { Header = title, Binding = new Binding(binding), Width = width, ElementStyle = CellText };
}

public sealed class LaunchWindow : ToolWindow
{
    private readonly TextBox executable;
    private readonly TextBox arguments;
    private readonly TextBox workingDirectory;
    private readonly TextBox expectedExitCodes;
    public string Executable => executable.Text.Trim().Trim('"');
    public string Arguments => arguments.Text;
    public string WorkingDirectory => workingDirectory.Text.Trim().Trim('"');
    public string ExpectedExitCodes => expectedExitCodes.Text.Trim();

    public LaunchWindow(string application = "", string commandLine = "", string directory = "",
        string exitCodes = "") :
        base("Launch a process",
        "Capture from startup and follow child processes with your current settings.", 660, 330)
    {
        // Keep launch options reachable when the dialog shrinks or validation needs extra space.
        SizeToContent = SizeToContent.Height;
        MinHeight = 280;
        Error.MinHeight = 18;
        var form = new StackPanel();
        Body.Children.Add(Scroll(form, new(0, 0, 8, 0)));
        Label(form, "Application");
        var row = new DockPanel { Margin = new(0, 0, 0, 20) };
        var browse = new Button { Content = "_Browse…", Margin = new(8, 0, 0, 0) };
        DockPanel.SetDock(browse, Dock.Right);
        row.Children.Add(browse);
        executable = new TextBox { Text = application };
        System.Windows.Automation.AutomationProperties.SetName(executable, "Application path");
        row.Children.Add(executable);
        form.Children.Add(row);
        Label(form, "Arguments", "Optional command-line arguments passed to the application.");
        arguments = Input(form, commandLine, "Arguments");
        Label(form, "Working directory", "Leave empty to use the application's folder.");
        workingDirectory = Input(form, directory, "Working directory");
        Label(form, "Expected exit codes",
            "Zero is always accepted. Add decimal or hexadecimal codes, separated by commas.");
        expectedExitCodes = Input(form, exitCodes, "Expected exit codes");
        expectedExitCodes.Width = 300;
        expectedExitCodes.HorizontalAlignment = HorizontalAlignment.Left;
        browse.Click += (_, _) =>
        {
            var picker = new OpenFileDialog
            {
                Title = "Choose application", Filter = "Applications (*.exe)|*.exe|All files|*.*"
            };
            if (picker.ShowDialog(this) == true) executable.Text = picker.FileName;
        };
        AddAction("_Cancel", false, (_, _) => DialogResult = false).IsCancel = true;
        AddAction("_Launch", true, (_, _) =>
        {
            if (!File.Exists(Executable))
            {
                Error.Text = "Choose an existing executable file.";
                return;
            }
            if (WorkingDirectory.Length > 0 && !Directory.Exists(WorkingDirectory))
            {
                Error.Text = "Choose an existing working directory.";
                return;
            }
            try { ParseExitCodes(ExpectedExitCodes); }
            catch (FormatException error) { Error.Text = error.Message; return; }
            DialogResult = true;
        }).IsDefault = true;
        Loaded += (_, _) =>
        {
            executable.Focus();
            executable.SelectAll();
        };
    }

    public static uint[] ParseExitCodes(string text)
    {
        var codes = new List<uint>();
        foreach (var code in text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var hex = code.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
            if (!uint.TryParse(hex ? code[2..] : code, hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None,
                CultureInfo.InvariantCulture, out var value))
                throw new FormatException("Enter unsigned decimal or 0x-prefixed hexadecimal exit codes.");
            codes.Add(value);
        }
        return [.. codes.Distinct()];
    }
}

public sealed record ProcessItem(long Pid, string Name, string Architecture);

public sealed class ProcessWindow : ToolWindow
{
    private readonly CollectorClient client;
    private readonly TextBox search = new();
    private readonly DataGrid grid = new();
    private readonly TextBlock hint = new() { Margin = new(0, 10, 0, 0) };
    private ProcessItem[] processes = [];
    public ProcessItem? Selected => grid.SelectedItem as ProcessItem;

    public ProcessWindow(CollectorClient client) : base("Attach to a process",
        "Choose a running x86 or x64 process. All its threads are monitored.", 780, 660)
    {
        this.client = client;
        SetRows(Body, GridLength.Auto, Fill, GridLength.Auto);
        search.Margin = new(0, 0, 0, 14);
        search.ToolTip = "Filter by process name or PID";
        System.Windows.Automation.AutomationProperties.SetName(search, "Search processes");
        Body.Children.Add(search);
        grid.Columns.Add(Column("PROCESS", "Name", FillColumn));
        grid.Columns.Add(Column("PID", "Pid", 100));
        grid.Columns.Add(Column("ARCHITECTURE", "Architecture", 140));
        AddRow(Body, 1, grid);
        hint.Foreground = (Brush)FindResource("MutedBrush");
        AddRow(Body, 2, hint);
        search.TextChanged += (_, _) => Filter();
        grid.MouseDoubleClick += (_, _) => Accept();
        AddAction("_Refresh", false, async (_, _) => await Refresh());
        AddAction("_Cancel", false, (_, _) => DialogResult = false).IsCancel = true;
        AddAction("_Attach", true, (_, _) => Accept());
        Loaded += async (_, _) => await Refresh();
    }

    private void Accept()
    {
        if (Selected is null) return;
        if (!Selected.Architecture.Equals("x64", StringComparison.OrdinalIgnoreCase) &&
            !Selected.Architecture.Equals("x86", StringComparison.OrdinalIgnoreCase))
        {
            Error.Text = "Choose an x86 or x64 process.";
            return;
        }
        DialogResult = true;
    }

    private async Task Refresh()
    {
        hint.Text = "Loading processes…";
        try
        {
            var result = await client.Send("processes");
            processes = result.EnumerateArray().Select(item => new ProcessItem(item.Number("pid"),
                item.Text("name"), item.Text("architecture"))).OrderBy(item => item.Name).ToArray();
            Filter();
        }
        catch (Exception error)
        {
            Error.Text = error.Message;
        }
    }

    private void Filter()
    {
        var visible = processes.Where(item => item.Name.Contains(search.Text, StringComparison.OrdinalIgnoreCase) ||
            item.Pid.ToString().Contains(search.Text, StringComparison.Ordinal)).ToArray();
        grid.ItemsSource = visible;
        hint.Text = $"{visible.Length:N0} processes · attach requires access to the target";
    }
}

public sealed class CaptureGroup
{
    public required string Name { get; init; }
    public required string Module { get; init; }
    public required ulong Mask { get; init; }
    public int Signatures { get; init; }
    public string SignatureSummary => Signatures == 0 ? "Runtime" : Signatures.ToString("N0");
    public bool Enabled { get; set; }
    public bool Applicable { get; set; } = true;
}

public sealed class SettingsWindow : ToolWindow
{
    public SettingsWindow(CaptureSettings settings, ApiInfo[] catalog, CategoryInfo[] categories, bool live,
        int section = 0) : base("Capture settings", live ?
            "Capture filters take effect immediately. Other settings apply to the next capture." :
            "Choose what to record. Display filters remain independent of capture.", 820, 560)
    {
        // Keep each settings section reachable without scrolling through unrelated controls.
        var tabs = new TabControl();
        Body.Children.Add(tabs);
        var general = new StackPanel { Margin = new(10) };
        tabs.Items.Add(new TabItem
        {
            Header = "_General", Content = Scroll(general)
        });
        var filters = new Grid { Margin = new(10) };
        SetRows(filters, GridLength.Auto, GridLength.Auto, Fill, GridLength.Auto);
        tabs.Items.Add(new TabItem { Header = "Capture _filters", Content = filters });
        var breakpointForm = new StackPanel { Margin = new(10) };
        tabs.Items.Add(new TabItem
        {
            Header = "_Breakpoints", Content = Scroll(breakpointForm)
        });
        var symbolPanel = new Grid { Margin = new(10) };
        SetRows(symbolPanel, GridLength.Auto, Fill, GridLength.Auto);
        tabs.Items.Add(new TabItem { Header = "_Symbols", Content = symbolPanel });
        var symbolLabel = new TextBlock
        {
            Text = "Search local PDB folders and caches. Matching PDBs beside the original image are also used.",
            TextWrapping = TextWrapping.Wrap, Margin = new(0, 0, 0, 10)
        };
        symbolPanel.Children.Add(symbolLabel);
        var symbolPaths = new System.Collections.ObjectModel.ObservableCollection<string>(settings.SymbolDirectories);
        var symbolList = new ListBox { ItemsSource = symbolPaths };
        System.Windows.Automation.AutomationProperties.SetName(symbolList, "Symbol folders");
        AddRow(symbolPanel, 1, symbolList);
        var symbolActions = new StackPanel { Orientation = Orientation.Horizontal, Margin = new(0, 10, 0, 0) };
        var addSymbol = new Button { Content = "A_dd folder…" };
        var removeSymbol = new Button { Content = "_Remove", Margin = new(8, 0, 0, 0), IsEnabled = false };
        symbolList.SelectionChanged += (_, _) => removeSymbol.IsEnabled = symbolList.SelectedItem is not null;
        addSymbol.Click += (_, _) =>
        {
            var picker = new OpenFolderDialog { Title = "Choose symbol folders", Multiselect = true };
            if (picker.ShowDialog(this) != true) return;
            foreach (var path in picker.FolderNames)
            {
                if (path.Length < 3 || path[1] != ':' || path.IndexOfAny(['*', '?', ';']) >= 0 ||
                    new DriveInfo(Path.GetPathRoot(path)!).DriveType is DriveType.Network or DriveType.Unknown)
                {
                    Error.Text = "Choose local symbol folders.";
                    continue;
                }
                if (!symbolPaths.Contains(path, StringComparer.OrdinalIgnoreCase)) symbolPaths.Add(path);
            }
        };
        removeSymbol.Click += (_, _) =>
        {
            if (symbolList.SelectedItem is string path) symbolPaths.Remove(path);
        };
        symbolActions.Children.Add(addSymbol);
        symbolActions.Children.Add(removeSymbol);
        AddRow(symbolPanel, 2, symbolActions);
        tabs.SelectedIndex = section;
        var top = new Grid { Margin = new(0, 0, 0, 14) };
        top.ColumnDefinitions.Add(new() { Width = new(1, GridUnitType.Star) });
        top.ColumnDefinitions.Add(new() { Width = new(1, GridUnitType.Star) });
        var bufferPanel = new StackPanel { Margin = new(0, 0, 24, 0) };
        Label(bufferPanel, "Global buffer limit", "Maximum bytes copied from each API buffer.");
        var buffer = Input(bufferPanel, settings.BufferLimit.ToString(), "Global buffer limit in bytes");
        buffer.Margin = new(0, 0, 0, 14);
        buffer.Width = 140;
        buffer.HorizontalAlignment = HorizontalAlignment.Left;
        top.Children.Add(bufferPanel);
        var engine = new ComboBox
        {
            ItemsSource = new[] { "Broad coverage", "Typed hooks" },
            SelectedIndex = settings.InstructionEngine ? 0 : 1, Margin = new(0, 0, 0, 14)
        };
        Label(bufferPanel, "Capture engine");
        bufferPanel.Children.Add(engine);
        System.Windows.Automation.AutomationProperties.SetName(engine, "Capture engine");
        Label(bufferPanel, "Stop At Trace Size (MiB)", "Includes the trace database and journal. Use 0 for unlimited.");
        var traceSize = Input(bufferPanel, settings.TraceStopMiB.ToString(), "Stop At Trace Size (MiB)");
        traceSize.Width = 140;
        traceSize.HorizontalAlignment = HorizontalAlignment.Left;
        var switches = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        var children = new CheckBox
        {
            Content = "Follow child processes", IsChecked = settings.FollowChildren, Margin = new(0, 0, 0, 14)
        };
        var stacks = new CheckBox { Content = "Capture available stacks", IsChecked = settings.Stacks };
        var fromApp = new CheckBox
        {
            Content = "Show app calls initially", IsChecked = settings.FromAppOnCapture, Margin = new(0, 8, 0, 0),
            ToolTip = "Start new captures with the From app display filter. Other calls are still recorded."
        };
        var rawProbes = new CheckBox
        {
            Content = "Probe Raw Argument Pointers", IsChecked = settings.RawPointerProbes, Margin = new(0, 8, 0, 0),
            ToolTip = "Dereference candidate pointer slots on unknown exports and syscalls during broad capture."
        };
        switches.Children.Add(children);
        switches.Children.Add(stacks);
        switches.Children.Add(fromApp);
        switches.Children.Add(rawProbes);
        switches.Children.Add(new TextBlock
        {
            Text = "Broad coverage: all DLL exports, syscall instructions and discovered interface slots. " +
                "It uses more CPU and memory. Unknown signatures use raw snapshots.\n" +
                "Stacks are available with either engine. Loader calls and dynamic code can have partial " +
                "or unavailable stacks; these are marked in the call stack inspector.",
            FontSize = 11, Margin = new(0, 8, 0, 0), TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)FindResource("MutedBrush")
        });
        Grid.SetColumn(switches, 1);
        top.Children.Add(switches);
        general.Children.Add(top);

        // Captures are named after their target and start time inside this folder.
        Label(general, "Trace folder", "New captures are saved here, named after the application and start time.");
        var folderRow = new DockPanel { Margin = new(0, 0, 0, 14) };
        var chooseFolder = new Button { Content = "B_rowse…", Margin = new(8, 0, 0, 0) };
        DockPanel.SetDock(chooseFolder, Dock.Right);
        folderRow.Children.Add(chooseFolder);
        var folder = new TextBox { Text = settings.TraceDirectory };
        System.Windows.Automation.AutomationProperties.SetName(folder, "Trace folder");
        folderRow.Children.Add(folder);
        general.Children.Add(folderRow);
        chooseFolder.Click += (_, _) =>
        {
            var picker = new OpenFolderDialog { Title = "Choose trace folder", InitialDirectory = folder.Text };
            if (picker.ShowDialog(this) == true) folder.Text = picker.FolderName;
        };
        var label = new StackPanel();
        label.Children.Add(new TextBlock
        {
            Text = "Record selected functions across enabled tracing sources.",
            Foreground = (Brush)FindResource("MutedBrush"), Margin = new(0, 0, 0, 8),
            TextWrapping = TextWrapping.Wrap
        });
        var view = new ComboBox
        {
            ItemsSource = new[] { "Functional categories", "Tracing sources", "Excluded APIs" }, SelectedIndex = 0,
            Width = 220, HorizontalAlignment = HorizontalAlignment.Left, Margin = new(0, 0, 0, 8)
        };
        System.Windows.Automation.AutomationProperties.SetName(view, "Capture filter list");
        label.Children.Add(view);
        filters.Children.Add(label);
        var signatures = catalog.ToLookup(api => api.Mask);
        var groups = settings.Sources.Select(source => new CaptureGroup
        {
            Name = source.Value,
            Module = source.Key == (ulong)ApiSourceMask.Managed ? "CLR / CoreCLR" :
                source.Key == (ulong)ApiSourceMask.DirectSyscalls ? "Any executable memory" :
                signatures[source.Key].Select(item => item.Module).Distinct().Count() > 1 ? "Multiple" :
                signatures[source.Key].First().Module,
            Mask = source.Key,
            Signatures = signatures[source.Key].Count(),
            Enabled = (settings.ApiMask & source.Key) != 0,
            Applicable = source.Key != (ulong)ApiSourceMask.DirectSyscalls || settings.InstructionEngine
        }).OrderByDescending(group => group.Signatures).ThenBy(group => group.Name).ToArray();
        var categoryGroups = categories.OrderBy(category => category.Name).Select(category => new CaptureGroup
        {
            Name = category.Name, Module = category.Description, Mask = category.Mask,
            Signatures = catalog.Count(api => api.CategoryId == category.Id),
            Enabled = (settings.CategoryMask & category.Mask) != 0
        }).ToArray();
        var exclusions = settings.ExcludedApis.Order(StringComparer.Ordinal).Select(name => new CaptureGroup
        {
            Name = name, Module = "All processes and modules", Mask = 0, Enabled = true
        }).ToList();
        var grid = new DataGrid { IsReadOnly = false, ItemsSource = categoryGroups };
        // Keep capture toggles directly actionable without entering a grid edit mode.
        var toggle = new FrameworkElementFactory(typeof(CheckBox));
        toggle.SetBinding(ToggleButton.IsCheckedProperty, new Binding("Enabled")
        {
            Mode = BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged
        });
        toggle.SetBinding(System.Windows.Automation.AutomationProperties.NameProperty, new Binding("Name"));
        toggle.SetBinding(IsEnabledProperty, new Binding("Applicable"));
        grid.Columns.Add(new DataGridTemplateColumn
        {
            Header = "RECORD", CellTemplate = new DataTemplate { VisualTree = toggle }, Width = 85
        });
        grid.Columns.Add(new DataGridTextColumn
        {
            Header = "CATEGORY", Binding = new Binding("Name"),
            Width = new(1, DataGridLengthUnitType.Star), IsReadOnly = true, ElementStyle = CellText
        });
        var purpose = new DataGridTextColumn
        {
            Header = "PURPOSE", Binding = new Binding("Module"),
            Width = new(1.5, DataGridLengthUnitType.Star), IsReadOnly = true, ElementStyle = CellText
        };
        grid.Columns.Add(purpose);
        grid.Columns.Add(new DataGridTextColumn
        {
            Header = "SIGNATURES", Binding = new Binding("SignatureSummary"), Width = 105, IsReadOnly = true,
            ElementStyle = CellText
        });
        AddRow(filters, 2, grid);

        // Exclusions can be entered by name before any call has been captured; row actions share one width.
        var exclusionControls = new StackPanel { Visibility = Visibility.Collapsed };
        Grid.SetIsSharedSizeScope(exclusionControls, true);
        void AddExclusionRow(UIElement field, Button action)
        {
            var row = new Grid { Margin = new(0, 0, 0, 8) };
            row.ColumnDefinitions.Add(new());
            row.ColumnDefinitions.Add(new() { Width = GridLength.Auto, SharedSizeGroup = "ExclusionAction" });
            Grid.SetColumn(action, 1);
            row.Children.Add(field);
            row.Children.Add(action);
            exclusionControls.Children.Add(row);
        }
        var add = new Button { Content = "A_dd", Margin = new(8, 0, 0, 0), MinWidth = 70 };
        var excluded = new TextBox { ToolTip = "Exact API name to stop recording in every process and module" };
        System.Windows.Automation.AutomationProperties.SetName(excluded, "API name to exclude");
        AddExclusionRow(excluded, add);
        AddRow(filters, 1, exclusionControls);
        void Exclude(IEnumerable<string> names)
        {
            foreach (var name in names.Select(name => name.Trim()).Where(name => name.Length > 0))
            {
                if (exclusions.FirstOrDefault(item => item.Name == name) is { } existing) existing.Enabled = true;
                else exclusions.Add(new()
                {
                    Name = name, Module = "All processes and modules", Mask = 0, Enabled = true
                });
            }
            exclusions.Sort((first, second) => string.CompareOrdinal(first.Name, second.Name));
            view.SelectedIndex = 2;
            grid.Items.Refresh();
        }

        // Presets populate editable exclusions, so individual helpers can still be recorded.
        if (settings.NoiseProfiles.Length > 0)
        {
            var applyProfile = new Button { Content = "Add _profile", Margin = new(8, 0, 0, 0) };
            var profile = new ComboBox { ItemsSource = settings.NoiseProfiles, SelectedIndex = 0 };
            System.Windows.Automation.AutomationProperties.SetName(profile, "Noise filter profile");
            profile.SelectionChanged += (_, _) =>
                profile.ToolTip = (profile.SelectedItem as NoiseProfileInfo)?.Description;
            profile.ToolTip = settings.NoiseProfiles[0].Description;
            AddExclusionRow(profile, applyProfile);
            exclusionControls.Children.Add(new TextBlock
            {
                Text = "Profiles add exclusions. Uncheck an API to record it.",
                TextWrapping = TextWrapping.Wrap, Margin = new(0, 0, 0, 8),
                Foreground = (Brush)FindResource("MutedBrush")
            });
            applyProfile.Click += (_, _) =>
            {
                if (profile.SelectedItem is NoiseProfileInfo selected) Exclude(selected.Apis);
            };
        }
        add.Click += (_, _) =>
        {
            Exclude([excluded.Text]);
            excluded.Clear();
        };
        excluded.KeyDown += (_, e) =>
        {
            if (e.Key != System.Windows.Input.Key.Enter || excluded.Text.Trim().Length == 0) return;
            e.Handled = true;
            Exclude([excluded.Text]);
            excluded.Clear();
        };
        engine.SelectionChanged += (_, _) =>
        {
            groups.First(group => group.Mask == (ulong)ApiSourceMask.DirectSyscalls).Applicable =
                live ? settings.InstructionEngine : engine.SelectedIndex == 0;
            grid.Items.Refresh();
        };
        var groupActions = new StackPanel { Orientation = Orientation.Horizontal, Margin = new(0, 8, 0, 0) };
        var all = new Button { Content = "Select all" };
        var none = new Button
        {
            Content = "Clear all", Margin = new(8, 0, 0, 0)
        };
        var browseCatalog = new Button
        {
            Content = "Browse signatures…", Margin = new(8, 0, 0, 0),
            ToolTip = "Search the signature catalog and exclude the selected APIs"
        };
        IEnumerable<CaptureGroup> Listed() => view.SelectedIndex == 0 ? categoryGroups :
            view.SelectedIndex == 1 ? groups : exclusions;
        all.Click += (_, _) =>
        {
            foreach (var group in Listed()) group.Enabled = true;
            grid.Items.Refresh();
        };
        none.Click += (_, _) =>
        {
            foreach (var group in Listed()) group.Enabled = false;
            grid.Items.Refresh();
        };
        view.SelectionChanged += (_, _) =>
        {
            grid.ItemsSource = Listed();
            exclusionControls.Visibility = view.SelectedIndex == 2 ? Visibility.Visible : Visibility.Collapsed;
            grid.Columns[0].Header = view.SelectedIndex == 2 ? "EXCLUDE" : "RECORD";
            grid.Columns[3].Visibility = view.SelectedIndex == 2 ? Visibility.Collapsed : Visibility.Visible;
            grid.Columns[1].Header = view.SelectedIndex == 0 ? "CATEGORY" :
                view.SelectedIndex == 1 ? "API / SOURCE" : "API NAME";
            purpose.Header = view.SelectedIndex == 0 ? "PURPOSE" : view.SelectedIndex == 1 ? "MODULE" : "SCOPE";
            purpose.Width = view.SelectedIndex == 0 ? new(1.5, DataGridLengthUnitType.Star) :
                view.SelectedIndex == 1 ? new(125) : new(190);
        };
        browseCatalog.Click += (_, _) =>
        {
            var browser = new CatalogWindow(catalog, categories, "E_xclude selected", true) { Owner = this };
            if (browser.ShowDialog() == true) Exclude(browser.Chosen.Select(api => api.Name));
        };
        groupActions.Children.Add(all);
        groupActions.Children.Add(none);
        groupActions.Children.Add(browseCatalog);
        AddRow(filters, 3, groupActions);
        general.Children.Add(new TextBlock
        {
            Text = "Managed attach supports CoreCLR, CLR 2, and CLR 4. " +
                "Managed tracing changes runtime optimization and increases target overhead.",
            TextWrapping = TextWrapping.Wrap, Foreground = (Brush)FindResource("MutedBrush"),
            FontSize = 12, Margin = new(0, 0, 0, 12)
        });
        Label(breakpointForm, "Initial breakpoints",
            "Pause every target thread at entry or return of the selected API.");

        // Breakpoint APIs are chosen from the searchable signature catalog.
        int entryApi = settings.EntryApi, exitApi = settings.ExitApi;
        void AddPicker(string title, string name, Func<int> current, Action<int> assign)
        {
            Label(breakpointForm, title);
            var row = new DockPanel { Margin = new(0, 0, 0, 14) };
            var clear = new Button { Content = "Clear", Margin = new(8, 0, 0, 0) };
            var choose = new Button { Content = "Choose…", Margin = new(8, 0, 0, 0) };
            DockPanel.SetDock(clear, Dock.Right);
            DockPanel.SetDock(choose, Dock.Right);
            row.Children.Add(clear);
            row.Children.Add(choose);
            var selection = new TextBox { IsReadOnly = true, Margin = new(0) };
            System.Windows.Automation.AutomationProperties.SetName(selection, name);
            System.Windows.Automation.AutomationProperties.SetName(choose, "Choose " + name.ToLowerInvariant());
            System.Windows.Automation.AutomationProperties.SetName(clear, "Clear " + name.ToLowerInvariant());
            row.Children.Add(selection);
            void Show()
            {
                selection.Text = current() < 0 ? "No breakpoint" :
                    catalog.FirstOrDefault(api => api.Id == current()) is { } api ? $"{api.Module}!{api.Name}" :
                    $"API 0x{current():X}";
                clear.IsEnabled = current() >= 0;
            }
            choose.Click += (_, _) =>
            {
                var picker = new CatalogWindow(catalog, categories, "_Select") { Owner = this };
                if (picker.ShowDialog() != true || picker.Chosen.FirstOrDefault() is not { } api) return;
                assign(api.Id);
                Show();
            };
            clear.Click += (_, _) =>
            {
                assign(-1);
                Show();
            };
            Show();
            breakpointForm.Children.Add(row);
        }
        AddPicker("Entry", "Initial entry breakpoint", () => entryApi, value => entryApi = value);
        AddPicker("Return", "Initial return breakpoint", () => exitApi, value => exitApi = value);
        AddAction("_Cancel", false, (_, _) => DialogResult = false).IsCancel = true;
        AddAction("OK", true, (_, _) =>
        {
            if (!int.TryParse(buffer.Text, out var limit) || limit < Protocol.MinimumBufferLimit ||
                limit > Protocol.MaximumBufferLimit)
            {
                Error.Text = $"Enter a buffer limit between {Protocol.MinimumBufferLimit:N0} and " +
                    $"{Protocol.MaximumBufferLimit:N0} bytes.";
                tabs.SelectedIndex = 0;
                buffer.Focus();
                return;
            }
            if (!uint.TryParse(traceSize.Text, out var stopSize))
            {
                Error.Text = "Enter a whole trace size in MiB. Use 0 for unlimited.";
                tabs.SelectedIndex = 0;
                traceSize.Focus();
                return;
            }
            grid.CommitEdit(DataGridEditingUnit.Row, true);
            settings.BufferLimit = limit;
            settings.TraceStopMiB = stopSize;
            settings.SymbolDirectories = [.. symbolPaths];
            settings.InstructionEngine = engine.SelectedIndex == 0;
            settings.Stacks = stacks.IsChecked == true;
            settings.FromAppOnCapture = fromApp.IsChecked == true;
            settings.RawPointerProbes = rawProbes.IsChecked == true;
            settings.FollowChildren = children.IsChecked == true;
            settings.TraceFolder = folder.Text.Trim().Equals(CaptureSettings.DefaultTraceDirectory,
                StringComparison.OrdinalIgnoreCase) ? "" : folder.Text.Trim();
            settings.ApiMask = groups.Where(group => group.Enabled).Aggregate(0UL, (mask, group) => mask | group.Mask);
            settings.CategoryMask = categoryGroups.Where(group => group.Enabled)
                .Aggregate(0UL, (mask, group) => mask | group.Mask);
            settings.ExcludedApis = exclusions.Where(item => item.Enabled).Select(item => item.Name).ToArray();
            settings.EntryApi = entryApi;
            settings.ExitApi = exitApi;
            DialogResult = true;
        }).IsDefault = true;
    }
}

public sealed class CatalogWindow : ToolWindow
{
    public ApiInfo[] Chosen { get; private set; } = [];

    public CatalogWindow(ApiInfo[] catalog, CategoryInfo[] categories, string? action = null, bool multiple = false) :
        base("API signatures",
        "Categories are inferred from API names, namespaces and modules. Unknown purposes remain unclassified.",
        1020, 700)
    {
        SetRows(Body, GridLength.Auto, Fill, GridLength.Auto);
        var filters = new Grid { Margin = new(0, 0, 0, 14) };
        filters.ColumnDefinitions.Add(new() { Width = new(1, GridUnitType.Star) });
        filters.ColumnDefinitions.Add(new() { Width = new(230) });
        var search = new TextBox { Margin = new(0, 0, 10, 0), ToolTip = "Search by API name or module" };
        System.Windows.Automation.AutomationProperties.SetName(search, "Search API signatures");
        var category = new ComboBox
        {
            ItemsSource = categories.OrderBy(item => item.Name).Select(item => new FilterItem(item.Id, item.Name))
                .Prepend(new(-1, "All categories")).ToArray(), DisplayMemberPath = "Label", SelectedIndex = 0
        };
        System.Windows.Automation.AutomationProperties.SetName(category, "Signature category filter");
        filters.Children.Add(search);
        Grid.SetColumn(category, 1);
        filters.Children.Add(category);
        var grid = new DataGrid
        {
            ItemsSource = catalog,
            SelectionMode = multiple ? DataGridSelectionMode.Extended : DataGridSelectionMode.Single
        };
        grid.Columns.Add(Column("API", "Name", 250));
        grid.Columns.Add(Column("MODULE", "Module", 130));
        grid.Columns.Add(Column("CATEGORY", "Category", 190));
        grid.Columns.Add(Column("PARAMETERS", "Parameters", FillColumn));
        var count = new TextBlock { Margin = new(0, 10, 0, 0), Foreground = (Brush)FindResource("MutedBrush") };
        void Filter()
        {
            var selected = (category.SelectedItem as FilterItem)?.Id ?? -1;
            var visible = catalog.Where(api => (selected == -1 || api.CategoryId == selected) &&
                (api.Name.Contains(search.Text, StringComparison.OrdinalIgnoreCase) ||
                api.Module.Contains(search.Text, StringComparison.OrdinalIgnoreCase))).ToArray();
            grid.ItemsSource = visible;
            count.Text = $"{visible.Length:N0} of {catalog.Length:N0} signatures" +
                (multiple ? " · Ctrl or Shift selects several" : "");
        }
        search.TextChanged += (_, _) => Filter();
        category.SelectionChanged += (_, _) => Filter();
        Filter();
        Body.Children.Add(filters);
        AddRow(Body, 1, grid);
        AddRow(Body, 2, count);
        Loaded += (_, _) => search.Focus();
        if (action is null)
        {
            AddAction("_Close", true, (_, _) => Close()).IsCancel = true;
            return;
        }

        // A catalog opened to choose APIs returns the selected rows.
        void Accept()
        {
            Chosen = [.. grid.SelectedItems.Cast<ApiInfo>()];
            if (Chosen.Length > 0) DialogResult = true;
        }
        AddAction("_Cancel", false, (_, _) => DialogResult = false).IsCancel = true;
        AddAction(action, true, (_, _) => Accept());
        grid.MouseDoubleClick += (_, _) => Accept();
    }
}

public sealed record CompareLine(string Left, string Right, bool Differs);

public sealed class CompareWindow : ToolWindow
{
    public CompareWindow(JsonElement left, JsonElement right) : base("Compare calls",
        $"{left.Text("name")} · call {left.Number("id")}   ↔   {right.Text("name")} · call {right.Number("id")}",
        1080, 660)
    {
        // The longest common run of lines stays aligned; every other line pairs with its counterpart or a blank.
        const int limit = 1500;
        static string[] Lines(JsonElement call) => call.Text("text").ReplaceLineEndings("\n").Split('\n');
        var (first, second) = (Lines(left), Lines(right));
        var truncated = first.Length > limit || second.Length > limit;
        (first, second) = (first[..Math.Min(limit, first.Length)], second[..Math.Min(limit, second.Length)]);
        var common = new int[first.Length + 1, second.Length + 1];
        for (var row = first.Length - 1; row >= 0; --row)
            for (var column = second.Length - 1; column >= 0; --column)
                common[row, column] = first[row] == second[column] ? common[row + 1, column + 1] + 1 :
                    Math.Max(common[row + 1, column], common[row, column + 1]);
        var lines = new List<CompareLine>();
        for (int row = 0, column = 0; row < first.Length || column < second.Length;)
        {
            if (row < first.Length && column < second.Length && first[row] == second[column])
                lines.Add(new(first[row++], second[column++], false));
            else if (row < first.Length && column < second.Length &&
                common[row + 1, column + 1] >= Math.Max(common[row + 1, column], common[row, column + 1]))
                lines.Add(new(first[row++], second[column++], true));
            else if (column >= second.Length ||
                (row < first.Length && common[row + 1, column] >= common[row, column + 1]))
                lines.Add(new(first[row++], "", true));
            else lines.Add(new("", second[column++], true));
        }
        var grid = new DataGrid
        {
            ItemsSource = lines, CanUserSortColumns = false, CanUserReorderColumns = false,
            FontFamily = new FontFamily("Consolas"), FontSize = 12, HeadersVisibility = DataGridHeadersVisibility.None,
            GridLinesVisibility = DataGridGridLinesVisibility.None
        };
        System.Windows.Automation.AutomationProperties.SetName(grid, "Call comparison");
        var rowStyle = new Style(typeof(DataGridRow), (Style)FindResource(typeof(DataGridRow)));
        var differs = new DataTrigger { Binding = new Binding(nameof(CompareLine.Differs)), Value = true };
        differs.Setters.Add(new Setter(BackgroundProperty, new SolidColorBrush(Color.FromRgb(0x4A, 0x3A, 0x1A))));
        rowStyle.Triggers.Add(differs);
        grid.RowStyle = rowStyle;
        grid.Columns.Add(Column(null, nameof(CompareLine.Left), FillColumn));
        grid.Columns.Add(Column(null, nameof(CompareLine.Right), FillColumn));
        Body.Children.Add(grid);
        var changed = lines.Count(line => line.Differs);
        Error.Foreground = (Brush)FindResource("MutedBrush");
        Error.Text = (changed == 0 ? "The recorded details are identical." :
            $"{changed:N0} of {lines.Count:N0} lines differ.") +
            (truncated ? $" Only the first {limit:N0} lines are compared." : "");
        AddAction("_Close", true, (_, _) => Close()).IsCancel = true;
    }
}

public sealed class CoverageWindow : ToolWindow
{
    public CoverageWindow(TargetCoverage[] targets, long selectedTarget, string scope, TraceDiagnostic[] diagnostics) :
        base("API coverage",
        "Installed capture hooks and runtime discovery for each process. Select a process for details.",
        1180, 730)
    {
        SetRows(Body, targets.Length > 0 ? Fill : GridLength.Auto, GridLength.Auto, Fill);
        var grid = new DataGrid
        {
            ItemsSource = targets, Visibility = targets.Length > 0 ? Visibility.Visible : Visibility.Collapsed
        };
        grid.Columns.Add(Column("PROCESS", "Name", FillColumn));
        grid.Columns.Add(Column("PID", "Pid", 75));
        grid.Columns.Add(Column("ENGINE", "Engine", 110));
        grid.Columns.Add(Column("SYSTEM TYPED", "NativeSummary", 115));
        grid.Columns.Add(Column("WIN32 TYPED", "Win32Summary", 115));
        grid.Columns.Add(Column("DLL EXPORTS", "InstalledExports", 105));
        grid.Columns.Add(Column("COM METHODS", "ComHooks", 100));
        grid.Columns.Add(Column("CLR METHODS", "ManagedApis", 125));
        grid.Columns.Add(Column("CLR STATE", "ManagedSummary", 110));
        Body.Children.Add(grid);
        var explanation = new TextBlock
        {
            Text = "Typed counts show installed / available known signatures. Broad coverage also discovers exports " +
                "without signatures and callable COM slots. CLR methods are registered at runtime.\n" + scope,
            TextWrapping = TextWrapping.Wrap, Foreground = (Brush)FindResource("MutedBrush"),
            FontSize = 12, Margin = new(0, 15, 0, 15), Visibility = grid.Visibility
        };
        AddRow(Body, 1, explanation);
        // Keep whole-capture diagnostics visible when inspecting different processes.
        var targetNames = targets.ToDictionary(target => target.Target);
        var notices = diagnostics.Length == 0 ? "" : "Capture Diagnostics\r\n" +
            string.Join("\r\n", diagnostics.Select(diagnostic =>
                targetNames.TryGetValue(diagnostic.Target, out var process) ?
                    $"{process.Name} (PID {process.Pid}) · {diagnostic.Message}" : diagnostic.Message)) + "\r\n\r\n";
        var details = new TextBox
        {
            Text = notices, IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap,
            FontFamily = new("Consolas"), VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        System.Windows.Automation.AutomationProperties.SetName(details, "Coverage Details");
        AddRow(Body, 2, details);
        grid.SelectionChanged += (_, _) =>
        {
            if (grid.SelectedItem is not TargetCoverage target) return;
            details.Text = notices + $"{target.Name} · PID {target.Pid} · {target.State}\r\n\r\n" +
                $"Engine: {target.Engine} · DLL exports: {target.InstalledExports:N0}\r\n" +
                $"System catalog: {target.Catalog:N0} · System exports: {target.NativeExports:N0}\r\n" +
                $"Win32 catalog: {target.Win32Catalog:N0} · CLR: {target.ManagedSummary}\r\n\r\n" +
                (target.ModuleRefreshError == 0 ? "" :
                    $"Module discovery encountered error {target.ModuleRefreshError}. " +
                    "Coverage may be incomplete.\r\n\r\n") +
                (target.UnknownExports.Length == 0 ?
                    "No system signature gaps were reported. " +
                    "Unknown signatures can use raw capture in broad coverage." :
                    "System exports without typed signatures\r\n" + string.Join("\r\n", target.UnknownExports));
        };
        grid.SelectedItem = targets.FirstOrDefault(target => target.Target == selectedTarget) ?? targets.FirstOrDefault();
        AddAction("_Close", true, (_, _) => Close()).IsCancel = true;
    }
}

public sealed class BreakpointWindow : ToolWindow
{
    private readonly CollectorClient client;
    private readonly JsonElement call;
    private readonly bool leaving;
    private readonly ParameterGrid parameters = new();
    private readonly MemoryEditor memory;
    private readonly TabControl tabs = new();
    private bool released;
    private bool sending;

    public BreakpointWindow(CollectorClient client, JsonElement status, int bufferLimit) :
        base(status.Flag("leaving") ? "API return breakpoint" : "API entry breakpoint",
            $"{status.GetProperty("stoppedCall").Text("module")}!{status.GetProperty("stoppedCall").Text("name")} · " +
            $"PID {status.GetProperty("stoppedCall").Number("pid")} · " +
            $"TID {status.GetProperty("stoppedCall").Number("tid")} · all target threads suspended", 920, 720)
    {
        this.client = client;
        call = status.GetProperty("stoppedCall").Clone();
        leaving = status.Flag("leaving");
        tabs.Items.Add(new TabItem { Header = "_Parameters", Content = parameters });
        memory = new MemoryEditor(client, call, bufferLimit);
        memory.BusyChanged += busy =>
        {
            parameters.IsEnabled = Actions.IsEnabled = !busy;
        };
        tabs.Items.Add(new TabItem { Header = "_Memory", Content = memory });
        Body.Children.Add(tabs);
        var dispatcher = (call.Number("flags") & (long)EventFlags.KernelDispatcher) != 0;
        if (!leaving && !dispatcher) AddAction("_Skip call", false, async (_, _) => await Release(true, true));
        AddAction("Continue _unchanged", false, async (_, _) => await Release(false, false));
        AddAction("_Continue", true, async (_, _) => await Release(false, true));
        Closing += OnClosing;
        parameters.MemoryRequested += row =>
        {
            memory.SetAddress(row.Editable ? row.EditedValue : row.Input ?? row.Output ?? 0, row.TypeName);
            tabs.SelectedIndex = 1;
        };
        parameters.ShowCall(call, true, leaving);
        Error.Text = dispatcher ? "Register and stack edits apply on continue." :
            leaving ? "Argument values are read only. Return and LastError edits apply on continue." :
            "Argument edits apply on continue. Return and LastError edits apply when skipping the call.";
        Error.Foreground = (Brush)FindResource("MutedBrush");
    }

    private async Task Release(bool skip, bool edited)
    {
        if (sending || released || memory.Busy) return;
        sending = true;
        tabs.IsEnabled = Actions.IsEnabled = false;
        try
        {
            var request = new Dictionary<string, object>
            {
                ["callId"] = call.Number("id"), ["pid"] = call.Number("pid"),
                ["tid"] = call.Number("tid"), ["skip"] = skip
            };
            if (edited)
            {
                request["result"] = parameters.Result();
                request["error"] = parameters.LastError();
                if (!leaving) request["arguments"] = parameters.Arguments();
            }
            await client.Send("continue", request);
            released = true;
            _ = Dispatcher.InvokeAsync(Close);
        }
        catch (Exception exception)
        {
            Error.Text = exception.Message;
            Error.Foreground = (Brush)FindResource("DangerBrush");
        }
        finally
        {
            sending = false;
            tabs.IsEnabled = Actions.IsEnabled = true;
        }
    }

    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (released || !client.IsConnected) return;
        e.Cancel = true;
        await Release(false, false);
    }
}

public sealed record ExportItem(string Name, long Ordinal, string Address, string Forwarder, string Kind);

public sealed class ExportWindow : ToolWindow
{
    public ExportWindow(string path, JsonElement data) : base("DLL exports",
        Path.GetFileName(path) + " · broad coverage records unknown signatures as bounded raw argument slots.",
        1050, 710)
    {
        SetRows(Body, GridLength.Auto, Fill);
        var exports = data.EnumerateArray().Select(item => new ExportItem(item.Text("name"), item.Number("ordinal"),
            item.Text("rva"), item.Text("forwarder"), item.Flag("executable") ? "Code" : "Data")).ToArray();
        var search = new TextBox { Margin = new(0, 0, 0, 14), ToolTip = "Filter exports by name" };
        System.Windows.Automation.AutomationProperties.SetName(search, "Filter exports");
        var grid = new DataGrid { ItemsSource = exports };
        grid.Columns.Add(new DataGridTextColumn
        {
            Header = "EXPORT", Binding = new Binding("Name"),
            Width = new(1, DataGridLengthUnitType.Star), MinWidth = 240, ElementStyle = CellText
        });
        grid.Columns.Add(Column("ORDINAL", "Ordinal", 90));
        grid.Columns.Add(Column("RVA", "Address", 110));
        grid.Columns.Add(Column("KIND", "Kind", 85));
        grid.Columns.Add(Column("FORWARDER", "Forwarder", 260));
        search.TextChanged += (_, _) => grid.ItemsSource = exports.Where(item =>
            item.Name.Contains(search.Text, StringComparison.OrdinalIgnoreCase)).ToArray();
        Body.Children.Add(search);
        AddRow(Body, 1, grid);
        AddAction("_Close", true, (_, _) => Close()).IsCancel = true;
    }
}

using Detourist.Desktop;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Detourist.Desktop.Tests;

public sealed class ProbeWindow : ToolWindow
{
    public readonly ParameterGrid Parameters = new();

    public ProbeWindow() : base("Parameter grid verification", "Real capture data and breakpoint edits", 920, 720)
    {
        Body.Children.Add(Parameters);
    }

    public void ShowMemory(MemoryEditor? memory)
    {
        Body.Children.Clear();
        Body.Children.Add(memory is null ? Parameters : memory);
    }
}

public static partial class Program
{
    internal static void Require(bool value, string message)
    {
        if (!value) throw new InvalidOperationException(message);
    }

    // Expand inspector rows and every descendant breadth-first.
    internal static List<ParameterProperty> Flatten(IEnumerable<ParameterProperty> rows)
    {
        var nodes = rows.ToList();
        for (var index = 0; index < nodes.Count; ++index) nodes.AddRange(nodes[index].Children);
        return nodes;
    }

    private static List<string[]> SddlAces(string text, char section)
    {
        // Each top-level parenthesized ACE splits into its seven semicolon-delimited SDDL fields.
        var aces = new List<string[]>();
        var start = text.IndexOf(section + ":", StringComparison.Ordinal);
        var position = start < 0 ? -1 : text.IndexOf('(', start);
        while (position >= 0 && position < text.Length && text[position] == '(')
        {
            var depth = 0;
            var quoted = false;
            var end = position;
            for (; end < text.Length; ++end)
            {
                if (text[end] == '"') quoted = !quoted;
                else if (!quoted && text[end] == '(') ++depth;
                else if (!quoted && text[end] == ')' && --depth == 0) break;
            }
            aces.Add(text[(position + 1)..Math.Min(end, text.Length)].Split(';', 7));
            position = end + 1;
        }
        return aces;
    }

    internal static List<DependencyObject> VisualTree(DependencyObject root)
    {
        var visuals = new List<DependencyObject> { root };
        for (var index = 0; index < visuals.Count; ++index)
            for (var child = 0; child < VisualTreeHelper.GetChildrenCount(visuals[index]); ++child)
                visuals.Add(VisualTreeHelper.GetChild(visuals[index], child));
        return visuals;
    }

    private static IEnumerable<FrameworkElement> Elements(DependencyObject parent)
    {
        foreach (var child in LogicalTreeHelper.GetChildren(parent).OfType<DependencyObject>())
        {
            if (child is FrameworkElement element) yield return element;
            foreach (var descendant in Elements(child)) yield return descendant;
        }
    }

    private static async Task<JsonElement> Wait(CollectorClient client, Func<JsonElement, bool> predicate,
        int seconds = 30)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(seconds))
        {
            var status = await client.Send("status");
            if (predicate(status)) return status;
            await Task.Delay(25);
        }
        throw new TimeoutException("The capture did not reach the expected state.");
    }

    internal static void SavePng(BitmapSource bitmap, string path)
    {
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }

    private static async Task SaveView(Window window, string name)
    {
        // Check layout and render available content without changing foreground focus.
        var directory = Environment.GetEnvironmentVariable("DETOURIST_TEST_ARTIFACTS");
        if (string.IsNullOrEmpty(directory) && name is not ("investigation-default" or "investigation-narrow")) return;
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        var content = (FrameworkElement)window.Content;
        var size = window is MainWindow ? name.EndsWith("scaled") ? new Size(1650, 1080) :
            name.EndsWith("narrow") ? new Size(1100, 620) : new Size(1540, 880) :
            new Size(window.Width - 16, window.SizeToContent == SizeToContent.Height ?
                double.PositiveInfinity : window.Height - 40);
        var host = new Border { Background = window.Background };
        TextElement.SetForeground(host, window.Foreground);
        TextElement.SetFontFamily(host, window.FontFamily);
        TextElement.SetFontSize(host, window.FontSize);
        window.Content = null;
        try
        {
            host.Child = content;
            host.Measure(size);
            if (double.IsPositiveInfinity(size.Height)) size.Height = host.DesiredSize.Height;
            host.Arrange(new Rect(size));
            host.UpdateLayout();
            await content.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            host.UpdateLayout();
            await content.Dispatcher.InvokeAsync(host.UpdateLayout, DispatcherPriority.ApplicationIdle);
            if (window is MainWindow)
            {
                var grid = (DataGrid)window.FindName("CallsGrid");
                var usedWidth = grid.Columns.Where(column => column.Visibility == Visibility.Visible)
                    .Sum(column => column.ActualWidth);
                Console.WriteLine($"Rendered call columns: {usedWidth:F1} / {grid.ActualWidth:F1} logical pixels.");
                Require(usedWidth >= grid.ActualWidth - 32,
                    "The call table left unused space while truncating its function and argument columns.");

                // Recycled, selected and highlighted rows keep the same column edges as their headers.
                var visuals = VisualTree(grid);
                var headers = visuals.OfType<DataGridColumnHeader>()
                    .Where(header => header.Column is { Visibility: Visibility.Visible } && header.ActualWidth > 0)
                    .ToDictionary(header => header.Column);
                Require(grid.Visibility != Visibility.Visible || headers.Count > 0 &&
                    visuals.OfType<DataGridCell>().Any(cell => cell.ActualWidth > 0),
                    "The call table did not render headers and cells for alignment verification.");
                foreach (var cell in visuals.OfType<DataGridCell>().Where(cell => cell.ActualWidth > 0))
                {
                    if (!headers.TryGetValue(cell.Column, out var columnHeader)) continue;
                    var offset = cell.TranslatePoint(new Point(), grid).X -
                        columnHeader.TranslatePoint(new Point(), grid).X;
                    Require(Math.Abs(offset) <= 1 && Math.Abs(cell.ActualWidth - columnHeader.ActualWidth) <= 1,
                        $"The {cell.Column.Header} cells are misaligned: offset {offset:F1}, " +
                        $"width {cell.ActualWidth:F1}/{columnHeader.ActualWidth:F1}.");
                }
                Require(visuals.OfType<DataGridRowHeader>().All(header => header.ActualWidth == 0),
                    "A hidden row header reserved space in the call table.");
                if (name is "investigation-default" or "investigation-narrow")
                {
                    var time = grid.Columns.First(column => column.Header.ToString() == "Time");
                    Require(time.Visibility == (name == "investigation-default" ? Visibility.Visible :
                        Visibility.Collapsed) && usedWidth <= grid.ActualWidth + 1,
                        "The call columns did not fit or hide time in the narrow view.");
                }
                var filters = (Grid)window.FindName("FilterBar");
                var search = (Grid)window.FindName("SearchPanel");
                var choices = (StackPanel)window.FindName("DisplayFilters");
                Require(search.ActualWidth >= 140 &&
                    search.TranslatePoint(new Point(search.ActualWidth, 0), filters).X <=
                    choices.TranslatePoint(new Point(0, 0), filters).X + 1 &&
                    choices.TranslatePoint(new Point(choices.ActualWidth, 0), filters).X <= filters.ActualWidth + 1,
                    "The display filters clip their search field or overlap at the rendered window size.");
                var modes = (Button)window.FindName("CaptureModeButton");
                var tools = (FrameworkElement)((Button)window.FindName("SettingsButton")).Parent;
                Require(modes.Visibility != Visibility.Visible ||
                    modes.TranslatePoint(new Point(modes.ActualWidth, 0), content).X <=
                    tools.TranslatePoint(new Point(), content).X,
                    "The capture mode selector overlaps the toolbar tools.");
            }
            if (string.IsNullOrEmpty(directory)) return;
            var bitmap = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(host);
            var pixels = new byte[(int)size.Width * (int)size.Height * 4];
            bitmap.CopyPixels(pixels, (int)size.Width * 4, 0);
            if (!Enumerable.Range(0, pixels.Length / 4).Any(index => pixels[index * 4 + 3] != 0))
            {
                Console.WriteLine("Minimized pixel render unavailable; layout assertions passed.");
                return;
            }
            SavePng(bitmap, Path.Combine(directory, name + ".png"));
        }
        finally
        {
            host.Child = null;
            window.Content = content;
            window.UpdateLayout();
        }
    }

    // Each inspector consumes one real capture artifact in its own process; rendered output goes beside it.
    private static string inspectionPath = "";
    private static readonly Dictionary<string, Action<JsonDocument>> Inspectors = new()
    {
        ["--rpc"] = details => RpcInspectorTests.Verify(details.RootElement),
        ["--symbols"] = details => SymbolInspectorTests.Verify(details.RootElement),
        ["--async-io"] = details =>
            AsyncIoInspectorTests.Verify(details.RootElement, Path.GetDirectoryName(inspectionPath)!),
        ["--authz-access"] = InspectAuthzAccess,
        ["--authz-audit"] = InspectAuthzAudit,
        ["--avi-save"] = InspectAviSave,
        ["--playsound"] = InspectPlaysound,
        ["--mru"] = InspectMru,
        ["--wgl"] = InspectWgl,
        ["--crt-counted-strings"] = InspectCrtCountedStrings,
        ["--ntdll-formats"] = InspectCrtCountedStrings,
        ["--shell-messages"] = InspectShellMessages,
        ["--prompt-user"] = InspectPromptUser,
        ["--trace-logging"] = InspectTraceLogging,
        ["--window-composition"] = InspectWindowComposition,
        ["--legacy-formats"] = InspectLegacyFormats,
        ["--scan-formats"] = InspectScanFormats,
        ["--locale-formats"] = InspectLocaleFormats,
        ["--positional-records"] = InspectPositionalRecords,
        ["--crt-counts"] = InspectCrtCounts,
        ["--ber-variadic"] = InspectBerVariadic,
        ["--buffer-elements"] = InspectBufferElements,
        ["--typed-variant-arrays"] = InspectTypedVariantArrays,
        ["--adsi-structures"] = InspectAdsiStructures,
        ["--adsi"] = InspectAdsi,
        ["--message-apis"] = details => InspectMessageApis(details, false),
        ["--peek-apis"] = details => InspectMessageApis(details, true),
        ["--winrt-structures"] = InspectWinrtStructures,
        ["--automation-enumeration"] = InspectAutomationEnumeration,
        ["--automation-strings"] = InspectAutomationStrings,
        ["--automation-arrays"] = InspectAutomationArrays,
        ["--com-context"] = InspectComContext,
        ["--managed"] = InspectManaged,
        ["--managed-values"] = ManagedLayoutInspectorTests.Verify,
        ["--managed-array-values"] = ManagedArrayInspectorTests.Verify,
        ["--managed-layout"] = InspectManagedLayout,
        ["--com-rpc-arrays"] = InspectComRpcArrays,
        ["--property-vectors"] = InspectPropertyVectors,
        ["--property-stores"] = InspectPropertyStores,
        ["--property-graphs"] = InspectPropertyGraphs,
        ["--property-variants"] = InspectPropertyVariants,
        ["--gdi-queries"] = InspectGdiQueries,
        ["--sdk-leaf"] = InspectSdkLeaf,
        ["--window-graphics"] = InspectWindowGraphics,
        ["--ufi"] = InspectUfi,
        ["--graphics"] = InspectGraphics,
        ["--reference-arrays"] = InspectReferenceArrays,
        ["--parameterized"] = InspectParameterized,
    };

    [STAThread]
    public static int Main(string[] arguments)
    {
        // Windows created here keep their settings apart from the user's profile.
        var settingsPath = Path.Combine(Path.GetTempPath(), $"Detourist-Settings-{Environment.ProcessId}.json");
        Environment.SetEnvironmentVariable("DETOURIST_SETTINGS", settingsPath);
        AppDomain.CurrentDomain.ProcessExit += (_, _) => File.Delete(settingsPath);
        if (arguments is [var mode, var path] && Inspectors.TryGetValue(mode, out var inspect))
        {
            try
            {
                new App().InitializeComponent();
                inspectionPath = path;
                using var details = JsonDocument.Parse(File.ReadAllText(path));
                inspect(details);
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine(error);
                return 1;
            }
        }
        if (arguments is ["--rtm-fields"])
        {
            try { InspectRtmFields(); return 0; }
            catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        }
        var app = new App();
        app.InitializeComponent();
        var window = new ProbeWindow { WindowState = WindowState.Minimized, ShowActivated = false };
        var code = 0;
        window.Loaded += async (_, _) =>
        {
            try
            {
                if (arguments is ["--window-spy"])
                {
                    await WindowSpyFlow();
                    Console.WriteLine("PASS: Window Spy views, properties, logging, filters, selection, " +
                        "message decoding, scaled layout and shutdown.");
                    return;
                }
                if (arguments is ["--view-concurrency"])
                {
                    await ViewConcurrency();
                    return;
                }
                if (arguments is ["--collector-failures"])
                {
                    await CollectorFailures();
                    Console.WriteLine(
                        "PASS: collector deadlines, blocked writes, queued requests and desktop shutdown.");
                    return;
                }
                if (arguments is ["--catalog-editing"])
                {
                    await CatalogEditing();
                    Console.WriteLine("PASS: architecture selection, isolated edits, catalog validation and editor layout.");
                    return;
                }
                await Run(window, arguments is ["--com-inspection"]);
                await TimelineFailure();
                await BreakpointDisconnection();
                await WindowLifetime();
                await CatalogEditing();
                Console.WriteLine(
                    "PASS: real capture, typed controls, validation, complete trace views, retained selection, " +
                    "scaled layout, catalog editing and window shutdown.");
            }
            catch (Exception exception)
            {
                code = 1;
                Console.Error.WriteLine(exception);
            }
            finally
            {
                window.Close();
            }
        };
        window.Closed += (_, _) => Dispatcher.CurrentDispatcher.BeginInvokeShutdown(DispatcherPriority.Background);
        window.Show();
        Dispatcher.Run();
        return code;
    }

    private static async Task WindowLifetime()
    {
        // Customized duration columns remain available when the saved layout is restored.
        var layout = CaptureSettings.Load();
        var savedColumns = layout.Columns;
        layout.Columns = new()
        {
            ["Elapsed (µs)"] = new(true, 108, 8), ["PID / TID"] = new(false, 125, 2)
        };
        layout.Save();
        var early = new MainWindow();
        var earlyGrid = (DataGrid)early.FindName("CallsGrid");
        Require(earlyGrid.Columns.First(column => column.Header.ToString() == "Elapsed (µs)").Visibility ==
            Visibility.Visible && earlyGrid.Columns.First(column => column.Header.ToString() == "PID / TID").Visibility ==
            Visibility.Collapsed, "The saved column choices were not restored.");

        // Closing before startup must return from the closing event before the final close begins.
        var earlyClosed = new TaskCompletionSource();
        early.Closed += (_, _) => earlyClosed.SetResult();
        early.Close();
        await earlyClosed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        layout.Columns = savedColumns;
        layout.Save();

        // A running desktop window releases its collector and closes through the same path.
        var main = new MainWindow { WindowState = WindowState.Minimized, ShowActivated = false };
        var closed = new TaskCompletionSource();
        main.Closed += (_, _) => closed.SetResult();
        main.Show();
        var deadline = Stopwatch.StartNew();
        while (!((TextBlock)main.FindName("StatusText")).Text.StartsWith("Ready"))
        {
            Require(deadline.Elapsed < TimeSpan.FromSeconds(10), "The desktop did not finish starting.");
            await Task.Delay(25);
        }
        try
        {
            // Render each dialog section with the same styles and catalog used by the desktop window.
            var catalog = (ApiInfo[])typeof(MainWindow)
                .GetField("catalog", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(main)!;
            var categories = (CategoryInfo[])typeof(MainWindow)
                .GetField("categories", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(main)!;
            var settings = (CaptureSettings)typeof(MainWindow)
                .GetField("settings", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(main)!;
            var settingsWindow = new SettingsWindow(settings, catalog, categories, false);
            var sections = Elements(settingsWindow).OfType<TabControl>().Single();
            foreach (var index in Enumerable.Range(0, sections.Items.Count))
            {
                sections.SelectedIndex = index;
                await SaveView(settingsWindow, "settings-" + index);
            }
            sections.SelectedIndex = 1;
            var filters = Elements(settingsWindow).OfType<ComboBox>().Single(element =>
                System.Windows.Automation.AutomationProperties.GetName(element) == "Capture filter list");
            filters.SelectedIndex = 2;
            var profile = Elements(settingsWindow).OfType<ComboBox>().Single(element =>
                System.Windows.Automation.AutomationProperties.GetName(element) == "Noise filter profile");
            profile.SelectedIndex = 1;
            Elements(settingsWindow).OfType<Button>().Single(button => Equals(button.Content, "Add _profile"))
                .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            var exclusions = Elements(settingsWindow).OfType<DataGrid>().Single(grid =>
                grid.ItemsSource is IEnumerable<CaptureGroup> items && items.Any(item => item.Name == "GetLastError"));
            var errorQuery = ((IEnumerable<CaptureGroup>)exclusions.ItemsSource)
                .Single(item => item.Name == "GetLastError");
            Require(errorQuery.Enabled, "Noise profile did not add the selected exclusions.");
            errorQuery.Enabled = false;
            await SaveView(settingsWindow, "settings-noise");
            settingsWindow.Close();
            var launch = new LaunchWindow(Path.Combine(AppContext.BaseDirectory, "DetouristTestTarget.exe"),
                exitCodes: "1, 0x10, 0xFFFFFFFF");
            await SaveView(launch, "launch");
            ((FrameworkElement)launch.Content).LayoutTransform = new ScaleTransform(1.25, 1.25);
            launch.Width = 600;
            await SaveView(launch, "launch-scaled");
            var exitCodes = Elements(launch).OfType<TextBox>().Single(input =>
                System.Windows.Automation.AutomationProperties.GetName(input) == "Expected exit codes");
            exitCodes.Text = "-1";
            Elements(launch).OfType<Button>().Single(button => Equals(button.Content, "_Launch"))
                .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Require(Elements(launch).OfType<TextBlock>().Any(text =>
                text.Text.StartsWith("Enter unsigned decimal", StringComparison.Ordinal)),
                "The launch dialog accepted an invalid exit code.");
            await SaveView(launch, "launch-invalid-exit-code");
            launch.Close();
            await TraceViews(main);
        }
        finally
        {
            main.Close();
            await closed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private static async Task Run(ProbeWindow window, bool inspectCom)
    {
        // Physical GDI text exports retain the public function signature and expandable structures.
        var script = ApiMetadata.Function("ScriptBreak", "gdi32full.dll");
        Require(script is not null && script.Module == "gdi32full.dll" && script.Parameters.Length == 4 &&
            script.Parameters[2].Name == "psa" &&
            ApiMetadata.Structure(script.Parameters[2].Type)?.Fields?.Any(field => field.Name == "eScript") == true,
            "The physical Uniscribe provider lost its typed, expandable public contract.");

        var root = Path.Combine(Path.GetTempPath(), "Detourist-Desktop-" + Guid.NewGuid().ToString("N"));
        Require(Path.GetDirectoryName(Path.GetFullPath(root)) == Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(Path.GetTempPath())), "The fixture directory is outside the temporary workspace.");
        Directory.CreateDirectory(root);
        var database = Path.Combine(root, "trace.db");
        await using var client = new CollectorClient();
        try
        {
            var hello = await client.Send("hello");
            var api = hello.Items("catalog").First(item => item.Text("name") == "FindFirstFileExW");
            await client.Send("launch", new
            {
                startMinimized = true,
                database, executable = Path.Combine(AppContext.BaseDirectory, "DetouristTestTarget.exe"),
                arguments = "--leaf 2", entryApi = api.Number("id"), exitApi = api.Number("id"),
                bufferLimit = 1024, stackDepth = 16, followChildren = false, instructionEngine = false
            });
            var status = await Wait(client, status => status.Flag("breakpoint"));
            var stopped = status.GetProperty("stoppedCall");
            var grid = window.Parameters;
            var inspection = Stopwatch.StartNew();
            grid.ShowCall(stopped, true, false);
            Console.WriteLine($"Cold parameter inspection: {inspection.Elapsed.TotalMilliseconds:F1} ms.");
            window.UpdateLayout();
            var properties = (DataGrid)grid.FindName("PropertiesGrid");
            var number = (TextBox)grid.FindName("NumberInput");
            var format = (ComboBox)grid.FindName("NumberFormat");
            var interpretation = (ComboBox)grid.FindName("InterpretCombo");
            var choice = (ComboBox)grid.FindName("ChoiceInput");
            var rows = properties.Items.Cast<ParameterProperty>().Where(row => row.Parameter >= 0).ToArray();
            Require(properties.Columns[1].Visibility == Visibility.Visible &&
                rows[0].Name.EndsWith("lpFileName") && rows[0].TypeName == "LPCWSTR",
                "The selected function did not resolve its named SDK parameters.");
            Require(properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == -1).TypeName == "HANDLE",
                "The function's declared return type was not resolved.");

            // Use the same editable controls and serializer that the breakpoint window consumes.
            properties.SelectedItem = rows[1];
            Require(choice.Visibility == Visibility.Visible && rows[1].Type.Kind == "Enum", "Enum selector missing.");
            choice.SelectedItem = ((IEnumerable<EnumValue>)choice.ItemsSource).First(value => value.Value == 0);
            Require(grid.Arguments()[1] == "0x0", "The enum selection did not reach the argument array.");
            properties.SelectedItem = rows[5];
            format.SelectedIndex = 1;
            number.Text = "4294967296";
            try
            {
                _ = grid.Arguments();
                throw new InvalidOperationException("An overflowing DWORD edit was accepted.");
            }
            catch (FormatException)
            {
                Require(rows[5].HasError, "The invalid row lost its validation state.");
            }
            number.Text = "0";
            interpretation.SelectedItem = "Boolean";
            Require(choice.Visibility == Visibility.Visible && number.Visibility == Visibility.Collapsed,
                "The Boolean editor did not replace the numeric input.");
            choice.SelectedItem = ((IEnumerable<EnumValue>)choice.ItemsSource).First(value => value.Value == 1);
            Require(grid.Arguments()[5] == "0x1", "The Boolean selection did not reach the argument array.");
            interpretation.SelectedItem = "Int32";
            number.Text = "-1";
            Require(grid.Arguments()[5] == "0xFFFFFFFF", "Signed editing lost the value's register bits.");
            interpretation.SelectedItem = "Float32";
            number.Text = "1.5";
            Require(grid.Arguments()[5] == "0x3FC00000", "Floating-point interpretation lost the register bits.");
            interpretation.SelectedItem = "Signature";
            number.Text = "2";
            Require(rows[5].Modified && ((Button)grid.FindName("FlagsButton")).Visibility == Visibility.Visible,
                "The mask edit did not show its modified state or bit editor.");
            await client.Send("continue", new { callId = stopped.Number("id"), pid = stopped.Number("pid"),
                tid = stopped.Number("tid"), arguments = grid.Arguments(), skip = false });
            status = await Wait(client, value => value.Flag("breakpoint") && value.Flag("leaving"));
            stopped = status.GetProperty("stoppedCall");
            grid.ShowCall(stopped, true, true);
            rows = properties.Items.Cast<ParameterProperty>().Where(row => row.Parameter >= 0).ToArray();
            Require(rows.All(row => !row.Editable), "Return breakpoints allow argument editing.");

            // Read and write a real structure while its owning process remains stopped.
            var memoryEditor = new MemoryEditor(client, stopped, 1024);
            memoryEditor.SetAddress(Convert.ToUInt64(stopped.Items("arguments")[2].GetString()![2..], 16), "LPVOID");
            window.ShowMemory(memoryEditor);
            var controls = Elements(memoryEditor).ToArray();
            var count = controls.OfType<TextBox>().First(control =>
                System.Windows.Automation.AutomationProperties.GetName(control) == "Memory read length");
            var bytes = controls.OfType<TextBox>().First(control =>
                System.Windows.Automation.AutomationProperties.GetName(control) == "Memory value");
            var memoryType = controls.OfType<ComboBox>().Single();
            count.Text = "592";
            controls.OfType<Button>().First(button => button.Content.ToString() == "_Read memory")
                .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            while (memoryEditor.Busy) await Task.Delay(10);
            Require(bytes.Text.Length == 1184, "Live memory inspection did not read the complete structure.");
            var attributes = MemorySnapshot.Scalar(Convert.FromHexString(bytes.Text), 0, 4);
            memoryType.SelectedItem = "UInt32";
            Require(bytes.Text == attributes.ToString(), "Changing memory interpretation discarded its loaded bytes.");
            controls.OfType<Button>().First(button => button.Content.ToString() == "_Write memory")
                .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            while (memoryEditor.Busy) await Task.Delay(10);
            Require(controls.OfType<TextBlock>().Any(text => text.Text.Contains("4 bytes written")),
                "The typed memory write was not acknowledged.");
            try
            {
                await client.Send("readMemory", new
                {
                    address = stopped.Items("arguments")[2].GetString(), length = 1025
                });
                throw new InvalidOperationException("Live memory inspection exceeded the configured capture limit.");
            }
            catch (IOException) { }
            window.ShowMemory(null);
            await client.Send("breakApi", new { entryApi = -1, exitApi = -1 });
            await client.Send("continue", new { callId = stopped.Number("id"), pid = stopped.Number("pid"),
                tid = stopped.Number("tid"), skip = false });
            await Wait(client, value => value.Flag("finished"));
            var page = await client.Send("page", new { database, limit = 1 });
            Require(page.Items("targets").All(target => target.Text("state") == "Exited"),
                "Typed edits broke the target's file workload.");
            var returned = await client.Send("details", new { database, target = stopped.Number("target"),
                callId = stopped.Number("id") });
            grid.ShowCall(returned);
            var memory = properties.Items.Cast<ParameterProperty>().First(row => row.OutputMemory?.Kind == 3);
            Require(memory.Children.Any(field => field.Name == "cFileName"), "The file structure was not expanded.");
            Require(memory.OutputMemory!.Bytes.Length == 592, "The captured structure has the wrong extent.");
            var time = memory.Children.First(field => field.Name == "ftCreationTime");
            Require(time.TypeName == "FILETIME" && time.Children.Count == 2,
                "A nested structure has no named fields.");
            Require(memory.Children.First(field => field.Name == "cFileName").OutputText.Contains("\""),
                "The fixed string array lost its decoded value.");

            // A pending return updates snapshots without moving the inspector away from the selected value.
            grid.ShowCall(returned);
            properties.SelectedItem = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == 1);
            interpretation.SelectedItem = "UInt32";
            format.SelectedIndex = 1;
            grid.ShowCall(returned);
            Require(properties.SelectedItem is ParameterProperty
                { Parameter: 1, Hex: false, OverrideType.Name: "UInt32" },
                "Refreshing the call discarded its selection or interpretation.");
            properties.SelectedItem = properties.Items.Cast<ParameterProperty>()
                .First(row => row.OutputMemory?.Kind == 3);
            var buffer = (Button)grid.FindName("BufferButton");
            Require(buffer.Visibility == Visibility.Visible && number.IsReadOnly && number.Text.Contains("592"),
                "The output snapshot has no read-only buffer view.");

            // Inspect real aggregate arguments and capped structure output through the same property grid.
            var graphicalDatabase = Path.Combine(root, "win32.db");
            await client.Send("launch", new
            {
                startMinimized = true,
                database = graphicalDatabase,
                executable = Path.Combine(AppContext.BaseDirectory, "DetouristWin32Tests.exe"),
                arguments = "--target",
                bufferLimit = 16, followChildren = false, instructionEngine = false
            });
            await Wait(client, value => value.Flag("finished"));
            async Task Inspect(string name, bool breakpoint = false, bool leaving = false)
            {
                var calls = await client.Send("page", new { database = graphicalDatabase, api = name, limit = 1 });
                var selected = calls.Items("calls").First();
                var details = await client.Send("details", new { database = graphicalDatabase,
                    target = selected.Number("target"), callId = selected.Number("id") });
                grid.ShowCall(details, breakpoint, leaving);
                window.UpdateLayout();
            }
            await Inspect("PtInRect");
            var point = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == 1);
            Require(point.TypeName == "POINT" && point.Children.First(field => field.Name == "x").Input == 25 &&
                point.Children.First(field => field.Name == "y").Input == 50,
                "A by-value structure was not expanded from its register value.");
            var rectangle = properties.Items.Cast<ParameterProperty>()
                .First(row => row.Parameter == 0).Children.Single();
            Require(rectangle.TypeName == "RECT" && rectangle.Children.Count == 4 &&
                rectangle.Children.First(field => field.Name == "right").Input == 100 &&
                rectangle.Children.First(field => field.Name == "bottom").Input == 100,
                "A pointed-to structure did not resolve its field layout.");
            await Inspect("NtUserGetClipCursor");
            rectangle = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == 0).Children.Single();
            Require(rectangle.Children.First(field => field.Name == "right").Output is > 0 &&
                rectangle.Children.First(field => field.Name == "bottom").Output is > 0,
                "An output structure was not decoded.");
            await Inspect("InitializeCriticalSection");
            var section = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == 0).Children.Single();
            Require(section.OutputMemory?.Bytes.Length == 16 && section.Children.Count >= 6 &&
                section.Children.First(field => field.Name == "RecursionCount").Output == 0 &&
                section.Children.First(field => field.Name == "OwningThread").Output is null &&
                section.Children.First(field => field.Name == "OwningThread").OutputText == "<not captured>",
                "A capped structure hid fields or invented missing values.");

            // Resolve a generic buffer from its captured information-class discriminator.
            graphicalDatabase = Path.Combine(root, "native.db");
            await client.Send("launch", new
            {
                startMinimized = true,
                database = graphicalDatabase,
                executable = Path.Combine(AppContext.BaseDirectory, "DetouristTestTarget.exe"),
                arguments = "--native", bufferLimit = 64, followChildren = false, instructionEngine = false
            });
            await Wait(client, value => value.Flag("finished"));
            await Inspect("NtQueryInformationProcess");
            var information = properties.Items.Cast<ParameterProperty>()
                .First(row => row.Parameter == 2).Children.Single();
            var process = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == 1);
            Require(process.TypeName == "PROCESSINFOCLASS" && process.Type.Kind == "Enum" &&
                process.InputText.StartsWith("ProcessBasicInformation"),
                "The information class was not resolved to its named enum value.");
            Require(information.TypeName == "PROCESS_BASIC_INFORMATION" &&
                information.Children.First(field => field.Name == "UniqueProcessId").Output is > 0 &&
                information.Children.First(field => field.Name == "PebBaseAddress").Output is > 0,
                "The information class did not resolve its generic output buffer to a structure.");
            graphicalDatabase = database;
            await Inspect("NtCreateFile");
            var ioStatus = properties.Items.Cast<ParameterProperty>()
                .First(row => row.Parameter == 3).Children.Single();
            var union = ioStatus.Children.First(field => field.TypeName == "union");
            Require(ioStatus.TypeName == "IO_STATUS_BLOCK" &&
                union.Children.First(field => field.Name == "Status").Output == 0 &&
                union.Children.First(field => field.Name == "Pointer").Type.Kind == "Pointer",
                "A union inside a captured structure was not expanded.");

            var warm = Stopwatch.StartNew();
            grid.ShowCall(returned);
            var lookupQueries = ApiMetadata.Statistics.Queries;
            for (var repeat = 0; repeat < 25; ++repeat) grid.ShowCall(returned);
            Require(ApiMetadata.Statistics.Queries == lookupQueries,
                "Redrawing the same property grid queried the API catalog again.");
            Console.WriteLine($"Warm structure inspection: {warm.Elapsed.TotalMilliseconds / 25:F2} ms per call.");
            grid.ShowCall(returned);
            properties.SelectedItem = properties.Items.Cast<ParameterProperty>()
                .First(row => row.OutputMemory?.Kind == 3);

            // Exercise the narrow inspector at larger display scaling with full captured data.
            window.Width = 620;
            ((FrameworkElement)window.Content).LayoutTransform = new ScaleTransform(1.5, 1.5);
            await window.Dispatcher.InvokeAsync(window.UpdateLayout, DispatcherPriority.ApplicationIdle);
            var editor = (FrameworkElement)grid.FindName("EditorPanel");
            Require(number.ActualWidth > 100 && editor.ActualWidth <= grid.ActualWidth + 1,
                "The scaled parameter editor overflows its inspector.");
            Elements(grid).OfType<Button>().First(button =>
                System.Windows.Automation.AutomationProperties.GetName(button) == "Expand all properties")
                .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            window.UpdateLayout();
            Require(properties.Items.Cast<ParameterProperty>()
                .Any(row => row.Name == "dwLowDateTime" && row.Level == 3),
                "Expanding the property grid did not reveal nested structure rows.");

            if (inspectCom)
            {
                // Inspect actual COM output structures and native floating values through SDK interface signatures.
                Require(File.Exists(Path.Combine(AppContext.BaseDirectory, "DetouristInstructions.dll")),
                    "The instruction engine fixture is missing.");
                graphicalDatabase = Path.Combine(root, "com.db");
                await client.Send("launch", new
                {
                    startMinimized = true,
                    database = graphicalDatabase,
                    executable = Path.Combine(AppContext.BaseDirectory, "DetouristComTarget.exe"),
                    apiMask = hello.Text("comMask"), bufferLimit = 64, followChildren = false, instructionEngine = true
                });
                await Wait(client, value => value.Flag("finished"), 90);
                await Inspect("ITypeInfo::GetTypeAttr");
                var attribute = properties.Items.Cast<ParameterProperty>()
                    .First(row => row.Parameter == 1).Children.Single(row => row.TypeName == "TYPEATTR");
                Require(attribute.OutputMemory is { OriginalBytes: 96, Bytes.Length: 64 } &&
                    attribute.Children.First(field => field.Name == "cFuncs").Output is > 0,
                    "A returned COM structure did not retain its named fields and captured values.");
                await Inspect("IStream::Read");
                Require(properties.Items.Cast<ParameterProperty>().Any(row => row.Name == "[2] cb"),
                    "An inherited interface method lost its named parameters.");
                await Inspect("ID2D1Brush::GetOpacity");
                var opacity = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == -1);
                Require(opacity.Type.Kind == "Float32" && opacity.Output == BitConverter.SingleToUInt32Bits(0.375f),
                    "A COM floating return was decoded as an integer or read from the wrong register.");
                await Inspect("ID2D1Brush::GetTransform");
                var matrix = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == 1)
                    .Children.Single(row => row.OutputMemory?.Bytes.Length == 24);
                Require(matrix.TypeName.Contains("MATRIX") && matrix.Children.Count > 0,
                    "A COM graphics structure did not expand in the property grid.");
                await Inspect("ID2D1SolidColorBrush::GetColor");
                var color = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == -1);
                Require(color.Output is null && !color.Editable && color.Children.Single().Children
                    .First(field => field.Name == "r").Output == BitConverter.SingleToUInt32Bits(0.125f),
                    "A structure return exposed its buffer address instead of its named fields.");
                await Inspect("ID2D1SolidColorBrush::GetColor", true, true);
                color = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == -1);
                Require(!color.Editable && color.Children.Any(row => row.Name == "Return buffer" &&
                    row.Type.Kind == "Pointer" && row.Output is > 0),
                    "A structure breakpoint did not expose its original buffer for memory inspection.");
                await Inspect("ID2D1Layer::GetSize");
                var size = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == -1);
                Require(size.Children.Single().Children.First(field => field.Name == "height").Output ==
                    BitConverter.SingleToUInt32Bits(257.25f), "A small structure return did not expand.");
                var blendCaptured = false;
                foreach (var version in new[] { "", "1", "2", "3", "4" })
                {
                    var method = $"ID3D11DeviceContext{version}::OMGetBlendState";
                    var calls = await client.Send("page",
                        new { database = graphicalDatabase, api = method, limit = 1 });
                    if (!calls.Items("calls").Any()) continue;
                    await Inspect(method);
                    blendCaptured = true;
                    break;
                }
                Require(blendCaptured, "The graphics blend-state call was not captured.");
                var blend = properties.Items.Cast<ParameterProperty>().First(row => row.Parameter == 2);
                var factors = blend.Children.Single();
                Require(blend.Type.Kind == "Pointer" && factors.Children.Count == 4 && factors.Children[2].Output ==
                    BitConverter.SingleToUInt32Bits(0.5f), "A returned fixed array did not expand.");
                await Inspect("IDWriteTextAnalyzer::GetGdiCompatibleGlyphPlacements");
                Require(properties.Items.Cast<ParameterProperty>().Any(row =>
                    row.Parameter == 21 && row.Name.EndsWith("glyphOffsets") && row.Input.HasValue),
                    "The property grid omitted a captured argument beyond the twentieth slot.");
            }
            grid.Clear("Loading parameters…");
            Require(properties.Items.Count == 0 && editor.Visibility == Visibility.Collapsed,
                "Changing calls leaves stale properties or editors visible.");
        }
        finally
        {
            await client.Send("stop");
            await Wait(client, value => value.Flag("finished"));
            await client.DisposeAsync();
            Directory.Delete(root, true);
        }
    }
}

using Detourist.Desktop;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Threading;

namespace Detourist.Desktop.Tests;

public static partial class Program
{
    [DllImport("user32.dll", EntryPoint = "SendMessageTimeoutW", SetLastError = true)]
    private static extern nint SpySend(nint window, uint message, nuint wparam, nint lparam,
        uint flags, uint timeout, out nuint result);

    private static T SpyField<T>(WindowSpyWindow window, string name) => (T)typeof(WindowSpyWindow)
        .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(window)!;

    private static async Task SpyWait(Func<bool> predicate)
    {
        var timeout = Stopwatch.StartNew();
        while (!predicate())
        {
            if (timeout.Elapsed > TimeSpan.FromSeconds(12))
                throw new TimeoutException("Window Spy did not finish the requested operation.");
            await Task.Delay(20);
        }
        await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
    }

    private static async Task SpyClick(WindowSpyWindow window, string name)
    {
        var button = SpyField<Button>(window, name);
        Require(button.IsEnabled && button.Visibility == Visibility.Visible, $"The {name} action is unavailable.");
        button.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        await SpyWait(() => !SpyField<bool>(window, "busy"));
    }

    private static IEnumerable<SpyNode> SpyNodes(IEnumerable<SpyNode> source)
    {
        foreach (var node in source)
        {
            yield return node;
            foreach (var child in SpyNodes(node.Children)) yield return child;
        }
    }

    private static async Task WindowSpyFlow()
    {
        // Drive real HWNDs through the same inspection and logging controls used by the desktop app.
        using var process = Process.Start(new ProcessStartInfo(
            Path.Combine(AppContext.BaseDirectory, "DetouristWindowSpyTarget.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
        })!;
        using var identity = JsonDocument.Parse((await process.StandardOutput.ReadLineAsync())!);
        var handle = identity.RootElement.Text("window");
        var hwnd = (nint)long.Parse(handle.AsSpan(2), NumberStyles.HexNumber);
        var childHandle = identity.RootElement.Text("child");
        ProcessItem? captured = null;
        var captureAllowed = true;
        var spy = new WindowSpyWindow(item => { captured = item; return Task.CompletedTask; }, () => captureAllowed)
        {
            ShowActivated = false, WindowStartupLocation = WindowStartupLocation.Manual, Left = -10000, Top = -10000
        };
        var finished = new TaskCompletionSource();
        spy.Closed += (_, _) => finished.TrySetResult();
        spy.Show();
        try
        {
            await SpyWait(() => !SpyField<bool>(spy, "busy") && SpyField<TreeView>(spy, "tree").Items.Count > 0);
            var tree = SpyField<TreeView>(spy, "tree");
            var view = SpyField<ComboBox>(spy, "view");
            var properties = SpyField<DataGrid>(spy, "properties");
            var search = SpyField<TextBox>(spy, "search");
            var snapshot = SpyField<JsonElement>(spy, "snapshot");
            var key = "w0x" + hwnd.ToInt64().ToString("X");
            foreach (var mode in new[] { 0, 1, 2 })
            {
                var roots = WindowSpyWindow.BuildTree(snapshot, mode, "DetouristWindowSpyTarget");
                Require(SpyNodes(roots).Any(node => node.Key == key), "A view lost the target window.");
                Require(mode != 1 || roots.All(node => node.Kind == "Process"), "Process view lost its roots.");
                Require(mode != 2 || roots.All(node => node.Kind == "Thread"), "Thread view lost its roots.");
            }
            var applications = tree.Items.Cast<SpyNode>().ToArray();
            Require(applications.All(node => node.Kind == "Process" && node.Window == "0x0" && node.Tid == 0) &&
                applications.Select(node => node.ProcessName).SequenceEqual(applications.Select(node =>
                    node.ProcessName).OrderBy(name => name, StringComparer.OrdinalIgnoreCase)),
                "Window view did not group windows by application in alphabetical order.");
            var application = applications.Single(node => node.Pid == process.Id);
            var targetWindow = application.Children.Single(node => node.Key == key);
            Require(targetWindow.Title == "Detourist Window Spy test" &&
                targetWindow.Children.Any(node => node.Window.Equals(childHandle, StringComparison.OrdinalIgnoreCase)),
                "Application grouping lost the readable window title or the child-window hierarchy.");
            search.Text = handle;
            await SpyWait(() => !SpyField<DispatcherTimer>(spy, "filterTimer").IsEnabled);
            tree.UpdateLayout();
            await SpyWait(() => SpyNodes(tree.Items.Cast<SpyNode>()).Any(node =>
                node.Window.Equals(handle, StringComparison.OrdinalIgnoreCase)));
            var selected = SpyNodes(tree.Items.Cast<SpyNode>()).Single(node => node.Key == key);
            selected.Selected = true;
            await SpyWait(() => properties.Items.Count > 0);
            Require(SpyField<Button>(spy, "highlight").Visibility == Visibility.Visible,
                "Window selection did not expose highlighting.");
            await SpyClick(spy, "captureButton");
            Require(captured?.Pid == process.Id, "API capture did not receive the selected process.");
            captureAllowed = false;
            await SpyWait(() => SpyField<Button>(spy, "captureButton").Visibility == Visibility.Collapsed);
            foreach (var mode in new[] { 1, 2, 0 })
            {
                view.SelectedIndex = mode;
                await SpyWait(() => properties.Items.Count > 0);
                Require(SpyField<SpyNode>(spy, "selected").Key == key,
                    "Switching object views lost the selected window.");
            }
            await SpyClick(spy, "highlight");
            var error = (TextBlock)typeof(ToolWindow).GetField("Error",
                BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(spy)!;
            Require(error.Text.Contains("hidden"), "Highlighting a hidden window did not explain its absence.");

            // Changing selection clears old properties and exposes only applicable target scopes.
            search.Text = "";
            await Task.Delay(300);
            SpyNodes(tree.Items.Cast<SpyNode>()).Single(node => node.Key == key).Expanded = true;
            tree.UpdateLayout();
            var child = SpyNodes(tree.Items.Cast<SpyNode>()).Single(node =>
                node.Window.Equals(childHandle, StringComparison.OrdinalIgnoreCase));
            child.Selected = true;
            await SpyWait(() => SpyField<SpyNode>(spy, "selected").Key == child.Key &&
                properties.Items.Cast<SpyProperty>().Any(item => item.Name == "Text"));
            var scope = SpyField<ComboBox>(spy, "scope");
            Require(scope.Items.Count == 3, "A window did not offer window, thread and process logging.");
            await SpyClick(spy, "start");
            Require(SpyField<CollectorClient>(spy, "logger") is not null && !scope.IsEnabled,
                "The live log did not retain its target scope.");
            Require(SpyField<string>(spy, "logTarget").Contains(child.Window),
                "Logging used a stale window selection.");
            await Task.Run(() => Require(SpySend(hwnd, 0x8002, 0, 0, 2, 3000, out _) != 0,
                "The target stopped responding while logging."));
            var messages = SpyField<DataGrid>(spy, "messages");
            await SpyWait(() => messages.Items.Cast<WindowMessage>().Any(item => item.Id == 0xC));
            SpyField<ComboBox>(spy, "kind").SelectedIndex = 2;
            Require(messages.Items.Cast<WindowMessage>().All(item => item.Type == 1), "Return filtering failed.");
            SpyField<TextBox>(spy, "messageFilter").Text = "WM_SETTEXT";
            await Task.Delay(300);
            Require(messages.Items.Count > 0 && messages.Items.Cast<WindowMessage>().All(item => item.Id == 0xC),
                "Message-name filtering failed.");
            messages.SelectedIndex = 0;
            Require(SpyField<TextBox>(spy, "detail").Text.Contains("result="), "Return details were omitted.");

            // Refresh recovers a failed inspection service while preserving the selection and active message log.
            var activeLogger = SpyField<CollectorClient>(spy, "logger");
            var failedReader = SpyField<CollectorClient>(spy, "reader");
            var readerProcess = (Process)ClientField(failedReader, "process");
            readerProcess.Kill();
            await readerProcess.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(12));
            await SpyClick(spy, "refresh");
            Require(SpyField<CollectorClient>(spy, "reader").IsConnected && error.Text.Length == 0,
                "Refreshing did not reconnect the failed inspection service.");
            await SpyWait(() => properties.Items.Cast<SpyProperty>().Any(item => item.Name == "Text"));
            Require(SpyField<SpyNode>(spy, "selected").Key == child.Key &&
                ReferenceEquals(activeLogger, SpyField<CollectorClient>(spy, "logger")) && messages.Items.Count > 0,
                "Recovering inspection lost the selection or interrupted message logging.");
            await SpyClick(spy, "stop");
            Require(messages.Items.Count > 0 && scope.IsEnabled, "Stopping discarded the log or left controls locked.");

            var caption = Marshal.StringToHGlobalUni("Detourist Window Spy test — a long window caption that " +
                "must stay within its column while handles remain readable");
            try
            {
                Require(SpySend(hwnd, 0xC, 0, caption, 2, 3000, out _) != 0,
                    "The target did not accept the long window caption.");
            }
            finally { Marshal.FreeHGlobal(caption); }
            await SpyClick(spy, "refresh");

            // Check layouts at normal, narrow and enlarged text sizes using the real rendered controls.
            foreach (var (width, height, scale, name) in new[]
            {
                (1240d, 850d, 1d, "window-spy"), (800d, 650d, 1d, "window-spy-narrow"),
                (1240d, 900d, 1.5d, "window-spy-scaled")
            })
            {
                spy.Width = width;
                spy.Height = height;
                var content = (FrameworkElement)spy.Content;
                content.LayoutTransform = new ScaleTransform(scale, scale);
                content.Measure(new Size(width - 16, height - 40));
                content.Arrange(new Rect(0, 0, width - 16, height - 40));
                content.UpdateLayout();
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                content.UpdateLayout();
                foreach (var field in new[] { "finder", "refresh", "scope", "start", "export", "messageFilter" })
                {
                    var control = (FrameworkElement)typeof(WindowSpyWindow).GetField(field,
                        BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(spy)!;
                    var bounds = control.TransformToAncestor(content).TransformBounds(new Rect(control.RenderSize));
                    Require(control.ActualWidth > 0 && bounds.Left >= 0 && bounds.Right <= content.ActualWidth + 1,
                        $"The {field} control clips at {name}.");
                }
                Require(messages.ActualHeight >= 60 && tree.ActualHeight >= 60,
                    $"The inspection or message view disappeared at {name}.");
                var visuals = VisualTree(tree);
                var identities = visuals.OfType<TextBlock>().Where(text =>
                    text.DataContext is SpyNode node && text.Text == node.Identifier).Select(text =>
                        text.TransformToAncestor(tree).TransformBounds(new Rect(text.RenderSize))).ToArray();
                Require(identities.Length > 0 && identities.All(bounds => bounds.Left >= 0 &&
                    bounds.Right <= tree.ActualWidth + 1) &&
                    identities.Max(bounds => bounds.Right) - identities.Min(bounds => bounds.Right) <= 1,
                    $"Object IDs do not stay aligned and visible at {name} ({tree.ActualWidth:F1}): " +
                    string.Join("; ", identities.Select(bounds => bounds.ToString(CultureInfo.InvariantCulture))));
                await SaveView(spy, name);
            }
            Require(WindowMessages.Name(0x400 + 5, "msctls_progress32") == "PBM_STEPIT" &&
                WindowMessages.Name(0x400 + 5, "custom") == "WM_USER+5" &&
                WindowMessages.Name(0x2001, "SysListView32") == "CCM_SETBKCOLOR" &&
                WindowMessages.Name(0x2001, "custom") == "WM_USER+7169",
                "Overlapping control and application message ranges were decoded as the same message.");
            Require(WindowMessages.Name(0xB0, "Edit") == "EM_GETSEL" &&
                WindowMessages.Name(0xB0, "RichEdit50W") == "EM_GETSEL" &&
                WindowMessages.Name(0x432, "RichEdit50W") == "EM_CANPASTE" &&
                WindowMessages.Name(0x432, "Edit") == "WM_USER+50",
                "Shared edit messages or RichEdit-specific messages were decoded for the wrong control class.");
            Require(WindowMessages.Decode(0x200, "0x0", "0xFFECFFF6").Contains("x=-10, y=-20"),
                "Negative mouse coordinates were decoded as unsigned values.");
            Require(WindowMessages.Decode(0x111, "0x1002A", "0x0") == "Accelerator ID=42",
                "A command accelerator was decoded as a control notification.");

            await SpyClick(spy, "clear");
            Require(messages.Items.Count == 0 && SpyField<TextBox>(spy, "detail").Text.Length == 0,
                "Clearing left stale messages or details.");
            scope.SelectedItem = "Process";
            await SpyClick(spy, "start");
            spy.Close();
            await finished.Task.WaitAsync(TimeSpan.FromSeconds(12));
            Require(SpySend(hwnd, 0x8001, 4, 9, 2, 3000, out var result) != 0 && result == 13,
                "Closing a live Window Spy stranded its target.");

            // Owner closure bypasses an owned WPF window's Closing event, but its collectors must still exit.
            var owner = new Window
            {
                ShowActivated = false, Width = 200, Height = 100, Left = -10000, Top = -10000,
                WindowStartupLocation = WindowStartupLocation.Manual
            };
            owner.Show();
            var owned = new WindowSpyWindow { Owner = owner, ShowActivated = false };
            owned.Show();
            await SpyWait(() => !SpyField<bool>(owned, "busy") &&
                SpyField<CollectorClient>(owned, "reader") is not null);
            var service = (Process)ClientField(SpyField<CollectorClient>(owned, "reader"), "process");
            using var monitor = Process.GetProcessById(service.Id);
            owner.Close();
            await monitor.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(12));
            Require(!owned.IsVisible, "The owned inspector remained open after its owner closed.");

            var immediate = new WindowSpyWindow();
            var immediatelyClosed = new TaskCompletionSource();
            immediate.Closed += (_, _) => immediatelyClosed.TrySetResult();
            immediate.Close();
            await immediatelyClosed.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Console.WriteLine($"Window Spy UI: {identity.RootElement.Number("bits")}-bit target verified.");
        }
        finally
        {
            spy.Close();
            await finished.Task.WaitAsync(TimeSpan.FromSeconds(12));
            if (!process.HasExited) SpySend(hwnd, 0x10, 0, 0, 2, 3000, out _);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8));
        }
    }
}

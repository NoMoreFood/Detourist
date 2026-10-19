using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Threading;
using static Detourist.Desktop.Tests.Program;

namespace Detourist.Desktop.Tests;

public static class SymbolInspectorTests
{
    public static void Verify(JsonElement inspection)
    {
        JsonElement resolved = default, partial = default;
        foreach (var call in inspection.Items("calls"))
        {
            var item = CallItem.FromJson(call);
            Require(item.Caller == call.Text("callerDisplay", call.Text("callerText")),
                "The call list dropped the resolved caller or its address fallback.");
            var stack = ParameterValues.Build(call).Single(value => value.Name == "Call stack");
            var frames = call.Items("stack");
            Require(stack.Children.Count == frames.Length, "The inspector dropped a recorded stack frame.");
            for (var index = 0; index < frames.Length; ++index)
            {
                var frame = stack.Children[index];
                Require(frame.InputLabel == frames[index].Text("display"), "The stack frame label differs.");
                if (frames[index].Text("source") is { Length: > 0 } source)
                    Require(frame.Children.Single().InputLabel == $"{source}:{frames[index].Number("line")}",
                        "The source location is missing from the stack frame.");
                else Require(frame.Children.Count == 0, "An unresolved frame retained a stale source location.");
            }
            if (stack.InputLabel == "Partial stack") partial = call;
            if (call.Text("symbolState") == "resolved") resolved = call;
        }
        Require(resolved.ValueKind == JsonValueKind.Object && partial.ValueKind == JsonValueKind.Object,
            "Resolved and partial stack fixtures are required.");

        // The main inspector gives frames their own tab and replaces them on selection changes.
        var main = new MainWindow();
        var showStack = typeof(MainWindow).GetMethod("ShowStack", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var stackGrid = (DataGrid)main.FindName("StackGrid");
        foreach (var call in new[] { resolved, partial })
        {
            showStack.Invoke(main, [call]);
            var frames = call.Items("stack");
            Require(stackGrid.Items.Cast<StackFrameItem>().Select(frame => frame.Display)
                .SequenceEqual(frames.Select(frame => frame.Text("display"))) &&
                stackGrid.Items.Cast<StackFrameItem>().Select(frame => frame.Application)
                .SequenceEqual(frames.Select(frame => frame.Flag("application"))),
                "The stack tab lost frames or application attribution.");
        }
        Require(resolved.Items("stack").Any(frame => frame.Flag("application")),
            "The resolved stack fixture has no application frames.");
        Require(((TextBlock)main.FindName("StackStatus")).Text.Contains("partial stack"),
            "The stack tab did not identify a partial stack.");
        showStack.Invoke(main, [resolved]);
        ((TabItem)main.FindName("StackTab")).IsSelected = true;
        var parameters = (ParameterGrid)main.FindName("Parameters");
        parameters.ShowCall(resolved);
        Require(((DataGrid)parameters.FindName("PropertiesGrid")).Items.Cast<ParameterProperty>()
            .All(row => row.Name != "Call stack"), "The main parameters tab duplicated the dedicated stack tab.");
        var mainContent = (FrameworkElement)main.Content;
        main.Content = null;
        var mainHost = new Border { Child = mainContent, Background = main.Background };
        TextElement.SetForeground(mainHost, main.Foreground);
        TextElement.SetFontFamily(mainHost, main.FontFamily);
        TextElement.SetFontSize(mainHost, main.FontSize);
        foreach (var scale in new[] { 1.0, 1.5 })
        {
            mainContent.LayoutTransform = new ScaleTransform(scale, scale);
            var size = new Size(1540 * scale, 880 * scale);
            mainHost.Measure(size);
            mainHost.Arrange(new Rect(size));
            main.Dispatcher.Invoke(mainHost.UpdateLayout, DispatcherPriority.ApplicationIdle);
            Require(stackGrid.ActualHeight > 200 && stackGrid.ActualWidth >= 350,
                "The stack tab collapsed under display scaling.");
        }
        showStack.Invoke(main, [JsonSerializer.SerializeToElement(new { stack = Array.Empty<object>() })]);
        Require(stackGrid.Items.Count == 0 && ((TextBlock)main.FindName("StackStatus")).Text.StartsWith("No stack"),
            "Selecting a call without a stack left the previous frames visible.");
        mainHost.Child = null;

        // Exercise actual frame labels and source rows through the grid at normal and enlarged display scales.
        foreach (var scale in new[] { 1.0, 1.5 })
        {
            var grid = new ParameterGrid();
            grid.ShowCall(resolved);
            grid.LayoutTransform = new ScaleTransform(scale, scale);
            var host = new Border { Background = Brushes.Black, Child = grid };
            TextElement.SetForeground(host, Brushes.White);
            TextElement.SetFontFamily(host, new FontFamily("Segoe UI"));
            TextElement.SetFontSize(host, 13);
            var size = new Size(1100 * scale, 720 * scale);
            host.Measure(size);
            host.Arrange(new Rect(size));
            grid.Dispatcher.Invoke(host.UpdateLayout, DispatcherPriority.ApplicationIdle);
            var table = (DataGrid)grid.FindName("PropertiesGrid");
            Require(grid.ActualWidth >= 1099 && table.ActualWidth >= 1000 &&
                table.Items.Cast<ParameterProperty>().Any(value =>
                    value.InputLabel == resolved.Items("stack")[0].Text("display")),
                "The resolved stack rows collapsed under display scaling.");
            grid.ShowCall(partial);
            Require(table.Items.Cast<ParameterProperty>().Single(value => value.Name == "Call stack").InputLabel ==
                "Partial stack", "Changing calls retained a stale stack label.");
            host.Child = null;
        }

        // Both engines expose stack capture, and symbol folders remain readable in their own settings section.
        var hello = inspection.GetProperty("hello");
        var categories = hello.Items("categories").Select(CategoryInfo.FromJson).ToArray();
        var names = categories.ToDictionary(item => item.Id, item => item.Name);
        var catalog = hello.Items("catalog").Select(item => ApiInfo.FromJson(item, names)).ToArray();
        var settings = new CaptureSettings { Stacks = true, SymbolDirectories = [Environment.CurrentDirectory] };
        settings.Resolve(catalog, categories, ulong.Parse(hello.Text("allApis"), CultureInfo.InvariantCulture),
            ulong.Parse(hello.Text("allCategories"), CultureInfo.InvariantCulture));
        var dialog = new SettingsWindow(settings, catalog, categories, false);
        var tabs = Descendants(dialog).OfType<TabControl>().Single();
        var stacks = Descendants(dialog).OfType<CheckBox>().Single(value =>
            Equals(value.Content, "Capture available stacks"));
        var engine = Descendants(dialog).OfType<ComboBox>().Single(value =>
            System.Windows.Automation.AutomationProperties.GetName(value) == "Capture engine");
        foreach (var index in new[] { 0, 1 })
        {
            engine.SelectedIndex = index;
            Require(stacks.IsEnabled && stacks.IsChecked == true, "Changing engines disabled stack capture.");
        }
        tabs.SelectedIndex = 3;
        var content = (FrameworkElement)dialog.Content;
        dialog.Content = null;
        var settingsHost = new Border { Child = content };
        foreach (var scale in new[] { 1.0, 1.5 })
        {
            content.LayoutTransform = new ScaleTransform(scale, scale);
            var size = new Size(804 * scale, 500 * scale);
            settingsHost.Measure(size);
            settingsHost.Arrange(new Rect(size));
            settingsHost.UpdateLayout();
            var list = Descendants(content).OfType<ListBox>().Single();
            Require(list.ActualWidth >= 700 && list.ActualHeight >= 180 && list.Items.Count == 1,
                "The symbol-folder list was clipped or collapsed.");
        }
        settingsHost.Child = null;
        dialog.Close();
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        foreach (var child in LogicalTreeHelper.GetChildren(parent).OfType<DependencyObject>())
        {
            yield return child;
            foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }
}

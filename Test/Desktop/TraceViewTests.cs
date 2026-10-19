using Detourist.Desktop;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Threading;

namespace Detourist.Desktop.Tests;

public static partial class Program
{
    private static async Task TraceViews(MainWindow main)
    {
        // Verify the actual list, ordering, filters and inspector using a saved capture across multiple processes.
        var root = Path.Combine(Path.GetTempPath(), "Detourist-Views-" + Guid.NewGuid().ToString("N"));
        Require(Path.GetDirectoryName(Path.GetFullPath(root)) == Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(Path.GetTempPath())), "The view fixture is outside the temporary workspace.");
        Directory.CreateDirectory(root);
        await using var client = new CollectorClient();
        object? Field(string name) => typeof(MainWindow)
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(main) ?? typeof(MainWindow)
            .GetProperty(name, BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(main);
        object? Invoke(string name, params object?[] values) => typeof(MainWindow)
            .GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(main, values);
        var mainClient = (CollectorClient)Field("client")!;
        var completed = false;
        try
        {
            var database = Path.Combine(root, "trace.db");
            await client.Send("launch", new
            {
                startMinimized = true,
                database, executable = Path.Combine(AppContext.BaseDirectory, "DetouristTestTarget.exe"),
                arguments = "--child 40", bufferLimit = 16, followChildren = true, instructionEngine = false
            });
            var status = await Wait(client, value => value.Flag("finished"));
            var total = (int)status.Number("calls");
            Require(total > 1000 && status.Number("processes") == 2, "The view fixture is too small.");

            // The collector's complete page walk, newest first, is the reference for every list position.
            async Task<List<CallItem>> Reference(string path)
            {
                var calls = new List<CallItem>();
                var query = new Dictionary<string, object>
                {
                    ["database"] = path, ["limit"] = 1000, ["includeSummary"] = true
                };
                while (true)
                {
                    var batch = (await client.Send("page", query)).Items("calls").Select(CallItem.FromJson).ToArray();
                    calls.AddRange(batch);
                    if (batch.Length < 1000) return calls;
                    query["beforeTimestamp"] = batch[^1].Started;
                    query["beforeTarget"] = batch[^1].Target;
                    query["beforeCallId"] = batch[^1].Id;
                    query["includeMetadata"] = false;
                }
            }
            var all = await Reference(database);
            Require(all.Count == total, "The reference walk did not return every recorded call.");
            Require(all.Any(call => call.FailureSummary.Length > 0) &&
                all.Where(call => call.FailureSummary.Length > 0).All(call => call.IsFailure &&
                    call.ResultDisplay.Contains(call.FailureSummary, StringComparison.Ordinal)),
                "Failed rows did not explain their result in the call list.");
            Require(all.Any(call => call.Summary.Contains('…')) && !all.Any(call => call.Summary.Contains("â€")),
                "Collector text was not decoded as UTF-8.");
            await (Task)Invoke("LoadTrace", database)!;
            var grid = (DataGrid)main.FindName("CallsGrid");
            var list = (CallList)grid.ItemsSource;
            var results = (TextBlock)main.FindName("ResultsText");
            var search = (TextBox)main.FindName("ApiSearch");
            var order = (ComboBox)main.FindName("OrderCombo");
            var process = (ComboBox)main.FindName("ProcessCombo");
            var thread = (ComboBox)main.FindName("ThreadCombo");
            var failures = (CheckBox)main.FindName("FailuresCheck");
            var follow = (CheckBox)main.FindName("FollowCheck");
            var emptyTitle = (TextBlock)main.FindName("EmptyTitle");
            var title = (TextBlock)main.FindName("DetailTitle");

            async Task Until(Func<bool> predicate, string description = "The view did not finish loading")
            {
                var deadline = Stopwatch.StartNew();
                while (!predicate())
                {
                    if (deadline.Elapsed >= TimeSpan.FromSeconds(30))
                    {
                        var scroll = (ScrollViewer?)Field("callScroll");
                        throw new InvalidOperationException($"{description}: {results.Text}; " +
                            $"{grid.Items.Count} rows, offset {scroll?.VerticalOffset}, " +
                            $"viewport {scroll?.ViewportHeight}, selected {grid.SelectedIndex}, " +
                            $"view {Field("view")}/{Field("viewGeneration")}, opening {Field("opening")}, " +
                            $"filter pending {((DispatcherTimer)Field("searchTimer")!).IsEnabled}.");
                    }
                    Require(((Border)main.FindName("ErrorBanner")).Visibility != Visibility.Visible,
                        ((TextBlock)main.FindName("ErrorText")).Text);
                    await Task.Delay(25);
                }
            }

            // Rows are requested through the same list positions the grid displays.
            async Task<CallItem[]> Rows(int first, int count)
            {
                CallItem[] items = [];
                await Until(() => (items = [.. Enumerable.Range(first, count).Select(list.At)])
                    .All(item => item.Loaded));
                return items;
            }
            async Task Showing(IReadOnlyList<CallItem> expected, string description)
            {
                await Until(() => results.Text.EndsWith("total") && grid.Items.Count == expected.Count);
                foreach (var first in new[] { 0, Math.Max(0, expected.Count / 2 - 40),
                    Math.Max(0, expected.Count - 90) }.Distinct())
                {
                    var rows = await Rows(first, Math.Min(90, expected.Count - first));
                    Require(rows.Select(call => (call.Started, call.Target, call.Id)).SequenceEqual(
                        expected.Skip(first).Take(90).Select(call => (call.Started, call.Target, call.Id))),
                        $"{description} Rows from {first:N0} of {expected.Count:N0} differ from the recorded calls.");
                }
            }
            Task ClearSearch(string description)
            {
                search.Text = "";
                return Showing(all, description);
            }
            List<CallItem> Matching(Func<CallItem, bool> predicate) => all.Where(predicate).ToList();
            bool Named(CallItem call, string text) => call.Name.Contains(text, StringComparison.OrdinalIgnoreCase);

            await Showing(all, "The default view is not the complete trace, newest first.");
            Require(results.Text == $"{total:N0} shown · {total:N0} total" && order.SelectedIndex == 0 &&
                follow.Visibility == Visibility.Collapsed,
                "The saved trace reported the wrong counts, order or a live-only control.");
            Require(new[] { "PID / TID", "Function", "Arguments", "Result" }.All(header =>
                grid.Columns.Any(column => column.Header.ToString() == header &&
                    column.Visibility == Visibility.Visible)),
                "The default view omitted essential investigation columns.");
            Require(new[] { "Adjusted (µs)", "Elapsed (µs)", "PID", "TID", "Δ µs" }.All(header =>
                grid.Columns.First(column => column.Header.ToString() == header).Visibility == Visibility.Collapsed),
                "Secondary identity and duration columns were visible by default.");
            var first = (await Rows(0, 1))[0];
            Require(first.Time.Length == 12 && first.Time == all[0].Time && first.Pid != 0 && first.Tid != 0 &&
                first.Identity == $"{first.Pid} / {first.Tid}", "The call time or process/thread identity was lost.");
            static bool Trims(Style? style) => style is not null && (style.Setters.OfType<Setter>().Any(setter =>
                setter.Property == TextBlock.TextTrimmingProperty) || Trims(style.BasedOn));
            Require(grid.EnableRowVirtualization && VirtualizingPanel.GetIsVirtualizing(grid) &&
                grid.Columns.OfType<DataGridTextColumn>().All(column => Trims(column.ElementStyle)),
                "The call list disabled row virtualization or lets cell text clip without an ellipsis.");

            search.Text = "WriteFile";
            var writes = Matching(call => Named(call, "WriteFile"));
            Require(writes.Count > 200, "The filtered fixture is too small.");
            await Showing(writes, "The name filter did not select the matching calls.");
            Require(results.Text == $"{writes.Count:N0} matching · {total:N0} total",
                "The filtered view did not report its matching and recorded counts.");
            var position = writes.FindIndex(call => call.Name == "WriteFile" &&
                call.Summary.Contains("[16/2048 B]"));
            var selected = (await Rows(position, 1))[0];
            Require(selected.Function == "kernel32!WriteFile" && selected.Summary.Contains("lpBuffer=") &&
                selected.Summary.Contains("[16/2048 B]") && selected.Summary.Contains("lpNumberOfBytesWritten=") &&
                selected.Summary.Contains(" → 0x800"),
                $"The desktop did not display the module-qualified function and captured argument summary: " +
                $"{selected.Function}; {selected.Summary}.");
            grid.SelectedItem = selected;
            await Until(() => ((TextBox)main.FindName("DetailText")).Text.Contains("WriteFile"));
            Require(title.Text == "WriteFile" && grid.SelectedItem == selected,
                "Loading call details displaced the inspected call.");
            Require(((TextBlock)main.FindName("DetailSignature")).Text.Contains("lpBuffer") &&
                ((TextBlock)main.FindName("DetailContext")).Text.Contains("Caller 0x") &&
                ((TextBlock)main.FindName("DetailSummary")).Text.Contains("elapsed "),
                "The inspector omitted the resolved signature, call identity or duration.");
            await SaveView(main, "investigation-default");
            await SaveView(main, "investigation-narrow");
            grid.ScrollIntoView(list.At(writes.Count - 1));
            await main.Dispatcher.InvokeAsync(main.UpdateLayout, DispatcherPriority.ApplicationIdle);
            Require(grid.ItemContainerGenerator.ContainerFromItem(list.At(writes.Count - 1)) is DataGridRow,
                "The last matching call could not be scrolled into view.");

            // The inspected call stays selected while it matches and stays inspected after it is filtered out.
            search.Text = "File";
            await Showing(Matching(call => Named(call, "File")), "The wider filter did not select its calls.");
            await Until(() => grid.SelectedItem is CallItem kept && kept.Id == selected.Id &&
                kept.Target == selected.Target);
            Require(grid.ItemContainerGenerator.ContainerFromItem(grid.SelectedItem) is DataGridRow,
                "The inspected call was not kept in view after the filter changed.");
            search.Text = "ReadFile";
            var reads = Matching(call => Named(call, "ReadFile"));
            await Showing(reads, "The replacement filter did not select its calls.");
            Require(grid.SelectedItem is null && title.Text == "WriteFile",
                "A call outside the filter stayed selected or left the inspector.");

            // Rapid changes must publish the newest filter and order instead of a superseded request.
            search.Text = "Reg";
            order.SelectedIndex = 1;
            search.Text = "Create";
            order.SelectedIndex = 0;
            search.Text = "ReadFile";
            await Showing(reads, "Rapid filter changes published a superseded view.");

            // Threads are offered before a process is chosen and carry their process.
            Require(process.SelectedIndex == 0 && thread.Items.Count > 2,
                "Threads were unavailable until a process was selected.");
            var worker = thread.Items.Cast<FilterItem>().Last();
            thread.SelectedItem = worker;
            await Showing(Matching(call => Named(call, "ReadFile") && call.Tid == worker.Id &&
                call.Target == worker.Target), "The thread filter did not select that thread's calls.");
            var target = all[0].Target;
            process.SelectedItem = ((IEnumerable<FilterItem>)process.ItemsSource).First(item => item.Id == target);
            await Showing(Matching(call => Named(call, "ReadFile") && call.Target == target),
                "Choosing a process did not reset the thread and select that process.");
            Require(thread.SelectedIndex == 0 && thread.Items.Cast<FilterItem>().Skip(1).All(item =>
                item.Target == target), "The thread list was not limited to the chosen process.");

            // An unmatched filter, an invalid one, and clearing them each leave an accurate view.
            search.Text = "DetouristNoMatchingFunction";
            await Until(() => grid.Items.Count == 0 && emptyTitle.Text == "No matching calls");
            search.Text = "tid:unknown";
            await Until(() => emptyTitle.Text == "Filter not understood" &&
                ((TextBlock)main.FindName("EmptyMessage")).Text.Contains("tid"));
            ((Button)main.FindName("ClearSearchButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await Showing(Matching(call => call.Target == target), "Clearing the filter did not restore the process.");
            ((Button)main.FindName("ResetFilterButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await Showing(all, "Resetting display filters did not restore the recorded view.");
            Require(process.SelectedIndex == 0 && results.Text == $"{total:N0} shown · {total:N0} total" &&
                ((Button)main.FindName("ResetFilterButton")).Visibility == Visibility.Collapsed,
                "Resetting display filters left stale choices or counts.");

            // Filter terms exclude, qualify by module, anchor with wildcards and combine alternatives.
            foreach (var (text, predicate) in new (string, Func<CallItem, bool>)[]
            {
                ("-WriteFile", call => !Named(call, "WriteFile")),
                ("kernel32!", call => call.Module.Contains("kernel32", StringComparison.OrdinalIgnoreCase)),
                ("ntdll!Nt*File", call => call.Module.Contains("ntdll", StringComparison.OrdinalIgnoreCase) &&
                    call.Name.StartsWith("Nt", StringComparison.OrdinalIgnoreCase) &&
                    call.Name.EndsWith("File", StringComparison.OrdinalIgnoreCase)),
                ("=WriteFile|=ReadFile", call => call.Name is "WriteFile" or "ReadFile"),
                ($"tid:{worker.Id} -kernel32!", call => call.Tid == worker.Id &&
                    !call.Module.Contains("kernel32", StringComparison.OrdinalIgnoreCase)),
                ("depth:0", call => call.Depth == 0)
            })
            {
                search.Text = text;
                await Showing(Matching(predicate), $"The filter '{text}' selected the wrong calls.");
            }
            search.Text = "";
            failures.IsChecked = true;
            await Showing(Matching(call => call.IsFailure), "The failures filter selected the wrong calls.");
            failures.IsChecked = false;

            // The same calls read from the start of the trace, or ranked by duration.
            order.SelectedIndex = 1;
            await Showing(Enumerable.Reverse(all).ToList(), "Oldest-first order did not begin at the first call.");
            order.SelectedIndex = 2;
            await Until(() => results.Text.Contains("slowest"));
            var slowest = await Rows(0, 60);
            Require(slowest.All(call => call.DurationUs >= 0) && slowest.Zip(slowest.Skip(1)).All(pair =>
                pair.First.DurationUs >= pair.Second.DurationUs) &&
                slowest[0].DurationUs == all.Max(call => call.DurationUs),
                "Slowest-first order did not rank returned calls by duration.");
            order.SelectedIndex = 0;
            await Showing(all, "Returning to newest-first order did not restore the recorded view.");

            // Finding marks matches in place and steps through them without filtering the list.
            async Task<long> Count(string filter)
            {
                var state = await client.Send("view", new { database, filter });
                while (!state.Flag("complete"))
                    state = await client.Send("view", new { view = state.Number("view"), includeMetadata = false });
                await client.Send("release", new { view = state.Number("view") });
                return state.Number("count");
            }
            var click = new RoutedEventArgs(MenuItem.ClickEvent);
            var captureSettings = (CaptureSettings)Field("settings")!;
            // Restoring thread context removes hiding filters and reselects the call in chronological order.
            var context = writes.First(call => call.Name == "WriteFile");
            search.Text = "=WriteFile";
            failures.IsChecked = true;
            order.SelectedIndex = 2;
            await Until(() => Field("viewComplete") is true && (int)Field("opening")! == 0);
            Action(context, "Show Thread Around This Call").RaiseEvent(click);
            await Until(() => grid.SelectedItem is CallItem kept && kept.Target == context.Target &&
                kept.Id == context.Id && Field("viewComplete") is true && (int)Field("opening")! == 0);
            Require(search.Text.Length == 0 && failures.IsChecked == false && order.SelectedIndex != 2 &&
                thread.SelectedItem is FilterItem chosenThread && chosenThread.Id == context.Tid &&
                chosenThread.Target == context.Target && grid.ItemContainerGenerator.ContainerFromItem(
                    grid.SelectedItem) is DataGridRow,
                "Thread context did not clear filters and keep the anchor call visible.");
            await Showing(Matching(call => call.Target == context.Target && call.Tid == context.Tid),
                "Thread context included calls from a different target or thread.");
            Require(Menu(context).Items.OfType<MenuItem>().All(item =>
                !item.Header.ToString()!.StartsWith("Break on ", StringComparison.Ordinal)),
                "Live breakpoint actions appeared on a saved trace.");
            Invoke("ClearDisplayFilters", main, click);
            await Showing(all, "Leaving thread context did not restore all calls.");
            var findText = (TextBox)main.FindName("FindText");
            var findStatus = (TextBlock)main.FindName("FindStatus");
            Invoke("OpenFind");
            findText.Text = "WriteFile";
            await Until(() => findStatus.Text == $"{writes.Count:N0} matches");
            var firstWrite = all.IndexOf(writes[0]);
            await Until(() => list.At(firstWrite).MarkSlot == 1);
            var nearby = await Rows(Math.Max(0, firstWrite - 20), 60);
            Require(grid.Items.Count == total && nearby.All(call => (call.MarkSlot == 1) == Named(call, "WriteFile")),
                "Finding filtered the list or marked the wrong calls.");
            grid.SelectedItem = (await Rows(0, 1))[0];
            await Until(() => title.Text == all[0].Name);
            var nextWrite = writes[all.IndexOf(writes[0]) == 0 ? 1 : 0];
            ((Button)main.FindName("FindNextButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await Until(() => grid.SelectedItem is CallItem found && found.Id == nextWrite.Id &&
                found.Target == nextWrite.Target && findStatus.Text ==
                $"{writes.IndexOf(nextWrite) + 1:N0} of {writes.Count:N0}");
            var previousWrite = writes[(writes.IndexOf(nextWrite) + writes.Count - 1) % writes.Count];
            ((Button)main.FindName("FindPreviousButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await Until(() => grid.SelectedItem is CallItem found && found.Id == previousWrite.Id &&
                found.Target == previousWrite.Target);
            await SaveView(main, "investigation-find");
            findText.Text = "tid:x";
            await Until(() => findStatus.Text.StartsWith("Filter", StringComparison.Ordinal));
            Require(grid.Items.Count == total, "Find text that is not understood disturbed the list.");
            findText.Text = "WriteFile";
            await Until(() => findStatus.Text == $"{writes.Count:N0} matches" && list.At(firstWrite).MarkSlot == 1);

            // A highlight rule keeps its own color beside the find text until it is removed.
            var firstRead = all.IndexOf(reads.First(call => call.Name == "ReadFile"));
            Action(all[firstRead], "Highlight API:").RaiseEvent(click);
            await Until(() => list.At(firstRead).MarkSlot == 2 && list.At(firstWrite).MarkSlot == 1);
            Require(captureSettings.Highlights.SequenceEqual(["=ReadFile"]), "The highlight rule was not kept.");
            Action(all[firstRead], "Remove Highlight:").RaiseEvent(click);
            await Until(() => list.At(firstRead).MarkSlot == 0);
            Invoke("CloseFind", main, click);
            await Until(() => list.At(firstWrite).MarkSlot == 0);
            Require(captureSettings.Highlights.Length == 0 && grid.Items.Count == total,
                "Closing find left marks behind or changed the list.");

            // A call's menu follows its nesting, its place in time and its result.
            var parents = all.ToDictionary(call => (call.Target, call.Id));
            var child = all.First(call => call.Parent != 0 && parents.ContainsKey((call.Target, call.Parent)));
            Action(child, "Go to Parent Call").RaiseEvent(click);
            await Until(() => grid.SelectedItem is CallItem parent && parent.Id == child.Parent &&
                parent.Target == child.Target);
            var nested = await Count($"under:{child.Target}.{child.Parent}");
            Action((CallItem)grid.SelectedItem, "Show Nested Calls").RaiseEvent(click);
            await Until(() => search.Text == $"under:{child.Target}.{child.Parent}" &&
                results.Text == $"{nested:N0} matching · {total:N0} total");
            Require(nested > 1 && (await Rows((int)nested - 1, 1))[0].Id == child.Parent,
                "Nested calls did not begin with the call that made them.");
            await ClearSearch("Clearing the nesting filter did not restore the recorded view.");
            var anchor = all[total / 2];
            Action(anchor, "Show Calls From Here").RaiseEvent(click);
            await Until(() => search.Text.StartsWith("after:", StringComparison.Ordinal) &&
                results.Text.Contains("matching"));
            Require(grid.Items.Count > total / 2 && grid.Items.Count <= total / 2 + 30 &&
                (await Rows(total / 2, 1))[0].Id == anchor.Id, "The time filter did not start at the chosen call.");
            Action(anchor, "Set Time Reference").RaiseEvent(click);
            var elapsed = grid.Columns.First(column => column.Header.ToString() == "Elapsed (s)");
            Require(elapsed.Visibility == Visibility.Visible && (await Rows(total / 2, 1))[0].Elapsed == "0.000000" &&
                (await Rows(0, 1))[0].ElapsedSeconds > 0, "Elapsed time was not measured from the reference call.");
            Action(anchor, "Clear Time Reference").RaiseEvent(click);
            Require(CallItem.Reference == 0 && (await Rows(0, 1))[0].ElapsedSeconds > anchor.ElapsedSeconds,
                "Clearing the time reference did not return to the capture start.");
            elapsed.Visibility = Visibility.Collapsed;
            await ClearSearch("Clearing the time filter did not restore the recorded view.");
            var handle = all.First(call => call.Name == "CreateFileW" && !call.IsFailure && call.DurationUs >= 0);
            Action(handle, "Follow Result:").RaiseEvent(click);
            await Until(() => search.Text == "value:" + handle.Result && results.Text.Contains("matching"));
            Require(grid.Items.Count > 1 && grid.Items.Count == await Count("value:" + handle.Result),
                "Following a result did not list the calls that used it.");

            // Callers resolve to the images recorded with the capture and narrow the list to the application's calls.
            await ClearSearch("Clearing the value filter did not restore the recorded view.");
            var fromApp = (CheckBox)main.FindName("FromAppCheck");
            var own = await Count("from:app");
            Require(fromApp.IsEnabled && own > 0 && own < total &&
                (await Rows(0, 90)).Any(call => call.Caller.Contains("+0x", StringComparison.Ordinal)),
                "Callers were not attributed to recorded modules.");
            fromApp.IsChecked = true;
            await Until(() => search.Text == "from:app" && results.Text == $"{own:N0} matching · {total:N0} total");
            search.Text = "";
            await Until(() => fromApp.IsChecked == false);
            await Showing(all, "Clearing the caller filter did not restore the recorded view.");

            // The summary totals the listed calls per API and narrows the list to one of them.
            var summaryCheck = (CheckBox)main.FindName("SummaryCheck");
            var summaryGrid = (DataGrid)main.FindName("SummaryGrid");
            summaryCheck.IsChecked = true;
            await Until(() => results.Text.EndsWith($"{total:N0} calls", StringComparison.Ordinal));
            var apis = summaryGrid.Items.Cast<SummaryItem>().ToList();
            Require(apis.Sum(api => api.Calls) == total && apis.Sum(api => api.Failed) == all.Count(call =>
                call.IsFailure) && apis.Zip(apis.Skip(1)).All(pair => pair.First.Calls >= pair.Second.Calls) &&
                apis.Where(api => api.Name == "WriteFile").Sum(api => api.Calls) == all.Count(call =>
                    call.Name == "WriteFile") && grid.Visibility == Visibility.Collapsed,
                "The summary did not total the listed calls by API.");
            await SaveView(main, "investigation-summary");
            var chosen = apis.First(api => api.Name == "WriteFile");
            summaryGrid.SelectedItem = chosen;
            Invoke("ShowSummaryApi", false);
            await Showing(Matching(call => call.Name == "WriteFile" && call.Module == chosen.Module),
                "Narrowing from the summary selected the wrong calls.");
            Require(summaryCheck.IsChecked == false && grid.Visibility == Visibility.Visible &&
                search.Text == $"{Path.GetFileNameWithoutExtension(chosen.Module)}!=WriteFile",
                "Narrowing from the summary did not return to the calls.");

            // Exports write every listed call in list order.
            search.Text = "WriteFile";
            await Showing(writes, "The export fixture did not list its calls.");
            await (Task)Invoke("Export", Path.Combine(root, "calls.csv"))!;
            var exported = File.ReadAllLines(Path.Combine(root, "calls.csv"));
            Require(exported.Length == writes.Count + 1 && exported[0].StartsWith("Time,Elapsed (s),PID") &&
                exported[1].Contains($",{writes[0].Id},") && exported[1].Contains($",{writes[0].Name},"),
                "The CSV export lost calls or its columns.");
            await (Task)Invoke("Export", Path.Combine(root, "calls.json"))!;
            using (var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "calls.json"))))
                Require(document.RootElement.GetArrayLength() == writes.Count &&
                    document.RootElement[0].Number("id") == writes[0].Id &&
                    document.RootElement[writes.Count - 1].Number("id") == writes[^1].Id,
                    "The JSON export lost calls or their order.");

            // Exported trace text stays literal in spreadsheets, including quoted formulas and leading whitespace.
            var formulaDatabase = Path.Combine(root, "formulas.db");
            WriteTrace(database, $"VACUUM INTO '{formulaDatabase.Replace("'", "''")}';");
            WriteTrace(formulaDatabase, "UPDATE apis SET module='@SUM(1,2)',name=' \t=1+1';");
            await (Task)Invoke("LoadTrace", formulaDatabase)!;
            await Showing(await Reference(formulaDatabase), "The formula trace did not load.");
            await (Task)Invoke("Export", Path.Combine(root, "formulas.csv"))!;
            var formulaRows = File.ReadAllLines(Path.Combine(root, "formulas.csv"));
            Require(formulaRows.Length == all.Count + 1 && formulaRows.Skip(1).All(line =>
                line.Contains(",\"'@SUM(1,2)\",' \t=1+1,")), "CSV trace text can become a spreadsheet formula.");
            await (Task)Invoke("LoadTrace", database)!;
            search.Text = "WriteFile";
            await Showing(writes, "The original trace did not reload after export.");

            // Two calls are compared line by line.
            await (Task)Invoke("Compare", writes[0], writes[1])!;
            var comparison = Application.Current.Windows.OfType<CompareWindow>().Single();
            await main.Dispatcher.InvokeAsync(comparison.UpdateLayout, DispatcherPriority.ApplicationIdle);
            var compared = Elements(comparison).OfType<DataGrid>().Single().Items.Cast<CompareLine>().ToList();
            Require(compared.Count > 3 && compared.Any(line => line.Differs) && compared.Any(line => !line.Differs),
                "The comparison did not align two calls of the same API.");
            comparison.Close();

            // Completion replaces the term at the caret; captures are named inside the chosen trace folder.
            search.Text = "Sleep -Writ";
            search.CaretIndex = search.Text.Length;
            Invoke("AcceptSuggestion", new Suggestion("WriteFile", ""));
            Require(search.Text == "Sleep -WriteFile", $"Completion produced '{search.Text}'.");
            await ClearSearch("Clearing the completed filter did not restore the recorded view.");
            captureSettings.TraceFolder = root;
            var named = (string)Invoke("NewDatabase", @"C:\Tools\Sample App.exe")!;
            Require(Path.GetDirectoryName(named) == root && Path.GetFileName(named).StartsWith("Sample App-") &&
                named.EndsWith(".db") && captureSettings.RecentTraces.FirstOrDefault() == database &&
                captureSettings.RecentFilters.Contains("WriteFile"),
                "Captures were not named in the trace folder, or recent traces and filters were not kept.");
            captureSettings.TraceFolder = "";

            // The timeline covers the capture and moves the list to a chosen moment.
            var strip = (CallTimeline)main.FindName("Timeline");
            await Until(() => strip.HasData &&
                ((Border)main.FindName("TimelinePanel")).Visibility == Visibility.Visible);
            var moment = all[total * 2 / 3].Started;
            var arrival = all.FindIndex(call => call.Started <= moment);
            bool Displayed(int index) => Field("callScroll") is ScrollViewer scroll &&
                index >= scroll.VerticalOffset && index < scroll.VerticalOffset + scroll.ViewportHeight &&
                grid.ItemContainerGenerator.ContainerFromItem(list.At(index)) is DataGridRow;
            async Task Seek(long clock, int index)
            {
                var origin = index < list.Count / 2 ? list.Count - 1 : 0;
                grid.ScrollIntoView(list.At(origin));
                await Until(() => Displayed(origin));
                await (Task)Invoke("SeekTime", clock)!;
                await Until(() => Displayed(index), $"The timeline did not display row {index}");
            }
            await Seek(moment, arrival);

            // Even a short viewport must display the chosen row rather than only the rows preceding it.
            var gridHeight = grid.Height;
            try
            {
                grid.Height = 64;
                await main.Dispatcher.InvokeAsync(main.UpdateLayout, DispatcherPriority.ApplicationIdle);
                await (Task)Invoke("SeekTime", moment)!;
                await main.Dispatcher.InvokeAsync(main.UpdateLayout, DispatcherPriority.ApplicationIdle);
                var scroll = (ScrollViewer)Field("callScroll")!;
                Require(Displayed(arrival),
                    $"A short timeline viewport hid row {arrival}: offset {scroll.VerticalOffset}, " +
                    $"viewport {scroll.ViewportHeight}.");
            }
            finally
            {
                grid.Height = gridHeight;
            }
            await Seek(all[^1].Started - 1, total - 1);
            await Seek(all[0].Started + 1, 0);

            // Navigation waits for a filter/order change that is already rebuilding the displayed view.
            foreach (var direction in new[] { 1, 0 })
            {
                search.Text = "WriteFile";
                order.SelectedIndex = direction;
                var expected = direction == 1 ? Enumerable.Reverse(writes).ToList() : writes;
                var index = expected.Count * 2 / 3;
                await (Task)Invoke("SeekTime", expected[index].Started)!;
                await Showing(expected, "A timeline seek interrupted the pending filter/order change.");
                await Until(() => Displayed(index),
                    $"A timeline seek during a view refresh did not display row {index}");
            }
            await ClearSearch("Clearing the timeline filter did not restore the trace.");

            // Restoring the inspected call after indexing must not undo navigation requested as rows arrive.
            var retained = (await Rows(0, 1))[0];
            grid.SelectedItem = retained;
            var ascending = Enumerable.Reverse(all).ToList();
            var destination = ascending.Count / 2;
            Task? publishedSeek = null;
            void SeekPublished(object? sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
            {
                if (list.Count == total && publishedSeek is null)
                    publishedSeek = (Task)Invoke("SeekTime", ascending[destination].Started)!;
            }
            list.CollectionChanged += SeekPublished;
            try
            {
                order.SelectedIndex = 1;
                await Until(() => publishedSeek is not null);
                await publishedSeek!;
                await Showing(ascending, "Navigating during selection restoration lost the ordered view.");
                await Until(() => grid.SelectedItem is CallItem kept && kept.Id == retained.Id &&
                    kept.Target == retained.Target);
                await main.Dispatcher.InvokeAsync(main.UpdateLayout, DispatcherPriority.ApplicationIdle);
                await Until(() => Displayed(destination),
                    "Selection restoration discarded timeline navigation after indexing");
            }
            finally
            {
                list.CollectionChanged -= SeekPublished;
            }
            order.SelectedIndex = 0;
            await Showing(all, "Returning from the timeline selection test did not restore the trace.");

            // Applying an order consumes the typed filter so its delayed refresh cannot undo a later seek.
            var debounce = (DispatcherTimer)Field("searchTimer")!;
            var interval = debounce.Interval;
            debounce.Interval = TimeSpan.FromSeconds(2);
            try
            {
                search.Text = "WriteFile";
                order.SelectedIndex = 1;
                var ascendingWrites = Enumerable.Reverse(writes).ToList();
                await Showing(ascendingWrites, "Filter and order changes did not apply together.");
                var clock = ascendingWrites[ascendingWrites.Count / 2].Started;
                var index = ascendingWrites.FindIndex(call => call.Started >= clock);
                await Seek(clock, index);
                await Task.Delay(debounce.Interval + TimeSpan.FromMilliseconds(200));
                Require(Displayed(index),
                    "A delayed filter refresh discarded timeline navigation after an order change.");

                // A seek applies pending filter text before locating its row in the filtered view.
                search.Text = "ReadFile";
                var ascendingReads = Enumerable.Reverse(reads).ToList();
                clock = ascendingReads[ascendingReads.Count * 2 / 3].Started;
                index = ascendingReads.FindIndex(call => call.Started >= clock);
                await (Task)Invoke("SeekTime", clock)!;
                await Showing(ascendingReads, "The timeline did not apply the pending filter.");
                await Until(() => Displayed(index), $"The filtered timeline did not display row {index}");
            }
            finally
            {
                debounce.Interval = interval;
            }
            search.Text = "";
            order.SelectedIndex = 0;
            await Showing(all, "Clearing the timeline filter did not restore the trace.");
            await Seek(moment, arrival);

            // Enumeration arguments are named from their signatures.
            var typed = new[] { "NtQueryInformationProcess", "NtQueryInformationFile", "NtSetInformationFile" }
                .SelectMany(name => (ApiMetadata.Function(name, "ntdll.dll")?.Parameters ?? []).Select(parameter =>
                    (Name: name, Parameter: parameter.Name, Type: ParameterType.Infer(parameter.Type))))
                .First(entry => entry.Type.Kind == "Enum" && entry.Type.Choices.Length > 1);
            var value = typed.Type.Choices[1].Value;
            var label = typed.Type.Choices.First(choice => choice.Value == value).Name;
            Require(ArgumentText.Decode(typed.Name, "ntdll.dll",
                $"Handle=0x4, {typed.Parameter}=0x{value:X}, Length=0x10") ==
                $"Handle=0x4, {typed.Parameter}={label}, Length=0x10",
                "An enumeration argument kept its numeric value.");
            Console.WriteLine($"List tools: find, highlights, navigation, {own:N0} application calls, " +
                $"{apis.Count:N0} summarized APIs, exports, comparison and timeline passed.");

            // The list header fits at a narrow window size and increased content scaling.
            main.Width = 1100;
            ((FrameworkElement)main.Content).LayoutTransform = new ScaleTransform(1.5, 1.5);
            await main.Dispatcher.InvokeAsync(main.UpdateLayout, DispatcherPriority.ApplicationIdle);
            var header = (FrameworkElement)VisualTreeHelper.GetParent(order);
            await SaveView(main, "investigation-scaled");
            Require(order.ActualWidth >= order.DesiredSize.Width - order.Margin.Left - order.Margin.Right - 1 &&
                results.TranslatePoint(new Point(results.ActualWidth, 0), header).X <=
                order.TranslatePoint(new Point(0, 0), header).X + 1,
                $"The scaled list header clips its order selector or overlaps the call count: " +
                $"selector {order.ActualWidth:F1}/{order.DesiredSize.Width:F1}, " +
                $"count end {results.TranslatePoint(new Point(results.ActualWidth, 0), header).X:F1}, " +
                $"selector start {order.TranslatePoint(new Point(0, 0), header).X:F1}.");
            Console.WriteLine($"Trace view: {total:N0} calls; windows, filters, orders, selection and layout passed.");

            // Capture and display choices return when the settings are loaded again.
            var disabled = captureSettings.Categories.First();
            captureSettings.CategoryMask &= ~disabled.Key;
            captureSettings.ExcludedApis = ["GetTickCount64"];
            captureSettings.Save();
            var restored = CaptureSettings.Load();
            Require(restored.ExcludedApis.SequenceEqual(["GetTickCount64"]) &&
                restored.DisabledCategories.SequenceEqual([disabled.Value]),
                "Saved capture settings did not return when loaded.");
            captureSettings.CategoryMask |= disabled.Key;
            captureSettings.ExcludedApis = [];
            captureSettings.Save();

            // Follow a paced live capture, then hold the list still while a call is inspected.
            database = Path.Combine(root, "live.db");
            Invoke("ResetSession", database, "Live view verification");
            var hello = await client.Send("hello");
            captureSettings.ApiMask = ulong.Parse(hello.Items("catalog").First(api =>
                api.Text("name") == "WriteFile").Text("mask")) | ulong.Parse(hello.Items("catalog").First(api =>
                api.Text("name") == "GetFileAttributesW").Text("mask"));
            await mainClient.Send("launch", new
            {
                startMinimized = true,
                database, executable = Path.Combine(AppContext.BaseDirectory, "DetouristTestTarget.exe"),
                arguments = "--paced 1200", bufferLimit = 16, followChildren = false, instructionEngine = false,
                apiMask = captureSettings.ApiMask.ToString()
            });
            var live = typeof(MainWindow).GetField("live", BindingFlags.Instance | BindingFlags.NonPublic)!;
            live.SetValue(main, true);
            Invoke("UpdateActions");
            await Until(() => grid.Items.Count > 0 && results.Text.EndsWith("total"));
            Require(follow.Visibility == Visibility.Visible && follow.IsChecked == true,
                "A live capture did not offer following or started paused.");
            var followed = grid.Items.Count;
            await Until(() => grid.Items.Count > followed);
            var newest = await Rows(0, 1);
            await Until(() => list.At(0).Loaded && list.At(0).Id != newest[0].Id);
            CallItem inspected;
            do
            {
                // Following replaces the newest rows; select one from the list as it is now.
                inspected = (await Rows(0, 40)).First(call => call.Name == "WriteFile");
                grid.SelectedItem = inspected;
            }
            while (grid.SelectedItem != inspected);
            await Until(() => title.Text == "WriteFile");
            var held = grid.Items.Count;
            Require(follow.IsChecked == false, "Selecting a call did not pause following.");
            await Task.Delay(700);
            Require((bool)live.GetValue(main)! && grid.Items.Count == held && grid.SelectedItem == inspected &&
                list.IndexOf(inspected) >= 0, "A paused newest-first list moved while a call was inspected.");

            // Slowest-first holds its ranked snapshot during live capture while total call counts continue advancing.
            order.SelectedIndex = 2;
            await Until(() => grid.Items.Count >= held && grid.SelectedItem is CallItem slowestKept &&
                slowestKept.Id == inspected.Id && results.Text.EndsWith("total"));
            var slowestCount = grid.Items.Count;
            var slowestTop = (await Rows(0, 1))[0].Id;
            var slowestStatus = results.Text;
            await Until(() => results.Text != slowestStatus && (bool)live.GetValue(main)!);
            Require(grid.Items.Count == slowestCount && list.At(0).Id == slowestTop &&
                grid.SelectedItem is CallItem slowestStill && slowestStill.Id == inspected.Id,
                "A live slowest-first view shifted its ranked rows while calls were arriving.");

            // Chronological order keeps growing at its end without disturbing the inspected call.
            order.SelectedIndex = 1;
            await Until(() => grid.Items.Count > slowestCount && grid.SelectedItem is CallItem kept &&
                kept.Id == inspected.Id && results.Text.EndsWith("total"));
            var growing = grid.Items.Count;
            await Until(() => grid.Items.Count > growing && (bool)live.GetValue(main)!);
            Require(grid.SelectedItem is CallItem still && still.Id == inspected.Id && title.Text == inspected.Name,
                "Incoming calls displaced the inspected call or stopped arriving after selection.");
            await SaveView(main, "investigation-live-scaled");
            Console.WriteLine($"Live view: followed {followed:N0} calls, held {held:N0} while inspecting, " +
                $"then grew to {grid.Items.Count:N0} in chronological order.");
            inspected = (CallItem)grid.SelectedItem;

            // The real context actions filter the list or stop future capture while preserving history.
            ContextMenu Menu(CallItem call) => (ContextMenu)Invoke("CreateCallMenu", call)!;
            MenuItem Action(CallItem call, string header) => Menu(call).Items.OfType<MenuItem>()
                .Single(item => item.Header.ToString()!.StartsWith(header, StringComparison.Ordinal));
            bool Busy() => Field("busy") is true;
            Action(inspected, "Show Only API:").RaiseEvent(new RoutedEventArgs(MenuItem.ClickEvent));
            await Until(() => search.Text == "=WriteFile" && results.Text.Contains("matching"));
            Action(inspected, "Show Only Thread").RaiseEvent(new RoutedEventArgs(MenuItem.ClickEvent));
            await Until(() => thread.SelectedItem is FilterItem chosen && chosen.Id == inspected.Tid);
            ((Button)main.FindName("ResetFilterButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await Until(() => search.Text.Length == 0 && results.Text.Contains("shown"));

            // A real syscall row exposes a separate exclusion while its API action still covers every layer.
            var nativeMenuPath = Environment.GetEnvironmentVariable("DETOURIST_NATIVE_MENU_CAPTURE");
            if (!string.IsNullOrEmpty(nativeMenuPath))
            {
                using var nativeRows = JsonDocument.Parse(File.ReadAllText(nativeMenuPath));
                var syscall = CallItem.FromJson(nativeRows.RootElement.EnumerateArray()
                    .First(item => item.Text("name") == "NtUserGetKeyboardState [syscall]"));
                var native = CallItem.FromJson(nativeRows.RootElement.EnumerateArray()
                    .First(item => item.Text("name") == "NtUserGetKeyboardState"));
                Require(Menu(native).Items.OfType<MenuItem>().All(item =>
                    item.Header.ToString() != "Exclude Syscall Events"),
                    "The syscall action appeared on an ordinary API row.");
                var syscallAction = Action(syscall, "Exclude Syscall Events");
                Require(syscallAction.IsEnabled, "The syscall exclusion was unavailable.");
                syscallAction.RaiseEvent(new RoutedEventArgs(MenuItem.ClickEvent));
                await Until(() => captureSettings.ExcludedApis.Contains(syscall.Name) && !Busy());
                Require(!captureSettings.ExcludedApis.Contains(native.Name) &&
                    Action(syscall, "Exclude API:").IsEnabled && !Action(syscall, "Exclude Syscall Events").IsEnabled,
                    "The syscall action also excluded the native API or stayed enabled.");
                captureSettings.ExcludedApis = [];
                await mainClient.Send("filters", new
                {
                    apiMask = captureSettings.ApiMask.ToString(), excludedApis = captureSettings.ExcludedApis
                });
                Console.WriteLine("Separate syscall and whole-API context exclusions passed.");
            }

            Action(inspected, "Exclude API:").RaiseEvent(new RoutedEventArgs(MenuItem.ClickEvent));
            await Until(() => captureSettings.ExcludedApis.Contains(inspected.Name) && !Busy());
            Require(((Button)main.FindName("CaptureFiltersButton")).Visibility == Visibility.Visible &&
                ((TextBlock)main.FindName("CaptureFiltersText")).Text.Contains("1 API excluded"),
                "An active capture exclusion was not shown on the main window.");
            await Task.Delay(250);
            var frozenWrites = await mainClient.Send("page", new { database, api = "WriteFile", limit = 1 });
            var latestWrite = frozenWrites.Items("calls")[0].Number("id");
            await Task.Delay(350);
            var futureWrites = await mainClient.Send("page", new { database, api = "WriteFile", limit = 1 });
            Require(futureWrites.Items("calls")[0].Number("id") == latestWrite &&
                !Action(inspected, "Exclude API:").IsEnabled,
                "The API context action continued recording new calls or removed captured history.");
            Action(inspected, "Exclude Category:").RaiseEvent(new RoutedEventArgs(MenuItem.ClickEvent));
            await Until(() => (captureSettings.CategoryMask & (1UL << inspected.CategoryId)) == 0);
            Require(!Action(inspected, "Exclude Category:").IsEnabled,
                "The category context action did not update the capture mask.");
            await Task.Delay(250);
            var frozenAttributes = await mainClient.Send("page", new
            {
                database, api = "GetFileAttributesW", limit = 1
            });
            var latestAttribute = frozenAttributes.Items("calls")[0].Number("id");
            await Task.Delay(350);
            var futureAttributes = await mainClient.Send("page", new
            {
                database, api = "GetFileAttributesW", limit = 1
            });
            Require(futureAttributes.Items("calls")[0].Number("id") == latestAttribute &&
                !(await mainClient.Send("status")).Flag("finished"),
                "The category context action continued recording calls or discarded captured history.");
            captureSettings.ExcludedApis = [];
            captureSettings.CategoryMask = ulong.Parse(hello.Text("allCategories"));
            await mainClient.Send("filters", new
            {
                apiMask = captureSettings.ApiMask.ToString(), categoryMask = captureSettings.CategoryMask.ToString(),
                excludedApis = captureSettings.ExcludedApis
            });
            await Task.Delay(350);
            var resumedWrites = await mainClient.Send("page", new { database, api = "WriteFile", limit = 1 });
            Require(resumedWrites.Items("calls")[0].Number("id") > latestWrite,
                "Clearing capture exclusions did not resume the selected API.");
            Console.WriteLine("API and category context exclusions preserved history; exclusions were cleared live.");
            await Until(() => (bool)live.GetValue(main)! == false &&
                ((TextBlock)main.FindName("StateText")).Text == "CAPTURE ENDED" && results.Text.EndsWith("total"));
            status = await mainClient.Send("status");
            Require(status.Number("calls") > 1000, "The live fixture is too small.");
            all = await Reference(database);
            await Showing(Enumerable.Reverse(all).ToList(), "The finished capture did not show every final call.");
            Require(follow.Visibility == Visibility.Collapsed && all.Count == status.Number("calls"),
                "The finished capture kept a live-only control or lost calls.");
            Console.WriteLine($"Live view: {grid.Items.Count:N0} final calls match the recorded trace.");
            completed = true;
        }
        finally
        {
            await mainClient.DisposeAsync();
            await client.DisposeAsync();
            if (completed) Directory.Delete(root, true);
            else Console.WriteLine("Retained view fixture: " + root);
        }
    }
}

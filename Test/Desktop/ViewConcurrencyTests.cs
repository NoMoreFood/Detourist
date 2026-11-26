using Detourist.Desktop;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;

namespace Detourist.Desktop.Tests;

public static partial class Program
{
    [DllImport("DetouristSqlite.dll", EntryPoint = "sqlite3_open_v2", CallingConvention = CallingConvention.Cdecl)]
    private static extern int OpenTraceSql([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out nint database,
        int flags, nint vfs);
    [DllImport("DetouristSqlite.dll", EntryPoint = "sqlite3_exec", CallingConvention = CallingConvention.Cdecl)]
    private static extern int ExecuteTraceSql(nint database, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql,
        nint callback, nint context, out nint error);
    [DllImport("DetouristSqlite.dll", EntryPoint = "sqlite3_close_v2", CallingConvention = CallingConvention.Cdecl)]
    private static extern int CloseTraceSql(nint database);
    [DllImport("DetouristSqlite.dll", EntryPoint = "sqlite3_free", CallingConvention = CallingConvention.Cdecl)]
    private static extern void FreeTraceSql(nint memory);

    private static void WriteTrace(string path, string sql)
    {
        Require(OpenTraceSql(path, out var database, 2, 0) == 0, "Cannot open the live trace fixture.");
        try
        {
            var result = ExecuteTraceSql(database, sql, 0, 0, out var error);
            var message = Marshal.PtrToStringUTF8(error);
            FreeTraceSql(error);
            Require(result == 0, "Cannot update the live trace fixture: " + message);
        }
        finally { CloseTraceSql(database); }
    }

    private static async Task ViewConcurrency()
    {
        var directory = Path.Combine(Path.GetTempPath(), "Detourist-ViewOwner-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var database = Path.Combine(directory, "live.db");
        var slowDatabase = Path.Combine(directory, "slow.db");
        try
        {
            await using var client = new CollectorClient();
            var api = (await client.Send("hello")).Items("catalog").Single(item => item.Text("name") == "WriteFile");
            await client.Send("launch", new
            {
                database, executable = Path.Combine(AppContext.BaseDirectory, "DetouristTestTarget.exe"),
                arguments = "--leaf 1", apiMask = api.Text("mask"), followChildren = false, startMinimized = true
            });
            await Wait(client, status => status.Flag("finished"));
            WriteTrace(database, $"DELETE FROM calls; WITH RECURSIVE ids(n) AS " +
                "(VALUES(1) UNION ALL SELECT n+1 FROM ids WHERE n<1500) " +
                "INSERT INTO calls(target,id,tid,api,started,ended,parent,depth,caller,result,error,flags,arguments) " +
                $"SELECT 1,n,1,{api.Number("id")},n*10,n*10+2,0,0,0,0,0,0,zeroblob(40) FROM ids; " +
                "UPDATE session SET total_calls=1500;");
            WriteTrace(database, $"VACUUM INTO '{slowDatabase.Replace("'", "''")}';");
            WriteTrace(slowDatabase, "DROP VIEW calls; CREATE VIEW calls AS " +
                "WITH RECURSIVE copies(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM copies WHERE n<1000000000) " +
                "SELECT c.rowid AS rowid,c.* FROM call_records c CROSS JOIN copies;");

            using var owner = new CallView(client);
            var list = new CallList();
            owner.Published += update => list.Resize(owner.Count, update.Keep, update.Blocks ?? []);
            await owner.Open(new() { ["database"] = database, ["order"] = "oldest" });
            while (!owner.Complete) await owner.Advance();
            var delayed = await owner.Query("rows", new { index = 0, limit = CallList.BlockSize });
            WriteTrace(database, "INSERT INTO calls(target,id,tid,api,started,ended,parent,depth,caller,result,error," +
                "flags,arguments,input,output) SELECT target,1501,tid,api,5,9,parent,depth,caller,result,error," +
                "flags,arguments,input,output FROM calls WHERE id=1; UPDATE session SET total_calls=1501;");
            await owner.Advance(first: 0, last: 127);
            Require(!owner.IsCurrent(delayed), "Rows from an older revision were accepted after a late entry.");
            Require(list.Count == 1501 && list.Peek(0)?.Id == 1501 && list.Peek(1)?.Id == 1,
                "The viewport and new count were not published together.");
            var located = await owner.Query("locate", new { target = 1, callId = 1 });
            Require(owner.IsCurrent(located) && located.Number("index") == 1,
                "Navigation did not use the published snapshot.");

            using (owner.Pin())
            {
                WriteTrace(database, "INSERT INTO calls(target,id,tid,api,started,ended,parent,depth,caller," +
                    "result,error," +
                    "flags,arguments,input,output) SELECT target,1502,tid,(SELECT id FROM apis WHERE target=0 " +
                    "AND name='ReadFile'),16000,16002,parent,depth,caller," +
                    "result,error,flags,arguments,input,output FROM calls WHERE id=1; " +
                    "UPDATE session SET total_calls=1502;");
                await owner.Advance(first: 0, last: 127);
                Require(owner.Count == 1501, "An export's pinned revision advanced during its reads.");
                await client.Send("status");
            }
            await owner.Advance(first: 0, last: 127);
            Require(owner.Count == 1502, "The view did not catch up after its export released the snapshot.");
            var unmarked = await owner.Query("rows", new { index = 0, limit = 1 });
            await owner.Mark(["id:1501"]);
            Require(!owner.IsCurrent(unmarked), "A delayed row replaced newer highlight rules.");
            var marked = await owner.Query("rows", new { index = 0, limit = 2 });
            Require(marked.Items("calls").Select(row => row.Number("marks")).SequenceEqual([1L, 0L]),
                "Highlight rules and row identities came from different revisions.");

            // A multi-slice summary retains its revision while new entries wait to advance the view.
            var summaryDatabase = Path.Combine(directory, "summary.db");
            WriteTrace(database, $"VACUUM INTO '{summaryDatabase.Replace("'", "''")}';");
            WriteTrace(summaryDatabase, "WITH RECURSIVE ids(n) AS " +
                "(VALUES(1503) UNION ALL SELECT n+1 FROM ids WHERE n<1048576) " +
                "INSERT INTO calls(target,id,tid,api,started,ended,parent,depth,caller,result,error,flags,arguments) " +
                $"SELECT 1,n,1,{api.Number("id")},n*10,n*10+2,0,0,0,0,0,0,zeroblob(40) FROM ids; " +
                "UPDATE session SET total_calls=1048576;");
            using (var summaryOwner = new CallView(client))
            {
                await summaryOwner.Open(new() { ["database"] = summaryDatabase, ["order"] = "oldest" });
                while (!summaryOwner.Complete) await summaryOwner.Advance(metadata: false);
                var revision = summaryOwner.Revision;
                Task<System.Text.Json.JsonElement>? advancing = null;
                Task<System.Text.Json.JsonElement>? status = null;
                var progress = new List<double>();
                var summary = await summaryOwner.Summarize(value =>
                {
                    progress.Add(value);
                    if (advancing is null)
                    {
                        WriteTrace(summaryDatabase, "INSERT INTO calls(target,id,tid,api,started,ended,parent," +
                            "depth,caller,result,error,flags,arguments) SELECT target,1048577,tid,api,10485770," +
                            "10485772,parent,depth,caller,result,error,flags,arguments FROM calls WHERE id=1; " +
                            "UPDATE session SET total_calls=1048577;");
                        advancing = summaryOwner.Advance(metadata: false);
                        status = client.Send("status");
                    }
                    Require(!advancing.IsCompleted && summaryOwner.Revision == revision,
                        "A live update interrupted aggregation before it completed.");
                    return true;
                });
                Require(progress.Count > 0 && summary.Flag("complete") &&
                    summary.Items("items").Sum(item => item.Number("calls")) == 1048576,
                    "A multi-slice summary lost its coherent snapshot.");
                Require(progress.SequenceEqual(progress.Order()), "Summary progress restarted during aggregation.");
                await status!.WaitAsync(TimeSpan.FromSeconds(2));
                await advancing!.WaitAsync(TimeSpan.FromSeconds(3));
                Require(summaryOwner.Count == 1048577 && summaryOwner.Revision > revision,
                    "The live view did not catch up after its summary completed.");
                var timer = Stopwatch.StartNew();
                var completed = await summaryOwner.Query("summary", new { restart = true });
                while (!completed.Flag("complete")) completed = await summaryOwner.Query("summary");
                var restartedMilliseconds = timer.Elapsed.TotalMilliseconds;
                timer.Restart();
                var cached = await summaryOwner.Summarize(_ =>
                    throw new InvalidOperationException("An unchanged summary scanned the trace again."));
                Require(completed.Items("items").Sum(item => item.Number("calls")) == 1048577 &&
                    cached.Items("items").Sum(item => item.Number("calls")) == 1048577,
                    "A cached summary returned the wrong snapshot.");
                Console.WriteLine($"Million-call summary: restart {restartedMilliseconds:F2} ms, " +
                    $"cached {timer.Elapsed.TotalMilliseconds:F2} ms.");
                await summaryOwner.Mark([]);
                var partial = await summaryOwner.Summarize(_ => false);
                Require(!partial.Flag("complete") &&
                    summaryOwner.IsCurrent(await summaryOwner.Query("rows", new { index = 0, limit = 1 })),
                    "Stopping summary progress left the view locked.");
            }

            using (var abandoned = new CallView(client))
            {
                var pending = abandoned.Open(new() { ["database"] = slowDatabase });
                await Task.Delay(100);
                Require(!pending.IsCompleted, "The slow view did not exercise cancellation.");
                abandoned.Dispose();
                await pending.WaitAsync(TimeSpan.FromSeconds(2));
                await client.Send("status");
                Require(owner.IsCurrent(await owner.Query("rows", new { index = 0, limit = 1 })),
                    "Canceling one view destroyed another view or the capture connection.");
            }

            // Replace a slow trace in the real window while its first query is still pending.
            var main = new MainWindow { WindowState = WindowState.Minimized, ShowActivated = false };
            var closed = new TaskCompletionSource();
            main.Closed += (_, _) => closed.TrySetResult();
            main.Show();
            try
            {
                var deadline = Stopwatch.StartNew();
                while (!((TextBlock)main.FindName("StatusText")).Text.StartsWith("Ready"))
                {
                    Require(deadline.Elapsed < TimeSpan.FromSeconds(10), "The desktop did not start.");
                    await Task.Delay(25);
                }
                const BindingFlags members = BindingFlags.Instance | BindingFlags.NonPublic;
                static FieldInfo Field(string name) => typeof(MainWindow).GetField(name, members)!;
                var load = typeof(MainWindow).GetMethod("LoadTrace", members)!;
                var pending = (Task)load.Invoke(main, [slowDatabase])!;
                await Task.Delay(100);
                Require(!pending.IsCompleted, "The desktop fixture was not still loading.");
                WriteTrace(database, "INSERT INTO diagnostics VALUES (1,1,'Child 451: Image-signing policy.');");
                var loading = (Task)load.Invoke(main, [database])!;
                Require(!loading.IsCompleted, "The saved trace finished before its order changed.");
                var order = (ComboBox)main.FindName("OrderCombo");
                order.SelectedIndex = order.SelectedIndex == 0 ? 1 : 0;
                var sorted = (Task)Field("openingView").GetValue(main)!;
                await Task.WhenAll(loading, sorted).WaitAsync(TimeSpan.FromSeconds(3));
                await pending.WaitAsync(TimeSpan.FromSeconds(2));
                Require(((DataGrid)main.FindName("CallsGrid")).Items.Count == 1502 &&
                    ((Border)main.FindName("ErrorBanner")).Visibility != Visibility.Visible,
                    "A superseded slow trace overwrote the current view or left an error.");
                Require(((TextBlock)main.FindName("StateText")).Text == "PARTIAL CAPTURE" &&
                    ((TextBlock)main.FindName("StatusText")).Text.Contains("1 child process skipped") &&
                    ((Button)main.FindName("CoverageButton")).Visibility == Visibility.Visible,
                    "Reopening a partial trace did not show its coverage warning.");
                var settings = (CaptureSettings)Field("settings").GetValue(main)!;
                Require(settings.RecentTraces.FirstOrDefault() == database &&
                    !settings.RecentTraces.Contains(slowDatabase),
                    "The recent trace list lost the opened file or included its canceled predecessor.");

                // Canceling or superseding an export preserves the existing destination and removes its scratch file.
                var export = typeof(MainWindow).GetMethod("Export", members)!;
                var mainClient = (CollectorClient)Field("client").GetValue(main)!;
                var writeLock = (SemaphoreSlim)ClientField(mainClient, "writeLock");
                foreach (var field in new[] { "cancelExport", "viewGeneration" })
                {
                    var destination = Path.Combine(directory, field + ".json");
                    await File.WriteAllTextAsync(destination, "Existing export");
                    Task exporting;
                    await writeLock.WaitAsync();
                    try
                    {
                        exporting = (Task)export.Invoke(main, [destination])!;
                        await Task.Delay(50);
                        Require(!exporting.IsCompleted, "The export fixture did not wait for its collector.");
                        var state = Field(field);
                        state.SetValue(main, field == "cancelExport" ? true : (object)((long)state.GetValue(main)! + 1));
                    }
                    finally { writeLock.Release(); }
                    await exporting.WaitAsync(TimeSpan.FromSeconds(5));
                    Require(await File.ReadAllTextAsync(destination) == "Existing export" &&
                        Directory.GetFiles(directory, Path.GetFileName(destination) + ".*.tmp").Length == 0,
                        "An interrupted export replaced its destination or retained a partial file.");
                }

                // Live viewport revisions retain the last summary and its independent refresh deadline.
                var summaryCheck = (CheckBox)main.FindName("SummaryCheck");
                var summaryGrid = (DataGrid)main.FindName("SummaryGrid");
                summaryCheck.IsChecked = true;
                deadline.Restart();
                while (summaryGrid.ItemsSource is null)
                {
                    Require(deadline.Elapsed < TimeSpan.FromSeconds(5), "The summary did not finish.");
                    await Task.Delay(25);
                }
                var displayedSummary = summaryGrid.ItemsSource;
                summaryGrid.SelectAll();
                var summaryDeadline = Field("nextSummary");
                var due = (DateTime)summaryDeadline.GetValue(main)!;
                var mainOwner = (CallView)Field("activeView").GetValue(main)!;
                WriteTrace(database, "INSERT INTO calls(target,id,tid,api,started,ended,parent,depth,caller,result," +
                    "error,flags,arguments) SELECT target,1503,tid,api,16010,16012,parent,depth,caller,result," +
                    "error,flags,arguments FROM calls WHERE id=1; UPDATE session SET total_calls=1503;");
                await mainOwner.Advance(metadata: false);
                Require(ReferenceEquals(displayedSummary, summaryGrid.ItemsSource) &&
                    due == (DateTime)summaryDeadline.GetValue(main)!,
                    "A viewport update discarded the summary or reset its refresh throttle.");

                summaryDeadline.SetValue(main, DateTime.UtcNow.AddSeconds(-1));
                var advance = typeof(MainWindow).GetMethod("Advance", members)!;
                await ((Task)advance.Invoke(main, [false])!);
                deadline.Restart();
                while (summaryGrid.ItemsSource.Cast<SummaryItem>().Sum(item => item.Calls) != 1503)
                {
                    Require(deadline.Elapsed < TimeSpan.FromSeconds(5),
                        "An idle view left a throttled summary refresh pending.");
                    await Task.Delay(25);
                }
                Require(summaryGrid.SelectedItems.Count == 2 &&
                    summaryGrid.SelectedItems.Cast<SummaryItem>().Sum(item => item.Calls) == 1503,
                    "Refreshing live totals lost selected APIs or retained their old counts.");
                WriteTrace(database, "INSERT INTO calls(target,id,tid,api,started,ended,parent,depth,caller,result," +
                    "error,flags,arguments) SELECT target,1504,tid,api,16020,16022,parent,depth,caller,result," +
                    "error,flags,arguments FROM calls WHERE id=1; UPDATE session SET total_calls=1504;");
                await mainOwner.Advance(metadata: false);
                await ((Task)advance.Invoke(main, [true])!);
                deadline.Restart();
                while (summaryGrid.ItemsSource.Cast<SummaryItem>().Sum(item => item.Calls) != 1504)
                {
                    Require(deadline.Elapsed < TimeSpan.FromSeconds(5), "Capture end left a stale summary displayed.");
                    await Task.Delay(25);
                }

                // A skipped child must reach Coverage while the parent is idle and capture is still running.
                var reset = typeof(MainWindow).GetMethod("ResetSession", members)!;
                var live = Field("live");
                var diagnostics = Field("traceDiagnostics");
                var records = Field("records");
                var refresh = Field("refreshingView");
                var stateText = (TextBlock)main.FindName("StateText");
                var targetPath = Path.Combine(AppContext.BaseDirectory, "DetouristTestTarget.exe");
                var quiet = Path.Combine(directory, "quiet.db");
                var gateName = @"Local\Detourist.QuietCapture." + Guid.NewGuid().ToString("N");
                using var gate = new EventWaitHandle(false, EventResetMode.AutoReset, gateName);
                summaryCheck.IsChecked = false;
                reset.Invoke(main, [quiet, "Quiet capture"]);
                await mainClient.Send("launch", new { database = quiet, executable = targetPath,
                    arguments = "--protected-child " + gateName, apiMask = 0, followChildren = true,
                    startMinimized = true });
                live.SetValue(main, true);
                var beforeChild = await Wait(mainClient, status => stateText.Text == "CAPTURING" &&
                    (long)records.GetValue(main)! == status.Number("records") &&
                    ((Task)refresh.GetValue(main)!).IsCompleted);
                gate.Set();
                try
                {
                    var partial = await Wait(mainClient, status => status.Flag("partial") &&
                        ((TraceDiagnostic[])diagnostics.GetValue(main)!).Any(item =>
                            item.Message.Contains("ProcessDynamicCodePolicy")), 10);
                    Require(!partial.Flag("finished") && partial.Number("records") == beforeChild.Number("records") &&
                        stateText.Text == "PARTIAL CAPTURE",
                        "A quiet capture did not publish its skipped child before completion.");
                }
                finally { gate.Set(); }
                await Wait(mainClient, status => status.Flag("finished") && !(bool)live.GetValue(main)!);

                // The status timer keeps reporting capture progress while display work waits behind slow SQL.
                var capture = Path.Combine(directory, "capture.db");
                reset.Invoke(main, [capture, "Query responsiveness"]);
                await mainClient.Send("launch", new
                {
                    database = capture, executable = targetPath,
                    arguments = "--paced 1200", apiMask = api.Text("mask"), followChildren = false,
                    startMinimized = true
                });
                live.SetValue(main, true);
                await Wait(mainClient, status => status.Number("calls") > 100);
                var targets = (await mainClient.Send("page", new { database = capture, limit = 0 })).Items("targets");
                using var target = Process.GetProcessById((int)targets[0].Number("pid"));
                var grid = (DataGrid)main.FindName("CallsGrid");
                deadline.Restart();
                while (grid.Items.Count == 0)
                {
                    Require(deadline.Elapsed < TimeSpan.FromSeconds(3), "The live view did not open.");
                    await Task.Delay(25);
                }
                using var cancel = new CancellationTokenSource();
                var blocked = mainClient.Send("view", new { database = slowDatabase }, cancel.Token);
                await Task.Delay(300);
                var counter = (TextBlock)main.FindName("CallsText");
                var before = counter.Text;
                await Task.Delay(600);
                Require(!blocked.IsCompleted && counter.Text != before,
                    "The desktop stopped reporting capture progress while a query was busy.");
                cancel.Cancel();
                try { await blocked; }
                catch (OperationCanceledException) { }
                await mainClient.Send("stop");
                await Wait(mainClient, status => status.Flag("finished") && !(bool)live.GetValue(main)!);
                await target.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25));
                Require(target.ExitCode == 0, "Stopping capture changed the running target's result.");

                // A replacement view that cannot read the trace must also clear the pending session.
                var invalid = Path.Combine(directory, "invalid.db");
                await File.WriteAllTextAsync(invalid, "Invalid trace");
                var rejected = (Task)load.Invoke(main, [invalid])!;
                order.SelectedIndex = order.SelectedIndex == 0 ? 1 : 0;
                try { await Task.WhenAll(rejected, (Task)Field("openingView").GetValue(main)!); }
                catch (IOException) { }
                Require(stateText.Text == "IDLE" && !settings.RecentTraces.Contains(invalid),
                    "An unreadable trace survived its replacement view or entered the recent list.");
            }
            finally
            {
                main.Close();
                await closed.Task.WaitAsync(TimeSpan.FromSeconds(10));
            }
            Console.WriteLine("View ownership: delayed rows, atomic viewport updates, export pinning, marks, " +
                "slow-view replacement and live status during slow SQL passed.");
        }
        finally { Directory.Delete(directory, true); }
    }
}

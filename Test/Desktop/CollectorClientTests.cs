using Detourist.Desktop;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace Detourist.Desktop.Tests;

public static partial class Program
{
    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr process);

    private static object ClientField(CollectorClient client, string name) => typeof(CollectorClient)
        .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;

    private static void ShortDeadline(CollectorClient client) => typeof(CollectorClient)
        .GetField("requestTimeout", BindingFlags.Instance | BindingFlags.NonPublic)!
        .SetValue(client, TimeSpan.FromMilliseconds(500));

    private static async Task ConnectionFailure(Task request)
    {
        try
        {
            await request.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (IOException)
        {
            return;
        }
        throw new InvalidOperationException("An unavailable collector did not report a connection failure.");
    }

    private static async Task TimelineFailure()
    {
        // A query rejected by the collector must stay inside the timeline's async timer event.
        await using var client = new CollectorClient();
        await client.Send("hello");
        using var view = new CallView(client);
        typeof(CallView).GetField("state", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(view,
            JsonSerializer.SerializeToElement(new { view = long.MaxValue, revision = 1, count = 1, complete = true }));
        var main = new MainWindow();
        typeof(MainWindow).GetField("client", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(main, client);
        typeof(MainWindow).GetField("activeView", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(main, view);
        var calls = (CallList)typeof(MainWindow).GetField("calls", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(main)!;
        typeof(CallList).GetProperty("Count")!.SetValue(calls, 1);
        var unhandled = new List<Exception>();
        DispatcherUnhandledExceptionEventHandler handler = (_, args) =>
        {
            unhandled.Add(args.Exception);
            args.Handled = true;
        };
        main.Dispatcher.UnhandledException += handler;
        var closed = new TaskCompletionSource();
        main.Closed += (_, _) => closed.TrySetResult();
        try
        {
            typeof(MainWindow).GetMethod("TimelineResized", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(main, [main, null]);
            await Until(() => unhandled.Count > 0 ||
                ((FrameworkElement)main.FindName("ErrorBanner")).Visibility == Visibility.Visible,
                "The rejected timeline query did not complete.", 10);
            Require(unhandled.Count == 0, "A timeline query failure escaped the desktop event handler.");
            Require(((TextBlock)main.FindName("ErrorText")).Text.Length > 0,
                "The timeline query failure was not shown in the desktop.");
        }
        finally
        {
            main.Close();
            await closed.Task.WaitAsync(TimeSpan.FromSeconds(10));
            main.Dispatcher.UnhandledException -= handler;
        }
    }

    private static async Task BreakpointDisconnection()
    {
        // Losing the collector must not trap the user in a modal breakpoint that cannot resume its target.
        await using var client = new CollectorClient();
        await client.Send("hello");
        var status = JsonSerializer.SerializeToElement(new
        {
            stoppedCall = new { id = 1, target = 1, pid = 1, tid = 1, module = "kernel32.dll", name = "GetTickCount64" }
        });
        var breakpoint = new BreakpointWindow(client, status, 1024);
        var closed = false;
        breakpoint.Closed += (_, _) => closed = true;
        try
        {
            var process = (Process)ClientField(client, "process");
            process.Kill();
            await process.WaitForExitAsync();
            await ConnectionFailure(client.Send("status"));
            breakpoint.Close();
            await breakpoint.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            Require(closed, "A disconnected breakpoint prevented the window from closing.");
        }
        finally
        {
            if (!closed)
            {
                typeof(BreakpointWindow).GetField("released", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .SetValue(breakpoint, true);
                breakpoint.Close();
            }
        }
    }

    private static async Task CollectorFailures()
    {
        // Stop a real collector at each transport stage and require every pending caller to finish safely.
        foreach (var scenario in new[] { "response", "pipe", "queue", "shutdown" })
        {
            await using var client = new CollectorClient();
            var hello = await client.Send("hello");
            await ConnectionFailure(client.Send("invalid-command"));
            await client.Send("status");
            var process = (Process)ClientField(client, "process");
            using var monitor = Process.GetProcessById(process.Id);
            var writeLock = (SemaphoreSlim)ClientField(client, "writeLock");
            var queued = false;
            var database = Path.Combine(Path.GetTempPath(),
                "Detourist-Timeout-" + Guid.NewGuid().ToString("N") + ".db");
            Process? target = null;
            try
            {
                // A timeout during a real breakpoint must let the captured application finish normally.
                if (scenario == "response")
                {
                    var api = hello.Items("catalog").Single(item => item.Text("name") == "WriteFile");
                    await client.Send("launch", new
                    {
                        database, executable = Path.Combine(AppContext.BaseDirectory, "DetouristTestTarget.exe"),
                        arguments = "--leaf 20", apiMask = api.Text("mask"), entryApi = api.Number("id"),
                        followChildren = false, startMinimized = true
                    });
                    var status = await Wait(client, value => value.Flag("breakpoint") || value.Flag("finished"));
                    Require(status.Flag("breakpoint"), "The timeout fixture did not reach its breakpoint.");
                    target = Process.GetProcessById((int)status.GetProperty("stoppedCall").Number("pid"));
                }
                if (scenario != "shutdown") ShortDeadline(client);
                Require(NtSuspendProcess(process.Handle) >= 0, "The collector could not be stalled.");
                if (scenario == "queue")
                {
                    await writeLock.WaitAsync();
                    queued = true;
                }
                var first = client.Send("status", scenario is "pipe" or "shutdown" ?
                    new { padding = new string('x', 2 * 1024 * 1024) } : null);
                var second = client.Send("status");
                if (scenario == "shutdown")
                    await client.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(12));
                await Task.WhenAll(ConnectionFailure(first), ConnectionFailure(second));
                await monitor.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                if (target is not null)
                {
                    await target.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                    Require(target.ExitCode == 0, "The timed-out breakpoint did not release its target normally.");
                    await ReconnectAfterViewRelease(database);
                }
                if (scenario != "shutdown") await ConnectionFailure(client.Send("status"));
                Console.WriteLine($"Collector failure: {scenario} passed.");
            }
            finally
            {
                if (queued) writeLock.Release();
                if (!monitor.HasExited) monitor.Kill();
                if (target is not null)
                {
                    if (!target.HasExited) target.Kill();
                    await target.WaitForExitAsync();
                    target.Dispose();
                }
                await monitor.WaitForExitAsync();
                foreach (var suffix in new[] { "", "-wal", "-shm" }) File.Delete(database + suffix);
            }
        }
    }

    private static async Task ReconnectAfterViewRelease(string database)
    {
        // Disposing a real view must contain a transport failure and allow the desktop to reconnect.
        var main = new MainWindow { WindowState = WindowState.Minimized, ShowActivated = false };
        var closed = new TaskCompletionSource();
        main.Closed += (_, _) => closed.TrySetResult();
        var unhandled = new List<Exception>();
        DispatcherUnhandledExceptionEventHandler handler = (_, args) =>
        {
            unhandled.Add(args.Exception);
            args.Handled = true;
        };
        main.Dispatcher.UnhandledException += handler;
        main.Show();
        try
        {
            var deadline = Stopwatch.StartNew();
            while (!((TextBlock)main.FindName("StatusText")).Text.StartsWith("Ready"))
            {
                Require(deadline.Elapsed < TimeSpan.FromSeconds(10), "The desktop did not finish starting.");
                await Task.Delay(25);
            }
            var client = (CollectorClient)typeof(MainWindow)
                .GetField("client", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(main)!;
            using var view = new CallView(client);
            await view.Open(new() { ["database"] = database });
            ShortDeadline(client);
            var process = (Process)ClientField(client, "process");
            using var monitor = Process.GetProcessById(process.Id);
            Require(NtSuspendProcess(process.Handle) >= 0, "The desktop collector could not be stalled.");
            view.Dispose();
            await monitor.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            await ConnectionFailure(client.Send("status"));
            await main.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);

            // Re-selecting the same architecture must create a usable collector after transport loss.
            await (Task)typeof(MainWindow).GetMethod("SelectCollector", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(main, [client.PointerSize])!;
            var replacement = (CollectorClient)typeof(MainWindow)
                .GetField("client", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(main)!;
            Require(!ReferenceEquals(client, replacement) && replacement.IsConnected,
                "The desktop reused a disconnected collector.");
            Require((await replacement.Send("hello")).Number("pointerSize") == client.PointerSize,
                "The replacement collector did not respond.");
        }
        finally
        {
            main.Close();
            await closed.Task.WaitAsync(TimeSpan.FromSeconds(10));
            main.Dispatcher.UnhandledException -= handler;
        }
        Require(unhandled.Count == 0, "A collector failure escaped the desktop event handler: " +
            string.Join("; ", unhandled.Select(error => error.ToString())));
    }
}

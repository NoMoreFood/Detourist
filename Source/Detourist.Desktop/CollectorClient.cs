using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Reflection.PortableExecutable;

namespace Detourist.Desktop;

public sealed class CollectorClient : IAsyncDisposable
{
    private const string DisconnectedMessage = "The capture service disconnected. The target is being released.";
    private const int RequestTimeoutSeconds = 65;
    private const int ShutdownTimeoutSeconds = 8;
    private readonly Process process;
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonElement>> pending = new();
    private readonly SemaphoreSlim writeLock = new(1, 1);
    private readonly TimeSpan requestTimeout = TimeSpan.FromSeconds(RequestTimeoutSeconds);
    private long nextId;
    private bool disposed;
    private IOException? disconnected;
    public int PointerSize { get; }
    public bool IsConnected => !disposed && Volatile.Read(ref disconnected) is null && !process.HasExited;

    public CollectorClient(int pointerSize = 8) : this(pointerSize, null) {}

    internal CollectorClient(int pointerSize, string? catalogPath)
    {
        // The collector owns capture and storage independently of the presentation thread.
        PointerSize = pointerSize == 4 ? 4 : 8;
        var directory = PointerSize == 4 ? Path.Combine(AppContext.BaseDirectory, "x86") : AppContext.BaseDirectory;
        var executable = Path.Combine(directory, "DetouristCollector.exe");
        if (!File.Exists(executable))
        {
            throw new FileNotFoundException(
                $"The {(PointerSize == 4 ? "x86" : "x64")} capture components are unavailable.", executable);
        }
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = directory
        };
        if (catalogPath is not null)
        {
            start.Environment["DETOURIST_API_CATALOG"] = Path.GetFullPath(catalogPath);
            start.Environment.Remove("DETOURIST_API_CATALOG_X86");
        }
        else if (PointerSize == 4)
        {
            // Each collector reads the catalog for its own architecture.
            if (Environment.GetEnvironmentVariable("DETOURIST_API_CATALOG_X86") is { Length: > 0 } catalog)
                start.Environment["DETOURIST_API_CATALOG"] = catalog;
            else start.Environment.Remove("DETOURIST_API_CATALOG");
        }
        process = Process.Start(start) ?? throw new IOException("The capture service could not start.");
        _ = ReadResponses();
        _ = process.StandardError.ReadToEndAsync();
    }

    public static int ExecutablePointerSize(string path)
    {
        using var stream = File.OpenRead(path);
        using var image = new PEReader(stream);
        var headers = image.PEHeaders;
        if (headers.CoffHeader.Machine == Machine.Amd64) return 8;
        if (headers.CoffHeader.Machine != Machine.I386)
            throw new IOException("Choose an x86 or x64 executable.");
        var flags = headers.CorHeader?.Flags ?? 0;
        return (flags & CorFlags.ILOnly) != 0 &&
            (flags & (CorFlags.Requires32Bit | CorFlags.Prefers32Bit)) == 0 ? 8 : 4;
    }

    public async Task<JsonElement> Send(string command, object? arguments = null,
        CancellationToken cancellation = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (Volatile.Read(ref disconnected) is { } failure) throw new IOException(failure.Message, failure);
        var id = Interlocked.Increment(ref nextId);
        var request = arguments is null ? new Dictionary<string, JsonElement>() :
            JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                JsonSerializer.SerializeToUtf8Bytes(arguments))!;
        request["id"] = JsonSerializer.SerializeToElement(id);
        request["command"] = JsonSerializer.SerializeToElement(command);
        var completion = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        pending[id] = completion;
        using var timeout = new CancellationTokenSource(requestTimeout);
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, cancellation);
        var writing = false;
        var sent = false;
        try
        {
            if (Volatile.Read(ref disconnected) is { } stopped) throw new IOException(stopped.Message, stopped);

            // Bound the entire exchange, including queued requests and a collector that stops reading its pipe.
            await writeLock.WaitAsync(waiting.Token);
            writing = true;
            if (Volatile.Read(ref disconnected) is { } failed) throw new IOException(failed.Message, failed);
            try
            {
                await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(request)).WaitAsync(timeout.Token);
                await process.StandardInput.FlushAsync().WaitAsync(timeout.Token);
            }
            catch (Exception error) when (error is IOException or InvalidOperationException)
            {
                throw Disconnect(new IOException(DisconnectedMessage, error));
            }
            writing = false;
            writeLock.Release();
            sent = true;
            return await completion.Task.WaitAsync(waiting.Token);
        }
        catch (OperationCanceledException error) when (timeout.IsCancellationRequested)
        {
            // An unfinished write or command cannot be safely retried; ending its collector also releases targets.
            throw Disconnect(new IOException("The capture service timed out. The target is being released.", error));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            if (sent) _ = Cancel(id);
            throw;
        }
        finally
        {
            if (writing) writeLock.Release();
            pending.TryRemove(id, out _);
        }
    }

    private async Task Cancel(long id)
    {
        // Cancel query work after its complete request has reached the collector, without interrupting capture.
        try { await Send("cancel", new { request = id }); }
        catch (Exception error) when (error is IOException or ObjectDisposedException) { }
    }

    private IOException Disconnect(IOException failure)
    {
        // Share the first transport failure and release targets even when the collector cannot process shutdown.
        failure = Interlocked.CompareExchange(ref disconnected, failure, null) ?? failure;
        foreach (var completion in pending.Values) completion.TrySetException(failure);
        try
        {
            process.Kill();
        }
        catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }
        return failure;
    }

    private async Task ReadResponses()
    {
        var failure = new IOException(DisconnectedMessage);
        try
        {
            // Parse responses away from the dispatcher before handing completed requests back to the UI.
            while (await process.StandardOutput.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                if (!root.TryGetProperty("id", out var id) || !pending.TryGetValue(id.GetInt64(), out var completion))
                {
                    continue;
                }
                if (root.Flag("ok"))
                {
                    completion.TrySetResult(root.GetProperty("data").Clone());
                }
                else
                {
                    completion.TrySetException(new IOException(root.Text("error", "The operation failed.")));
                }
            }
        }
        catch (Exception error)
        {
            failure = new IOException(DisconnectedMessage, error);
        }
        Disconnect(failure);
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed) return;
        disposed = true;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(ShutdownTimeoutSeconds));
        try
        {
            // Let an active write finish before closing its stream, with the same bounded shutdown as the process.
            await writeLock.WaitAsync(timeout.Token);
            try
            {
                process.StandardInput.Close();
            }
            finally
            {
                writeLock.Release();
            }
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or InvalidOperationException)
        {
            Disconnect(new IOException(DisconnectedMessage, error));
        }
        await process.WaitForExitAsync();
        process.Dispose();
    }
}

public static class JsonFields
{
    public static string Text(this JsonElement item, string name, string fallback = "") =>
        item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out var value) ?
            value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : value.ToString() : fallback;
    public static long Number(this JsonElement item, string name, long fallback = 0)
    {
        if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty(name, out var value)) return fallback;
        return value.ValueKind == JsonValueKind.Number ? value.TryGetInt64(out var number) ? number : fallback :
            value.ValueKind == JsonValueKind.String && long.TryParse(value.GetString(), out number) ? number : fallback;
    }
    public static double Decimal(this JsonElement item, string name, double fallback = 0)
    {
        if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty(name, out var value)) return fallback;
        return value.ValueKind == JsonValueKind.Number ? value.TryGetDouble(out var number) ? number : fallback :
            value.ValueKind == JsonValueKind.String && double.TryParse(value.GetString(),
                System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture,
                out number) ? number : fallback;
    }
    public static bool Flag(this JsonElement item, string name) =>
        item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out var value) &&
        (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.String &&
            string.Equals(value.GetString(), "true", StringComparison.OrdinalIgnoreCase));
    public static JsonElement[] Items(this JsonElement item, string name) =>
        item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().ToArray() : [];
}

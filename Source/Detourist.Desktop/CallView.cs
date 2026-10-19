using System.IO;
using System.Text.Json;

namespace Detourist.Desktop;

// Owns one collector snapshot and serializes changes before publishing its count, rows and revision together.
public sealed class CallView(CollectorClient client) : IDisposable
{
    public sealed record Update(JsonElement State, bool Keep, Dictionary<int, JsonElement[]>? Blocks, int First,
        bool Changed);
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly CancellationTokenSource lifetime = new();
    private JsonElement state;
    private bool disposed;
    private int pins;
    public event Action<Update>? Published;
    public long Id => disposed ? 0 : state.Number("view");
    public long Revision => disposed ? 0 : state.Number("revision");
    public int Count => (int)Math.Min(state.Number("count"), int.MaxValue);
    public long Scanned => state.Number("scanned");
    public bool Complete => !disposed && state.Flag("complete");
    public bool IsCurrent(JsonElement response) => !disposed && response.Number("view") == Id &&
        response.Number("revision") == Revision && !response.Flag("stale");

    public Task<JsonElement> Open(Dictionary<string, object> request) => Advance(request: request);

    public Task<JsonElement> Advance(bool extend = true, bool metadata = true, int first = 0, int last = -1,
        bool following = false, bool newest = false, Dictionary<string, object>? request = null) => Run(async () =>
    {
        if (pins > 0 && Id != 0) return state;
        var previous = Count;
        var revision = Revision;
        var next = await Send("view", request ?? new() { ["extend"] = extend, ["includeMetadata"] = metadata });
        if (next.Flag("stale")) return next;
        var count = (int)Math.Min(next.Number("count"), int.MaxValue);
        var keep = next.Number("changedFrom") >= previous && count >= previous;
        Dictionary<int, JsonElement[]>? blocks = null;
        if (last >= first && (request is not null || next.Number("revision") != revision))
        {
            // Fetch the destination viewport from this exact revision before publishing any new positions.
            var span = last - first;
            if (following) first = newest ? 0 : Math.Max(0, count - span - 1);
            else if (!keep && newest) first += count - previous;
            first = Math.Clamp(first, 0, Math.Max(0, count - 1));
            blocks = [];
            for (var number = first / CallList.BlockSize; count > 0 &&
                number <= Math.Min(first + span, count - 1) / CallList.BlockSize; ++number)
            {
                var rows = await Send("rows", new()
                {
                    ["view"] = next.Number("view"), ["revision"] = next.Number("revision"),
                    ["index"] = (long)number * CallList.BlockSize, ["limit"] = CallList.BlockSize
                });
                if (rows.Flag("stale")) throw new IOException("The call view changed while loading its rows.");
                blocks[number] = rows.Items("calls");
            }
        }
        state = next;
        Published?.Invoke(new(state, keep, blocks, first, revision != Revision));
        return state;
    });

    public Task<JsonElement> Query(string command, object? arguments = null) =>
        Run(() => Send(command, Fields(arguments)));

    // Keep aggregation on one revision while capture and status requests continue independently.
    public Task<JsonElement> Summarize(Func<double, bool> keepGoing) => Run(async () =>
    {
        JsonElement result;
        do
        {
            result = await Send("summary", []);
        } while (!result.Flag("complete") && !result.Flag("stale") && keepGoing(result.Decimal("progress")));
        return result;
    });

    public Task Mark(string[] filters) => Run(async () =>
    {
        try { await Send("mark", new() { ["filters"] = filters }); }
        finally
        {
            // Failed mark compilation also clears marks; read the resulting revision without advancing it.
            if (!disposed)
            {
                state = await client.Send("view", new { view = Id, advance = false }, lifetime.Token);
                Published?.Invoke(new(state, true, [], 0, true));
            }
        }
        return state;
    });

    private async Task<JsonElement> Run(Func<Task<JsonElement>> action)
    {
        var entered = false;
        try
        {
            await gate.WaitAsync(lifetime.Token);
            entered = true;
            return await action();
        }
        catch (OperationCanceledException) when (disposed) { return default; }
        catch (IOException) when (disposed) { return default; }
        finally { if (entered) gate.Release(); }
    }

    // Export keeps its starting snapshot while ordinary reads and capture controls continue.
    public IDisposable Pin() { ++pins; return new PinScope(this); }
    private sealed class PinScope(CallView owner) : IDisposable
    {
        public void Dispose() => --owner.pins;
    }

    private async Task<JsonElement> Send(string command, Dictionary<string, object> request)
    {
        lifetime.Token.ThrowIfCancellationRequested();
        if (Id != 0)
        {
            request.TryAdd("view", Id);
            request.TryAdd("revision", Revision);
        }
        var response = await client.Send(command, request, lifetime.Token);
        lifetime.Token.ThrowIfCancellationRequested();
        return response;
    }

    private static Dictionary<string, object> Fields(object? arguments) => arguments is null ? [] :
        JsonSerializer.Deserialize<Dictionary<string, object>>(JsonSerializer.SerializeToUtf8Bytes(arguments))!;

    public void Dispose()
    {
        if (disposed) return;
        var identifier = Id;
        disposed = true;
        lifetime.Cancel();
        if (identifier != 0) _ = Release(identifier);
    }

    private async Task Release(long identifier)
    {
        try { await client.Send("release", new { view = identifier }); }
        catch (Exception error) when (error is IOException or ObjectDisposedException) { }
    }
}

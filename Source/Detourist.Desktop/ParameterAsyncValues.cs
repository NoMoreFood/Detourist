using System.Text.Json;

namespace Detourist.Desktop;

public static partial class ParameterValues
{
    private static void AddAsyncCompletion(List<ParameterProperty> rows, JsonElement call,
        Dictionary<uint, List<MemorySnapshot>> output)
    {
        if (!call.TryGetProperty("completion", out var completion)) return;
        var source = (AsyncIoSource)completion.Number("source") switch
        {
            AsyncIoSource.Result => "Result query", AsyncIoSource.CompletionPort => "Completion port",
            AsyncIoSource.Apc => "APC", AsyncIoSource.Event => "Event wait",
            AsyncIoSource.Return => "API return", AsyncIoSource.Rpc => "RPC completion", _ => "Unknown"
        };
        var rpc = completion.Number("domain") == (long)AsyncIoDomain.Rpc;
        var root = new ParameterProperty
        {
            Name = rpc ? "RPC completion" : "I/O completion", SignatureType = new("Completion"),
            OutputLabel = rpc ? source : $"{completion.Number("transferred")} bytes · {source}"
        };
        void Add(string name, string type, ulong? value = null, string? text = null) => root.Children.Add(new()
        {
            Name = name, SignatureType = ParameterType.Infer(type), Level = 1, Output = value, OutputLabel = text
        });
        Add("Final status", completion.Number("domain") == (long)AsyncIoDomain.NtStatus ? "NTSTATUS" : "DWORD",
            ParameterType.ParseHex(completion.Text("status")));
        if (!rpc)
        {
            Add("Transferred", "SIZE_T", (ulong)completion.Number("transferred"));
            Add("I/O flags", "DWORD", (ulong)completion.Number("ioFlags"));
        }
        Add("Observed after", "Duration", text: $"{completion.Decimal("elapsedUs"):N1} µs");
        Add("Control block", "void *", ParameterType.ParseHex(completion.Text("control")));
        Add("Observer call", "UINT64", (ulong)completion.Number("observer"));
        Add("Observer thread", "DWORD", (ulong)completion.Number("tid"));

        // Completion descriptors retain submission addresses even when the original WSABUF array is gone.
        foreach (var buffer in completion.Items("buffers"))
        {
            var parameter = (uint)buffer.Number("parameter");
            var index = (uint)buffer.Number("index");
            var memory = output.GetValueOrDefault(parameter, []).FirstOrDefault(value =>
                value.Kind == (int)ValueKind.Bytes &&
                (index == uint.MaxValue ? (value.Flags & (uint)ValueFlags.ReferencedData) == 0 :
                    (value.Flags & (uint)ValueFlags.ReferencedData) != 0 && value.Flags >> 16 == index));
            var row = new ParameterProperty
            {
                Name = $"Buffer {parameter}" + (index == uint.MaxValue ? "" : $"[{index}]"),
                SignatureType = new("Bytes"), Level = 1,
                OutputMemory = memory,
                OutputLabel = $"{buffer.Number("completed")} / {buffer.Number("requested")} bytes" +
                    (memory is not null && memory.Bytes.Length < buffer.Number("completed") ?
                        $" · {memory.Bytes.Length} captured" : "") +
                    (memory is not null && memory.State.Length > 0 ? $" · {memory.State}" : "")
            };
            row.Children.Add(new()
            {
                Name = "Address", SignatureType = new("void *", Kind: "Pointer"), Level = 2,
                Output = ParameterType.ParseHex(buffer.Text("address"))
            });
            root.Children.Add(row);
        }
        if (completion.Number("flags") != 0) Add("Descriptors", "Capture state", text:
            (completion.Number("flags") & (long)ValueFlags.Unreadable) != 0 ? "Some descriptors unreadable" :
            "Descriptor limit reached");
        rows.Add(root);
    }
}

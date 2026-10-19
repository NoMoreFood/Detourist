using System.Text.Json;

namespace Detourist.Desktop;

public static partial class ParameterValues
{
    private static Dictionary<int, ApiParameter> RpcArguments(JsonElement call)
    {
        var result = new Dictionary<int, ApiParameter>();
        if (!call.TryGetProperty("rpc", out var rpc) || (rpc.Number("flags") & (long)RpcCaptureFlags.DescriptorValid) == 0)
            return result;
        foreach (var parameter in rpc.Items("parameters"))
        {
            var attributes = parameter.Number("attributes");
            var argument = (int)parameter.Number("argument");
            if ((attributes & (long)RpcParameterFlags.Return) != 0) continue;
            var inOut = (long)(RpcParameterFlags.In | RpcParameterFlags.Out);
            var direction = (attributes & inOut) == inOut ? "in/out" :
                (attributes & (long)RpcParameterFlags.Out) != 0 ? "out" : "in";
            var name = (RpcValueType)parameter.Number("typeId") switch
            {
                RpcValueType.Binding => "RPC binding", RpcValueType.AsyncHandle => "RPC async handle",
                _ => $"RPC argument {argument - rpc.Number("prefix")}"
            };
            if ((rpc.Number("flags") & (long)RpcCaptureFlags.ObjectProcedure) != 0 &&
                argument == rpc.Number("prefix")) name = "RPC receiver";
            result[argument] = new($"{name} ({direction})", parameter.Text("type"));
        }
        return result;
    }

    private static void AddRpcValues(List<ParameterProperty> rows, JsonElement call)
    {
        if (!call.TryGetProperty("rpc", out var rpc)) return;
        var descriptor = new ParameterProperty
        {
            Name = "RPC procedure", SignatureType = new(rpc.Text("syntax")), InputLabel =
                $"{rpc.Text("interface")} v{rpc.Number("major")}.{rpc.Number("minor")} · {rpc.Number("procedure")}",
            OutputLabel = rpc.Text("state") + (rpc.Text("operation") is { Length: > 0 } operation ?
                " · " + operation : "") + ((rpc.Number("flags") & (long)RpcCaptureFlags.OutputsDeferred) != 0 ?
                    (rpc.Number("flags") & (long)RpcCaptureFlags.ObjectProcedure) != 0 ?
                        " · outputs returned by Finish" : " · completion not observed" : "")
        };
        rows.Add(descriptor);
        var parameters = rpc.Items("parameters")
            .Where(value => (value.Number("attributes") & (long)RpcParameterFlags.Return) == 0)
            .ToDictionary(value => (int)value.Number("argument"));
        var merged = new Dictionary<string, ParameterProperty>();

        // Node paths merge corresponding input and output memory even when each side traversed different arguments.
        foreach (var side in new[] { "input", "output" })
        {
            var nodes = new Dictionary<int, (string Path, ParameterProperty Row)>();
            foreach (var value in call.Items(side).Where(value => value.Number("kind") == (long)ValueKind.RpcValue))
            {
                var argument = (int)value.Number("parameter");
                var owner = rows.FirstOrDefault(row => row.Parameter == argument);
                if (owner is null) continue;
                var parentId = (int)value.Number("parent");
                var parent = parentId == ushort.MaxValue ? ($"{argument}", owner) :
                    nodes.GetValueOrDefault(parentId, ($"{argument}", owner));
                var type = (RpcValueType)value.Number("typeId");
                var parameter = parameters.GetValueOrDefault(argument);
                var scalar = type is (>= RpcValueType.UInt8 and <= RpcValueType.Float64) or RpcValueType.Pointer or
                    RpcValueType.Binding or RpcValueType.AsyncHandle;
                var inline = parentId == ushort.MaxValue && parameter.Number("pointerDepth") == 0 && scalar;
                var path = $"{parent.Item1}/{value.Number("offset")}:{(int)type}";
                if (!merged.TryGetValue(path, out var row))
                {
                    row = inline ? owner : new ParameterProperty
                    {
                        Name = parentId == ushort.MaxValue ? type switch
                        {
                            RpcValueType.Ansi or RpcValueType.Utf16 => "Text", RpcValueType.Structure => "Structure",
                            RpcValueType.Array => "Buffer", RpcValueType.Pointer => "Pointer",
                            RpcValueType.Custom => "Custom value", RpcValueType.Union => "Union", _ => "Value"
                        } : value.Number("offset") == 0 ? "Referent" : $"+0x{value.Number("offset"):X}",
                        SignatureType = type == RpcValueType.Pointer ? new("void *", Kind: "Pointer") :
                            scalar ? ParameterType.Infer(value.Text("rpcType")) : new(value.Text("rpcType")),
                        Level = parent.Item2.Level + 1,
                        Hex = type is not RpcValueType.Float32 and not RpcValueType.Float64
                    };
                    if (!inline) parent.Item2.Children.Add(row);
                    merged[path] = row;
                }
                nodes[(int)value.Number("node")] = (path, row);
                var snapshot = MemorySnapshot.FromJson(value) with
                {
                    Kind = type == RpcValueType.Utf16 ? (int)ValueKind.Utf16 : (int)ValueKind.Bytes
                };
                var number = scalar && snapshot.Bytes.Length is > 0 and <= 8 ?
                    MemorySnapshot.Scalar(snapshot.Bytes, 0, snapshot.Bytes.Length) : (ulong?)null;
                var text = type is RpcValueType.Ansi or RpcValueType.Utf16 ?
                    QuotedText(snapshot, type == RpcValueType.Utf16) :
                    scalar ? null : $"{snapshot.Bytes.Length} / {snapshot.OriginalBytes} bytes";
                if (snapshot.State.Length > 0) text = (text is null ? "" : text + " · ") + snapshot.State;
                if (side == "input")
                {
                    row.InputMemory = snapshot;
                    if (!inline) row.Input = number;
                    if (text is not null) row.InputLabel = text;
                }
                else
                {
                    row.OutputMemory = snapshot;
                    row.Output = number;
                    if (text is not null) row.OutputLabel = text;
                }
            }
        }
        var incomplete = (rpc.Number("flags") & (long)RpcCaptureFlags.OutputsDeferred) != 0;
        var asyncObject = (long)(RpcCaptureFlags.ObjectProcedure | RpcCaptureFlags.Asynchronous);
        var failed = (call.Number("flags") & (long)EventFlags.Failed) != 0 &&
            ((rpc.Number("flags") & asyncObject) == asyncObject ||
            call.TryGetProperty("completion", out var completion) && completion.Number("domain") == (long)AsyncIoDomain.Rpc);
        if (incomplete || failed)
            foreach (var parameter in parameters.Values.Where(value =>
                (value.Number("attributes") & (long)RpcParameterFlags.Out) != 0))
                if (rows.FirstOrDefault(row => row.Parameter == parameter.Number("argument")) is { } row)
                    row.OutputLabel = incomplete ? "<RPC completion not observed>" : "<RPC call failed>";
    }
}

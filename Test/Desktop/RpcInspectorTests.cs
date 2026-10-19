using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using static Detourist.Desktop.Tests.Program;

namespace Detourist.Desktop.Tests;

public static class RpcInspectorTests
{
    public static void Verify(JsonElement calls)
    {
        static IEnumerable<ParameterProperty> Descendants(ParameterProperty row) =>
            row.Children.SelectMany(child => new[] { child }.Concat(Descendants(child)));
        JsonElement sample = default;
        List<JsonElement> asynchronous = [];
        foreach (var call in calls.EnumerateArray())
        {
            var rows = ParameterValues.Build(call);
            if (call.Text("name").StartsWith("RPC user "))
            {
                var nodes = rows.Concat(rows.SelectMany(Descendants)).ToArray();
                Require(nodes.Any(row => row.OutputMemory?.Bytes.Length == 4) &&
                    nodes.Any(row => row.InputMemory?.Bytes.Length == 8 || row.OutputMemory?.Bytes.Length == 8),
                    "Custom marshaling lost its wire or native snapshot in the inspector.");
                asynchronous.Add(call);
                continue;
            }
            var rpc = call.GetProperty("rpc");
            var descriptor = rows.Single(row => row.Name == "RPC procedure");
            Require(descriptor.OutputText.Contains(rpc.Text("state")), "RPC decoding state is missing.");
            if ((rpc.Number("flags") & 1) == 0) continue;
            var prefix = rpc.Number("prefix");
            if ((rpc.Number("flags") & 64) != 0)
            {
                Require(descriptor.OutputText.Contains(rpc.Text("operation")),
                    "The serialization direction is missing from the inspector.");
                continue;
            }
            if ((rpc.Number("flags") & 132) == 132)
            {
                Require(descriptor.OutputText.Contains(rpc.Text("operation")),
                    "COM Begin/Finish direction is missing.");
                Require(rows.Any(row => row.Name.Contains("RPC receiver")), "COM receiver identity is missing.");
                if (rpc.Text("operation") == "Finish")
                {
                    var output = rows.Single(row => row.Parameter == prefix + 1);
                    if ((call.Number("flags") & 1) != 0)
                        Require(output.OutputText == "<RPC call failed>" &&
                            !Descendants(output).Any(row => row.OutputMemory is not null),
                            "Failed COM Finish exposed an output value.");
                    else
                        Require(Descendants(output).Any(row => row.Output is 42 or 57 or 0x1234567A0),
                            "COM Finish lost its returned value.");
                }
                else if ((call.Number("flags") & 1) == 0)
                    Require(descriptor.OutputText.Contains("outputs returned by Finish"),
                        "COM Begin was presented as a missing RPC completion.");
                asynchronous.Add(call);
                sample = call;
                continue;
            }
            if ((rpc.Number("flags") & 4) != 0)
            {
                asynchronous.Add(call);
                var output = rows.Single(row => row.Parameter == prefix + 3);
                Require(rows.Any(row => row.Name == "RPC completion"), "RPC completion status is missing.");
                if ((call.Number("flags") & 1) != 0)
                    Require(output.OutputText == "<RPC call failed>" &&
                        !Descendants(output).Any(row => row.OutputMemory is not null),
                        "Cancelled RPC output was presented as completed.");
                else
                    Require(Descendants(output).Any(row => row.Output == 58),
                        "Async RPC completion lost the returned referent.");
                continue;
            }
            if (rpc.Number("procedure") == 0)
            {
                var parameters = rpc.Items("parameters");
                var floatingIndex = parameters.Single(value => value.Number("typeId") == 10).Number("argument");
                var floating = rows.Single(row => row.Parameter == floatingIndex);
                Require(floating.Type.Kind == "Float64" &&
                    BitConverter.UInt64BitsToDouble(floating.Input!.Value) == 3.25,
                    "The floating RPC argument lost its type or register bits.");
                var changedIndex = parameters.Single(value => value.Number("typeId") == 6 &&
                    value.Number("pointerDepth") == 1 && (value.Number("attributes") & 24) == 24).Number("argument");
                var changed = rows.Single(row => row.Parameter == changedIndex);
                Require(Descendants(changed).Any(row => row.Input == 9 && row.Output == 27),
                    "The scalar reference lost its before-and-after values.");
            }
            else if (rpc.Number("procedure") == 4)
            {
                var records = rows.Single(row => row.Parameter == prefix + 2);
                var count = call.Items("input").Count(value => value.Number("typeId") == 12);
                Require(Descendants(records).Count(row => row.InputText.Contains("rpc-array-")) == count,
                    "Record-array strings were not reachable in the inspector.");
                asynchronous.Add(call);
            }
            else if (rpc.Number("procedure") == 5)
            {
                var outputIndex = rpc.Items("parameters").Single(value =>
                    value.Number("typeId") == 19 && (value.Number("attributes") & 24) == 24).Number("argument");
                var value = rows.Single(row => row.Parameter == outputIndex);
                Require(Descendants(value).Any(row => row.Name == "Custom value" &&
                    row.InputMemory?.Bytes.Length == 8 && row.OutputMemory?.Bytes.Length == 8),
                    "The custom native representation was not labeled or preserved.");
                asynchronous.Add(call);
            }
            else if (rpc.Number("procedure") == 9)
            {
                var nodes = Descendants(rows.Single(row => row.Parameter == prefix + 2)).ToArray();
                Require(nodes.Count(row =>
                    row.Type.Name == "RPC custom value" && row.OutputMemory?.Bytes.Length == 8) == 2 &&
                    !nodes.Any(row => row.InputMemory is not null),
                    "Output-only custom values were not preserved in the inspector.");
                asynchronous.Add(call);
            }
            else if (rpc.Number("procedure") is 6 or 7 or 8)
            {
                var nodes = rows.SelectMany(Descendants).ToArray();
                Require(nodes.Any(row => row.InputMemory is not null) && nodes.Any(row => row.OutputMemory is not null),
                    "Correlated RPC values were not reachable in the inspector.");
                if (rpc.Number("procedure") is 6 or 8)
                    Require(nodes.Any(row => row.Type.Name == "RPC union"), "The selected union is missing.");
                asynchronous.Add(call);
            }
            else
            {
                var output = rows.Single(row => row.Parameter == prefix + 4);
                Require(Descendants(output).Single(row => row.OutputMemory is not null).OutputMemory!.Bytes.Length == 7,
                    "The RPC buffer viewer included uncompleted capacity.");
                var record = rows.Single(row => row.Parameter == prefix + 6);
                Require(Descendants(record).Any(row => row.OutputText.Contains("rpc-record")),
                    "The structure's referenced string was not reachable in the inspector.");
                sample = call;
            }
        }
        Require(sample.ValueKind == JsonValueKind.Object, "A real RPC fixture is required.");

        // Inspect the actual captured graph through the standard grid at normal and enlarged display scales.
        foreach (var scale in new[] { 1.0, 1.5 })
        foreach (var current in asynchronous.Append(sample))
        {
            var grid = new ParameterGrid();
            grid.ShowCall(current);
            grid.LayoutTransform = new ScaleTransform(scale, scale);
            var host = new Border { Child = grid };
            var size = new Size(1100 * scale, 720 * scale);
            host.Measure(size);
            host.Arrange(new Rect(size));
            grid.Dispatcher.Invoke(host.UpdateLayout, DispatcherPriority.ApplicationIdle);
            var table = (DataGrid)grid.FindName("PropertiesGrid");
            var properties = table.Items.Cast<ParameterProperty>();
            Require(table.ActualWidth >= 1000 && (current.TryGetProperty("rpc", out _) ?
                properties.Any(row => row.Name == "RPC procedure") : properties.Any(row => row.Parameter == 1)),
                "RPC rows were clipped under display scaling.");
            host.Child = null;
        }
    }
}

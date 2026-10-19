using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using static Detourist.Desktop.Tests.Program;

namespace Detourist.Desktop.Tests;

public static class AsyncIoInspectorTests
{
    public static void Verify(JsonElement calls, string directory)
    {
        JsonElement vector = default;
        foreach (var call in calls.EnumerateArray())
        {
            var item = CallItem.FromJson(call);
            Require(!item.IsPending && item.DurationUs >= 0, "Completed I/O still refreshes as pending.");
            var completion = call.GetProperty("completion");
            var rows = ParameterValues.Build(call);
            var row = rows.Single(value => value.Name == "I/O completion");
            Require(row.Children.Single(value => value.Name == "Transferred").Output ==
                (ulong)completion.Number("transferred"), "The inspector changed the completion transfer count.");
            var buffers = row.Children.Where(value => value.Name.StartsWith("Buffer ")).ToArray();
            Require(buffers.Length == completion.Items("buffers").Length,
                "The inspector dropped a completion buffer descriptor.");
            foreach (var buffer in buffers)
            {
                Require(buffer.OutputMemory is not null || buffer.OutputText.StartsWith("0 / "),
                    "A completed buffer is missing its byte viewer.");
                if (buffer.OutputMemory is { Flags: var flags } && (flags & 3) != 0)
                    Require(buffer.OutputText.Contains((flags & 2) != 0 ? "unreadable" : "truncated"),
                        "The completion inspector hid incomplete buffer data.");
            }
            if ((item.Flags & 524288) != 0)
                Require(item.State == "Cancelled" && item.IsFailure, "Cancellation lost its final failure state.");
            if (call.Text("name") == "WSARecv" && buffers.Length == 2)
            {
                Require(buffers[0].OutputMemory!.Bytes.AsSpan().SequenceEqual("asyn"u8) &&
                    buffers[1].OutputMemory!.Bytes.AsSpan().SequenceEqual("c-wsa"u8),
                    "The completion inspector confused vector buffers with their stack descriptors.");
                IEnumerable<ParameterProperty> Descendants(ParameterProperty value) =>
                    value.Children.SelectMany(child => new[] { child }.Concat(Descendants(child)));
                Require(Descendants(rows.Single(value => value.Parameter == 1))
                    .All(value => value.OutputMemory is null),
                    "Completion bytes were decoded as output WSABUF descriptors.");
                vector = call;
            }
        }
        Require(vector.ValueKind == JsonValueKind.Object, "The inspector fixture contains no vector completion.");

        // Check the completion inspector at normal and enlarged scale without taking foreground focus.
        foreach (var scale in new[] { 1.0, 1.5 })
        {
            var grid = new ParameterGrid();
            grid.ShowCall(vector);
            grid.LayoutTransform = new ScaleTransform(scale, scale);
            var size = new Size(1100 * scale, 720 * scale);
            var host = new Border
            {
                Background = (Brush)Application.Current.FindResource("CanvasBrush"), Child = grid
            };
            TextElement.SetForeground(host, (Brush)Application.Current.FindResource("TextBrush"));
            TextElement.SetFontFamily(host, new FontFamily("Segoe UI"));
            TextElement.SetFontSize(host, 13);
            host.Measure(size);
            host.Arrange(new Rect(size));
            host.UpdateLayout();
            grid.Dispatcher.Invoke(host.UpdateLayout, DispatcherPriority.ApplicationIdle);
            Require(grid.ActualWidth >= 1099 && grid.ActualHeight >= 719,
                "The completion inspector collapsed under display scaling.");
            var table = (DataGrid)grid.FindName("PropertiesGrid");
            Require(table.ActualWidth >= 1000 && table.Items.Cast<ParameterProperty>()
                .Any(value => value.Name == "I/O completion"), "The completion rows were clipped from the inspector.");
            var bitmap = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(host);
            var pixels = new byte[(int)size.Width * (int)size.Height * 4];
            bitmap.CopyPixels(pixels, (int)size.Width * 4, 0);
            var painted = Enumerable.Range(0, pixels.Length / 4).Count(index => pixels[index * 4 + 3] != 0);
            if (painted < 10000 || Enumerable.Range(0, pixels.Length / 4)
                .Select(index => BitConverter.ToUInt32(pixels, index * 4)).Distinct().Take(8).Count() < 8)
            {
                Console.WriteLine($"Pixel rendering unavailable at {scale:P0}; completion layout assertions passed.");
                continue;
            }
            SavePng(bitmap, Path.Combine(directory, $"async-inspector-{scale:0.0}.png"));
            host.Child = null;
        }
    }
}

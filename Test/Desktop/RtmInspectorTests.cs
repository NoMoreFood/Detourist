using Detourist.Desktop;
using System.Text.Json;

namespace Detourist.Desktop.Tests;

public static partial class Program
{
    private static void InspectRtmFields()
    {
        // Unnamed route layouts still expose the retained common fields and no fabricated surrounding bytes.
        JsonElement Call(string module) => JsonSerializer.SerializeToElement(new
        {
            name = "RtmAddRoute", module,
            parameters = "HANDLE ClientHandle, PVOID Route, DWORD TimeToLive, DWORD * Flags, " +
                "PVOID CurBestRoute, PVOID PrevBestRoute",
            arguments = new[] { "0x1", "0x1000", "0x0", "0x0", "0x0", "0x0" },
            input = new[]
            {
                new { parameter = 1, kind = 0, flags = 16, originalBytes = 4, bytes = "01020304", memberOffset = 12 },
                new { parameter = 1, kind = 0, flags = 16, originalBytes = 4, bytes = "05060708", memberOffset = 32 }
            },
            output = Array.Empty<object>(), result = "0x0", durationUs = 1
        });
        var route = ParameterValues.Build(Call("rtm.dll")).Single(row => row.Parameter == 1);
        var fields = route.Children.Where(row => row.Name.StartsWith("field +0x", StringComparison.Ordinal)).ToArray();
        Require(fields.Select(row => row.Name).SequenceEqual(["field +0xC", "field +0x20"]) &&
            fields[0].InputMemory?.Bytes.SequenceEqual(new byte[] { 1, 2, 3, 4 }) == true &&
            fields[1].InputMemory?.Bytes.SequenceEqual(new byte[] { 5, 6, 7, 8 }) == true,
            "Family-independent route fields were hidden or changed in the inspector.");
        var other = ParameterValues.Build(Call("other.dll")).Single(row => row.Parameter == 1);
        Require(other.Children.All(row => !row.Name.StartsWith("field +0x", StringComparison.Ordinal)),
            "A route-only field display was applied to an unrelated module.");
    }
}

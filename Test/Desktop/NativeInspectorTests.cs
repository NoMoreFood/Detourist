using Detourist.Desktop;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media.Imaging;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows;
using static Detourist.Desktop.Tests.Program;

namespace Detourist.Desktop.Tests;

public static partial class Program
{
    private static CheckBox ShowRawSlots(ParameterGrid grid)
    {
        var raw = (CheckBox)grid.FindName("RawCheck");
        Require(raw.Visibility == Visibility.Visible && raw.IsChecked == false,
            "Raw ABI slots were hidden or enabled by default.");
        raw.IsChecked = true;
        raw.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
        var properties = (DataGrid)grid.FindName("PropertiesGrid");
        Require(properties.Items.Cast<ParameterProperty>().Count(value => value.Parameter >= 0) == 32,
            "The raw-slots control lost captured ABI slots.");
        return raw;
    }

    internal static void CheckToolbarBounds(ParameterGrid grid, FrameworkElement control)
    {
        foreach (var scale in new[] { 1.0, 1.5 })
        {
            grid.LayoutTransform = new ScaleTransform(scale, scale);
            grid.Measure(new Size(480, 360));
            grid.Arrange(new Rect(0, 0, 480, 360));
            grid.UpdateLayout();
            var bounds = control.TransformToAncestor(grid).TransformBounds(new Rect(control.RenderSize));
            Require(control.ActualWidth > 0 && bounds.Left >= 0 && bounds.Right <= grid.ActualWidth,
                $"The {control.Name} control clips at {scale:P0} scale.");
        }
    }

    internal static void TruncateSnapshot(JsonNode snapshot, int bytes)
    {
        snapshot["bytes"] = snapshot["bytes"]!.GetValue<string>()[..(bytes * 2)];
        snapshot["flags"] = snapshot["flags"]!.GetValue<int>() | 1;
    }

    private static void InspectAuthzAccess(JsonDocument details)
    {
        foreach (var item in details.RootElement.EnumerateArray()) AuthzAccessInspectorTests.Verify(item);
        Console.WriteLine("AuthZ authorization request and decision inspector views passed.");
    }

    private static void InspectAuthzAudit(JsonDocument details)
    {
        var checkedLayout = false;
        // Native audit calls retain opaque handles, typed scalar values and bounded referenced structures.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var call = item.GetProperty("call");
            var expected = item.GetProperty("expected");
            var rows = ParameterValues.Build(call);
            var count = Math.Min(32, expected.Items("arguments").Length);
            Require(call.Items("arguments").Length == count, "Unrelated audit stack slots were exposed.");
            Require(rows.Single(value => value.Parameter == 1).Children.Count == 0,
                "An opaque audit handle was expanded as memory.");
            if (expected.TryGetProperty("outputIndex", out var outputIndex))
            {
                var output = rows.Single(value => value.Parameter == outputIndex.GetInt32());
                if (expected.Number("result") != 0)
                    Require(output.Children.Count == 1 && output.Children[0].Children.Count == 1 &&
                        output.Children[0].Children[0].Output == (ulong)expected.Number("handle"),
                        "The returned audit handle lost its scalar value.");
                else Require(output.Children.Count == 0, "A failed audit creation exposed a stale handle.");
                continue;
            }
            Require(rows.Single(value => value.Parameter == 3).Children.Single().InputText
                .StartsWith("S-1-5-21-42"),
                "The reporting SID was not decoded.");
            if (call.Text("name") == "AuthzReportSecurityEventFromParams")
            {
                AuthzAuditInspectorTests.Verify(item, rows);
                continue;
            }
            Require(rows.Where(value => value.Parameter >= 5 && value.Parameter < count)
                .All(value => value.Name.Contains("audit[")), "Audit argument names were lost.");
            var label = expected.Text("label");
            if (label is "window" or "extended-window" or "unknown" or "unknown-tail")
                Require(rows.Any(value => value.Parameter == -3 && value.InputLabel == "<not captured>"),
                    "An unsupported or uncaptured audit tail was hidden.");
            if (label == "values")
            {
                Require(rows.Single(value => value.Parameter == 10).Children.Count == 0,
                    "An APT_Pointer value was dereferenced.");
                Require(rows.Single(value => value.Parameter == 12).Children.Single().TypeName == "GUID",
                    "The audit GUID lost its layout.");
            }
            if (label == "aggregates")
            {
                Require(rows.Single(value => value.Parameter == 6).Children.Any(value => value.Name == "LowPart"),
                    "A by-value logon identifier was treated as a pointer.");
                var types = rows.Single(value => value.Parameter == 12).Children.Single();
                Require(types.Children.Single(value => value.Name == "pObjectTypes").Children.Count == 1,
                    "The audit object-type array was not attached to its pointer field.");
            }
            if (label == "flags")
                Require(rows.Single(value => value.Parameter == 9).Name.EndsWith("objectTypeIndex") &&
                    rows.Single(value => value.Parameter == 10).Name.EndsWith("audit[2].type") &&
                    rows.Single(value => value.Parameter == 14).SignatureType.Name == "GUID *",
                    "Audit control flags shifted subsequent argument types.");
            if (label is "empty-objects" or "guarded-header")
                Require(rows.Single(value => value.Parameter == 6).Children.Single().Children
                    .Single(value => value.Name == "pObjectTypes").Children.Count == 0,
                    "An empty or unreadable audit header exposed referenced memory.");
            if (label == "flags" && !checkedLayout)
            {
                var grid = new ParameterGrid();
                grid.ShowCall(call);
                var raw = ShowRawSlots(grid);
                CheckToolbarBounds(grid, raw);
                checkedLayout = true;
            }
        }
        Console.WriteLine("AuthZ audit handle and typed argument inspector views passed.");
    }

    private static void InspectAviSave(JsonDocument details)
    {
        // Real save calls expose a typed pair per captured stream and an explicit capture-window remainder.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var call = item.GetProperty("call");
            var expected = item.GetProperty("expected");
            var count = (int)expected.Number("count");
            var observed = Math.Clamp(count, 0, 14);
            var rows = ParameterValues.Build(call);
            Require(call.Items("arguments").Length == Math.Max(6, 4 + observed * 2),
                "The AVI call retained unrelated stack arguments.");
            for (var index = 0; index < observed; ++index)
            {
                var stream = rows.Single(value => value.Parameter == 4 + index * 2);
                var options = rows.Single(value => value.Parameter == 5 + index * 2);
                Require(stream.Name.EndsWith($"streams[{index}]") && stream.Children.Count == 0,
                    "An AVI stream pointer was expanded as arbitrary memory.");
                Require(options.Name.EndsWith($"options[{index}]") &&
                    options.Children.Single().TypeName == "AVICOMPRESSOPTIONS",
                    "Compression options lost their per-stream declaration.");
                var fields = options.Children.Single().Children;
                foreach (var (name, offset) in new[] { ("lpFormat", 24), ("lpParms", 40) })
                {
                    var field = fields.Single(value => value.Name == name);
                    Require(field.Children.Count == (item.Number("limit") >= offset + 12 ? 1 : 0),
                        "A compression buffer was missing or expanded beyond its captured option fields.");
                }
            }
            Require(rows.Any(value => value.Parameter == -3 && value.InputText == "<not captured>") ==
                (count > observed), "The AVI inspector concealed streams beyond its argument window.");
        }
        Console.WriteLine("AVI stream pairs, option fields and bounded referenced buffers passed.");
    }

    private static void InspectPlaysound(JsonDocument details)
    {
        // The actual captured flags distinguish text and identifiers from binary WAVE data.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var call = item.GetProperty("call");
            var parameter = ParameterValues.Build(call).Single(value => value.Parameter == 0);
            var snapshots = call.Items("input").Where(value => value.Number("parameter") == 0).ToArray();
            if (snapshots.Length == 0)
            {
                Require(parameter.Children.Count == 0, "A sound identifier was expanded as pointed-to data.");
                continue;
            }
            var memory = parameter.Children.Single();
            Require(memory.InputText.StartsWith('"') == (item.Text("mode") == "text") &&
                memory.Children.Count == 0, $"Incorrect sound inspector view for {call.Text("name")} " +
                $"({item.Text("mode")}): {memory.InputText}; {memory.Children.Count} children.");
            Require(memory.InputText.Contains("truncated") == ((snapshots[0].Number("flags") & 1) != 0),
                "A sound buffer lost its capture-limit indication.");
        }
        Console.WriteLine("Sound identifiers, names and bounded WAVE inspector views passed.");
    }

    private static void InspectMru(JsonDocument details)
    {
        // Live MRU calls expose full handles and preserve the buffer's observed text or binary mode.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var call = item.GetProperty("call");
            var rows = ParameterValues.Build(call);
            var name = call.Text("name");
            if (name == "CreateMRUListW")
            {
                var result = rows.Single(value => value.Parameter == -1);
                Require(result.Type.Bits == 64 && result.Children.Count == 0,
                    "An MRU factory result lost its full opaque handle.");
                continue;
            }
            if (name == "FreeMRUList") continue;
            var output = name == "EnumMRUListW";
            var parameter = output ? 2 : 1;
            var snapshots = call.Items(output ? "output" : "input")
                .Where(value => value.Number("parameter") == parameter).Select(MemorySnapshot.FromJson).ToArray();
            if (snapshots.Length == 0) continue;
            var sample = snapshots.Single();
            var parent = rows.Single(value => value.Parameter == parameter);
            var memory = parent.Children.Single();
            var text = output ? memory.OutputText : memory.InputText;
            Require(text.StartsWith('"') == (sample.Kind == 1) && memory.Children.Count == 0,
                "An MRU buffer was interpreted using the wrong list mode.");
            Require(text.Contains("truncated") == ((sample.Flags & 1) != 0),
                "An MRU buffer lost its capture-limit indication.");
        }
        Console.WriteLine("MRU handles and bounded text/binary inspector views passed.");
    }

    private static void InspectWgl(JsonDocument details)
    {
        // Actual driver calls retain opaque contexts, bounded glyph records and typed extension results.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var call = item.GetProperty("call");
            var rows = ParameterValues.Build(call);
            var name = call.Text("name");
            foreach (var handle in rows.Where(value => value.TypeName == "HGLRC"))
                Require(handle.Type.Kind == "Integer" && handle.Children.Count == 0,
                    "An opaque rendering context exposed a dummy SDK structure.");
            if (name.StartsWith("wglUseFontOutlines", StringComparison.Ordinal))
            {
                var parent = rows.Single(value => value.Parameter == 7);
                var captured = call.Items("output").Where(value => value.Number("parameter") == 7)
                    .Select(MemorySnapshot.FromJson).SingleOrDefault();
                if (captured is null) continue;
                var array = parent.Children.Single(value => value.OutputMemory is not null);
                Require(array.OutputMemory!.OriginalBytes == 72, "A glyph array lost its full declared extent.");
                for (var index = 0; index * 24 < captured.Bytes.Length; ++index)
                {
                    var glyph = array.Children.Single(value => value.Name == $"[{index}]");
                    var width = glyph.Children.Single(value => value.Name == "gmfBlackBoxX");
                    var advance = glyph.Children.Single(value => value.Name == "gmfCellIncX");
                    Require(width.Type.Kind == "Float32" && width.Output ==
                        MemorySnapshot.Scalar(captured.Bytes, index * 24, 4) && advance.Output ==
                        (captured.Bytes.Length >= index * 24 + 20 ?
                            MemorySnapshot.Scalar(captured.Bytes, index * 24 + 16, 4) : null),
                        "A glyph metric lost its floating-point type or expanded beyond captured bytes.");
                }
            }
            else if (name.StartsWith("wglGetPixelFormatAttrib", StringComparison.Ordinal))
            {
                var parent = rows.Single(value => value.Parameter == 5);
                var captured = call.Items("output").Where(value => value.Number("parameter") == 5)
                    .Select(MemorySnapshot.FromJson).Single();
                var array = parent.Children.Single();
                var elements = array.Children.Where(value => value.Output.HasValue).ToArray();
                Require(elements.Length == captured.Bytes.Length / 4 && elements.All(value =>
                    value.Type.Kind == (name.Contains("fvARB") ? "Float32" : "Integer")),
                    "Driver attributes lost their array extent or integer/floating-point type.");
                for (var index = 0; index < elements.Length; ++index)
                    Require(elements[index].Output == MemorySnapshot.Scalar(captured.Bytes, index * 4, 4),
                        "A driver attribute differs from its recorded output bytes.");
            }
            else if (name.StartsWith("wglGetExtensionsString", StringComparison.Ordinal))
            {
                var result = rows.Single(value => value.Parameter == -1);
                var text = result.Children.Single();
                Require(result.Type.Kind == "Pointer" && text.Type.Kind == "Pointer" &&
                    text.OutputText.StartsWith("\"WGL_", StringComparison.Ordinal) &&
                    text.OutputMemory is { } captured &&
                    text.OutputText.Contains("truncated") == ((captured.Flags & 1) != 0),
                    "An extension string lost its return-value ownership, text or truncation state.");
            }
            else if (name == "wglGetSwapIntervalEXT")
                Require(rows.Single(value => value.Parameter == -1).Type is
                    { Kind: "Integer", Bits: 32, Signed: true }, "A zero swap interval was not a signed result.");
        }
        Console.WriteLine("WGL contexts, glyph arrays, driver attributes and returned extension strings passed.");
    }

    private static void InspectCrtCountedStrings(JsonDocument captures)
    {
        // Real formatter calls establish descriptor ownership, provider encodings and bounded text.
        foreach (var capture in captures.RootElement.EnumerateArray())
        {
            var call = capture.GetProperty("call");
            var parameter = capture.Number("parameter");
            var rows = ParameterValues.Build(call);
            if (capture.Text("case") == "FLOAT")
            {
                Require(rows.Count(value => value.Parameter >= parameter) == 32 - parameter &&
                    rows.Where(value => value.Parameter >= parameter).All(value =>
                    value.Name == $"[{value.Parameter}] arg{value.Parameter}"),
                    "An unsupported NTDLL floating directive shifted or typed the remaining raw arguments.");
                continue;
            }
            var parent = rows.Single(value => value.Parameter == parameter);
            if (capture.GetProperty("listed").GetBoolean())
                parent = parent.Children.Single(value => value.Name == "[0] counted[1]");
            Require(parent.TypeName == (capture.GetProperty("wide").GetBoolean() ?
                "UNICODE_STRING *" : "ANSI_STRING *"),
                $"A CRT counted string lost its provider type: {call.Text("module")}!{call.Text("name")}: " +
                $"{parent.Name} {parent.TypeName}.");
            var descriptor = parent.Children.Single(value => value.Children.Any(field => field.Name == "Buffer"));
            Require(new[] { "Length", "MaximumLength", "Buffer" }.All(name =>
                descriptor.Children.Any(field => field.Name == name)), "A counted descriptor lost its fields.");
            var buffer = descriptor.Children.Single(value => value.Name == "Buffer");
            var label = capture.Text("label");
            if (label == "NO_DESCRIPTOR")
            {
                Require(buffer.Input is null && buffer.Children.Count == 0,
                    "An unavailable counted descriptor fabricated a buffer.");
                continue;
            }
            var text = buffer.Children.Single(value => value.Name == "Text");
            var samples = call.Items("input").Where(item => item.Number("parameter") == parameter)
                .Select(MemorySnapshot.FromJson).Where(value =>
                    value.ElementIndex <= 0 && (value.Flags & 8) != 0).ToArray();
            if (label is "NULL" or "NULL_EMPTY") Require(text.InputText == "<null>" && text.InputMemory is null,
                "A null counted buffer fabricated text.");
            else if (label == "EMPTY") Require(text.InputText == "\"\"" && text.InputMemory?.Bytes.Length == 0,
                "An empty counted value was followed or lost its known empty text.");
            else
            {
                Require(samples.Length == 1 && text.InputMemory?.Bytes.SequenceEqual(samples[0].Bytes) == true,
                    "Counted text lost its descriptor association or captured byte prefix.");
                if (label == "EMBED") Require(text.InputText.Contains("\\0", StringComparison.Ordinal),
                    "A counted string discarded its embedded null.");
                if (label == "LONG") Require(text.InputText.Contains("truncated", StringComparison.Ordinal),
                    "A capped counted string lost its truncation state.");
            }

            // Incomplete recorded descriptors do not establish their referenced text.
            var altered = JsonNode.Parse(call.GetRawText())!;
            var header = altered["input"]!.AsArray().Single(item => item!["parameter"]!.GetValue<int>() ==
                parameter && item["kind"]!.GetValue<int>() == 0 &&
                (item["flags"]!.GetValue<int>() & 8) == 0 &&
                (!capture.GetProperty("listed").GetBoolean() ||
                    (item["flags"]!.GetValue<int>() & 64) != 0 && item["flags"]!.GetValue<int>() >> 16 == 0));
            TruncateSnapshot(header!, 12);
            using var partial = JsonDocument.Parse(altered.ToJsonString());
            parent = ParameterValues.Build(partial.RootElement).Single(value => value.Parameter == parameter);
            if (capture.GetProperty("listed").GetBoolean())
                parent = parent.Children.Single(value => value.Name == "[0] counted[1]");
            buffer = parent.Children.Single(value => value.Children.Any(field => field.Name == "Buffer"))
                .Children.Single(value => value.Name == "Buffer");
            Require(buffer.Input is null && buffer.Children.Count == 0,
                "A partial counted descriptor exposed a pointer or referenced text.");
        }
        Console.WriteLine("Counted format structures, text ownership, partial descriptors and raw fallback passed.");
    }

    private static void InspectShellMessages(JsonDocument captures)
    {
        foreach (var capture in captures.RootElement.EnumerateArray()) ShellMessageInspectorTests.Verify(capture);
        Console.WriteLine("Message insert types, numbered slots, guarded text and raw fallback passed.");
    }

    private static void InspectPromptUser(JsonDocument captures)
    {
        // Template-selected prompt inserts keep their title and insert encodings as quoted text.
        foreach (var capture in captures.RootElement.EnumerateArray())
        {
            var sample = capture.GetProperty("sample");
            var rows = ParameterValues.Build(capture.GetProperty("call"));
            var inserts = (int)sample.Number("inserts");
            Require(rows.Count(value => value.Parameter >= 0) == 3 + inserts,
                "A prompt call retained variable slots its template does not consume.");
            var expected = new List<(string Name, bool Wide, string Text)>
                { ("title", sample.GetProperty("wide").GetBoolean(), sample.Text("title")) };
            if (inserts > 0)
                expected.Add(("userType", sample.GetProperty("insertWide").GetBoolean(), sample.Text("insert")));
            for (var index = 0; index < expected.Count; ++index)
            {
                var row = rows.Single(value => value.Parameter == index + 2);
                Require(row.Name == $"[{index + 2}] {expected[index].Name}" &&
                    row.TypeName == (expected[index].Wide ? "wchar_t *" : "char *") &&
                    row.Children.Any(value => value.InputText.StartsWith('"') &&
                        value.InputText.Contains(expected[index].Text, StringComparison.Ordinal)),
                    $"Prompt {sample.Number("id")} lost its {expected[index].Name} type or text.");
            }
        }
        Console.WriteLine("Prompt titles, template inserts and consumed slots passed.");
    }

    private static void InspectTraceLogging(JsonDocument captures)
    {
        // A macro-built TraceLogging event decodes every field from its own provider and event metadata.
        var call = captures.RootElement[0];
        var nodes = Flatten(ParameterValues.Build(call));
        var decoded = nodes.Single(value => value.Name == "TraceLogging event");
        Require(decoded.InputText == "Detourist.TraceLogging/DetouristEvent",
            "A TraceLogging event lost its provider or event name.");
        var expected = new (string Name, string Text)[]
        {
            ("Signed", "-42"), ("Unsigned", "4886718345"), ("Hex", "0xBEEF"), ("Wide", "\"wide text\""),
            ("Narrow", "\"narrow text\""), ("Counted", "\"counted\""), ("Flag", "True (1)"),
            ("Guid", "{01234567-89ab-cdef-0102-030405060708}"), ("Values", "[7, 8, 9]"),
            ("Blob", "010203"), ("Result", "0x80004005")
        };
        foreach (var (name, text) in expected)
            Require(decoded.Children.Single(value => value.Name == name).InputText == text,
                $"TraceLogging field {name} decoded incorrectly.");
        var point = decoded.Children.Single(value => value.Name == "Point");
        Require(point.Children.Select(value => (value.Name, value.InputText))
            .SequenceEqual([("X", "3"), ("Y", "4")]), "A TraceLogging structure lost its member fields.");
        Console.WriteLine("TraceLogging provider, event, scalar, string, array and structure fields passed.");
    }

    private static void InspectWindowComposition(JsonDocument captures)
    {
        // Composition attributes select pvData layouts; returned button captions remain UTF-16 text.
        foreach (var capture in captures.RootElement.EnumerateArray())
        {
            var rows = ParameterValues.Build(capture.GetProperty("call"));
            if (capture.Text("kind") == "string")
            {
                Require(rows.Single(value => value.Parameter == -1).Children.Any(value =>
                    value.OutputText.StartsWith('"') &&
                    value.OutputText.Contains(capture.Text("text"), StringComparison.Ordinal)),
                    "A returned button caption lost its UTF-16 text.");
                continue;
            }
            var nodes = Flatten([rows.Single(value => value.Parameter == 1)]);
            var name = capture.Text("name");
            var data = Convert.FromHexString(capture.Text("data"));
            var written = capture.GetProperty("set").GetBoolean();
            Require(nodes.Any(value => value.Name == "Attrib" &&
                value.InputText.StartsWith(name + " (", StringComparison.Ordinal)),
                $"{name} lost its composition attribute name.");
            var pointer = nodes.Single(value => value.Name == "pvData");
            if (capture.GetProperty("type").ValueKind != JsonValueKind.String)
            {
                Require(pointer.TypeName == "void *" && pointer.Children.Any(value =>
                    (written ? value.InputMemory : value.OutputMemory)?.Bytes.SequenceEqual(data) == true),
                    $"{name} data without a confirmed layout lost its raw bytes.");
                continue;
            }
            var type = capture.Text("type");
            var region = pointer.Children.Single();
            var fields = type == "RECT" ? new[] { "left", "top", "right", "bottom" } : ["Value"];
            Require(pointer.TypeName == type + " *" && fields.Select((field, index) =>
                region.Children.Single(value => value.Name == field) is var node &&
                (written ? node.Input : node.Output) == MemorySnapshot.Scalar(data, index * 4, 4))
                .All(value => value), $"{name} data lost its {type} layout or values.");
            if (type.StartsWith("DWM", StringComparison.Ordinal))
            {
                var value = region.Children.Single();
                Require(value.Type.Kind == "Enum" &&
                    (written ? value.InputText : value.OutputText).StartsWith("DWM", StringComparison.Ordinal),
                    $"{name} data lost its DWM enumeration name.");
            }
        }
        Console.WriteLine("Composition attribute names, selected pvData layouts and button captions passed.");
    }

    private static void InspectLegacyFormats(JsonDocument captures)
    {
        foreach (var capture in captures.RootElement.EnumerateArray()) LegacyFormatInspectorTests.Verify(capture);
        Console.WriteLine("Legacy format slots, pointer ownership, scalar types and count storage passed.");
    }

    private static void InspectScanFormats(JsonDocument captures)
    {
        foreach (var capture in captures.RootElement.EnumerateArray()) ScanFormatInspectorTests.Verify(capture);
        Console.WriteLine("Scan destination types, assigned values, count storage and argument lists passed.");
    }

    private static void InspectLocaleFormats(JsonDocument captures)
    {
        foreach (var capture in captures.RootElement.EnumerateArray()) LocaleFormatInspectorTests.Verify(capture);
        Console.WriteLine("Locale-specific source bytes, argument types and capture limits passed.");
    }

    private static void InspectPositionalRecords(JsonDocument captures)
    {
        var layouts = new HashSet<bool>();
        foreach (var capture in captures.RootElement.EnumerateArray())
        {
            PositionalRecordInspectorTests.Verify(capture);
            if (capture.Number("limit") == 96 && capture.Text("case") == "DUAL" &&
                capture.Text("sample") == "FULL" && layouts.Add(capture.GetProperty("listed").GetBoolean()))
                PositionalRecordInspectorTests.VerifyPartialAndLayout(capture);
        }
        Console.WriteLine("Positional counted record views, pointer conflicts and bounded fields passed.");
    }

    private static void InspectCrtCounts(JsonDocument captures)
    {
        var checkedLayout = false;
        // Installed providers establish count widths independently of a presumed format declaration.
        foreach (var capture in captures.RootElement.EnumerateArray())
        {
            var rows = ParameterValues.Build(capture.GetProperty("call"));
            if (!capture.GetProperty("listed").GetBoolean() && capture.Text("case") != "INVALID")
            {
                var call = capture.GetProperty("call");
                Require(rows.Count(value => value.Parameter >= 0) == 5 &&
                    ParameterValues.Build(call, rawSlots: true).Count(value => value.Parameter >= 0) == 32,
                    "A complete formatter lost consumed arguments or its optional raw ABI slots.");
                var grid = new ParameterGrid();
                grid.ShowCall(call);
                var raw = ShowRawSlots(grid);
                if (!checkedLayout)
                {
                    CheckToolbarBounds(grid, raw);
                    checkedLayout = true;
                }
                grid.Clear();
                Require(raw.Visibility == Visibility.Collapsed && raw.IsChecked == false,
                    "Clearing the view retained stale raw-slot state.");
            }
            var parameter = capture.Number("parameter");
            var element = (int)capture.Number("element");
            var parent = rows.Single(value => value.Parameter == parameter);
            if (capture.Text("case") == "INVALID")
            {
                var rawNodes = Flatten([parent]);
                var size = (int)capture.Number("size");
                Require(rawNodes.All(value => value.Name != "Count") && rawNodes.Any(value =>
                    value.InputMemory is { } memory && memory.Bytes.Length == size &&
                    MemorySnapshot.Scalar(memory.Bytes, 0, size) ==
                        capture.GetProperty("before").GetUInt64()) &&
                    rawNodes.Any(value => value.OutputMemory is { } memory && memory.Bytes.Length == size &&
                        MemorySnapshot.Scalar(memory.Bytes, 0, size) ==
                            capture.GetProperty("after").GetUInt64()),
                    "An incomplete format lost its raw count snapshots or inferred a complete contract.");
                continue;
            }
            if (capture.GetProperty("listed").GetBoolean())
                parent = parent.Children.Single(value => value.Name == $"[{element}] count[{element + 1}]");
            Require(parent.TypeName == $"Int{capture.Number("size") * 8} *",
                $"A CRT count pointer lost its provider-specific integer width: " +
                $"{capture.GetProperty("call").Text("module")}!" +
                $"{capture.GetProperty("call").Text("name")}: {parent.Name} {parent.TypeName}; " +
                $"expected Int{capture.Number("size") * 8} *.");
            var count = parent.Children.Single(value => value.Name == "Count");
            Require(count.SignatureType.Bits == capture.Number("size") * 8,
                "A CRT count lost its provider-specific integer width.");
            if (capture.GetProperty("before").ValueKind == JsonValueKind.Null)
            {
                Require(count.Input is null && count.Output is null &&
                    count.InputText.Contains("unreadable", StringComparison.Ordinal) &&
                    count.OutputText.Contains("unreadable", StringComparison.Ordinal),
                    "An inaccessible count destination displayed an invented value.");
                continue;
            }
            Require(count.Input == capture.GetProperty("before").GetUInt64() &&
                count.Output == capture.GetProperty("after").GetUInt64() &&
                count.InputMemory?.Bytes.Length == capture.Number("size") &&
                count.OutputMemory?.Bytes.Length == capture.Number("size"),
                "A CRT count lost its before or after state across a partial or disabled write.");

            // Partial recorded integers retain their type and a partial label rather than a scalar value.
            if (capture.Number("size") <= 1) continue;
            foreach (var phase in new[] { "input", "output" })
            {
                var altered = JsonNode.Parse(capture.GetProperty("call").GetRawText())!;
                var sample = altered[phase]!.AsArray().Single(item => item!["parameter"]!.GetValue<int>() ==
                    parameter && item["kind"]!.GetValue<int>() == 0 &&
                    (!capture.GetProperty("listed").GetBoolean() ||
                        item["elementIndex"]?.GetValue<int>() == element));
                TruncateSnapshot(sample!, 1);
                using var partial = JsonDocument.Parse(altered.ToJsonString());
                parent = ParameterValues.Build(partial.RootElement)
                    .Single(value => value.Parameter == parameter);
                if (capture.GetProperty("listed").GetBoolean())
                    parent = parent.Children.Single(value => value.Name == $"[{element}] count[{element + 1}]");
                count = parent.Children.Single(value => value.Name == "Count");
                Require(phase == "input" ? count.Input is null &&
                    count.InputText.StartsWith("<partial:", StringComparison.Ordinal) : count.Output is null &&
                    count.OutputText.StartsWith("<partial:", StringComparison.Ordinal),
                    "A partial CRT count was displayed as a complete integer.");
            }
        }
        Console.WriteLine("CRT count output types and property-grid values passed.");
    }

    private static void InspectBerVariadic(JsonDocument captures)
    {
        foreach (var capture in captures.RootElement.EnumerateArray())
        {
            var call = capture.GetProperty("call");
            var rows = ParameterValues.Build(call);
            var nodes = Flatten(rows);
            var samples = call.Items("input").Where(item => item.Number("parameter") == 1).ToArray();
            var format = samples.Length == 0 ? "" : System.Text.Encoding.Latin1.GetString(
                Convert.FromHexString(samples[0].Text("bytes"))).TrimEnd('\0');
            var encoded = call.Text("name") == "ber_printf";

            // Real provider calls establish names, scalar widths, allocated outputs and binary ownership.
            if (format.StartsWith("{tbienosX", StringComparison.Ordinal))
            {
                Require(rows[2].Name == "[2] tag[1]" && rows[2].Type.Bits == 32 &&
                    rows[4].Name == "[4] integer[3]" && rows[4].Type.Sign(rows[4].Input!.Value) == 3 &&
                    rows[5].Name == "[5] enumeration[4]" && rows[5].Type.Sign(rows[5].Input!.Value) == -7 &&
                    rows[7].Name == "[7] length[6]" && rows[7].Type.Bits == 32 &&
                    rows[11].TypeName == "char **" && rows[12].TypeName == "BERVAL **",
                    "BER encoding arguments did not retain their format names and SDK widths: " +
                        string.Join(", ", rows.Where(row => row.Parameter >= 0).Take(13).Select(row =>
                            $"{row.Name} {row.TypeName}/{row.Type.Bits} {row.InputText}")));
            }
            if (format.StartsWith("{beinOaBvV", StringComparison.Ordinal))
            {
                Require(rows[2].Name == "[2] boolean[1]" && rows[2].TypeName == "ber_int_t *" &&
                    rows[2].Children.Single().SignatureType.Sign(rows[2].Children.Single().Output!.Value) == -1 &&
                    rows[4].Children.Single().SignatureType.Sign(rows[4].Children.Single().Output!.Value) == -7 &&
                    rows[8].Name == "[8] bitCount[7]" && rows[8].Children.Single().Output == 9 &&
                    rows[9].TypeName == "char ***" && rows[10].TypeName == "BERVAL ***",
                    "BER decoding arguments lost their pointer types or completed scalar values.");
            }
            if (!encoded && format == "{ti}")
                Require(rows[2].Name == "[2] integer[1]" && rows[2].Children.Single().Output == 7 &&
                    rows[3].Name == "[3] arg3",
                    "An ignored decoder tag shifted the following integer or named an uncaptured tag output.");
            if (!encoded && format == "t")
                Require(rows[2].Name == "[2] arg2" && rows[2].Children.Count == 0,
                    "An ignored decoder tag exposed a phantom output.");
            foreach (var descriptor in nodes.Where(node => node.TypeName == "BERVAL"))
            {
                var snapshot = encoded ? descriptor.InputMemory : descriptor.OutputMemory;
                Require(snapshot is not null && descriptor.Children.Any(field => field.Name == "bv_len") &&
                    descriptor.Children.Any(field => field.Name == "bv_val"),
                    "A captured BERVAL did not expose its known length and pointer fields.");
                var pointer = descriptor.Children.Single(field => field.Name == "bv_val");
                if (snapshot!.Bytes.Length < 16)
                    Require(pointer.Input is null && pointer.Output is null && pointer.Children.Count == 0,
                        "An incomplete BERVAL pointer exposed uncaptured data.");
                foreach (var bytes in pointer.Children)
                {
                    var data = encoded ? bytes.InputMemory : bytes.OutputMemory;
                    Require(data is not null && data.Bytes.Length <= capture.Number("limit") &&
                        data.OriginalBytes == MemorySnapshot.Scalar(snapshot.Bytes, 0, 4),
                        "BERVAL bytes lost their counted extent or exceeded the global capture limit.");
                }
            }
            if (format == "!s") Require(rows[2].Name == "[2] arg2",
                "An unknown BER token inferred later argument identities.");
            if (format.StartsWith("{i!", StringComparison.Ordinal))
                Require(rows[2].Name == "[2] integer[1]" &&
                    rows[3].Name == (encoded ? "[3] arg3" : "[3] text[2]"),
                    "BER inference lost the encoder stop or decoder recovery after an unknown token.");
            if (!encoded && format.Length == 11 && format[1] == '{' && format[2] == 'i' &&
                format[4] == 'a' && format[6] == 'B' && format[8] == 'i')
            {
                Require(rows[2].Name == "[2] integer[1]" && rows[2].Children.Single().Output == 7 &&
                    rows[3].Name == "[3] text[2]" && rows[3].TypeName == "char **" &&
                    rows[4].Name == "[4] bits[3]" && rows[4].TypeName == "char **" &&
                    rows[5].Name == "[5] bitCount[4]" && rows[5].Children.Single().Output == 9 &&
                    rows[6].Name == "[6] integer[5]" && rows[6].Children.Single().Output == 9,
                    "An ignored BER byte shifted a scalar, allocated output or paired argument.");
                Require(nodes.Any(node => node.OutputMemory is { Kind: 0 } text &&
                        text.Bytes.AsSpan().SequenceEqual("OK\0"u8)) &&
                    nodes.Any(node => node.OutputMemory is { Kind: 0 } bits &&
                        bits.Bytes.AsSpan().SequenceEqual(new byte[] { 0xA5, 0x80 })),
                    "The inspector lost decoded text or bit bytes after an ignored BER token.");
            }
            if (format.StartsWith("{iiii", StringComparison.Ordinal))
            {
                var integers = format.Skip(1).TakeWhile(value => value == 'i').Count();
                for (var index = 2; index < Math.Min(32, integers + 2); ++index)
                    Require(rows[index].Name == $"[{index}] integer[{index - 1}]" &&
                        (encoded ? rows[index].Type.Bits == 32 :
                            rows[index].Children.Single().OutputMemory?.Bytes.Length == 4),
                        "A late BER integer lost its type or decoded output.");
                if (capture.Number("limit") == 64 && integers <= 28)
                    Require(rows[integers + 2].Name == $"[{integers + 2}] text[{integers + 1}]",
                        "The BER inspector lost a late string argument.");
                if (capture.Number("limit") == 64 && integers == 27)
                    Require(rows[31].Name == "[31] bitCount[30]" && (encoded ?
                        (rows[31].Input & uint.MaxValue) == 9 :
                        rows[31].Children.Single().Output == 9),
                        "A BER pair ending at the capture limit lost its bit count.");
                if (capture.Number("limit") == 64 && integers == 28)
                    Require(rows[31].Name == "[31] arg31", "An incomplete BER pair inferred a missing extent.");
            }
            if (!encoded && (new ParameterType("UInt64").Parse(call.Text("result"), true) &
                uint.MaxValue) == uint.MaxValue)
                Require(nodes.Where(node => node.Parameter == 2 || node.Level > 0 &&
                    node.Name == "Decoded value").All(node => node.OutputMemory is null && node.Output is null),
                    "A failed BER decode exposed stale output values.");
            Require(rows.Count(row => row.Parameter >= 0) == call.Items("arguments").Length,
                "BER format inference concealed unresolved raw slots.");
        }
        Console.WriteLine("PASS: BER format names, SDK types, decoded values and expandable bounded BERVALs.");
    }
}

public static class AuthzAccessInspectorTests
{
    public static void Verify(JsonElement item)
    {
        var call = item.GetProperty("call");
        var expected = item.GetProperty("expected");
        var limit = (int)item.Number("limit");
        var rows = ParameterValues.Build(call);
        var cached = call.Text("name") == "AuthzCachedAccessCheck";
        Require(rows.Single(value => value.Parameter == 1).Children.Count == 0,
            "An opaque authorization handle was expanded.");
        var request = rows.Single(value => value.Parameter == 2).Children.Single();
        Require(request.TypeName == "AUTHZ_ACCESS_REQUEST", "The authorization request lost its SDK layout.");
        Require(request.Children.Single(value => value.Name == "PrincipalSelfSid").Children.Single()
            .InputText.StartsWith("S-1-5-21-42"), "The request's principal SID was not decoded.");
        Require(request.Children.Single(value => value.Name == "OptionalArguments").Children.Count == 0,
            "The opaque callback argument was dereferenced.");
        var objects = request.Children.Single(value => value.Name == "ObjectTypeList");
        if (expected.Text("label") is "objects" or "optional" && limit >= 28)
        {
            var table = objects.Children.Single();
            var records = table.Children.Where(value => !value.Name.Contains('…')).ToArray();
            Require(records.Length == Math.Min(7, (limit + 15) / 16), "The object-type array extent was lost.");
            Require(records.Take(Math.Min(7, limit / 16)).All(record => record.Children
                .Single(value => value.Name == "ObjectType").Children.Single().TypeName == "GUID"),
                "An object-type GUID was not attached to its complete record.");
        }
        else Require(objects.Children.Count == 0, "An absent object-type array was expanded.");
        if (!cached)
        {
            var descriptor = rows.Single(value => value.Parameter == 4).Children.Single();
            Require(descriptor.TypeName == "SECURITY_DESCRIPTOR", "The absolute descriptor lost its layout.");
            var owner = descriptor.Children.Single(value => value.Name == "Owner");
            Require(owner.Children.Count == (limit >= 40 ? 1 : 0),
                "Security components escaped a truncated descriptor header.");
            if (expected.Text("label") == "optional")
            {
                var relative = rows.Single(value => value.Parameter == 5).Children.Single().Children.Single()
                    .Children.Single();
                Require(relative.TypeName == "SECURITY_DESCRIPTOR_RELATIVE",
                    "An optional self-relative descriptor was interpreted as absolute pointers.");
                Require(relative.Children.Single(value => value.Name == "Owner").Children.Count ==
                    (limit >= 20 ? 1 : 0),
                    "A relative owner SID did not respect the header capture limit.");
            }
        }
        var reply = rows.Single(value => value.Parameter == (cached ? 4 : 7)).Children.Single();
        Require(reply.Children.Single(value => value.Name == "SaclEvaluationResults").Children.Count == 0,
            "An audit result was fabricated when no auditing was requested.");
        var granted = reply.Children.Single(value => value.Name == "GrantedAccessMask");
        if (expected.Number("result") == 0 || expected.Text("label") == "zero-count")
            Require(granted.Children.Count == 0, "A failed or empty check exposed stale decision arrays.");
        else
        {
            var array = granted.Children.Single();
            Require(array.Children[0].Input is null &&
                array.Children[0].Output == (ulong)expected.Items("granted")[0].GetInt64(),
                "An authorization result lost its output-only direction or value.");
            if (limit >= 32)
                Require(reply.Children.Single(value => value.Name == "Error").Children.Single().Children[0].Output ==
                    (ulong)expected.Items("errors")[0].GetInt64(), "The per-object decision status was lost.");
        }
        if (expected.Text("label") == "optional" && limit == 128)
        {
            var grid = new ParameterGrid();
            grid.ShowCall(call);
            var raw = (CheckBox)grid.FindName("RawCheck");
            Require(raw.Visibility != Visibility.Visible, "A fixed authorization signature exposed raw ABI slots.");
            CheckToolbarBounds(grid, (CheckBox)grid.FindName("TypesCheck"));
        }
    }
}

public static class AuthzAuditInspectorTests
{
    public static void Verify(JsonElement item, List<ParameterProperty> rows)
    {
        var call = item.GetProperty("call");
        var expected = item.GetProperty("expected");
        var label = expected.Text("label");
        var limit = (int)item.Number("limit");
        var root = rows.Single(value => value.Parameter == 4).Children.Single();
        Require(root.TypeName == "AUDIT_PARAMS", "The audit root lost its structure layout.");
        var pointer = root.Children.Single(value => value.Name == "Parameters");
        if (label is "null-root" or "zero-count" || label == "short-root" && limit > 16)
        {
            Require(pointer.Children.Count == 0, "An absent audit array exposed descriptor records.");
            return;
        }
        var array = pointer.Children.Single();
        Require(array.TypeName == "AUDIT_PARAM[]", "The descriptor array was not attached to its pointer.");
        var records = array.Children.Where(value => !value.Name.Contains('…')).ToArray();
        if (limit < 24 || label == "null-array" || label is "short-array" or "large-count" && limit > 48)
        {
            Require(records.Length == 0 && array.Children.Single().ValueText == "<not captured>",
                "An unavailable audit array hid its missing values or expanded unrelated memory.");
            return;
        }
        var requested = label == "typed-array" ? 14 : label == "short-array" ? 2 :
            label == "large-count" ? 65535 : 1;
        Require(records.Length == Math.Min(requested, (limit + 31) / 32),
            "A partial audit record was hidden or uncaptured records were expanded.");
        Require(array.Children.Any(value => value.Name.Contains('…')) == (records.Length < requested),
            "The audit array remainder does not match the capture limit.");
        Require(records.All(record => record.Children.All(value => value.Name != "union")),
            "Inactive audit union members were expanded.");
        if (label is "typed-array" or "short-array" or "large-count")
        {
            Require(records[0].Children.Single(value => value.Name == "String").Children.Single()
                .InputText.StartsWith("\"Audit operation"), "The audit string lost its text interpretation.");
            if (records.Length >= 2)
            {
                var scalar = records[1].Children.Single(value => value.Name == "u");
                Require(scalar.Children.Count == 0, "An opaque audit pointer was dereferenced.");
                if (limit == 40) Require(scalar.Input is null && scalar.InputLabel == "<not captured>",
                    "A partial descriptor fabricated an uncaptured pointer value.");
            }
        }
        if (label == "typed-array" && limit >= 1024)
        {
            Require(records[3].Children.Single(value => value.Name == "psid").Children.Single()
                .InputText == "S-1-5-21-42-7", "A structured audit SID lost its subauthorities.");
            Require(records[4].Children.Single(value => value.Name == "pguid").Children.Single().TypeName == "GUID",
                "A structured audit GUID lost its layout.");
            var objects = records[5].Children.Single(value => value.Name == "pObjectTypes").Children.Single();
            Require(objects.Children.Single(value => value.Name == "pObjectTypes").Children.Single()
                .Children.Count == 2, "The nested audit object array was not attached to its pointer field.");
            Require(records[6].Children.Single(value => value.Name == "Value").Input == 0xffffffff80000001 &&
                records[7].Children.Single(value => value.Name == "Value").Input == 0x89abcdef01234567 &&
                records[8].Children.Single(value => value.Name == "Value").Input == 0xfedcba9876543210,
                "The split audit scalar halves were not reconstructed.");
            Require(records[11].Children.Single(value => value.Name == "pIpAddress").Children.Single()
                .TypeName == "AUDIT_IP_ADDRESS", "The audit address buffer lost its layout.");
            Require(records[13].Children.All(value => value.Children.Count == 0),
                "An unknown audit type expanded a pointer.");
            var grid = new ParameterGrid();
            grid.ShowCall(call);
            Require(((CheckBox)grid.FindName("RawCheck")).Visibility != Visibility.Visible,
                "A fixed structured audit signature exposed the variadic ABI control.");
        }
        if (label is "empty-object-array" or "short-object-header")
            Require(records[0].Children.Single(value => value.Name == "pObjectTypes").Children.Single()
                .Children.Single(value => value.Name == "pObjectTypes").Children.Count == 0,
                "An empty or unreadable object header exposed referenced memory.");
        if (label == "unreadable-guid")
            Require(records[0].Children.Single(value => value.Name == "pguid").Children.Single()
                .InputMemory?.State == "unreadable", "An unreadable audit GUID lost its state.");
    }
}

public static class LegacyFormatInspectorTests
{
    public static void Verify(JsonElement capture)
    {
        var rows = ParameterValues.Build(capture.GetProperty("call"));
        if (capture.GetProperty("raw").GetBoolean())
        {
            Require(rows.Where(value => value.Parameter >= 0).All(value =>
                !value.Name.Contains("format[", StringComparison.Ordinal)),
                "An ambiguous shared report stub inferred a variable argument contract.");
            return;
        }
        var list = capture.GetProperty("list").GetInt32();
        foreach (var field in capture.GetProperty("fields").EnumerateArray())
        {
            var index = field.GetProperty("index").GetInt32();
            if (index >= (list >= 0 ? 32 : 32 - (int)capture.Number("first"))) continue;
            var row = rows.Single(value => value.Parameter == (list >= 0 ? list : capture.Number("first") + index));
            if (list >= 0) row = row.Children.Single(value => value.InputMemory is { Kind: 2 } scalar &&
                scalar.ElementIndex == index && (scalar.Flags & 64) != 0);
            Require(row.TypeName == field.Text("type") && row.Input == field.GetProperty("value").GetUInt64(),
                $"Legacy format type or value mismatch: {capture.Text("module")}!{capture.Text("name")} " +
                    $"{capture.Text("text")} [{index}] {row.TypeName}.");
            if (field.Text("data").Length == 0) continue;
            var nodes = Flatten(row.Children);
            var expected = Convert.FromHexString(field.Text("data"));
            Require(nodes.Any(value => value.InputMemory is { } memory &&
                memory.Bytes.AsSpan().SequenceEqual(expected)), "A legacy formatter lost its referenced input.");
            if (!field.GetProperty("count").GetBoolean()) continue;
            var storage = nodes.Single(value => value.Name == "Count");
            Require(storage.Input.HasValue && storage.OutputMemory is { } output &&
                output.Bytes.AsSpan().SequenceEqual(Convert.FromHexString(field.Text("after"))),
                "A legacy formatter lost before-and-after count storage.");
        }
    }
}

public static class LocaleFormatInspectorTests
{
    public static void Verify(JsonElement capture)
    {
        // Source bytes remain attached to the narrow argument even when its output uses UTF-16 character precision.
        var rows = ParameterValues.Build(capture.GetProperty("call"));
        var argument = rows.Single(value => value.Parameter == capture.Number("parameter"));
        var element = capture.Number("element");
        if (element >= 0) argument = argument.Children.Single(value =>
            value.InputMemory is { Kind: 2 } scalar && scalar.ElementIndex == element);
        Require(argument.TypeName == "char *" && argument.Input == capture.GetProperty("pointer").GetUInt64(),
            "A locale-specific string lost its narrow source pointer or format argument type.");
        var expected = Convert.FromHexString(capture.Text("data"));
        var memories = argument.Children.Where(value => value.InputMemory is { Kind: 0 }).ToArray();
        if (expected.Length == 0)
        {
            Require(memories.Length == 0, "Zero precision read the inaccessible source pointer.");
            return;
        }
        var count = Math.Min(expected.Length, (int)capture.Number("limit"));
        Require(memories.Length == 1 &&
            memories[0].InputMemory!.Bytes.AsSpan().SequenceEqual(expected.AsSpan(0, count)),
            "A locale-specific source lost bytes at a character boundary or exceeded the capture limit.");
        var complete = expected[^1] == 0 && expected.Length <= count;
        Require(memories[0].InputText.Contains("truncated", StringComparison.Ordinal) != complete,
            "The inspector lost a precision-limited or globally capped string's truncation state.");
    }
}

public static class PositionalRecordInspectorTests
{
    public static void Verify(JsonElement item)
    {
        var call = item.GetProperty("call");
        var parent = ParameterValues.Build(call).Single(value => value.Parameter == item.Number("parameter"));
        var nodes = Flatten([parent]);
        var views = item.Text("views").Distinct().ToArray();
        var complete = (item.Text("text").Length + 1) * (item.GetProperty("wide").GetBoolean() ? 2 : 1) <=
            item.Number("limit");
        var ansi = ApiMetadata.Structure("ANSI_STRING")!.Name;
        var unicode = ApiMetadata.Structure("UNICODE_STRING")!.Name;
        var records = nodes.Where(value => value.TypeName == ansi || value.TypeName == unicode).ToArray();

        // An incomplete or incompatible format retains raw memory without choosing a record interpretation.
        if (!complete || views.Length == 0)
        {
            Require(records.Length == 0 && nodes.All(value => value.Name != "Count"),
                "A rejected or incomplete positional format inferred a typed pointer contract.");
            return;
        }
        if (item.GetProperty("listed").GetBoolean())
            parent = parent.Children.Single(value => value.Name == "[0] counted[1]");
        Require(parent.TypeName == (views.Length > 1 ? "void *" :
            views[0] == 'U' ? "UNICODE_STRING *" : "ANSI_STRING *"),
            "A positional pointer selected one record type for incompatible character views.");
        Require(records.Select(value => value.TypeName).SequenceEqual(views.Select(view =>
            view == 'U' ? unicode : ansi)),
            $"A shared positional pointer lost a counted-string view: {call.Text("module")}!{call.Text("name")} " +
                $"{item.Text("case")}/{item.Text("sample")}: " +
                string.Join(", ", nodes.Select(value => value.TypeName)));
        foreach (var record in records)
        {
            var snapshot = record.InputMemory;
            if (item.Text("sample") == "NO_DESCRIPTOR")
            {
                Require(snapshot is null && record.Children.All(value =>
                    value.Input is null && value.Children.Count == 0),
                    "A null counted pointer fabricated descriptor fields or referenced text.");
                continue;
            }
            Require(snapshot is not null && snapshot.Bytes.Length <= item.Number("limit"),
                "A counted view lost its bounded descriptor.");
            var buffer = record.Children.Single(value => value.Name == "Buffer");
            if (snapshot!.Bytes.Length < 16)
            {
                Require(buffer.Input is null && buffer.Children.Count == 0,
                    "A partial counted descriptor exposed a pointer or referenced text.");
                continue;
            }
            Require(buffer.Input == item.GetProperty("buffer").GetUInt64() &&
                record.Children.Single(value => value.Name == "Length").Input == (ulong)item.Number("length") &&
                record.Children.Single(value => value.Name == "MaximumLength").Input == (ulong)item.Number("maximum"),
                "A counted interpretation lost its captured descriptor fields.");
            var text = buffer.Children.Single();
            var wide = record.TypeName == unicode;
            if (item.Number("buffer") == 0)
            {
                Require(text.InputMemory is null && text.InputText == "<null>",
                    "A null counted buffer fabricated referenced memory.");
                continue;
            }
            Require(text.TypeName == (wide ? "wchar_t *" : "char *") && text.InputMemory?.Kind == (wide ? 1 : 0),
                "A counted view attached the other character encoding's referenced bytes.");
            var expected = item.Number("buffer") == 0 ? 0 : Math.Min(item.Number("length"), item.Number("limit"));
            Require(text.InputMemory?.Bytes.Length == expected,
                "A positional counted view exceeded its recorded byte extent.");
            if (item.Text("sample") == "EMPTY") Require(text.InputText == "\"\"",
                "A known empty counted string was replaced by missing data.");
        }
    }

    public static void VerifyPartialAndLayout(JsonElement item)
    {
        // Partial stored descriptors cannot reveal referenced data even when that data remains in the record.
        var altered = JsonNode.Parse(item.GetRawText())!;
        foreach (var snapshot in altered["call"]!["input"]!.AsArray().Where(value =>
            value!["parameter"]!.GetValue<int>() == item.Number("parameter") &&
                value["kind"]!.GetValue<int>() == 0 && (value["flags"]!.GetValue<int>() & 8) == 0))
        {
            TruncateSnapshot(snapshot!, 12);
        }
        using var partial = JsonDocument.Parse(altered.ToJsonString());
        Verify(partial.RootElement);

        // A changing record can be empty for one captured conversion and nonempty for the next.
        altered = JsonNode.Parse(item.GetRawText())!;
        var inputs = altered["call"]!["input"]!.AsArray();
        var records = inputs.Where(value => value!["parameter"]!.GetValue<int>() == item.Number("parameter") &&
            value["kind"]!.GetValue<int>() == 0 && (value["flags"]!.GetValue<int>() & 8) == 0).ToArray();
        records[0]!["bytes"] = "0000" + records[0]!["bytes"]!.GetValue<string>()[4..];
        inputs.Remove(inputs.First(value => value!["parameter"]!.GetValue<int>() == item.Number("parameter") &&
            value["kind"]!.GetValue<int>() == 0 && (value["flags"]!.GetValue<int>() & 8) != 0));
        using var changing = JsonDocument.Parse(altered.ToJsonString());
        var parent = ParameterValues.Build(changing.RootElement.GetProperty("call"))
            .Single(value => value.Parameter == item.Number("parameter"));
        if (item.GetProperty("listed").GetBoolean())
            parent = parent.Children.Single(value => value.Name == "[0] counted[1]");
        var ansi = parent.Children.Single(value => value.TypeName == ApiMetadata.Structure("ANSI_STRING")!.Name);
        var unicode = parent.Children.Single(value => value.TypeName == "UNICODE_STRING");
        if (ansi.Children.Single(value => value.Name == "Length").Input != 0 ||
            ansi.Children.Single(value => value.Name == "Buffer").Children.Single().InputText != "\"\"" ||
            unicode.Children.Single(value => value.Name == "Length").Input != (ulong)item.Number("length") ||
            unicode.Children.Single(value => value.Name == "Buffer").Children.Single().InputMemory?.Kind != 1)
            throw new InvalidOperationException("A counted view borrowed another conversion's descriptor or bytes.");

        // Both record views remain available through the real parameter grid at normal and enlarged scale.
        var grid = new ParameterGrid();
        grid.ShowCall(item.GetProperty("call"));
        var properties = (DataGrid)grid.FindName("PropertiesGrid");
        foreach (var scale in new[] { 1.0, 1.5 })
        {
            grid.LayoutTransform = new ScaleTransform(scale, scale);
            grid.Measure(new Size(640, 480));
            grid.Arrange(new Rect(0, 0, 640, 480));
            grid.UpdateLayout();
            var controls = Program.VisualTree(grid);
            controls.OfType<Button>().Single(value => Equals(value.ToolTip, "Expand all properties"))
                .RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            grid.UpdateLayout();
            foreach (var type in new[] { "ANSI_STRING", "UNICODE_STRING" })
            {
                var row = properties.Items.Cast<ParameterProperty>()
                    .Single(value => value.TypeName == ApiMetadata.Structure(type)!.Name);
                properties.ScrollIntoView(row);
                properties.UpdateLayout();
                if (properties.ItemContainerGenerator.ContainerFromItem(row) is not DataGridRow { ActualHeight: > 0 })
                    throw new InvalidOperationException("A counted record view is unavailable in the parameter grid.");
            }
            if (properties.ActualWidth <= 0 || properties.ActualHeight <= 0)
                throw new InvalidOperationException("The expanded counted record grid has no visible layout.");
        }
        grid.Clear();
        if (properties.Items.Count != 0) throw new InvalidOperationException("Clearing retained counted record views.");
    }
}

public static class ScanFormatInspectorTests
{
    public static void Verify(JsonElement capture)
    {
        var rows = ParameterValues.Build(capture.GetProperty("call"));
        var listed = capture.GetProperty("listed").GetBoolean();
        var tail = capture.Number("tail");
        if (capture.Text("text").EndsWith("%F %d", StringComparison.Ordinal) ||
            (capture.GetProperty("options").GetUInt64() & ~7UL) != 0)
        {
            Require(listed || rows.Where(value => value.Parameter >= tail).All(value =>
                value.Name == $"[{value.Parameter}] arg{value.Parameter}"),
                "An unsupported provider conversion inferred destination types.");
            if (listed) Require(rows.Single(value => value.Parameter == tail).Children.All(value =>
                !value.Name.Contains("scan[", StringComparison.Ordinal) &&
                    (value.OutputMemory is null || (value.OutputMemory.Flags & 72) != 72)),
                "An unsupported argument-list conversion inferred a scanned value.");
            return;
        }
        foreach (var destination in capture.GetProperty("destinations").EnumerateArray())
        {
            var index = destination.Number("index");
            var argument = rows.Single(value => value.Parameter == (listed ? tail : tail + index));
            if (listed) argument = argument.Children.Single(value =>
                value.InputMemory is { Kind: 2 } scalar && scalar.ElementIndex == index);
            if (capture.GetProperty("incomplete").GetBoolean() && index == 29)
            {
                Require(argument.Name == "[31] arg31", "A secure destination inferred an uncaptured capacity slot.");
                continue;
            }
            Require(argument.TypeName == destination.Text("type") &&
                argument.Input == destination.GetProperty("pointer").GetUInt64(),
                $"A scan destination lost its provider type or argument position: {capture.Text("name")} " +
                    $"{capture.Text("text")} [{index}] {argument.TypeName}.");
            var nodes = Flatten(argument.Children);
            var count = destination.GetProperty("count").GetBoolean();
            var assigned = destination.GetProperty("assigned").GetBoolean();
            if (!assigned)
            {
                Require(nodes.All(value => value.OutputMemory is null && value.Output is null),
                    "An unassigned scan destination exposed a stale value.");
                continue;
            }
            var expected = Convert.FromHexString(destination.Text("data"));
            var uncertain = capture.GetProperty("multibyte").GetBoolean() && index == 0 &&
                expected.Length > capture.Number("limit");
            var bytes = expected.AsSpan(0, Math.Min(expected.Length, (int)capture.Number("limit"))).ToArray();
            Require(nodes.Any(value => value.OutputMemory is { } memory && memory.Bytes.AsSpan().SequenceEqual(bytes)),
                "The inspector lost completed scan data or its argument-list association.");
            if (uncertain) Require(nodes.Any(value => value.OutputMemory is { OriginalBytes: 0 } memory &&
                (memory.Flags & 1) != 0 && memory.State.Length > 0),
                "A multibyte character prefix was presented as a complete output.");
            if (destination.GetProperty("buffer").GetBoolean())
                Require(argument.Name.Contains("buffer[", StringComparison.Ordinal) &&
                    nodes.Any(value => value.TypeName == "Raw capture" && value.OutputMemory is { Kind: 0 } memory &&
                        memory.OriginalBytes == (ulong)expected.Length && value.Children.Count == 0),
                    "A native cross-encoding buffer was presented as a contiguous scanned string.");
            if (destination.Text("type") is "char *" or "wchar_t *") continue;
            var scalarValue = nodes.Single(value => value.Name == (count ? "Count" : "Scanned value"));
            var scalarBytes = new byte[8];
            expected.CopyTo(scalarBytes, 0);
            Require(scalarValue.Output == BitConverter.ToUInt64(scalarBytes),
                "A scanned scalar used the wrong provider width or displayed a pointer instead of its value.");
            if (count) Require(scalarValue.Input.HasValue, "A count lost its neutral before-and-after storage view.");
        }
    }
}

public static class ShellMessageInspectorTests
{
    public static void Verify(JsonElement capture)
    {
        var sample = capture.GetProperty("sample");
        var rows = ParameterValues.Build(capture.GetProperty("call"));
        var complete = sample.GetProperty("complete").GetBoolean();
        if (!complete)
        {
            if (rows.Where(value => value.Parameter >= 5).Any(value =>
                value.Name.Contains("string[", StringComparison.Ordinal) ||
                value.Name.Contains("value[", StringComparison.Ordinal)))
                throw new InvalidOperationException("An incomplete message template inferred typed inserts.");
            return;
        }
        if (rows.Count(value => value.Parameter >= 0) != sample.Number("consumed"))
            throw new InvalidOperationException($"Message {sample.Number("id")} retained unused tail slots.");
        foreach (var field in sample.GetProperty("fields").EnumerateArray())
        {
            var row = rows.Single(value => value.Parameter == field.Number("index") + 5);
            if (row.TypeName != field.Text("type"))
                throw new InvalidOperationException($"Message {sample.Number("id")} slot {row.Parameter}: " +
                    $"expected {field.Text("type")}, found {row.TypeName}.");
            var expected = Convert.FromHexString(field.Text("data"));
            if (expected.Length == 0) continue;
            var nodes = Flatten(row.Children);
            if (!nodes.Any(value => value.InputMemory is { } memory &&
                memory.Bytes.AsSpan().SequenceEqual(expected)))
                throw new InvalidOperationException($"Message {sample.Number("id")} lost its insert text.");
        }
    }
}

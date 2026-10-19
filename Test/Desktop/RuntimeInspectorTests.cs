using Detourist.Desktop;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media.Imaging;
using System.Windows.Media;
using System.Windows.Threading;
using System.Windows;

namespace Detourist.Desktop.Tests;

public static partial class Program
{
    private static ParameterProperty Field(ParameterProperty parent, string name) =>
        parent.Children.Single(field => field.Name == name);

    private static ParameterProperty[] ArrayStrings(ParameterProperty row)
    {
        var array = row.Children.Single(child => child.TypeName == "SAFEARRAY");
        return [.. Field(array, "Elements").Children.SelectMany(child => child.Children)
            .Where(child => child.Name == "Text")];
    }

    private static void InspectTypedVariantArrays(JsonDocument details)
    {
        // Typed vtable methods retain the same bounded Automation array editor as dispatch calls.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var limit = item.GetProperty("limit").GetInt32();
            var output = item.GetProperty("output").GetBoolean();
            var variants = item.GetProperty("variantArray").GetBoolean();
            var parameter = item.GetProperty("parameter").GetInt32();
            var row = ParameterValues.Build(item.GetProperty("call"))
                .Single(row => row.Parameter == parameter);
            var texts = ArrayStrings(row);
            var count = variants ? (limit == 16 ? 1 : limit == 56 ? 2 : 3) : (limit == 16 ? 2 : 3);
            Require(texts.Length == count, "Typed array strings were associated with the wrong element.");
            var memory = output ? texts[0].OutputMemory : texts[0].InputMemory;
            var expected = System.Text.Encoding.Unicode.GetBytes("Detourist\0ADSI directory object");
            Require(memory is { OriginalBytes: 62 } && memory.Bytes.Length == Math.Min(limit, 62) &&
                memory.Bytes.SequenceEqual(expected.Take(limit)),
                "The typed array lost its counted embedded-null string or capture limit.");
            if (count > 1)
            {
                memory = output ? texts[1].OutputMemory : texts[1].InputMemory;
                Require(memory?.Text(System.Text.Encoding.Unicode) == "tail\0",
                    "The typed array treated a trailing BSTR null as a terminator.");
            }
            if (count > 2)
                Require((output ? texts[2].OutputMemory : texts[2].InputMemory) is
                    { Bytes.Length: 0, OriginalBytes: 0 }, "The null BSTR lost its empty value.");
        }
        Require(details.RootElement.GetArrayLength() == 15, "A typed array or capture limit was omitted.");
        Console.WriteLine("Typed COM array expansion, element association and counted string previews passed.");
    }

    private static void InspectAdsiStructures(JsonDocument details)
    {
        // The inspector expands real SDK offsets while leaving truncated fields unpopulated.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var kind = item.GetProperty("kind").GetString();
            var limit = item.GetProperty("limit").GetInt32();
            var bytes = Convert.FromHexString(item.GetProperty("bytes").GetString()!);
            var row = ParameterValues.Build(item.GetProperty("call")).Single(row => row.Parameter == 1);
            var name = kind switch
            {
                "information" => "ADS_OBJECT_INFO", "attribute" => "ADS_ATTR_INFO",
                _ => "ADS_SEARCHPREF_INFO"
            };
            var structure = row.Children.Single(child => child.TypeName == name);
            Require(structure.Children.Count == (kind == "preference" ? 3 : 5),
                "The ADSI structure lost its named SDK fields.");
            if (kind == "information")
            {
                Require(structure.Children[0].Name == "pszRDN" &&
                    structure.Children[0].Output == BitConverter.ToUInt64(bytes) &&
                    structure.Children[4].Output == (limit == 64 ? BitConverter.ToUInt64(bytes, 32) : null),
                    "The returned object information used incorrect offsets or uncaptured bytes.");
            }
            else if (kind == "attribute")
            {
                Require(Field(structure, "dwControlCode").Input == 2 &&
                    Field(structure, "dwADsType").InputText
                        .StartsWith("ADSTYPE_LARGE_INTEGER"), "The attribute lost its typed enum choices.");
            }
            else
            {
                var value = Field(structure, "vValue");
                var integer = Field(value, "union").Children
                    .Single(field => field.Name == "Integer");
                Require(Field(structure, "dwSearchPref").InputText
                    .StartsWith("ADS_SEARCHPREF_PAGESIZE") &&
                    Field(value, "dwType").Input == 7 &&
                    integer.Input == (limit == 64 ? 312UL : null),
                    "The nested ADSVALUE union lost its fields or capture limit.");
            }
        }
        Require(details.RootElement.GetArrayLength() == 6, "An ADSI structure or buffer limit was omitted.");
        Console.WriteLine("ADSI allocated structures, enum choices, nested unions and truncation passed.");
    }

    private static void InspectAdsi(JsonDocument details)
    {
        // Real ADSI snapshots retain named properties, expandable variants and counted BSTR text.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var method = item.GetProperty("method").GetString();
            var limit = item.GetProperty("limit").GetInt32();
            var rows = ParameterValues.Build(item.GetProperty("call"));
            var nodes = Flatten(rows);
            if (method is "get_Name" or "GetEx")
            {
                var text = nodes.Single(row => row.OutputMemory?.Kind == 1);
                Require(text.OutputMemory is { OriginalBytes: 62 } &&
                    text.OutputMemory.Bytes.Length == Math.Min(limit, 62) &&
                    System.Text.Encoding.Unicode.GetString(text.OutputMemory.Bytes) ==
                        (limit == 16 ? "Detouris" : "Detourist\0ADSI directory object"),
                    "The ADSI BSTR lost its bounded counted text.");
                if (limit == 64)
                    Require(text.OutputText.Contains("Detourist\\0"),
                        "The BSTR preview hid its embedded null.");
            }
            if (method is "Get" or "Put")
            {
                var variant = rows.Single(row => row.Parameter == 2);
                Require(variant.Name == (method == "Get" ? "[2] pvProp" : "[2] vProp") &&
                    nodes.Any(row => row.Name == "vt" &&
                        (method == "Get" ? row.Output : row.Input) == 21) &&
                    nodes.Any(row => row.Name == "ullVal" &&
                        (method == "Get" ? row.Output : row.Input) == 0x1122334455667788UL),
                    "The ADSI VARIANT lost its named expandable scalar fields.");
            }
        }
        Require(details.RootElement.GetArrayLength() == 12, "ADSI capture omitted a method or buffer limit.");
        Console.WriteLine("ADSI property names, expandable VARIANT fields and bounded BSTR previews passed.");
    }

    private static void InspectMessageApis(JsonDocument details, bool peek)
    {
        // Real native message buffers retain named fields and pointer-width message payloads.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var limit = item.GetProperty("limit").GetInt32();
            var rows = ParameterValues.Build(item.GetProperty("call"));
            var parameter = rows.Single(row => row.Parameter == 0);
            var message = parameter.Children.Single();
            Require(parameter.Name == "[0] Message" && message.TypeName == "MSG" &&
                Field(message, "hwnd").Output == 0 &&
                Field(message, "wParam").Output ==
                    (limit == 64 ? 0x1122334455667788UL : null) &&
                Field(message, "lParam").Output ==
                    (limit == 64 ? 0x2233445566778899UL : null) &&
                Field(message, "pt").Children.Count == 2 &&
                message.OutputMemory is { OriginalBytes: 48 } &&
                message.OutputMemory.Bytes.Length == Math.Min(limit, 48),
                "The native message output lost its expandable SDK fields or pointer-width values.");
            if (peek)
            {
                var flags = rows.Single(row => row.Parameter == 5);
                Require(flags.Name == "[5] InternalFlags" && flags.Type.Bits == 32 && flags.Input == 0,
                    "The native peek-message flags lost their named scalar editor.");
            }
        }
        Require(details.RootElement.GetArrayLength() == 8, "The message capture omitted a native boundary.");
        Console.WriteLine("Native message names, expandable MSG fields and pointer-width payloads passed.");
    }

    private static void InspectWinrtStructures(JsonDocument details)
    {
        // Expand real bounded SDK structures and array elements without manufacturing missing field data.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var type = item.GetProperty("type").GetString();
            var limit = item.GetProperty("limit").GetInt32();
            var rows = ParameterValues.Build(item.GetProperty("call"));
            var parameter = rows.Single(row => row.Parameter == (type == "Rect[]" ? 2 : 1));
            var structure = type == "Rect[]" ?
                parameter.Children.Single(child => child.OutputMemory?.Kind == 0) : parameter.Children.Single();
            if (type == "Rect[]")
            {
                var elements = structure.Children.Where(row => row.Children.Any(field => field.Name == "X"))
                    .ToArray();
                Require(elements.Length == limit / 16 &&
                    Field(elements[0], "X").Output ==
                        BitConverter.SingleToUInt32Bits(0.25f),
                    "The allocated rectangle array exceeded its captured extent or lost named fields.");
            }
            else if (type!.EndsWith("Matrix4x4"))
            {
                var first = Field(structure, "M11");
                var last = Field(structure, "M44");
                Require(first.Output == BitConverter.SingleToUInt32Bits(1) &&
                    (limit == 64 ? last.Output == BitConverter.SingleToUInt32Bits(16) : last.Output is null) &&
                    structure.OutputMemory is { OriginalBytes: 64 } &&
                    structure.OutputMemory.Bytes.Length == limit,
                    "The matrix output did not preserve bounded floating fields.");
            }
            else
            {
                Require(parameter.Name == "[1] value" && structure.Children.Count > 0 &&
                    structure.Children.Any(field => field.Output is not null),
                    $"A WinRT value structure lost its named parameter or captured fields: {type}, " +
                    $"{parameter.Name}, {structure.TypeName}, {structure.Children.Count} fields.");
            }
        }
        Console.WriteLine("WinRT structure fields, bounded matrices and allocated rectangle arrays expanded.");
    }

    private static void InspectAutomationEnumeration(JsonDocument details)
    {
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var limit = item.GetProperty("limit").GetInt32();
            var rows = ParameterValues.Build(item.GetProperty("call"));
            var parameter = rows.Single(row => row.Parameter == 2);
            Require(parameter.Name == "[2] rgVar" && parameter.TypeName.Contains("VARIANT"),
                "Enumeration output lost its named parameter or type.");
            var array = parameter.Children.Single();
            Require(array.TypeName == "VARIANT[]", "Completed values did not expand as a variant array.");
            var elements = array.Children.Where(child => child.Name.StartsWith('[') &&
                int.TryParse(child.Name[1..^1], out _)).ToArray();
            Require(elements.Length == (limit == 16 ? 1 : 3), "Expansion exceeded the captured extent.");
            var pending = new Stack<ParameterProperty>(elements[0].Children);
            ParameterProperty? variant = null;
            while (pending.TryPop(out var field))
            {
                if (field.Name == "vt") { variant = field; break; }
                foreach (var child in field.Children) pending.Push(child);
            }
            Require(variant?.Output == 9, "The first element lost its VT_DISPATCH tag.");
            Require(rows.Single(row => row.Parameter == 3).Children.Single().Children.Single().Output == 3,
                "The completed count lost its typed scalar value.");
        }
        Console.WriteLine("Named enumeration parameters and bounded variant array expansion passed.");
    }

    private static void InspectAutomationStrings(JsonDocument details)
    {
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var index = item.GetProperty("index").GetInt32();
            var limit = item.GetProperty("limit").GetInt32();
            var row = ParameterValues.Build(item.GetProperty("call")).Single(row => row.Parameter == 6);
            var text = ArrayStrings(row);
            var expected = index == 0 ? (limit == 16 ? 2 : 3) : (limit == 16 ? 1 : limit == 56 ? 2 : 3);
            Require(text.Length == expected, "Strings were associated with the wrong array element.");
            Require(text[0].OutputMemory?.Text(System.Text.Encoding.Unicode) ==
                (limit == 16 ? "alpha\0om" : "alpha\0omega"), "BSTR text lost its embedded null or capture limit.");
            Require(text[0].OutputText.Contains("alpha\\0"), "The string preview hid an embedded null.");
            if (text.Length > 1)
                Require(text[1].OutputMemory?.Text(System.Text.Encoding.Unicode) == "tail\0" &&
                    text[1].OutputText.Contains("tail\\0"), "A trailing BSTR null was treated as a terminator.");
            if (index == 0 && text.Length == 3)
                Require(text[2].OutputMemory is { Bytes.Length: 0, OriginalBytes: 0 } &&
                    text[2].OutputText.Contains("\"\""), "A null BSTR did not retain its empty value.");
        }
        Console.WriteLine("Array string association, counted text and bounded preview passed.");
    }

    private static void InspectAutomationArrays(JsonDocument details)
    {
        // Inspect real native captures, including partial descriptors and variant element tails.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var limit = item.GetProperty("limit").GetInt32();
            var index = item.GetProperty("index").GetInt32();
            var root = ParameterValues.Build(item.GetProperty("call")).Single(row => row.Parameter == 6);
            var array = root.Children.Single(row => row.TypeName == "SAFEARRAY");
            Require(array.Children.Single(row => row.Name == "cDims").Output == (index == 0 ? 2UL : 1UL),
                "The array descriptor lost its dimension count.");
            var elements = array.Children.Single(row => row.Name == "Elements");
            var visible = elements.Children.Where(row => !row.Name.Contains('…')).ToArray();
            if (index == 0)
            {
                Require(visible[0].Output == unchecked((uint)-7) && visible[2].Output == 42,
                    "Integer array elements lost their signed value bits.");
                Require(visible.Length == (limit == 16 ? 4 : 6), "Integer array capture bound was ignored.");
                if (limit == 64)
                {
                    var bounds = array.Children.Where(row => row.Name.StartsWith("rgsabound["))
                        .Select(row => unchecked((int)row.Children
                            .Single(field => field.Name == "lLbound").Output!.Value))
                        .Order().ToArray();
                    Require(bounds.SequenceEqual(new[] {-4, 5}), "Multidimensional array lower bounds were lost.");
                }
            }
            else if (index == 1)
                Require(BitConverter.UInt64BitsToDouble(visible[0].Output!.Value) == -3.25 &&
                    visible[0].Type.Kind == "Float64", "Floating array elements were not decoded.");
            else if (index == 2)
                Require(visible.Length == 4 && visible[0].Output == 65535 && visible[1].Output == 0 &&
                    visible[0].Type.Kind == "Boolean", "Boolean array elements were not decoded.");
            else if (index == 3)
            {
                Require(visible[0].Children.Single(row => row.Name == "vt").Output == 3 &&
                    visible[0].Children.Single(row => row.Name == "Value").Output == unchecked((uint)-99),
                    "Variant array elements did not expand their actual value type.");
                if (limit == 56)
                    Require(visible[2].Children.Single(row => row.Name == "Value").Output is null &&
                        visible[2].Children.Single(row => row.Name == "Value").OutputLabel == "<not captured>",
                        "An uncaptured variant value was interpreted as complete.");
                if (limit == 64)
                    Require(visible[2].Children.Single(row => row.Name == "Value").Output == 0xDEADBEEF &&
                        visible[2].OutputMemory is { Bytes.Length: 16 },
                        "A complete scalar inside a partial variant was not decoded.");
            }
            else Require(visible.Length == 0, "An empty array gained fabricated elements.");
        }
        Console.WriteLine("Automation array descriptors, typed elements and bounded expansion passed.");
    }

    private static void InspectComContext(JsonDocument details)
    {
        // The property grid expands SDK field names without exposing bytes beyond the capture limit.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var row = ParameterValues.Build(item.GetProperty("callback"))
                .Single(row => row.Parameter == 2);
            var structure = row.Children.Single();
            Require(row.Name == "[2] pParam" && structure.TypeName == "ComCallData" &&
                Field(structure, "dwDispid").Input == 0x2A &&
                Field(structure, "dwReserved").Input == 0x12345678 &&
                Field(structure, "pUserDefined").Input is > 0 &&
                structure.InputMemory is { OriginalBytes: 16, Flags: 0 },
                "The context callback lost its SDK names, layout or bounded field values.");
        }
        Console.WriteLine("Context callback parameter and structure expansion passed.");
    }

    private static void InspectManaged(JsonDocument details)
    {
        // Real attached calls retain names and expose captured values without inventing scalar words.
        var vector = ParameterValues.Build(details.RootElement.GetProperty("vector"));
        var left = vector.Single(row => row.Parameter == 0);
        var right = vector.Single(row => row.Parameter == 1);
        var result = vector.Single(row => row.Parameter == -1);
        Require(left.Name == "[0] left" && right.Name == "[1] right" &&
            left.Input is null && left.InputText == "<32-byte value>" &&
            result.Output is null && result.OutputText == "<32-byte value>",
            "A managed value type lost its parameter name or displayed an invented scalar word.");
        var leftBytes = left.Children.Single().InputMemory!.Bytes;
        var rightBytes = right.Children.Single().InputMemory!.Bytes;
        var returnedBytes = result.Children.Single().OutputMemory!.Bytes;
        Require(leftBytes.Length == 32 && rightBytes.Length == 32 && returnedBytes.Length == 32 &&
            Enumerable.Range(0, 4).All(index => BitConverter.ToDouble(returnedBytes, index * 8) ==
                BitConverter.ToDouble(leftBytes, index * 8) + BitConverter.ToDouble(rightBytes, index * 8)),
            "The managed vector's captured input and return regions were not inspectable.");
        var scalar = ParameterValues.Build(details.RootElement.GetProperty("scalar"))
            .Single(row => row.Parameter == 1);
        var referenced = scalar.Children.Single(row => row.OutputMemory?.Kind == 0);
        Require(scalar.Name == "[1] result" && referenced.Children.Single().Output == 654321 &&
            referenced.Children.Single().TypeName == "int32",
            "The managed by-reference scalar did not expand using its declared type.");
        var floating = ParameterValues.Build(details.RootElement.GetProperty("floating"))
            .Single(row => row.Parameter == -1);
        Require(floating.Type.Kind == "Float64" && floating.OutputText == "7",
            "The managed floating-point return did not use its declared numeric interpretation.");
        var buffer = ParameterValues.Build(details.RootElement.GetProperty("buffer"))
            .Single(row => row.Parameter == -1).Children.Single(row => row.OutputMemory?.Kind == 0);
        Require(buffer.OutputMemory is { Bytes.Length: 64, OriginalBytes: 104, Flags: 1 },
            "The managed return buffer lost its captured bytes or global memory limit.");
        Console.WriteLine("Managed names, by-reference scalars, buffers and value-type returns passed.");
    }

    private static void InspectManagedLayout(JsonDocument details)
    {
        // Captured CLR receiver bytes expand using the layout persisted with their API definition.
        var receiver = ParameterValues.Build(details.RootElement).Single(row => row.Parameter == 0);
        var structure = receiver.Children.Single(row => row.TypeName == "System.Guid");
        Require(receiver.Name == "[0] this" && receiver.SignatureType.Name == "System.Guid&" &&
            structure.InputMemory is { Bytes.Length: 16, OriginalBytes: 16, Flags: 0 } &&
            structure.Children.Count == 11,
            "The managed receiver did not expose its named, expandable layout and bounded bytes.");
        var fields = structure.Children.ToDictionary(field => field.Name);
        Require(fields["_a"].Input == 0x00112233 && fields["_a"].Type.Bits == 32 &&
            fields["_b"].Input == 0x4455 && fields["_b"].Type.Bits == 16 &&
            fields["_c"].Input == 0x6677 && fields["_c"].Type.Bits == 16 &&
            Enumerable.Range(0, 8).All(index =>
                fields["_" + (char)('d' + index)].Input == (ulong)(0x88 + index * 0x11) &&
                fields["_" + (char)('d' + index)].Type.Bits == 8),
            "The managed receiver's primitive field values or widths were decoded incorrectly.");
        Console.WriteLine("Persisted managed receiver layout, field names, widths and captured values passed.");
    }

    private static void InspectComRpcArrays(JsonDocument details)
    {
        // Inspect captured SDK arrays and preserve the association between BSTR pointers and their text.
        foreach (var item in details.RootElement.EnumerateArray())
        {
            var mode = item.GetProperty("mode").GetString();
            var limit = item.GetProperty("limit").GetInt32();
            if (mode is not ("input" or "output" or "allocated" or "pipe-output" or "pipe-input" or "names"))
                continue;
            var index = mode is "allocated" or "pipe-output" or "pipe-input" ? 1 :
                mode == "names" ? 2 : mode == "input" ? 3 : 4;
            var parameter = ParameterValues.Build(item.GetProperty("call")).Single(row => row.Parameter == index);
            var array = parameter.Children.Single(row => row.TypeName.EndsWith("[]"));
            var visible = array.Children.Where(row => !row.Name.Contains('…')).ToArray();
            if (mode is "input" or "output")
            {
                Require(visible.Length == (limit == 16 ? 1 : 3), "Variant array expansion exceeded its capture.");
                var fields = Flatten([visible[^1]]);
                Require(fields.Any(field => field.Name == "vt" &&
                    (mode == "input" ? field.Input : field.Output) == 9),
                    "A captured array variant lost its SDK discriminator.");
            }
            else if (mode == "allocated")
                Require(visible.Length == (limit == 16 ? 2 : 3) &&
                    visible.All(row => row.Output is > 0 && row.Type.Kind == "Pointer"),
                    "An allocated interface array lost its captured pointer values.");
            else if (mode is "pipe-output" or "pipe-input")
                Require(visible.Length == Math.Min(limit, mode == "pipe-input" ? 80 : 48) &&
                    (mode == "pipe-input" ? visible[0].Input : visible[0].Output) == 0x6D &&
                    visible[0].Type.Bits == 8, "A completed byte buffer did not expand its bounded values.");
            else
            {
                Require(visible.Length == 2 && visible.All(row => row.Output is > 0),
                    "A BSTR array lost its completed pointer count.");
                var text = visible.Select(row => row.Children.Single(child => child.Name == "Text")).ToArray();
                Require(text[0].OutputMemory?.Text(System.Text.Encoding.Unicode) ==
                    (limit == 16 ? "Transfor" : "Transform") &&
                    text[1].OutputMemory?.Text(System.Text.Encoding.Unicode) == "Argument",
                    "Counted strings were truncated incorrectly or attached to the wrong pointer.");
            }
        }
        Console.WriteLine("SDK RPC arrays, completed byte buffers, allocated pointers and BSTR text expansion passed.");
    }

    private static void InspectGdiQueries(JsonDocument details)
    {
        // Native output snapshots retain named parameters and expandable SDK fields.
        var captured = details.RootElement.EnumerateArray().Select(detail => ParameterValues.Build(detail)).ToArray();
        var bounds = captured[1].Single(row => row.Parameter == 1);
        var rectangle = bounds.Children.Single();
        Require(bounds.Name == "[1] Bounds" && rectangle.TypeName == "RECT" &&
            Field(rectangle, "left").Output == 2 &&
            Field(rectangle, "top").Output == 3 &&
            Field(rectangle, "right").Output == 13 &&
            Field(rectangle, "bottom").Output == 14,
            "The native clip query did not expose its named, expandable rectangle.");
        var data = captured[2].Single(row => row.Parameter == 2);
        var region = data.Children.Single();
        Require(data.Name == "[2] Data" && region.OutputMemory is { Bytes.Length: 48, OriginalBytes: 48 },
            "The native region query did not retain its completed buffer and layout.");
        var header = Field(region, "rdh");
        Require(Field(header, "nCount").Output == 1 &&
            Field(header, "nRgnSize").Output == 16,
            "The captured region header did not expose its SDK fields.");
        Console.WriteLine("Native GDI parameter names, completed output lengths and SDK structure expansion passed.");
    }

    private static void InspectSdkLeaf(JsonDocument details)
    {
        // Native exports and private syscalls retain SDK names and expandable output fields.
        var captured = details.RootElement.EnumerateArray().Select(detail => ParameterValues.Build(detail)).ToArray();
        var size = captured[0].Single(row => row.Parameter == 1);
        var dimensions = size.Children.Single();
        Require(size.Name == "[1] lpsize" && dimensions.TypeName == "SIZE" &&
            Field(dimensions, "cx").Output == 23 &&
            Field(dimensions, "cy").Output == 47,
            "The native bitmap query did not expose its expandable SIZE output.");
        var miter = captured[1].Single(row => row.Parameter == 1).Children.Single().Children.Single();
        miter.Hex = false;
        Require(miter.Type.Kind == "Float32" && miter.OutputText == "3.5",
            "The native miter query did not interpret its floating-point output.");
        var adjustment = captured[2].Single(row => row.Parameter == 1);
        var color = adjustment.Children.Single();
        Require(adjustment.Name == "[1] lpca" && color.TypeName == "COLORADJUSTMENT" &&
            color.Children.Count == 12 && Field(color, "caSize").Output == 24,
            "The native color query did not expand its SDK structure fields.");
        Console.WriteLine("Native SDK leaf names, expandable structures and floating-point output passed.");
    }

    private static void InspectWindowGraphics(JsonDocument details)
    {
        // A real native region query uses the SDK's named parameter and rectangle layout.
        var row = ParameterValues.Build(details.RootElement).Single(item => item.Parameter == 1);
        var structure = row.Children.Single();
        Require(row.Name == "[1] lprc" && structure.TypeName == "RECT" && structure.Children.Count == 4 &&
            Field(structure, "left").Output == 5 &&
            Field(structure, "top").Output == 7 &&
            Field(structure, "right").Output == 29 &&
            Field(structure, "bottom").Output == 31,
            "The native region query did not resolve its SDK signature and expandable rectangle.");
        Console.WriteLine("Native graphics alias and expandable rectangle passed.");
    }

    private static void InspectUfi(JsonDocument details)
    {
        // The native font identifier expands into its captured checksum and index fields.
        var row = ParameterValues.Build(details.RootElement).Single(item => item.Parameter == 1);
        var structure = row.Children.Single();
        Require(row.Name == "[1] pufi" && structure.TypeName == "UNIVERSAL_FONT_ID" &&
            structure.OutputMemory is { Bytes.Length: 8 } && structure.Children.Count == 2 &&
            Field(structure, "CheckSum").Output is > 0 &&
            Field(structure, "Index").Output is > 0,
            "The native font identifier did not expand its captured output structure.");
        Console.WriteLine("Native font identifier structure inspection passed.");
    }

    private static void InspectGraphics(JsonDocument details)
    {
        // A real private syscall resolves the SDK's names and expandable structure in the property grid.
        var input = ParameterValues.Build(details.RootElement).Single(row => row.Parameter == 0);
        var structure = input.Children.Single();
        var adapters = Field(structure, "NumAdapters");
        Require(input.Name == "[0] data" && structure.TypeName == "D3DKMT_ENUMADAPTERS2" &&
            structure.Children.Count == 2 && adapters.Input == 64 && adapters.Output is > 0 and <= 64,
            "The graphics syscall's named parameter and structure fields were not resolved.");
        var pointer = Field(structure, "pAdapters");
        var array = pointer.Children.Single();
        Require(array.OutputMemory is { Bytes.Length: > 0 } && array.TypeName == "D3DKMT_ADAPTERINFO[]" &&
            array.Children.First().Children.Single(field => field.Name == "hAdapter").Output is > 0,
            "The referenced adapter array was not attached to its pointer field or decoded.");
        if ((array.OutputMemory!.Flags & 1) != 0)
        {
            var partial = array.Children.Last(row => row.Children.Count > 0);
            var omitted = Field(partial, "bPrecisePresentRegionsPreferred");
            Require(omitted.Output is null && omitted.OutputText == "<not captured>",
                "A capped adapter array invented a value for a field beyond its captured bytes.");
        }
        Console.WriteLine("Graphics syscall signature and expandable structure passed.");
    }

    private static void InspectReferenceArrays(JsonDocument details)
    {
        // Inspect real allocated arrays through their captured count, pointer and bounded element data.
        var integers = ParameterValues.Build(details.RootElement.GetProperty("int32_t"));
        Require(integers.Single(row => row.Parameter == 1).Name == "[1] count",
            "The returned array count lost its name.");
        var items = integers.Single(row => row.Parameter == 2);
        var array = items.Children.Single(child => child.OutputMemory?.Kind == 0);
        Require(items.Name == "[2] items" && items.Children.Count == 2 && array.Children.Count == 17 &&
            array.Children[0].Output == 0x41525200 && array.Children[15].Output == 0x4152520F,
            "The returned integer array did not expand its captured elements and truncation range.");
        var identifiers = ParameterValues.Build(details.RootElement.GetProperty("GUID"))
            .Single(row => row.Parameter == 2);
        array = identifiers.Children.Single(child => child.OutputMemory?.Kind == 0);
        Require(identifiers.Children.Count == 2 && array.Children.Count == 5 &&
            array.Children[0].Children.First(field => field.Name == "Data1").Output == 0x12345678 &&
            array.Children[3].Children.First(field => field.Name == "Data1").Output == 0x1234567B,
            "The returned GUID array did not expand its bounded structure elements.");
        Console.WriteLine("Allocated reference arrays, primitive values and GUID fields expanded correctly.");
    }

    private static void InspectParameterized(JsonDocument details)
    {
        // Resolve the closed contract's named parameters and expand its captured GUID output.
        var integer = ParameterValues.Build(details.RootElement.GetProperty("integer"))
            .Single(row => row.Parameter == 1);
        Require(integer.Name == "[1] value" && integer.TypeName == "int32_t *",
            "A closed WinRT reference lost its named output parameter.");
        var guid = ParameterValues.Build(details.RootElement.GetProperty("guid"))
            .Single(row => row.Parameter == 1);
        Require(guid.Name == "[1] value" && guid.Children.Single().Children
            .First(field => field.Name == "Data1").Output == 0x12345678,
            "A closed WinRT reference's GUID output was not expandable.");
        var many = ParameterValues.Build(details.RootElement.GetProperty("many"));
        Require(many.Single(row => row.Parameter == 2).Name == "[2] capacity" &&
            many.Single(row => row.Parameter == 4).Name == "[4] actual" &&
            many.Single(row => row.Parameter == 3).Children.Single().OutputMemory is
                { Bytes.Length: 64, OriginalBytes: 128, Flags: 1 },
            "A closed collection lost its counted bounded output.");
        Console.WriteLine("Parameterized WinRT signatures, GUID fields and bounded output inspection passed.");
    }
}

public static class ManagedArrayInspectorTests
{
    public static void Verify(JsonDocument document)
    {
        foreach (var item in document.RootElement.EnumerateArray())
        {
            var operation = item.Text("kind");
            var type = item.Text("type");
            var stride = (int)item.Number("stride");
            var limit = (int)item.Number("limit");
            void Require(bool condition, string message)
            {
                if (!condition) throw new InvalidOperationException($"{type}, {operation}, {limit}: {message}");
            }
            var rows = ParameterValues.Build(item.GetProperty("call"));
            var returning = operation is "return" or "attached-return";
            var parameter = returning ? -1 : operation == "attached-list-copy" ? 2 :
                operation is "copy" or "multidimensional" or "attached-copy" ? 1 : 0;
            var row = rows.Single(value => value.Parameter == parameter);
            Require(row.Type.Kind == "Pointer" && (returning ? row.Output : row.Input) is not null,
                "An array reference was interpreted as an inline structure.");
            var array = row.Children.Single(value => value.InputMemory?.Kind == 12 ||
                value.OutputMemory?.Kind == 12);
            var beforeCount = (int)((array.InputMemory?.OriginalBytes ?? 0) / (uint)stride);
            var afterCount = (int)((array.OutputMemory?.OriginalBytes ?? 0) / (uint)stride);
            var total = Math.Max(beforeCount, afterCount);
            var available = Math.Max(array.InputMemory?.Bytes.Length ?? 0, array.OutputMemory?.Bytes.Length ?? 0);
            var visible = Math.Min(total, Math.Max(1, (available + stride - 1) / stride));
            Require(array.Children.Count == visible + (visible < total ? 1 : 0),
                "The array lost elements or expanded beyond its captured extent.");
            for (var index = 0; index < visible; ++index)
            {
                var element = array.Children[index];
                Require(element.Name == $"[{index}]", "An array index is wrong.");
                Require(element.Children.Count == (type == "ManagedArrayEmpty" ||
                    operation is "multidimensional" or "attached" or "attached-copy" or "attached-return" or
                        "attached-list-copy" ?
                    0 : type == "DayOfWeek" ? 1 : 2),
                    "The array element lost its field layout.");
                foreach (var output in new[] { false, true })
                {
                    var memory = output ? array.OutputMemory : array.InputMemory;
                    var count = output ? afterCount : beforeCount;
                    var populated = operation == "return" || operation == "copy" && output ||
                        operation == "resize" && beforeCount == 3 && index < 3;
                    var number = populated ? index == 1 ? 200UL : 100UL : 0;
                    var tag = populated ? index == 1 ? 9UL : 7UL : 0;
                    foreach (var field in element.Children)
                    {
                        var offset = field.Name == "Tag" ? type == "ManagedArraySized" ? 8 : 4 : 0;
                        var width = field.Name == "Tag" ? 1 : 4;
                        var expected = field.Name == "Tag" ? tag : type == "DayOfWeek" ?
                            populated ? index == 1 ? 5UL : 1UL : 0 : number;
                        var complete = index < count && memory is not null &&
                            index * stride + offset + width <= memory.Bytes.Length;
                        Require(field.Type.Bits == width * 8, "An array field width is wrong.");
                        Require((output ? field.Output : field.Input) == (complete ? expected : null),
                            "An array field has an incorrect value or reads across a padding boundary.");
                    }
                }
            }
            if (visible < total)
                Require(array.Children[^1].Name == $"[{visible}…{total - 1}]",
                    "The uncaptured element range is wrong.");
        }
        Console.WriteLine("Managed array fields, padding, truncation, null replacement and empty arrays passed.");
    }
}

public static class ManagedLayoutInspectorTests
{
    public static void Verify(JsonDocument document)
    {
        foreach (var item in document.RootElement.EnumerateArray())
        {
            var kind = item.Text("kind");
            var limit = item.Number("limit");
            var rows = ParameterValues.Build(item.GetProperty("call"));
            ParameterProperty Structure(int parameter)
            {
                var row = rows.Single(row => row.Parameter == parameter);
                return row.Children.Single(child => child.TypeName == row.TypeName.TrimEnd('&'));
            }
            void Require(bool condition, string message)
            {
                if (!condition) throw new InvalidOperationException($"{kind}, {limit} bytes: {message}");
            }
            static ParameterProperty Field(ParameterProperty parent, string name) => parent.Children.Single(
                field => (field.Name.StartsWith("m_") ? field.Name[2..] : field.Name.TrimStart('_')) == name);
            static ulong? Value(ParameterProperty field, bool output) => output ? field.Output : field.Input;
            void GuidFields(ParameterProperty guid, bool output)
            {
                // A known GUID checks field widths and truncated nested data independently of CLR offsets.
                var bytes = output ? guid.OutputMemory?.Bytes.Length : guid.InputMemory?.Bytes.Length;
                Require(guid.Children.Count == 11, "The GUID field definitions were lost.");
                for (var index = 0; index < 11; ++index)
                {
                    var field = Field(guid, ((char)('a' + index)).ToString());
                    var offset = index == 0 ? 0 : index == 1 ? 4 : index == 2 ? 6 : index + 5;
                    var width = index == 0 ? 4 : index < 3 ? 2 : 1;
                    var expected = index == 0 ? 0x00112233UL : index == 1 ? 0x4455UL :
                        index == 2 ? 0x6677UL : (ulong)(0x88 + (index - 3) * 0x11);
                    Require(field.Type.Bits == width * 8, "A GUID field has the wrong width.");
                    if (bytes >= offset + width)
                        Require(Value(field, output) == expected, "A captured GUID field has the wrong value.");
                    else
                        Require(Value(field, output) is null &&
                            (output ? field.OutputText : field.InputText).StartsWith('<'),
                            "An incomplete GUID field was displayed as a scalar value.");
                }
            }
            void DecimalFields(ParameterProperty value, bool output, ulong coefficient, ulong scale)
            {
                foreach (var field in value.Children)
                {
                    var name = field.Name.TrimStart('_');
                    var expected = name == "flags" ? scale << 16 : name is "lo" or "lo64" ? coefficient : 0;
                    Require(Value(field, output) == expected, "A decimal field has the wrong value.");
                }
                Require(value.Children.Count is 3 or 4, "The decimal layout is incomplete.");
            }

            // Verify the inspector's real parameter tree, including nested return values and capped buffers.
            if (kind == "decimal")
            {
                DecimalFields(Structure(0), false, 1235, 1);
                DecimalFields(Structure(1), false, 625, 2);
                DecimalFields(Structure(-1), true, 12975, 2);
            }
            else if (kind is "span" or "external-span")
            {
                var returned = rows.Single(row => row.Parameter == -1);
                Require(returned.Output is null && returned.OutputText == "<structure>" &&
                    Field(Structure(-1), "ticks").Output == 1232500000,
                    "The scalar-sized TimeSpan return did not expand as a structure.");
            }
            else if (kind == "small")
            {
                var argument = rows.Single(row => row.Parameter == 1);
                Require(argument.Input is null && argument.InputText == "<structure>" &&
                    Field(Structure(0), "ticks").Input == 1232500000 &&
                    Field(Structure(1), "ticks").Input == 10000000 &&
                    Field(Structure(-1), "ticks").Output == 1242500000,
                    "The scalar-sized value argument did not expand as a structure.");
            }
            else if (kind is "date" or "external-date" or "external-value")
            {
                var ticks = (ulong)new DateTime(2020, 5, 6, 7, 8, 9).Ticks;
                foreach (var parameter in kind == "external-date" ? new[] { -1 } :
                    kind == "external-value" ? [0] : [0, -1])
                {
                    var date = Structure(parameter);
                    var dateTime = Field(date, "dateTime");
                    var data = Field(dateTime, "dateData");
                    var output = parameter == -1;
                    Require((Value(data, output) & 0x3FFFFFFFFFFFFFFFUL) ==
                        ticks + (output && kind == "date" ? 1800000000UL : 0) &&
                        Value(Field(date, "offsetMinutes"), output) == 0,
                        "The nested DateTimeOffset fields have the wrong values.");
                }
            }
            else if (kind is "pair" or "arguments")
            {
                foreach (var parameter in kind == "pair" ? new[] { 0 } : [1, 2])
                {
                    var pair = Structure(parameter);
                    Require(pair.TypeName.Contains("<int32, System.Guid>") &&
                        Field(pair, "key").Input == 0x12345678,
                        "A closed generic parameter lost its concrete type or key.");
                    GuidFields(Field(pair, "value"), false);
                }
                if (kind == "pair") GuidFields(Structure(-1), true);
                else Require(rows.Single(row => row.Parameter == -1).Output == 1,
                    "Capturing the generic value arguments changed the equality result.");
            }
            else if (kind == "nested")
            {
                var outer = Structure(0);
                Require(Field(outer, "key").Input == 17, "The outer generic key was lost.");
                foreach (var output in new[] { false, true })
                {
                    var inner = output ? Structure(-1) : Field(outer, "value");
                    GuidFields(Field(inner, "key"), output);
                    var field = Field(inner, "value");
                    if (limit >= 32)
                        Require(Value(field, output) == 0x1122334455667788,
                            "The nested generic value was decoded at the wrong offset.");
                    else
                        Require(Value(field, output) is null &&
                            (output ? field.OutputText : field.InputText) == "<not captured>",
                            "A truncated generic field displayed an invented value.");
                }
            }
            else if (kind == "forwarded")
            {
                var outer = Structure(0);
                Require(Field(outer, "key").Input == 31, "The custom value-type receiver lost its key.");
                foreach (var output in new[] { false, true })
                {
                    var value = output ? Structure(-1) : Field(outer, "value");
                    var date = Field(value, "Timestamp");
                    var dateTime = Field(date, "dateTime");
                    var data = Field(dateTime, "dateData");
                    Require(Value(Field(date, "offsetMinutes"), output) == 0,
                        "The cross-module nested offset was not decoded.");
                    if ((output ? dateTime.OutputMemory : dateTime.InputMemory)?.Bytes.Length >= 8)
                        Require((Value(data, output) & 0x3FFFFFFFFFFFFFFFUL) ==
                            (ulong)new DateTime(2020, 5, 6, 7, 8, 9).Ticks,
                            "The forwarded field type did not retain its nested date value.");
                    else Require(data.Input is null && data.InputText == "<not captured>",
                        "The forwarded field type read beyond the capture limit.");
                }
            }
            else if (kind is "version32" or "version64")
            {
                var outer = Structure(0);
                Require(Field(outer, "key").Input == (kind == "version32" ? 37UL : 38UL),
                    "The assembly-version fixture lost its receiver identity.");
                foreach (var output in new[] { false, true })
                {
                    var wrapper = output ? Structure(-1) : Field(outer, "value");
                    var value = Field(Field(wrapper, "Inner"), "Number");
                    Require(value.Type.Bits == (kind == "version32" ? 32 : 64) && Value(value, output) ==
                        (kind == "version32" ? 0x12345678UL : 0x1122334455667788UL),
                        "The type reference resolved against a different loaded assembly version.");
                }
            }
            else if (kind == "mixed")
            {
                var pair = Structure(0);
                var key = Field(Field(Field(pair, "key"), "Inner"), "Number");
                var value = Field(Field(Field(pair, "value"), "Inner"), "Number");
                var returned = Field(Field(Structure(-1), "Inner"), "Number");
                Require(key.Type.Bits == 32 && key.Input == 0x12345678 && value.Type.Bits == 64 &&
                    value.Input == 0x1122334455667788 && returned.Output == value.Input,
                    "Equal type names from different assemblies were merged in one parameter tree.");
            }
            else if (kind == "large")
            {
                var pair = Structure(0);
                Require(Field(pair, "key").Input == 43, "The large value receiver lost its key.");
                foreach (var output in new[] { false, true })
                {
                    var value = output ? Structure(-1) : Field(pair, "value");
                    var available = output ? value.OutputMemory?.Bytes.Length : value.InputMemory?.Bytes.Length;
                    Require(value.Children.Count == 200, "The large descriptor lost field definitions.");
                    for (var index = 0; index < 200; ++index)
                    {
                        var field = Field(value, $"RetainedValueFieldForCapture_{index:D3}_Ω");
                        Require(field.Type.Bits == 64, "A large-layout field has the wrong width.");
                        if ((index + 1) * 8 <= available)
                            Require(Value(field, output) == 1000UL + (uint)index,
                                "A large-layout field has the wrong captured value.");
                        else Require(Value(field, output) is null &&
                            (output ? field.OutputText : field.InputText) == "<not captured>",
                            "A large layout ignored the value capture limit.");
                    }
                }
            }
            else throw new InvalidOperationException("Unknown managed layout case.");
        }
        Console.WriteLine("Managed parameter, return, nested and generic field expansion passed.");
    }
}

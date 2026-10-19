using System.Text;

namespace Detourist.Desktop;

public static partial class ParameterValues
{
    private static void AddEtwBuffers(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        inputs = inputs.Where(value => value.EtwFormat >= 0).ToList();
        outputs = outputs.Where(value => value.EtwFormat >= 0).ToList();
        AddTraceMessageArguments(parent, inputs, outputs);
        foreach (var format in inputs.Concat(outputs).Select(value => value.EtwFormat).Distinct())
        {
            var before = inputs.FirstOrDefault(value => value.EtwFormat == format && value.MemberOffset < 0);
            var after = outputs.FirstOrDefault(value => value.EtwFormat == format && value.MemberOffset < 0);
            var sample = after ?? before;
            var type = format switch
            {
                0 => "EVENT_DATA_DESCRIPTOR", 1 => "EVENT_TRACE_HEADER", 2 => "EVENT_INSTANCE_HEADER",
                3 => "MOF_FIELD", _ => ""
            };
            if (sample is null || ApiMetadata.Structure(type) is not { Size: > 0 } layout) continue;
            var array = format is 0 or 3;
            var region = AddCapturedNode(parent, array ? format == 0 ? "Event data" : "MOF fields" : type,
                new(type + (array ? "[]" : ""), Kind: array ? "Array" : "Structure"), before, after);
            if (!array)
            {
                AddFields(region, layout, before, after);
                if (format == 1)
                {
                    var nodes = new List<ParameterProperty> { region };
                    for (var index = 0; index < nodes.Count; ++index) nodes.AddRange(nodes[index].Children);
                    var pointer = nodes.FirstOrDefault(value => value.Name == "GuidPtr");
                    var guidBefore = inputs.FirstOrDefault(value => value.EtwFormat == 4 && value.MemberOffset == 24);
                    var guidAfter = outputs.FirstOrDefault(value => value.EtwFormat == 4 && value.MemberOffset == 24);
                    if (pointer is not null && (guidBefore is not null || guidAfter is not null) &&
                        ApiMetadata.Structure("GUID") is { } guidLayout)
                    {
                        AddCapturedRecord(pointer, "GUID", "GUID", guidBefore, guidAfter, guidLayout);
                    }
                }
                var extent = Math.Max(before?.OriginalBytes ?? 0, after?.OriginalBytes ?? 0);
                if (extent > (uint)layout.Size && !inputs.Concat(outputs).Any(value => value.EtwFormat == 3))
                    AddCapturedNode(region, "Payload", new("byte[]"),
                        Slice(before, layout.Size, (int)Math.Min(extent - (uint)layout.Size, int.MaxValue)),
                        Slice(after, layout.Size, (int)Math.Min(extent - (uint)layout.Size, int.MaxValue)), parent.Hex);
                continue;
            }

            var length = Math.Max(before?.OriginalBytes ?? 0, after?.OriginalBytes ?? 0);
            AddArray(region, new("Array", (int)Math.Min(length, int.MaxValue), type + "[]", type,
                (int)Math.Min(length / (uint)layout.Size, int.MaxValue)), before, after, 0, 0);

            // Event schema-independent payload bytes belong to their recorded descriptor's pointer field.
            foreach (var offset in inputs.Concat(outputs)
                .Where(value => value.EtwFormat == format && value.MemberOffset >= 0)
                .Select(value => value.MemberOffset).Distinct())
            {
                var recordName = $"[{offset / layout.Size}]";
                var record = region.Children.FirstOrDefault(value => value.Name == recordName);
                var pointer = record?.Children.FirstOrDefault(value => value.Name == (format == 0 ? "Ptr" : "DataPtr"));
                if (pointer is not null) AddCapturedReference(pointer, "Bytes", new("byte[]"),
                    inputs.FirstOrDefault(value => value.EtwFormat == format && value.MemberOffset == offset),
                    outputs.FirstOrDefault(value => value.EtwFormat == format && value.MemberOffset == offset));
            }
            if (format == 0 && before is not null)
                AddTraceLoggingEvent(region, before, inputs.Where(value => value.EtwFormat == 0 &&
                    value.MemberOffset >= 0).ToList());
        }
    }

    private const int EventDataDescriptorSize = 16;
    private const int TraceLoggingChainBit = 0x80;
    private const int TraceLoggingCountMask = 0x60;
    private const int TraceLoggingTypeMask = 0x1F;
    private const int TraceLoggingOutTypeMask = 0x7F;
    private const int TraceLoggingStructType = 24;

    private static readonly string[] TraceLoggingTypes = ["NULL", "UNICODESTRING", "ANSISTRING", "INT8", "UINT8",
        "INT16", "UINT16", "INT32", "UINT32", "INT64", "UINT64", "FLOAT", "DOUBLE", "BOOL32", "BINARY", "GUID",
        "POINTER", "FILETIME", "SYSTEMTIME", "SID", "HEXINT32", "HEXINT64", "COUNTEDSTRING", "COUNTEDANSISTRING",
        "STRUCT", "COUNTEDBINARY"];

    private static void AddTraceLoggingEvent(ParameterProperty region, MemorySnapshot descriptors,
        List<MemorySnapshot> payloads)
    {
        // TraceLogging marks its provider and event metadata descriptors; the remaining payloads follow that schema.
        var available = descriptors.Bytes.Length / EventDataDescriptorSize;
        if (available < 2 || descriptors.Bytes[12] != 2 || descriptors.Bytes[28] != 1) return;
        byte[]? Payload(int index)
        {
            var value = payloads.FirstOrDefault(item => item.MemberOffset == index * EventDataDescriptorSize);
            return value is not null && (value.Flags & (uint)ValueFlags.Unreadable) == 0 &&
                (ulong)value.Bytes.Length == value.OriginalBytes ? value.Bytes : null;
        }
        static string? Text(byte[] data, ref int offset, int end)
        {
            var terminator = Array.IndexOf(data, (byte)0, offset, Math.Max(0, end - offset));
            if (terminator < 0) return null;
            var text = Encoding.UTF8.GetString(data, offset, terminator - offset);
            offset = terminator + 1;
            return text;
        }
        if (Payload(0) is not { Length: >= 3 } provider || Payload(1) is not { Length: >= 3 } metadata) return;
        var position = 2;
        var providerName = Text(provider, ref position, Math.Min(provider.Length, BitConverter.ToUInt16(provider)));
        var end = Math.Min(metadata.Length, BitConverter.ToUInt16(metadata));
        position = 2;
        while (position < end && (metadata[position++] & TraceLoggingChainBit) != 0) { }
        var eventName = Text(metadata, ref position, end);
        if (providerName is null || eventName is null) return;

        // Field metadata holds a name, an in-type with an optional chained out-type and tags, then any constant count.
        var fields = new List<(string Name, int InType, int OutType, int Count)>();
        while (position < end)
        {
            if (Text(metadata, ref position, end) is not { } name || position >= end) return;
            int inType = metadata[position++], outType = 0;
            if ((inType & TraceLoggingChainBit) != 0)
            {
                if (position >= end) return;
                outType = metadata[position++];
                if ((outType & TraceLoggingChainBit) != 0)
                    while (position < end && (metadata[position++] & TraceLoggingChainBit) != 0) { }
            }
            var count = 1;
            if ((inType & TraceLoggingCountMask) == 0x20)
            {
                if (position + 2 > end) return;
                count = BitConverter.ToUInt16(metadata, position);
                position += 2;
            }
            else if ((inType & TraceLoggingCountMask) == 0x40) count = -1;
            else if ((inType & TraceLoggingCountMask) == 0x60 ||
                (inType & TraceLoggingTypeMask) >= TraceLoggingTypes.Length) return;
            fields.Add((name, inType & TraceLoggingTypeMask, outType & TraceLoggingOutTypeMask, count));
        }

        // Field data is the end-to-end concatenation of every recorded data descriptor after the metadata.
        var data = new List<byte>();
        var complete = descriptors.OriginalBytes == (ulong)descriptors.Bytes.Length;
        for (var index = 2; index < available && complete; ++index)
        {
            if (MemorySnapshot.Scalar(descriptors.Bytes, index * EventDataDescriptorSize + 8, 4) == 0) continue;
            if (Payload(index) is { } part) data.AddRange(part);
            else complete = false;
        }
        var bytes = data.ToArray();
        var offset = 0;
        var node = AddCapturedNode(region, "TraceLogging event", new("TraceLogging event", Kind: "Structure"),
            null, null);
        node.InputLabel = $"{providerName}/{eventName}";

        bool Value(int inType, int outType, out string text)
        {
            text = "";
            var remaining = bytes.Length - offset;
            int WideLength()
            {
                for (var at = offset; at + 1 < bytes.Length; at += 2)
                    if (bytes[at] == 0 && bytes[at + 1] == 0) return at - offset + 2;
                return -1;
            }
            var size = inType switch
            {
                3 or 4 => 1, 5 or 6 => 2, 7 or 8 or 11 or 13 or 20 => 4, 9 or 10 or 12 or 17 or 21 => 8, 15 or 18 => 16,
                14 or 22 or 23 or 25 => remaining >= 2 ? 2 + BitConverter.ToUInt16(bytes, offset) : -1,
                19 => remaining >= 2 && bytes[offset + 1] <= 15 ? 8 + bytes[offset + 1] * 4 : -1,
                1 => WideLength(),
                2 => Array.IndexOf(bytes, (byte)0, offset) is var terminator and >= 0 ? terminator - offset + 1 : -1,
                _ => -1
            };
            if (size < 0 || size > remaining) return false;
            var span = bytes.AsSpan(offset, size);
            var value = inType is >= 3 and <= 10 or 13 or 20 or 21 ? MemorySnapshot.Scalar(bytes, offset, size) : 0;
            var signed = (long)(value << (64 - size * 8)) >> (64 - size * 8);
            var narrow = outType == 35 ? Encoding.UTF8 : Encoding.Latin1;
            var invariant = System.Globalization.CultureInfo.InvariantCulture;
            offset += size;
            text = inType switch
            {
                1 => "\"" + Encoding.Unicode.GetString(span[..^2]) + "\"",
                2 => "\"" + narrow.GetString(span[..^1]) + "\"",
                22 => "\"" + Encoding.Unicode.GetString(span[2..]) + "\"",
                23 => "\"" + narrow.GetString(span[2..]) + "\"",
                14 or 25 => Convert.ToHexString(span[2..]),
                11 => BitConverter.ToSingle(span).ToString(invariant),
                12 => BitConverter.ToDouble(span).ToString(invariant),
                15 => new Guid(span).ToString("B"),
                17 => BitConverter.ToInt64(span) is var time and >= 0 and <= 2650467743999999999 ?
                    DateTime.FromFileTimeUtc(time).ToString("o", invariant) : $"0x{BitConverter.ToUInt64(span):X}",
                18 => $"{BitConverter.ToUInt16(span):0000}-{BitConverter.ToUInt16(span[2..]):00}-" +
                    $"{BitConverter.ToUInt16(span[6..]):00} {BitConverter.ToUInt16(span[8..]):00}:" +
                    $"{BitConverter.ToUInt16(span[10..]):00}:{BitConverter.ToUInt16(span[12..]):00}." +
                    $"{BitConverter.ToUInt16(span[14..]):000}",
                19 => SidText(span) ?? Convert.ToHexString(span),
                _ when inType == 13 || outType == 3 => value == 0 ? "False" : $"True ({value})",
                _ when inType is 20 or 21 || outType is 4 or 13 or 14 or 15 => $"0x{value:X}",
                _ when inType is 3 or 5 or 7 or 9 => signed.ToString(invariant),
                _ => value.ToString(invariant)
            };
            return true;
        }
        void Skip(ref int index)
        {
            var (_, inType, outType, _) = fields[index++];
            if (inType != TraceLoggingStructType) return;
            for (var member = 0; member < outType && index < fields.Count; ++member) Skip(ref index);
        }

        // Structures group the following fields; arrays repeat a value or structure by constant or prefixed count.
        bool Field(ParameterProperty parent, ref int index)
        {
            var (name, inType, outType, count) = fields[index++];
            var members = index;
            var property = AddCapturedNode(parent, name,
                new(TraceLoggingTypes[inType] + (count == 1 ? "" : "[]"),
                    Kind: inType == TraceLoggingStructType ? "Structure" : count == 1 ? "Integer" : "Array"),
                null, null);
            var values = count;
            if (count < 0)
            {
                if (offset + 2 > bytes.Length) return false;
                values = BitConverter.ToUInt16(bytes, offset);
                offset += 2;
            }
            var texts = new List<string>();
            for (var element = 0; element < values; ++element)
            {
                var target = property;
                if (count != 1)
                    property.Children.Add(target = new()
                    {
                        Name = $"[{element}]", SignatureType = new(TraceLoggingTypes[inType]),
                        Level = property.Level + 1, Hex = parent.Hex
                    });
                if (inType == TraceLoggingStructType)
                {
                    index = members;
                    for (var member = 0; member < outType; ++member)
                        if (index >= fields.Count || !Field(target, ref index)) return false;
                    continue;
                }
                if (!Value(inType, outType, out var text)) return false;
                target.InputLabel = text;
                texts.Add(text);
            }

            // A structure's member definitions follow it once, even when an array encodes no elements.
            if (inType == TraceLoggingStructType)
            {
                index = members;
                for (var member = 0; member < outType && index < fields.Count; ++member) Skip(ref index);
            }
            else if (count != 1) property.InputLabel = "[" + string.Join(", ", texts) + "]";
            return true;
        }
        for (var index = 0; index < fields.Count;)
        {
            var start = index;
            if (complete && Field(node, ref index)) continue;

            // Unrecorded or malformed data leaves the remaining declared fields without fabricated values.
            if (complete) node.Children.RemoveAt(node.Children.Count - 1);
            for (index = start; index < fields.Count;)
            {
                node.Children.Add(new()
                {
                    Name = fields[index].Name, SignatureType = new(TraceLoggingTypes[fields[index].InType]),
                    InputLabel = "<not captured>", Level = node.Level + 1, Hex = region.Hex
                });
                Skip(ref index);
            }
        }
    }

    private static void AddTraceMessageArguments(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        var before = inputs.FirstOrDefault(value => value.EtwFormat == 5);
        var after = outputs.FirstOrDefault(value => value.EtwFormat == 5);
        if (before is null && after is null) return;
        var table = AddCapturedNode(parent, "Argument pairs", new("(PVOID, SIZE_T)[]", Kind: "Array"),
            before, after);
        var bytes = Math.Max(before?.Bytes.Length ?? 0, after?.Bytes.Length ?? 0);
        var width = parent.PointerSize;
        var stride = width * 2;
        var count = Math.Min(Protocol.MaxExpandedElements, (bytes + stride - 1) / stride);

        // Each recorded pair preserves its pointer, declared length and captured payload independently.
        for (var index = 0; index < count; ++index)
        {
            var offset = index * stride;
            var pair = AddCapturedNode(table, $"[{index}]", new("Argument pair", Kind: "Structure"),
                Slice(before, offset, stride), Slice(after, offset, stride), parent.Hex);
            foreach (var (name, type, position) in new[] { ("Pointer", "PVOID", 0), ("Length", "SIZE_T", width) })
            {
                var field = new ParameterProperty
                {
                    Name = name, SignatureType = ParameterType.Infer(type), Level = pair.Level + 1, Hex = parent.Hex,
                    Input = before is not null && before.Bytes.Length >= offset + position + width ?
                        MemorySnapshot.Scalar(before.Bytes, offset + position, width) : null,
                    Output = after is not null && after.Bytes.Length >= offset + position + width ?
                        MemorySnapshot.Scalar(after.Bytes, offset + position, width) : null
                };
                pair.Children.Add(field);
                if (position != 0) continue;
                var input = inputs.FirstOrDefault(value => value.EtwFormat == 6 && value.MemberOffset == offset);
                var output = outputs.FirstOrDefault(value => value.EtwFormat == 6 && value.MemberOffset == offset);
                if (input is null && output is null) continue;
                AddCapturedNode(field, "Bytes", new("byte[]"),
                    input, output, parent.Hex);
            }
        }
        if ((bytes + stride - 1) / stride > count)
            AddCapturedNode(table, "Remaining pairs", new("(PVOID, SIZE_T)[]", Kind: "Array"),
                Slice(before, count * stride, bytes - count * stride),
                Slice(after, count * stride, bytes - count * stride), parent.Hex);
    }
}

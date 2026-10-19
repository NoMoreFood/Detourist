namespace Detourist.Desktop;

public static partial class ParameterValues
{
    private const int SidHeaderSize = 8;
    private const int SidMaxSubAuthorities = 15;
    private const ushort SelfRelativeControlFlag = 0x8000;
    private const int AclHeaderSize = 8;
    private const int GuidSize = 16;
    private const int MaxConditionStack = 256;
    private const int MaxConditionDepth = 8;
    private const int MaxClaimValues = 1024;

    private static void AddNetApiRecords(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        inputs = inputs.Where(value => value.Structure.Length > 0 || value.SecurityPart >= 0).ToList();
        outputs = outputs.Where(value => value.Structure.Length > 0 || value.SecurityPart >= 0).ToList();
        var before = inputs.FirstOrDefault(value => value.MemberOffset < 0);
        var after = outputs.FirstOrDefault(value => value.MemberOffset < 0);
        var sample = after ?? before;
        if (sample is null || ApiMetadata.Structure(sample.Structure) is not { Size: > 0 } layout) return;
        var extent = Math.Max(before?.OriginalBytes ?? 0, after?.OriginalBytes ?? 0);
        var count = (int)Math.Min(extent / (uint)layout.Size, int.MaxValue);
        var array = AddCapturedRecord(parent, "Records", sample.Structure + "[]", before, after,
            new("Array", (int)Math.Min(extent, int.MaxValue), sample.Structure + "[]",
                sample.Structure, count), "Integer");

        // Each referenced field remains associated with its complete captured record.
        foreach (var offset in inputs.Concat(outputs).Where(value => value.MemberOffset >= 0)
            .Select(value => value.MemberOffset).Distinct())
        {
            var recordName = $"[{offset / layout.Size}]";
            var record = array.Children.FirstOrDefault(value => value.Name == recordName);
            var (owner, field) = record is null ? (null, null) :
                FindCapturedField(record, layout, offset % layout.Size);
            if (owner is null || field is null) continue;
            if (inputs.Concat(outputs).Any(value => value.MemberOffset == offset && value.SecurityPart >= 0))
            {
                AddNetApiSecurity(owner, inputs.Where(value => value.MemberOffset == offset).ToList(),
                    outputs.Where(value => value.MemberOffset == offset).ToList());
                continue;
            }
            before = inputs.FirstOrDefault(value => value.MemberOffset == offset);
            after = outputs.FirstOrDefault(value => value.MemberOffset == offset);
            if ((before?.Sid ?? false) || (after?.Sid ?? false))
                AddNetApiSid(owner, before, after);
            else if ((before?.Buffer ?? false) || (after?.Buffer ?? false))
                AddCapturedReference(owner, "Bytes", new("byte[]", Kind: "Array"), before, after);
            else AddCapturedReference(owner, "Text", ParameterType.Infer(field.Type), before, after, true);
        }
    }

    private static void AddNetApiSid(ParameterProperty parent, MemorySnapshot? before, MemorySnapshot? after)
    {
        if (ApiMetadata.Structure("SID") is not { } layout) return;
        static int Count(MemorySnapshot? value) => value is { Bytes.Length: >= SidHeaderSize } &&
            value.Bytes[0] == 1 && value.Bytes[1] <= SidMaxSubAuthorities ? value.Bytes[1] : 0;
        var sid = AddCapturedNode(parent, "SID", new("SID", Kind: "Structure"),
            before, after);
        sid.InputLabel = SidText(before?.Bytes, allowPartial: true);
        sid.OutputLabel = SidText(after?.Bytes, allowPartial: true);

        // The fixed authority header defines the variable inline subauthority array.
        AddFields(sid, layout with { Fields = layout.Fields?.Where(field => field.Name != "SubAuthority").ToArray() },
            before, after);
        var count = Math.Max(Count(before), Count(after));
        var array = AddCapturedNode(sid, "SubAuthority", new("DWORD[]", Kind: "Array"),
            Slice(before, SidHeaderSize, count * 4), Slice(after, SidHeaderSize, count * 4), parent.Hex);
        AddArray(array, new("Array", count * 4, "DWORD[]", "DWORD", count), before, after, SidHeaderSize, 0);
    }

    private static void AddSecurityDescriptors(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        // Standalone descriptors and pointer arrays share the same bounded security-component rendering.
        inputs = inputs.Where(value => value.SecurityPart >= 0 && (value.Flags & (uint)ValueFlags.NetApiData) == 0).ToList();
        outputs = outputs.Where(value => value.SecurityPart >= 0 && (value.Flags & (uint)ValueFlags.NetApiData) == 0).ToList();
        var table = inputs.FirstOrDefault(value => value.SecurityPart == 5);
        if (table is null)
        {
            AddNetApiSecurity(parent, inputs, outputs);
            return;
        }
        var array = AddCapturedNode(parent, "Security descriptors", new("PSECURITY_DESCRIPTOR[]", Kind: "Array"),
            table, null);
        AddArray(array, new("Array", (int)Math.Min(table.OriginalBytes, int.MaxValue), "PSECURITY_DESCRIPTOR[]",
            "PSECURITY_DESCRIPTOR", (int)Math.Min(table.OriginalBytes / 8, int.MaxValue)), table, null, 0, 0);
        foreach (var offset in inputs.Where(value => value.SecurityPart == 0 && value.MemberOffset >= 0)
            .Select(value => value.MemberOffset).Distinct())
        {
            var element = array.Children.FirstOrDefault(value => value.Name == $"[{offset / 8}]");
            if (element is not null)
                AddNetApiSecurity(element, inputs.Where(value => value.MemberOffset == offset).ToList(), []);
        }
    }

    private static void AddNetApiSecurity(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        var before = inputs.FirstOrDefault(value => value.SecurityPart == 0);
        var after = outputs.FirstOrDefault(value => value.SecurityPart == 0);
        var sample = after ?? before;
        if (sample is null) return;
        var relative = sample.OriginalBytes == 20 || sample.Bytes.Length >= 4 &&
            (MemorySnapshot.Scalar(sample.Bytes, 2, 2) & SelfRelativeControlFlag) != 0;
        var type = relative ? "SECURITY_DESCRIPTOR_RELATIVE" : "SECURITY_DESCRIPTOR";
        var descriptor = AddCapturedNode(parent, "Security descriptor", new(type, Kind: "Structure"),
            before, after);
        if (ApiMetadata.Structure(type) is { } layout) AddFields(descriptor, layout, before, after);

        // Captured components belong to the descriptor's SDK pointer or relative-offset field.
        foreach (var (part, name) in new[] { (1, "Owner"), (2, "Group"), (3, "Dacl"), (4, "Sacl") })
        {
            before = inputs.FirstOrDefault(value => value.SecurityPart == part);
            after = outputs.FirstOrDefault(value => value.SecurityPart == part);
            if (before is null && after is null) continue;
            var field = descriptor.Children.FirstOrDefault(value => value.Name == name);
            if (field is null) continue;
            if (part <= 2) AddNetApiSid(field, before, after);
            else AddNetApiAcl(field, before, after);
        }
    }

    private static void AddNetApiAcl(ParameterProperty parent, MemorySnapshot? before, MemorySnapshot? after)
    {
        var acl = AddCapturedNode(parent, "ACL", new("ACL", Kind: "Structure"),
            before, after);
        if (ApiMetadata.Structure("ACL") is { } layout) AddFields(acl, layout, before, after);
        var sample = after ?? before;
        if (sample is not { Bytes.Length: >= AclHeaderSize } || sample.Bytes[0] is not (2 or 4)) return;
        var size = (int)MemorySnapshot.Scalar(sample.Bytes, 2, 2);
        var count = (int)MemorySnapshot.Scalar(sample.Bytes, 4, 2);
        if (size < AclHeaderSize || (uint)size > sample.OriginalBytes) return;
        var offset = AclHeaderSize;

        // Each complete recorded ACE header supplies its extent; unknown ACE bodies remain raw bytes.
        for (var index = 0; index < count && index < Protocol.MaxExpandedElements &&
            offset + 4 <= sample.Bytes.Length; ++index)
        {
            var bytes = (int)MemorySnapshot.Scalar(sample.Bytes, offset + 2, 2);
            if (bytes < 4 || bytes > size - offset) return;
            var input = Slice(before, offset, bytes);
            var output = Slice(after, offset, bytes);
            var entry = AddCapturedNode(acl, $"ACE [{index}]", new("ACE_HEADER", Kind: "Structure"),
                input, output, parent.Hex);
            if (ApiMetadata.Structure("ACE_HEADER") is { } header) AddFields(entry, header, input, output);
            if (bytes > 4)
                AddCapturedNode(entry, "Data", new("byte[]"),
                    Slice(input, 4, bytes - 4), Slice(output, 4, bytes - 4), parent.Hex);
            AddAceBody(entry, sample.Bytes[offset], bytes, input, output);
            offset += bytes;
        }
        if (count > Protocol.MaxExpandedElements || offset < size)
            AddCapturedNode(acl, "Remaining ACE data", new("byte[]"),
                Slice(before, offset, size - offset), Slice(after, offset, size - offset), parent.Hex);
    }

    private static void AddAceBody(ParameterProperty entry, byte type, int bytes, MemorySnapshot? input,
        MemorySnapshot? output)
    {
        // MS-DTYP bodies start with a mask; object forms add flags and optional GUIDs before the trustee SID.
        var objectAce = type is >= 5 and <= 8 or 11 or 12 or 15 or 16;
        var trailing = type is >= 9 and <= 16 or 0x12 or 0x15;
        if (type is 4 or > 0x15 || bytes < 8) return;
        var sample = output ?? input;
        entry.Children.Add(new()
        {
            Name = "Mask", SignatureType = ParameterType.Infer("ACCESS_MASK"),
            Input = input is { Bytes.Length: >= 8 } ? MemorySnapshot.Scalar(input.Bytes, 4, 4) : null,
            Output = output is { Bytes.Length: >= 8 } ? MemorySnapshot.Scalar(output.Bytes, 4, 4) : null,
            Level = entry.Level + 1, Hex = entry.Hex
        });
        var sidOffset = 8;
        if (objectAce)
        {
            if (sample is not { Bytes.Length: >= 12 } || bytes < 12) return;
            var flags = MemorySnapshot.Scalar(sample.Bytes, 8, 4);
            entry.Children.Add(new()
            {
                Name = "Flags", SignatureType = ParameterType.Infer("DWORD"),
                Input = input is { Bytes.Length: >= 12 } ? MemorySnapshot.Scalar(input.Bytes, 8, 4) : null,
                Output = output is { Bytes.Length: >= 12 } ? MemorySnapshot.Scalar(output.Bytes, 8, 4) : null,
                Level = entry.Level + 1, Hex = entry.Hex
            });
            sidOffset = 12;
            static string? GuidText(MemorySnapshot? value) => value is { Bytes.Length: GuidSize } ?
                new Guid(value.Bytes).ToString("B") : null;
            foreach (var (bit, name) in new[] { (1UL, "ObjectType"), (2UL, "InheritedObjectType") })
            {
                if ((flags & bit) == 0) continue;
                if (sidOffset + GuidSize > bytes) return;
                var guidBefore = Slice(input, sidOffset, GuidSize);
                var guidAfter = Slice(output, sidOffset, GuidSize);
                var guid = AddCapturedNode(entry, name, new("GUID", Kind: "Structure"),
                    guidBefore, guidAfter);
                guid.InputLabel = GuidText(guidBefore);
                guid.OutputLabel = GuidText(guidAfter);
                if (ApiMetadata.Structure("GUID") is { } layout) AddFields(guid, layout, guidBefore, guidAfter);
                sidOffset += GuidSize;
            }
        }

        // The validated trustee SID bounds any callback, filter or resource-attribute data that follows it.
        if (sample is not { } value || value.Bytes.Length < sidOffset + SidHeaderSize || value.Bytes[sidOffset] != 1 ||
            value.Bytes[sidOffset + 1] > SidMaxSubAuthorities) return;
        var sid = SidHeaderSize + value.Bytes[sidOffset + 1] * 4;
        if (sid > bytes - sidOffset) return;
        AddNetApiSid(entry, Slice(input, sidOffset, sid), Slice(output, sidOffset, sid));
        var dataOffset = sidOffset + sid;
        if (!trailing || dataOffset >= bytes) return;
        var dataBefore = Slice(input, dataOffset, bytes - dataOffset);
        var dataAfter = Slice(output, dataOffset, bytes - dataOffset);
        string? Describe(MemorySnapshot? data) => data is null || (ulong)data.Bytes.Length < data.OriginalBytes ? null :
            type == 0x12 ? ClaimText(data.Bytes) : ConditionText(data.Bytes);
        entry.Children.Add(new()
        {
            Name = type == 0x12 ? "AttributeData" : "ApplicationData", SignatureType = new("byte[]"),
            InputMemory = dataBefore, OutputMemory = dataAfter, InputLabel = Describe(dataBefore),
            OutputLabel = Describe(dataAfter), Level = entry.Level + 1, Hex = entry.Hex
        });
    }

    private static string? SidText(ReadOnlySpan<byte> bytes, bool allowPartial = false)
    {
        if (bytes.Length < SidHeaderSize || bytes[0] != 1 || bytes[1] > SidMaxSubAuthorities) return null;
        var captured = Math.Min(bytes[1], (bytes.Length - SidHeaderSize) / 4);
        if (!allowPartial && captured < bytes[1]) return null;
        ulong authority = 0;
        for (var index = 2; index < SidHeaderSize; ++index) authority = authority << 8 | bytes[index];
        var text = authority > uint.MaxValue ? $"S-1-0x{authority:X}" : $"S-1-{authority}";
        for (var index = 0; index < captured; ++index)
            text += $"-{BitConverter.ToUInt32(bytes.Slice(SidHeaderSize + index * 4, 4))}";
        return captured == bytes[1] ? text : text + "-… · truncated";
    }

    private static string? ConditionText(byte[] data)
    {
        // Conditional ACE data is an "artx" postfix token stream; render it with the SDDL spellings Windows emits.
        if (data.Length < 4 || data[0] != 'a' || data[1] != 'r' || data[2] != 't' || data[3] != 'x') return null;
        var stack = new List<(string Text, bool Expression)>();
        var position = 4;
        static string Operand((string Text, bool Expression) item) => item.Expression ? item.Text : $"({item.Text})";
        while (position < data.Length && stack.Count < MaxConditionStack)
        {
            var token = data[position];
            if (token == 0)
            {
                if (data.AsSpan(position).ContainsAnyExcept((byte)0)) return null;
                break;
            }
            string? unary = token switch
            {
                0x87 => "Exists", 0x89 => "Member_of", 0x8a => "Device_Member_of", 0x8b => "Member_of_any",
                0x8c => "Device_Member_of_any", 0x8d => "Not_Exists", 0x90 => "Not_Member_of",
                0x91 => "Not_Device_Member_of", 0x92 => "Not_Member_of_any", 0x93 => "Not_Device_Member_of_any",
                _ => null
            };
            string? binary = token switch
            {
                0x80 => "==", 0x81 => "!=", 0x82 => "<", 0x83 => "<=", 0x84 => ">", 0x85 => ">=",
                0x86 => "Contains", 0x88 => "Any_of", 0x8e => "Not_Contains", 0x8f => "Not_Any_of",
                0xa0 => "&&", 0xa1 => "||", _ => null
            };
            if (unary is not null || token == 0xa2)
            {
                if (stack.Count < 1) return null;
                var operand = stack[^1];
                stack[^1] = (token == 0xa2 ? $"(!{Operand(operand)})" : $"({unary} {operand.Text})", true);
                ++position;
            }
            else if (binary is not null)
            {
                if (stack.Count < 2) return null;
                var (left, right) = (stack[^2], stack[^1]);
                stack.RemoveAt(stack.Count - 1);
                stack[^1] = token >= 0xa0 ? ($"({Operand(left)} {binary} {Operand(right)})", true) :
                    ($"({left.Text} {binary} {right.Text})", true);
                ++position;
            }
            else if (ConditionLiteral(data, ref position, data.Length, 0) is { } literal) stack.Add((literal, false));
            else return null;
        }
        return stack.Count == 1 ? stack[0].Expression ? stack[0].Text : $"({stack[0].Text})" : null;
    }

    private static string? ConditionLiteral(byte[] data, ref int position, int end, int depth)
    {
        // Integer literals keep their recorded sign and base; length-prefixed operands stay within the token stream.
        if (position >= end || depth > MaxConditionDepth) return null;
        var token = data[position++];
        if (token is >= 1 and <= 4)
        {
            if (end - position < 10) return null;
            var value = BitConverter.ToInt64(data, position);
            var (sign, radix) = (data[position + 8], data[position + 9]);
            position += 10;
            var negative = sign == 2 || sign != 1 && radix == 2 && value < 0;
            var magnitude = negative ? unchecked((ulong)-value) : unchecked((ulong)value);
            var digits = radix switch
            {
                1 => magnitude == 0 ? "0" : "0" + Convert.ToString(unchecked((long)magnitude), 8),
                2 => magnitude.ToString(System.Globalization.CultureInfo.InvariantCulture),
                3 => $"0x{magnitude:x}", _ => null
            };
            return digits is null || sign is < 1 or > 3 ? null : (sign == 1 ? "+" : negative ? "-" : "") + digits;
        }
        if (token is not (0x10 or 0x18 or 0x50 or 0x51 or >= 0xf8 and <= 0xfb) || end - position < 4) return null;
        var length = BitConverter.ToUInt32(data, position);
        position += 4;
        if (length > end - position) return null;
        var payload = data.AsSpan(position, (int)length);
        var start = position;
        position += (int)length;
        if (token == 0x18) return "#" + Convert.ToHexStringLower(payload);
        if (token == 0x51) return SidText(payload) is { } sid ? $"SID({sid})" : null;
        if (token == 0x50)
        {
            var items = new List<string>();
            for (var offset = start; offset < position;)
            {
                if (ConditionLiteral(data, ref offset, position, depth + 1) is not { } item) return null;
                items.Add(item);
            }
            return "{" + string.Join(", ", items) + "}";
        }
        if (length % 2 != 0) return null;
        var text = System.Text.Encoding.Unicode.GetString(payload);
        return token switch
        {
            0x10 => $"\"{text}\"", 0xf9 => "@USER." + text, 0xfa => "@RESOURCE." + text, 0xfb => "@DEVICE." + text,
            _ => text
        };
    }

    private static string? ClaimText(byte[] data)
    {
        // CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 offsets are relative to the start of the resource-attribute data.
        if (data.Length < 16) return null;
        var count = MemorySnapshot.Scalar(data, 12, 4);
        if (count > MaxClaimValues || 16 + count * 4 > (ulong)data.Length) return null;
        string? Text(ulong offset)
        {
            if (offset >= (ulong)data.Length) return null;
            var span = data.AsSpan((int)offset);
            var length = 0;
            while (length + 1 < span.Length && (span[length] | span[length + 1]) != 0) length += 2;
            return length + 1 < span.Length ? System.Text.Encoding.Unicode.GetString(span[..length]) : null;
        }
        byte[]? Octets(ulong offset) => offset + 4 <= (ulong)data.Length &&
            MemorySnapshot.Scalar(data, (int)offset, 4) <= (ulong)data.Length - offset - 4 ?
            data.AsSpan((int)offset + 4, (int)MemorySnapshot.Scalar(data, (int)offset, 4)).ToArray() : null;
        var valueType = MemorySnapshot.Scalar(data, 4, 2);
        var code = valueType switch { 1 => "TI", 2 => "TU", 3 => "TS", 5 => "TD", 6 => "TB", 0x10 => "TX", _ => null };
        if (code is null || Text(MemorySnapshot.Scalar(data, 0, 4)) is not { } name) return null;
        var parts = new List<string> { $"\"{name}\"", code, $"0x{MemorySnapshot.Scalar(data, 8, 4):x}" };
        for (var index = 0; index < (int)count; ++index)
        {
            var offset = MemorySnapshot.Scalar(data, 16 + index * 4, 4);
            string? item = valueType switch
            {
                1 or 2 or 6 when offset + 8 <= (ulong)data.Length => valueType == 1 ?
                    BitConverter.ToInt64(data, (int)offset)
                        .ToString(System.Globalization.CultureInfo.InvariantCulture) :
                    BitConverter.ToUInt64(data, (int)offset)
                        .ToString(System.Globalization.CultureInfo.InvariantCulture),
                3 => Text(offset) is { } text ? $"\"{text}\"" : null,
                5 => Octets(offset) is { } sid ? SidText(sid) : null,
                0x10 => Octets(offset) is { } octets ? Convert.ToHexStringLower(octets) : null,
                _ => null
            };
            if (item is null) return null;
            parts.Add(item);
        }
        return "(" + string.Join(",", parts) + ")";
    }
}

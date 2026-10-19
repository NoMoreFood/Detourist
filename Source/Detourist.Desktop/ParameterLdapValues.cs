using System.Text;

namespace Detourist.Desktop;

public static partial class ParameterValues
{
    private static (MemorySnapshot? Before, MemorySnapshot? After) LdapPair(List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs, int index, int part, int? element = null)
    {
        bool Matches(MemorySnapshot sample) => sample.ModIndex == index && sample.LdapPart == part &&
            (element is null || sample.ElementIndex == element);
        return (inputs.FirstOrDefault(Matches), outputs.FirstOrDefault(Matches));
    }

    private static void AddLdapControls(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        inputs = inputs.Where(value => (value.Flags & (uint)ValueFlags.LdapData) != 0 &&
            value.LdapPart is >= 7 and <= 10).ToList();
        outputs = outputs.Where(value => (value.Flags & (uint)ValueFlags.LdapData) != 0 &&
            value.LdapPart is >= 7 and <= 10).ToList();
        if (inputs.Count == 0 && outputs.Count == 0) return;
        var layout = ApiMetadata.Structure(parent.SignatureType.Name);
        if (layout?.Name is not ("LDAPControlA" or "LDAPControlW")) return;
        var pointers = inputs.Concat(outputs).Any(value => value.LdapPart == 10);
        var container = parent;
        if (pointers)
            container = AddCapturedNode(parent, "Controls", new(layout.Name + " *[]"),
                inputs.FirstOrDefault(value => value.LdapPart == 10),
                outputs.FirstOrDefault(value => value.LdapPart == 10));

        // Control fields retain their own OID and binary payload, including embedded zero bytes.
        foreach (var index in inputs.Concat(outputs).Where(value => value.LdapPart == 7)
            .Select(value => value.ModIndex).Distinct())
        {
            var (before, after) = LdapPair(inputs, outputs, index, 7);
            var control = AddCapturedRecord(container, pointers ? $"[{index}]" : layout.Name,
                layout.Name, before, after, layout);
            var oid = control.Children.FirstOrDefault(value => value.Name == "ldctl_oid");
            (before, after) = LdapPair(inputs, outputs, index, 8);
            if (oid is not null && (before is not null || after is not null)) AddCapturedReference(oid, "Text",
                new(layout.Name.EndsWith('W') ? "wchar_t *" : "char *"), before, after, true);
            var binary = control.Children.FirstOrDefault(value => value.Name == "ldctl_value")?
                .Children.FirstOrDefault(value => value.Name == "bv_val");
            (before, after) = LdapPair(inputs, outputs, index, 9);
            if (binary is not null && (before is not null || after is not null))
                AddCapturedReference(binary, "Bytes", new("byte[]"), before, after);
        }
    }

    private static void AddBerBytes(ParameterProperty descriptor, MemorySnapshot? before, MemorySnapshot? after)
    {
        if ((before is not null || after is not null) &&
            descriptor.Children.FirstOrDefault(field => field.Name == "bv_val") is { } pointer)
            AddCapturedReference(pointer, "Bytes", new("byte[]"), before, after);
    }

    private static void AddLdapBerValues(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        var samples = inputs.Concat(outputs).Where(value => (value.Flags & (uint)ValueFlags.LdapData) != 0).ToArray();
        if (samples.Any(value => value.LdapPart is 1 or 7 or 10 or 11) ||
            !samples.Any(value => value.LdapPart == 5)) return;
        var layout = ApiMetadata.Structure("BERVAL");
        if (layout is null) return;
        var before = inputs.FirstOrDefault(value => value.LdapPart == 5 && (value.Flags & (uint)ValueFlags.LdapData) != 0);
        var after = outputs.FirstOrDefault(value => value.LdapPart == 5 && (value.Flags & (uint)ValueFlags.LdapData) != 0);
        var descriptor = AddCapturedRecord(parent, layout.Name ?? "BERVAL", layout.Name ?? "BERVAL",
            before, after, layout);
        AddBerBytes(descriptor,
            inputs.FirstOrDefault(value => value.LdapPart == 6 && (value.Flags & (uint)ValueFlags.LdapData) != 0),
            outputs.FirstOrDefault(value => value.LdapPart == 6 && (value.Flags & (uint)ValueFlags.LdapData) != 0));
    }

    private static void AddLdapBerArrays(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        inputs = inputs.Where(value => (value.Flags & (uint)ValueFlags.LdapData) != 0).ToList();
        outputs = outputs.Where(value => (value.Flags & (uint)ValueFlags.LdapData) != 0).ToList();
        var beforeTable = inputs.FirstOrDefault(value => value.LdapPart == 11);
        var afterTable = outputs.FirstOrDefault(value => value.LdapPart == 11);
        if (beforeTable is null && afterTable is null) return;
        var layout = ApiMetadata.Structure("BERVAL");
        if (layout is null) return;
        var table = AddCapturedNode(parent, "Values", new("BERVAL *[]"), beforeTable, afterTable);

        // Binary values preserve their vector index, descriptor fields and counted bytes.
        foreach (var index in inputs.Concat(outputs).Where(value => value.LdapPart == 5)
            .Select(value => value.ModIndex).Distinct())
        {
            var (before, after) = LdapPair(inputs, outputs, index, 5);
            var value = AddCapturedRecord(table, $"[{index}]", layout.Name ?? "BERVAL", before, after, layout);
            (before, after) = LdapPair(inputs, outputs, index, 6);
            AddBerBytes(value, before, after);
        }
    }

    private static void AddSyncAllErrors(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        const uint SyncAllMask = (uint)(ValueFlags.LdapData | ValueFlags.SyncAllData);
        inputs = inputs.Where(value => (value.Flags & SyncAllMask) == (uint)ValueFlags.SyncAllData).ToList();
        outputs = outputs.Where(value => (value.Flags & SyncAllMask) == (uint)ValueFlags.SyncAllData).ToList();
        if (inputs.Count == 0 && outputs.Count == 0) return;
        var structure = ApiMetadata.Structure(parent.SignatureType.Name);
        var table = AddCapturedNode(parent, "Errors",
            new((structure?.Name ?? "DS_REPSYNCALL_ERRINFO") + " *[]"),
            inputs.FirstOrDefault(value => value.SyncPart == 1),
            outputs.FirstOrDefault(value => value.SyncPart == 1));

        // Returned error descriptors remain paired with their server and source strings.
        foreach (var index in inputs.Concat(outputs).Where(value => value.SyncPart == 2)
            .Select(value => value.ErrorIndex).Distinct())
        {
            var before = inputs.FirstOrDefault(value => value.SyncPart == 2 && value.ErrorIndex == index);
            var after = outputs.FirstOrDefault(value => value.SyncPart == 2 && value.ErrorIndex == index);
            var error = AddCapturedRecord(table, $"[{index}]", structure?.Name ?? "DS_REPSYNCALL_ERRINFO",
                before, after, structure, "Integer");
            foreach (var member in inputs.Concat(outputs)
                .Where(value => value.SyncPart == 3 && value.ErrorIndex == index)
                .Select(value => value.MemberOffset).Distinct())
            {
                var field = structure?.Fields?.FirstOrDefault(value => value.Offset == member * 8);
                var owner = error.Children.FirstOrDefault(value => value.Name == field?.Name);
                if (owner is null || field is null) continue;
                before = inputs.FirstOrDefault(value => value.SyncPart == 3 && value.ErrorIndex == index &&
                    value.MemberOffset == member);
                after = outputs.FirstOrDefault(value => value.SyncPart == 3 && value.ErrorIndex == index &&
                    value.MemberOffset == member);
                AddCapturedReference(owner, "Text", new(field.Type, Kind: "Pointer"), before, after, true);
            }
        }
    }

    private static void AddLdapModifications(ParameterProperty parent, List<MemorySnapshot> inputs,
        List<MemorySnapshot> outputs)
    {
        inputs = inputs.Where(value => (value.Flags & (uint)ValueFlags.LdapData) != 0).ToList();
        outputs = outputs.Where(value => (value.Flags & (uint)ValueFlags.LdapData) != 0).ToList();
        if (!inputs.Concat(outputs).Any(value => value.LdapPart == 1 ||
            value.LdapPart == 0 && value.Kind == (int)ValueKind.Bytes)) return;
        var structure = ApiMetadata.Structure(parent.SignatureType.Name);
        var wide = structure?.Name?.EndsWith('W') == true;
        var textType = wide ? "wchar_t *" : "char *";
        var beforeTable = inputs.FirstOrDefault(value => value.LdapPart == 0);
        var afterTable = outputs.FirstOrDefault(value => value.LdapPart == 0);
        var table = AddCapturedNode(parent, "Modification pointers", new((structure?.Name ?? "LDAPMod") + " *[]"),
            beforeTable, afterTable);

        // Each modification retains its own descriptor, attribute name, values and binary lengths.
        foreach (var index in inputs.Concat(outputs).Where(value => value.LdapPart == 1)
            .Select(value => value.ModIndex).Distinct())
        {
            var (before, after) = LdapPair(inputs, outputs, index, 1, 0);
            var descriptor = after ?? before!;
            var modification = AddCapturedRecord(table, $"[{index}]", structure?.Name ?? "LDAPMod",
                before, after, structure);
            var attribute = modification.Children.FirstOrDefault(value => value.Name == "mod_type");
            var (attributeBefore, attributeAfter) = LdapPair(inputs, outputs, index, 2, 0);
            if (attributeBefore is not null || attributeAfter is not null)
            {
                attribute ??= modification;
                AddCapturedReference(attribute, "Attribute", new(textType, Kind: "Pointer"),
                    attributeBefore, attributeAfter, true);
            }
            if (descriptor.Bytes.Length < 4) continue;
            var binary = (MemorySnapshot.Scalar(descriptor.Bytes, 0, 4) & 128) != 0;
            var (valuesBefore, valuesAfter) = LdapPair(inputs, outputs, index, 3, 0);
            if (valuesBefore is null && valuesAfter is null) continue;
            var values = AddCapturedNode(modification, "Values", new(binary ? "BERVAL *[]" : textType + "[]"),
                valuesBefore, valuesAfter, parent.Hex);
            foreach (var element in inputs.Concat(outputs).Where(value => value.ModIndex == index &&
                value.LdapPart is 4 or 5).Select(value => value.ElementIndex).Distinct())
            {
                (before, after) = LdapPair(inputs, outputs, index, binary ? 5 : 4, element);
                var value = AddCapturedNode(values, $"[{element}]",
                    new(binary ? "BERVAL" : textType, Kind: binary ? "Structure" : "Pointer"),
                    before, after, parent.Hex);
                value.InputLabel = !binary && before is not null ? QuotedText(before) : null;
                value.OutputLabel = !binary && after is not null ? QuotedText(after) : null;
                if (!binary) continue;
                if (ApiMetadata.Structure("BERVAL") is { } binaryLayout)
                    AddFields(value, binaryLayout, before, after);
                var (bytesBefore, bytesAfter) = LdapPair(inputs, outputs, index, 6, element);
                if (bytesBefore is null && bytesAfter is null) continue;
                var pointer = value.Children.FirstOrDefault(field => field.Name == "bv_val") ?? value;
                AddCapturedReference(pointer, "Bytes", new("byte[]"), bytesBefore, bytesAfter);
            }
        }
    }

    private sealed record BerArgument(ApiParameter Parameter, char Token, bool Encode);

    private static Dictionary<int, BerArgument> BerArguments(string function, string module,
        Dictionary<uint, List<MemorySnapshot>> input, int argumentCount)
    {
        var result = new Dictionary<int, BerArgument>();
        if (!System.IO.Path.GetFileName(module).Equals("wldap32.dll", StringComparison.OrdinalIgnoreCase) ||
            function is not ("ber_printf" or "ber_scanf")) return result;
        var sample = input.GetValueOrDefault(1u, []).FirstOrDefault(value => value.Kind == (int)ValueKind.Bytes &&
            value.Bytes.Length > 0 && (value.Flags & (uint)ValueFlags.Unreadable) == 0);
        if (sample is null) return result;
        var encode = function == "ber_printf";
        var next = 2;

        // Decoder tokens retain their argument positions across ignored characters; encoder inference stops there.
        foreach (var token in Encoding.Latin1.GetString(sample.Bytes.AsSpan(0,
            Math.Min(sample.Bytes.Length, Protocol.MaxFormatStringChars))))
        {
            if (token == '\0') break;
            if (token is '{' or '}' or '[' or ']' or 'n' || !encode && token is 'x' or 't') continue;
            var type = token switch
            {
                'b' or 'e' or 'i' => encode ? "ber_int_t" : "ber_int_t *",
                't' when encode => "ber_tag_t",
                'o' or 'X' when encode => "char *",
                's' when encode => "char *",
                'a' or 'B' when !encode => "char **",
                'O' when !encode => "BERVAL **",
                'v' => encode ? "char **" : "char ***",
                'V' => encode ? "BERVAL **" : "BERVAL ***",
                _ => null
            };
            if (type is null)
            {
                if (encode) break;
                continue;
            }
            var paired = encode && token is 'o' or 'X' || !encode && token == 'B';
            if (next + (paired ? 2 : 1) > argumentCount) break;
            var role = token switch
            {
                'b' => "boolean", 'e' => "enumeration", 'i' => "integer", 't' => "tag",
                'o' or 'O' => "octets", 'X' or 'B' => "bits", 's' or 'a' => "text",
                'v' => "strings", _ => "values"
            };
            result.Add(next, new(new($"{role}[{next - 1}]", type), token, encode));
            ++next;
            if (!paired) continue;
            result.Add(next, new(new($"{(token == 'o' ? "length" : "bitCount")}[{next - 1}]",
                encode ? "ber_len_t" : "ber_len_t *"), 'l', encode));
            ++next;
        }
        return result;
    }

    private static void AddBerMemory(ParameterProperty parent, BerArgument argument,
        List<MemorySnapshot> inputs, List<MemorySnapshot> outputs)
    {
        if (!argument.Encode && argument.Token is 'b' or 'e' or 'i' or 'l')
        {
            var sample = outputs.FirstOrDefault(value => value.Kind == (int)ValueKind.Scalar);
            parent.Children.Add(new()
            {
                Name = "Decoded value", SignatureType = ParameterType.Infer(argument.Token == 'l' ?
                    "ber_len_t" : "ber_int_t"), OutputMemory = sample,
                Output = sample?.Bytes.Length == 4 ? MemorySnapshot.Scalar(sample.Bytes, 0, 4) : null,
                OutputLabel = sample is null ? "<not captured>" : sample.Bytes.Length < 4 ?
                    Missing(sample, 0, 4) : null, Level = parent.Level + 1, Hex = parent.Hex
            });
            return;
        }
        if (argument.Encode && argument.Token is 'b' or 'e' or 'i' or 't' or 'l') return;
        var container = parent;
        if (!argument.Encode)
        {
            var pointer = outputs.FirstOrDefault(value => value.Kind == (int)ValueKind.Scalar);
            container = new()
            {
                Name = "Returned pointer", SignatureType = ParameterType.Infer(argument.Parameter.Type[..^1].Trim()),
                Output = pointer?.Bytes.Length == ApiMetadata.PointerSize ?
                    MemorySnapshot.Scalar(pointer.Bytes, 0, ApiMetadata.PointerSize) : null,
                OutputMemory = pointer, OutputLabel = pointer is null ? "<not captured>" :
                    pointer.Bytes.Length < ApiMetadata.PointerSize ?
                        Missing(pointer, 0, ApiMetadata.PointerSize) : null,
                Level = parent.Level + 1, Hex = parent.Hex
            };
            parent.Children.Add(container);
        }
        var before = inputs.Where(value => value.Kind == (int)ValueKind.Bytes).ToList();
        var after = outputs.Where(value => value.Kind == (int)ValueKind.Bytes).ToList();
        var layout = ApiMetadata.Structure("BERVAL");

        void Descriptor(ParameterProperty owner, MemorySnapshot? first, MemorySnapshot? second,
            MemorySnapshot? firstBytes, MemorySnapshot? secondBytes)
        {
            if (first is null && second is null) return;
            var value = AddCapturedRecord(owner, "BERVAL", "BERVAL", first, second, layout);
            if (layout is null) return;
            bool Complete(MemorySnapshot? header) => header is not null &&
                header.Bytes.Length >= parent.PointerSize * 2 && MemorySnapshot.Scalar(header.Bytes, 0, 4) > 0 &&
                MemorySnapshot.Scalar(header.Bytes, parent.PointerSize, parent.PointerSize) != 0;
            if (!Complete(first)) firstBytes = null;
            if (!Complete(second)) secondBytes = null;
            AddBerBytes(value, firstBytes, secondBytes);
        }

        // Array elements retain their recorded index; incomplete pointer prefixes cannot establish an element.
        if (argument.Token is 'v' or 'V')
        {
            var first = before.FirstOrDefault(value => (value.Flags & (uint)ValueFlags.StringArrayElement) == 0);
            var second = after.FirstOrDefault(value => (value.Flags & (uint)ValueFlags.StringArrayElement) == 0);
            if (first is null && second is null) return;
            var array = AddCapturedNode(container, "Values", new(argument.Token == 'V' ? "BERVAL *[]" : "char *[]"),
                first, second, parent.Hex);
            foreach (var index in before.Concat(after).Where(value =>
                (value.Flags & (uint)ValueFlags.StringArrayElement) != 0)
                .Select(value => value.ElementIndex).Where(index => index >= 0).Distinct().Order())
            {
                bool Present(MemorySnapshot? table) => table is not null &&
                    index < table.Bytes.Length / parent.PointerSize &&
                    MemorySnapshot.Scalar(table.Bytes, index * parent.PointerSize, parent.PointerSize) != 0;
                var input = Present(first) ? before.Where(value => value.ElementIndex == index).ToArray() : [];
                var output = Present(second) ? after.Where(value => value.ElementIndex == index).ToArray() : [];
                if (input.Length == 0 && output.Length == 0) continue;
                var element = AddCapturedNode(array, $"[{index}]",
                    new(argument.Token == 'V' ? "BERVAL *" : "char *", Kind: "Pointer"),
                    null, null, parent.Hex);
                if (argument.Token == 'V')
                    Descriptor(element, input.ElementAtOrDefault(0), output.ElementAtOrDefault(0),
                        input.ElementAtOrDefault(1), output.ElementAtOrDefault(1));
                else element.Children.Add(new()
                {
                    Name = "Text", SignatureType = new("char *", Kind: "Pointer"),
                    InputMemory = input.FirstOrDefault(), OutputMemory = output.FirstOrDefault(),
                    InputLabel = input.Length == 0 ? null : QuotedText(input[0]),
                    OutputLabel = output.Length == 0 ? null : QuotedText(output[0]),
                    Level = element.Level + 1, Hex = parent.Hex
                });
            }
            return;
        }
        if (argument.Token == 'O')
        {
            Descriptor(container, before.ElementAtOrDefault(0), after.ElementAtOrDefault(0),
                before.ElementAtOrDefault(1), after.ElementAtOrDefault(1));
            return;
        }
        var inputBytes = before.FirstOrDefault();
        var outputBytes = after.FirstOrDefault();
        if (inputBytes is null && outputBytes is null) return;
        var text = argument.Token is 's' or 'a';
        container.Children.Add(new()
        {
            Name = text ? "Text" : "Bytes", SignatureType = new(text ? "char *" : "byte[]"),
            InputMemory = inputBytes, OutputMemory = outputBytes,
            InputLabel = text && inputBytes is not null ? QuotedText(inputBytes) : null,
            OutputLabel = text && outputBytes is not null ? QuotedText(outputBytes) : null,
            Level = container.Level + 1, Hex = parent.Hex
        });
    }
}

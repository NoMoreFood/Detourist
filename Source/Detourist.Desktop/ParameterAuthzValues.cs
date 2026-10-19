using System.Text.Json;

namespace Detourist.Desktop;

public static partial class ParameterValues
{
    private const int ObjectTypeListSize = 16;
    private const int AuditParamSize = 32;
    private const int AuditParamDataOffset = 16;
    private const uint AuditFlagLowMask = 0x7FFFu;

    private static void AddAuthzAccessRequest(ParameterProperty parent, List<MemorySnapshot> inputs)
    {
        var header = inputs.FirstOrDefault(value => value.AuditPart == 4);
        if (header is null || ApiMetadata.Structure("AUTHZ_ACCESS_REQUEST") is not { } layout) return;
        var request = AddCapturedNode(parent, "AUTHZ_ACCESS_REQUEST", new("AUTHZ_ACCESS_REQUEST", Kind: "Structure"),
            header, null);
        AddFields(request, layout, header, null);
        var principal = request.Children.FirstOrDefault(value => value.Name == "PrincipalSelfSid");
        var sid = inputs.FirstOrDefault(value => value.AuditPart == 5);
        if (principal is not null && sid is not null) AddNetApiSid(principal, sid, null);
        var pointer = request.Children.FirstOrDefault(value => value.Name == "ObjectTypeList");
        var table = inputs.FirstOrDefault(value => value.AuditPart == 6);
        if (pointer is null || table is null) return;
        var array = AddCapturedNode(pointer, "Object types", new("OBJECT_TYPE_LIST[]", Kind: "Array"),
            table, null, parent.Hex);
        AddArray(array, new("Array", (int)Math.Min(table.OriginalBytes, int.MaxValue), "OBJECT_TYPE_LIST[]",
            "OBJECT_TYPE_LIST", (int)Math.Min(table.OriginalBytes / ObjectTypeListSize, int.MaxValue)), table, null, 0, 0);
        foreach (var guid in inputs.Where(value => value.AuditPart == 7 && value.MemberOffset >= 8))
        {
            var record = array.Children.FirstOrDefault(value => value.Name == $"[{guid.MemberOffset / ObjectTypeListSize}]");
            var field = record?.Children.FirstOrDefault(value => value.Name == "ObjectType");
            if (field is not null) AddSnapshot(field, guid, null, ApiMetadata.Structure("GUID"));
        }
    }

    private static void AddAuthzAuditParameters(ParameterProperty parent, List<MemorySnapshot> inputs)
    {
        var header = inputs.FirstOrDefault(value => value.AuditPart == 0);
        if (header is null || ApiMetadata.Structure("AUDIT_PARAMS") is not { } layout) return;
        var root = AddCapturedNode(parent, "AUDIT_PARAMS", new("AUDIT_PARAMS", Kind: "Structure"),
            header, null);
        AddFields(root, layout, header, null);
        var pointer = root.Children.FirstOrDefault(value => value.Name == "Parameters");
        if (pointer is null) return;
        var table = inputs.FirstOrDefault(value => value.AuditPart == 1);
        var requested = header.Bytes.Length >= 10 ? (int)MemorySnapshot.Scalar(header.Bytes, 8, 2) : 0;
        if (requested == 0) return;
        var array = AddCapturedNode(pointer, "Parameters", new("AUDIT_PARAM[]", Kind: "Array"),
            table, null, parent.Hex);
        array.InputLabel = table is null ? "<not captured>" : null;
        array.OutputLabel = table is null ? "<not captured>" : null;
        var count = Math.Min(requested, Math.Min(Protocol.MaxExpandedElements,
            ((table?.Bytes.Length ?? 0) + AuditParamSize - 1) / AuditParamSize));
        for (var index = 0; index < count; ++index)
        {
            var record = AddCapturedNode(array, $"[{index}]", new("AUDIT_PARAM", Kind: "Structure"),
                Slice(table, index * AuditParamSize, AuditParamSize), null, parent.Hex);
            ParameterProperty Add(string name, string type, int offset, int size)
            {
                var field = Field(record, name, ParameterType.Infer(type), offset, size);
                if (field.Input is null)
                    field.InputLabel = field.OutputLabel = Missing(record.InputMemory, offset, size);
                record.Children.Add(field);
                return field;
            }
            var tag = Add("Type", "AUDIT_PARAM_TYPE", 0, 4).Input;
            Add("Length", "ULONG", 4, 4);
            Add("Flags", "DWORD", 8, 4);

            // The type tag selects one union member; opaque pointers and scalar halves never expand as memory.
            var (name, type) = tag switch
            {
                2 => ("String", "PWSTR"), 3 => ("u", "ULONG"), 4 => ("u", "ULONG_PTR"),
                5 => ("psid", "PSID"), 7 => ("pObjectTypes", "AUDIT_OBJECT_TYPES *"),
                9 => ("pguid", "GUID *"), 12 => ("pIpAddress", "AUDIT_IP_ADDRESS *"),
                6 or 8 or 10 or 11 or 13 => ("Data0", "ULONG"), _ => ("Data0", "ULONG_PTR")
            };
            var split = tag is 6 or 8 or 10 or 11 or 13;
            var value = Add(name, type, 16, tag == 3 || split ? 4 : 8);
            var high = Add("Data1", split ? "ULONG" : "ULONG_PTR", 24, split ? 4 : 8);
            if (split && value.Input is { } low && high.Input is { } upper)
            {
                var combined = low | upper << 32;
                var valueType = tag == 10 ? "FILETIME" : tag == 11 ? "ULONGLONG" : "LUID";
                var scalar = new ParameterProperty
                {
                    Name = "Value", SignatureType = ParameterType.Infer(valueType), Input = combined,
                    Level = record.Level + 1, Hex = parent.Hex
                };
                record.Children.Add(scalar);
                if (ApiMetadata.Structure(valueType) is { } scalarLayout)
                    AddFields(scalar, scalarLayout, new(0, 0, 8, BitConverter.GetBytes(combined)), null);
            }
            var member = index * AuditParamSize + AuditParamDataOffset;
            var pointee = inputs.FirstOrDefault(item => item.AuditPart == 2 && item.MemberOffset == member);
            if (pointee is null) continue;
            if (tag == 5)
            {
                AddNetApiSid(value, pointee, null);
                continue;
            }

            // Referenced object arrays belong to the pointer inside their retained object-list header.
            var regions = new List<MemorySnapshot>
            {
                pointee with { Flags = pointee.Flags & AuditFlagLowMask, MemberOffset = -1 }
            };
            var objects = inputs.FirstOrDefault(item => item.AuditPart == 3 && item.MemberOffset == member);
            if (objects is not null) regions.Add(objects with { Flags = objects.Flags & AuditFlagLowMask, MemberOffset = 8 });
            AddMemory(value, regions, []);
        }
        if (requested > count)
        {
            var remainder = (table?.Bytes.Length ?? 0) > count * AuditParamSize ?
                $"{requested - count:N0} more elements" : "<not captured>";
            array.Children.Add(new()
            {
                Name = $"[{count}…{requested - 1}]", SignatureType = new("AUDIT_PARAM"),
                InputLabel = remainder, OutputLabel = remainder, Level = array.Level + 1, Hex = parent.Hex
            });
        }
    }

    private static (Dictionary<int, ApiParameter> Parameters, uint Captured, uint Requested)
        AuthzArguments(JsonElement[] arguments)
    {
        var parameters = new Dictionary<int, ApiParameter>();
        if (arguments.Length < 5) return (parameters, 0, 0);
        ulong Value(int index) => ParameterType.ParseHex(arguments[index].ToString());
        var requested = (uint)Value(4);
        uint captured = 0;
        for (var index = 5; captured < requested && index < arguments.Length; ++captured)
        {
            var flags = (uint)Value(index);
            parameters[index++] = new($"audit[{captured}].type", "AUDIT_PARAM_TYPE");
            var type = flags & 255;
            if (type is 6 or 13 && (flags & 768) != 0) continue;
            var valueType = type switch
            {
                2 => "PWSTR", 3 => "ULONG", 4 => "ULONG_PTR", 5 => "PSID",
                6 or 8 or 13 => "LUID", 7 => "AUDIT_OBJECT_TYPES *", 9 => "GUID *",
                10 => "FILETIME", 11 => "ULONGLONG", 12 => "AUDIT_IP_ADDRESS *", _ => ""
            };
            if (valueType.Length == 0 || index >= arguments.Length) break;
            parameters[index++] = new($"audit[{captured}].value", valueType);
            if (type != 7 && (type != 3 || (flags & 512) == 0)) continue;
            if (index >= arguments.Length) break;
            parameters[index++] = new($"audit[{captured}].objectTypeIndex", "LONG");
        }
        return (parameters, captured, requested);
    }
}

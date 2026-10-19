using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Detourist.Desktop;

public sealed record EnumValue(string Name, ulong Value, string[]? Structures = null)
{
    public string Label => $"{Name} (0x{Value:X})";
}

public sealed record ParameterType(string Name, int Bits = 0, bool Signed = false, string Kind = "Integer")
{
    public int Bits { get; init; } = Bits != 0 ? Bits : Kind == "Pointer" ? ApiMetadata.PointerSize * 8 : 64;
    public EnumValue[] Choices { get; init; } = [];
    public ulong Mask => Bits == 64 ? ulong.MaxValue : (1UL << Bits) - 1;
    public static readonly string[] Interpretations =
        ["Signature", "Pointer", "Boolean", "UInt8", "Int8", "UInt16", "Int16", "UInt32", "Int32",
            "UInt64", "Int64", "Float32", "Float64"];

    public static ParameterType Infer(string declaration, string name = "")
    {
        var type = Regex.Replace(declaration, @"\b(const|volatile|struct|enum)\s+", "").Trim();
        var upper = type.ToUpperInvariant();
        if (ApiMetadata.Type(type) is { Kind: not "Unknown" } layout)
            return new(layout.Name ?? type, layout.Size is 1 or 2 or 4 or 8 ? layout.Size * 8 : 64,
                layout.Signed, layout.Kind) { Choices = layout.Choices ?? [] };
        if (upper is "LPARAM" or "LRESULT" or "SSIZE_T" or "LONG_PTR" or "INT_PTR" or "SYSTEM.INTPTR")
            return new(type, ApiMetadata.PointerSize * 8, true);
        if (upper is "HANDLE" or "HKEY" or "HWND" or "HMODULE" or "HINSTANCE" or "HDC" or "HGDIOBJ" or
            "WPARAM" or "UINT_PTR" or "ULONG_PTR" or "SIZE_T" or "SYSTEM.UINTPTR")
            return new(type, ApiMetadata.PointerSize * 8);
        if (type.Contains('*') || type.Contains('&') || type.Contains('[') || upper.StartsWith("LP") ||
            upper.StartsWith("PC") || upper.StartsWith("PVOID") || upper.StartsWith("PHANDLE") ||
            upper.StartsWith("PULONG") || upper.StartsWith("PDWORD") || upper.StartsWith("PBOOLEAN") ||
            upper.StartsWith("PBOOL") || upper.StartsWith("PUNICODE") || upper.StartsWith("PLARGE") ||
            upper.StartsWith("PIO_") || upper.StartsWith("POBJECT_") || upper.StartsWith("PFILE_") ||
            upper.StartsWith("PPROCESS_") || upper.StartsWith("PSECURITY_") || upper.StartsWith("PCHAR") ||
            upper.StartsWith("PWCHAR") || upper.StartsWith("PBYTE") || upper.StartsWith("PUSHORT") ||
            upper is "PHKEY" or "PINT" or "PUINT" or "PNTSTATUS" or "REFIID" or "REFCLSID" or "REFGUID")
            return new(type, Kind: "Pointer");
        if (upper is "BOOLEAN" or "BOOL" or "BOOLEAN (INFERRED)" or "SYSTEM.BOOLEAN" or "BOOL (INFERRED)")
            return new(type, upper == "BOOLEAN" ? 8 : 32, Kind: "Boolean");
        if (upper is "FLOAT" or "FLOAT32" or "SYSTEM.SINGLE") return new(type, 32, Kind: "Float32");
        if (upper is "DOUBLE" or "FLOAT64" or "SYSTEM.DOUBLE") return new(type, Kind: "Float64");
        if (upper is "BYTE" or "UCHAR" or "UINT8" or "SYSTEM.BYTE") return new(type, 8);
        if (upper is "CHAR" or "INT8" or "SYSTEM.SBYTE") return new(type, 8, true);
        if (upper is "WORD" or "USHORT" or "WCHAR" or "UINT16" or "SYSTEM.UINT16" or "SYSTEM.CHAR")
            return new(type, 16);
        if (upper is "SHORT" or "INT16" or "SYSTEM.INT16") return new(type, 16, true);
        if (upper is "BER_LEN_T" or "BER_TAG_T" or "DWORD" or "ULONG" or "UINT" or "UINT32" or
            "SYSTEM.UINT32" or "ACCESS_MASK" or "REGSAM")
            return new(type, 32);
        if (upper is "BER_INT_T" or "LONG" or "INT" or "INT32" or "HRESULT" or "NTSTATUS" or "LSTATUS" or
            "SYSTEM.INT32")
            return new(type, 32, true);
        if (upper is "LONGLONG" or "INT64" or "LARGE_INTEGER" or "SYSTEM.INT64")
            return new(type, 64, true);

        // Known enum choices retain a numeric escape hatch for values outside the catalog.
        var choices = upper switch
        {
            "FINDEX_INFO_LEVELS" => new[] { new EnumValue("FindExInfoStandard", 0), new("FindExInfoBasic", 1) },
            "FINDEX_SEARCH_OPS" => new[] { new EnumValue("FindExSearchNameMatch", 0),
                new("FindExSearchLimitToDirectories", 1), new("FindExSearchLimitToDevices", 2) },
            _ => Array.Empty<EnumValue>()
        };
        if (choices.Length != 0) return new(type, 32, Kind: "Enum") { Choices = choices };
        if (upper.EndsWith("_CLASS") || upper.EndsWith("_TYPE") || upper.EndsWith("_LEVEL"))
            return new(type, 32);
        if (type.Length > 0) return new(type);
        if (name is "inherit" or "lock") return new("BOOL (inferred)", 32, Kind: "Boolean");
        if (Regex.IsMatch(name, @"(?i)(flags|access|attributes|options|creation|sharing)$"))
            return new("UInt32 (inferred)", 32);
        return new("uintptr_t");
    }

    public string Format(ulong value, bool hex)
    {
        value &= Mask;
        if (Kind == "Boolean") return value == 0 ? "False" : $"True ({value})";
        if (Kind == "Float32" && !hex)
            return BitConverter.UInt32BitsToSingle((uint)value).ToString("R", CultureInfo.InvariantCulture);
        if (Kind == "Float64" && !hex)
            return BitConverter.UInt64BitsToDouble(value).ToString("R", CultureInfo.InvariantCulture);
        if (Kind == "Enum" && Choices.FirstOrDefault(choice => choice.Value == value) is { } choice)
            return choice.Label;
        if (hex || Kind == "Pointer") return $"0x{value:X}";
        return Signed ? Sign(value).ToString(CultureInfo.InvariantCulture) :
            value.ToString(CultureInfo.InvariantCulture);
    }

    public long Sign(ulong value) => Bits == 64 ? unchecked((long)value) :
        unchecked((long)(value << (64 - Bits))) >> (64 - Bits);

    private static readonly ParameterType Unsigned64 = new("UInt64");
    internal static ulong ParseHex(string text) => Unsigned64.Parse(text, true);

    public ulong Parse(string text, bool hex)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            hex = true;
            text = text[2..];
        }
        if (!hex && Kind == "Float32" && float.TryParse(text, NumberStyles.Float,
            CultureInfo.InvariantCulture, out var single)) return BitConverter.SingleToUInt32Bits(single);
        if (!hex && Kind == "Float64" && double.TryParse(text, NumberStyles.Float,
            CultureInfo.InvariantCulture, out var number)) return BitConverter.DoubleToUInt64Bits(number);
        if (!hex && Signed && long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var signed))
        {
            if (Bits < 64 && (signed < -(1L << (Bits - 1)) || signed > (1L << (Bits - 1)) - 1))
                throw new FormatException($"Enter a signed {Bits}-bit value.");
            return unchecked((ulong)signed) & Mask;
        }
        if (ulong.TryParse(text, hex ? NumberStyles.HexNumber : NumberStyles.Integer,
            CultureInfo.InvariantCulture, out var value) && value <= Mask) return value;
        throw new FormatException($"Enter a valid {Bits}-bit {Name} value.");
    }
}

public sealed record MemorySnapshot(int Kind, uint Flags, ulong OriginalBytes, byte[] Bytes, int MemberOffset = -1,
    int ArrayIndex = -1, int ElementIndex = -1, int ModIndex = -1, int LdapPart = -1,
    int SyncPart = -1, int ErrorIndex = -1, int ReplicaType = -1, string Structure = "", int EtwFormat = -1,
    bool Sid = false, bool Buffer = false, int SecurityPart = -1, int ElementSize = 0,
    int ParentArrayIndex = -1, int ParentElementIndex = -1, int VariantType = -1)
{
    public int AuditPart => (Flags & (uint)ValueFlags.AuditData) != 0 ? (int)(Flags >> 16) : -1;

    public static MemorySnapshot FromJson(JsonElement item) => new((int)item.Number("kind"),
        (uint)item.Number("flags"), ulong.Parse(item.Text("originalBytes", "0"), CultureInfo.InvariantCulture),
        Convert.FromHexString(item.Text("bytes")), (int)item.Number("memberOffset", -1),
        (int)item.Number("arrayIndex", -1), (int)item.Number("elementIndex", -1),
        (int)item.Number("modIndex", -1), (int)item.Number("ldapPart", -1),
        (int)item.Number("syncPart", -1), (int)item.Number("errorIndex", -1), (int)item.Number("replicaType", -1),
        item.Text("structure"), (int)item.Number("etwFormat", -1),
        item.TryGetProperty("sid", out var sid) && sid.ValueKind == JsonValueKind.True,
        item.TryGetProperty("buffer", out var buffer) && buffer.ValueKind == JsonValueKind.True,
        (int)item.Number("securityPart", -1), (int)item.Number("elementSize"),
        (int)item.Number("parentArrayIndex", -1), (int)item.Number("parentElementIndex", -1),
        (int)item.Number("variantType", -1));

    public string TypeName => (ValueKind)Kind switch
    {
        ValueKind.Utf16 => "UTF-16", ValueKind.Scalar when Bytes.Length <= 8 => $"UInt{Bytes.Length * 8}",
        ValueKind.FindData => "WIN32_FIND_DATAW", ValueKind.ProcessInformation => "PROCESS_INFORMATION",
        ValueKind.Stack => "Stack", ValueKind.ObjectAttributes => "OBJECT_ATTRIBUTES",
        ValueKind.IoStatus => "IO_STATUS_BLOCK", ValueKind.SafeArray => "SAFEARRAY",
        ValueKind.SafeArrayData => "Automation elements", ValueKind.PropertyVector => "Property vector",
        ValueKind.PropertyVectorData => "Property elements", _ => $"byte[{Bytes.Length}]"
    };
    public string Size => OriginalBytes > 0 ?
        $"{Bytes.Length:N0} / {OriginalBytes:N0} bytes" : $"{Bytes.Length:N0} bytes";
    public string State => string.Join(", ", new[] { (Flags & (uint)ValueFlags.Truncated) != 0 ? "truncated" : "",
        (Flags & (uint)ValueFlags.Unreadable) != 0 ? "unreadable" : "",
        (Flags & (uint)ValueFlags.Pending) != 0 ? "pending" : "" }.Where(value => value.Length != 0));

    public string Summary(bool hex)
    {
        if ((Flags & (uint)ValueFlags.Unreadable) != 0) return "<unreadable>";
        if ((Flags & (uint)ValueFlags.Pending) != 0 && Bytes.Length == 0) return "<pending>";
        if (Kind == (int)ValueKind.Scalar && Bytes.Length is > 0 and <= 8)
            return new ParameterType(TypeName, Bytes.Length * 8).Format(Scalar(Bytes, 0, Bytes.Length), hex);
        var preview = Kind == (int)ValueKind.Utf16 ? "\"" + Text(Encoding.Unicode).Replace("\r", "\\r")
            .Replace("\n", "\\n").Replace("\0", "\\0") + "\"" : Size;
        if (preview.Length > Protocol.MaxPreviewChars) preview = preview[..Protocol.MaxPreviewChars] + "…";
        return State.Length == 0 ? preview : preview + " · " + State;
    }

    public string Text(Encoding encoding) => (Flags & (uint)ValueFlags.AutomationElement) != 0 ?
        encoding.GetString(Bytes) : encoding.GetString(Bytes).TrimEnd('\0');

    public string HexDump()
    {
        // Render buffers on demand rather than allocating one property per captured byte.
        var text = new StringBuilder();
        for (var offset = 0; offset < Bytes.Length; offset += 16)
        {
            text.Append(offset.ToString("X8")).Append("  ");
            for (var column = 0; column < 16; ++column)
                text.Append(offset + column < Bytes.Length ? Bytes[offset + column].ToString("X2") + " " : "   ");
            text.Append(" ");
            for (var column = offset; column < Math.Min(offset + 16, Bytes.Length); ++column)
                text.Append(Bytes[column] is >= 32 and < 127 ? (char)Bytes[column] : '.');
            text.AppendLine();
        }
        return text.ToString();
    }

    public static ulong Scalar(byte[] bytes, int offset, int size)
    {
        if (offset < 0 || size is < 1 or > 8 || offset + size > bytes.Length) return 0;
        ulong value = 0;
        for (var index = 0; index < size; ++index) value |= (ulong)bytes[offset + index] << (index * 8);
        return value;
    }
}

public sealed class ParameterProperty : INotifyPropertyChanged
{
    public int PointerSize { get; init; } = ApiMetadata.PointerSize;
    public event PropertyChangedEventHandler? PropertyChanged;
    public required string Name { get; init; }
    public required ParameterType SignatureType { get; set; }
    public ParameterType? OverrideType { get; set; }
    public ParameterType Type => OverrideType ?? SignatureType;
    public string TypeName => Type.Name;
    public int Parameter { get; init; } = -3;
    public int Level { get; set; }
    public ulong? Input { get; set; }
    public ulong? Output { get; set; }
    public string? InputLabel { get; set; }
    public string? OutputLabel { get; set; }
    public MemorySnapshot? InputMemory { get; set; }
    public MemorySnapshot? OutputMemory { get; set; }
    public List<ParameterProperty> Children { get; } = [];
    public bool Expanded { get; set; }
    public bool Editable { get; init; }
    public bool Hex { get; set; } = true;
    public bool IsFlags => Type.Kind is "Integer" or "Enum" && Regex.IsMatch(Name,
        @"(?i)(flags|access|attributes|options|protect|sharing|mask)");
    public ulong EditedValue { get; set; }
    public string? InvalidText { get; set; }
    public string? Error { get; set; }
    public bool Modified => Editable && EditedValue != (Input ?? Output ?? 0);
    public bool HasError => Error is not null;
    public bool CanExpand => Children.Count > 0;
    public string ExpandGlyph => Children.Count == 0 ? "" : Expanded ? "−" : "+";
    public System.Windows.Thickness Indent => new(Level * 13, 0, 0, 0);
    public string InputText => InputLabel ?? (Input.HasValue ? Type.Format(Input.Value, Hex) :
        InputMemory?.Summary(Hex) ?? "—");
    public string OutputText => OutputLabel ?? (Output.HasValue ? Type.Format(Output.Value, Hex) :
        OutputMemory?.Summary(Hex) ?? "—");
    public string EditText => InvalidText ?? Type.Format(EditedValue, Hex);
    public string ValueText => Editable ? EditText : Output.HasValue || OutputMemory is not null ||
        !Input.HasValue && InputMemory is null ? OutputText : InputText;
    public string Note => Error ?? (Modified ? "Modified · applied on continue" : Editable ?
        $"{Type.Bits}-bit value · applied on continue" : InputMemory is not null || OutputMemory is not null ?
        "Captured memory · read only" : "Captured value · read only");

    public void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
}

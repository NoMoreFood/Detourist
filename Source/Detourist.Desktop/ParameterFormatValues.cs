using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Detourist.Desktop;

public static partial class ParameterValues
{
    private static readonly string[] FormatSizes = ["I64", "I32", "hh", "ll", "h", "l", "L", "z", "t", "j", "w", "I"];

    private static Dictionary<int, ApiParameter> ListArguments(string function, ApiParameter[] prefix,
        JsonElement[] arguments)
    {
        var inferred = new Dictionary<int, ApiParameter>();
        if (!Regex.IsMatch(function, @"^_w?(?:exec|spawn)l(?:e|p|pe)?$")) return inferred;
        var first = Array.FindIndex(prefix, parameter => parameter.Name is "_Arguments" or "_ArgList");
        if (first < 0 || first != prefix.Length - 1) return inferred;
        var wide = function.StartsWith("_w", StringComparison.Ordinal);
        var pointer = wide ? "wchar_t *" : "char *";
        var environment = function.EndsWith("le", StringComparison.Ordinal) ||
            function.EndsWith("lpe", StringComparison.Ordinal);

        // The first null pointer ends argv; environment variants place envp immediately after it.
        for (var index = first; index < arguments.Length; ++index)
        {
            var value = ParameterType.ParseHex(arguments[index].ToString());
            if (index > first && value == 0)
            {
                inferred.Add(index, new("argv end", "void *"));
                if (environment && index + 1 < arguments.Length)
                    inferred.Add(index + 1, new("envp", wide ? "wchar_t **" : "char **"));
                break;
            }
            inferred.Add(index, new($"argv[{index - first}]", pointer));
        }
        return inferred;
    }

    private static Dictionary<int, ApiParameter> FormatArguments(string function, string module, ApiParameter[] prefix,
        Dictionary<uint, List<MemorySnapshot>> input, int argumentCount, bool legacyWide,
        Dictionary<int, List<string>>? countedTypes = null, bool secureScan = false)
    {
        var inferred = new Dictionary<int, ApiParameter>();
        if (function is "ShellMessageBoxA" or "ShellMessageBoxW" &&
            System.IO.Path.GetFileName(module).ToLowerInvariant() is "shlwapi.dll" or "shell32.dll")
            return MessageArguments(function.EndsWith('W'), input, argumentCount);
        var setupLog = function is "SetupWriteTextLog" or "SetupWriteTextLogError" or
            "DevRtlWriteTextLog" or "DevRtlWriteTextLogError";
        var debugging = function is "DbgPrint" or "DbgPrintEx" &&
            System.IO.Path.GetFileName(module).Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase);
        var dbgeng = module.Equals("COM", StringComparison.OrdinalIgnoreCase) &&
            Regex.IsMatch(function,
                @"^IDebugControl(?:[2-7])?::(?:ControlledOutput|OutputPrompt|Output)(?:VaList)?(?:Wide)?$");
        var reporting = function is "_CrtDbgReport" or "_CrtDbgReportW" or "_VCrtDbgReportA" or "_VCrtDbgReportW";
        var wdsTrace = function is "PxeTrace" or "PxeTraceV" &&
            System.IO.Path.GetFileName(module).Equals("wdspxe.dll", StringComparison.OrdinalIgnoreCase) ||
            function is "WdsTransportServerTrace" or "WdsTransportServerTraceV" &&
            System.IO.Path.GetFileName(module).Equals("wdsmc.dll", StringComparison.OrdinalIgnoreCase);
        var printing = function.Contains("printf", StringComparison.OrdinalIgnoreCase) ||
            setupLog || debugging || dbgeng || reporting || wdsTrace;
        var scanning = function.Contains("scanf", StringComparison.OrdinalIgnoreCase);
        if (!printing && !scanning) return inferred;
        var shellFormat = function is "wnsprintfA" or "wnsprintfW";
        var windowFormat = function is "wsprintfA" or "wsprintfW";
        var provider = System.IO.Path.GetFileName(module).ToLowerInvariant();
        var ucrt = provider is "ucrtbase.dll" or "ucrtbased.dll" or "ucrtbase_clr0400.dll";
        var crt = ucrt || Regex.IsMatch(provider, @"^msvc(?:rt|r(?:80|90|100|110|120)(?:_clr0400)?)\.dll$");
        var formatIndex = Array.FindIndex(prefix, parameter => parameter.Name.Equals("_Format",
            StringComparison.OrdinalIgnoreCase) || crt && parameter.Name.Equals("format",
                StringComparison.OrdinalIgnoreCase) || shellFormat && parameter.Name == "pszFmt" ||
            windowFormat && parameter.Name is ("arg1" or "lpFmt") ||
            setupLog && parameter.Name == "MessageStr" || (debugging || dbgeng) && parameter.Name == "Format" ||
            wdsTrace && parameter.Name is "pszFormat" or "pwszFormat");
        if (formatIndex < 0 || !input.TryGetValue((uint)formatIndex, out var snapshots)) return inferred;
        var sample = snapshots.FirstOrDefault(value => value.Kind is (int)ValueKind.Bytes or (int)ValueKind.Utf16 &&
            (value.Flags & (uint)ValueFlags.Unreadable) == 0);
        if (sample is null || sample.Bytes.Length is 0 or > Protocol.MaxFormatSampleBytes) return inferred;
        var wide = shellFormat || windowFormat ? function.EndsWith('W') : dbgeng ? function.EndsWith("Wide") :
            wdsTrace || prefix[formatIndex].Type.Contains("wchar_t", StringComparison.OrdinalIgnoreCase);
        var defaultWide = wide && legacyWide;
        if (wide && sample.Bytes.Length % 2 != 0) return inferred;
        var format = (wide ? Encoding.Unicode : Encoding.Latin1).GetString(sample.Bytes);
        var end = format.IndexOf('\0');
        if (end < 0 || end > Protocol.MaxFormatStringChars) return inferred;
        format = format[..end];
        if (scanning) return ScanArguments(format, prefix.Length, argumentCount, wide, legacyWide, ucrt, provider,
            secureScan || function.EndsWith("_s", StringComparison.Ordinal) ||
                function.EndsWith("_s_l", StringComparison.Ordinal));
        var next = 1;
        var positional = false;
        var sequential = false;
        var conflictingRecord = false;

        int Decimal(ref int offset)
        {
            var value = 0;
            while (offset < format.Length && char.IsAsciiDigit(format[offset]))
            {
                value = Math.Min(1000, value * 10 + format[offset] - '0');
                ++offset;
            }
            return value;
        }

        void Add(int position, string role, string type)
        {
            var ordinal = position > 0 ? position : next++;
            if (position > 0) positional = true;
            else sequential = true;
            var index = prefix.Length + ordinal - 1;
            if (index >= argumentCount || index < prefix.Length) return;
            if (role == "counted" && countedTypes is not null)
            {
                if (!countedTypes.TryGetValue(index, out var types)) countedTypes[index] = types = [];
                types.Add(type);
            }
            if (inferred.TryAdd(index, new($"{role}[{ordinal}]", type))) return;

            // Counted records support both character views, but cannot share a slot with another pointer contract.
            var previous = inferred[index];
            var counted = previous.Name.StartsWith("counted[", StringComparison.Ordinal);
            if (counted != (role == "counted")) conflictingRecord = true;
        }

        // Interpret complete conversion directives; unknown syntax leaves every tail slot raw.
        for (var offset = 0; offset < format.Length; ++offset)
        {
            if (format[offset] != '%') continue;
            ++offset;
            if (offset >= format.Length) return [];
            if (format[offset] == '%') continue;
            var positionStart = offset;
            var position = Decimal(ref offset);
            if (offset < format.Length && format[offset] == '$') ++offset;
            else { position = 0; offset = positionStart; }
            while (offset < format.Length && "-+ #0".Contains(format[offset]))
            {
                if (shellFormat && format[offset] != '-') return [];
                if (windowFormat && !"-#0".Contains(format[offset])) return [];
                ++offset;
            }
            if (offset < format.Length && format[offset] == '*')
            {
                if (shellFormat || windowFormat) return [];
                ++offset;
                var width = Decimal(ref offset);
                if (width > 0 && (offset >= format.Length || format[offset] != '$')) return [];
                if (width > 0) ++offset;
                Add(width, "width", "Int32");
            }
            else Decimal(ref offset);
            if (offset < format.Length && format[offset] == '.')
            {
                ++offset;
                if (offset < format.Length && format[offset] == '*')
                {
                    if (shellFormat || windowFormat) return [];
                    ++offset;
                    var precision = Decimal(ref offset);
                    if (precision > 0 && (offset >= format.Length || format[offset] != '$')) return [];
                    if (precision > 0) ++offset;
                    Add(precision, "precision", "Int32");
                }
                else Decimal(ref offset);
            }
            var size = FormatSizes.FirstOrDefault(value =>
                format.AsSpan(offset).StartsWith(value, StringComparison.Ordinal));
            if (shellFormat && size is not null) return [];
            if (windowFormat && size is not null and not ("h" or "l" or "I")) return [];
            if (size is not null) offset += size.Length;
            if (dbgeng && size == "I" && (offset >= format.Length || !"diuoxX".Contains(format[offset])))
            {
                size = null;
                --offset;
            }
            if (offset >= format.Length) return [];
            var specifier = format[offset];
            var targetAddress = dbgeng && specifier is 'p' or 'y';

            // Target-address directives retain their values without pretending they reference local captured memory.
            if (dbgeng && specifier == 'm')
            {
                if (size is not null || ++offset >= format.Length) return [];
                if (format[offset] == 's' && ++offset >= format.Length) return [];
                if (format[offset] is not ('a' or 'u')) return [];
                targetAddress = true;
                specifier = 'p';
            }
            if (dbgeng && specifier == 'Y')
            {
                if (size is not (null or "h" or "w") || ++offset >= format.Length || format[offset] != '{') return [];
                var closing = format.IndexOf('}', offset + 1);
                if (closing < 0) return [];
                var directive = format[(offset + 1)..closing];
                targetAddress = directive is "as" or "ps" or "l";
                if (!targetAddress && directive is not ("t" or "T" or "s" or "S") ||
                    targetAddress && size is not null) return [];
                offset = closing;
                specifier = targetAddress ? 'p' : 's';
            }
            if (provider == "ntdll.dll" && specifier is 'f' or 'F' or 'e' or 'E' or 'g' or 'G' or 'a' or 'A') return [];
            if (shellFormat && specifier is not ('d' or 'i' or 'u' or 'o' or 'x' or 'X' or
                'c' or 'C' or 's' or 'S')) return [];
            if (windowFormat && specifier is not ('c' or 'C' or 'd' or 'i' or 'p' or
                's' or 'S' or 'u' or 'x' or 'X')) return [];
            var bits = size is "ll" or "I64" or "j" ? 64 :
                size is "I" or "z" or "t" ? ApiMetadata.PointerSize * 8 : 32;
            var type = specifier switch
            {
                'd' or 'i' => bits == 64 ? "Int64" : "Int32",
                'u' or 'o' or 'x' or 'X' => bits == 64 ? "UInt64" : "UInt32",
                'f' or 'F' or 'e' or 'E' or 'g' or 'G' or 'a' or 'A' => "Float64",
                'c' or 'C' => "Int32",
                'p' when targetAddress => "UInt64",
                'p' when !dbgeng || size is null => "void *",
                'N' when dbgeng && size is null => "void *",
                'I' when dbgeng && size is null => "UInt64",
                'y' when dbgeng && size is null or "l" => "UInt64",
                'n' when crt && size is not ("w" or "L") &&
                    (ucrt || size is not ("I" or "j" or "z" or "t")) =>
                    size == "hh" ? ucrt ? "Int8 *" : "Int16 *" : size == "h" ? "Int16 *" :
                    ucrt && (size is "ll" or "I64" or "j" ||
                        size is "z" or "t" && ApiMetadata.PointerSize == 8) ? "Int64 *" : "Int32 *",
                'Z' when (crt || debugging) && size is null or "h" or "w" or "l" =>
                    size == "w" || ucrt && (size == "l" || size is null && !defaultWide) ?
                        "UNICODE_STRING *" : "ANSI_STRING *",
                's' or 'S' => size is "h" or "hh" ? "char *" : size is "l" or "w" ? "wchar_t *" :
                    (defaultWide == (specifier == 's') ? "wchar_t *" : "char *"),
                _ => null
            };
            if (type is null) return [];
            Add(position, targetAddress ? "target" : specifier == 'n' ? "count" :
                specifier == 'Z' ? "counted" : "format", type);
        }
        return conflictingRecord || positional && sequential ? [] : inferred;
    }

    private static Dictionary<int, ApiParameter> ScanArguments(string format, int prefixCount,
        int argumentCount, bool wide, bool legacyWide, bool ucrt, string provider, bool secure)
    {
        var inferred = new Dictionary<int, ApiParameter>();
        var next = prefixCount;

        // A suppressed conversion consumes input but no argument; secure string conversions add a size slot.
        for (var offset = 0; offset < format.Length; ++offset)
        {
            if (!wide && format[offset] >= 128) return [];
            if (format[offset] != '%') continue;
            ++offset;
            if (offset >= format.Length) return [];
            if (format[offset] == '%') continue;
            var suppressed = format[offset] == '*';
            if (suppressed) ++offset;
            while (offset < format.Length && char.IsAsciiDigit(format[offset])) ++offset;
            var size = FormatSizes.FirstOrDefault(value =>
                format.AsSpan(offset).StartsWith(value, StringComparison.Ordinal));
            if (size is not null) offset += size.Length;
            if (offset >= format.Length) return [];
            var specifier = format[offset];
            if (specifier == '[')
            {
                ++offset;
                if (offset < format.Length && format[offset] == '^') ++offset;
                if (offset < format.Length && format[offset] == ']') ++offset;
                while (offset < format.Length && format[offset] != ']') ++offset;
                if (offset >= format.Length) return [];
            }
            if (!ucrt && provider is not ("ntdll.dll" or "msvcrt.dll") && size is "j" or "z" or "t") return [];
            if (provider == "ntdll.dll" && "fFeEgGaA".Contains(specifier)) return [];
            if (!ucrt && specifier is 'F' or 'a' or 'A') return [];
            if ("fFeEgGaA".Contains(specifier) && size is not (null or "l" or "L") ||
                "diuoxXn".Contains(specifier) && size is "w" or "L" ||
                specifier == 'p' && size is not null) return [];
            if (specifier is 'c' or 'C' or 's' or 'S' or '[' && size is not (null or "h" or "l" or "L" or "w") &&
                !(ucrt && size == "ll")) return [];
            var stringType = size is "h" or "hh" ? "char *" : size is "l" or "ll" or "L" or "w" ? "wchar_t *" :
                (wide ? legacyWide && specifier is not ('C' or 'S') : specifier is 'C' or 'S') ?
                    "wchar_t *" : "char *";
            var bits = size is "ll" or "I64" or "j" ? 64 :
                size is "I" or "z" or "t" ? ApiMetadata.PointerSize * 8 :
                size == "h" ? 16 : size == "hh" && ucrt ? 8 : 32;
            var type = specifier switch
            {
                'd' or 'i' or 'n' => $"Int{bits} *",
                'u' or 'o' or 'x' or 'X' => $"UInt{bits} *",
                'f' or 'F' or 'e' or 'E' or 'g' or 'G' or 'a' or 'A' =>
                    size is "l" or "L" ? "Float64 *" : "Float32 *",
                'c' or 'C' or 's' or 'S' or '[' => stringType,
                'p' => "void **",
                _ => null
            };
            if (type is null) return [];
            if (suppressed) continue;
            var slots = secure && specifier is 'c' or 'C' or 's' or 'S' or '[' ? 2 : 1;
            if (next + slots > argumentCount) return inferred;
            var ordinal = next - prefixCount + 1;
            var role = specifier is 'c' or 'C' ? "characters" : specifier == 'n' ? "count" : "scan";
            if (provider == "ntdll.dll" && secure && slots == 2 && (stringType == "wchar_t *") != wide)
                role = "buffer";
            if (next < argumentCount) inferred.Add(next, new($"{role}[{ordinal}]", type));
            ++next;
            if (secure && specifier is 'c' or 'C' or 's' or 'S' or '[')
            {
                if (next < argumentCount) inferred.Add(next, new($"capacity[{ordinal}]", "UInt32"));
                ++next;
            }
        }
        return inferred;
    }

    private static ParameterProperty CapturedScalar(ParameterProperty parent, string name, ParameterType type,
        List<MemorySnapshot> inputs, List<MemorySnapshot> outputs, bool hex)
    {
        var size = type.Bits / 8;
        var before = inputs.FirstOrDefault(value => value.Kind == (int)ValueKind.Bytes);
        var after = outputs.FirstOrDefault(value => value.Kind == (int)ValueKind.Bytes);
        ulong? Read(MemorySnapshot? sample) => sample is not null && (sample.Flags & (uint)ValueFlags.Unreadable) == 0 &&
            sample.Bytes.Length >= size ? MemorySnapshot.Scalar(sample.Bytes, 0, size) : null;
        var input = Read(before);
        var output = Read(after);
        return new()
        {
            Name = name, SignatureType = type, Level = parent.Level + 1, Hex = hex,
            Input = input, Output = output, InputMemory = before, OutputMemory = after,
            InputLabel = input is null ? Missing(before, 0, size) : null,
            OutputLabel = output is null ? Missing(after, 0, size) : null
        };
    }

    private static void AddScannedValue(ParameterProperty parent, string pointerType,
        List<MemorySnapshot> inputs, List<MemorySnapshot> outputs)
    {
        // Only a captured completed assignment supplies a scanned scalar value.
        parent.Children.Insert(0, CapturedScalar(parent, "Scanned value", ParameterType.Infer(pointerType[..^1].Trim()),
            inputs, outputs, !pointerType.StartsWith("Float", StringComparison.Ordinal)));
    }

    private static void AddCountedFormatString(ParameterProperty parent, string pointerType,
        List<MemorySnapshot> inputs, IReadOnlyList<string>? interpretations = null)
    {
        // A shared counted pointer retains each character interpretation and its own captured descriptor.
        var sequence = interpretations?.ToArray() ?? [pointerType];
        var types = sequence.Distinct().ToArray();
        var headers = inputs.Select((value, index) => (value, index))
            .Where(item => item.value.Kind == (int)ValueKind.Bytes &&
                (item.value.Flags & (uint)ValueFlags.ReferencedData) == 0).ToArray();
        if (types.Length > 1) parent.SignatureType = ParameterType.Infer("void *");
        foreach (var interpretation in types)
        {
            var wide = interpretation.StartsWith("UNICODE", StringComparison.Ordinal);
            var ordinal = Array.IndexOf(sequence, interpretation);
            var descriptor = ordinal < headers.Length ? headers[ordinal].value : null;
            var payload = descriptor is null ? null : inputs.Skip(headers[ordinal].index + 1)
                .TakeWhile(value => value.Kind != (int)ValueKind.Bytes ||
                    (value.Flags & (uint)ValueFlags.ReferencedData) != 0)
                .FirstOrDefault(value => value.Kind == (wide ? (int)ValueKind.Utf16 : (int)ValueKind.Bytes) &&
                    (value.Flags & (uint)ValueFlags.ReferencedData) != 0);
            var layout = ApiMetadata.Structure(interpretation);
            if (layout is null) continue;
            AddSnapshot(parent, descriptor, null, layout);
            if (descriptor is null || descriptor.Bytes.Length < parent.PointerSize * 2 ||
                (descriptor.Flags & (uint)ValueFlags.Unreadable) != 0) continue;
            var length = MemorySnapshot.Scalar(descriptor.Bytes, 0, 2);
            var address = MemorySnapshot.Scalar(descriptor.Bytes, parent.PointerSize, parent.PointerSize);
            var buffer = parent.Children.Last().Children.Single(value => value.Name == "Buffer");
            if (length == 0 && address != 0) payload = new(wide ? (int)ValueKind.Utf16 : (int)ValueKind.Bytes, 0, 0, []);
            var text = payload is null ? null : (wide ? System.Text.Encoding.Unicode :
                System.Text.Encoding.Latin1).GetString(payload.Bytes.AsSpan(0,
                    Math.Min(payload.Bytes.Length, wide ? (Protocol.MaxPreviewChars + 1) * 2 :
                        Protocol.MaxPreviewChars + 1))).Replace("\r", "\\r").Replace("\n", "\\n")
                .Replace("\0", "\\0");
            if (text?.Length > Protocol.MaxPreviewChars) text = text[..Protocol.MaxPreviewChars] + "…";
            buffer.Children.Add(new()
            {
                Name = "Text", SignatureType = new(wide ? "wchar_t *" : "char *", Kind: "Pointer"),
                Level = buffer.Level + 1, Hex = parent.Hex, InputMemory = payload,
                InputLabel = payload is null ? address == 0 ? "<null>" : "<not captured>" :
                    (payload.Flags & (uint)ValueFlags.Unreadable) != 0 ? "<unreadable>" : $"\"{text}\"" +
                    (payload.State.Length == 0 ? "" : " · " + payload.State)
            });
        }
    }

    private static void AddFormatCount(ParameterProperty parent, string pointerType,
        List<MemorySnapshot> inputs, List<MemorySnapshot> outputs)
    {
        // Before and after snapshots expose partial changes without treating a failed formatter as an atomic write.
        parent.Children.Add(CapturedScalar(parent, "Count", ParameterType.Infer(pointerType.TrimEnd('*', ' ')),
            inputs, outputs, parent.Hex));
    }
}

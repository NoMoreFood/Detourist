using System.Text;

namespace Detourist.Desktop;

public static partial class ParameterValues
{
    private static Dictionary<int, ApiParameter> PromptArguments(bool wide, uint template, int argumentCount)
    {
        // The dialog title precedes inserts that the system prompt templates fix with explicit %ls or %hs.
        var insert = template switch
        {
            1008 or 1020 or 1023 or 1024 => "", 1021 or 1022 => "wchar_t *", 1025 or 1026 => "char *", _ => null
        };
        if (insert is null || argumentCount < 3) return [];
        var inferred = new Dictionary<int, ApiParameter> { [2] = new("title", wide ? "wchar_t *" : "char *") };
        if (insert.Length > 0 && argumentCount > 3) inferred[3] = new("userType", insert);
        return inferred;
    }

    private static Dictionary<int, ApiParameter> WdsLogArguments(uint code, int argumentCount)
    {
        // Documented client log codes fix how many wide strings follow the message code.
        string[]? names = code switch
        {
            2 or 3 or 5 or 6 => [], 1 => ["error"], 4 => ["imageName", "groupName"], 7 => ["message"], _ => null
        };
        return names is null ? [] : names.Select((name, index) => (name, index: index + 3))
            .Where(item => item.index < argumentCount).ToDictionary(item => item.index,
                item => new ApiParameter(item.name, "wchar_t *"));
    }

    private static Dictionary<int, ApiParameter> MessageArguments(bool wide,
        Dictionary<uint, List<MemorySnapshot>> input, int argumentCount)
    {
        // Resource templates use the same character encoding as direct message strings.
        var sample = input.GetValueOrDefault(2u, []).FirstOrDefault(value =>
            value.Kind is (int)ValueKind.Bytes or (int)ValueKind.Utf16 &&
            (value.Flags & (uint)ValueFlags.Unreadable) == 0);
        if (sample is null || sample.Bytes.Length is 0 or > Protocol.MaxFormatSampleBytes ||
            sample.Kind == (int)ValueKind.Utf16 && sample.Bytes.Length % 2 != 0)
            return [];
        var format = (sample.Kind == (int)ValueKind.Utf16 ? Encoding.Unicode : Encoding.Latin1).GetString(sample.Bytes);
        var end = format.IndexOf('\0');
        if (end < 0) return [];
        format = format[..end];
        var inferred = new Dictionary<int, ApiParameter>();
        var contracts = new Dictionary<int, int>();
        var cache = new List<int>();
        var next = 5;

        bool Add(int index, string role, string type, int contract)
        {
            if (index >= argumentCount || index >= Protocol.MaximumArguments ||
                contracts.TryGetValue(index, out var previous) && previous != contract) return false;
            contracts[index] = contract;
            inferred.TryAdd(index, new($"{role}[{index - 4}]", type));
            return true;
        }

        // Numbered va_list inserts cache ordinary slots; the first extra star argument bypasses that cache.
        for (var offset = 0; offset < format.Length; ++offset)
        {
            if (format[offset] != '%') continue;
            if (++offset >= format.Length) return [];
            if (format[offset] == '0') break;
            if (format[offset] is < '1' or > '9') continue;
            var ordinal = 0;
            while (offset < format.Length && char.IsAsciiDigit(format[offset]))
                ordinal = Math.Min(100, ordinal * 10 + format[offset++] - '0');
            if (ordinal > 27) return [];
            var widthArgument = false;
            var precisionArgument = false;
            string? size = null;
            var specifier = 's';
            if (offset < format.Length && format[offset] == '!')
            {
                ++offset;
                while (offset < format.Length && "-+ #0".Contains(format[offset])) ++offset;
                if (offset < format.Length && format[offset] == '*') { widthArgument = true; ++offset; }
                else while (offset < format.Length && char.IsAsciiDigit(format[offset])) ++offset;
                if (offset < format.Length && format[offset] == '.')
                {
                    ++offset;
                    if (offset < format.Length && format[offset] == '*') { precisionArgument = true; ++offset; }
                    else while (offset < format.Length && char.IsAsciiDigit(format[offset])) ++offset;
                }
                size = new[] { "I64", "I32", "ll", "h", "l", "w", "I" }.FirstOrDefault(value =>
                    format.AsSpan(offset).StartsWith(value, StringComparison.Ordinal));
                if (size is not null) offset += size.Length;
                if (offset >= format.Length) return [];
                specifier = format[offset++];
                if (offset >= format.Length || format[offset] != '!') return [];
            }
            else --offset;
            var text = specifier is 's' or 'S';
            var character = specifier is 'c' or 'C';
            var counted = specifier == 'Z';
            var integer = "diuoxX".Contains(specifier);
            if (text || character || counted)
            {
                if (size is not (null or "h" or "l" or "w")) return [];
            }
            else if (integer)
            {
                if (size == "w") return [];
            }
            else if (specifier != 'p' || size is not null) return [];
            while (cache.Count < ordinal) cache.Add(next++);
            int[] indices = [cache[ordinal - 1], 0, 0];
            var stars = (widthArgument ? 1 : 0) + (precisionArgument ? 1 : 0);
            for (var index = 1; index <= stars; ++index)
            {
                indices[index] = next++;
                if (index == 2) cache.Add(indices[index]);
            }
            for (var index = 0; index < stars; ++index)
                if (!Add(indices[index], index == 0 && widthArgument ? "width" : "precision", "Int32", 4))
                    return [];
            // Counted inserts read a UNICODE_STRING only for the w modifier; other sizes select an ANSI_STRING.
            var wideValue = counted ? size == "w" : size is "l" or "w" || size is null &&
                (specifier is 's' or 'c' ? wide : !wide);
            var bits = size is "I64" or "ll" ? 64 : size == "I" ? ApiMetadata.PointerSize * 8 : 32;
            var type = counted ? wideValue ? "UNICODE_STRING *" : "ANSI_STRING *" :
                text ? wideValue ? "wchar_t *" : "char *" : character ? "Int32" :
                specifier == 'p' ? "void *" : (specifier is 'd' or 'i' ? "Int" : "UInt") + bits;
            var contract = counted ? 0x300 + (wideValue ? 1 : 0) : text ? 0x100 + (wideValue ? 1 : 0) :
                character ? 4 : specifier == 'p' ? 0x200 : bits / 8;
            if (!Add(indices[stars], counted ? "counted" : text ? "string" : "value", type, contract)) return [];
        }
        return inferred;
    }
}

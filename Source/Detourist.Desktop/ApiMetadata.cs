using System.IO;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Detourist.Desktop;

public sealed record ApiParameter(string Name, string Type);
public sealed record ApiSignature(ApiParameter[] Parameters, string Result, string Module = "");
public sealed record TypeField(string Name, string Type, int Offset, int Bits = 0, TypeLayout? Layout = null);
public sealed record TypeLayout(string Kind, int Size, string? Name = null, string? Element = null,
    int Count = 0, bool Signed = false, TypeField[]? Fields = null, EnumValue[]? Choices = null,
    TypeLayout? ElementLayout = null);

public static class ApiMetadata
{
    private const int ErrorCacheCapacity = 512;
    private const int FormatMessageBufferChars = 512;
    private const uint FormatMessageFromSystem = 0x1000u;
    private const uint FormatMessageIgnoreInserts = 0x0200u;
    private const uint FormatMessageFromHModule = 0x0800u;
    private const int MaxAliasResolutionDepth = 16;
    private const int MaxPointerDereferenceDepth = 4;

    private static readonly Lazy<CatalogDatabase> definitions = new(() => new());
    private static readonly Lazy<CatalogDatabase> definitions32 = new(() => new(pointerSize: 4));
    private static readonly AsyncLocal<int> pointerSize = new();
    private static readonly ConcurrentDictionary<(bool Status, uint Code), string> errors = new();
    public static int PointerSize => pointerSize.Value == 4 ? 4 : 8;
    public static long Revision { get; private set; }
    private static CatalogDatabase Definitions => PointerSize == 4 ? definitions32.Value : definitions.Value;
    public static (int Functions, int Types, long Queries) Statistics => Definitions.Statistics;

    public static IDisposable UsePointerSize(int bytes) => new ArchitectureScope(bytes);

    private sealed class ArchitectureScope : IDisposable
    {
        private readonly int previous = pointerSize.Value;
        public ArchitectureScope(int bytes) => pointerSize.Value = bytes == 4 ? 4 : 8;
        public void Dispose() => pointerSize.Value = previous;
    }

    public static void Refresh()
    {
        var changed = definitions.IsValueCreated && definitions.Value.Refresh();
        changed |= definitions32.IsValueCreated && definitions32.Value.Refresh();
        if (changed) ++Revision;
    }

    public static ApiSignature? Function(string name, string module, string description = "")
    {
        if (name.EndsWith(" [syscall]", StringComparison.Ordinal)) name = name[..^10];
        if (name.StartsWith("TlsCallback #", StringComparison.Ordinal)) name = "TlsCallback";
        if (name.StartsWith("Zw", StringComparison.Ordinal)) name = "Nt" + name[2..];
        module = Path.GetFileName(module).ToLowerInvariant();
        if (module == "com" && description.IndexOf(" * instance", StringComparison.Ordinal) is > 0 and var receiver)
            name = description[..receiver] + "::" + name[(name.LastIndexOf("::", StringComparison.Ordinal) + 2)..];
        var crt = module is "ucrtbase.dll" or "ntdll.dll" || module.StartsWith("msvcr", StringComparison.Ordinal) ||
            module.StartsWith("vcruntime", StringComparison.Ordinal) ||
            module.StartsWith("api-ms-win-crt-", StringComparison.Ordinal);
        if (crt && name.StartsWith("_o_", StringComparison.Ordinal)) name = name[3..];
        return Definitions.Function(name, module, module == "com" ? description : "");
    }

    // Describes a status, HRESULT or Win32 error using the system's own message tables.
    public static string ErrorMessage(string type, ulong value)
    {
        var status = type.Equals("NTSTATUS", StringComparison.OrdinalIgnoreCase);
        if (errors.Count >= ErrorCacheCapacity) errors.Clear();
        return errors.GetOrAdd((status, (uint)value), key =>
        {
            var buffer = new char[FormatMessageBufferChars];
            var length = FormatMessage(FormatMessageFromSystem | FormatMessageIgnoreInserts |
                (key.Status ? FormatMessageFromHModule : 0u),
                key.Status ? GetModuleHandle("ntdll.dll") : 0, key.Code, 0, buffer, buffer.Length, 0);
            var message = new string(buffer, 0, (int)length).ReplaceLineEndings(" ").Trim();
            var code = (key.Code & 0xFFFF0000) == 0x80070000 ? key.Code & 0xFFFF : key.Code;
            var name = (key.Status, code) switch
            {
                (true, 0xC0000005) => "ACCESS_VIOLATION", (true, 0xC0000008) => "INVALID_HANDLE",
                (true, 0xC000000D) => "INVALID_PARAMETER", (true, 0xC0000022) => "ACCESS_DENIED",
                (true, 0xC0000023) => "BUFFER_TOO_SMALL", (true, 0xC0000034) => "OBJECT_NAME_NOT_FOUND",
                (true, 0xC000003A) => "OBJECT_PATH_NOT_FOUND", (true, 0x80000005) => "BUFFER_OVERFLOW",
                (false, 2) => "ERROR_FILE_NOT_FOUND", (false, 3) => "ERROR_PATH_NOT_FOUND",
                (false, 5) => "ERROR_ACCESS_DENIED", (false, 6) => "ERROR_INVALID_HANDLE",
                (false, 32) => "ERROR_SHARING_VIOLATION", (false, 87) => "ERROR_INVALID_PARAMETER",
                (false, 122) => "ERROR_INSUFFICIENT_BUFFER", (false, 126) => "ERROR_MOD_NOT_FOUND",
                (false, 127) => "ERROR_PROC_NOT_FOUND", (false, 183) => "ERROR_ALREADY_EXISTS",
                (false, 234) => "ERROR_MORE_DATA", (false, 259) => "ERROR_NO_MORE_ITEMS",
                _ => ""
            };
            return name.Length == 0 ? message : message.Length == 0 ? name : $"{name}: {message}";
        });
    }

    [DllImport("kernel32.dll", EntryPoint = "FormatMessageW", CharSet = CharSet.Unicode)]
    private static extern uint FormatMessage(uint flags, nint source, uint message, uint language, [Out] char[] buffer,
        int size, nint arguments);
    [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode)]
    private static extern nint GetModuleHandle(string name);

    internal static bool MatchesModule(string origin, string module, string name)
    {
        // Module families match the same literal prefix and suffix used by the capture engines.
        var wildcard = origin.IndexOf('*');
        var family = wildcard >= 0 && module.Length >= origin.Length - 1 &&
            module.StartsWith(origin[..wildcard], StringComparison.OrdinalIgnoreCase) &&
            module.EndsWith(origin[(wildcard + 1)..], StringComparison.OrdinalIgnoreCase);
        var crt = module is "ucrtbase.dll" or "ntdll.dll" || module.StartsWith("msvcr", StringComparison.Ordinal) ||
            module.StartsWith("vcruntime", StringComparison.Ordinal) ||
            module.StartsWith("api-ms-win-crt-", StringComparison.Ordinal);
        return origin.Length == 0 || origin == "$image" ||
            origin == "$crt" && crt || family || origin.Equals(module, StringComparison.OrdinalIgnoreCase) ||
            (module == "kernelbase.dll" || module.StartsWith("api-ms-win-core-", StringComparison.Ordinal)) &&
                origin is "kernel32.dll" or "advapi32.dll" ||
            module == "sechost.dll" && origin == "advapi32.dll" ||
            module == "combase.dll" && origin == "ole32.dll" ||
            module == "gdi32full.dll" && origin == "gdi32.dll" ||
            name.StartsWith("?", StringComparison.Ordinal) && (
                module == "msvcr120_clr0400.dll" && origin == "msvcr120.dll" ||
                module == "msvcp120_clr0400.dll" && origin == "msvcp120.dll");
    }

    public static TypeLayout? Type(string declaration)
    {
        var name = Regex.Replace(declaration, @"\b(const|volatile|struct|union|enum)\s+", "").Trim();
        name = Regex.Replace(name, @"(?<=\*)\s*(?:(?:const|volatile)\b\s*)+", "").Trim();
        if (Definitions.Type(name) is { } type)
        {
            for (var depth = 0; type.Kind == "Alias" && type.Element is { } element && depth < MaxAliasResolutionDepth; ++depth)
            {
                // An external SDK can supply an alias width without defining the underlying type.
                if (Definitions.Type(element) is not { } target) return type.Size > 0 ? type : null;
                type = target;
            }
            return type;
        }
        if (name.EndsWith('*') || name.EndsWith('&'))
            return new("Pointer", PointerSize, Element: name[..^1].Trim());
        return null;
    }

    public static TypeLayout? Structure(string declaration)
    {
        var type = Type(declaration);
        for (var depth = 0; type?.Kind == "Pointer" && type.Element is { } element && depth < MaxPointerDereferenceDepth; ++depth)
            type = Type(element);
        return type?.Kind is "Structure" or "Union" && type.Fields is { Length: > 0 } ? type : null;
    }
}

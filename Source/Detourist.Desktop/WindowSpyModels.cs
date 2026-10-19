using System.ComponentModel;
using System.Globalization;
using System.Text.Json;

namespace Detourist.Desktop;

public sealed class SpyNode : INotifyPropertyChanged
{
    public required string Key { get; init; }
    public required string Label { get; init; }
    public required string Title { get; init; }
    public required string Kind { get; init; }
    public required long Pid { get; init; }
    public long Tid { get; init; }
    public string Window { get; init; } = "0x0";
    public string Architecture { get; init; } = "";
    public string ProcessName { get; init; } = "";
    public string Identifier => Kind == "Window" ? Window : Kind == "Thread" ? $"TID {Tid}" : $"PID {Pid}";
    public List<SpyNode> Children { get; init; } = [];
    private bool expanded;
    private bool selected;
    public event PropertyChangedEventHandler? PropertyChanged;
    public bool Expanded
    {
        get => expanded;
        set { expanded = value; PropertyChanged?.Invoke(this, new(nameof(Expanded))); }
    }
    public bool Selected
    {
        get => selected;
        set { selected = value; PropertyChanged?.Invoke(this, new(nameof(Selected))); }
    }
}

public sealed record SpyProperty(string Name, string Value);

public sealed record WindowMessage(long Sequence, double Seconds, string Window, long Tid, uint Id, int Type,
    string WParam, string LParam, string Result, string ClassName, string Registered)
{
    public string Time => Seconds.ToString("F6", CultureInfo.InvariantCulture);
    public string Kind => Type switch { 0 => "Sent", 1 => "Return", 2 => "Posted", _ => "Peek" };
    public string Code => $"0x{Id:X4}";
    public string Name { get; } = WindowMessages.Name(Id, ClassName, Registered);
    public string ReturnValue => Type == 1 ? Result : "";
    public string Decoded { get; } = WindowMessages.Decode(Id, WParam, LParam);
    public string Category => Id is >= 0x100 and <= 0x109 or >= 0x10D and <= 0x10F ? "Keyboard" :
        Id is >= 0x200 and <= 0x20E or >= 0xA0 and <= 0xAD or >= 0x2A0 and <= 0x2A3 ? "Mouse" :
        Id >= 0x8000 || Name.StartsWith("WM_USER", StringComparison.Ordinal) ? "Application" :
        Name.StartsWith("WM_", StringComparison.Ordinal) ? "Window" : "Control";

    public bool Matches(string text) => text.Length == 0 || new[]
    {
        Name, Code, Window, Tid.ToString(CultureInfo.InvariantCulture), Kind, WParam, LParam, ReturnValue,
        ClassName, Decoded
    }.Any(value => value.Contains(text, StringComparison.OrdinalIgnoreCase));

    public static WindowMessage FromJson(JsonElement value, long sequence) => new(sequence,
        value.GetProperty("time").GetDouble(), value.Text("window"), value.Number("tid"),
        (uint)value.Number("message"), (int)value.Number("kind"), value.Text("wparam"), value.Text("lparam"),
        value.Text("result"), value.Text("class"), value.Text("registered"));
}

public static partial class WindowMessages
{
    private const uint WmUserBase = 0x0400;
    private const uint WmAppBase = 0x8000;
    private const uint RegisteredMessageMin = 0xC000;
    private const uint RegisteredMessageMax = 0xFFFF;

    public static string Name(uint id, string className, string registered = "")
    {
        // Control messages share numeric ranges; decode them only in the owning window class.
        if (registered.Length > 0) return registered;
        var group = className.ToUpperInvariant() switch
        {
            "BUTTON" => "Button", "EDIT" => "Edit", "LISTBOX" => "ListBox", "COMBOBOX" => "ComboBox",
            "SCROLLBAR" => "ScrollBar", "SYSLISTVIEW32" => "ListView", "SYSTREEVIEW32" => "TreeView",
            "SYSHEADER32" => "Header", "SYSTABCONTROL32" => "Tab", "SYSPAGER" => "Pager",
            "SYSDATETIMEPICK32" => "DateTime", "SYSMONTHCAL32" => "MonthCalendar",
            "MSCTLS_PROGRESS32" => "Progress", "MSCTLS_TRACKBAR32" => "TrackBar", "MSCTLS_UPDOWN32" => "UpDown",
            "MSCTLS_STATUSBAR32" => "StatusBar", "TOOLBARWINDOW32" => "ToolBar", "REBARWINDOW32" => "Rebar",
            "TOOLTIPS_CLASS32" => "ToolTip", var text when text.StartsWith("RICHEDIT") => "RichEdit", _ => ""
        };
        if (ControlNames.TryGetValue(group, out var messages) && messages.TryGetValue(id, out var name)) return name;
        if (group == "RichEdit" && ControlNames["Edit"].TryGetValue(id, out name)) return name;
        if (CommonControls.TryGetValue(group, out messages) &&
            (messages.TryGetValue(id, out name) || CommonMessages.TryGetValue(id, out name))) return name;
        if (WindowNames.TryGetValue(id, out name)) return name;
        return id >= RegisteredMessageMin && id <= RegisteredMessageMax ? $"Registered 0x{id:X4}" :
            id >= WmAppBase ? $"WM_APP+{id - WmAppBase}" :
            id >= WmUserBase ? $"WM_USER+{id - WmUserBase}" : $"0x{id:X4}";
    }

    public static string Decode(uint id, string first, string second)
    {
        // shortcut: pointer payloads remain addresses; add bounded target-side snapshots for structured decoding.
        var w = ulong.Parse(first.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        var l = ulong.Parse(second.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        var low = (ushort)w;
        var high = (ushort)(w >> 16);
        var x = (short)l;
        var y = (short)(l >> 16);
        return id switch
        {
            0x0003 => $"x={x}, y={y}",
            0x0005 => $"width={(ushort)l}, height={(ushort)(l >> 16)}, state={w}",
            0x0006 => $"state={low}, minimized={high != 0}, other={second}",
            0x0007 or 0x0008 => $"other window={first}",
            0x000A => $"enabled={w != 0}",
            0x000B => $"redraw={w != 0}",
            0x0018 => $"shown={w != 0}, reason={l}",
            0x0020 => $"window={first}, hit test={x}, mouse message=0x{(ushort)(l >> 16):X4}",
            0x004E => $"control ID={w}, NMHDR address={second}",
            0x007B => $"window={first}, screen x={x}, y={y}",
            >= 0x0100 and <= 0x0109 => $"key=0x{w:X}, repeat={(ushort)l}, scan={(l >> 16) & 255}, " +
                $"extended={(l & (1UL << 24)) != 0}, Alt={(l & (1UL << 29)) != 0}, " +
                $"was down={(l & (1UL << 30)) != 0}, released={(l & (1UL << 31)) != 0}",
            0x0111 => l == 0 ? $"{(high == 1 ? "Accelerator" : "Menu")} ID={low}" :
                $"control ID={low}, notification={high}, window={second}",
            0x0112 => $"command=0x{w & 0xFFF0:X4}, x={x}, y={y}",
            0x0113 or 0x0118 => $"timer={first}, callback={second}",
            0x0114 or 0x0115 => $"request={low}, position={high}, control={second}",
            0x020A or 0x020E => $"delta={(short)high}, keys=0x{low:X}, screen x={x}, y={y}",
            >= 0x0200 and <= 0x020D => $"x={x}, y={y}, keys=0x{low:X}" +
                (id is >= 0x020B and <= 0x020D ? $", X button={high}" : ""),
            >= 0x00A0 and <= 0x00AD => $"screen x={x}, y={y}, hit test={w}",
            0x02E0 => $"DPI x={low}, y={high}, rectangle address={second}",
            _ => $"wParam={first}, lParam={second}"
        };
    }
}

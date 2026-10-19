using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;

namespace Detourist.Desktop;

public sealed class BufferWindow : ToolWindow
{
    public BufferWindow(ParameterProperty property) : base(property.Name, "Captured memory · read only", 870, 650)
    {
        var tabs = new TabControl();
        Body.Children.Add(tabs);
        foreach (var (name, snapshot) in new[] { ("Input", property.InputMemory), ("Output", property.OutputMemory) })
        {
            if (snapshot is null) continue;
            var layout = new Grid();
            layout.RowDefinitions.Add(new() { Height = GridLength.Auto });
            layout.RowDefinitions.Add(new() { Height = new(1, GridUnitType.Star) });
            var bar = new DockPanel { Margin = new(7) };
            var format = new ComboBox
            {
                ItemsSource = new[] { "Hex / ASCII", "UTF-16", "UTF-8", "ASCII" }, Width = 125,
                SelectedIndex = snapshot.Kind == (int)ValueKind.Utf16 ? 1 : 0
            };
            AutomationProperties.SetName(format, name + " buffer format");
            DockPanel.SetDock(format, Dock.Right);
            bar.Children.Add(format);
            bar.Children.Add(new TextBlock
            {
                Text = snapshot.TypeName + " · " + snapshot.Size +
                    (snapshot.State.Length == 0 ? "" : " · " + snapshot.State),
                VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap, Margin = new(0, 0, 8, 0)
            });
            layout.Children.Add(bar);
            var text = new TextBox
            {
                IsReadOnly = true, AcceptsReturn = true, FontFamily = new("Consolas"), FontSize = 12,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                BorderThickness = new(0), Background = Brushes.Transparent
            };
            AutomationProperties.SetName(text, name + " captured bytes");
            Grid.SetRow(text, 1);
            layout.Children.Add(text);
            void Display() => text.Text = format.SelectedIndex switch
            {
                1 => snapshot.Text(Encoding.Unicode), 2 => snapshot.Text(Encoding.UTF8),
                3 => snapshot.Text(Encoding.ASCII), _ => snapshot.HexDump()
            };
            format.SelectionChanged += (_, _) => Display();
            Display();
            tabs.Items.Add(new TabItem { Header = name, Content = layout });
        }
        AddAction("_Close", true, (_, _) => Close()).IsCancel = true;
    }
}

public sealed class BitsWindow : ToolWindow
{
    private readonly CheckBox[] bits;
    public ulong Value => bits.Select((bit, index) => bit.IsChecked == true ? 1UL << index : 0)
        .Aggregate(0UL, (value, bit) => value | bit);

    public BitsWindow(ParameterProperty property) : base(property.Name + " · bits",
        $"{property.Type.Bits}-bit mask. Changes are staged until the call continues.", 850,
        property.Type.Bits == 64 ? 630 : 420)
    {
        var panel = new UniformGrid { Columns = 4 };
        Body.Children.Add(new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        bits = new CheckBox[property.Type.Bits];
        for (var index = 0; index < bits.Length; ++index)
        {
            bits[index] = new CheckBox
            {
                Content = $"Bit {index} · 0x{1UL << index:X}", IsChecked = (property.EditedValue & (1UL << index)) != 0,
                Margin = new(0, 3, 10, 3), FontFamily = new("Consolas"), FontSize = 11
            };
            panel.Children.Add(bits[index]);
        }
        AddAction("_Cancel", false, (_, _) => DialogResult = false).IsCancel = true;
        AddAction("_Apply", true, (_, _) => DialogResult = true).IsDefault = true;
    }
}

public sealed class MemoryEditor : Grid
{
    private readonly TextBox address = new() { FontFamily = new("Consolas") };
    private readonly TextBox length = new() { Width = 80 };
    private readonly ComboBox format = new();
    private readonly TextBox data = new();
    private byte[]? loaded;
    private bool displaying;
    public event Action<bool>? BusyChanged;
    public bool Busy { get; private set; }

    public void SetAddress(ulong value, string type)
    {
        address.Text = $"0x{value:X}";
        format.SelectedIndex = type.Contains("WSTR") || type.Contains("WCHAR") ? 1 : 0;
        data.Clear();
        loaded = null;
    }

    public MemoryEditor(CollectorClient client, JsonElement call, int limit)
    {
        Margin = new(10);
        RowDefinitions.Add(new() { Height = GridLength.Auto });
        RowDefinitions.Add(new() { Height = GridLength.Auto });
        RowDefinitions.Add(new() { Height = GridLength.Auto });
        RowDefinitions.Add(new() { Height = new(1, GridUnitType.Star) });
        RowDefinitions.Add(new() { Height = GridLength.Auto });
        Children.Add(new TextBlock
        {
            Text = $"Live target memory · {limit:N0}-byte limit. Writes apply immediately while the process is paused.",
            TextWrapping = TextWrapping.Wrap, Foreground = (Brush)FindResource("MutedBrush"), Margin = new(0, 0, 0, 10)
        });

        // Address, extent and interpretation apply to both reading and writing target memory.
        AutomationProperties.SetName(address, "Memory address");
        AutomationProperties.SetName(length, "Memory read length");
        length.Text = limit.ToString(CultureInfo.InvariantCulture);
        var line = new Grid { Margin = new(0, 0, 0, 8) };
        line.ColumnDefinitions.Add(new() { Width = new(110) });
        line.ColumnDefinitions.Add(new() { Width = new(1, GridUnitType.Star) });
        line.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        line.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        line.Children.Add(new TextBlock { Text = "Address (hex)", VerticalAlignment = VerticalAlignment.Center });
        Grid.SetColumn(address, 1);
        line.Children.Add(address);
        var sizeLabel = new TextBlock
        {
            Text = "Read bytes", VerticalAlignment = VerticalAlignment.Center, Margin = new(10, 0, 7, 0)
        };
        Grid.SetColumn(sizeLabel, 2);
        line.Children.Add(sizeLabel);
        Grid.SetColumn(length, 3);
        line.Children.Add(length);
        Grid.SetRow(line, 1);
        Children.Add(line);
        format.ItemsSource = new[] { "Hex bytes", "UTF-16 + NUL", "UTF-8 + NUL", "UInt32", "Int32", "UInt64",
            "Int64", "Float32", "Float64" };
        format.SelectedIndex = 0;
        format.Width = 180;
        format.HorizontalAlignment = HorizontalAlignment.Left;
        AutomationProperties.SetName(format, "Memory data type");
        var typeLine = new DockPanel { Margin = new(0, 0, 0, 8) };
        typeLine.Children.Add(new TextBlock { Text = "Data type", Width = 110,
            VerticalAlignment = VerticalAlignment.Center });
        typeLine.Children.Add(format);
        Grid.SetRow(typeLine, 2);
        Children.Add(typeLine);
        data.AcceptsReturn = data.AcceptsTab = true;
        data.FontFamily = new("Consolas");
        data.TextWrapping = TextWrapping.Wrap;
        data.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
        AutomationProperties.SetName(data, "Memory value");
        Grid.SetRow(data, 3);
        Children.Add(data);
        data.TextChanged += (_, _) =>
        {
            if (!displaying) loaded = null;
        };
        void Display()
        {
            using var architecture = ApiMetadata.UsePointerSize((int)call.Number("pointerSize", 8));
            if (loaded is null) return;
            displaying = true;
            try
            {
                var type = ParameterType.Infer((string)format.SelectedItem);
                data.Text = format.SelectedIndex switch
                {
                    0 => Convert.ToHexString(loaded), 1 => Encoding.Unicode.GetString(loaded).TrimEnd('\0'),
                    2 => Encoding.UTF8.GetString(loaded).TrimEnd('\0'),
                    _ => type.Format(MemorySnapshot.Scalar(loaded, 0, Math.Min(type.Bits / 8, loaded.Length)), false)
                };
            }
            finally
            {
                displaying = false;
            }
        }
        format.SelectionChanged += (_, _) => Display();
        var footer = new DockPanel { Margin = new(0, 8, 0, 0) };
        var write = new Button { Content = "_Write memory", Margin = new(5, 0, 0, 0) };
        var read = new Button { Content = "_Read memory", Margin = new(8, 0, 0, 0) };
        DockPanel.SetDock(write, Dock.Right);
        DockPanel.SetDock(read, Dock.Right);
        footer.Children.Add(write);
        footer.Children.Add(read);
        var message = new TextBlock { TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
        footer.Children.Add(message);
        Grid.SetRow(footer, 4);
        Children.Add(footer);

        // Bind every operation to the paused call and keep continue disabled until it completes.
        async Task Access(bool reading)
        {
            Busy = true;
            BusyChanged?.Invoke(true);
            IsEnabled = false;
            try
            {
                var target = new ParameterType("Pointer", Kind: "Pointer").Parse(address.Text, true);
                var request = new Dictionary<string, object>
                {
                    ["address"] = $"0x{target:X}", ["callId"] = call.Number("id"),
                    ["pid"] = call.Number("pid"), ["tid"] = call.Number("tid")
                };
                if (reading)
                {
                    if (!int.TryParse(length.Text, out var count) || count < 1 || count > limit)
                        throw new FormatException($"Read length must be 1 to {limit:N0} bytes.");
                    request["length"] = count;
                    var result = await client.Send("readMemory", request);
                    loaded = Convert.FromHexString(result.Text("bytes"));
                    Display();
                    message.Text = $"{loaded.Length:N0} / {count:N0} bytes read from 0x{target:X}.";
                }
                else
                {
                    byte[] bytes;
                    if (format.SelectedIndex == 0)
                        bytes = Convert.FromHexString(string.Concat(
                            data.Text.Where(character => !char.IsWhiteSpace(character))));
                    else if (format.SelectedIndex is 1 or 2)
                        bytes = (format.SelectedIndex == 1 ? Encoding.Unicode : Encoding.UTF8)
                            .GetBytes(data.Text + '\0');
                    else
                    {
                        using var architecture = ApiMetadata.UsePointerSize((int)call.Number("pointerSize", 8));
                        var type = ParameterType.Infer((string)format.SelectedItem);
                        var value = type.Parse(data.Text, false);
                        bytes = new byte[type.Bits / 8];
                        for (var index = 0; index < bytes.Length; ++index) bytes[index] = (byte)(value >> (index * 8));
                    }
                    if (bytes.Length == 0 || bytes.Length > limit)
                        throw new FormatException($"Enter 1 to {limit:N0} bytes of data.");
                    request["bytes"] = Convert.ToHexString(bytes);
                    await client.Send("writeMemory", request);
                    message.Text = $"{bytes.Length:N0} bytes written to 0x{target:X}.";
                }
                message.Foreground = (Brush)FindResource("AccentBrush");
            }
            catch (Exception exception)
            {
                message.Text = exception.Message;
                message.Foreground = (Brush)FindResource("DangerBrush");
            }
            finally
            {
                IsEnabled = true;
                Busy = false;
                BusyChanged?.Invoke(false);
            }
        }
        write.Click += async (_, _) => await Access(false);
        read.Click += async (_, _) => await Access(true);
    }
}

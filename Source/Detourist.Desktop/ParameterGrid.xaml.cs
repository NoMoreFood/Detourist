using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace Detourist.Desktop;

public partial class ParameterGrid : UserControl
{
    private const double ExpandedValueMaxHeight = 160;
    private const double CollapsedValueMaxHeight = 48;

    public event Action<ParameterProperty>? MemoryRequested;
    public event Action<ulong>? FollowRequested;
    public bool IncludeStack { get; set; } = true;
    private readonly ObservableCollection<ParameterProperty> visible = [];
    private List<ParameterProperty> roots = [];
    private (long Target, long Call, bool Breakpoint, bool Leaving)? identity;
    private bool updating;
    private bool valueExpanded;
    private JsonElement? captured;
    private ParameterProperty? Selected => PropertiesGrid.SelectedItem as ParameterProperty;

    public ParameterGrid()
    {
        InitializeComponent();
        updating = true;
        InterpretCombo.ItemsSource = ParameterType.Interpretations;
        NumberFormat.ItemsSource = new[] { "Hexadecimal", "Decimal" };
        PropertiesGrid.ItemsSource = visible;
        updating = false;

        // A scalar value can be followed through every other call that received or returned it.
        var follow = new MenuItem { Header = "Show Calls With This Value" };
        var copy = new MenuItem { Header = "Copy Value" };
        follow.Click += (_, _) =>
        {
            if ((Selected?.Input ?? Selected?.Output) is { } value) FollowRequested?.Invoke(value);
        };
        copy.Click += (_, _) =>
        {
            try
            {
                if (Selected is { } property) Clipboard.SetText(property.ValueText);
            }
            catch (System.Runtime.InteropServices.ExternalException)
            {
            }
        };
        PropertiesGrid.ContextMenu = new ContextMenu { Items = { follow, copy } };
        PropertiesGrid.PreviewMouseRightButtonDown += ToolWindow.SelectContextRow;
        PropertiesGrid.ContextMenuOpening += (_, e) =>
        {
            follow.Visibility = FollowRequested is null ? Visibility.Collapsed : Visibility.Visible;
            follow.IsEnabled = (Selected?.Input ?? Selected?.Output).HasValue;
            e.Handled = Selected is null;
        };
    }

    public void Clear(string message = "No parameters loaded")
    {
        roots = [];
        identity = null;
        captured = null;
        RawCheck.Visibility = Visibility.Collapsed;
        RawCheck.IsChecked = false;
        visible.Clear();
        EmptyText.Text = message;
        EmptyText.Visibility = Visibility.Visible;
        EditorPanel.Visibility = Visibility.Collapsed;
    }

    public void ShowCall(JsonElement call, bool breakpoint = false, bool leaving = false)
    {
        // Retain the inspected property and its interpretation when a pending call receives output.
        var nextIdentity = (call.Number("target"), call.Number("id"), breakpoint, leaving);
        var showRaw = identity == nextIdentity && RawCheck.IsChecked == true;
        var previous = identity == nextIdentity ? Keyed(roots).ToDictionary(item => item.Key, item => item.Row) : null;
        var selectedKey = previous?.FirstOrDefault(item => item.Value == Selected).Key;
        if (previous is null) valueExpanded = false;
        Clear();
        RawCheck.Visibility = !breakpoint && call.Items("rawArguments").Length > 0 ?
            Visibility.Visible : Visibility.Collapsed;
        captured = RawCheck.Visibility == Visibility.Visible ? call.Clone() : null;
        RawCheck.IsChecked = showRaw && RawCheck.Visibility == Visibility.Visible;
        roots = ParameterValues.Build(call, breakpoint, leaving, RawCheck.IsChecked == true);
        if (!IncludeStack) roots.RemoveAll(row => row.Name == "Call stack");
        identity = nextIdentity;
        ModeText.Text = breakpoint ? leaving ? "Return breakpoint" : "Entry breakpoint" : "Captured values · read only";
        InputColumn.Visibility = OutputColumn.Visibility = breakpoint ? Visibility.Collapsed : Visibility.Visible;
        ValueColumn.Visibility = breakpoint ? Visibility.Visible : Visibility.Collapsed;
        TypesCheck.Visibility = breakpoint ? Visibility.Collapsed : Visibility.Visible;
        TypeColumn.Visibility = breakpoint || TypesCheck.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PropertiesGrid.Columns[0].Width = breakpoint ? new(230) : new(125);
        TypeColumn.Width = breakpoint ? new(170) : new(100);
        foreach (var (key, row) in Keyed(roots))
        {
            row.Expanded = row.Level == 0 && row.Children.Count > 0;
            if (row.Parameter >= 0 || row.Level > 0) row.Hex = HexCheck.IsChecked == true;
            if (previous is null || !previous.TryGetValue(key, out var before)) continue;
            row.Expanded = before.Expanded;
            row.Hex = before.Hex;
            row.OverrideType = before.OverrideType;
        }
        Rebuild();
        PropertiesGrid.SelectedItem = selectedKey is null ? roots.FirstOrDefault() :
            Keyed(roots).FirstOrDefault(item => item.Key == selectedKey).Row ?? roots.FirstOrDefault();
    }

    public string[] Arguments()
    {
        Validate();
        return roots.Where(row => row.Parameter >= 0 && row.Input.HasValue)
            .Select(row => $"0x{row.EditedValue:X}").ToArray();
    }

    private void RawSlotsChanged(object sender, RoutedEventArgs e)
    {
        if (captured is { } call) ShowCall(call, identity?.Breakpoint == true, identity?.Leaving == true);
    }

    public string Result()
    {
        Validate();
        return $"0x{roots.First(row => row.Parameter == -1).EditedValue:X}";
    }

    public uint LastError()
    {
        Validate();
        var value = roots.First(row => row.Parameter == -2).EditedValue;
        if (value > uint.MaxValue) throw new FormatException("LastError must fit in 32 bits.");
        return (uint)value;
    }

    private void Validate()
    {
        if (roots.FirstOrDefault(row => row.Error is not null) is { } invalid)
            throw new FormatException(invalid.Name + ": " + invalid.Error);
    }

    private static IEnumerable<ParameterProperty> All(IEnumerable<ParameterProperty> rows)
    {
        foreach (var row in rows)
        {
            yield return row;
            foreach (var child in All(row.Children)) yield return child;
        }
    }

    private static IEnumerable<(string Key, ParameterProperty Row)> Keyed(IEnumerable<ParameterProperty> rows,
        string parent = "")
    {
        var index = 0;
        foreach (var row in rows)
        {
            var key = parent + "/" + index++ + ":" + row.Name;
            yield return (key, row);
            foreach (var child in Keyed(row.Children, key)) yield return child;
        }
    }

    private void Rebuild()
    {
        var selection = Selected;
        visible.Clear();
        void Add(IEnumerable<ParameterProperty> rows)
        {
            foreach (var row in rows)
            {
                visible.Add(row);
                row.Refresh();
                if (row.Expanded) Add(row.Children);
            }
        }
        Add(roots);

        // Expanded names retain room for indentation, cell padding and the expansion button.
        var typeface = new Typeface(PropertiesGrid.FontFamily, PropertiesGrid.FontStyle,
            PropertiesGrid.FontWeight, PropertiesGrid.FontStretch);
        var pixels = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        PropertiesGrid.Columns[0].MinWidth = Math.Max(95, visible.Where(row => row.Level > 1)
            .Select(row => Math.Ceiling(row.Indent.Left + 28 + new FormattedText(row.Name,
                CultureInfo.CurrentUICulture, FlowDirection, typeface, PropertiesGrid.FontSize,
                Foreground, pixels).WidthIncludingTrailingWhitespace))
            .DefaultIfEmpty(0).Max());
        EmptyText.Visibility = visible.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (selection is not null && visible.Contains(selection)) PropertiesGrid.SelectedItem = selection;
    }

    private void ToggleExpansion(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: ParameterProperty row } || row.Children.Count == 0) return;
        SetExpanded(row, !row.Expanded);
        e.Handled = true;
    }

    private void ExpandAll(object sender, RoutedEventArgs e) => SetAllExpanded(true);
    private void CollapseAll(object sender, RoutedEventArgs e) => SetAllExpanded(false);

    private void SetAllExpanded(bool expanded)
    {
        foreach (var row in All(roots)) row.Expanded = expanded;
        Rebuild();
    }

    private void FormatChanged(object sender, RoutedEventArgs e)
    {
        foreach (var row in All(roots))
        {
            if (row.InvalidText is not null) continue;
            row.Hex = HexCheck.IsChecked == true;
            row.Refresh();
        }
        ShowEditor();
    }

    private void TypesChanged(object sender, RoutedEventArgs e) =>
        TypeColumn.Visibility = TypesCheck.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;

    private void ExpandValue(object sender, RoutedEventArgs e)
    {
        valueExpanded = !valueExpanded;
        ShowEditor();
    }

    private void ValueResized(object sender, SizeChangedEventArgs e) => UpdateExpandValueButton();

    private void UpdateExpandValueButton() =>
        ExpandValueButton.Visibility = NumberInput.IsReadOnly &&
            (valueExpanded || NumberInput.ExtentHeight > NumberInput.ViewportHeight + 1) ?
            Visibility.Visible : Visibility.Collapsed;

    private void PropertySelected(object sender, SelectionChangedEventArgs e) => ShowEditor();

    private void ShowEditor()
    {
        if (Selected is not { } row)
        {
            EditorPanel.Visibility = Visibility.Collapsed;
            return;
        }
        updating = true;
        try
        {
            EditorPanel.Visibility = Visibility.Visible;
            if (EditorTitle.Text != row.Name + " : " + row.TypeName) valueExpanded = false;
            EditorTitle.Text = row.Name + " : " + row.TypeName;
            EditorTitle.ToolTip = EditorTitle.Text;
            InterpretCombo.SelectedIndex = row.OverrideType is null ? 0 :
                Math.Max(0, Array.IndexOf(ParameterType.Interpretations, row.OverrideType.Name));
            InterpretCombo.IsEnabled = row.InputMemory is null && row.OutputMemory is null &&
                (row.Input is not null || row.Output is not null);
            NumberFormat.SelectedIndex = row.Hex ? 0 : 1;
            NumberFormat.IsEnabled = row.Type.Kind != "Boolean" && InterpretCombo.IsEnabled;
            FlagsButton.Visibility = row.Editable && row.IsFlags ? Visibility.Visible : Visibility.Collapsed;
            var liveMemory = MemoryRequested is not null && row.Type.Kind == "Pointer" &&
                (row.Editable ? row.EditedValue : row.Input ?? row.Output ?? 0) != 0;
            BufferButton.Content = liveMemory ? "Memory…" : "Buffer…";
            BufferButton.Visibility = row.InputMemory is not null || row.OutputMemory is not null || liveMemory ?
                Visibility.Visible : Visibility.Collapsed;
            NumberInput.IsReadOnly = !row.Editable;
            NumberInput.Visibility = row.Editable && row.Type.Kind == "Boolean" ?
                Visibility.Collapsed : Visibility.Visible;
            var value = row.Editable ? row.EditedValue : row.Output ?? row.Input ?? 0;
            NumberInput.Text = row.Editable ? row.InvalidText ??
                (row.Type.Kind == "Enum" ? new ParameterType(row.TypeName, row.Type.Bits).Format(value, row.Hex) :
                    row.Type.Format(value, row.Hex)) : row.ValueText;

            // Keep long captured values readable without expanding the default inspector.
            NumberInput.TextWrapping = row.Editable ? TextWrapping.NoWrap : TextWrapping.Wrap;
            NumberInput.MaxHeight = row.Editable ? double.PositiveInfinity :
                valueExpanded ? ExpandedValueMaxHeight : CollapsedValueMaxHeight;
            UpdateExpandValueButton();
            ExpandValueButton.Content = valueExpanded ? "Less" : "More";
            ChoiceInput.Visibility = row.Editable && row.Type.Kind is "Boolean" or "Enum" ?
                Visibility.Visible : Visibility.Collapsed;
            if (ChoiceInput.Visibility == Visibility.Visible)
            {
                ShowChoices(row, value);
                Grid.SetColumn(ChoiceInput, row.Type.Kind == "Boolean" ? 0 : 1);
                Grid.SetColumnSpan(ChoiceInput, row.Type.Kind == "Boolean" ? 2 : 1);
                Grid.SetColumnSpan(NumberInput, row.Type.Kind == "Enum" ? 1 : 2);
            }
            else Grid.SetColumnSpan(NumberInput, 2);
            ShowNote(row);
        }
        finally
        {
            updating = false;
        }
    }

    private void ShowNote(ParameterProperty row)
    {
        EditorNote.Text = row.Note;
        EditorNote.Foreground = (Brush)FindResource(row.Error is not null ? "DangerBrush" :
            row.Modified ? "AccentBrush" : "MutedBrush");
    }

    private void InterpretChanged(object sender, SelectionChangedEventArgs e)
    {
        if (updating || Selected is not { } row || InterpretCombo.SelectedItem is not string type) return;
        using var architecture = ApiMetadata.UsePointerSize(row.PointerSize);
        row.OverrideType = type == "Signature" ? null : ParameterType.Infer(type);
        if (row.Type.Kind.StartsWith("Float")) row.Hex = false;
        if (row.InvalidText is not null && row.Editable) SetNumber(row, row.InvalidText);
        row.Refresh();
        ShowEditor();
    }

    private void NumberFormatChanged(object sender, SelectionChangedEventArgs e)
    {
        if (updating || Selected is not { } row) return;
        row.Hex = NumberFormat.SelectedIndex == 0;
        if (row.InvalidText is not null) SetNumber(row, row.InvalidText);
        row.Refresh();
        ShowEditor();
    }

    private void NumberEdited(object sender, TextChangedEventArgs e)
    {
        if (updating || Selected is not { Editable: true } row) return;
        SetNumber(row, NumberInput.Text);
        if (row.Type.Kind == "Enum" && !row.HasError)
        {
            updating = true;
            ShowChoices(row, row.EditedValue);
            updating = false;
        }
        row.Refresh();
        ShowNote(row);
        if (row.Type.Kind == "Pointer" && MemoryRequested is not null)
            BufferButton.Visibility = row.EditedValue == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    private static void SetNumber(ParameterProperty row, string text)
    {
        try
        {
            row.EditedValue = row.Type.Parse(text, row.Hex);
            row.InvalidText = row.Error = null;
        }
        catch (FormatException exception)
        {
            row.InvalidText = text;
            row.Error = exception.Message;
        }
    }

    private void ChoiceEdited(object sender, SelectionChangedEventArgs e)
    {
        if (updating || Selected is not { Editable: true } row ||
            ChoiceInput.SelectedItem is not EnumValue choice) return;
        CommitChoice(row, choice.Value);
    }

    private void EditFlags(object sender, RoutedEventArgs e)
    {
        if (Selected is not { Editable: true } row) return;
        var dialog = new BitsWindow(row) { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() == true) CommitChoice(row, dialog.Value);
    }

    private void CommitChoice(ParameterProperty row, ulong value)
    {
        row.EditedValue = value;
        row.InvalidText = row.Error = null;
        row.Refresh();
        ShowEditor();
    }

    private void ViewBuffer(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        if (row.InputMemory is null && row.OutputMemory is null)
        {
            MemoryRequested?.Invoke(row);
            return;
        }
        new BufferWindow(row) { Owner = Window.GetWindow(this) }.ShowDialog();
    }

    private void ShowChoices(ParameterProperty row, ulong value)
    {
        var choices = row.Type.Kind == "Boolean" ? new[] { new EnumValue("False", 0), new("True", 1) } :
            row.Type.Choices;
        if (choices.All(choice => choice.Value != value)) choices = [new("Current value", value), .. choices];
        ChoiceInput.ItemsSource = choices;
        ChoiceInput.SelectedItem = choices.First(choice => choice.Value == value);
    }

    private void SetExpanded(ParameterProperty row, bool expanded)
    {
        row.Expanded = expanded;
        Rebuild();
        PropertiesGrid.SelectedItem = row;
    }

    private void Activate(ParameterProperty row, object sender, RoutedEventArgs e)
    {
        if (row.InputMemory is not null || row.OutputMemory is not null) ViewBuffer(sender, e);
        else if (row.Editable)
        {
            (ChoiceInput.Visibility == Visibility.Visible && row.Type.Kind == "Boolean" ?
                (Control)ChoiceInput : NumberInput).Focus();
            NumberInput.SelectAll();
        }
    }

    private void PropertyDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (Selected is not { } row) return;
        if (row.Children.Count > 0)
        {
            SetExpanded(row, !row.Expanded);
            e.Handled = true;
        }
        else Activate(row, sender, e);
    }

    private void PropertyKeyDown(object sender, KeyEventArgs e)
    {
        if (Selected is not { } row) return;
        if (e.Key is Key.Left or Key.Right && row.Children.Count > 0)
        {
            SetExpanded(row, e.Key == Key.Right);
            e.Handled = true;
        }
        else if (e.Key is Key.F2 or Key.Enter)
        {
            Activate(row, sender, e);
            e.Handled = true;
        }
    }
}

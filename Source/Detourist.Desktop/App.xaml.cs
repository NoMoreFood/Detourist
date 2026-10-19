using System.Windows;
using System.Runtime.InteropServices;
using System.Windows.Interop;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]

namespace Detourist.Desktop;

public partial class App : Application
{
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaBorderColor = 34;
    private const int DwmwaCaptionColor = 35;
    private const int DwmwaTextColor = 36;

    internal static void ApplyNativeTheme(Window window)
    {
        // Keep the native caption and window controls consistent with the dark workspace.
        var handle = new WindowInteropHelper(window).Handle;
        var dark = 1;
        _ = DwmSetWindowAttribute(handle, DwmwaUseImmersiveDarkMode, ref dark, sizeof(int));
        var caption = 0x001F1C1B;
        var text = 0x00E0DCDA;
        var border = 0x00423D3A;
        _ = DwmSetWindowAttribute(handle, DwmwaCaptionColor, ref caption, sizeof(int));
        _ = DwmSetWindowAttribute(handle, DwmwaTextColor, ref text, sizeof(int));
        _ = DwmSetWindowAttribute(handle, DwmwaBorderColor, ref border, sizeof(int));
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(nint window, int attribute, ref int value, int size);
}

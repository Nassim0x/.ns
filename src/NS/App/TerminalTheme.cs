using System.Runtime.InteropServices;

namespace NS.App;

internal static class TerminalTheme
{
    private const int StdOutputHandle = -11;
    private const uint EnableVirtualTerminalProcessing = 0x0004;

    public static bool UseAnsi { get; private set; }

    public static void Initialize()
    {
        if (Console.IsOutputRedirected)
        {
            UseAnsi = false;
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            UseAnsi = true;
            return;
        }

        try
        {
            var handle = GetStdHandle(StdOutputHandle);

            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                UseAnsi = false;
                return;
            }

            if (!GetConsoleMode(handle, out var mode))
            {
                UseAnsi = false;
                return;
            }

            UseAnsi = SetConsoleMode(handle, mode | EnableVirtualTerminalProcessing);
        }
        catch
        {
            UseAnsi = false;
        }
    }

    public static string Strong(string text) => Fg(text, 232, 237, 255, bold: true);

    public static string Accent(string text) => Fg(text, 102, 217, 239, bold: true);

    public static string AccentSoft(string text) => Fg(text, 185, 143, 255, bold: true);

    public static string Muted(string text) => Fg(text, 150, 156, 187);

    public static string Success(string text) => Fg(text, 125, 230, 170, bold: true);

    public static string Warning(string text) => Fg(text, 255, 192, 112, bold: true);

    public static string Error(string text) => Fg(text, 255, 120, 147, bold: true);

    public static string Prompt(string text) => Fg(text, 125, 230, 255, bold: true);

    public static string Divider(int width)
    {
        var raw = new string('-', Math.Max(8, width));
        return AccentSoft(raw);
    }

    private static string Fg(string text, int r, int g, int b, bool bold = false)
    {
        if (!UseAnsi)
        {
            return text;
        }

        var weight = bold ? "\u001b[1m" : string.Empty;
        return $"{weight}\u001b[38;2;{r};{g};{b}m{text}\u001b[0m";
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
}

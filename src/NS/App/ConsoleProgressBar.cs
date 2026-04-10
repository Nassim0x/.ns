using System.Diagnostics;
using NS.Crypto;

namespace NS.App;

internal sealed class ConsoleProgressBar : IProgress<NsProgressUpdate>, IDisposable
{
    private readonly object _sync = new();
    private readonly Stopwatch _stopwatch = Stopwatch.StartNew();
    private string _lastLabel = string.Empty;
    private int _lastRawLength;
    private long _lastRenderedTickMs = -1;
    private bool _hasRendered;

    public void Report(NsProgressUpdate value)
    {
        lock (_sync)
        {
            var nowMs = _stopwatch.ElapsedMilliseconds;
            var isFinished = value.TotalBytes <= 0 || value.ProcessedBytes >= value.TotalBytes;
            var phaseChanged = !string.Equals(_lastLabel, value.Label, StringComparison.Ordinal);

            if (!isFinished && !phaseChanged && _lastRenderedTickMs >= 0 && nowMs - _lastRenderedTickMs < 50)
            {
                return;
            }

            Render(value);
            _lastLabel = value.Label;
            _lastRenderedTickMs = nowMs;
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_hasRendered)
            {
                Console.WriteLine();
            }
        }
    }

    private void Render(NsProgressUpdate value)
    {
        var totalBytes = Math.Max(0, value.TotalBytes);
        var processedBytes = totalBytes > 0
            ? Math.Clamp(value.ProcessedBytes, 0, totalBytes)
            : value.ProcessedBytes;

        var ratio = totalBytes > 0 ? (double)processedBytes / totalBytes : 1d;
        ratio = Math.Clamp(ratio, 0d, 1d);

        var consoleWidth = GetConsoleWidth();
        var barWidth = Math.Clamp(consoleWidth - 54, 18, 34);
        var filled = (int)Math.Round(barWidth * ratio, MidpointRounding.AwayFromZero);
        filled = Math.Clamp(filled, 0, barWidth);

        var empty = barWidth - filled;
        var percent = $"{ratio * 100,5:0.0}%";
        var sizeText = totalBytes > 0
            ? $"{FormatBytes(processedBytes)} / {FormatBytes(totalBytes)}"
            : FormatBytes(processedBytes);
        var speedText = _stopwatch.Elapsed.TotalSeconds > 0.25 && processedBytes > 0
            ? $"{FormatBytes((long)(processedBytes / _stopwatch.Elapsed.TotalSeconds))}/s"
            : string.Empty;

        var rawBar = $"{new string('#', filled)}{new string('-', empty)}";
        var rawLine = $"{value.Label,-10} [{rawBar}] {percent} {sizeText}";

        if (!string.IsNullOrWhiteSpace(speedText))
        {
            rawLine += $"  {speedText}";
        }

        string renderedBar;

        if (TerminalTheme.UseAnsi)
        {
            renderedBar = $"{TerminalTheme.Accent(new string('#', filled))}{TerminalTheme.Muted(new string('-', empty))}";
        }
        else
        {
            renderedBar = rawBar;
        }

        var renderedLine = $"{TerminalTheme.Strong(value.Label.PadRight(10))} [{renderedBar}] {TerminalTheme.Accent(percent)} {TerminalTheme.Muted(sizeText)}";

        if (!string.IsNullOrWhiteSpace(speedText))
        {
            renderedLine += $"  {TerminalTheme.AccentSoft(speedText)}";
        }

        Console.Write('\r');
        Console.Write(renderedLine);

        if (_lastRawLength > rawLine.Length)
        {
            Console.Write(new string(' ', _lastRawLength - rawLine.Length));
        }

        _lastRawLength = rawLine.Length;
        _hasRendered = true;
    }

    private static int GetConsoleWidth()
    {
        try
        {
            return Console.IsOutputRedirected ? 120 : Console.WindowWidth;
        }
        catch
        {
            return 120;
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = Math.Max(0, bytes);
        var unitIndex = 0;

        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        return unitIndex == 0 ? $"{value:0} {units[unitIndex]}" : $"{value:0.0} {units[unitIndex]}";
    }
}

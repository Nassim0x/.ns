using System.Text;
using NS.Crypto;
using NS.Security;

namespace NS.App;

internal sealed class NSConsole
{
    private readonly NsFileProtector _protector = new();

    public int Run(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.Title = "NS";
        TerminalTheme.Initialize();
        var pauseOnExit = ShouldPauseOnExit(args);
        TryAutoInstallShellIntegration(args);

        try
        {
            return args.Length == 0 ? RunInteractive() : RunCommand(args);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine();
            Console.WriteLine(TerminalTheme.Warning("[cancelled] Operation cancelled."));

            if (pauseOnExit)
            {
                PauseBeforeExit();
            }

            return 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine(TerminalTheme.Error($"[error] {ex.Message}"));

            if (pauseOnExit)
            {
                PauseBeforeExit();
            }

            return 1;
        }
    }

    private int RunInteractive()
    {
        while (true)
        {
            DrawDashboard();
            WriteCenteredPrompt("Choice > ");

            var input = (Console.ReadLine() ?? string.Empty).Trim();
            Console.WriteLine();

            switch (input)
            {
                case "1":
                    EncryptInteractive();
                    break;
                case "2":
                    DecryptInteractive();
                    break;
                case "3":
                    return 0;
                default:
                    if (TryHandleQuickFileInput(input))
                    {
                        break;
                    }

                    Console.WriteLine(TerminalTheme.Warning("[warning] Invalid choice."));
                    Pause();
                    break;
            }
        }
    }

    private int RunCommand(string[] args)
    {
        var force = args.Any(arg => string.Equals(arg, "--force", StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(arg, "-f", StringComparison.OrdinalIgnoreCase));
        var compress = args.Any(arg => string.Equals(arg, "--compress", StringComparison.OrdinalIgnoreCase) ||
                                       string.Equals(arg, "-z", StringComparison.OrdinalIgnoreCase));

        var positional = args
            .Where(arg => !string.Equals(arg, "--force", StringComparison.OrdinalIgnoreCase) &&
                          !string.Equals(arg, "-f", StringComparison.OrdinalIgnoreCase) &&
                          !string.Equals(arg, "--compress", StringComparison.OrdinalIgnoreCase) &&
                          !string.Equals(arg, "-z", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (positional.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        if (TryRunImplicitPathCommand(positional, force, compress))
        {
            return 0;
        }

        var command = positional[0].ToLowerInvariant();

        switch (command)
        {
            case "encrypt":
                if (positional.Length is < 2 or > 3)
                {
                    PrintUsage();
                    return 1;
                }

                EncryptFile(positional[1], positional.ElementAtOrDefault(2), force, compress);
                return 0;

            case "decrypt":
                if (positional.Length is < 2 or > 3)
                {
                    PrintUsage();
                    return 1;
                }

                DecryptFile(positional[1], positional.ElementAtOrDefault(2), force);
                return 0;

            case "encrypt-shell":
                if (positional.Length != 2)
                {
                    PrintUsage();
                    return 1;
                }

                EncryptInteractive(positional[1]);
                return 0;

            case "decrypt-shell":
            case "open-shell":
                if (positional.Length != 2)
                {
                    PrintUsage();
                    return 1;
                }

                DecryptInteractive(positional[1]);
                return 0;

            case "help":
            case "--help":
            case "-h":
                PrintUsage();
                return 0;

            default:
                PrintUsage();
                return 1;
        }
    }

    private void EncryptInteractive(string? initialInputPath = null)
    {
        DrawActionScreen("Encrypt", "Protect a file, folder, or drive into a .ns container.");

        var inputPath = string.IsNullOrWhiteSpace(initialInputPath)
            ? ReadPath("Path: ")
            : NormalizePath(initialInputPath);

        if (!string.IsNullOrWhiteSpace(initialInputPath))
        {
            Console.WriteLine(TerminalTheme.Muted($"Path    : {inputPath}"));
        }

        var suggestedOutput = $"{inputPath}.ns";
        var rawOutputPath = ReadOptionalPath($"Output .ns (leave empty for {suggestedOutput}): ", suggestedOutput) ?? suggestedOutput;
        var outputPath = ResolveEncryptOutputPath(inputPath, rawOutputPath);
        var compress = ConfirmCompression();
        var force = ConfirmOverwriteIfNeeded(outputPath);

        EncryptFile(inputPath, outputPath, force, compress);
        Pause();
    }

    private void DecryptInteractive(string? initialInputPath = null)
    {
        DrawActionScreen("Decrypt", "Restore a file, folder, or drive backup from a .ns container.");

        var inputPath = string.IsNullOrWhiteSpace(initialInputPath)
            ? ReadPath("Path: ")
            : NormalizePath(initialInputPath);

        if (!string.IsNullOrWhiteSpace(initialInputPath))
        {
            Console.WriteLine(TerminalTheme.Muted($"Path    : {inputPath}"));
        }

        var outputPath = ReadOptionalPath("Output (leave empty for the original name): ", defaultValue: null);
        var force = !string.IsNullOrWhiteSpace(outputPath) && ConfirmOverwriteIfNeeded(outputPath);

        DecryptFile(inputPath, outputPath, force);
        Pause();
    }

    private void EncryptFile(string inputPath, string? outputPath, bool force, bool compress)
    {
        var cleanInputPath = NormalizePath(inputPath);
        var cleanOutputPath = ResolveEncryptOutputPath(cleanInputPath, outputPath);

        using var password = PasswordBundle.CreateForEncryption();
        using var progress = new ConsoleProgressBar();

        _protector.EncryptFile(cleanInputPath, cleanOutputPath, password.Password, force, compress, progress);
        Console.WriteLine(TerminalTheme.Success($"[done] Output: {cleanOutputPath}"));
    }

    private void DecryptFile(string inputPath, string? outputPath, bool force)
    {
        var cleanInputPath = NormalizePath(inputPath);
        var cleanOutputPath = string.IsNullOrWhiteSpace(outputPath) ? null : NormalizePath(outputPath);

        using var password = PasswordBundle.CreateForDecryption();
        using var progress = new ConsoleProgressBar();

        var finalPath = _protector.DecryptFile(cleanInputPath, cleanOutputPath, password.Password, force, progress);
        Console.WriteLine(TerminalTheme.Success($"[done] Restored: {finalPath}"));
    }

    private bool TryHandleQuickFileInput(string input)
    {
        var candidates = ParseInputPaths(input)
            .Where(path => File.Exists(path) || Directory.Exists(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (candidates.Length == 0)
        {
            return false;
        }

        if (candidates.Length > 1)
        {
            Console.WriteLine(TerminalTheme.Warning("[warning] Drop one path at a time."));
            Pause();
            return true;
        }

        var path = candidates[0];

        Console.WriteLine(TerminalTheme.Accent("[auto] Path detected from the home screen."));

        if (path.EndsWith(".ns", StringComparison.OrdinalIgnoreCase))
        {
            DecryptInteractive(path);
        }
        else
        {
            EncryptInteractive(path);
        }

        return true;
    }

    private static void DrawDashboard()
    {
        ClearScreen();

        var left = new[]
        {
            AccentLine("      _----------_,"),
            AccentLine("    ,\"__         _-:,"),
            AccentLine("   /    \"\"--_--\"\"...:\\"),
            AccentLine("  /         |.........\\"),
            AccentLine(" /          |..........\\"),
            AccentLine("/,         _'_........./:"),
            StrongLine("! -,    _-\"   \"-_... ,;;:"),
            AccentLine("\\   -_-\"         \"-_/;;;;"),
            AccentLine(" \\   \\             /;;;;'"),
            AccentLine("  \\   \\           /;;;;"),
            AccentLine("   '.  \\         /;;;'"),
            AccentLine("     \"-_\\_______/;;'")
        };

        var right = new[]
        {
            PlainLine(string.Empty),
            StrongLine("NS"),
            MutedLine("Local file encryption for Windows."),
            PlainLine(string.Empty),
            SuccessLine("[1] Encrypt"),
            AccentSoftLine("[2] Decrypt .ns"),
            MutedLine("[3] Exit")
        };

        RenderDashboard(left, right, gap: 7);
        Console.WriteLine();
        WriteCenteredLine("Choose an action, then press Enter", TerminalTheme.Muted);
    }

    private static void DrawActionScreen(string title, string subtitle)
    {
        ClearScreen();
        Console.WriteLine(TerminalTheme.Divider(76));
        Console.WriteLine(TerminalTheme.Strong($"NS // {title}"));
        Console.WriteLine(TerminalTheme.Muted(subtitle));
        Console.WriteLine(TerminalTheme.Divider(76));
        Console.WriteLine();
    }

    private static void PrintUsage()
    {
        Console.WriteLine(TerminalTheme.Strong("NS"));
        Console.WriteLine(TerminalTheme.Muted("Simple Windows file, folder, and drive encryption."));
        Console.WriteLine();
        Console.WriteLine(TerminalTheme.Accent("Usage"));
        Console.WriteLine("  NS encrypt <path> [output.ns] [--compress] [--force]");
        Console.WriteLine("  NS decrypt <file.ns> [output] [--force]");
        Console.WriteLine("  NS help");
        Console.WriteLine();
        Console.WriteLine(TerminalTheme.AccentSoft("Examples"));
        Console.WriteLine(@"  NS encrypt ""C:\Docs\contract.pdf""");
        Console.WriteLine(@"  NS encrypt ""C:\Docs\contract.pdf"" --compress");
        Console.WriteLine(@"  NS encrypt ""C:\Docs\Projects""");
        Console.WriteLine(@"  NS encrypt ""E:\\"" ""D:\Backups\drive-e.ns""");
        Console.WriteLine(@"  NS decrypt ""C:\Docs\contract.pdf.ns""");
        Console.WriteLine(@"  NS decrypt ""C:\Docs\contract.pdf.ns"" ""C:\Docs\contract.pdf"" --force");
        Console.WriteLine();
        Console.WriteLine("You can also drop a path directly onto the home screen or run NS.exe <path>.");
    }

    private static string ReadPath(string prompt)
    {
        while (true)
        {
            Console.Write(TerminalTheme.Prompt(prompt));
            var value = NormalizePath(Console.ReadLine());

            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }

            Console.WriteLine(TerminalTheme.Warning("[warning] Invalid path."));
        }
    }

    private static string? ReadOptionalPath(string prompt, string? defaultValue)
    {
        Console.Write(TerminalTheme.Prompt(prompt));
        var value = NormalizePath(Console.ReadLine());
        return string.IsNullOrWhiteSpace(value) ? defaultValue : value;
    }

    private static bool ConfirmOverwriteIfNeeded(string outputPath)
    {
        if (!File.Exists(outputPath) && !Directory.Exists(outputPath))
        {
            return false;
        }

        Console.Write(TerminalTheme.Warning("Output file already exists. Overwrite? (y/N): "));
        var answer = (Console.ReadLine() ?? string.Empty).Trim();
        return string.Equals(answer, "y", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(answer, "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ConfirmCompression()
    {
        Console.Write(TerminalTheme.Muted("Compression before encryption? (y/N): "));
        var answer = (Console.ReadLine() ?? string.Empty).Trim();
        return string.Equals(answer, "y", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(answer, "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string? value)
    {
        var trimmed = (value ?? string.Empty).Trim().Trim('"');

        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return string.Empty;
        }

        var root = Path.GetPathRoot(trimmed);

        while (trimmed.Length > (root?.Length ?? 0) &&
               (trimmed.EndsWith(Path.DirectorySeparatorChar) || trimmed.EndsWith(Path.AltDirectorySeparatorChar)))
        {
            trimmed = trimmed[..^1];
        }

        return trimmed;
    }

    private static string ResolveEncryptOutputPath(string inputPath, string? outputPath)
    {
        var cleanOutputPath = string.IsNullOrWhiteSpace(outputPath)
            ? $"{inputPath}.ns"
            : NormalizePath(outputPath);

        return cleanOutputPath.EndsWith(".ns", StringComparison.OrdinalIgnoreCase)
            ? cleanOutputPath
            : $"{cleanOutputPath}.ns";
    }

    private static string[] ParseInputPaths(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return [];
        }

        var paths = new List<string>();
        var current = new StringBuilder();
        var insideQuotes = false;

        foreach (var character in input)
        {
            if (character == '"')
            {
                insideQuotes = !insideQuotes;

                if (!insideQuotes && current.Length > 0)
                {
                    paths.Add(current.ToString());
                    current.Clear();
                }

                continue;
            }

            if (char.IsWhiteSpace(character) && !insideQuotes)
            {
                if (current.Length > 0)
                {
                    paths.Add(current.ToString());
                    current.Clear();
                }

                continue;
            }

            current.Append(character);
        }

        if (current.Length > 0)
        {
            paths.Add(current.ToString());
        }

        return paths
            .Select(NormalizePath)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .ToArray();
    }

    private static void Pause()
    {
        Console.WriteLine();
        Console.Write(TerminalTheme.Muted("Press Enter to continue..."));
        Console.ReadLine();
    }

    private static void PauseBeforeExit()
    {
        if (!Console.IsOutputRedirected && !Console.IsInputRedirected)
        {
            Pause();
        }
    }

    private static void ClearScreen()
    {
        if (!Console.IsOutputRedirected)
        {
            Console.Clear();
        }
    }

    private static void RenderDashboard(DashboardLine[] left, DashboardLine[] right, int gap)
    {
        var leftWidth = GetMaxWidth(left);
        var rightWidth = GetMaxWidth(right);
        var totalWidth = leftWidth + gap + rightWidth;
        var consoleWidth = GetConsoleWidth();

        if (consoleWidth < totalWidth + 6)
        {
            RenderBlockCentered(left);
            Console.WriteLine();
            RenderBlockCentered(right);
            return;
        }

        var margin = Math.Max(0, (consoleWidth - totalWidth) / 2);
        var rows = Math.Max(left.Length, right.Length);
        var leftPadTop = Math.Max(0, (rows - left.Length) / 2);
        var rightPadTop = Math.Max(0, (rows - right.Length) / 2);

        for (var row = 0; row < rows; row++)
        {
            var leftLine = GetLineAt(left, row - leftPadTop);
            var rightLine = GetLineAt(right, row - rightPadTop);

            WriteSpaces(margin);
            Console.Write(leftLine.Rendered);
            WriteSpaces(Math.Max(0, leftWidth - leftLine.Raw.Length + gap));
            Console.WriteLine(rightLine.Rendered);
        }
    }

    private static void RenderBlockCentered(DashboardLine[] lines)
    {
        var width = GetMaxWidth(lines);
        var margin = Math.Max(0, (GetConsoleWidth() - width) / 2);

        foreach (var line in lines)
        {
            WriteSpaces(margin);
            Console.WriteLine(line.Rendered);
        }
    }

    private static void WriteCenteredLine(string text, Func<string, string> style)
    {
        var margin = Math.Max(0, (GetConsoleWidth() - text.Length) / 2);
        WriteSpaces(margin);
        Console.WriteLine(style(text));
    }

    private static void WriteCenteredPrompt(string prompt)
    {
        var margin = Math.Max(0, (GetConsoleWidth() - prompt.Length) / 2);
        WriteSpaces(margin);
        Console.Write(TerminalTheme.Prompt(prompt));
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

    private static int GetMaxWidth(IEnumerable<DashboardLine> lines)
    {
        return lines.Any() ? lines.Max(line => line.Raw.Length) : 0;
    }

    private static DashboardLine GetLineAt(IReadOnlyList<DashboardLine> lines, int index)
    {
        return index >= 0 && index < lines.Count ? lines[index] : PlainLine(string.Empty);
    }

    private static void WriteSpaces(int count)
    {
        if (count > 0)
        {
            Console.Write(new string(' ', count));
        }
    }

    private static DashboardLine PlainLine(string text) => new(text, text);

    private static DashboardLine AccentLine(string text) => new(text, TerminalTheme.Accent(text));

    private static DashboardLine AccentSoftLine(string text) => new(text, TerminalTheme.AccentSoft(text));

    private static DashboardLine StrongLine(string text) => new(text, TerminalTheme.Strong(text));

    private static DashboardLine MutedLine(string text) => new(text, TerminalTheme.Muted(text));

    private static DashboardLine SuccessLine(string text) => new(text, TerminalTheme.Success(text));

    private static DashboardLine InfoLine(string text) => new(text, TerminalTheme.Strong(text));

    private static bool ShouldPauseOnExit(string[] args)
    {
        return args.Length > 0 &&
               args[0].EndsWith("-shell", StringComparison.OrdinalIgnoreCase);
    }

    private static void TryAutoInstallShellIntegration(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        WindowsShellIntegration.TryAutoInstall();
    }

    private bool TryRunImplicitPathCommand(string[] positional, bool force, bool compress)
    {
        if (positional.Length != 1)
        {
            return false;
        }

        var candidatePath = NormalizePath(positional[0]);

        if (!File.Exists(candidatePath) && !Directory.Exists(candidatePath))
        {
            return false;
        }

        if (candidatePath.EndsWith(".ns", StringComparison.OrdinalIgnoreCase))
        {
            DecryptFile(candidatePath, outputPath: null, force);
            return true;
        }

        EncryptFile(candidatePath, outputPath: null, force, compress);
        return true;
    }

    private readonly record struct DashboardLine(string Raw, string Rendered);
}

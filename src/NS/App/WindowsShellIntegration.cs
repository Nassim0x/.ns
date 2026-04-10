using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NS.App;

[SupportedOSPlatform("windows")]
internal static partial class WindowsShellIntegration
{
    private const uint SHCNE_ASSOCCHANGED = 0x08000000;
    private const uint SHCNF_IDLIST = 0x0000;
    private const string ClassesRootPath = @"Software\Classes";
    private const string Extension = ".ns";
    private const string ProgId = "NS.File";
    private const string FileTypeName = "NS Encrypted Container";
    private const string InstallFolderName = "NS";

    public static string Install()
    {
        EnsureWindows();

        var installedExecutablePath = InstallExecutable();
        using var classesRoot = Registry.CurrentUser.CreateSubKey(ClassesRootPath, writable: true)
            ?? throw new InvalidOperationException("Unable to open the current-user file association registry hive.");

        ConfigureExtension(classesRoot);
        ConfigureProgId(classesRoot, installedExecutablePath);
        ConfigureEncryptContextMenu(classesRoot, @"*\shell\NS.Encrypt", "Encrypt with NS", installedExecutablePath, "encrypt-shell");
        ConfigureEncryptContextMenu(classesRoot, @"Directory\shell\NS.Encrypt", "Encrypt with NS", installedExecutablePath, "encrypt-shell");
        ConfigureEncryptContextMenu(classesRoot, @"Drive\shell\NS.Encrypt", "Encrypt drive contents with NS", installedExecutablePath, "encrypt-shell");

        NotifyShellChanged();
        return installedExecutablePath;
    }

    public static void TryAutoInstall()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            var currentExecutablePath = TryResolveCurrentExecutablePath();

            if (string.IsNullOrWhiteSpace(currentExecutablePath))
            {
                return;
            }

            var installedExecutablePath = Path.Combine(GetInstallDirectory(), "NS.exe");

            if (!string.Equals(
                Path.GetFullPath(currentExecutablePath),
                Path.GetFullPath(installedExecutablePath),
                StringComparison.OrdinalIgnoreCase))
            {
                Install();
                return;
            }

            if (!IsRegistryConfiguredFor(installedExecutablePath))
            {
                Install();
            }
        }
        catch
        {
            // Automatic shell setup must never block the main app flow.
        }
    }

    private static void ConfigureExtension(RegistryKey classesRoot)
    {
        using var extensionKey = classesRoot.CreateSubKey(Extension, writable: true)
            ?? throw new InvalidOperationException("Unable to create the .ns extension registry key.");

        extensionKey.SetValue(null, ProgId, RegistryValueKind.String);
        extensionKey.SetValue("PerceivedType", "document", RegistryValueKind.String);

        using var openWithProgIds = extensionKey.CreateSubKey("OpenWithProgids", writable: true)
            ?? throw new InvalidOperationException("Unable to create the .ns OpenWithProgids registry key.");

        openWithProgIds.SetValue(ProgId, string.Empty, RegistryValueKind.String);
    }

    private static void ConfigureProgId(RegistryKey classesRoot, string installedExecutablePath)
    {
        using var progIdKey = classesRoot.CreateSubKey(ProgId, writable: true)
            ?? throw new InvalidOperationException("Unable to create the NS file type registry key.");

        progIdKey.SetValue(null, FileTypeName, RegistryValueKind.String);
        progIdKey.SetValue("FriendlyTypeName", FileTypeName, RegistryValueKind.String);

        using (var defaultIconKey = progIdKey.CreateSubKey("DefaultIcon", writable: true))
        {
            defaultIconKey?.SetValue(null, BuildIconLocation(installedExecutablePath), RegistryValueKind.String);
        }

        ConfigureShellVerb(progIdKey, "open", "Open with NS", installedExecutablePath, "open-shell");
        ConfigureShellVerb(progIdKey, "decrypt", "Decrypt with NS", installedExecutablePath, "decrypt-shell");
    }

    private static void ConfigureEncryptContextMenu(
        RegistryKey classesRoot,
        string relativeKeyPath,
        string label,
        string installedExecutablePath,
        string action)
    {
        using var verbKey = classesRoot.CreateSubKey(relativeKeyPath, writable: true)
            ?? throw new InvalidOperationException($"Unable to create the shell verb '{relativeKeyPath}'.");

        verbKey.SetValue(null, label, RegistryValueKind.String);
        verbKey.SetValue("Icon", installedExecutablePath, RegistryValueKind.String);

        using var commandKey = verbKey.CreateSubKey("command", writable: true)
            ?? throw new InvalidOperationException($"Unable to create the command for '{relativeKeyPath}'.");

        commandKey.SetValue(null, BuildCommand(installedExecutablePath, action), RegistryValueKind.String);
    }

    private static void ConfigureShellVerb(RegistryKey progIdKey, string verbName, string label, string installedExecutablePath, string action)
    {
        using var verbKey = progIdKey.CreateSubKey($@"shell\{verbName}", writable: true)
            ?? throw new InvalidOperationException($"Unable to create the NS file verb '{verbName}'.");

        verbKey.SetValue(null, label, RegistryValueKind.String);
        verbKey.SetValue("Icon", installedExecutablePath, RegistryValueKind.String);

        using var commandKey = verbKey.CreateSubKey("command", writable: true)
            ?? throw new InvalidOperationException($"Unable to create the command for the NS file verb '{verbName}'.");

        commandKey.SetValue(null, BuildCommand(installedExecutablePath, action), RegistryValueKind.String);
    }

    private static string InstallExecutable()
    {
        var currentExecutablePath = ResolveCurrentExecutablePath()
            ?? throw new InvalidOperationException("Run this from a published NS.exe binary, for example dist\\NS.exe.");
        var installDirectory = GetInstallDirectory();
        Directory.CreateDirectory(installDirectory);

        var installedExecutablePath = Path.Combine(installDirectory, "NS.exe");

        if (!string.Equals(
            Path.GetFullPath(currentExecutablePath),
            Path.GetFullPath(installedExecutablePath),
            StringComparison.OrdinalIgnoreCase))
        {
            File.Copy(currentExecutablePath, installedExecutablePath, overwrite: true);
        }

        return installedExecutablePath;
    }

    private static string? ResolveCurrentExecutablePath()
    {
        return TryResolveCurrentExecutablePath();
    }

    private static string? TryResolveCurrentExecutablePath()
    {
        var executablePath = Environment.ProcessPath;

        if (string.IsNullOrWhiteSpace(executablePath) ||
            !File.Exists(executablePath) ||
            !executablePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Path.GetFileName(executablePath), "dotnet.exe", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return Path.GetFullPath(executablePath);
    }

    private static string GetInstallDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs",
            InstallFolderName);
    }

    private static string BuildCommand(string executablePath, string action)
    {
        return $"\"{executablePath}\" {action} \"%1\"";
    }

    private static string BuildIconLocation(string executablePath)
    {
        return $"\"{executablePath}\",0";
    }

    private static bool IsRegistryConfiguredFor(string executablePath)
    {
        using var classesRoot = Registry.CurrentUser.OpenSubKey(ClassesRootPath, writable: false);

        if (classesRoot is null)
        {
            return false;
        }

        var expectedIcon = BuildIconLocation(executablePath);
        var expectedOpenCommand = BuildCommand(executablePath, "open-shell");
        var expectedDecryptCommand = BuildCommand(executablePath, "decrypt-shell");
        var expectedEncryptCommand = BuildCommand(executablePath, "encrypt-shell");

        return string.Equals(ReadDefaultValue(classesRoot, Extension), ProgId, StringComparison.Ordinal) &&
               string.Equals(ReadDefaultValue(classesRoot, $@"{ProgId}\DefaultIcon"), expectedIcon, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(ReadDefaultValue(classesRoot, $@"{ProgId}\shell\open\command"), expectedOpenCommand, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(ReadDefaultValue(classesRoot, $@"{ProgId}\shell\decrypt\command"), expectedDecryptCommand, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(ReadDefaultValue(classesRoot, @"*\shell\NS.Encrypt\command"), expectedEncryptCommand, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(ReadDefaultValue(classesRoot, @"Directory\shell\NS.Encrypt\command"), expectedEncryptCommand, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(ReadDefaultValue(classesRoot, @"Drive\shell\NS.Encrypt\command"), expectedEncryptCommand, StringComparison.OrdinalIgnoreCase);
    }

    private static string? ReadDefaultValue(RegistryKey root, string relativePath)
    {
        using var subKey = root.OpenSubKey(relativePath, writable: false);
        return subKey?.GetValue(null) as string;
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows shell integration is only available on Windows.");
        }
    }

    private static void NotifyShellChanged()
    {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
    }

    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(uint wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
}

using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NS.Setup;

[SupportedOSPlatform("windows")]
internal sealed class InstallerService
{
    private const string AppName = "NS";
    private const string InstallerName = "NS-Installer.exe";
    private const string MainExecutableName = "NS.exe";
    private const string UninstallKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\NS";
    private const string ShellClassesRootPath = @"Software\Classes";

    public void Install(InstallerOptions options)
    {
        var sourceDirectory = AppContext.BaseDirectory;
        var sourceMainExecutablePath = Path.Combine(sourceDirectory, MainExecutableName);
        var sourceInstallerPath = Environment.ProcessPath ?? Path.Combine(sourceDirectory, InstallerName);

        if (!File.Exists(sourceMainExecutablePath))
        {
            throw new FileNotFoundException("NS.exe must be next to NS-Installer.exe.", sourceMainExecutablePath);
        }

        var installDirectory = GetInstallDirectory();
        Directory.CreateDirectory(installDirectory);

        var installedMainExecutablePath = Path.Combine(installDirectory, MainExecutableName);
        var installedInstallerPath = Path.Combine(installDirectory, InstallerName);

        File.Copy(sourceMainExecutablePath, installedMainExecutablePath, overwrite: true);

        if (File.Exists(sourceInstallerPath))
        {
            File.Copy(sourceInstallerPath, installedInstallerPath, overwrite: true);
        }

        CreateStartMenuShortcuts(installedMainExecutablePath, installedInstallerPath);

        if (options.CreateDesktopShortcut)
        {
            CreateDesktopShortcut(installedMainExecutablePath);
        }
        else
        {
            RemoveDesktopShortcut();
        }

        WriteUninstallRegistry(installedMainExecutablePath, installedInstallerPath);
        RepairShellIntegration(installedMainExecutablePath);

        if (options.LaunchAfterInstall)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = installedMainExecutablePath,
                WorkingDirectory = Path.GetDirectoryName(installedMainExecutablePath) ?? installDirectory,
                UseShellExecute = true
            });
        }
    }

    public void Uninstall()
    {
        var installDirectory = GetInstallDirectory();
        RemoveStartMenuShortcuts();
        RemoveDesktopShortcut();
        RemoveUninstallRegistry();
        RemoveShellIntegration();
        ScheduleDirectoryRemoval(installDirectory);
    }

    public string GetInstallDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs",
            AppName);
    }

    public bool IsInstalled()
    {
        return File.Exists(Path.Combine(GetInstallDirectory(), MainExecutableName));
    }

    public string GetInstalledMainExecutablePath()
    {
        return Path.Combine(GetInstallDirectory(), MainExecutableName);
    }

    public string GetInstalledInstallerPath()
    {
        return Path.Combine(GetInstallDirectory(), InstallerName);
    }

    public bool DesktopShortcutExists()
    {
        return File.Exists(GetDesktopShortcutPath());
    }

    private string GetStartMenuDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Programs),
            AppName);
    }

    private string GetDesktopShortcutPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            "NS.lnk");
    }

    private void CreateStartMenuShortcuts(string installedMainExecutablePath, string installedInstallerPath)
    {
        var startMenuDirectory = GetStartMenuDirectory();
        Directory.CreateDirectory(startMenuDirectory);

        CreateShortcut(
            Path.Combine(startMenuDirectory, "NS.lnk"),
            installedMainExecutablePath,
            arguments: string.Empty,
            "Open NS",
            installedMainExecutablePath);

        CreateShortcut(
            Path.Combine(startMenuDirectory, "Uninstall NS.lnk"),
            installedInstallerPath,
            "--uninstall",
            "Remove NS",
            installedMainExecutablePath);
    }

    private void CreateDesktopShortcut(string installedMainExecutablePath)
    {
        CreateShortcut(
            GetDesktopShortcutPath(),
            installedMainExecutablePath,
            arguments: string.Empty,
            "Open NS",
            installedMainExecutablePath);
    }

    private void RemoveStartMenuShortcuts()
    {
        var startMenuDirectory = GetStartMenuDirectory();

        try
        {
            if (Directory.Exists(startMenuDirectory))
            {
                Directory.Delete(startMenuDirectory, recursive: true);
            }
        }
        catch
        {
        }
    }

    private void RemoveDesktopShortcut()
    {
        try
        {
            var desktopShortcutPath = GetDesktopShortcutPath();

            if (File.Exists(desktopShortcutPath))
            {
                File.Delete(desktopShortcutPath);
            }
        }
        catch
        {
        }
    }

    private static void CreateShortcut(string shortcutPath, string targetPath, string arguments, string description, string iconPath)
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell")
            ?? throw new InvalidOperationException("Unable to create Windows shortcuts on this system.");
        var shell = Activator.CreateInstance(shellType)
            ?? throw new InvalidOperationException("Unable to start the Windows shortcut service.");

        try
        {
            object shortcutObject = shellType.InvokeMember(
                "CreateShortcut",
                System.Reflection.BindingFlags.InvokeMethod,
                binder: null,
                target: shell,
                args: [shortcutPath]) ?? throw new InvalidOperationException("Unable to create the shortcut.");
            dynamic shortcut = shortcutObject;

            try
            {
                shortcut.TargetPath = targetPath;
                shortcut.Arguments = arguments;
                shortcut.WorkingDirectory = Path.GetDirectoryName(targetPath) ?? AppContext.BaseDirectory;
                shortcut.Description = description;
                shortcut.IconLocation = $"{iconPath},0";
                shortcut.Save();
            }
            finally
            {
                Marshal.FinalReleaseComObject(shortcutObject);
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(shell);
        }
    }

    private void WriteUninstallRegistry(string installedMainExecutablePath, string installedInstallerPath)
    {
        using var uninstallKey = Registry.CurrentUser.CreateSubKey(UninstallKeyPath, writable: true)
            ?? throw new InvalidOperationException("Unable to create the uninstall registry entry.");

        var version = FileVersionInfo.GetVersionInfo(installedMainExecutablePath).ProductVersion ?? "1.0.0";

        uninstallKey.SetValue("DisplayName", "NS", RegistryValueKind.String);
        uninstallKey.SetValue("DisplayVersion", version, RegistryValueKind.String);
        uninstallKey.SetValue("Publisher", "NS", RegistryValueKind.String);
        uninstallKey.SetValue("InstallLocation", GetInstallDirectory(), RegistryValueKind.String);
        uninstallKey.SetValue("DisplayIcon", installedMainExecutablePath, RegistryValueKind.String);
        uninstallKey.SetValue("UninstallString", $"\"{installedInstallerPath}\" --uninstall", RegistryValueKind.String);
        uninstallKey.SetValue("QuietUninstallString", $"\"{installedInstallerPath}\" --uninstall --silent", RegistryValueKind.String);
        uninstallKey.SetValue("NoModify", 1, RegistryValueKind.DWord);
        uninstallKey.SetValue("NoRepair", 1, RegistryValueKind.DWord);
    }

    private static void RemoveUninstallRegistry()
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(UninstallKeyPath, throwOnMissingSubKey: false);
        }
        catch
        {
        }
    }

    private static void RepairShellIntegration(string installedMainExecutablePath)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = installedMainExecutablePath,
            Arguments = "help",
            WorkingDirectory = Path.GetDirectoryName(installedMainExecutablePath) ?? AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        });

        process?.WaitForExit();
    }

    private static void RemoveShellIntegration()
    {
        try
        {
            using var classesRoot = Registry.CurrentUser.CreateSubKey(ShellClassesRootPath, writable: true);

            if (classesRoot is null)
            {
                return;
            }

            DeleteSubKeyTreeIfPresent(classesRoot, ".ns");
            DeleteSubKeyTreeIfPresent(classesRoot, "NS.File");
            DeleteSubKeyTreeIfPresent(classesRoot, @"*\shell\NS.Encrypt");
            DeleteSubKeyTreeIfPresent(classesRoot, @"Directory\shell\NS.Encrypt");
            DeleteSubKeyTreeIfPresent(classesRoot, @"Drive\shell\NS.Encrypt");
        }
        catch
        {
        }

        NotifyShellChanged();
    }

    private static void DeleteSubKeyTreeIfPresent(RegistryKey parentKey, string subKeyName)
    {
        try
        {
            parentKey.DeleteSubKeyTree(subKeyName, throwOnMissingSubKey: false);
        }
        catch
        {
        }
    }

    private static void ScheduleDirectoryRemoval(string installDirectory)
    {
        if (!Directory.Exists(installDirectory))
        {
            return;
        }

        var commandScriptPath = Path.Combine(Path.GetTempPath(), $"ns-uninstall-{Guid.NewGuid():N}.cmd");
        var escapedInstallDirectory = installDirectory.Replace("\"", "\"\"");

        var commandLines = string.Join(
            Environment.NewLine,
            [
                "@echo off",
                "ping 127.0.0.1 -n 3 > nul",
                $"rmdir /s /q \"{escapedInstallDirectory}\"",
                $"del /f /q \"%~f0\""
            ]);

        File.WriteAllText(commandScriptPath, commandLines);

        Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c \"{commandScriptPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        });
    }

    private static void NotifyShellChanged()
    {
        SHChangeNotify(0x08000000, 0x0000, IntPtr.Zero, IntPtr.Zero);
    }

    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(uint wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
}

using System.Runtime.Versioning;

namespace NS.Setup;

[SupportedOSPlatform("windows")]
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            MessageBox.Show("This installer is only available on Windows.", "NS", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }

        var service = new InstallerService();
        var silent = args.Any(arg => string.Equals(arg, "--silent", StringComparison.OrdinalIgnoreCase));
        var uninstall = args.Any(arg => string.Equals(arg, "--uninstall", StringComparison.OrdinalIgnoreCase));
        var launch = args.Any(arg => string.Equals(arg, "--launch", StringComparison.OrdinalIgnoreCase));
        var desktopShortcut = args.Any(arg => string.Equals(arg, "--desktop-shortcut", StringComparison.OrdinalIgnoreCase));

        try
        {
            if (silent)
            {
                if (uninstall)
                {
                    service.Uninstall();
                }
                else
                {
                    service.Install(new InstallerOptions
                    {
                        LaunchAfterInstall = launch,
                        CreateDesktopShortcut = desktopShortcut
                    });
                }

                return 0;
            }

            ApplicationConfiguration.Initialize();
            using var form = new InstallerForm(service, uninstallMode: uninstall);
            return form.ShowDialog() == DialogResult.OK ? 0 : 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "NS", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}

using System.Drawing.Drawing2D;

namespace NS.Setup;

internal sealed class InstallerForm : Form
{
    private readonly InstallerService _service;
    private readonly bool _uninstallMode;
    private readonly CheckBox _launchCheckBox;
    private readonly CheckBox _desktopShortcutCheckBox;
    private readonly Label _statusLabel;
    private readonly Button _primaryButton;
    private readonly Button _secondaryButton;

    public InstallerForm(InstallerService service, bool uninstallMode)
    {
        _service = service;
        _uninstallMode = uninstallMode;

        Text = uninstallMode ? "NS Uninstaller" : "NS Installer";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(560, uninstallMode ? 300 : 360);
        BackColor = Color.FromArgb(15, 18, 26);
        ForeColor = Color.FromArgb(234, 240, 255);
        Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point);

        try
        {
            Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? Application.ExecutablePath);
        }
        catch
        {
        }

        var headerPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 110
        };
        headerPanel.Paint += PaintHeader;
        Controls.Add(headerPanel);

        var titleLabel = new Label
        {
            AutoSize = false,
            Location = new Point(132, 20),
            Size = new Size(390, 30),
            Text = uninstallMode ? "Remove NS from this PC" : "Install NS for this user",
            Font = new Font("Segoe UI Semibold", 18F, FontStyle.Bold, GraphicsUnit.Point),
            ForeColor = Color.White,
            BackColor = Color.Transparent
        };
        headerPanel.Controls.Add(titleLabel);

        var subtitleLabel = new Label
        {
            AutoSize = false,
            Location = new Point(134, 56),
            Size = new Size(380, 40),
            Text = uninstallMode
                ? "Remove the installed app, Start Menu entries, shell integration, and uninstall record."
                : "Set up NS with shell integration, Start Menu shortcuts, and an optional desktop shortcut.",
            Font = new Font("Segoe UI", 9.5F, FontStyle.Regular, GraphicsUnit.Point),
            ForeColor = Color.FromArgb(208, 220, 255),
            BackColor = Color.Transparent
        };
        headerPanel.Controls.Add(subtitleLabel);

        var logoPanel = new Panel
        {
            Location = new Point(24, 20),
            Size = new Size(84, 84),
            BackColor = Color.Transparent
        };
        logoPanel.Paint += PaintLogo;
        headerPanel.Controls.Add(logoPanel);

        var infoPanel = new Panel
        {
            Location = new Point(24, 126),
            Size = new Size(512, uninstallMode ? 82 : 134),
            BackColor = Color.FromArgb(22, 28, 38)
        };
        Controls.Add(infoPanel);

        var installLocationTitle = new Label
        {
            AutoSize = false,
            Location = new Point(18, 16),
            Size = new Size(140, 20),
            Text = uninstallMode ? "Installed location" : "Install location",
            Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold, GraphicsUnit.Point),
            ForeColor = Color.FromArgb(153, 172, 214)
        };
        infoPanel.Controls.Add(installLocationTitle);

        var installLocationValue = new Label
        {
            AutoSize = false,
            Location = new Point(18, 40),
            Size = new Size(476, uninstallMode ? 34 : 26),
            Text = _service.GetInstallDirectory(),
            Font = new Font("Consolas", 9.5F, FontStyle.Regular, GraphicsUnit.Point),
            ForeColor = Color.FromArgb(232, 243, 255)
        };
        infoPanel.Controls.Add(installLocationValue);

        _launchCheckBox = new CheckBox
        {
            AutoSize = true,
            Location = new Point(24, 276),
            Text = "Launch NS after install",
            Checked = true,
            ForeColor = Color.FromArgb(236, 242, 255),
            BackColor = Color.Transparent,
            Visible = !uninstallMode
        };
        Controls.Add(_launchCheckBox);

        _desktopShortcutCheckBox = new CheckBox
        {
            AutoSize = true,
            Location = new Point(24, 306),
            Text = "Create desktop shortcut",
            Checked = _service.DesktopShortcutExists() || !_service.IsInstalled(),
            ForeColor = Color.FromArgb(236, 242, 255),
            BackColor = Color.Transparent,
            Visible = !uninstallMode
        };
        Controls.Add(_desktopShortcutCheckBox);

        _statusLabel = new Label
        {
            AutoSize = false,
            Location = new Point(24, uninstallMode ? 228 : 220),
            Size = new Size(512, 30),
            Text = uninstallMode
                ? "This removes the local per-user NS installation."
                : "The installer will also refresh the .ns shell integration automatically.",
            ForeColor = Color.FromArgb(160, 179, 214),
            BackColor = Color.Transparent
        };
        Controls.Add(_statusLabel);

        _secondaryButton = new Button
        {
            Text = "Cancel",
            Size = new Size(112, 38),
            Location = new Point(306, uninstallMode ? 248 : 304),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(34, 42, 58),
            ForeColor = Color.FromArgb(228, 236, 255)
        };
        _secondaryButton.FlatAppearance.BorderColor = Color.FromArgb(70, 86, 117);
        _secondaryButton.Click += (_, _) => Close();
        Controls.Add(_secondaryButton);

        _primaryButton = new Button
        {
            Text = uninstallMode ? "Uninstall" : "Install",
            Size = new Size(112, 38),
            Location = new Point(424, uninstallMode ? 248 : 304),
            FlatStyle = FlatStyle.Flat,
            BackColor = uninstallMode ? Color.FromArgb(120, 48, 48) : Color.FromArgb(54, 157, 255),
            ForeColor = Color.White
        };
        _primaryButton.FlatAppearance.BorderColor = uninstallMode ? Color.FromArgb(160, 68, 68) : Color.FromArgb(78, 188, 255);
        _primaryButton.Click += async (_, _) => await RunPrimaryActionAsync();
        Controls.Add(_primaryButton);
    }

    private async Task RunPrimaryActionAsync()
    {
        SetBusy(true, _uninstallMode ? "Removing NS..." : "Installing NS...");

        try
        {
            if (_uninstallMode)
            {
                await Task.Run(() => _service.Uninstall());
                MessageBox.Show(this, "NS has been removed.", "NS", MessageBoxButtons.OK, MessageBoxIcon.Information);
                DialogResult = DialogResult.OK;
                Close();
                return;
            }

            var options = new InstallerOptions
            {
                LaunchAfterInstall = _launchCheckBox.Checked,
                CreateDesktopShortcut = _desktopShortcutCheckBox.Checked
            };

            await Task.Run(() => _service.Install(options));
            MessageBox.Show(this, "NS is installed and ready to use.", "NS", MessageBoxButtons.OK, MessageBoxIcon.Information);
            DialogResult = DialogResult.OK;
            Close();
        }
        catch (Exception ex)
        {
            SetBusy(false, ex.Message);
            MessageBox.Show(this, ex.Message, "NS", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void SetBusy(bool busy, string status)
    {
        _primaryButton.Enabled = !busy;
        _secondaryButton.Enabled = !busy;
        _launchCheckBox.Enabled = !busy;
        _desktopShortcutCheckBox.Enabled = !busy;
        _statusLabel.Text = status;
    }

    private static void PaintHeader(object? sender, PaintEventArgs eventArgs)
    {
        if (sender is not Panel panel)
        {
            return;
        }

        using var brush = new LinearGradientBrush(
            panel.ClientRectangle,
            Color.FromArgb(31, 43, 64),
            Color.FromArgb(15, 18, 26),
            LinearGradientMode.ForwardDiagonal);

        eventArgs.Graphics.FillRectangle(brush, panel.ClientRectangle);
    }

    private static void PaintLogo(object? sender, PaintEventArgs eventArgs)
    {
        if (sender is not Panel panel)
        {
            return;
        }

        eventArgs.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        var rect = new Rectangle(6, 6, panel.Width - 12, panel.Height - 12);

        using var backgroundBrush = new SolidBrush(Color.FromArgb(24, 30, 42));
        using var borderPen = new Pen(Color.FromArgb(104, 229, 255), 2f);
        using var accentPen = new Pen(Color.FromArgb(194, 242, 255), 1.2f);
        using var textBrush = new SolidBrush(Color.White);
        using var font = new Font("Segoe UI Semibold", 21F, FontStyle.Bold, GraphicsUnit.Point);
        using var format = new StringFormat
        {
            Alignment = StringAlignment.Center,
            LineAlignment = StringAlignment.Center
        };

        eventArgs.Graphics.FillRectangle(backgroundBrush, rect);
        eventArgs.Graphics.DrawRectangle(borderPen, rect);
        eventArgs.Graphics.DrawLine(accentPen, rect.Left + 10, rect.Top + 15, rect.Right - 10, rect.Top + 15);
        eventArgs.Graphics.DrawLine(accentPen, rect.Left + 10, rect.Bottom - 15, rect.Right - 10, rect.Bottom - 15);
        eventArgs.Graphics.DrawString("NS", font, textBrush, rect, format);
    }
}

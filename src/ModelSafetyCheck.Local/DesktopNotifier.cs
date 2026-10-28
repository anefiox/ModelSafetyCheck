using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Local;

/// <summary>
/// Best-effort desktop notification for scheduled `watch` runs (W-05). The text includes model names,
/// which come from file names and are therefore untrusted, so it is passed through environment
/// variables and never spliced into a script.
/// </summary>
public static class DesktopNotifier
{
    // PowerShell's own AppUserModelID; toasts from an unregistered app id are silently dropped.
    const string WindowsAppId = @"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

    const string WindowsScript = """
        $ErrorActionPreference = 'Stop'
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $text = $xml.GetElementsByTagName('text')
        [void]$text.Item(0).AppendChild($xml.CreateTextNode($env:MODELCHECK_TITLE))
        [void]$text.Item(1).AppendChild($xml.CreateTextNode($env:MODELCHECK_MESSAGE))
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:MODELCHECK_APPID).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
        """;

    /// <summary>Returns the command that would show the notification (for tests and --print-schedule).</summary>
    public static (string File, string[] Arguments, Dictionary<string, string> Environment) Command(string title, string message)
    {
        var env = new Dictionary<string, string> { ["MODELCHECK_TITLE"] = Clip(title, 64), ["MODELCHECK_MESSAGE"] = Clip(message, 200) };
        if (OperatingSystem.IsWindows())
        {
            env["MODELCHECK_APPID"] = WindowsAppId;
            return ("powershell", ["-NoProfile", "-NonInteractive", "-Command", WindowsScript], env);
        }
        if (OperatingSystem.IsMacOS())
            return ("osascript", ["-e", "display notification (system attribute \"MODELCHECK_MESSAGE\") with title (system attribute \"MODELCHECK_TITLE\")"], env);
        return ("notify-send", ["--app-name=modelcheck", "--urgency=critical", "--", env["MODELCHECK_TITLE"], env["MODELCHECK_MESSAGE"]], env);
    }

    /// <summary>Shows the notification. Returns false if the platform tool is missing or failed.</summary>
    public static bool Notify(string title, string message)
    {
        var (file, arguments, environment) = Command(title, message);
        return ProcessRunner.Run(file, arguments, TimeSpan.FromSeconds(15), environment) is { ExitCode: 0 };
    }

    static string Clip(string text, int max)
    {
        var flat = new string(text.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
        return flat.Length <= max ? flat : flat[..(max - 1)] + "…";
    }
}

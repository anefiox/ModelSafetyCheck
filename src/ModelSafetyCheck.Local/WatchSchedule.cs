using System.Security;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Local;

public sealed record ScheduleFile(string Path, string Content);

/// <summary>A planned schedule: files to write and commands to run. `--print-schedule` shows it; `--install-schedule` applies it.</summary>
public sealed record SchedulePlan(string Description, IReadOnlyList<ScheduleFile> Files, IReadOnlyList<string[]> Commands);

/// <summary>Runs `modelcheck watch` hourly with the platform's own scheduler (Task Scheduler, systemd user timer, launchd).</summary>
public static class WatchSchedule
{
    public const string TaskName = "modelcheck-watch";

    public static string LogPath => Path.Combine(Path.GetDirectoryName(TemplateWatch.DefaultStorePath)!, "watch.log");

    /// <summary>The command that re-runs this program. Under `dotnet modelcheck.dll` that is dotnet plus the dll.</summary>
    public static string[] SelfCommand()
    {
        var process = Environment.ProcessPath ?? "modelcheck";
        return Path.GetFileNameWithoutExtension(process).Equals("dotnet", StringComparison.OrdinalIgnoreCase)
            ? [process, Path.Combine(AppContext.BaseDirectory, "modelcheck.dll")]
            : [process];
    }

    public static SchedulePlan Plan()
    {
        var command = SelfCommand().Concat(["watch", "--no-color", "--notify", "--log", LogPath]).ToArray();
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (OperatingSystem.IsWindows())
        {
            var taskRun = string.Join(' ', command.Select(a => a.Contains(' ') ? $"\"{a}\"" : a));
            return new SchedulePlan("Windows Task Scheduler task, hourly, as the current user", [],
                [["schtasks", "/Create", "/F", "/SC", "HOURLY", "/TN", TaskName, "/TR", taskRun]]);
        }

        if (OperatingSystem.IsMacOS())
        {
            var plist = Path.Combine(home, "Library", "LaunchAgents", "com.modelcheck.watch.plist");
            var args = string.Concat(command.Select(a => $"\n    <string>{SecurityElement.Escape(a)}</string>"));
            var content = $"""
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0">
                <dict>
                  <key>Label</key><string>com.modelcheck.watch</string>
                  <key>ProgramArguments</key>
                  <array>{args}
                  </array>
                  <key>StartInterval</key><integer>3600</integer>
                  <key>RunAtLoad</key><true/>
                </dict>
                </plist>
                """;
            return new SchedulePlan("launchd user agent, hourly", [new ScheduleFile(plist, content)], [["launchctl", "load", "-w", plist]]);
        }

        var unitDir = Path.Combine(home, ".config", "systemd", "user");
        var exec = string.Join(' ', command.Select(a => a.Contains(' ') ? $"\"{a}\"" : a));
        return new SchedulePlan("systemd user timer, hourly",
        [
            new ScheduleFile(Path.Combine(unitDir, $"{TaskName}.service"), $"[Unit]\nDescription=modelcheck template drift check\n\n[Service]\nType=oneshot\nExecStart={exec}\n"),
            new ScheduleFile(Path.Combine(unitDir, $"{TaskName}.timer"), $"[Unit]\nDescription=Run modelcheck watch hourly\n\n[Timer]\nOnCalendar=hourly\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"),
        ],
        [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", $"{TaskName}.timer"]]);
    }

    public static string Describe(SchedulePlan plan) =>
        $"{plan.Description}\n" +
        string.Concat(plan.Files.Select(f => $"\nwrite {f.Path}:\n{f.Content}\n")) +
        string.Concat(plan.Commands.Select(c => $"\nrun: {string.Join(' ', c.Select(a => a.Contains(' ') ? $"\"{a}\"" : a))}")) +
        $"\n\nOutput is appended to {LogPath}.";

    /// <summary>Writes the files and runs the commands. Returns an error message, or null on success.</summary>
    public static string? Install(SchedulePlan plan)
    {
        foreach (var file in plan.Files)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file.Path)!);
            File.WriteAllText(file.Path, file.Content);
        }
        foreach (var command in plan.Commands)
        {
            var result = ProcessRunner.Run(command[0], command[1..], TimeSpan.FromSeconds(30));
            if (result is null || result.ExitCode != 0)
                return $"'{string.Join(' ', command)}' failed: {result?.Error.Trim() ?? "could not start"}";
        }
        return null;
    }
}

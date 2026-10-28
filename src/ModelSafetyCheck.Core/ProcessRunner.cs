using System.Diagnostics;

namespace ModelSafetyCheck.Core;

public sealed record ProcessResult(int ExitCode, string Output, string Error);

/// <summary>Runs a command with a timeout. Returns null when the program is missing or does not finish in time.</summary>
public static class ProcessRunner
{
    /// <param name="environment">Extra environment variables. Use these to pass untrusted text (e.g. model names) to scripts instead of splicing it into code.</param>
    public static ProcessResult? Run(string fileName, IEnumerable<string> arguments, TimeSpan? timeout = null, IReadOnlyDictionary<string, string>? environment = null)
    {
        var info = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
            info.ArgumentList.Add(argument);
        foreach (var (key, value) in environment ?? new Dictionary<string, string>())
            info.Environment[key] = value;

        try
        {
            using var process = Process.Start(info);
            if (process is null)
                return null;
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(timeout ?? TimeSpan.FromSeconds(10)))
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                return null;
            }
            return new ProcessResult(process.ExitCode, output.GetAwaiter().GetResult(), error.GetAwaiter().GetResult());
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null; // Not installed / not on PATH.
        }
    }
}

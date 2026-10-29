using System.Text.Json;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Audit;

/// <summary>
/// A-08 (A009): Ollama for Windows did not verify downloaded updates before installing them (CVE-2026-42248), and
/// installs staged updates silently. This checks the Authenticode signature of every installer staged under
/// %LOCALAPPDATA%\Ollama itself, so a tampered update is caught before the next restart runs it.
/// </summary>
public static class OllamaUpdates
{
    const string ExpectedSigner = "Ollama";

    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Ollama");

    public sealed record Signature(string Path, string Status, string? Signer);

    public static IEnumerable<Finding> Check(string? directory = null)
    {
        if (!OperatingSystem.IsWindows())
            yield break;
        directory ??= DefaultDirectory;
        if (!Directory.Exists(directory))
            yield break;

        var installers = Directory.EnumerateFiles(directory, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
            .Where(f => Path.GetExtension(f).ToLowerInvariant() is ".exe" or ".msi")
            .Where(f => f.Contains("update", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(f).Contains("setup", StringComparison.OrdinalIgnoreCase))
            .Take(20)
            .ToList();
        if (installers.Count == 0)
            yield break;

        var signatures = Verify(installers);
        if (signatures is null)
        {
            yield return new Finding("A009", Severity.Low, "Staged Ollama update could not be verified",
                $"Found {installers.Count} staged installer(s) in {directory}, but PowerShell's Get-AuthenticodeSignature was not available.", directory);
            yield break;
        }

        foreach (var s in signatures)
        {
            if (s.Status != "Valid")
                yield return new Finding("A009", Severity.Critical, "Staged Ollama update is not validly signed",
                    $"{s.Path}: signature status {s.Status}. Ollama for Windows installs staged updates without checking (CVE-2026-42248), so this file would run on the next restart.\n" +
                    "Fix: quit Ollama, delete the file, and reinstall from ollama.com. Turn off \"Auto-download updates\" in Ollama's settings.", s.Path);
            else if (s.Signer is null || !s.Signer.Contains(ExpectedSigner, StringComparison.OrdinalIgnoreCase))
                yield return new Finding("A009", Severity.High, "Staged Ollama update is signed by someone else",
                    $"{s.Path} is validly signed, but by \"{s.Signer}\", not Ollama.\nFix: quit Ollama, delete the file, and reinstall from ollama.com.", s.Path);
            else
                yield return new Finding("A009", Severity.Info, "Staged Ollama update is signed by Ollama", $"{s.Path} ({s.Signer}).", s.Path);
        }
    }

    /// <summary>Authenticode status and signer for each file. Paths go through an environment variable, never into the script text.</summary>
    public static List<Signature>? Verify(IReadOnlyList<string> paths)
    {
        // Works in Windows PowerShell 5.1 (no -AsArray): -InputObject @(...) keeps a one-item result as an array.
        const string script = "$ErrorActionPreference='Stop'; " +
            "$r = @($env:MODELCHECK_PATHS -split [char]10 | Where-Object { $_ } | ForEach-Object { " +
            "$s = Get-AuthenticodeSignature -LiteralPath $_; " +
            "[pscustomobject]@{ Path = $_; Status = [string]$s.Status; Signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null } } " +
            "}); ConvertTo-Json -Compress -InputObject $r";
        var environment = new Dictionary<string, string> { ["MODELCHECK_PATHS"] = string.Join('\n', paths) };
        // A .NET child inherits PowerShell 7's PSModulePath verbatim. Windows PowerShell can then try to
        // import incompatible PS7 modules instead of its own Authenticode and JSON commands.
        if (OperatingSystem.IsWindows())
            environment["PSModulePath"] = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "Modules");
        var result = ProcessRunner.Run("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], TimeSpan.FromSeconds(60), environment);
        if (result is not { ExitCode: 0 } || result.Output.Trim().Length == 0)
            return null;
        try
        {
            using var doc = JsonDocument.Parse(result.Output);
            return doc.RootElement.EnumerateArray()
                .Select(e => new Signature(e.GetProperty("Path").GetString() ?? "", e.GetProperty("Status").GetString() ?? "Unknown",
                    e.GetProperty("Signer").ValueKind == JsonValueKind.String ? e.GetProperty("Signer").GetString() : null))
                .ToList();
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return null;
        }
    }
}

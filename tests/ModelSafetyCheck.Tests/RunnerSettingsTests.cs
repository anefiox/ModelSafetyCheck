using ModelSafetyCheck.Audit;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Tests;

public class RunnerSettingsTests
{
    [Fact]
    public void Lm_studio_bind_to_all_interfaces_is_A002()
    {
        var previous = Environment.GetEnvironmentVariable("LMS_SERVER_HOST");
        try
        {
            Environment.SetEnvironmentVariable("LMS_SERVER_HOST", "0.0.0.0");
            Assert.Contains(NetworkExposure.CheckOllamaConfig(), f => f.RuleId == "A002" && f.Title.Contains("LM Studio"));
            Environment.SetEnvironmentVariable("LMS_SERVER_HOST", "127.0.0.1");
            Assert.DoesNotContain(NetworkExposure.CheckOllamaConfig(), f => f.Title.Contains("LM Studio") && f.Source() == "this shell's environment");
        }
        finally
        {
            Environment.SetEnvironmentVariable("LMS_SERVER_HOST", previous);
        }
    }

    [Fact]
    public void Staged_ollama_updates_are_signature_checked()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var root = Directory.CreateTempSubdirectory("modelcheck-ollama-").FullName;
        try
        {
            var updates = Directory.CreateDirectory(Path.Combine(root, "updates", "v0.99.0")).FullName;
            // A tampered installer (a signed binary with one byte changed) and a validly signed binary from another publisher.
            var notepad = File.ReadAllBytes(Path.Combine(Environment.SystemDirectory, "notepad.exe"));
            var tampered = (byte[])notepad.Clone();
            tampered[tampered.Length / 2] ^= 0xFF;
            File.WriteAllBytes(Path.Combine(updates, "OllamaSetup.exe"), tampered);
            File.WriteAllBytes(Path.Combine(updates, "OllamaSetup-other.exe"), notepad);

            var findings = OllamaUpdates.Check(root).ToList();
            Assert.Contains(findings, f => f.RuleId == "A009" && f.Severity == Severity.Critical && f.Location!.EndsWith("OllamaSetup.exe"));
            Assert.Contains(findings, f => f.RuleId == "A009" && f.Severity == Severity.High && f.Detail.Contains("Microsoft"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void No_staged_updates_means_no_findings()
    {
        var root = Directory.CreateTempSubdirectory("modelcheck-ollama-").FullName;
        try
        {
            Assert.Empty(OllamaUpdates.Check(root));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}

static class FindingExtensions
{
    public static string? Source(this Finding f) => f.Location;
}

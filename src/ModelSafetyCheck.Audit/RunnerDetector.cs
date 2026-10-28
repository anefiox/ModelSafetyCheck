using System.Text.Json;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Audit;

/// <param name="ServerPort">Port of the runner's API server when it reports one (LM Studio can use any port).</param>
public sealed record DetectedRunner(string Runner, string? Version, string Source, int? ServerPort = null);

/// <summary>Finds installed model runners and their versions without changing anything.</summary>
public static partial class RunnerDetector
{
    [GeneratedRegex(@"\d+\.\d+\.\d+(?:[-.]?(?:rc|alpha|beta)\.?\d*)?")]
    private static partial Regex VersionRegex();

    public static string Platform =>
        OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" : "linux";

    public static List<DetectedRunner> Detect(HttpClient http)
    {
        var runners = new List<DetectedRunner>();
        if (DetectOllama(http) is { } ollama) runners.Add(ollama);
        if (DetectLmStudio() is { } lmStudio) runners.Add(lmStudio);
        runners.AddRange(DetectPythonPackages());
        return runners;
    }

    static DetectedRunner? DetectOllama(HttpClient http)
    {
        // The running server is the version that matters; the CLI can be a different install.
        try
        {
            using var response = http.Send(new HttpRequestMessage(HttpMethod.Get, "http://127.0.0.1:11434/api/version"));
            if (response.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(response.Content.ReadAsStream());
                if (doc.RootElement.TryGetProperty("version", out var v))
                    return new DetectedRunner("ollama", v.GetString(), "running server on 127.0.0.1:11434");
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IOException)
        {
            // Not running; fall back to the CLI.
        }

        var cli = ProcessRunner.Run("ollama", ["--version"], TimeSpan.FromSeconds(5));
        if (cli is null)
            return null;
        var match = VersionRegex().Match(cli.Output + cli.Error);
        return new DetectedRunner("ollama", match.Success ? match.Value : null, "ollama CLI");
    }

    static DetectedRunner? DetectLmStudio()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".lmstudio", ".internal", "historical-version-info.json");
        if (!File.Exists(path))
            return null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.TryGetProperty("targetHistories", out var histories))
                foreach (var h in histories.EnumerateArray())
                    if (h.TryGetProperty("target", out var t) && t.GetString() == "lmstudio" && h.TryGetProperty("lastRecordedAppVersion", out var v))
                        return new DetectedRunner("lmstudio", v.GetString(), path, LmStudioServerPort());
        }
        catch (Exception ex) when (ex is IOException or JsonException or InvalidOperationException)
        {
        }
        return new DetectedRunner("lmstudio", null, path, LmStudioServerPort());
    }

    /// <summary>`lms server status --json` reports whether LM Studio's API server runs and on which port (it is configurable).</summary>
    static int? LmStudioServerPort()
    {
        var result = ProcessRunner.Run("lms", ["server", "status", "--json"], TimeSpan.FromSeconds(10));
        if (result is not { ExitCode: 0 })
            return null;
        try
        {
            var json = result.Output[result.Output.IndexOf('{')..];
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("running", out var r) && r.ValueKind == JsonValueKind.True
                ? doc.RootElement.TryGetProperty("port", out var p) && p.TryGetInt32(out var port) ? port : 1234
                : null;
        }
        catch (Exception ex) when (ex is JsonException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>Python runners (llama-cpp-python, SGLang, vLLM) in the first Python on PATH. Other virtual environments are not seen.</summary>
    static IEnumerable<DetectedRunner> DetectPythonPackages()
    {
        const string script = "import importlib.metadata as m\nfor p in ('llama-cpp-python','sglang','vllm','onnx','onnxruntime'):\n  try: print(p, m.version(p))\n  except Exception: pass";
        foreach (var python in OperatingSystem.IsWindows() ? new[] { "python", "py" } : ["python3", "python"])
        {
            var result = ProcessRunner.Run(python, ["-I", "-c", script], TimeSpan.FromSeconds(15));
            if (result is null || result.ExitCode != 0)
                continue;
            foreach (var line in result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var parts = line.Split(' ', 2);
                if (parts.Length == 2)
                    yield return new DetectedRunner(parts[0], parts[1], $"Python package ({python})");
            }
            yield break;
        }
    }
}

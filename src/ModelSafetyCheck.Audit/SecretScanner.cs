using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Audit;

/// <summary>
/// Layer 5: secrets an agent could read from its working directory. Values are never printed, only
/// the file and what kind of secret it holds, so the report itself is safe to share.
/// </summary>
public static partial class SecretScanner
{
    const int MaxFiles = 50_000;
    const long MaxContentBytes = 1 << 20;

    static readonly HashSet<string> SkipDirectories = new(StringComparer.OrdinalIgnoreCase) { "node_modules", "bin", "obj", ".venv", "venv", "__pycache__", ".tox", "dist", "build", "target", ".gradle", ".idea", ".vs" };
    static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "", ".env", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties", ".xml", ".py", ".js", ".ts", ".cs",
        ".go", ".rb", ".php", ".java", ".sh", ".ps1", ".bat", ".md", ".tf", ".tfvars", ".npmrc", ".pypirc", ".netrc", ".ipynb", ".local",
    };

    static readonly (Regex Name, string Kind)[] SecretFiles =
    [
        (new(@"^\.env(\..+)?$", RegexOptions.IgnoreCase), ".env file"),
        (new(@"^id_(rsa|dsa|ecdsa|ed25519)$", RegexOptions.IgnoreCase), "SSH private key"),
        (new(@"\.(pem|key|p12|pfx|ppk|jks|keystore)$", RegexOptions.IgnoreCase), "private key or certificate store"),
        (new(@"^(\.netrc|_netrc|\.git-credentials|\.pgpass|\.htpasswd)$", RegexOptions.IgnoreCase), "credential file"),
        (new(@"^(credentials|config)$", RegexOptions.IgnoreCase), "cloud credentials"), // only counted inside .aws / .kube, see below
        (new(@"^(terraform\.tfstate|.*\.tfstate)$", RegexOptions.IgnoreCase), "Terraform state (often holds secrets)"),
    ];

    static readonly (Regex Pattern, string Kind)[] SecretPatterns =
    [
        (new(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "private key"),
        (new(@"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
        (new(@"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "GitHub token"),
        (new(@"\bsk-ant-[A-Za-z0-9_\-]{20,}"), "Anthropic API key"),
        (new(@"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"), "OpenAI-style API key"),
        (new(@"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
        (new(@"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
        (new(@"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}"), "Stripe live key"),
        (new(@"\bhf_[A-Za-z0-9]{30,}\b"), "Hugging Face token"),
        (new(@"""type""\s*:\s*""service_account"""), "Google service-account key"),
        (new(@"_authToken\s*=\s*\S+"), "npm auth token"),
        (new(@"https?://[^/\s:@]+:[^/\s@]{6,}@"), "credentials embedded in a URL"),
    ];

    public static List<Finding> Scan(string root)
    {
        var findings = new List<Finding>();
        if (!Directory.Exists(root))
        {
            findings.Add(new Finding("G001", Severity.Medium, "Agent directory not found", $"'{root}' does not exist.", root));
            return findings;
        }

        var hits = new List<(string Path, string Kind)>();
        var scanned = 0;
        foreach (var file in EnumerateFiles(root))
        {
            if (++scanned > MaxFiles)
            {
                findings.Add(new Finding("G001", Severity.Low, "Secret scan stopped early", $"Stopped after {MaxFiles:N0} files; the directory is very large.", root));
                break;
            }

            var name = Path.GetFileName(file);
            var parent = Path.GetFileName(Path.GetDirectoryName(file)) ?? "";
            if (Regex.IsMatch(name, @"\.(example|sample|template|dist)$", RegexOptions.IgnoreCase) || name.EndsWith(".pub", StringComparison.OrdinalIgnoreCase))
                continue;

            var byName = SecretFiles.FirstOrDefault(s => s.Name.IsMatch(name)).Kind;
            if (byName == "cloud credentials" && !(parent is ".aws" or ".kube" or ".docker" or ".azure"))
                byName = null;
            if (byName is not null)
            {
                hits.Add((file, byName));
                continue;
            }

            var kind = ScanContent(file);
            if (kind is not null)
                hits.Add((file, kind));
        }

        foreach (var group in hits.GroupBy(h => h.Kind))
        {
            var files = group.Select(h => Path.GetRelativePath(root, h.Path)).ToList();
            findings.Add(new Finding("G001", Severity.High, $"Agent can read: {group.Key}",
                $"{files.Count} file(s) an agent working in this directory can read: {string.Join(", ", files.Take(8))}{(files.Count > 8 ? $" (+{files.Count - 8} more)" : "")}. " +
                "A backdoored model with file or shell tools can send these anywhere.\nFix: move secrets out of the agent's working directory and inject them only into the processes that need them.",
                root));
        }
        return findings;
    }

    static string? ScanContent(string file)
    {
        try
        {
            var info = new FileInfo(file);
            if (info.Length is 0 or > MaxContentBytes || !TextExtensions.Contains(info.Extension))
                return null;
            var text = File.ReadAllText(file);
            return SecretPatterns.FirstOrDefault(p => p.Pattern.IsMatch(text)).Kind;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    static IEnumerable<string> EnumerateFiles(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            string[] files, dirs;
            try
            {
                files = Directory.GetFiles(dir);
                dirs = Directory.GetDirectories(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }
            foreach (var f in files)
                yield return f;
            foreach (var d in dirs)
            {
                var name = Path.GetFileName(d);
                if (SkipDirectories.Contains(name) || (new DirectoryInfo(d).Attributes & FileAttributes.ReparsePoint) != 0)
                    continue;
                if (name == ".git")
                {
                    // Only the config can hold credentials (remote URLs with tokens).
                    var config = Path.Combine(d, "config");
                    if (File.Exists(config)) yield return config;
                    continue;
                }
                pending.Push(d);
            }
        }
    }
}

using System.Text.Json;
using System.Text.RegularExpressions;
using ModelSafetyCheck.Core;

namespace ModelSafetyCheck.Audit;

[Flags]
public enum ToolPower
{
    None = 0,
    Shell = 1,
    Files = 2,
    Network = 4,
}

public sealed record McpServer(string Client, string ConfigPath, string Name, ToolPower Powers, IReadOnlyList<string> Directories, bool Remote, int EnvVarCount);

/// <summary>
/// Layer 5: tools that local-model clients hand to the model through MCP (A-11). A model with both a
/// shell/file tool and a network tool can read a secret and send it out; that is the combination the
/// project-discovery backdoor needed. Env values are never read into the report.
/// </summary>
public static partial class McpTools
{
    [GeneratedRegex(@"shell|terminal|exec|command|commander|bash|powershell|pwsh|cmd\b|code[-_ ]?runner|interpreter|run[-_]?python|sandbox|ssh|docker|kubectl", RegexOptions.IgnoreCase)]
    private static partial Regex ShellRegex();

    [GeneratedRegex(@"filesystem|file[-_ ]?system|server-files|\bfiles?\b|\bfs\b|obsidian|notes|git\b|sqlite|postgres|mysql|database|memory", RegexOptions.IgnoreCase)]
    private static partial Regex FilesRegex();

    [GeneratedRegex(@"fetch|browser|puppeteer|playwright|http|web|search|slack|discord|email|gmail|mail|github|gitlab|notion|jira|telegram|whatsapp|twitter|upload|webhook|s3|drive", RegexOptions.IgnoreCase)]
    private static partial Regex NetworkRegex();

    public static IEnumerable<(string Client, string Path)> KnownConfigs()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        yield return ("LM Studio", Path.Combine(home, ".lmstudio", "mcp.json"));
        yield return ("AnythingLLM", Path.Combine(appData, "anythingllm-desktop", "storage", "plugins", "anythingllm_mcp_servers.json"));
        if (OperatingSystem.IsMacOS())
            yield return ("AnythingLLM", Path.Combine(home, "Library", "Application Support", "anythingllm-desktop", "storage", "plugins", "anythingllm_mcp_servers.json"));
        if (OperatingSystem.IsLinux())
            yield return ("AnythingLLM", Path.Combine(home, ".config", "anythingllm-desktop", "storage", "plugins", "anythingllm_mcp_servers.json"));
    }

    public static List<McpServer> Read(IEnumerable<(string Client, string Path)> configs)
    {
        var servers = new List<McpServer>();
        foreach (var (client, path) in configs.Where(c => File.Exists(c.Path)))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
                if (!doc.RootElement.TryGetProperty("mcpServers", out var list) || list.ValueKind != JsonValueKind.Object)
                    continue;
                foreach (var server in list.EnumerateObject())
                    servers.Add(Describe(client, path, server.Name, server.Value));
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
            }
        }
        return servers;
    }

    static McpServer Describe(string client, string path, string name, JsonElement server)
    {
        var command = server.TryGetProperty("command", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() ?? "" : "";
        var args = server.TryGetProperty("args", out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
            : [];
        var url = server.TryGetProperty("url", out var u) && u.ValueKind == JsonValueKind.String ? u.GetString() : null;
        var envCount = server.TryGetProperty("env", out var e) && e.ValueKind == JsonValueKind.Object ? e.EnumerateObject().Count() : 0;

        // Package names are the best signal (e.g. @modelcontextprotocol/server-filesystem); paths are not, so leave them out.
        var signature = string.Join(' ', new[] { name, command }.Concat(args.Where(x => !Path.IsPathRooted(x))));
        var powers = ToolPower.None;
        if (ShellRegex().IsMatch(signature)) powers |= ToolPower.Shell;
        if (FilesRegex().IsMatch(signature)) powers |= ToolPower.Files;
        if (NetworkRegex().IsMatch(signature) || url is not null) powers |= ToolPower.Network;

        var directories = args.Where(x => Path.IsPathRooted(x) && Directory.Exists(x)).ToList();
        return new McpServer(client, path, name, powers, directories, url is not null, envCount);
    }

    public static IEnumerable<Finding> Check(List<McpServer> servers)
    {
        var home = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        foreach (var s in servers)
        {
            var powers = s.Powers == ToolPower.None ? "unknown capabilities" : s.Powers.ToString().ToLowerInvariant();
            yield return new Finding("A008", Severity.Info, $"{s.Client} gives the model the '{s.Name}' tool ({powers})",
                $"Configured in {s.ConfigPath}.{(s.Remote ? " It is a remote MCP server, so tool calls leave this machine." : "")}" +
                (s.EnvVarCount > 0 ? $" {s.EnvVarCount} environment variable(s) are passed to it (values not shown)." : "") +
                (s.Directories.Count > 0 ? $" Directories: {string.Join(", ", s.Directories)}." : ""),
                s.ConfigPath);

            foreach (var dir in s.Directories)
            {
                var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dir));
                if (string.Equals(full, home, StringComparison.OrdinalIgnoreCase) || string.Equals(Path.GetPathRoot(full), full, StringComparison.OrdinalIgnoreCase))
                    yield return new Finding("G004", Severity.High, $"The '{s.Name}' tool can reach your whole {(full == home ? "home directory" : "drive")}",
                        $"{full} includes SSH keys, browser profiles and credential files. Give file tools a project folder, not {full}.", s.ConfigPath);
            }
        }

        var local = servers.Where(s => (s.Powers & (ToolPower.Shell | ToolPower.Files)) != 0).Select(s => s.Name).ToList();
        var network = servers.Where(s => (s.Powers & ToolPower.Network) != 0).Select(s => s.Name).ToList();
        if (local.Count > 0 && network.Count > 0)
            yield return new Finding("G004", Severity.High, "The model can both read local data and send data out",
                $"Local tools: {string.Join(", ", local)}. Network tools: {string.Join(", ", network)}. A backdoored or prompt-injected model needs exactly this pair to exfiltrate secrets. " +
                "Fix: use official weights for tool use, and split these tools across separate agents or sessions.", null);
        else if (servers.Any(s => (s.Powers & ToolPower.Shell) != 0))
            yield return new Finding("G004", Severity.Medium, "The model has a shell tool",
                "Shell access can also reach the network (curl, PowerShell), so it counts as both powers. Use official weights for tool use and keep secrets out of reach.", null);
    }
}

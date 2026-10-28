using ModelSafetyCheck.Audit;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Hub;
using ModelSafetyCheck.Local;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Tests;

public sealed class McpToolsTests : IDisposable
{
    readonly string _dir = Directory.CreateTempSubdirectory("modelcheck-mcp-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    string Config(string json)
    {
        var path = Path.Combine(_dir, "mcp.json");
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public void File_tool_plus_network_tool_is_G004_high()
    {
        var project = Directory.CreateDirectory(Path.Combine(_dir, "project")).FullName.Replace('\\', '/');
        var path = Config($$"""
            { "mcpServers": {
                "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "{{project}}"] },
                "fetch": { "command": "uvx", "args": ["mcp-server-fetch"], "env": { "API_TOKEN": "do-not-print-me" } } } }
            """);
        var servers = McpTools.Read([("test", path)]);
        Assert.Equal(2, servers.Count);
        Assert.Equal(ToolPower.Files, servers.Single(s => s.Name == "filesystem").Powers);
        Assert.Equal(ToolPower.Network, servers.Single(s => s.Name == "fetch").Powers);

        var findings = McpTools.Check(servers).ToList();
        Assert.Contains(findings, f => f.RuleId == "G004" && f.Severity == Severity.High && f.Title.Contains("send data out"));
        Assert.DoesNotContain(findings, f => f.Detail.Contains("do-not-print-me"));
    }

    [Fact]
    public void File_tool_on_home_directory_is_flagged()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).Replace('\\', '/');
        var path = Config($$"""{ "mcpServers": { "files": { "command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "{{home}}"] } } }""");
        Assert.Contains(McpTools.Check(McpTools.Read([("test", path)])), f => f.RuleId == "G004" && f.Title.Contains("home directory"));
    }

    [Fact]
    public void Shell_tool_alone_is_G004_medium_and_remote_server_counts_as_network()
    {
        var path = Config("""{ "mcpServers": { "desktop-commander": { "command": "npx", "args": ["@wonderwhy-er/desktop-commander"] }, "remote": { "url": "https://mcp.example/sse" } } }""");
        var servers = McpTools.Read([("test", path)]);
        Assert.True(servers.Single(s => s.Name == "remote").Remote);
        // Shell + remote network tool = both powers.
        Assert.Contains(McpTools.Check(servers), f => f.RuleId == "G004" && f.Severity == Severity.High);

        var shellOnly = McpTools.Read([("test", Config("""{ "mcpServers": { "shell": { "command": "mcp-shell" } } }"""))]);
        Assert.Contains(McpTools.Check(shellOnly), f => f.RuleId == "G004" && f.Severity == Severity.Medium);
    }

    [Fact]
    public void Broken_or_empty_configs_are_ignored()
    {
        Assert.Empty(McpTools.Read([("test", Config("{ not json"))]));
        Assert.Empty(McpTools.Read([("test", Config("""{ "mcpServers": {} }"""))]));
        Assert.Empty(McpTools.Check([]));
    }
}

public class ProvenanceTests
{
    [Theory]
    [InlineData("lmstudio", "lmstudio:lmstudio-community/gemma-4-12B-it-GGUF/gemma-4-12B-it-Q4_K_M.gguf", "lmstudio-community/gemma-4-12B-it-GGUF", "gemma-4-12B-it-Q4_K_M.gguf")]
    [InlineData("hf-cache", "hf-cache:models--bartowski--Llama-3.2-3B-Instruct-GGUF/snapshots/abc123/Llama-3.2-3B-Instruct-Q4_K_M.gguf", "bartowski/Llama-3.2-3B-Instruct-GGUF", "Llama-3.2-3B-Instruct-Q4_K_M.gguf")]
    [InlineData("ollama", "ollama:hf.co/bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M", "bartowski/Llama-3.2-3B-Instruct-GGUF", null)]
    public void Local_models_map_to_their_repo(string kind, string target, string repo, string? file)
    {
        var report = new ScanReport { Target = target, Kind = kind, Path = kind == "ollama" ? null : "/x" };
        Assert.Equal((repo, file), LocalProvenance.RepoOf(report));
    }

    [Fact]
    public void Ollama_library_models_have_no_repo()
    {
        Assert.Null(LocalProvenance.RepoOf(new ScanReport { Target = "ollama:llama3:latest", Kind = "ollama" }));
    }
}

public class NotifierTests
{
    [Fact]
    public void Untrusted_text_goes_through_environment_not_the_script()
    {
        const string hostile = "x'; Remove-Item C:\\ -Recurse; '\"$(rm -rf ~)";
        var (_, arguments, environment) = DesktopNotifier.Command("modelcheck", hostile);
        Assert.DoesNotContain(arguments, a => a.Contains("Remove-Item", StringComparison.Ordinal) || a.Contains("rm -rf", StringComparison.Ordinal));
        Assert.Contains(environment.Values, v => v.Contains("Remove-Item", StringComparison.Ordinal));
    }

    [Fact]
    public void Scheduled_watch_runs_with_notify()
    {
        var plan = WatchSchedule.Plan();
        var text = WatchSchedule.Describe(plan);
        Assert.Contains("--notify", text);
        Assert.Contains("--log", text);
    }
}

public class PortOwnerTests
{
    [Fact]
    public void Shared_ports_are_skipped_when_owned_by_unrelated_processes()
    {
        var listener = new NetworkExposure.Listener(new System.Net.IPEndPoint(System.Net.IPAddress.Any, 8080), NetworkExposure.KnownPorts.Single(p => p.Port == 8080));
        Assert.Empty(NetworkExposure.CheckListeners([listener], new Dictionary<int, PortOwner> { [8080] = new(42, "nginx") }));
        Assert.Single(NetworkExposure.CheckListeners([listener], new Dictionary<int, PortOwner> { [8080] = new(42, "llama-server") }));
        Assert.Single(NetworkExposure.CheckListeners([listener], null));
    }

    [Fact]
    public void Dedicated_ports_always_report_and_name_the_owner()
    {
        var listener = new NetworkExposure.Listener(new System.Net.IPEndPoint(System.Net.IPAddress.Any, 11434), NetworkExposure.KnownPorts.Single(p => p.Port == 11434));
        var finding = Assert.Single(NetworkExposure.CheckListeners([listener], new Dictionary<int, PortOwner> { [11434] = new(7, "ollama") }));
        Assert.Contains("ollama (PID 7)", finding.Title);
    }
}

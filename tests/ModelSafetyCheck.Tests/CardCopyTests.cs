using System.Net;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Hub;

namespace ModelSafetyCheck.Tests;

public class CardCopyTests
{
    const string OfficialCard = """
        ---
        license: apache-2.0
        ---
        # Privacy Filter

        Privacy Filter is a small open model that detects and redacts personal information such as names, addresses,
        phone numbers and account numbers in free text before it is stored or shared. It runs entirely on device and
        was trained on a large synthetic corpus covering many languages and document formats. Use it as a first pass
        in data pipelines that must not leak personal data, and pair it with human review for high stakes decisions.
        The model returns spans with a category and a confidence score so that downstream tools can decide what to do.
        """;

    /// <summary>Serves the Hub API and raw files from an in-memory map; everything else is 404.</summary>
    sealed class FakeHub(Dictionary<string, string> files) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(Send(request, cancellationToken));

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var key = request.RequestUri!.PathAndQuery;
            return files.TryGetValue(key, out var body)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }

    static string ModelJson(string id, string[] files, string? baseModel = null) => $$"""
        {"id":"{{id}}","author":"{{id.Split('/')[0]}}","createdAt":"2024-01-01T00:00:00Z","lastModified":"2024-01-01T00:00:00Z","downloads":10,
         "tags":[],"cardData":{{(baseModel is null ? "{}" : $$"""{"base_model":"{{baseModel}}"}""")}},
         "siblings":[{{string.Join(",", files.Select(f => $$"""{"rfilename":"{{f}}","size":100}"""))}}]}
        """;

    static List<Finding> Scan(string repo, string readme, string[] files)
    {
        var hub = new FakeHub(new()
        {
            [$"/api/models/{repo}?blobs=true"] = ModelJson(repo, files),
            [$"/{repo}/resolve/main/README.md"] = readme,
            ["/openai/privacy-filter/resolve/main/README.md"] = OfficialCard,
        });
        using var client = new HuggingFaceClient(hub);
        return RepoScanner.Scan(client, repo, new RepoScanOptions(MaxGgufFiles: 0)).SelectMany(r => r.Findings).ToList();
    }

    [Fact]
    public void Undeclared_copy_of_an_official_card_with_a_loader_is_H011_high()
    {
        var findings = Scan("totally-legit/privacy-filter", OfficialCard.Replace("Privacy Filter is", "Privacy Filter (by openai) is"), ["README.md", "loader.bat"]);
        var finding = Assert.Single(findings, f => f.RuleId == "H011");
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("openai/privacy-filter", finding.Title);
    }

    [Fact]
    public void Attributed_copy_is_info()
    {
        var readme = "Quantized by someone. Original model: https://huggingface.co/openai/privacy-filter\n\n" + OfficialCard;
        var findings = Scan("someone/privacy-filter-GGUF", readme, ["README.md"]);
        Assert.Contains(findings, f => f.RuleId == "H011" && f.Severity == Severity.Info);
    }

    [Fact]
    public void Original_card_is_not_flagged()
    {
        var readme = "# My tiny model\n\nThis is an original model that I trained myself on public domain books to write short poems about cats and the sea, nothing more.";
        Assert.DoesNotContain(Scan("someone/cat-poems", readme, ["README.md"]), f => f.RuleId == "H011");
    }
}

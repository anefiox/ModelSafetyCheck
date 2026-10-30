using System.Net;
using ModelSafetyCheck.Hub;

namespace ModelSafetyCheck.Tests;

public sealed class DiscoveryTests : IDisposable
{
    readonly string _dir = Path.Combine(Path.GetTempPath(), "modelcheck-discover-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            return respond(request);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(Send(request, cancellationToken));
    }

    static string Model(string id, string sha, long downloads, params string[] tags) =>
        $$"""{"id":"{{id}}","sha":"{{sha}}","downloads":{{downloads}},"createdAt":"2026-10-29T12:00:00.000Z","tags":[{{string.Join(',', tags.Select(t => $"\"{t}\""))}}]}""";

    static readonly string Page = "[" + string.Join(',',
        Model("a/finetuned-GGUF", "s1", 3, "gguf", "base_model:org/base", "base_model:finetune:org/base"),
        Model("b/official", "s2", 9000, "gguf"),
        Model("c/merged-GGUF", "s3", 50000, "gguf", "base_model:merge:x/y"),
        Model("d/quant-GGUF", "s4", 1, "gguf", "base_model:quantized:a/finetuned")) + "]";

    [Fact]
    public void Query_string_sends_search_filters_sort_and_asks_for_commit_shas()
    {
        var query = HfDiscovery.QueryString(new DiscoverQuery { Filters = ["gguf"], Author = "huihui-ai", Sort = DiscoverSort.Downloads, Ascending = true }, "abliterated v2");
        Assert.Contains("sort=downloads", query);
        Assert.Contains("direction=1", query);
        Assert.Contains("search=abliterated%20v2", query);
        Assert.Contains("author=huihui-ai", query);
        Assert.Contains("filter=gguf", query);
        Assert.Contains("expand%5B%5D=sha", query);
    }

    [Fact]
    public void Relation_and_download_filters_apply_client_side()
    {
        using var hub = new HuggingFaceClient(new Handler(_ => new(HttpStatusCode.OK) { Content = new StringContent(Page) }));
        string[] Ids(DiscoverQuery q) => HfDiscovery.Discover(hub, q).Select(m => m.Id).ToArray();

        Assert.Equal(["a/finetuned-GGUF", "c/merged-GGUF", "d/quant-GGUF"], Ids(new DiscoverQuery { Relations = ["any"] }));
        Assert.Equal(["a/finetuned-GGUF", "c/merged-GGUF"], Ids(new DiscoverQuery { Relations = ["finetune", "merge"] }));
        Assert.Equal(["a/finetuned-GGUF", "d/quant-GGUF"], Ids(new DiscoverQuery { MaxDownloads = 10 }));
        Assert.Equal(["a/finetuned-GGUF", "b/official"], Ids(new DiscoverQuery { Limit = 2 }));
    }

    [Fact]
    public void Search_terms_run_separately_and_repos_are_not_repeated()
    {
        var handler = new Handler(_ => new(HttpStatusCode.OK) { Content = new StringContent(Page) });
        using var hub = new HuggingFaceClient(handler);
        var models = HfDiscovery.Discover(hub, new DiscoverQuery { Search = ["abliterated", "uncensored"], Limit = 2 }).ToList();
        Assert.Equal(["a/finetuned-GGUF", "b/official", "c/merged-GGUF", "d/quant-GGUF"], models.Select(m => m.Id));
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(["finetune"], models[0].Relations);
        Assert.Equal("s1", models[0].Sha);
    }

    [Fact]
    public void Dropped_connections_and_server_errors_are_retried()
    {
        var calls = 0;
        using var hub = new HuggingFaceClient(new Handler(_ => ++calls switch
        {
            1 => throw new HttpRequestException("The SSL connection could not be established"),
            2 => new(HttpStatusCode.ServiceUnavailable),
            3 => new((HttpStatusCode)429),
            _ => new(HttpStatusCode.OK) { Content = new StringContent(Page) },
        })) { RetryDelay = TimeSpan.Zero };
        Assert.Equal(4, HfDiscovery.Discover(hub, new DiscoverQuery()).Count());
        Assert.Equal(4, calls);
    }

    [Fact]
    public void Retries_give_up_and_do_not_repeat_client_errors()
    {
        var calls = 0;
        using var failing = new HuggingFaceClient(new Handler(_ => { calls++; throw new HttpRequestException("down"); })) { RetryDelay = TimeSpan.Zero };
        Assert.Throws<HttpRequestException>(() => HfDiscovery.Discover(failing, new DiscoverQuery()).ToList());
        Assert.Equal(4, calls);

        calls = 0;
        using var missing = new HuggingFaceClient(new Handler(_ => { calls++; return new(HttpStatusCode.NotFound); })) { RetryDelay = TimeSpan.Zero };
        Assert.Throws<HttpRequestException>(() => missing.GetModel("a/b"));
        Assert.Equal(1, calls);
    }

    [Fact]
    public void State_skips_only_repos_whose_commit_was_already_scanned()
    {
        var path = Path.Combine(_dir, "state.json");
        var model = new HfListedModel("a/m", "sha1", null, null, 0, []);
        var state = DiscoverState.Load(path);
        Assert.False(state.IsUnchanged(model));
        state.Record(model, "High");

        var reloaded = DiscoverState.Load(path);
        Assert.True(reloaded.IsUnchanged(model));
        Assert.True(reloaded.IsUnchanged(model with { Id = "A/M" }));
        Assert.False(reloaded.IsUnchanged(model with { Sha = "sha2" }), "a new commit is scanned again");
        Assert.False(reloaded.IsUnchanged(model with { Sha = null }), "without a sha there is no way to tell");
        Assert.False(File.Exists(path + ".tmp"));
    }
}

using System.Security.Cryptography;
using ModelSafetyCheck.Classifier;
using ModelSafetyCheck.Hub;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Cli;

/// <summary>`modelcheck classifier download|test`: the optional ONNX prompt-injection classifier (rule T015).</summary>
static class ClassifierCommand
{
    public const string DefaultRepo = "protectai/deberta-v3-base-prompt-injection-v2";
    static readonly string[] Files = ["onnx/model.onnx", "onnx/spm.model", "onnx/config.json", "onnx/tokenizer.json"];

    /// <summary>Downloads the model files and verifies each LFS file against the sha256 Hugging Face publishes.</summary>
    public static int Download(string repo, string directory, TextWriter output)
    {
        using var client = new HuggingFaceClient();
        var info = client.GetModel(repo);
        Directory.CreateDirectory(directory);
        foreach (var path in Files)
        {
            var file = info.Files.FirstOrDefault(f => f.Path == path);
            if (file is null)
            {
                output.WriteLine($"{repo} has no {path}.");
                return Program.ExitError;
            }
            var target = Path.Combine(directory, Path.GetFileName(path));
            if (File.Exists(target) && new FileInfo(target).Length == file.Size && (file.Sha256 is null || Sha256(target) == file.Sha256))
            {
                output.WriteLine($"ok    {path} (already downloaded)");
                continue;
            }

            output.WriteLine($"get   {path} ({file.Size / 1024.0 / 1024.0:N1} MiB)");
            var partial = target + ".partial";
            using (var response = client.Http.Send(new HttpRequestMessage(HttpMethod.Get, client.FileUrl(repo, path)), HttpCompletionOption.ResponseHeadersRead))
            {
                response.EnsureSuccessStatusCode();
                using var body = response.Content.ReadAsStream();
                using var outFile = File.Create(partial);
                body.CopyTo(outFile);
            }
            if (file.Sha256 is not null && Sha256(partial) != file.Sha256)
            {
                File.Delete(partial);
                output.WriteLine($"sha256 mismatch for {path}; download discarded.");
                return Program.ExitError;
            }
            File.Move(partial, target, overwrite: true);
            output.WriteLine($"ok    {path}{(file.Sha256 is null ? "" : " (sha256 verified)")}");
        }
        output.WriteLine($"\nClassifier installed in {directory}. Use it with --classifier.");
        return Program.ExitClean;
    }

    public static int Test(string directory, string text, TextWriter output)
    {
        using var classifier = PromptInjectionClassifier.TryLoad(directory, out var error);
        if (classifier is null)
        {
            output.WriteLine(error);
            return Program.ExitError;
        }
        var score = classifier.Score([text])[0];
        output.WriteLine($"{score:P2} prompt injection ({classifier.Name}; T015 reports at {TextClassification.Threshold:P0} or above)");
        return Program.ExitClean;
    }

    static string Sha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
}

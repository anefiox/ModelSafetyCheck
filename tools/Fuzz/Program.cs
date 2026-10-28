// Coverage-guided fuzzing of the GGUF parser and rules with SharpFuzz (libFuzzer).
// The scanner reads hostile files, so any exception that escapes ModelScanner is a bug.
//
// Linux / macOS:
//   dotnet tool install --global SharpFuzz.CommandLine
//   dotnet publish tools/Fuzz -c Release -o fuzz-bin
//   sharpfuzz fuzz-bin/ModelSafetyCheck.Core.dll && sharpfuzz fuzz-bin/ModelSafetyCheck.Rules.dll && sharpfuzz fuzz-bin/ModelSafetyCheck.Jinja.dll
//   # build libfuzzer-dotnet from https://github.com/Metalnem/libfuzzer-dotnet, then:
//   ./libfuzzer-dotnet --target_path=fuzz-bin/Fuzz -max_len=65536 tools/Fuzz/corpus
// Windows: use libfuzzer-dotnet-windows.exe from the same project.
//
// `dotnet run --project tools/Fuzz -- --seed tools/Fuzz/corpus` writes a starting corpus of valid files.

using ModelSafetyCheck.Rules;
using SharpFuzz;

if (args is ["--seed", var dir])
{
    Directory.CreateDirectory(dir);
    foreach (var (name, bytes) in Seeds.All())
        File.WriteAllBytes(Path.Combine(dir, name), bytes);
    Console.WriteLine($"Wrote {Seeds.All().Count()} seed files to {dir}");
    return;
}

Fuzzer.LibFuzzer.Run(span =>
{
    using var stream = new MemoryStream(span.ToArray(), writable: false);
    var report = ModelScanner.ScanStream(stream, "fuzz");
    // Touch everything a reporter would, so lazy paths run too.
    foreach (var f in report.Findings)
        _ = f.Detail.Length + (f.Location?.Length ?? 0);
});

static class Seeds
{
    public static IEnumerable<(string Name, byte[] Bytes)> All()
    {
        yield return ("minimal.gguf", Gguf([("general.architecture", "llama")], []));
        yield return ("template.gguf", Gguf(
            [("general.architecture", "llama"), ("tokenizer.chat_template", "{% for m in messages %}{{ '<|im_start|>' + m.role + '\\n' + m.content }}{% if 'x y' in m.content %}{{ m.content.__class__ }}{% endif %}{% endfor %}")],
            [("token_embd.weight", [8UL, 4UL], 0u)]));
        yield return ("go-template.gguf", Gguf([("tokenizer.chat_template", "{{ range .Messages }}{{ if eq .Role \"user\" }}{{ .Content }}{{ end }}{{ end }}")], []));
    }

    /// <summary>A tiny GGUF v3 writer for seeds (string metadata, F32 tensors).</summary>
    static byte[] Gguf((string Key, string Value)[] kvs, (string Name, ulong[] Dims, uint Type)[] tensors)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        void Str(string s) { var b = System.Text.Encoding.UTF8.GetBytes(s); w.Write((ulong)b.Length); w.Write(b); }

        w.Write(0x46554747u); w.Write(3u); w.Write((ulong)tensors.Length); w.Write((ulong)kvs.Length);
        foreach (var (k, v) in kvs) { Str(k); w.Write(8u); Str(v); }
        ulong offset = 0;
        foreach (var (name, dims, type) in tensors)
        {
            Str(name); w.Write((uint)dims.Length);
            foreach (var d in dims) w.Write(d);
            w.Write(type); w.Write(offset);
            offset += dims.Aggregate(1UL, (a, d) => a * d) * 4;
        }
        while (ms.Position % 32 != 0) w.Write((byte)0);
        w.Write(new byte[offset]);
        return ms.ToArray();
    }
}

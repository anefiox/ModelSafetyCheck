using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Tests;

/// <summary>
/// Mutation fuzzing of the whole scan pipeline. Hostile files must produce findings, never exceptions.
/// Seeds are fixed so failures reproduce; a coverage-guided SharpFuzz harness is planned separately (X-05).
/// </summary>
public class FuzzTests
{
    const int Iterations = 3000;

    static byte[] Seed() =>
        GgufWriter.Minimal("{% for m in messages %}{{ '<|im_start|>' + m.role + '\\n' + m.content }}{% endfor %}", vocab: 16)
            .Add("general.alignment", 32u)
            .AddStringArray("general.tags", ["a", "b"])
            .Add("tokenizer.ggml.token_type", GgufValueType.Array, (GgufValueType.Int32, Enumerable.Repeat((object)1, 16).ToArray()))
            .AddTensor("output.weight", [32, 16], type: 8)
            .Build();

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Mutated_files_never_throw(int seed)
    {
        var original = Seed();
        var random = new Random(seed);
        for (var i = 0; i < Iterations; i++)
        {
            var bytes = (byte[])original.Clone();
            var mutations = random.Next(1, 8);
            for (var m = 0; m < mutations && bytes.Length > 16; m++)
            {
                switch (random.Next(4))
                {
                    case 0: // flip a byte
                        bytes[random.Next(bytes.Length)] = (byte)random.Next(256);
                        break;
                    case 1: // write an extreme 64-bit value where a length or count could be
                        var at = random.Next(bytes.Length - 8);
                        BitConverter.GetBytes(random.Next(3) switch { 0 => ulong.MaxValue, 1 => 1UL << random.Next(64), _ => (ulong)random.Next() }).CopyTo(bytes, at);
                        break;
                    case 2: // truncate
                        Array.Resize(ref bytes, random.Next(bytes.Length));
                        break;
                    default: // append junk
                        var junk = new byte[random.Next(1, 256)];
                        random.NextBytes(junk);
                        bytes = [.. bytes, .. junk];
                        break;
                }
            }

            var report = ModelScanner.ScanStream(new MemoryStream(bytes), $"fuzz-{seed}-{i}");
            Assert.Null(report.Error);
        }
    }
}

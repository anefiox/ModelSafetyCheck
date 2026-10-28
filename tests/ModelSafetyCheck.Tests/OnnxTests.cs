using System.Text;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Tests;

public class OnnxTests
{
    // Minimal protobuf writer: field numbers follow onnx.proto.
    static byte[] Field(int number, byte[] value) => [.. Varint((ulong)(number << 3 | 2)), .. Varint((ulong)value.Length), .. value];
    static byte[] Field(int number, string value) => Field(number, Encoding.UTF8.GetBytes(value));
    static byte[] VarintField(int number, ulong value) => [.. Varint((ulong)(number << 3)), .. Varint(value)];
    static byte[] Varint(ulong v)
    {
        var bytes = new List<byte>();
        do { var b = (byte)(v & 0x7F); v >>= 7; bytes.Add(v != 0 ? (byte)(b | 0x80) : b); } while (v != 0);
        return [.. bytes];
    }

    static byte[] ExternalTensor(string name, string location) =>
        [.. Field(8, name), .. VarintField(14, 1), .. Field(13, [.. Field(1, "location"), .. Field(2, location)]), .. Field(9, new byte[64])];

    static byte[] Model(byte[] graph, string domain = "", params (string Key, string Value)[] metadata) =>
        [.. VarintField(1, 8), .. Field(8, [.. Field(1, domain), .. VarintField(2, 17)]), .. Field(7, graph),
         .. metadata.SelectMany(m => Field(14, [.. Field(1, m.Key), .. Field(2, m.Value)]))];

    static ScanReport Scan(byte[] bytes, string? path = null)
    {
        var report = new ScanReport { Target = "m.onnx", Kind = "onnx" };
        OnnxScanner.Scan(new MemoryStream(bytes), report, path);
        return report;
    }

    [Fact]
    public void Plain_model_is_clean()
    {
        var report = Scan(Model(Field(5, [.. Field(8, "w"), .. Field(9, new byte[16])])));
        Assert.DoesNotContain(report.Findings, f => f.Severity > Severity.Info);
        Assert.Contains(report.Findings, f => f.RuleId == "OX004" && f.Detail.StartsWith("1 tensor"));
    }

    [Theory]
    [InlineData("../../../etc/passwd", Severity.Critical)]
    [InlineData("/home/user/.ssh/id_rsa", Severity.Critical)]
    [InlineData(@"C:\Windows\win.ini", Severity.High)]
    [InlineData(@"..\secrets.bin", Severity.High)]
    public void Traversing_external_data_is_OX001(string location, Severity severity)
    {
        var finding = Assert.Single(Scan(Model(Field(5, ExternalTensor("w", location)))).Findings, f => f.RuleId == "OX001");
        Assert.Equal(severity, finding.Severity);
    }

    [Fact]
    public void Traversal_inside_a_subgraph_is_found()
    {
        var subgraph = Field(5, ExternalTensor("inner", "../outside.bin"));
        var node = Field(1, [.. Field(4, "If"), .. Field(5, [.. Field(1, "then_branch"), .. Field(6, subgraph)])]);
        Assert.Contains(Scan(Model(node)).Findings, f => f.RuleId == "OX001" && f.Detail.Contains("inner"));
    }

    [Fact]
    public void Custom_domain_and_metadata_payloads_are_reported()
    {
        var hidden = string.Concat("fetch".Select(c => char.ConvertFromUtf32(0xE0000 + c)));
        var report = Scan(Model(Field(5, Field(8, "w")), "com.example.customops", ("description", "model" + hidden)));
        Assert.Contains(report.Findings, f => f.RuleId == "OX003");
        Assert.Contains(report.Findings, f => f.RuleId == "M005" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Missing_external_file_next_to_model_is_OX002()
    {
        var dir = Directory.CreateTempSubdirectory("modelcheck-onnx-").FullName;
        try
        {
            var model = Path.Combine(dir, "m.onnx");
            Assert.Contains(Scan(Model(Field(5, ExternalTensor("w", "weights.bin"))), model).Findings, f => f.RuleId == "OX002");
            File.WriteAllBytes(Path.Combine(dir, "weights.bin"), new byte[4]);
            Assert.DoesNotContain(Scan(Model(Field(5, ExternalTensor("w", "weights.bin"))), model).Findings, f => f.Severity > Severity.Info);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Corrupt_protobuf_does_not_throw()
    {
        var bytes = Model(Field(5, ExternalTensor("w", "x.bin")));
        for (var cut = 1; cut < bytes.Length; cut += 5)
            Assert.NotNull(Scan(bytes[..cut]));
        Assert.Contains(Scan([0x3A, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]).Findings, f => f.RuleId == "OX005");
    }
}

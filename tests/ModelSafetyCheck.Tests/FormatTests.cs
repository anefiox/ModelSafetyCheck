using System.IO.Compression;
using System.Text;
using ModelSafetyCheck.Core;
using ModelSafetyCheck.Rules;

namespace ModelSafetyCheck.Tests;

public class PickleTests
{
    static ScanReport Scan(byte[] bytes)
    {
        var report = new ScanReport { Target = "t", Kind = "pickle" };
        PickleScanner.Scan(new MemoryStream(bytes), report);
        return report;
    }

    // pickle.dumps of an object whose __reduce__ returns (posix.system, ('id',)), protocol 2 (GLOBAL opcode).
    static readonly byte[] GlobalSystem = [0x80, 0x02, .. "cposix\nsystem\n"u8, 0x71, 0x00, 0x58, 0x02, 0x00, 0x00, 0x00, .. "id"u8, 0x71, 0x01, 0x85, 0x71, 0x02, 0x52, 0x71, 0x03, 0x2E];

    // Protocol 4 (STACK_GLOBAL + MEMOIZE + FRAME): builtins.eval('x').
    static readonly byte[] StackGlobalEval =
        [0x80, 0x04, 0x95, 0x1E, 0, 0, 0, 0, 0, 0, 0, 0x8C, 0x08, .. "builtins"u8, 0x94, 0x8C, 0x04, .. "eval"u8, 0x94, 0x93, 0x94, 0x8C, 0x01, (byte)'x', 0x94, 0x85, 0x94, 0x52, 0x94, 0x2E];

    [Fact]
    public void Global_os_system_is_PK001()
    {
        var report = Scan(GlobalSystem);
        var finding = Assert.Single(report.Findings, f => f.RuleId == "PK001");
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains("posix.system", finding.Detail);
    }

    [Fact]
    public void Stack_global_builtins_eval_is_PK001()
    {
        Assert.Contains(Scan(StackGlobalEval).Findings, f => f.RuleId == "PK001" && f.Detail.Contains("builtins.eval"));
    }

    [Fact]
    public void Torch_zip_checkpoint_is_unpacked()
    {
        byte[] safe = [0x80, 0x02, .. "ctorch._utils\n_rebuild_tensor_v2\n"u8, 0x71, 0x00, 0x2E];
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            using (var e = zip.CreateEntry("archive/data.pkl").Open()) e.Write(safe);
            using (var e = zip.CreateEntry("archive/evil/data.pkl").Open()) e.Write(GlobalSystem);
        }
        var report = Scan(buffer.ToArray());
        Assert.Contains(report.Findings, f => f.RuleId == "PK001" && f.Location == "archive/evil/data.pkl");
        Assert.DoesNotContain(report.Findings, f => f.Location == "archive/data.pkl" && f.Severity > Severity.Info);
    }

    [Fact]
    public void Truncated_and_non_pickle_inputs_do_not_throw()
    {
        Assert.Contains(Scan(GlobalSystem[..10]).Findings, f => f.RuleId is "PK003" or "PK001");
        Assert.Contains(Scan("not a pickle at all"u8.ToArray()).Findings, f => f.Title == "Not a pickle");
        Assert.Contains(Scan([0x80, 0x02, 0x58, 0xFF, 0xFF, 0xFF, 0x7F]).Findings, f => f.RuleId == "PK003");
    }
}

public class SafetensorsTests
{
    static byte[] Build(string headerJson, int dataBytes, byte[]? trailing = null)
    {
        var header = Encoding.UTF8.GetBytes(headerJson);
        using var ms = new MemoryStream();
        ms.Write(BitConverter.GetBytes((ulong)header.Length));
        ms.Write(header);
        ms.Write(new byte[dataBytes]);
        if (trailing is not null) ms.Write(trailing);
        return ms.ToArray();
    }

    static ScanReport Scan(byte[] bytes)
    {
        var report = new ScanReport { Target = "t", Kind = "safetensors" };
        SafetensorsScanner.Scan(new MemoryStream(bytes), report);
        return report;
    }

    [Fact]
    public void Valid_file_is_clean()
    {
        var report = Scan(Build("""{"__metadata__":{"format":"pt"},"w":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}""", 16));
        Assert.DoesNotContain(report.Findings, f => f.Severity > Severity.Info);
    }

    [Fact]
    public void Impossible_header_length_is_F001()
    {
        var bytes = Build("{}", 0);
        BitConverter.GetBytes(1UL << 40).CopyTo(bytes, 0);
        Assert.Contains(Scan(bytes).Findings, f => f.RuleId == "F001" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Offsets_past_data_are_F004()
    {
        Assert.Contains(Scan(Build("""{"w":{"dtype":"F32","shape":[1000],"data_offsets":[0,4000]}}""", 16)).Findings, f => f.RuleId == "F004" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void Shape_mismatch_and_overlap_are_flagged()
    {
        var report = Scan(Build("""{"a":{"dtype":"F32","shape":[4],"data_offsets":[0,16]},"b":{"dtype":"F32","shape":[2],"data_offsets":[8,24]}}""", 24));
        Assert.Contains(report.Findings, f => f.RuleId == "F004" && f.Location == "tensor:b");
        Assert.Contains(report.Findings, f => f.RuleId == "F005");
    }

    [Fact]
    public void Hidden_executable_after_tensors_is_found()
    {
        var elf = new byte[64];
        "\u007fELF"u8.CopyTo(elf);
        var report = Scan(Build("""{"w":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}""", 4, elf));
        Assert.Contains(report.Findings, f => f.RuleId == "M003");
        Assert.Contains(report.Findings, f => f.RuleId == "F006" && f.Severity == Severity.Medium);
    }

    [Fact]
    public void Metadata_strings_get_payload_checks()
    {
        var hidden = string.Concat("run this".Select(c => char.ConvertFromUtf32(0xE0000 + c)));
        var json = "{\"__metadata__\":{\"note\":\"hi" + hidden + "\"},\"w\":{\"dtype\":\"U8\",\"shape\":[1],\"data_offsets\":[0,1]}}";
        Assert.Contains(Scan(Build(json, 1)).Findings, f => f.RuleId == "M005" && f.Severity == Severity.Critical);
    }
}

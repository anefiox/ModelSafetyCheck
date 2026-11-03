# Downloading and scanning model collections

`modelcheck batch` downloads supported model files from HTTP(S) providers and runs the existing static scanners.
It never loads models into a runner, imports repository Python, executes checkpoints, or extracts archives.
Scans cover GGUF, safetensors, ONNX, pickle checkpoints and chat templates. Other formats can be included as
companion files in a manifest; they do not receive standalone scans.

## Hugging Face discovery

Start with a plan:

```powershell
modelcheck batch --discover-hf --limit 100 --dry-run
```

Scan every matching repository, streaming results to JSON Lines:

```powershell
modelcheck batch --discover-hf --limit 0 --max-gb 100 --max-total-gb 1000 --format jsonl > findings.jsonl
```

Discovery follows API pagination and deduplicates repositories across text tasks. The default limit is 100
repositories; `--limit 0` removes it. Tasks include generation, text-to-text generation, fill-mask, embeddings,
classification, question answering, summarization, translation and similarity. Narrow discovery with repeated
`--task` options, or name repositories explicitly:

```powershell
modelcheck batch --discover-hf --task text-generation --task text2text-generation --limit 500
modelcheck batch hf:HuggingFaceTB/SmolLM2-135M-Instruct --dry-run
```

Discovery relies on publishers' task tags and cannot guarantee finding incorrectly tagged models. Set `HF_TOKEN`
for private/gated repositories you are authorized to download. Discovery and download failures appear as errors.
HTTP 429, 408 and transient gateway/service errors receive up to three retries with bounded `Retry-After` delays.

Repository commits are pinned before planning downloads. Quantizations and formats are separate variants.
Numbered GGUF, safetensors and PyTorch `.bin` shards are grouped; missing/inconsistent shards are errors. Root
and representation-local template/config files accompany the weights. ONNX `.data` and `.onnx_data` files in
the same directory are included where available. Use a manifest for nonstandard external-data names/layouts;
the scanner reports missing ONNX external files.

## Other providers and arbitrary URLs

```powershell
modelcheck batch https://models.example.org/releases/model.gguf --keep-downloads
```

For download endpoints without a recognizable extension, authentication, or multi-file models, create a local
manifest. Paths preserve shard and ONNX external-data relationships:

```json
{
  "models": [
    {
      "id": "my-provider/my-model",
      "revision": "release-2026-10-29",
      "files": [
        {
          "url": "https://models.example.org/download?id=123",
          "path": "model.gguf",
          "size": 4500000000,
          "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "tokenEnvironment": "MODEL_PROVIDER_TOKEN"
        },
        {
          "url": "https://models.example.org/templates/model",
          "path": "chat_template.jinja"
        }
      ]
    }
  ]
}
```

Replace example hashes/sizes with actual publisher values. `size`, `sha256`, `revision` and `tokenEnvironment`
are optional. Expected hashes are verified; every completed download gets a computed SHA-256 receipt.

```powershell
modelcheck batch --manifest models.json --directory D:\model-scans --format jsonl > findings.jsonl
```

Bearer tokens come from the named environment variable and require HTTPS. Authorization is removed on redirects.
Hugging Face credentials are scoped to its own HTTPS host. Signed URL queries are omitted from receipts/progress.
Treat manifests and retained reports as local configuration: reports include model-supplied template text.

## Limits, retention and resuming

- `--max-gb 100` means **strictly less than 100,000,000,000 bytes per complete model set**, including all shards
  and companions. This is decimal GB, not GiB. Hugging Face plans with unknown file sizes are rejected.
- Direct URLs/manifests can omit sizes. Advertised sizes are checked before reading; streamed downloads are
  bounded even when the server omits/lies about length. One boundary-probe byte may be consumed to detect an
  oversized response, but it is never written to disk.
- `--max-total-gb 1000` is the default transfer budget per invocation. If more work remains when it is exhausted,
  the run returns an error. Rerun to continue pinned/hashed jobs, or raise the budget explicitly.
- One model set is processed at a time. Downloads are removed after scanning by default; reports are retained.
  `--keep-downloads` retains files, including partial failed downloads. A forcibly killed process can leave its
  isolated download directory behind; check `downloads/` before removing leftovers.
- State lives under `--directory` (default `modelcheck-batch`). `results/<fingerprint>.json` stores the model id,
  revision, scanner/data fingerprint, receipts, completion flag and findings. Writes are atomic; a directory lock
  prevents concurrent runs from replacing each other's results.
- Completed results are reused only for pinned Hugging Face URLs or manifests with hashes for **every file**.
  An arbitrary `revision` label alone does not establish immutability. Plain URLs are downloaded again because
  their contents can change. `--force` always rescans; classifier-enabled runs also rescan.
- Resume works at model-set level. Interrupted files restart their downloads. Failed checks remain incomplete
  and are retried on a later invocation. Discovery is repeated, then unchanged completed jobs are reused.
- `--dry-run` reads discovery/metadata only, downloads no model files and writes no batch state.
- For large crawls use `--format jsonl` or default text: both stream reports. JSON arrays and SARIF collect the
  invocation's reports in memory before writing them.

## Long crawls across machines

A crawl can be stopped on one machine and continued on another by keeping its batch directory in git:

```powershell
# Once: pin the list. One variant per repository (the smallest real model below --max-gb), exact commits and sha256.
modelcheck batch --discover-hf --limit 117 --variant smallest --write-manifest scans/hf-top100/manifest.json
# On any machine, any number of times: pull, scan what is not done yet, export, commit and push.
./scripts/scan-collection.ps1 hf-top100        # or scripts/scan-collection.sh hf-top100
```

- `--write-manifest` resolves discovery to pinned file sets and writes them instead of scanning, so every run works
  through the same list even as Hub rankings and repositories change. Repositories that fail to plan, or whose
  smallest model is over the limit, are listed on stderr and left out.
- `--variant smallest` keeps one file set per repository. Vision projectors (`mmproj`), imatrix calibration files,
  vocabularies, training state and anything under 2% of the repository's largest set are not treated as the model;
  pickle-only sets rank after safetensors, GGUF and ONNX.
- `scans/<name>/results/` and `manifest.json` are committed; `downloads/`, `partial/` and `batch.lock` are ignored.
  Stop with Ctrl+C: finished models are already saved, and the script still commits and pushes them.
- Results are reused only at the same scanner build (all `src/**/*.cs` plus reference data). Run every machine on the
  same commit; changing scanner code makes the next run scan everything again, which keeps the dataset consistent.
- `modelcheck export --batch-dir scans/<name> --out scans/<name>/dataset` builds the dataset straight from the
  results, with no `--save` needed. With only `--batch-dir`, `~/.modelcheck/reports` is not read.

Exit codes remain 0 (no known issues), 1 (low/medium findings), 2 (high/critical) and 3 (failed/incomplete checks).
Display filtering never lowers risk status. Hashes identify bytes; they do not certify publishers or behavior.
Static checks cannot detect backdoors trained into weights; that requires a separate inference evaluation.

# ModelSafetyCheck

`modelcheck` scans local AI models and setups for the attacks that code-execution scanners miss:
files that *instruct* rather than *execute*.

Existing model scanners answer one question: will this file run code when loaded? Newer attacks don't
need to. A GGUF's chat template is Jinja code that runs on every prompt and can hide trigger-activated
instructions; malformed headers can make a runner leak its own memory; a runner exposed on the network
lets anyone rewrite templates behind your back; and an agent that can read your `.env` turns a
backdoored model into a credential stealer. `modelcheck` checks all five layers of a local setup:

| Layer | What | Command |
|---|---|---|
| L1 | The model file | `scan`, `local`, `repo` |
| L2 | The chat template (inside the GGUF, or overridden by Ollama / LM Studio) | `scan`, `local`, `repo`, `watch` |
| L3 | The runner (Ollama, LM Studio, llama-cpp-python, SGLang, vLLM) | `audit` |
| L4 | Network exposure (`OLLAMA_HOST`, open ports, Docker) | `audit` |
| L5 | What an agent can reach (secrets in its working directory) | `audit --agent-dir` |

> **A clean result does not mean a model is safe.** Backdoors trained into the weights cannot be found
> by static scanning. `modelcheck` finds known file, template and setup problems and helps you limit
> what a compromised model can reach.

## Usage

```bash
modelcheck repo bartowski/Llama-3.2-3B-Instruct-GGUF   # before downloading: files, card, publisher, each GGUF's template (header only)
modelcheck repo ollama:llama3.2:1b                      # before `ollama pull`: template layer + GGUF header from the registry
modelcheck repo bartowski/Qwen2.5-0.5B-Instruct-GGUF --lineage   # ...and compare a quant's weights with the base it claims
modelcheck repo --discover --search abliterated --filter gguf --derived any --save  # find new derivative repos; skips ones already scanned
modelcheck lineage model.gguf --base hf:org/base-GGUF/model-f16.gguf  # is this really a quantization of that model? (~20 MiB of Range reads)
modelcheck scan ./models                                # .gguf, .safetensors, .onnx, pickle checkpoints, tokenizer_config.json, chat_template.jinja
modelcheck explain model.gguf                           # the exact prompt the model receives, and what trigger phrases/dates change
modelcheck explain ollama:llama3.2:1b                   # same for an Ollama template layer (Go templates)
modelcheck local                                        # everything in Ollama, LM Studio, llama.cpp and HF caches
modelcheck local --dump-template                        # ...and print the templates so you can read them
modelcheck local --online --hash                        # ...and check each model's publisher, lineage and sha256 against Hugging Face
modelcheck audit --agent-dir ~/my-agent --probe         # runner versions, network exposure, Docker, MCP tools, secrets, risk rating
modelcheck watch --notify                               # first run: baseline; later runs: templates changed without a model update
modelcheck watch --print-schedule                       # how an hourly check would be scheduled (--install-schedule to do it)
modelcheck batch --discover-hf --limit 100 --dry-run     # plan a text-model crawl, below 100 GB per complete file set
modelcheck batch https://example.org/model.gguf         # download and scan a file from any HTTP(S) provider
modelcheck batch --manifest models.json --format jsonl # multi-file models, durable reports and streaming output
modelcheck batch --discover-hf --variant smallest --write-manifest scans/x/manifest.json  # pin a crawl to resume anywhere
modelcheck download hf:org/name/model.gguf --scan        # resumable download, checked against the published sha256, then scanned
```

Downloads (`batch` and `download`) use several connections per file and retry each one on its own. An interrupted
download resumes when rerun: `batch` keeps partial files in `<directory>/partial/`, and `download` keeps them beside the
target as `<file>.part`.

To check before every download, use the wrappers in [`scripts/`](scripts): `ollama-safe-pull` and `lms-safe-get`
(bash and PowerShell) run `modelcheck repo` first and refuse on high/critical findings unless `--force`.

Optional ML check: `modelcheck classifier download` installs a local prompt-injection classifier
(protectai/deberta-v3-base-prompt-injection-v2, Apache-2.0, ~700 MB, sha256-verified); add `--classifier` to any scan
for rule T015. It is supporting evidence only: measured on real templates it also flags ordinary instructions.
Integrations: an Open WebUI filter ([`integrations/open-webui`](integrations/open-webui)) and an LM Studio plugin
([`integrations/lmstudio-plugin`](integrations/lmstudio-plugin)) block chats with flagged models.

Common options: `--format text|json|jsonl|sarif`, `--min-severity info|low|medium|high|critical`, `--no-color`.
Exit codes: `0` clean, `1` warnings (low/medium), `2` high or critical findings (or the policy's `fail-on`), `3` scan error.
`--min-severity` controls displayed findings; it does not lower the exit status.

Keeping results: add `--save` to any scan command to also write the run to
`~/.modelcheck/reports/yyyyMMdd-HHmmss-<command>.json` (UTC; `--save <dir>` for another folder). The file holds the
command line, start and end times, exit code and every finding, including those hidden by `--min-severity` and
suppressed or baselined ones (flagged). A failed save exits `3`. For a running record, schedule e.g.
`modelcheck local --save` or `modelcheck watch --notify --save`.

`modelcheck export --out results/` turns saved runs into a dataset: `targets.csv`/`.jsonl` (one row per scanned
repo or file, latest scan only, with severity counts) and `findings.csv`/`.jsonl` (one row per finding), plus a
`README.md` summary. Query it with DuckDB, SQLite, pandas or a spreadsheet. Only remote scans (`repo`, `batch`,
`lineage`) are exported unless `--include-local` is given, and local file paths are reduced to file names, so the
result can be published.

Watching Hugging Face: `repo --discover` finds repos with a Hub search instead of a list of names, and scans each the
same way as `repo` (headers, templates, card and publisher; no weight downloads). `--search` (repeatable), `--filter`
(Hub tags such as `gguf`), `--author`, `--derived finetune|merge|quantized|adapter|any` (from the repo's `base_model`
tags), `--max-downloads`, `--sort created|modified|downloads|likes`, `--ascending` and `--limit` (per search term,
default 50) choose the repos. The commit of every scanned repo is recorded in `~/.modelcheck/discover-state.json`
(`--state`), so a scheduled run scans only new or changed repos; `--rescan` ignores it. Repos that failed to scan
are tried again next time. Expect `--lineage` to flag fine-tunes and merges (L001): that shows modification, not
malice.

Team policy: commit a `.modelcheck.yml` (`modelcheck policy init`) to allow-list publishers and models, suppress
accepted findings (each needs a reason and an expiry date), override rule severities, and set `fail-on`. Add a
baseline (`--write-baseline`) so CI fails only on new findings. Every command picks the policy up from the current
directory or its parents. `modelcheck policy check` validates it. Suppressed findings stay in JSON and SARIF,
flagged. See [policy files](docs/rules.md#policy-files).

`repo`, `batch`, `local --online`, and classifier installation use the network. Other scans run offline.
`HF_TOKEN` is sent only to the Hugging Face HTTPS origin. Other providers can use signed URLs or a bearer-token
environment variable specified in a local manifest. See [batch scanning](docs/batch.md) for discovery, size limits,
provider manifests, resumability and report storage.

## What it checks

| Area | Rules | Examples |
|---|---|---|
| File structure | S001–S013 | lying string/array lengths, impossible counts, tensors past end of file ("Bleeding Llama" class), overlaps, hidden data in gaps or after the last tensor |
| Metadata | M001–M006 | executables or base64 payloads in strings, invisible Unicode, URLs |
| Tokenizer | K001–K003 | special-token ids outside the vocabulary, vocabulary larger than the embedding table, instructions hidden in special tokens |
| Chat templates | T001–T014 | Jinja sandbox escapes (CVE-2024-34359 "Llama Drama"), trigger phrases, date/random conditions, hidden instructions, exfiltration links, Unicode tag smuggling, diff against 62 official templates (including earlier versions), and **rendered evidence**: the template is run in a sandbox with and without each suspected trigger |
| Other formats | F001–F006, PK001–PK004, OX001–OX005 | safetensors header/offset checks; pickle checkpoints (raw, legacy torch, PyTorch zip) analysed opcode by opcode for imports like `os.system`; ONNX external-data path traversal (incl. symlinks) and custom operators |
| Ollama | O001–O005 | Ollama's own template and system layers (what actually runs), path-traversal digests |
| Runner & network | A001–A009 | known-vulnerable versions, `OLLAMA_HOST=0.0.0.0`, `OLLAMA_ORIGINS=*`, open ports and the process behind them, Docker port publishing, unauthenticated access, MCP tools given to local models, staged Ollama updates' signatures |
| Agent | G001–G004 | readable secrets (values never printed), file/shell + network tool combinations, per-layer risk rating |
| Provenance | P001–P003 | `local --online`: installed file still matches its Hugging Face upload (size / sha256) |
| Hugging Face repo | H001–H011 | executables and lure instructions in the card, publisher tier, lineage, file template differing from the displayed one, pickle files, model cards copied from an official repo |
| Template drift | W001–W003 | template or system prompt changed while the weights did not |

False positives are measured, not guessed: every official template in the database must analyse clean, and
`tools/TemplateCorpus` runs all rules over the templates of the 1,000 most-downloaded GGUF repos (currently 6.5% of
distinct templates get any warning, about 4% Medium or above, mostly unusual community templates worth a look).

Templates are never run by a real Jinja or Go engine. `explain` and rule T013 use modelcheck's own renderers (Jinja and Go text/template), which
only sees plain data (strings, numbers, lists, dicts) and whitelisted helpers, has no reflection, file, network or
process access, and caps steps, output and recursion. Its output is byte-for-byte identical to real jinja2 (with Hugging
Face's settings) on all 62 official templates and on all 346 templates from the top 1,000 GGUF repos that jinja2 renders;
CI and a weekly job keep checking that. The parsers have also been fuzzed (2.26M libFuzzer executions, no crashes).

Reference data (vulnerable versions, official templates, trusted publishers) lives in [`data/`](data) with sources,
and a newer copy in `~/.modelcheck/data` overrides the built-in one. See [docs/rules.md](docs/rules.md) for every rule,
[docs/hardening.md](docs/hardening.md) for the five-layer hardening guide, and [BUILD_PLAN.md](BUILD_PLAN.md) for the roadmap.

## GitHub Action

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: <owner>/ModelSafetyCheck@v0.3.0
    with:
      command: scan          # or: repo
      args: models/          # or: bartowski/Llama-3.2-3B-Instruct-GGUF ollama:llama3.2
      fail-on: high
```

Findings appear in the repository's code scanning alerts (SARIF).

## Install

Download a native single binary from the GitHub releases (built by `.github/workflows/release.yml`), or:

```bash
dotnet tool install --global ModelSafetyCheck      # once published to NuGet; portable, needs the .NET 10 runtime
```

The release also carries the `.nupkg`, and winget and Homebrew manifests (see [packaging](packaging/README.md)).

### Verify a download

A security tool should be verifiable itself. Every release has `SHA256SUMS`. Releases made while the repository is
public also carry a GitHub build-provenance attestation and a Sigstore signature bundle (`<file>.sigstore.json`) for
every asset, proving that this repository's release workflow built the file from the tagged source:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify modelcheck-v0.3.0-linux-x64.tar.gz --repo anefiox/ModelSafetyCheck
cosign verify-blob modelcheck-v0.3.0-linux-x64.tar.gz   --bundle modelcheck-v0.3.0-linux-x64.tar.gz.sigstore.json   --certificate-identity-regexp '^https://github.com/anefiox/ModelSafetyCheck/.github/workflows/release.yml@refs/tags/v'   --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

On Windows use `Get-FileHash` instead of `sha256sum`. The GitHub Action (`action.yml`) checks SHA256SUMS and, for a
public repository, the attestation (`verify-provenance: auto`) before it runs the binary.

## Building

Requires the .NET 10 SDK. The resumable download library is the [Downloader](https://github.com/anefiox/Downloader)
submodule in `external/Downloader`: clone with `git clone --recursive`, or run `git submodule update --init` in an
existing checkout.

```bash
dotnet test
dotnet publish src/ModelSafetyCheck.Cli -c Release -r linux-x64   # native binary: win-x64, win-arm64, linux-x64, linux-arm64, osx-arm64
dotnet pack src/ModelSafetyCheck.Cli -c Release                     # dotnet tool package
dotnet run --project tools/TemplateDbBuilder                        # refresh data/known-templates.json from Hugging Face
dotnet run --project tools/TemplateCorpus -- 1000                   # false-positive benchmark over the top GGUF repos
dotnet run --project tools/Fuzz -- --seed corpus                    # seed corpus for the SharpFuzz harness (see tools/Fuzz/Program.cs)
```

Native AOT on Windows needs the Visual Studio C++ build tools with `vswhere.exe` on PATH.

## Licence

MIT

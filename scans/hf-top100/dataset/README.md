# modelcheck scan results

Scanned 100 Hugging Face repo(s) and 637 model file(s) between 2026-11-03 and 2026-11-05 with modelcheck build 8de0aa2db355.

Only the latest scan of each target is included. A finding marks something to review, not proof of malice; 
a clean result cannot prove weights are free of trained-in backdoors. See the rule reference in docs/rules.md.

## Findings by severity

| Severity | Findings | Targets |
|---|---:|---:|
| critical | 0 | 0 |
| high | 0 | 0 |
| medium | 1 | 1 |
| low | 1 | 1 |
| info | 391 | 179 |

4 target(s) could not be scanned (see the `error` column of targets.csv).

## Findings by rule

| Rule | Severity | Title | Findings | Repos |
|---|---|---|---:|---:|
| S006 | medium | Unknown tensor type | 1 | 1 |
| T003 | low | URL in template | 1 | 1 |

## Medium and above, one row per repo and rule

| Repo | Rule | Severity | Detail |
|---|---|---|---|
| prism-ml/Ternary-Bonsai-2-27B-gguf | S006 | medium | Type 143 is not known to this scanner. It may be a new quantization format, or an invalid value meant to confuse a runner. 402 tensor(s) use it: output.weight, token_embd.weight, blk.0.attn_gate.weight, blk.0.attn_qkv.we… |

## Files

- `targets.csv` / `targets.jsonl`: one row per scanned repo or file (latest scan), with severity counts.
- `findings.csv` / `findings.jsonl`: one row per finding. `counts` is false for suppressed or baselined findings.

Query with DuckDB, for example:

```sql
SELECT rule_id, severity, count(*) AS findings, count(DISTINCT repo) AS repos
FROM 'findings.csv' WHERE counts AND severity <> 'info'
GROUP BY ALL ORDER BY findings DESC;
```

Regenerate with `modelcheck export --out <dir>` after scanning with `--save`.

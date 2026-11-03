# hf-top100

The 100 most-downloaded text models on Hugging Face (as of 2026-11-03), one variant each: the smallest complete model
file set below 100 GB, pinned to an exact commit with sha256 hashes in `manifest.json` (about 2.0 TB in total).

Created with:

```bash
modelcheck batch --discover-hf --limit 117 --variant smallest --write-manifest scans/hf-top100/manifest.json
```

117 repositories were discovered to get 100 models: the rest were over 100 GB in every variant or had file layouts
modelcheck could not plan. Continue the scan from any machine with `scripts/scan-collection.ps1` or
`scripts/scan-collection.sh` (see [batch scanning](../../docs/batch.md#long-crawls-across-machines)). Each run
commits `results/` (one file per scanned model) and the exported dataset in `dataset/`.

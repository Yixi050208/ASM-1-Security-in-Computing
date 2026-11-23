# Cryptographic Data Protection

Security-in-Computing assignment measuring hashing, authenticated encryption,
hybrid encryption, tamper detection, and file-size effects.

## Repository layout

- `scripts/` - experiment runners and shared utilities
- `data/inputs/` - deterministic synthetic test fixtures
- `data/runs/` - official benchmark and functional-check outputs
- `data/analysis/` - validated summaries, statistics, and figures
- `tests/` - test documentation
- `hashing/`, `symmetric/`, `asymmetric/` - topic notes

## Setup

```powershell
python -m pip install -r requirements.txt
```

## Run the checks

```powershell
python scripts/generate_inputs.py
python scripts/functional_checks.py --output-dir data/runs/functional_local
```

Run the official benchmark with `scripts/benchmark.py`, then analyze its
outputs with `scripts/analyze.py`. Existing official outputs are available in
`data/runs/benchmark_full_20261120_official_20261121/` and
`data/analysis/full_20261120_official_20261121/`.

## Key outputs

- `validation_report.json` - validation status for the official analysis
- `size_effect_statistics.csv` - file-size effect statistics
- `verification_outcome_matrix.csv` - tamper and verification outcomes
- `*_timing.svg` - report-ready timing figures

Scratch experiments, report exports, presentation files, and author-specific
artifacts are intentionally not tracked.

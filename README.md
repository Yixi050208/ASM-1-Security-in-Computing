# Cryptographic Data Protection

Security-in-Computing assignment measuring hashing, authenticated encryption,
hybrid encryption, tamper detection, and file-size effects.

## Layout

- `scripts/` — experiment runners and shared utilities
- `data/inputs/` — deterministic synthetic fixtures
- `data/runs/` — official benchmark and functional-run outputs
- `data/analysis/` — validated analysis outputs
- `evidence/` — official collection notes
- `tests/` — test documentation

## Reproduce

See [REPRODUCE.md](REPRODUCE.md) for Windows commands and environment details.
The official collection is `full_20261120T191526Z_7e351974`.

Useful outputs:

- [Validation report](data/analysis/full_20261120_official_20261121/validation_report.json)
- [Size-effect statistics](data/analysis/full_20261120_official_20261121/size_effect_statistics.csv)
- [Verification outcomes](data/analysis/full_20261120_official_20261121/verification_outcome_matrix.csv)

Scratch experiments, report exports, presentation material, and author-specific
artifacts are intentionally not tracked.

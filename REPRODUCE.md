# Reproduce the assignment

This repository contains the completed local synthetic-data experiment and
the saved official results. It does not contain the course brief, the
dat-nix reference clone, credentials, private keys, or a virtual environment.
The authoritative brief remains the supplied file `ASM 1 Security in
Computing.pdf` outside this repository.

## Windows PowerShell setup

From the repository root:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The project requires `cryptography==50.0.2`. The scripts use the five local
fixtures under `data\inputs\`; `scripts\generate_inputs.py` verifies their lengths
and creates missing fixtures without using external data.

```powershell
.\.venv\Scripts\python.exe scripts\generate_inputs.py
```

## Functional checks

Write a new functional run to a separate directory:

```powershell
.\.venv\Scripts\python.exe scripts\functional_checks.py `
  --output-dir data\runs\functional_reproduce
```

Expected result: 124 functional rows with zero unexpected outcomes. The
supplemental HMAC-labelled rows include two actual keyed-HMAC checks and two
ordinary SHA-256 replacement comparisons; the latter are not HMAC forgery
tests.

## Smoke benchmark and analysis

The smoke profile is deliberately separate from the reportable full dataset:

```powershell
.\.venv\Scripts\python.exe scripts\benchmark.py `
  --profile smoke `
  --seed 20261120 `
  --output-dir data\runs\benchmark_smoke_reproduce

.\.venv\Scripts\python.exe scripts\analyze.py `
  --benchmark-csv data\runs\benchmark_smoke_reproduce\benchmark.csv `
  --metadata data\runs\benchmark_smoke_reproduce\benchmark_metadata.json `
  --functional-csv data\runs\functional_reproduce\functional_checks.csv `
  --functional-metadata data\runs\functional_reproduce\functional_checks_metadata.json `
  --output-dir data\analysis\smoke_reproduce `
  --expected-profile smoke
```

The smoke run is expected to validate without inferential statistics. The
checked-in smoke evidence contains 54 rows; new reproduction output should
remain in its own `*_reproduce` directories.

## Validate the saved official run

The official dataset is already included and must not be regenerated merely
to read the report. It contains 1,350 benchmark rows from nine methods, five
sizes and 30 trial blocks. Its corresponding functional evidence contains
124 rows. To re-run validation and regenerate analysis outputs in a new
directory:

```powershell
.\.venv\Scripts\python.exe scripts\analyze.py `
  --benchmark-csv data\runs\benchmark_full_20261120_official_20261121\benchmark.csv `
  --metadata data\runs\benchmark_full_20261120_official_20261121\benchmark_metadata.json `
  --functional-csv data\runs\functional_20261120\functional_checks.csv `
  --functional-metadata data\runs\functional_20261120\functional_checks_metadata.json `
  --output-dir data\analysis\full_validation_reproduce `
  --expected-profile full
```

The saved official analysis under
`data/analysis/full_20261120_official_20261121/` includes validation,
descriptive statistics, nine primary ANOVA results, overhead accounting,
verification outcomes, run-order diagnostics and four family/breakdown
figures.

## Collect a new full run only when required

Full collection is intentionally not part of repository publication. If a
new machine-specific dataset is required, use a fresh output directory and
retain the recorded seed:

```powershell
.\.venv\Scripts\python.exe scripts\benchmark.py `
  --profile full `
  --seed 20261120 `
  --output-dir data\runs\benchmark_full_reproduce
```

The full profile uses five untimed warm-up batches and 30 measured batches per
method and size. One batch is one observation. Do not mix new or scratch rows
into the saved official CSV.

Report exports, presentation material, pilot results, and smoke runs are
author-specific scratch artifacts and are intentionally not tracked. The
official benchmark and analysis outputs under `data/` remain the reproducible
project record.

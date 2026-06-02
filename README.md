# Amalfi Reproduction

This repository is a runnable reproduction of:

> Practical Automated Detection of Malicious npm Packages

Amalfi detects malicious npm packages with machine-learning classifiers, package reproducibility checks, and clone detection. This reproduction focuses on the NPM malicious-package classification workflow and provides a standardized split pipeline in `standard_pipeline.py` for controlled train/test experiments.

The pipeline consumes explicit train/test split manifests and writes a `metrics.json` file for downstream result aggregation.

## Environment

Recommended on Windows PowerShell from this repository root:

```powershell
uv sync
```

If the requested Python version is not installed, let `uv` install it first:

```powershell
uv python install 3.10
uv sync
```

The environment is ignored by git and can remain in place.

## Inputs

The standardized pipeline needs:

- `--split-dir`: a directory containing `train_manifest.json` and `test_manifest.json`.
- Benign training input: either `--benign-train-dir` or `--benign-train-manifest`.
- Benign testing input: either `--benign-test-dir` or `--benign-test-manifest`.
- `--out-dir`: output directory for materialized data, features, model, predictions, and metrics.

The malicious split directory should have this shape:

```text
example_split/
  train_manifest.json
  test_manifest.json
```

## Run Standard Evaluation

PowerShell:

```powershell
uv run .\standard_pipeline.py `
  --split-dir C:\path\to\split `
  --benign-train-dir C:\path\to\benign\train `
  --benign-test-dir C:\path\to\benign\test `
  --out-dir .\results\standard_eval `
  --classifier random-forest `
  --materialize hardlink
```

Git Bash / WSL-style shell:

```bash
./run.sh standard-eval \
  --split-dir /path/to/split \
  --benign-train-dir /path/to/benign/train \
  --benign-test-dir /path/to/benign/test \
  --out-dir ./results/standard_eval \
  --classifier random-forest \
  --materialize hardlink
```

Useful options:

- `--classifier`: `decision-tree`, `random-forest`, `naive-bayes`, or `svm`.
- `--materialize`: `copy`, `hardlink`, or `symlink`. Use `hardlink` when train/test archives are on the same filesystem.
- `--max-workers`: parallel archive feature extraction workers.
- `--archive-timeout-seconds`: per-archive feature extraction timeout.
- `--smote`: enable SMOTE oversampling.
- `--booleanize`: convert feature values to binary indicators.

## Outputs

The output directory contains the materialized split data, extracted feature CSV files, model/prediction artifacts, and:

```text
metrics.json
```

`metrics.json` contains the binary classification metrics for the selected split.

## Legacy Manual Workflow

The older step-by-step workflow is still available when debugging Amalfi directly:

```powershell
uv run .\generate_malicious_csv.py C:\path\to\malicious -o .\features\true_value.csv
uv run .\code\training\feature_extractor.py --dataset C:\path\to\dataset --out .\features\train.csv
uv run .\code\training\train_classifier.py random-forest .\features\true_value.csv .\features\train.csv -o model.pkl
uv run .\predict.py model.pkl .\features\test.csv -o predictions.csv
uv run .\calc.py predictions.csv -m .\features\test_true_value.csv
```

For controlled comparisons, prefer `standard_pipeline.py`; it keeps split handling and output metrics consistent across runs.

## Common Issues

- If Graphviz-related imports fail, rerun `uv sync`; the reproduction uses the dependencies listed in `pyproject.toml`.
- If archive extraction stalls, lower `--max-workers` and increase `--archive-timeout-seconds`.
- If hardlink materialization fails across drives, switch to `--materialize copy`.

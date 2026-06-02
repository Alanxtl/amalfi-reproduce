#!/usr/bin/env bash
set -euo pipefail

model_path="${1:-model.pkl}"
malicious_csv="${2:-features/true_value.csv}"
classifier="${3:-decision-tree}"

combined_train="features/p0-all-train.csv"
negatives_csv="features/new.csv"

datasets=(
  "features/p0-33.csv"
  "features/p0-66.csv"
  "features/p0-100.csv"
)

mkdir -p results

echo "==> Splitting positives and negatives into train/test (by package_name)"
python - <<'PY'
import csv
import random

inputs = [
    "features/p0-33.csv",
    "features/p0-66.csv",
    "features/p0-100.csv",
]
negatives = "features/10k_8k_2k.csv"
combined_train = "features/p0-all-train.csv"
split_ratio = 0.2  # test ratio
seed = 42

random.seed(seed)

first_header = None
neg_test_rows = []

with open(combined_train, "w", newline="", encoding="utf-8") as out_f:
    train_writer = None

    # Split negatives once (shared across difficulty tests)
    with open(negatives, newline="", encoding="utf-8") as neg_f:
        neg_reader = csv.DictReader(neg_f)
        neg_header = neg_reader.fieldnames
        if not neg_header:
            raise ValueError(f"Missing header in {negatives}")
        if train_writer is None:
            train_writer = csv.DictWriter(out_f, fieldnames=neg_header)
            train_writer.writeheader()
            first_header = neg_header
        elif neg_header != first_header:
            raise ValueError(f"Header mismatch in {negatives}")

        neg_rows = list(neg_reader)
        neg_by_pkg = {}
        for row in neg_rows:
            neg_by_pkg.setdefault(row.get("package_name", ""), []).append(row)

        neg_pkgs = list(neg_by_pkg.keys())
        random.shuffle(neg_pkgs)
        neg_test_count = max(1, int(len(neg_pkgs) * split_ratio))
        neg_test_pkgs = set(neg_pkgs[:neg_test_count])

        for pkg, pkg_rows in neg_by_pkg.items():
            if pkg in neg_test_pkgs:
                neg_test_rows.extend(pkg_rows)
            else:
                train_writer.writerows(pkg_rows)

        print(f"Negatives: test packages {len(neg_test_pkgs)}/{len(neg_pkgs)}")

    for path in inputs:
        with open(path, newline="", encoding="utf-8") as in_f:
            reader = csv.DictReader(in_f)
            header = reader.fieldnames
            if not header:
                raise ValueError(f"Missing header in {path}")
            if train_writer is None:
                train_writer = csv.DictWriter(out_f, fieldnames=header)
                train_writer.writeheader()
                first_header = header
            elif header != first_header:
                raise ValueError(f"Header mismatch in {path}")

            rows = list(reader)
            by_pkg = {}
            for row in rows:
                by_pkg.setdefault(row.get("package_name", ""), []).append(row)

            packages = list(by_pkg.keys())
            random.shuffle(packages)
            test_count = max(1, int(len(packages) * split_ratio))
            test_pkgs = set(packages[:test_count])

            test_path = path.replace(".csv", "-test.csv")
            with open(test_path, "w", newline="", encoding="utf-8") as test_f:
                test_writer = csv.DictWriter(test_f, fieldnames=header)
                test_writer.writeheader()
                for pkg, pkg_rows in by_pkg.items():
                    if pkg in test_pkgs:
                        test_writer.writerows(pkg_rows)
                    else:
                        train_writer.writerows(pkg_rows)
                if neg_test_rows:
                    test_writer.writerows(neg_test_rows)

            print(f"Wrote {test_path} (test packages: {len(test_pkgs)}/{len(packages)})")

print(f"Wrote {combined_train}")
PY

echo "==> Training model on combined train dataset"
python code/training/train_classifier.py "${classifier}" "${malicious_csv}" "${combined_train}" -o "${model_path}" --smote true

for dataset in "${datasets[@]}"; do
  test_dataset="${dataset/.csv/-test.csv}"
  name="$(basename "${dataset}" .csv)"
  pred_out="results/${name}-predictions.csv"
  echo "==> Predicting: ${test_dataset}"
  python predict.py "${model_path}" "${test_dataset}" -o "${pred_out}"
  echo "==> Metrics: ${pred_out}"
  python calc.py "${pred_out}" -m "${malicious_csv}"
  echo
done

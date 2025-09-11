import csv

import pandas as pd
from sklearn.metrics import classification_report


def load_malicious_set(malicious_path: str, hashing: bool = False) -> set:
    """
    Read a headerless malicious list CSV:
    - hashing=False: Each row contains 'package,version'
    - hashing=True : Each row contains 'hash'
    """
    malicious = set()
    with open(malicious_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            if hashing:
                malicious.add(row[0].strip())
            else:
                if len(row) < 2:
                    continue
                pkg, ver = row[0].strip(), row[1].strip()
                malicious.add((pkg, ver))
    return malicious


def calculate_metrics(
    file_path: str,
    malicious_path: str,
    *,
    hashing: bool = False,
    pkg_col: str = "package_name",
    ver_col: str = "package_version",
    pred_col: str = "prediction",
    positive_label: str = "malicious",
    negative_label: str = "benign",
):
    """
    Use (package,version) or hash to construct ground truth from malicious_path, align with the prediction column in file_path, and calculate metrics.
    file_path should include:
      - hashing=False: [package_name, package_version, prediction]
      - hashing=True : [hash, prediction]
    """
    # 1) 真值集合
    malicious = load_malicious_set(malicious_path, hashing=hashing)

    # 2) 读预测文件
    true_labels = []

    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            package = row["package_name"]
            version = row["package_version"]

            label = "benign"
            if hashing:
                # TODO: 如果你有 hash.csv，可以在这里对比 hash 值
                pass
            else:
                if (package, version) in malicious:
                    label = "malicious"

            true_labels.append(label)


    df = pd.read_csv(file_path)
    predicted_labels = df[pred_col].astype(str)

    print("\n--- Classification Report ---")
    report = classification_report(true_labels, predicted_labels, zero_division=0)
    print(report)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Compute metrics using label truth from a headerless malicious CSV.")
    ap.add_argument("features_csv", help="Path to features/prediction CSV (must include prediction column).")
    ap.add_argument("-m", "--malicious-csv", required=True, help="Headerless CSV with either 'pkg,ver' or 'hash' per line.")
    ap.add_argument("--hashing", action="store_true", help="If set, malicious-csv contains one hash per line and features_csv must have 'hash' column.")
    ap.add_argument("--pkg-col", default="package_name")
    ap.add_argument("--ver-col", default="package_version")
    ap.add_argument("--pred-col", default="prediction")
    ap.add_argument("--pos", default="malicious", help="Positive label name.")
    ap.add_argument("--neg", default="benign", help="Negative label name.")
    args = ap.parse_args()

    calculate_metrics(
        args.features_csv,
        args.malicious_csv,
        hashing=args.hashing,
        pkg_col=args.pkg_col,
        ver_col=args.ver_col,
        pred_col=args.pred_col,
        positive_label=args.pos,
        negative_label=args.neg,
    )
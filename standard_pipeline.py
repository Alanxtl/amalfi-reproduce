from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
from pathlib import Path

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from code.training.feature_extractor import scan_tarballs_to_csv as extract_features_csv
from code.training.train_classifier import train_classifier_full_from_bigcsv
from predict import predict_from_bigcsv


ARCHIVE_EXTS = (".tgz", ".tar.gz", ".tar", ".zip")


def load_manifest_archives(manifest_path: Path) -> list[Path]:
    payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    return [Path(path) for path in payload.get("archives") or []]


def iter_archives(dataset_dir: Path):
    for path in Path(dataset_dir).rglob("*"):
        if path.is_file() and any(path.name.lower().endswith(ext) for ext in ARCHIVE_EXTS):
            yield path


def resolve_dataset_archives(
    *, manifest_path: Path | None, dataset_dir: Path | None
) -> list[Path]:
    if manifest_path is not None:
        return load_manifest_archives(Path(manifest_path))
    if dataset_dir is not None:
        return sorted(iter_archives(Path(dataset_dir)))
    raise ValueError("Either manifest_path or dataset_dir must be provided.")


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _reset_dir(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _resolve_optional_path(value: str | None) -> Path | None:
    if not value:
        return None
    return Path(value).resolve()


def _unique_destination(dest_dir: Path, src: Path) -> Path:
    candidate = dest_dir / src.name
    counter = 1
    while candidate.exists():
        candidate = dest_dir / f"{src.stem}-{counter}{src.suffix}"
        counter += 1
    return candidate


def _materialize_file(src: Path, dest: Path, mode: str) -> None:
    try:
        if mode == "hardlink":
            os.link(src, dest)
        elif mode == "symlink":
            dest.symlink_to(src)
        elif mode == "copy":
            shutil.copy2(src, dest)
        else:
            raise ValueError(f"Unsupported materialize mode: {mode}")
    except OSError:
        shutil.copy2(src, dest)


def materialize_archives(archives: list[Path], dest_dir: Path, mode: str) -> list[Path]:
    _ensure_dir(dest_dir)
    materialized = []
    for archive in archives:
        destination = _unique_destination(dest_dir, archive)
        _materialize_file(archive, destination, mode)
        materialized.append(destination)
    return materialized


def _load_malicious_pairs(malicious_csv: Path) -> set[tuple[str, str]]:
    pairs = set()
    with malicious_csv.open("r", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if len(row) >= 2:
                pairs.add((row[0], row[1]))
    return pairs


def write_truth_csv_from_features(
    features_csv: Path,
    out_csv: Path,
    *,
    malicious_archives: list[Path],
) -> dict:
    malicious_tarballs = {Path(path).name for path in malicious_archives}
    matched_tarballs: set[str] = set()
    written_rows = 0

    with Path(features_csv).open("r", encoding="utf-8", newline="") as source, Path(
        out_csv
    ).open("w", encoding="utf-8", newline="") as sink:
        reader = csv.DictReader(source)
        writer = csv.writer(sink)
        for row in reader:
            tarball = Path(row.get("tarball", "")).name
            if tarball not in malicious_tarballs:
                continue
            writer.writerow([row.get("package_name", ""), row.get("package_version", "")])
            matched_tarballs.add(tarball)
            written_rows += 1

    missing_tarballs = sorted(malicious_tarballs - matched_tarballs)
    return {
        "requested_malicious_count": len(malicious_archives),
        "matched_malicious_count": written_rows,
        "missing_malicious_tarballs": missing_tarballs,
    }


def count_csv_rows(csv_path: Path, *, has_header: bool = True) -> int:
    with Path(csv_path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        if has_header:
            next(reader, None)
        return sum(1 for _ in reader)


def assert_csv_row_count(
    csv_path: Path,
    *,
    expected_rows: int,
    label: str,
    has_header: bool = True,
) -> int:
    actual_rows = count_csv_rows(Path(csv_path), has_header=has_header)
    if actual_rows != expected_rows:
        raise RuntimeError(
            f"{label} row count mismatch: expected {expected_rows}, found {actual_rows} "
            f"in {csv_path}"
        )
    return actual_rows


def evaluate_predictions(predictions_csv: Path, malicious_csv: Path) -> dict:
    malicious_pairs = _load_malicious_pairs(malicious_csv)
    y_true: list[str] = []
    y_pred: list[str] = []

    with predictions_csv.open("r", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            package = row.get("package_name", "")
            version = row.get("package_version", "")
            y_true.append(
                "malicious" if (package, version) in malicious_pairs else "benign"
            )
            y_pred.append(row.get("prediction", "benign"))

    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "confusion_matrix": confusion_matrix(
            y_true, y_pred, labels=["benign", "malicious"]
        ).tolist(),
        "classification_report": report,
        "sample_count": len(y_true),
    }


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run_standard_eval(args: argparse.Namespace) -> dict:
    split_dir = Path(args.split_dir).resolve()
    out_dir = _ensure_dir(Path(args.out_dir).resolve())
    work_dir = _reset_dir(out_dir / "work")

    train_malicious = resolve_dataset_archives(
        manifest_path=split_dir / "train_manifest.json",
        dataset_dir=None,
    )
    test_malicious = resolve_dataset_archives(
        manifest_path=split_dir / "test_manifest.json",
        dataset_dir=None,
    )
    train_benign = resolve_dataset_archives(
        manifest_path=_resolve_optional_path(args.benign_train_manifest),
        dataset_dir=_resolve_optional_path(args.benign_train_dir),
    )
    test_benign = resolve_dataset_archives(
        manifest_path=_resolve_optional_path(args.benign_test_manifest),
        dataset_dir=_resolve_optional_path(args.benign_test_dir),
    )

    train_mal_dir = _reset_dir(work_dir / "malicious_train")
    test_mal_dir = _reset_dir(work_dir / "malicious_test")
    train_dataset_dir = _reset_dir(work_dir / "train_dataset")
    test_dataset_dir = _reset_dir(work_dir / "test_dataset")

    materialized_train_malicious = materialize_archives(
        train_malicious, train_mal_dir, args.materialize
    )
    materialized_test_malicious = materialize_archives(
        test_malicious, test_mal_dir, args.materialize
    )
    materialize_archives(
        train_malicious + train_benign, train_dataset_dir, args.materialize
    )
    materialize_archives(
        test_malicious + test_benign, test_dataset_dir, args.materialize
    )

    train_features_csv = out_dir / "train_features.csv"
    test_features_csv = out_dir / "test_features.csv"
    train_truth_csv = out_dir / "train_true_value.csv"
    test_truth_csv = out_dir / "test_true_value.csv"
    train_scan_summary_path = out_dir / "train_feature_scan_summary.json"
    test_scan_summary_path = out_dir / "test_feature_scan_summary.json"
    model_path = out_dir / "model.pkl"
    predictions_csv = out_dir / "predictions.csv"

    for output_file in [
        train_features_csv,
        test_features_csv,
        train_truth_csv,
        test_truth_csv,
        train_scan_summary_path,
        test_scan_summary_path,
        model_path,
        predictions_csv,
    ]:
        if output_file.exists():
            output_file.unlink()

    train_scan_summary = extract_features_csv(
        str(train_dataset_dir),
        str(train_features_csv),
        max_workers=args.max_workers,
        archive_timeout_seconds=args.archive_timeout_seconds,
        summary_path=str(train_scan_summary_path),
    )
    test_scan_summary = extract_features_csv(
        str(test_dataset_dir),
        str(test_features_csv),
        max_workers=args.max_workers,
        archive_timeout_seconds=args.archive_timeout_seconds,
        summary_path=str(test_scan_summary_path),
    )
    train_truth_summary = write_truth_csv_from_features(
        train_features_csv,
        train_truth_csv,
        malicious_archives=materialized_train_malicious,
    )
    test_truth_summary = write_truth_csv_from_features(
        test_features_csv,
        test_truth_csv,
        malicious_archives=materialized_test_malicious,
    )

    train_feature_rows = assert_csv_row_count(
        train_features_csv,
        expected_rows=train_scan_summary["processed_archive_count"],
        label="train_features",
    )
    test_feature_rows = assert_csv_row_count(
        test_features_csv,
        expected_rows=test_scan_summary["processed_archive_count"],
        label="test_features",
    )
    train_truth_rows = assert_csv_row_count(
        train_truth_csv,
        expected_rows=train_truth_summary["matched_malicious_count"],
        label="train_true_value",
        has_header=False,
    )
    test_truth_rows = assert_csv_row_count(
        test_truth_csv,
        expected_rows=test_truth_summary["matched_malicious_count"],
        label="test_true_value",
        has_header=False,
    )

    train_classifier_full_from_bigcsv(
        args.classifier,
        str(train_truth_csv),
        str(train_features_csv),
        str(model_path),
        booleanize=args.booleanize,
        smote=args.smote,
    )
    predict_from_bigcsv(str(model_path), str(test_features_csv), str(predictions_csv))
    assert_csv_row_count(
        predictions_csv,
        expected_rows=test_feature_rows,
        label="predictions",
    )

    metrics = evaluate_predictions(predictions_csv, test_truth_csv)
    payload = {
        "baseline": "amalfi",
        "split_dir": str(split_dir),
        "classifier": args.classifier,
        "materialize_mode": args.materialize,
        "counts": {
            "requested": {
                "train_malicious": len(train_malicious),
                "test_malicious": len(test_malicious),
                "train_benign": len(train_benign),
                "test_benign": len(test_benign),
            },
            "effective": {
                "train_total": train_feature_rows,
                "test_total": test_feature_rows,
                "train_malicious": train_truth_rows,
                "test_malicious": test_truth_rows,
                "train_benign": train_feature_rows - train_truth_rows,
                "test_benign": test_feature_rows - test_truth_rows,
            },
        },
        "feature_scan": {
            "train": train_scan_summary,
            "test": test_scan_summary,
        },
        "truth_alignment": {
            "train": train_truth_summary,
            "test": test_truth_summary,
        },
        "artifacts": {
            "train_features_csv": str(train_features_csv),
            "test_features_csv": str(test_features_csv),
            "train_truth_csv": str(train_truth_csv),
            "test_truth_csv": str(test_truth_csv),
            "train_scan_summary_path": str(train_scan_summary_path),
            "test_scan_summary_path": str(test_scan_summary_path),
            "model_path": str(model_path),
            "predictions_csv": str(predictions_csv),
        },
        "metrics": metrics,
    }
    _write_json(out_dir / "metrics.json", payload)
    return payload


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Amalfi on explicit train/test manifests from research group splits."
    )
    parser.add_argument("--split-dir", required=True)
    parser.add_argument("--benign-train-dir")
    parser.add_argument("--benign-train-manifest")
    parser.add_argument("--benign-test-dir")
    parser.add_argument("--benign-test-manifest")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument(
        "--classifier",
        default="random-forest",
        choices=["decision-tree", "random-forest", "naive-bayes", "svm"],
    )
    parser.add_argument(
        "--materialize",
        default="hardlink",
        choices=["copy", "hardlink", "symlink"],
    )
    parser.add_argument("--max-workers", type=int, default=1)
    parser.add_argument("--archive-timeout-seconds", type=int)
    parser.add_argument("--booleanize", action="store_true")
    parser.add_argument("--smote", action="store_true")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    if not (args.benign_train_dir or args.benign_train_manifest):
        raise SystemExit("Provide either --benign-train-dir or --benign-train-manifest.")
    if not (args.benign_test_dir or args.benign_test_manifest):
        raise SystemExit("Provide either --benign-test-dir or --benign-test-manifest.")
    payload = run_standard_eval(args)
    print(json.dumps(payload["metrics"], indent=2))


if __name__ == "__main__":
    main()

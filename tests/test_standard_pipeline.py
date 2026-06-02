import json
import tempfile
import unittest
from pathlib import Path

from standard_pipeline import resolve_dataset_archives, write_truth_csv_from_features


class StandardPipelineTests(unittest.TestCase):
    def test_resolve_dataset_archives_reads_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "sample.tgz"
            archive.write_text("x", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"archives": [str(archive)]}),
                encoding="utf-8",
            )

            self.assertEqual(resolve_dataset_archives(manifest_path=manifest, dataset_dir=None), [archive])

    def test_write_truth_csv_from_features_keeps_only_successfully_extracted_malicious_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            features_csv = root / "features.csv"
            truth_csv = root / "truth.csv"
            features_csv.write_text(
                "\n".join(
                    [
                        "tarball,package_name,package_version",
                        "mal-1.tgz,mal-one,1.0.0",
                        "ben-1.tgz,ben-one,2.0.0",
                        "ben-2.tgz,ben-two,3.0.0",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            summary = write_truth_csv_from_features(
                features_csv,
                truth_csv,
                malicious_archives=[root / "mal-1.tgz", root / "missing-mal.tgz"],
            )

            self.assertEqual(summary["requested_malicious_count"], 2)
            self.assertEqual(summary["matched_malicious_count"], 1)
            self.assertEqual(summary["missing_malicious_tarballs"], ["missing-mal.tgz"])
            self.assertEqual(
                truth_csv.read_text(encoding="utf-8").strip(),
                "mal-one,1.0.0",
            )


if __name__ == "__main__":
    unittest.main()

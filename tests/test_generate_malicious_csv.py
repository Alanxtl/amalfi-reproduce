import csv
import tempfile
import unittest
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from unittest import mock

import generate_malicious_csv


class _FakeFuture:
    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error

    def result(self):
        if self._error is not None:
            raise self._error
        return self._result

    def cancel(self):
        return True


class _FakeExecutor:
    def __init__(self, max_workers=None):
        self.max_workers = max_workers
        self.futures = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def submit(self, fn, path):
        name = Path(path).name
        if name == "a.tgz":
            future = _FakeFuture(
                result={"package_name": "a", "package_version": "1.0.0"}
            )
        elif name == "b.tgz":
            future = _FakeFuture(error=BrokenProcessPool("pool crashed"))
        else:
            future = _FakeFuture(result=None)
        self.futures.append(future)
        return future


class GenerateMaliciousCsvTests(unittest.TestCase):
    def test_scan_tarballs_to_csv_retries_unresolved_archives_after_pool_break(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset_dir = root / "dataset"
            dataset_dir.mkdir()
            for name in ["a.tgz", "b.tgz", "c.tgz"]:
                (dataset_dir / name).write_text("archive", encoding="utf-8")

            out_csv = root / "truth.csv"
            retried = []

            def fake_process_package_archive(path: str):
                name = Path(path).name
                retried.append(name)
                return {
                    "package_name": name.split(".")[0],
                    "package_version": "1.0.0",
                }

            with (
                mock.patch.object(
                    generate_malicious_csv.concurrent.futures,
                    "ProcessPoolExecutor",
                    _FakeExecutor,
                ),
                mock.patch.object(
                    generate_malicious_csv.concurrent.futures,
                    "as_completed",
                    lambda futures: list(futures)[:2],
                ),
                mock.patch.object(
                    generate_malicious_csv, "tqdm", lambda iterable, **_: iterable
                ),
                mock.patch.object(
                    generate_malicious_csv,
                    "process_package_archive",
                    side_effect=fake_process_package_archive,
                ),
            ):
                generate_malicious_csv.scan_tarballs_to_csv(
                    str(dataset_dir),
                    str(out_csv),
                    max_workers=4,
                )

            with out_csv.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle, fieldnames=["package_name", "package_version"]))

            self.assertEqual(len(rows), 3)
            self.assertCountEqual(retried, ["b.tgz", "c.tgz"])


if __name__ == "__main__":
    unittest.main()

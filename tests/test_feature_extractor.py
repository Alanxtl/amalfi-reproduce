import csv
import tempfile
import unittest
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from unittest import mock

from code.training import feature_extractor


class _FakeFuture:
    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error

    def result(self):
        if self._error is not None:
            raise self._error
        return self._result

    def done(self):
        return self._error is not None or self._result is not None

    def cancel(self):
        return True


class _FakeExecutor:
    def __init__(self, futures, max_workers=None):
        self.max_workers = max_workers
        self._futures = list(futures)
        self.submitted_paths = []
        self.shutdown_calls = []
        self._processes = {}

    def submit(self, fn, path):
        self.submitted_paths.append(path)
        future = self._futures.pop(0)
        return future

    def shutdown(self, *args, **kwargs):
        self.shutdown_calls.append((args, kwargs))


class _FakeProgress:
    def __init__(self, total=None, desc=None):
        self.total = total
        self.desc = desc
        self.updates = 0
        self.closed = False

    def update(self, amount=1):
        self.updates += amount

    def close(self):
        self.closed = True


def _fake_row(name: str) -> dict:
    stem = Path(name).stem
    return {
        "tarball": name,
        "package_name": stem,
        "package_version": "1.0.0",
    }


class FeatureExtractorTests(unittest.TestCase):
    def test_scan_tarballs_to_csv_retries_unresolved_archives_after_pool_break(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_csv = root / "features.csv"
            archive_paths = [str(root / name) for name in ["a.tgz", "b.tgz", "c.tgz"]]
            a_future = _FakeFuture(result=_fake_row("a.tgz"))
            b_future = _FakeFuture(error=BrokenProcessPool("pool crashed"))
            c_future = _FakeFuture(result=_fake_row("c.tgz"))
            retry_b_future = _FakeFuture(result=_fake_row("b.tgz"))
            retry_c_future = _FakeFuture(result=_fake_row("c.tgz"))
            executors = [
                _FakeExecutor([a_future, b_future, c_future], max_workers=4),
                _FakeExecutor([retry_b_future, retry_c_future], max_workers=4),
            ]

            def fake_executor_factory(max_workers=None):
                return executors.pop(0)

            wait_results = [
                ([a_future, b_future], {c_future}),
                ([retry_b_future, retry_c_future], set()),
            ]

            with (
                mock.patch.object(
                    feature_extractor.concurrent.futures,
                    "ProcessPoolExecutor",
                    side_effect=fake_executor_factory,
                ),
                mock.patch.object(
                    feature_extractor.concurrent.futures,
                    "wait",
                    side_effect=lambda *args, **kwargs: wait_results.pop(0),
                ),
                mock.patch.object(
                    feature_extractor,
                    "_collect_archive_paths",
                    return_value=archive_paths,
                ),
                mock.patch.object(feature_extractor, "tqdm", _FakeProgress),
                mock.patch.object(
                    feature_extractor,
                    "process_package_archive",
                    side_effect=AssertionError(
                        "process_package_archive should not run outside executor futures"
                    ),
                ),
            ):
                summary = feature_extractor.scan_tarballs_to_csv(
                    str(root),
                    str(out_csv),
                    max_workers=4,
                )

            with out_csv.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

            self.assertEqual(len(rows), 3)
            self.assertEqual(summary["processed_archive_count"], 3)
            self.assertEqual(summary["skipped_archive_count"], 0)

    def test_scan_tarballs_to_csv_sequential_branch_iterates_archive_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_csv = root / "features.csv"
            archive_paths = [str(root / name) for name in ["a.tgz", "b.tgz"]]
            seen_paths = []

            def fake_process_package_archive(path: str):
                seen_paths.append(path)
                return _fake_row(Path(path).name)

            with (
                mock.patch.object(
                    feature_extractor,
                    "_collect_archive_paths",
                    return_value=archive_paths,
                ),
                mock.patch.object(feature_extractor, "tqdm", _FakeProgress),
                mock.patch.object(
                    feature_extractor,
                    "process_package_archive",
                    side_effect=fake_process_package_archive,
                ),
            ):
                summary = feature_extractor.scan_tarballs_to_csv(
                    str(root),
                    str(out_csv),
                    max_workers=1,
                )

            with out_csv.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

            self.assertEqual(seen_paths, archive_paths)
            self.assertEqual(len(rows), 2)
            self.assertEqual(summary["processed_archive_count"], 2)
            self.assertEqual(summary["skipped_archive_count"], 0)

    def test_scan_tarballs_to_csv_skips_only_timed_out_archives_and_requeues_others(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_csv = root / "features.csv"
            archive_paths = [str(root / name) for name in ["a.tgz", "b.tgz", "c.tgz"]]
            slow_a_future = _FakeFuture(result=_fake_row("a.tgz"))
            fast_b_future = _FakeFuture(result=_fake_row("b.tgz"))
            c_future = _FakeFuture(result=_fake_row("c.tgz"))
            retry_c_future = _FakeFuture(result=_fake_row("c.tgz"))
            executors = [
                _FakeExecutor([slow_a_future, fast_b_future, c_future], max_workers=2),
                _FakeExecutor([retry_c_future], max_workers=2),
            ]

            def fake_executor_factory(max_workers=None):
                return executors.pop(0)

            wait_results = [
                ([fast_b_future], {slow_a_future}),
                (set(), {slow_a_future, c_future}),
                ([retry_c_future], set()),
            ]
            monotonic_values = iter([0.0, 1.0, 2.0, 6.0, 6.0, 7.0, 8.0, 8.5])

            with (
                mock.patch.object(
                    feature_extractor,
                    "_collect_archive_paths",
                    return_value=archive_paths,
                ),
                mock.patch.object(
                    feature_extractor.concurrent.futures,
                    "ProcessPoolExecutor",
                    side_effect=fake_executor_factory,
                ),
                mock.patch.object(
                    feature_extractor.concurrent.futures,
                    "wait",
                    side_effect=lambda *args, **kwargs: wait_results.pop(0),
                ),
                mock.patch.object(feature_extractor, "tqdm", _FakeProgress),
                mock.patch.object(
                    feature_extractor.time,
                    "monotonic",
                    side_effect=lambda: next(monotonic_values),
                ),
            ):
                summary = feature_extractor.scan_tarballs_to_csv(
                    str(root),
                    str(out_csv),
                    max_workers=2,
                    archive_timeout_seconds=5,
                )

            with out_csv.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

            self.assertEqual([row["tarball"] for row in rows], ["b.tgz", "c.tgz"])
            self.assertEqual(summary["processed_archive_count"], 2)
            self.assertEqual(summary["skipped_archive_count"], 1)
            self.assertEqual(summary["skipped_archives"][0]["path"], archive_paths[0])
            self.assertIn("timed out after 5 seconds", summary["skipped_archives"][0]["reason"])


if __name__ == "__main__":
    unittest.main()

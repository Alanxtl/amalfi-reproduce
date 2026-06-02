import tempfile
import unittest
from pathlib import Path

from standard_pipeline import assert_csv_row_count


class PipelineGuardTests(unittest.TestCase):
    def test_assert_csv_row_count_raises_on_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "rows.csv"
            csv_path.write_text("col\n1\n2\n", encoding="utf-8")

            with self.assertRaises(RuntimeError):
                assert_csv_row_count(csv_path, expected_rows=3, label="train_features")


if __name__ == "__main__":
    unittest.main()

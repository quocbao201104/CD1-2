import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.ml_anomaly import evaluate_anomaly, reset_model_cache


class TrainModelCommandTests(unittest.TestCase):
    def test_training_command_writes_model_and_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = Path(temp_dir) / "isolation_forest.joblib"
            metadata_path = Path(temp_dir) / "isolation_forest_metadata.json"
            command = [
                sys.executable,
                "train_model.py",
                "--baseline",
                "data/baseline_vm2_20260722.json",
                "--model",
                str(model_path),
                "--metadata",
                str(metadata_path),
            ]
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertTrue(model_path.exists())
            self.assertTrue(metadata_path.exists())

            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual("IsolationForest", metadata["model"])
            self.assertEqual(13, metadata["baseline_rows"])
            self.assertEqual(9, metadata["feature_count"])
            self.assertEqual(42, metadata["random_state"])
            self.assertIn("baseline_sha256", metadata)
            self.assertIn("decision_floor", metadata)

            previous_baseline = os.environ.get("BASELINE_PATH")
            previous_model = os.environ.get("MODEL_PATH")
            try:
                os.environ["BASELINE_PATH"] = (
                    "data/baseline_vm2_20260722.json"
                )
                os.environ["MODEL_PATH"] = str(model_path)
                reset_model_cache()
                result = evaluate_anomaly(
                    {"source": "os", "related_ip": None},
                    "Possible Server Compromise",
                    100,
                    {
                        "correlated": True,
                        "has_network_precursor": True,
                    },
                )
                self.assertEqual("persisted-joblib", result["model_source"])
                self.assertEqual(13, result["baseline_rows"])
                self.assertTrue(result["is_anomaly"])
            finally:
                if previous_baseline is None:
                    os.environ.pop("BASELINE_PATH", None)
                else:
                    os.environ["BASELINE_PATH"] = previous_baseline
                if previous_model is None:
                    os.environ.pop("MODEL_PATH", None)
                else:
                    os.environ["MODEL_PATH"] = previous_model
                reset_model_cache()


if __name__ == "__main__":
    unittest.main()

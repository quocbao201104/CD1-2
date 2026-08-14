import glob
import json
import os
import unittest

from app.classifier import classify
from app.ml_anomaly import evaluate_anomaly
from app.normalizer import from_soc_flat
from app.scoring import is_off_hours, score_envelope


BASELINE_PATH = "data/baseline_vm2_20260722.json"
WHITELIST_PATH = "data/whitelist.json"


class TimestampParsingTests(unittest.TestCase):
    def test_wazuh_basic_timezone_offset_is_detected_as_off_hours(self):
        self.assertTrue(is_off_hours("2026-07-22T20:47:25.846+0700"))


class RealBaselineIsolationForestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["BASELINE_PATH"] = BASELINE_PATH
        with open(WHITELIST_PATH, encoding="utf-8") as stream:
            cls.whitelist = json.load(stream)

    def evaluate_payload(self, path):
        with open(path, encoding="utf-8") as stream:
            payload = json.load(stream)
        event = from_soc_flat(payload)
        incident = classify(
            event["description"],
            event["raw"].get("full_log", ""),
        )
        base_risk = score_envelope(
            event,
            incident,
            None,
            self.whitelist,
        )
        return evaluate_anomaly(event, incident, base_risk, None)

    def test_all_captured_benign_samples_are_inliers(self):
        paths = sorted(glob.glob("data/baseline_samples_vm2_20260722/*.json"))
        self.assertEqual(13, len(paths))
        results = [self.evaluate_payload(path) for path in paths]
        self.assertTrue(
            all(not result["is_anomaly"] for result in results),
            results,
        )

    def test_all_attack_samples_are_outliers(self):
        paths = sorted(glob.glob("data/samples/*.json"))
        self.assertEqual(9, len(paths))
        results = [self.evaluate_payload(path) for path in paths]
        self.assertTrue(
            all(result["is_anomaly"] for result in results),
            results,
        )


if __name__ == "__main__":
    unittest.main()

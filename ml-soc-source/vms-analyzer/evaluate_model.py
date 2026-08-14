"""Evaluate the persisted VM3 model on captured benign and lab attack samples."""

import argparse
import glob
import json
from datetime import datetime, timezone
from pathlib import Path

from app.classifier import classify
from app.ml_anomaly import evaluate_anomaly, reset_model_cache
from app.normalizer import from_soc_flat
from app.scoring import score_envelope


def evaluate_file(path: str, expected_anomaly: bool, whitelist: dict) -> dict:
    with open(path, encoding="utf-8") as stream:
        payload = json.load(stream)
    event = from_soc_flat(payload)
    incident = classify(
        event["description"],
        event["raw"].get("full_log", ""),
    )
    base_risk = score_envelope(event, incident, None, whitelist)
    result = evaluate_anomaly(event, incident, base_risk, None)
    return {
        "sample": Path(path).name,
        "expected_anomaly": expected_anomaly,
        "predicted_anomaly": result["is_anomaly"],
        "correct": result["is_anomaly"] == expected_anomaly,
        "source": event["source"],
        "incident_type": incident,
        "base_risk": base_risk,
        "anomaly_score": result["anomaly_score"],
        "decision_score": result.get("decision_score"),
        "out_of_range_features": result.get("out_of_range_features", []),
        "model_source": result.get("model_source"),
    }


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benign",
        default="data/baseline_samples_vm2_20260722/*.json",
    )
    parser.add_argument("--attack", default="data/samples/*.json")
    parser.add_argument("--whitelist", default="data/whitelist.json")
    parser.add_argument(
        "--output",
        default="data/evaluation_report.json",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    whitelist = json.loads(Path(args.whitelist).read_text(encoding="utf-8"))
    reset_model_cache()

    benign = [
        evaluate_file(path, False, whitelist)
        for path in sorted(glob.glob(args.benign))
    ]
    attack = [
        evaluate_file(path, True, whitelist)
        for path in sorted(glob.glob(args.attack))
    ]
    results = benign + attack

    true_negative = sum(
        not row["expected_anomaly"] and not row["predicted_anomaly"]
        for row in results
    )
    false_positive = sum(
        not row["expected_anomaly"] and row["predicted_anomaly"]
        for row in results
    )
    true_positive = sum(
        row["expected_anomaly"] and row["predicted_anomaly"]
        for row in results
    )
    false_negative = sum(
        row["expected_anomaly"] and not row["predicted_anomaly"]
        for row in results
    )
    total = len(results)

    report = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "scope": (
            "Functional lab evaluation: captured benign VM2 logs versus "
            "designed attack samples; not an independent production dataset."
        ),
        "counts": {
            "benign_samples": len(benign),
            "attack_samples": len(attack),
            "total_samples": total,
        },
        "confusion_matrix": {
            "true_negative": true_negative,
            "false_positive": false_positive,
            "true_positive": true_positive,
            "false_negative": false_negative,
        },
        "functional_accuracy": (
            (true_negative + true_positive) / total if total else 0.0
        ),
        "all_checks_passed": all(row["correct"] for row in results),
        "results": results,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report["all_checks_passed"] else 1)


if __name__ == "__main__":
    main()

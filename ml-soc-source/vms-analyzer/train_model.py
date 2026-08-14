"""Train and persist the local IsolationForest model used by VM3."""

import argparse
import hashlib
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path

import joblib
import sklearn
from sklearn.ensemble import IsolationForest

from app.ml_anomaly import FEATURE_NAMES


def load_baseline(path: Path) -> list[list[float]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError("baseline must be a non-empty JSON list")

    rows = []
    for index, row in enumerate(data):
        if not isinstance(row, list) or len(row) != len(FEATURE_NAMES):
            raise ValueError(
                f"baseline row {index} must contain {len(FEATURE_NAMES)} features"
            )
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in row):
            raise ValueError(f"baseline row {index} contains a non-numeric feature")
        rows.append([float(value) for value in row])
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def train(baseline_path: Path) -> dict:
    baseline = load_baseline(baseline_path)
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=1,
    )
    model.fit(baseline)
    scores = [float(value) for value in model.score_samples(baseline)]

    return {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "feature_min": [
            min(row[index] for row in baseline) for index in range(len(FEATURE_NAMES))
        ],
        "feature_max": [
            max(row[index] for row in baseline) for index in range(len(FEATURE_NAMES))
        ],
        "decision_floor": min(scores),
        "decision_median": statistics.median(scores),
        "baseline_rows": len(baseline),
        "baseline_path": str(baseline_path),
        "baseline_sha256": sha256_file(baseline_path),
        "model_name": "IsolationForest",
        "n_estimators": 200,
        "contamination": "auto",
        "random_state": 42,
        "sklearn_version": sklearn.__version__,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }


def public_metadata(bundle: dict) -> dict:
    return {
        "model": bundle["model_name"],
        "model_path": None,
        "baseline_path": bundle["baseline_path"],
        "baseline_sha256": bundle["baseline_sha256"],
        "baseline_rows": bundle["baseline_rows"],
        "feature_count": len(bundle["feature_names"]),
        "feature_names": bundle["feature_names"],
        "feature_min": bundle["feature_min"],
        "feature_max": bundle["feature_max"],
        "decision_floor": bundle["decision_floor"],
        "decision_median": bundle["decision_median"],
        "n_estimators": bundle["n_estimators"],
        "contamination": bundle["contamination"],
        "random_state": bundle["random_state"],
        "sklearn_version": bundle["sklearn_version"],
        "trained_at": bundle["trained_at"],
    }


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="data/baseline.json")
    parser.add_argument("--model", default="data/isolation_forest.joblib")
    parser.add_argument(
        "--metadata",
        default="data/isolation_forest_metadata.json",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    baseline_path = Path(args.baseline).resolve()
    model_path = Path(args.model).resolve()
    metadata_path = Path(args.metadata).resolve()

    bundle = train(baseline_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)

    metadata = public_metadata(bundle)
    metadata["model_path"] = str(model_path)
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

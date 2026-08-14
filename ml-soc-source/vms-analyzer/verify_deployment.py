"""Verify that the active baseline, model artifact and evaluation agree."""

import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


metadata = json.loads(
    Path("data/isolation_forest_metadata.json").read_text(encoding="utf-8")
)
evaluation = json.loads(
    Path("data/evaluation_report.json").read_text(encoding="utf-8")
)
baseline_hash = sha256_file(Path("data/baseline.json"))
matrix = evaluation["confusion_matrix"]

print(f"BASELINE_HASH_MATCH={baseline_hash == metadata['baseline_sha256']}")
print(f"MODEL_ROWS={metadata['baseline_rows']}")
print(
    "EVAL="
    f"TN:{matrix['true_negative']} "
    f"FP:{matrix['false_positive']} "
    f"TP:{matrix['true_positive']} "
    f"FN:{matrix['false_negative']}"
)
print(f"ALL_CHECKS_PASSED={evaluation['all_checks_passed']}")

if baseline_hash != metadata["baseline_sha256"]:
    raise SystemExit("active baseline does not match the trained model")
if not evaluation["all_checks_passed"]:
    raise SystemExit("model evaluation contains failed checks")

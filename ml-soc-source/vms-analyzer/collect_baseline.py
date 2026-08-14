"""Build local ML baseline vectors from captured normal alert JSON files.

Usage:
  python3 collect_baseline.py --input data/baseline_samples --out data/baseline.json

Only feed normal/benign operation samples here. Attack samples should be used for
testing, not for training the baseline.
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.classifier import classify
from app.ml_anomaly import feature_vector
from app.normalizer import from_soc_flat
from app.scoring import score_envelope


def _load_whitelist(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"ips": []}


def _json_files(paths):
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            yield from sorted(path.glob("*.json"))
        elif path.is_file():
            yield path


def _envelopes(payload: dict):
    return [from_soc_flat(payload)]


def _incident_for(ev: dict):
    return classify(ev.get("description", ""), ev.get("raw", {}).get("full_log", ""))


def build_baseline(input_paths, whitelist_path: str):
    whitelist = _load_whitelist(whitelist_path)
    rows = []
    for path in _json_files(input_paths):
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        for ev in _envelopes(payload):
            incident = _incident_for(ev)
            base_score = score_envelope(ev, incident, None, whitelist)
            rows.append(feature_vector(ev, incident, base_score, None))
    return rows


def main():
    parser = argparse.ArgumentParser(description="Build IsolationForest baseline vectors.")
    parser.add_argument(
        "--input",
        nargs="+",
        default=["data/baseline_samples"],
        help="JSON files or directories containing normal alert samples.",
    )
    parser.add_argument("--out", default="data/baseline.json", help="Output baseline JSON path.")
    parser.add_argument("--whitelist", default="data/whitelist.json", help="Whitelist JSON path.")
    args = parser.parse_args()

    rows = build_baseline(args.input, args.whitelist)
    if not rows:
        raise SystemExit("No baseline rows generated. Provide normal alert JSON files with --input.")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rows, f, indent=2)
        f.write("\n")
    print(f"Wrote {len(rows)} baseline rows to {out}")


if __name__ == "__main__":
    main()

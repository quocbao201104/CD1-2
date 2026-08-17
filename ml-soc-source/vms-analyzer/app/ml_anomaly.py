"""Local ML anomaly scoring for CD2.

This module runs fully on VM3. It uses scikit-learn IsolationForest when
available and falls back to a small deterministic heuristic if the dependency is
missing. The ML score is advisory: rule/correlation logic still owns the core
incident decision.
"""

import hashlib
import json
import os
import statistics
import threading

try:
    import joblib
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover - exercised only when dependency missing
    joblib = None
    IsolationForest = None


INCIDENT_WEIGHT = {
    "Unknown": 0,
    "SSH Brute Force": 4,
    "Suspicious User Creation": 5,
    "Network Port Scan": 3,
    "Web Sensitive Path Scan": 4,
    "Web Traversal Attempt": 6,
    "Web Root Modified": 7,
    "Suspicious Web File": 8,
    "Suspected Web Compromise": 7,
    "Account File Modified": 6,
    "SSH Key Backdoor": 7,
    "Privilege Escalation": 8,
    "Valid Login After Brute Force": 9,
    "Possible Server Compromise": 10,
}


TRAINING_BASELINE = [
    # source_network, source_web, source_os, source_auth,
    # incident_weight, base_risk, correlated, has_network_precursor, has_srcip
    [0, 1, 0, 0, 1, 10, 0, 0, 0],
    [0, 1, 0, 0, 2, 20, 0, 0, 1],
    [0, 0, 1, 0, 2, 20, 0, 0, 0],
    [0, 0, 0, 1, 2, 20, 0, 0, 1],
    [1, 0, 0, 0, 2, 30, 0, 0, 1],
    [0, 1, 0, 0, 3, 35, 0, 0, 1],
    [0, 0, 1, 0, 3, 40, 0, 0, 0],
    [0, 0, 0, 1, 4, 40, 0, 0, 1],
    [0, 1, 0, 0, 4, 45, 0, 0, 1],
    [0, 0, 1, 0, 5, 50, 0, 0, 0],
]

FEATURE_NAMES = [
    "source_network",
    "source_web",
    "source_os",
    "source_auth",
    "incident_weight",
    "base_risk",
    "correlated",
    "has_network_precursor",
    "has_srcip",
]

FEATURE_SCALES = [1, 1, 1, 1, 10, 100, 1, 1, 1]

_MODEL_CACHE = {}
_MODEL_LOCK = threading.Lock()


def _corr_flag(correlation) -> int:
    if isinstance(correlation, dict):
        return 1 if correlation.get("correlated") else 0
    return 1 if correlation else 0


def _network_precursor(correlation) -> int:
    if isinstance(correlation, dict):
        return 1 if correlation.get("has_network_precursor") else 0
    return 0


def _time_delta_bucket(correlation) -> int:
    if not isinstance(correlation, dict) or not correlation.get("has_network_precursor"):
        return 0
    seconds = int(correlation.get("time_delta_network_to_os") or 0)
    return max(1, min(10, seconds // 60 + 1))


def feature_vector(ev: dict, incident: str, base_risk: int, correlation=None) -> list:
    source = ev.get("source")
    return [
        1 if source == "network" else 0,
        1 if source == "web" else 0,
        1 if source == "os" else 0,
        1 if source == "auth" else 0,
        INCIDENT_WEIGHT.get(incident, INCIDENT_WEIGHT["Unknown"]),
        int(base_risk),
        _corr_flag(correlation),
        _network_precursor(correlation),
        1 if ev.get("related_ip") else 0,
    ]


def _heuristic_score(features: list) -> int:
    incident_weight = features[4]
    base_risk = features[5]
    correlated = features[6]
    has_network_precursor = features[7]
    has_srcip = features[8]
    score = 20
    score += incident_weight * 5
    score += max(0, base_risk - 40) // 2
    if correlated:
        score += 25
    if has_network_precursor:
        score += 15
    if has_srcip and incident_weight >= 4:
        score += 10
    return min(100, int(score))


def load_training_baseline(path: str | None = None):
    """Load feature baseline from JSON, fallback to embedded lab baseline."""

    baseline_path = path or os.getenv("BASELINE_PATH", "data/baseline.json")
    try:
        with open(baseline_path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list) or not data or any(len(row) != 9 for row in data):
            raise ValueError("baseline must be a non-empty list of 9-feature rows")
        return data, baseline_path
    except Exception:
        return TRAINING_BASELINE, "embedded-default"


def reset_model_cache():
    """Clear the fitted model so tests or a baseline update can reload it."""

    with _MODEL_LOCK:
        _MODEL_CACHE.clear()


def _baseline_signature(source: str):
    if source == "embedded-default":
        return source, None, len(TRAINING_BASELINE)
    try:
        stat = os.stat(source)
        return source, stat.st_mtime_ns, stat.st_size
    except OSError:
        return source, None, None


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _model_signature(path: str):
    try:
        stat = os.stat(path)
        return path, stat.st_mtime_ns, stat.st_size
    except OSError:
        return path, None, None


def _load_persisted_engine(model_path: str, baseline_source: str):
    if joblib is None or baseline_source == "embedded-default":
        return None
    try:
        bundle = joblib.load(model_path)
        required = {
            "model",
            "feature_names",
            "feature_min",
            "feature_max",
            "decision_floor",
            "decision_median",
            "baseline_rows",
            "baseline_sha256",
        }
        if not isinstance(bundle, dict) or not required.issubset(bundle):
            return None
        if bundle["feature_names"] != FEATURE_NAMES:
            return None
        if bundle["baseline_sha256"] != _sha256_file(baseline_source):
            return None
        return {
            "model": bundle["model"],
            "model_source": "persisted-joblib",
            "model_path": model_path,
            "baseline_source": baseline_source,
            "baseline_rows": bundle["baseline_rows"],
            "feature_min": bundle["feature_min"],
            "feature_max": bundle["feature_max"],
            "decision_floor": bundle["decision_floor"],
            "decision_median": bundle["decision_median"],
            "trained_at": bundle.get("trained_at"),
            "baseline_sha256": bundle["baseline_sha256"],
        }
    except Exception:
        return None


def _fit_engine(baseline: list, baseline_source: str):
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=1,
    )
    model.fit(baseline)
    training_scores = [float(value) for value in model.score_samples(baseline)]
    return {
        "model": model,
        "model_source": "runtime-fit",
        "model_path": None,
        "baseline_source": baseline_source,
        "baseline_rows": len(baseline),
        "feature_min": [min(row[index] for row in baseline) for index in range(9)],
        "feature_max": [max(row[index] for row in baseline) for index in range(9)],
        "decision_floor": min(training_scores),
        "decision_median": statistics.median(training_scores),
    }


def _engine():
    baseline, baseline_source = load_training_baseline()
    model_path = os.getenv("MODEL_PATH", "data/isolation_forest.joblib")
    signature = (
        _baseline_signature(baseline_source),
        _model_signature(model_path),
    )
    with _MODEL_LOCK:
        if _MODEL_CACHE.get("signature") != signature:
            _MODEL_CACHE.clear()
            persisted = _load_persisted_engine(model_path, baseline_source)
            _MODEL_CACHE.update(
                persisted or _fit_engine(baseline, baseline_source)
            )
            _MODEL_CACHE["signature"] = signature
        return dict(_MODEL_CACHE)


def _range_novelty(features: list, engine: dict):
    outside = []
    normalized_distance = 0.0
    for index, value in enumerate(features):
        low = engine["feature_min"][index]
        high = engine["feature_max"][index]
        if value < low:
            outside.append(FEATURE_NAMES[index])
            normalized_distance += (low - value) / FEATURE_SCALES[index]
        elif value > high:
            outside.append(FEATURE_NAMES[index])
            normalized_distance += (value - high) / FEATURE_SCALES[index]
    return outside, normalized_distance


def _calibrated_score(raw_score: float, engine: dict, outside: list, distance: float):
    floor = engine["decision_floor"]
    median = engine["decision_median"]
    spread = max(1e-9, median - floor)

    if raw_score < floor - 1e-9:
        below_floor = (floor - raw_score) / spread
        model_score = 70 + min(25, int(round(below_floor * 25)))
    else:
        model_score = max(
            0,
            min(49, int(round(49 * (median - raw_score) / spread))),
        )

    if outside:
        range_score = 70 + min(
            30,
            len(outside) * 8 + int(round(distance * 15)),
        )
        return max(model_score, range_score)
    return model_score


def evaluate_anomaly(ev: dict, incident: str, base_risk: int, correlation=None) -> dict:
    """Return local ML advisory result.

    `anomaly_score` is 0-100, where higher means more unusual/risky for the lab
    baseline. `risk_delta` is intentionally capped so ML cannot overrule the
    deterministic security correlation logic.
    """

    features = feature_vector(ev, incident, base_risk, correlation)
    baseline, baseline_source = load_training_baseline()

    if IsolationForest is None:
        score = _heuristic_score(features)
        return {
            "model": "heuristic-fallback",
            "baseline_source": baseline_source,
            "anomaly_score": score,
            "is_anomaly": score >= 70,
            "risk_delta": 10 if score >= 80 else 5 if score >= 70 else 0,
        }

    engine = _engine()
    raw = float(engine["model"].score_samples([features])[0])
    outside, distance = _range_novelty(features, engine)
    score = _calibrated_score(raw, engine, outside, distance)
    is_anomaly = bool(outside) or raw < engine["decision_floor"] - 1e-9
    return {
        "model": "IsolationForest",
        "model_source": engine["model_source"],
        "model_path": engine.get("model_path"),
        "baseline_source": engine["baseline_source"],
        "baseline_rows": engine["baseline_rows"],
        "trained_at": engine.get("trained_at"),
        "feature_count": len(features),
        "decision_score": round(raw, 6),
        "decision_floor": round(engine["decision_floor"], 6),
        "out_of_range_features": outside,
        "anomaly_score": score,
        "is_anomaly": is_anomaly,
        "risk_delta": 10 if score >= 80 else 5 if is_anomaly else 0,
    }

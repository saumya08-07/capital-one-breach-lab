"""
iam.py — A minimal IAM policy evaluation engine.

WHY THIS EXISTS
---------------
The central claim of the case study is that the *scope* of the IAM role,
not the SSRF vulnerability, determined the size of the Capital One breach.
To measure that claim we need to actually evaluate real AWS policy JSON
against real requests, rather than assert what a policy "would" allow.

This module implements the subset of AWS IAM evaluation logic that the
experiment depends on:

  1. Default deny          — if nothing explicitly allows an action, it is denied.
  2. Explicit deny wins    — a matching Deny overrides any Allow.
  3. Wildcard matching     — "s3:Get*" and "arn:aws:s3:::*" behave as in AWS.
  4. NotAction             — used by the deny-everything-else guard rail.

It deliberately does NOT implement: condition keys evaluated against live
request context, permission boundaries, SCPs, resource-based policies, or
session policies. Those are out of scope for the measurement and are
discussed as limitations in the report.
"""

import fnmatch
import json
from pathlib import Path


class PolicyEvaluationError(Exception):
    pass


def _as_list(value):
    """AWS allows a string or a list anywhere a list is accepted."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _matches_any(candidate, patterns):
    """
    Glob match with AWS semantics. AWS uses '*' (any sequence) and '?' (any
    single char), which is exactly fnmatch, but fnmatch is case-insensitive
    on some platforms, so we normalise explicitly to keep results identical
    across the machines this is run on.
    """
    c = candidate.lower()
    return any(fnmatch.fnmatchcase(c, p.lower()) for p in patterns)


class Policy:
    """An IAM policy document loaded from JSON."""

    def __init__(self, document, name="inline"):
        if "Statement" not in document:
            raise PolicyEvaluationError(f"policy {name!r} has no Statement block")
        self.name = name
        self.document = document
        self.statements = _as_list(document["Statement"])

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        with path.open() as fh:
            return cls(json.load(fh), name=path.name)

    def _statement_matches(self, statement, action, resource):
        """
        Does this statement apply to the (action, resource) pair?

        A statement applies when BOTH the action and the resource match.
        Action can be expressed positively (Action) or negatively (NotAction);
        the latter is what makes a 'deny everything except these' guard work.
        """
        actions = _as_list(statement.get("Action"))
        not_actions = _as_list(statement.get("NotAction"))

        if actions:
            action_hit = _matches_any(action, actions)
        elif not_actions:
            # NotAction matches when the action is NOT in the listed set.
            action_hit = not _matches_any(action, not_actions)
        else:
            raise PolicyEvaluationError(
                f"statement in {self.name!r} has neither Action nor NotAction"
            )

        if not action_hit:
            return False

        resources = _as_list(statement.get("Resource"))
        not_resources = _as_list(statement.get("NotResource"))

        if resources:
            return _matches_any(resource, resources)
        if not_resources:
            return not _matches_any(resource, not_resources)
        raise PolicyEvaluationError(
            f"statement in {self.name!r} has neither Resource nor NotResource"
        )

    def evaluate(self, action, resource):
        """
        Return (allowed: bool, reason: str).

        Evaluation order mirrors AWS: collect matching statements, then apply
        explicit-deny precedence, then allow, then default deny.
        """
        matched_allow = None
        matched_deny = None

        for statement in self.statements:
            if not self._statement_matches(statement, action, resource):
                continue
            effect = statement.get("Effect")
            sid = statement.get("Sid", "<no-sid>")
            if effect == "Deny":
                matched_deny = sid
            elif effect == "Allow":
                if matched_allow is None:
                    matched_allow = sid
            else:
                raise PolicyEvaluationError(
                    f"statement {sid!r} in {self.name!r} has invalid Effect {effect!r}"
                )

        if matched_deny is not None:
            return False, f"explicit Deny by statement {matched_deny!r}"
        if matched_allow is not None:
            return True, f"Allow by statement {matched_allow!r}"
        return False, "implicit deny (no matching Allow)"


def bucket_arn(bucket):
    return f"arn:aws:s3:::{bucket}"


def object_arn(bucket, key):
    return f"arn:aws:s3:::{bucket}/{key}"


if __name__ == "__main__":
    # Smoke test demonstrating the three behaviours the experiment relies on.
    wildcard = Policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "Wide", "Effect": "Allow",
                 "Action": ["s3:List*", "s3:Get*"], "Resource": "*"}
            ],
        },
        name="wildcard",
    )
    scoped = Policy.from_file(Path(__file__).parent / "policies" / "least_privilege.json")

    checks = [
        ("s3:GetObject", object_arn("customer-card-applications", "2019/app-00001.json")),
        ("s3:GetObject", object_arn("waf-config-bucket", "rules/crs.conf")),
        ("s3:DeleteObject", object_arn("waf-config-bucket", "rules/crs.conf")),
    ]
    for pol in (wildcard, scoped):
        print(f"\n[{pol.name}]")
        for action, res in checks:
            ok, why = pol.evaluate(action, res)
            print(f"  {'ALLOW' if ok else 'DENY ':5}  {action:16}  {res}\n         -> {why}")

"""
detector.py — Detection rules over the audit log (Layer 4).

WHY THIS EXISTS
---------------
The decisive failure in 2019 was detective, not preventive. The telemetry to
catch the intrusion existed; no rule interpreted it. This module supplies the
two rules that would have interpreted it, and the experiment measures how
quickly they fire once the signal is present.

Rule 1 — Credential-origin mismatch.
    Temporary credentials issued to an instance role should only be exercised
    from that instance's own network context. A call bearing those credentials
    from any other source address is anomalous REGARDLESS of whether policy
    authorised it. This is the single most reliable signal, because it does
    not depend on volume or timing. It mirrors the GuardDuty finding
    UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.

Rule 2 — Volumetric deviation.
    A burst of ListBucket followed by sustained GetObject beyond an
    established baseline indicates collection and exfiltration. Weaker than
    Rule 1 on its own because a patient adversary can stay under a threshold,
    which is why both rules are used together.
"""

INSTANCE_IP = "10.0.1.47"


def _is_instance_local(ip):
    """
    True when the call originated on the instance's own network context.
    The instance address and loopback count as local; everything else is foreign.
    """
    return ip == INSTANCE_IP or ip.startswith("127.")


def rule_credential_origin(events):
    """
    Return the first event whose instance-role credentials were used from a
    foreign source address, or None. That event's timestamp is the moment the
    intrusion became detectable.
    """
    for event in events:
        identity = event.get("userIdentity", {})
        if identity.get("type") != "AssumedRole":
            continue
        if "ISRM-WAF-Role" not in identity.get("arn", ""):
            continue
        if not _is_instance_local(event.get("sourceIPAddress", "")):
            return event
    return None


def rule_volumetric(events, get_threshold=100, window_seconds=60.0):
    """
    Return the event at which GetObject volume first exceeds the baseline
    threshold within a rolling window, or None.
    """
    gets = [e for e in events if e.get("eventName") == "GetObject"]
    for i, event in enumerate(gets):
        window_start = event["monotonic"] - window_seconds
        in_window = [e for e in gets[: i + 1] if e["monotonic"] >= window_start]
        if len(in_window) >= get_threshold:
            return event
    return None


def evaluate(events):
    """
    Run both rules and report, for each, whether it fired and at what
    monotonic time, plus the overall first-detection time.

    Detection latency in this simulator is the interval from the first
    anomalous API call to the first rule firing. It measures how fast the
    RULE responds once the signal exists; it is not a claim about real cloud
    provider detection-pipeline latency, which depends on log-delivery delay.
    """
    origin_hit = rule_credential_origin(events)
    volume_hit = rule_volumetric(events)

    # The first foreign-origin call is when the activity first became anomalous.
    first_anomaly = rule_credential_origin(events)
    first_anomaly_t = first_anomaly["monotonic"] if first_anomaly else None

    hits = []
    if origin_hit:
        hits.append(("credential_origin_mismatch", origin_hit["monotonic"]))
    if volume_hit:
        hits.append(("volumetric_deviation", volume_hit["monotonic"]))

    if hits and first_anomaly_t is not None:
        rule_name, hit_t = min(hits, key=lambda h: h[1])
        latency = max(0.0, hit_t - first_anomaly_t)
    else:
        rule_name, hit_t, latency = None, None, None

    # How many objects were successfully read BEFORE the detecting event. This
    # is the figure that quantifies the value of the rule: the credential-origin
    # rule fires on the first foreign call, so exfiltration is caught before any
    # object leaves, whereas the actual 2019 incident read everything.
    objects_before_detection = 0
    if hit_t is not None:
        for e in events:
            if (e.get("eventName") == "GetObject"
                    and not e.get("errorCode")
                    and e["monotonic"] < hit_t):
                objects_before_detection += 1

    return {
        "credential_origin_fired": origin_hit is not None,
        "volumetric_fired": volume_hit is not None,
        "first_rule": rule_name,
        "detection_latency_seconds": latency,
        "objects_before_detection": objects_before_detection,
        "fires_on_first_call": rule_name == "credential_origin_mismatch" and latency == 0.0,
        "detected": bool(hits),
    }

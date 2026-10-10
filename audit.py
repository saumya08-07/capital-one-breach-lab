"""
audit.py — A CloudTrail-like control-plane event log.

WHY THIS EXISTS
---------------
In the real incident, every one of the attacker's API calls WAS recorded in
CloudTrail. Capital One was collecting the telemetry. What was missing was any
rule that interpreted it. The intrusion therefore ran for roughly 129 days and
was eventually reported by an outsider who noticed the attacker's public post.

So the experiment must record events the same way a real environment would,
and then run detection rules over that record. If the log were not faithful,
a successful detection would prove nothing.

Each event mirrors the fields a CloudTrail record carries that our detection
rules actually depend on:

  eventTime        when the call happened
  eventName        the API action, e.g. GetObject
  sourceIPAddress  where the call came from  <- the origin-mismatch signal
  userIdentity     which principal made it, including session type
  requestParameters / errorCode  outcome detail
"""

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    """Thread-safe, append-only event log with a monotonic clock reference."""

    def __init__(self):
        self._events = []
        self._lock = threading.Lock()
        # Recorded so detection latency can be measured as an interval rather
        # than a wall-clock timestamp difference, which is more precise.
        self._t0 = time.perf_counter()

    def record(self, event_name, source_ip, principal_arn,
               session_type="AssumedRole", resource=None,
               error_code=None, bytes_returned=0):
        event = {
            "eventTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "monotonic": time.perf_counter() - self._t0,
            "eventSource": "s3.amazonaws.com",
            "eventName": event_name,
            "sourceIPAddress": source_ip,
            "userIdentity": {
                "type": session_type,
                "arn": principal_arn,
            },
            "requestParameters": {"resource": resource} if resource else {},
            "bytesTransferredOut": bytes_returned,
        }
        if error_code:
            event["errorCode"] = error_code
        with self._lock:
            self._events.append(event)
        return event

    @property
    def events(self):
        with self._lock:
            return list(self._events)

    def __len__(self):
        with self._lock:
            return len(self._events)

    def elapsed(self):
        """Seconds since the log was created, on the same clock as events."""
        return time.perf_counter() - self._t0

    def clear(self):
        with self._lock:
            self._events.clear()
        self._t0 = time.perf_counter()

    def write_jsonl(self, path):
        """
        Persist as JSON Lines, the format CloudTrail delivers and the format
        Athena expects, so the queries in the report would run against it.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as fh:
            for event in self.events:
                fh.write(json.dumps(event) + "\n")
        return path

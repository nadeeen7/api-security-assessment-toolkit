"""Small bounded sample, serial requests, stop immediately on 429/error."""
import math
import time
from core.risk_engine import finding

def analyze(client, path, count=5, delay=0.5, headers=None):
    if not 1 <= count <= 10 or not math.isfinite(delay) or not 0.2 <= delay <= 10:
        raise ValueError("Rate test count must be 1..10 and delay 0.2..10 seconds.")
    observations = []
    for i in range(count):
        if i:
            time.sleep(delay)
        obs = client.request("GET", path, headers=headers)
        observations.append(obs.evidence())
        if obs.status is None or obs.status == 429 or obs.status >= 500 or obs.status in (401, 403) or 300 <= obs.status < 400:
            break
    saw_429 = any(o["status"] == 429 for o in observations)
    complete = len(observations) == count and all(o["status"] is not None and 200 <= o["status"] < 300 for o in observations)
    all_404 = bool(observations) and all(o["status"] == 404 for o in observations)
    if all_404:
        title = "Rate limit path not found (HTTP 404)"
        description = (
            "The rate-limit test path returned HTTP 404 for every probe request. "
            "The endpoint does not appear to exist at this path. "
            "No rate-limit conclusion can be drawn. Configure the correct documented path."
        )
    elif saw_429:
        title = "Rate limiting observed"
        description = "This sample does not establish a global threshold or absence of protection. No further requests are sent after a stop condition."
    elif complete:
        title = "No 429 in this small sample"
        description = "This sample does not establish a global threshold or absence of protection. No further requests are sent after a stop condition."
    else:
        title = "Rate test inconclusive"
        description = "This sample does not establish a global threshold or absence of protection. No further requests are sent after a stop condition."
    confidence = "High" if saw_429 else "Low"
    return [finding(
        "rate", title, "Rate limiting", path.split("?")[0], "GET",
        description,
        {"requested_count": count, "observations": observations, "endpoint_not_found": all_404},
        "Compare with the documented quota, identity/IP bucket and time window. "
        "Verify the rate-limit path resolves to a real endpoint (non-404) before interpreting results.",
        confidence=confidence,
        classification="Observation",
    )]

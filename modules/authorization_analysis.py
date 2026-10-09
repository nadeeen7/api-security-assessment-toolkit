"""One explicit object, two users; strictly GET-only comparison; no object-ID guessing or modification.

Optional: when the BOLA case includes `login_endpoint`, `owner_credentials` and
`other_credentials`, the engine can obtain tokens via a controlled POST to the
configured login path instead of requiring pre-written token files.  This is
only permitted on loopback targets (enforced by HTTPClient.allow_post).
"""
from core.risk_engine import finding


def login_via_endpoint(client, login_endpoint, username, password, secrets):
    """POST to login_endpoint and return a Bearer-auth header dict.

    Returns None if the request fails or no token is found in the response.
    Adds the returned token to `secrets` for report scrubbing.
    Raises ValueError for non-loopback attempts (HTTPClient enforces allow_post).
    """
    obs = client.request("POST", login_endpoint,
                         json={"username": username, "password": password})
    if obs.status != 200 or not isinstance(obs.data, dict):
        return None
    token = obs.data.get("token") or obs.data.get("access_token") or obs.data.get("jwt")
    if not isinstance(token, str) or not token.strip():
        return None
    token = token.strip()
    secrets.append(token)
    return {"Authorization": "Bearer " + token}



def _extract_subject(data, field_name=None):
    if not isinstance(data, dict):
        return None
    if field_name and field_name in data and data[field_name] is not None:
        return str(data[field_name])
    for key in ("sub", "username", "user", "id", "name", "login", "subject"):
        if key in data and data[key] is not None:
            return str(data[key])
    return None


def analyze(client, case, owner_headers, other_headers):
    required = {"path", "owner_subject", "other_subject", "expected_object_id", "id_field", "owner_field", "identity_path"}
    if not required <= case.keys() or str(case["owner_subject"]) == str(case["other_subject"]):
        raise ValueError("BOLA case requires two distinct subjects, one object and identity verification.")
    if owner_headers == other_headers:
        raise ValueError("BOLA requires distinct credentials.")

    # Strictly GET requests: verify both caller identities
    a = client.request("GET", case["identity_path"], headers=owner_headers)
    b = client.request("GET", case["identity_path"], headers=other_headers)
    evidence = [a.evidence(), b.evidence()]

    owner_sub = _extract_subject(a.data, case.get("subject_field"))
    other_sub = _extract_subject(b.data, case.get("subject_field"))

    if not (a.status == b.status == 200 and owner_sub == str(case["owner_subject"])
            and other_sub == str(case["other_subject"])):
        return [], {"outcome": "Inconclusive: identity verification failed", "observations": evidence}

    # Strictly GET requests: compare object access without modifying or deleting data
    owner = client.request("GET", case["path"], headers=owner_headers)
    other = client.request("GET", case["path"], headers=other_headers)
    evidence += [owner.evidence(), other.evidence()]

    def matches(obs):
        if obs.status != 200 or not isinstance(obs.data, dict) or obs.truncated:
            return False
        id_val = obs.data.get(case["id_field"])
        owner_val = obs.data.get(case["owner_field"])
        return (id_val is not None and str(id_val) == str(case["expected_object_id"])
                and owner_val is not None and str(owner_val) == str(case["owner_subject"]))

    if matches(owner) and matches(other):
        return [finding("bola", "Potential cross-user object access (BOLA)", "Authorization",
            owner.endpoint, "GET", "Two verified test users received the configured owner's object. Confirm that sharing is prohibited by policy.",
            {"observations": evidence, "identities_verified": True, "object_and_owner_match": True},
            "Check the object's owner or access policy on every request before returning it.", "High",
            cwe="CWE-639", owasp_api="API1:2023 Broken Object Level Authorization",
            classification="Potential issue")], {"outcome": "Potential BOLA", "observations": evidence}

    if matches(owner) and other.status in (401, 403, 404):
        outcome = "Access denied for other user"
    elif matches(owner) and other.status == 200 and not matches(other):
        outcome = "Different object returned for other user"
    else:
        outcome = "Inconclusive: expected object comparison not established"

    return [], {"outcome": outcome, "observations": evidence}


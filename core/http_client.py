"""Single-origin, paced HTTP client with no redirects or automatic retries."""
import ipaddress
import math
import time
from urllib.parse import urlsplit, unquote
import requests
from core.models import Observation

MAX_BODY = 262144

def validate_path(path):
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ValueError("Endpoint must be an absolute path on the configured target.")
    parts = urlsplit(path)
    decoded = unquote(parts.path)
    if parts.scheme or parts.netloc or parts.fragment or "\\" in decoded:
        raise ValueError("External URLs, fragments and backslashes are not allowed.")
    if any(ord(c) < 32 or ord(c) == 127 for c in unquote(path)):
        raise ValueError("Control characters are not allowed.")
    if any(p in (".", "..") for p in decoded.split("/")):
        raise ValueError("Dot-segment paths are not allowed.")
    return path

class HTTPClient:
    def __init__(self, target, timeout=5, max_requests=100, delay=0.2,
                 authorized=False, allow_post=False):
        parsed = urlsplit(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Target must be an http:// or https:// origin.")
        if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("Use only scheme, host and optional port as target; paths go in endpoint lists.")
        try:
            local = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            local = False
        if not local and not authorized:
            raise ValueError("Non-loopback targets require --authorized and explicit permission.")
        if not local and parsed.scheme != "https":
            raise ValueError("Non-loopback assessments require HTTPS.")
        if not math.isfinite(timeout) or not 0.1 <= timeout <= 30:
            raise ValueError("Timeout must be 0.1 to 30 seconds.")
        if not 1 <= max_requests <= 200 or not math.isfinite(delay) or not 0.2 <= delay <= 10:
            raise ValueError("Budget must be 1..200; delay 0.2..10 seconds.")
        _ = parsed.port  # Reject invalid ports before any requests.
        self.target = target.rstrip("/")
        self.timeout, self.max_requests, self.delay = timeout, max_requests, delay
        self.count, self.last_request = 0, None
        self.allow_post, self.stopped = allow_post, None
        self.session = requests.Session()
        self.session.trust_env = False  # No ambient proxies or .netrc credentials.
        self.session.headers["User-Agent"] = "API-Security-Toolkit/1.0 (authorized assessment)"

    def close(self):
        self.session.close()

    def request(self, method, path, headers=None, json=None):
        method = method.upper()
        validate_path(path)
        if method not in {"GET", "HEAD", "OPTIONS"} and not (method == "POST" and self.allow_post):
            raise ValueError("Only GET/HEAD/OPTIONS are enabled; POST requires explicit lab use.")
        if any(k.lower() in {"host", "cookie", "proxy-authorization"} for k in (headers or {})):
            raise ValueError("Host overrides and cookie/proxy credentials are not supported.")
        safe_path = urlsplit(path).path
        if self.stopped or self.count >= self.max_requests:
            return Observation(method, safe_path, None, error=self.stopped or "Request budget reached")
        if self.last_request is not None:
            time.sleep(max(0, self.delay - (time.monotonic() - self.last_request)))
        self.count += 1
        self.last_request = time.monotonic()
        self.session.cookies.clear()  # Keep user A, user B and anonymous independent.
        try:
            with self.session.request(method, self.target + path, headers=headers, json=json,
                                      timeout=(self.timeout, self.timeout), allow_redirects=False,
                                      verify=True, stream=True) as response:
                chunks = bytearray()
                truncated = False
                for chunk in response.iter_content(chunk_size=8192):
                    room = MAX_BODY + 1 - len(chunks)
                    chunks.extend(chunk[:room])
                    if len(chunks) > MAX_BODY or time.monotonic() - self.last_request > self.timeout * 2:
                        truncated = True
                        break
                data = None
                if not truncated and "json" in response.headers.get("Content-Type", "").lower():
                    import json as jsonlib
                    try:
                        data = jsonlib.loads(chunks)
                    except (ValueError, UnicodeError, RecursionError):
                        pass
                result = Observation(method, safe_path, response.status_code,
                    {k.lower(): v for k, v in response.headers.items()}, data,
                    truncated=truncated,
                    elapsed_ms=round((time.monotonic() - self.last_request) * 1000))
                if response.status_code == 429 or response.status_code >= 500:
                    self.stopped = "Stopped after HTTP 429 or server error"
                return result
        except requests.RequestException as exc:
            # str(exc) may contain a credential-bearing URL; only retain class name.
            self.stopped = "Stopped after transport error"
            return Observation(method, safe_path, None, error=type(exc).__name__)
        finally:
            self.session.cookies.clear()

"""Acquire only the two known demo accounts. No password guessing."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.http_client import HTTPClient

def main():
    folder = Path(__file__).resolve().parents[1] / ".local"
    folder.mkdir(exist_ok=True)
    client = HTTPClient("http://127.0.0.1:5000", allow_post=True, max_requests=2)
    try:
        for username in ("alice", "bob"):
            result = client.request("POST", "/api/login", json={"username": username, "password": username + "-lab-only"})
            if result.status != 200 or not isinstance(result.data, dict) or "token" not in result.data:
                raise SystemExit("Lab login failed. Start the lab and try again. No token was printed.")
            path = folder / (username + ".token")
            path.write_text(result.data["token"], encoding="utf-8")
            try:
                path.chmod(0o600)
            except OSError:
                pass
        print("Saved Alice and Bob lab tokens under .local (valid for one hour).")
        print("Regenerate after restarting the lab. Do not share token files.")
    finally:
        client.close()

if __name__ == "__main__":
    main()

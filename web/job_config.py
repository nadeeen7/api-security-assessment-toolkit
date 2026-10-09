"""Translate a validated request into the engine's own argument namespace.

The web layer does not re-implement assessment logic or duplicate the CLI's
defaults. It writes the same inputs the CLI would read from disk and then calls
main.parser().parse_args(argv), so every default and every engine-side check is
identical to a command-line run.
"""
import json
import os
import shutil
from pathlib import Path

from main import parser

SECRETS_DIRECTORY = "secrets"


def _write_private(path, text):
    """Write a token file and restrict it as far as this platform allows."""
    path.write_text(text, encoding="utf-8")
    try:
        os.chmod(path, 0o600)  # Best effort on Windows; not an ACL guarantee.
    except OSError:
        pass


def build_engine_args(job_directory, config):
    """Create the job's inputs and return (args, secret_paths)."""
    directory = Path(job_directory)
    directory.mkdir(parents=True, exist_ok=True)
    argv = []
    secrets = []

    target = config["target"]
    if target:
        argv += ["--target", target]
        if config["authorized"]:
            argv += ["--authorized"]

    if config["openapi_text"] is not None:
        spec = directory / "openapi.json"
        spec.write_text(config["openapi_text"], encoding="utf-8")
        argv += ["--openapi", str(spec)]

    if config["endpoints_text"] is not None:
        listing = directory / "endpoints.json"
        listing.write_text(config["endpoints_text"], encoding="utf-8")
        argv += ["--endpoints", str(listing)]

    secrets_directory = directory / SECRETS_DIRECTORY
    identities = config["identities"]
    if identities:
        secrets_directory.mkdir(parents=True, exist_ok=True)
        engine_config = {"identities": {}, "default_identity": config["default_identity"]}
        engine_config["identities"] = {name: _write_identity(secrets_directory, name, identity, secrets)
                                       for name, identity in identities.items()}
        if config["bola"] is not None:
            engine_config["bola"] = config["bola"]
        config_path = directory / "config.json"
        config_path.write_text(json.dumps(engine_config), encoding="utf-8")
        argv += ["--config", str(config_path)]

    if config["bola"] is not None:
        argv += ["--bola"]

    if config["jwt_token"] is not None:
        secrets_directory.mkdir(parents=True, exist_ok=True)
        jwt_path = secrets_directory / "jwt.token"
        _write_private(jwt_path, config["jwt_token"])
        secrets.append(jwt_path)
        argv += ["--jwt-file", str(jwt_path)]

    if config["rate_limit"] is not None:
        argv += ["--rate-limit-path", config["rate_limit"]["path"],
                 "--rate-limit-count", str(config["rate_limit"]["count"]),
                 "--rate-limit-delay", str(config["rate_limit"]["delay"])]

    limits = config["limits"]
    argv += ["--timeout", str(limits["timeout"]),
             "--max-requests", str(limits["max_requests"]),
             "--delay", str(limits["delay"]),
             "--output", str(directory)]

    return parser().parse_args(argv), secrets


def _write_identity(secrets_directory, name, identity, secrets):
    """Persist one identity's credentials and return the engine config entry."""
    scheme = identity.get("scheme", "bearer")
    relative = SECRETS_DIRECTORY + "/" + name

    def store(suffix, value):
        path = secrets_directory / (name + suffix)
        _write_private(path, value)
        secrets.append(path)
        return relative + suffix

    if scheme == "bearer":
        return {"auth": {"type": "bearer", "token_file": store(".token", identity["token"])}}
    if scheme in ("api_key", "header"):
        return {"auth": {"type": scheme, "header": identity["header"],
                         "value_file": store(".value", identity["value"])}}
    if scheme == "basic":
        return {"auth": {"type": "basic",
                         "username_file": store(".user", identity["username"]),
                         "password_file": store(".pass", identity["password"])}}
    raise ValueError("unsupported identity scheme")


def clear_secrets(job_directory):
    """Remove the job's token files.

    Returns None on success (or when there was nothing to remove) and a short
    error type name when removal failed, so the caller can surface it instead of
    silently leaving credentials on disk.
    """
    directory = Path(job_directory) / SECRETS_DIRECTORY
    if not directory.exists():
        return None
    try:
        shutil.rmtree(directory)
    except OSError as exception:
        return type(exception).__name__
    return None

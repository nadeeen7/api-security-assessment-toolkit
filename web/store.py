"""Job storage: one directory per assessment plus a small newest-first index.

Nothing here knows about security. It only keeps the web layer's bookkeeping on
disk next to the engine's own report.html / report.md / evidence.json.
"""
import json
import re
import shutil
import uuid
from pathlib import Path

# A job id is always a plain uuid4 hex string, so it can never escape the root.
JOB_ID_PATTERN = re.compile(r"\A[0-9a-f]{32}\Z")
INDEX_NAME = "index.json"
INDEX_LIMIT = 100


def new_job_id():
    return uuid.uuid4().hex


def is_valid_job_id(job_id):
    return isinstance(job_id, str) and bool(JOB_ID_PATTERN.match(job_id))


def create_job_dir(root, job_id):
    directory = Path(root) / job_id
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def job_dir(root, job_id):
    """Return an existing job directory, or raise ValueError for anything else."""
    if not is_valid_job_id(job_id):
        raise ValueError("Unknown assessment id")
    directory = Path(root) / job_id
    if not directory.is_dir():
        raise ValueError("Unknown assessment id")
    return directory


import time


def write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write-then-replace so a reader never sees a half-written file.
    text = json.dumps(payload, indent=2, ensure_ascii=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    for attempt in range(5):
        try:
            temporary.replace(path)
            return
        except OSError:
            if attempt == 4:
                # If atomic replace fails on Windows due to file lock, fallback to direct write
                path.write_text(text, encoding="utf-8")
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
                return
            time.sleep(0.02)


def read_json(path):
    """Read JSON, returning None instead of raising for missing or corrupt files."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def index_path(root):
    return Path(root) / INDEX_NAME


def history(root):
    entries = read_json(index_path(root))
    return entries if isinstance(entries, list) else []


def record(root, entry):
    """Insert or update one history entry, newest first, capped at INDEX_LIMIT."""
    entries = [item for item in history(root) if item.get("job_id") != entry.get("job_id")]
    entries.insert(0, entry)
    write_json(index_path(root), entries[:INDEX_LIMIT])
    return entries


def remove(root, job_id):
    directory = job_dir(root, job_id)
    shutil.rmtree(directory, ignore_errors=True)
    remaining = [item for item in history(root) if item.get("job_id") != job_id]
    write_json(index_path(root), remaining)
    return True

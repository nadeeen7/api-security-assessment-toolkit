"""Background assessment jobs: one worker, progress events, cooperative cancel.

A job is the web layer's wrapper around a single main.run() call. State lives in
memory while the process is alive and is mirrored to job.json so history survives
a restart. Exactly one assessment runs at a time: this tool is not a flooder, and
serialising jobs keeps the request budget and pacing predictable.
"""
import threading
import time
import queue
from datetime import datetime, timezone
from pathlib import Path

from core.logger import get_logger
from main import run
from web import store
from web.job_config import build_engine_args, clear_secrets

QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"
TERMINAL = (COMPLETED, FAILED, CANCELLED)

MAX_PENDING = 5

# Messages are ours, never str(exception): an exception string can carry a
# credential-bearing URL, which is exactly why the CLI hides it too.
SAFE_MESSAGES = {
    "ValueError": "The assessment could not complete. Check the target, the input format, "
                  "the token files and the documented limits.",
    "JSONDecodeError": "The supplied OpenAPI document or endpoint list contains invalid JSON.",
    "RuntimeError": "The assessment could not complete due to an unexpected worker error.",
    "PermissionError": "A local file access lock prevented reading or writing assessment data.",
    "OSError": "A local file operation failed while preparing or writing the assessment.",
    "KeyError": "The configuration was incomplete. Check the identity and BOLA settings.",
    "TypeError": "The configuration contained an unexpected value type.",
    "RecursionError": "The supplied document nested too deeply to analyse safely.",
    "SystemExit": "The engine rejected the generated arguments.",
}


class JobCancelled(Exception):
    """Raised by the progress callback to stop an assessment between requests."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _safe_error(exception):
    name = type(exception).__name__
    return {"type": name, "message": SAFE_MESSAGES.get(name, "The assessment failed unexpectedly.")}


class JobManager:
    def __init__(self, root, engine=run):
        self.root = Path(root)
        self.engine = engine
        self._jobs = {}
        self._cancellations = {}
        self._lock = threading.RLock()
        self._queue = queue.Queue()
        self._worker = None

    # ---------------------------------------------------------------- lifecycle

    def _ensure_worker(self):
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._loop, name="assessment-worker", daemon=True)
                self._worker.start()

    def start(self, config):
        """Queue one assessment. Returns the public job record."""
        with self._lock:
            pending = sum(1 for job in self._jobs.values() if job["status"] not in TERMINAL)
            if pending >= MAX_PENDING:
                raise RuntimeError("Too many assessments are already queued.")
            job_id = store.new_job_id()
            store.create_job_dir(self.root, job_id)
            job = {
                "job_id": job_id,
                "status": QUEUED,
                "target": config["target"] or "Offline supplied files only",
                "tests_selected": list(config["tests"]),
                "created_at": _now(),
                "started_at": None,
                "finished_at": None,
                "duration_seconds": None,
                "current_phase": None,
                "progress": [],
                "summary": None,
                "error": None,
            }
            self._jobs[job_id] = job
            self._cancellations[job_id] = threading.Event()
            self._persist(job)
        self._ensure_worker()
        self._queue.put((job_id, config))
        return self.status(job_id)

    def cancel(self, job_id):
        with self._lock:
            event = self._cancellations.get(job_id)
            if event is None:
                raise ValueError("Unknown assessment id")
            event.set()
            job = self._jobs[job_id]
            if job["status"] == QUEUED:
                # Never started: remove credentials first, then finish the job so
                # a terminal record never coexists with leftover token files.
                error = self._clear_secrets(job_id)
                job["status"] = CANCELLED
                job["finished_at"] = _now()
                job["cleanup_error"] = error
                self._persist(job)
            return self.status(job_id)

    def status(self, job_id):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                return dict(job)
        stored = store.read_json(store.job_dir(self.root, job_id) / "job.json")
        if stored is None:
            raise ValueError("Unknown assessment id")
        return stored

    def history(self):
        return store.history(self.root)

    def delete(self, job_id):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None and job["status"] not in TERMINAL:
                raise ValueError("An assessment that is still running cannot be deleted.")
            self._jobs.pop(job_id, None)
            self._cancellations.pop(job_id, None)
        store.remove(self.root, job_id)
        return True

    def wait(self, job_id, timeout=120):
        """Test helper: block until a job reaches a terminal state."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.status(job_id)["status"] in TERMINAL:
                return self.status(job_id)
            time.sleep(0.1)
        raise TimeoutError("assessment did not finish in time")

    # ------------------------------------------------------------------ internals

    def _clear_secrets(self, job_id):
        """Remove token files and make any failure visible."""
        error = clear_secrets(self.root / job_id)
        if error:
            get_logger().warning("Secret cleanup failed for job %s (%s); token files may remain.", job_id, error)
        return error

    def _persist(self, job):
        store.write_json(Path(self.root) / job["job_id"] / "job.json", job)

    def _update(self, job_id, **changes):
        with self._lock:
            job = self._jobs[job_id]
            job.update(changes)
            self._persist(job)
            return dict(job)

    def _record_progress(self, job_id, phase, detail):
        with self._lock:
            job = self._jobs[job_id]
            job["current_phase"] = phase
            job["progress"].append({"phase": phase, "detail": detail, "at": _now()})
            self._persist(job)

    def _loop(self):
        while True:
            job_id, config = self._queue.get()
            try:
                self._execute(job_id, config)
            except (Exception, SystemExit) as exc:  # never let the worker die with work queued
                get_logger().exception("Assessment worker error on job %s: %s", job_id, exc)
                self._update(job_id, status=FAILED, finished_at=_now(), error=_safe_error(exc))
            finally:
                self._queue.task_done()

    def _execute(self, job_id, config):
        directory = Path(self.root) / job_id
        if self._cancellations[job_id].is_set():
            error = self._clear_secrets(job_id)
            self._update(job_id, status=CANCELLED, finished_at=_now(), cleanup_error=error)
            return

        started = time.monotonic()
        self._update(job_id, status=RUNNING, started_at=_now())

        def progress(phase, detail):
            # Cooperative cancellation: the manager raises, the engine unwinds.
            if self._cancellations[job_id].is_set():
                raise JobCancelled()
            self._record_progress(job_id, phase, detail)

        # Token files must be gone before the job is declared terminal; a failure
        # to remove them is recorded on the job rather than silently swallowed.
        try:
            args, _secrets = build_engine_args(directory, config)
            paths = self.engine(args, progress=progress, selected=set(config["tests"]))
            duration = round(time.monotonic() - started, 2)
            summary = self._summarise(directory)
            error = self._clear_secrets(job_id)
            job = self._update(job_id, status=COMPLETED, finished_at=_now(),
                               duration_seconds=duration, current_phase="report", summary=summary,
                               cleanup_error=error)
            store.record(self.root, self._index_entry(job))
            del paths
        except JobCancelled:
            error = self._clear_secrets(job_id)
            job = self._update(job_id, status=CANCELLED, finished_at=_now(),
                               duration_seconds=round(time.monotonic() - started, 2),
                               cleanup_error=error)
            store.record(self.root, self._index_entry(job))
        except (Exception, SystemExit) as exception:
            error = self._clear_secrets(job_id)
            job = self._update(job_id, status=FAILED, finished_at=_now(),
                               duration_seconds=round(time.monotonic() - started, 2),
                               error=_safe_error(exception), cleanup_error=error)
            try:
                store.record(self.root, self._index_entry(job))
            except Exception:
                pass

    def _summarise(self, directory):
        report = store.read_json(Path(directory) / "evidence.json")
        if not isinstance(report, dict):
            return None
        coverage = report.get("coverage") or {}
        metadata = report.get("metadata") or {}
        # Only the BOLA outcome is summarised here; the full observations stay in
        # evidence.json so job.json does not balloon.
        bola = coverage.get("bola")
        return {
            "severity_summary": report.get("severity_summary") or {},
            "endpoints_total": len(report.get("endpoints") or []),
            "findings_total": len(report.get("findings") or []),
            "requests_sent": coverage.get("requests_sent"),
            "stop_reason": coverage.get("stop_reason"),
            "bola": bola.get("outcome") if isinstance(bola, dict) else bola,
            "rate_test": coverage.get("rate_test"),
            "date": report.get("date"),
            "target": report.get("target"),
            "openapi_version": metadata.get("version"),
            "limitations": report.get("limitations") or [],
            "tests_selected": coverage.get("tests_selected") or [],
            "tests_executed": coverage.get("tests_executed") or [],
            "tests_skipped": coverage.get("tests_skipped") or [],
            "tests_failed": coverage.get("tests_failed") or [],
            "tests": coverage.get("tests") or [],
        }

    @staticmethod
    def _index_entry(job):
        summary = job.get("summary") or {}
        return {
            "job_id": job["job_id"],
            "target": job["target"],
            "status": job["status"],
            "created_at": job["created_at"],
            "finished_at": job.get("finished_at"),
            "duration_seconds": job.get("duration_seconds"),
            "severity_summary": summary.get("severity_summary", {}),
            "findings_total": summary.get("findings_total"),
            "endpoints_total": summary.get("endpoints_total"),
            "cleanup_error": job.get("cleanup_error"),
        }

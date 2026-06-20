"""Background crack jobs with progress tracking (aircrack-ng style ETA).

PDF and hash dictionary attacks are parallelised across all CPU cores using
``multiprocessing``. A shared stop flag halts every worker the instant a match
is found, and a shared counter feeds the existing job/progress shape so the CLI
and GUI pollers keep working unchanged.
"""

import hashlib
import io
import multiprocessing as mp
import platform
import threading
import time
import uuid

import PyPDF2

from wordlists import get_wordlist_info, iter_passwords

_jobs = {}
_lock = threading.Lock()

PROGRESS_INTERVAL = 1000
# How often each worker flushes its local attempt count into the shared counter.
_COUNTER_FLUSH = 500


def _mp_context():
    """Return a multiprocessing context.

    'fork' is used on POSIX (fast, no re-import of the main module which would
    otherwise re-trigger the console bootstrap); 'spawn' elsewhere.
    """
    if platform.system() == "Windows":
        return mp.get_context("spawn")
    try:
        return mp.get_context("fork")
    except ValueError:  # pragma: no cover - fork unavailable
        return mp.get_context("spawn")


def _cpu_count() -> int:
    try:
        return max(1, mp.cpu_count())
    except NotImplementedError:  # pragma: no cover
        return 1


def _format_duration(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def format_progress_line(elapsed, tried, total, rate):
    """Format progress like aircrack-ng."""
    if rate > 0 and total > tried:
        eta = (total - tried) / rate
        eta_str = f"~{_format_duration(eta)}"
    elif total and tried >= total:
        eta_str = "00:00:00"
    else:
        eta_str = "—"
    total_str = f"{tried:,} / {total:,}" if total else f"{tried:,}"
    return (
        f"Elapsed: {_format_duration(elapsed)} | "
        f"Tried: {total_str} | "
        f"Rate: {rate:,.0f} p/s | "
        f"ETA: {eta_str}"
    )


def _new_job(job_type, wordlist_info):
    job_id = uuid.uuid4().hex[:12]
    job = {
        'job_id': job_id,
        'type': job_type,
        'status': 'running',
        'started_at': time.time(),
        'tried': 0,
        'total': wordlist_info.get('line_count') or wordlist_info.get('entries') or 0,
        'wordlist': wordlist_info.get('name', 'unknown'),
        'wordlist_path': wordlist_info.get('path'),
        'password': None,
        'message': None,
        'error': None,
        'rate': 0.0,
        'elapsed': 0.0,
        'eta_seconds': None,
        'progress_line': '',
    }
    with _lock:
        _jobs[job_id] = job
    return job_id, job


def get_job(job_id):
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return None
        return dict(job)


def _update_progress(job_id, tried, total, start_time):
    elapsed = time.time() - start_time
    rate = tried / elapsed if elapsed > 0 else 0.0
    eta_seconds = (total - tried) / rate if rate > 0 and total > tried else None
    progress_line = format_progress_line(elapsed, tried, total, rate)
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job['tried'] = tried
        job['elapsed'] = elapsed
        job['rate'] = rate
        job['eta_seconds'] = eta_seconds
        job['progress_line'] = progress_line


def _finish_job(job_id, **fields):
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job.update(fields)
        job['status'] = fields.get('status', 'done')
        job['elapsed'] = time.time() - job['started_at']


# ──────────────────────────────────────────────────────────────────────────
# Hashing helpers (shared by workers and validation)
# ──────────────────────────────────────────────────────────────────────────
_HASHERS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
}
SUPPORTED_HASH_TYPES = tuple(_HASHERS.keys())


def _apply_salt(word: str, salt: str, salt_mode: str) -> str:
    """Combine a candidate password with a salt according to *salt_mode*."""
    if not salt:
        return word
    if salt_mode == 'prepend':
        return salt + word
    return word + salt  # default: append


def _hash_word(word: str, hash_type: str, salt: str, salt_mode: str) -> str:
    hasher = _HASHERS.get(hash_type)
    if hasher is None:
        return ''
    candidate = _apply_salt(word, salt, salt_mode)
    data = candidate.encode('utf-8', errors='surrogateescape')
    return hasher(data).hexdigest()


# ══════════════════════════════════════════════════════════════════════════
# Multiprocessing worker functions (must be top-level for picklability)
# ══════════════════════════════════════════════════════════════════════════
def _pdf_worker(pdf_bytes, wordlist_path, worker_id, num_workers, stop_event, counter, result_queue):
    """Try every (index % num_workers == worker_id) password against the PDF."""
    local = 0
    try:
        for idx, pwd in enumerate(iter_passwords(wordlist_path)):
            if idx % num_workers != worker_id:
                continue
            if stop_event.is_set():
                break
            try:
                reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
                if reader.decrypt(pwd):
                    result_queue.put(pwd)
                    stop_event.set()
                    break
            except Exception:
                pass
            local += 1
            if local >= _COUNTER_FLUSH:
                with counter.get_lock():
                    counter.value += local
                local = 0
    finally:
        if local:
            with counter.get_lock():
                counter.value += local


def _hash_worker(target_hash, hash_type, salt, salt_mode, wordlist_path,
                 worker_id, num_workers, stop_event, counter, result_queue):
    """Hash every (index % num_workers == worker_id) password and compare."""
    local = 0
    try:
        for idx, word in enumerate(iter_passwords(wordlist_path)):
            if idx % num_workers != worker_id:
                continue
            if stop_event.is_set():
                break
            if _hash_word(word, hash_type, salt, salt_mode) == target_hash:
                result_queue.put(word)
                stop_event.set()
                break
            local += 1
            if local >= _COUNTER_FLUSH:
                with counter.get_lock():
                    counter.value += local
                local = 0
    finally:
        if local:
            with counter.get_lock():
                counter.value += local


# ══════════════════════════════════════════════════════════════════════════
# Coordinators
# ══════════════════════════════════════════════════════════════════════════
def start_pdf_crack(pdf_bytes, wordlist_path):
    """Start a parallel background PDF dictionary attack. Returns job_id."""
    wl = get_wordlist_info(wordlist_path)
    if not wl['available']:
        raise FileNotFoundError("No wordlist available")

    job_id, _ = _new_job('pdf', wl)

    def _run():
        start_time = time.time()
        total = wl['line_count']
        try:
            probe = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
            if not probe.is_encrypted:
                _finish_job(
                    job_id,
                    status='error',
                    error='PDF is not encrypted',
                    message='PDF is not encrypted',
                )
                return

            ctx = _mp_context()
            stop_event = ctx.Event()
            counter = ctx.Value('Q', 0)
            result_queue = ctx.Queue()
            num_workers = _cpu_count()

            procs = [
                ctx.Process(
                    target=_pdf_worker,
                    args=(pdf_bytes, wl['path'], wid, num_workers,
                          stop_event, counter, result_queue),
                    daemon=True,
                )
                for wid in range(num_workers)
            ]
            for p in procs:
                p.start()

            while any(p.is_alive() for p in procs):
                with counter.get_lock():
                    tried = counter.value
                _update_progress(job_id, tried, total, start_time)
                time.sleep(0.4)

            for p in procs:
                p.join()

            with counter.get_lock():
                tried = counter.value

            password = None
            try:
                if not result_queue.empty():
                    password = result_queue.get_nowait()
            except Exception:
                password = None

            if password is not None:
                _update_progress(job_id, tried, total, start_time)
                _finish_job(
                    job_id,
                    status='success',
                    password=password,
                    tried=tried,
                    message=f"Password found after {tried:,} attempts",
                )
            else:
                _update_progress(job_id, tried, total, start_time)
                _finish_job(
                    job_id,
                    status='failed',
                    tried=tried,
                    message=f"Password not found in {wl['name']} ({total:,} entries)",
                )
        except Exception as exc:
            _finish_job(job_id, status='error', error=str(exc), message=str(exc))

    threading.Thread(target=_run, daemon=True).start()
    return job_id


def start_hash_crack(hash_value, hash_type, wordlist_path, salt=None, salt_mode='append'):
    """Start a parallel background hash dictionary attack. Returns job_id.

    Optional *salt* with *salt_mode* ('prepend' or 'append') is combined with
    each candidate before hashing. No salt reproduces the legacy behaviour.
    """
    wl = get_wordlist_info(wordlist_path)
    if not wl['available']:
        raise FileNotFoundError("No wordlist available")

    hash_value = hash_value.strip().lower()
    hash_type = hash_type.strip().lower()
    salt = salt or ''
    salt_mode = (salt_mode or 'append').strip().lower()
    if salt_mode not in ('prepend', 'append'):
        salt_mode = 'append'

    job_id, _ = _new_job('hash', wl)

    def _run():
        start_time = time.time()
        total = wl['line_count']
        try:
            ctx = _mp_context()
            stop_event = ctx.Event()
            counter = ctx.Value('Q', 0)
            result_queue = ctx.Queue()
            num_workers = _cpu_count()

            procs = [
                ctx.Process(
                    target=_hash_worker,
                    args=(hash_value, hash_type, salt, salt_mode, wl['path'],
                          wid, num_workers, stop_event, counter, result_queue),
                    daemon=True,
                )
                for wid in range(num_workers)
            ]
            for p in procs:
                p.start()

            while any(p.is_alive() for p in procs):
                with counter.get_lock():
                    tried = counter.value
                _update_progress(job_id, tried, total, start_time)
                time.sleep(0.4)

            for p in procs:
                p.join()

            with counter.get_lock():
                tried = counter.value

            password = None
            try:
                if not result_queue.empty():
                    password = result_queue.get_nowait()
            except Exception:
                password = None

            if password is not None:
                _update_progress(job_id, tried, total, start_time)
                _finish_job(
                    job_id,
                    status='success',
                    password=password,
                    hash_type=hash_type,
                    tried=tried,
                    message=f"Password found after {tried:,} attempts",
                )
            else:
                _update_progress(job_id, tried, total, start_time)
                _finish_job(
                    job_id,
                    status='failed',
                    hash_type=hash_type,
                    tried=tried,
                    message=f"Password not found in {wl['name']} ({total:,} entries)",
                )
        except Exception as exc:
            _finish_job(job_id, status='error', error=str(exc), message=str(exc))

    threading.Thread(target=_run, daemon=True).start()
    return job_id

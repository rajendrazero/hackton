from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import BinaryIO

from sentinel_x.redaction import redact

MAX_OUTPUT_BYTES = 5 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class ProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None
    timed_out: bool = False
    cancelled: bool = False


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _read_stream(
    stream: BinaryIO,
    output: bytearray,
    other_output: bytearray,
    output_lock: threading.Lock,
    overflow: threading.Event,
    max_output_bytes: int,
) -> None:
    while True:
        chunk = stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            return
        with output_lock:
            used = len(output) + len(other_output)
            available = max_output_bytes - used
            if len(chunk) > available:
                output.extend(chunk[:available])
                overflow.set()
            else:
                output.extend(chunk)


def run_process(
    argv: list[str],
    *,
    timeout: float,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
) -> ProcessResult:
    if not argv or timeout <= 0 or max_output_bytes <= 0:
        raise ValueError(
            "argv, a positive timeout, and a positive output limit are required"
        )

    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
            shell=False,
        )
    except OSError as exc:
        return ProcessResult(
            returncode=None,
            stdout="",
            stderr="",
            error=f"could not start {argv[0]!r}: {exc}",
        )

    if process.stdout is None or process.stderr is None:
        _terminate(process)
        raise RuntimeError("subprocess output pipes were not created")

    stdout_data = bytearray()
    stderr_data = bytearray()
    output_lock = threading.Lock()
    output_overflow = threading.Event()
    stdout_reader = threading.Thread(
        target=_read_stream,
        args=(
            process.stdout,
            stdout_data,
            stderr_data,
            output_lock,
            output_overflow,
            max_output_bytes,
        ),
        daemon=True,
    )
    stderr_reader = threading.Thread(
        target=_read_stream,
        args=(
            process.stderr,
            stderr_data,
            stdout_data,
            output_lock,
            output_overflow,
            max_output_bytes,
        ),
        daemon=True,
    )
    stdout_reader.start()
    stderr_reader.start()

    deadline = time.monotonic() + timeout
    timed_out = False
    cancelled = False
    output_limited = False
    try:
        while process.poll() is None:
            if output_overflow.is_set():
                output_limited = True
                _terminate(process)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate(process)
                break
            time.sleep(0.02)
    except KeyboardInterrupt:
        _terminate(process)
        stdout_reader.join(timeout=2)
        stderr_reader.join(timeout=2)
        cancelled = True

    returncode = process.wait()
    stdout_reader.join(timeout=2)
    stderr_reader.join(timeout=2)
    if output_overflow.is_set():
        output_limited = True

    stdout = bytes(stdout_data).decode("utf-8", errors="replace")
    stderr = bytes(stderr_data).decode("utf-8", errors="replace")
    error: str | None = None
    if timed_out:
        error = f"process exceeded {timeout:g}s timeout"
    elif cancelled:
        error = "process cancelled by user"
    elif output_limited:
        error = f"process output exceeded {max_output_bytes} bytes"
    return ProcessResult(
        returncode=returncode,
        stdout=stdout,
        stderr=redact(stderr, limit=max_output_bytes),
        error=error,
        timed_out=timed_out,
        cancelled=cancelled,
    )

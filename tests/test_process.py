from __future__ import annotations

from io import BytesIO
from typing import Any

import pytest

from sentinel_x.adapters.process import run_process


class FakeProcess:
    def __init__(
        self, stdout: bytes, stderr: bytes, returncode: int = 0
    ) -> None:
        self.returncode: int | None = returncode
        self.terminated = False
        self.stdout = BytesIO(stdout)
        self.stderr = BytesIO(stderr)

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode if self.returncode is not None else 0

    def kill(self) -> None:
        self.returncode = -9


class WaitingProcess(FakeProcess):
    def __init__(self) -> None:
        self.returncode = None
        self.terminated = False
        self.stdout = BytesIO(b"")
        self.stderr = BytesIO(b"")


def test_process_uses_argument_list_without_shell_and_reads_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invocation: dict[str, Any] = {}

    def fake_popen(argv: list[str], **kwargs: Any) -> FakeProcess:
        invocation["argv"] = argv
        invocation.update(kwargs)
        return FakeProcess(b'{"ok": true}', b"")

    monkeypatch.setattr("sentinel_x.adapters.process.subprocess.Popen", fake_popen)

    result = run_process(["scanner.exe", "--json", "path with spaces"], timeout=2)

    assert result.returncode == 0
    assert result.stdout == '{"ok": true}'
    assert invocation["argv"] == ["scanner.exe", "--json", "path with spaces"]
    assert invocation["shell"] is False
    assert invocation["stdin"] is not None


def test_output_limit_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    class LargeOutputProcess(FakeProcess):
        def __init__(
            self, stdout: bytes, stderr: bytes, returncode: int = 0
        ) -> None:
            super().__init__(stdout, stderr, returncode)

    def fake_popen(argv: list[str], **kwargs: Any) -> LargeOutputProcess:
        return LargeOutputProcess(b"123456", b"")

    monkeypatch.setattr(
        "sentinel_x.adapters.process.subprocess.Popen",
        fake_popen,
    )

    result = run_process(["scanner.exe"], timeout=2, max_output_bytes=4)

    assert "output exceeded" in (result.error or "")
    assert result.stdout == "1234"


def test_timeout_terminates_child_and_is_distinguished(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = WaitingProcess()
    monkeypatch.setattr(
        "sentinel_x.adapters.process.subprocess.Popen", lambda *args, **kwargs: process
    )
    clock = iter((0.0, 2.0))
    monkeypatch.setattr("sentinel_x.adapters.process.time.monotonic", lambda: next(clock))
    monkeypatch.setattr("sentinel_x.adapters.process.time.sleep", lambda _: None)

    result = run_process(["scanner.exe"], timeout=1)

    assert result.timed_out is True
    assert result.cancelled is False
    assert process.terminated is True


def test_keyboard_interrupt_stops_process_and_returns_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = WaitingProcess()
    monkeypatch.setattr(
        "sentinel_x.adapters.process.subprocess.Popen", lambda *args, **kwargs: process
    )
    monkeypatch.setattr("sentinel_x.adapters.process.time.monotonic", lambda: 0.0)

    def interrupt(_: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("sentinel_x.adapters.process.time.sleep", interrupt)

    result = run_process(["k6.exe", "run", "script.js"], timeout=10)

    assert result.cancelled is True
    assert result.timed_out is False
    assert "cancelled" in (result.error or "")
    assert process.terminated is True

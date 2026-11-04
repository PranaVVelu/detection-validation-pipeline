"""Shared helpers for running the pipeline's scripts as CI does: as real processes."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Iterator, List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "rules"


def run_script(name: str, *args: object) -> subprocess.CompletedProcess:
    command: List[str] = [sys.executable, str(REPO_ROOT / "scripts" / name), *map(str, args)]
    return subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)


@pytest.fixture
def siem_url() -> Iterator[str]:
    """Start a real mock SIEM with ingestion lag on a free local port."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    process = subprocess.Popen(
        [sys.executable, "-m", "dvp.siem_server", "--port", str(port), "--alert-delay", "1"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{url}/healthz", timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("mock SIEM did not start")
        yield url
    finally:
        process.terminate()
        process.wait(timeout=5)

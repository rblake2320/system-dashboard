"""Tests for BPC/TSK process health tracking."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import psutil
from core import server_health


class _Addr:
    def __init__(self, port: int):
        self.port = port


class _Conn:
    def __init__(self, port: int, pid: int, status: str = "LISTEN"):
        self.laddr = _Addr(port)
        self.pid = pid
        self.status = status


def test_pid_for_port_finds_listening_process(monkeypatch):
    monkeypatch.setattr(
        server_health.psutil,
        "net_connections",
        lambda kind="tcp": [_Conn(3100, 63264), _Conn(9999, 111)],
    )

    assert server_health._pid_for_port(3100) == 63264


def test_resolve_pid_prefers_port_listener(monkeypatch):
    monkeypatch.setattr(server_health, "_pid_for_port", lambda port: 70848)

    assert server_health._resolve_pid("tsk", 1234) == 70848


def test_check_process_adopts_new_port_listener_when_tracked_pid_dies(monkeypatch):
    def dead_process(_pid):
        raise psutil.NoSuchProcess(_pid)

    monkeypatch.setattr(server_health.psutil, "Process", dead_process)
    monkeypatch.setattr(server_health, "_pid_for_port", lambda port: 63264)
    info = {"pid": 1234, "status": "running", "crashed_at": None, "port": 3100}

    server_health._check_process(info)

    assert info["pid"] == 63264
    assert info["status"] == "running"
    assert info["crashed_at"] is None


def test_check_process_marks_crashed_when_no_pid_or_listener(monkeypatch):
    def dead_process(_pid):
        raise psutil.NoSuchProcess(_pid)

    monkeypatch.setattr(server_health.psutil, "Process", dead_process)
    monkeypatch.setattr(server_health, "_pid_for_port", lambda port: None)
    info = {"pid": 1234, "status": "running", "crashed_at": None, "port": 3100}

    server_health._check_process(info)

    assert info["status"] == "crashed"
    assert info["crashed_at"]


def test_poll_once_adopts_external_listener(monkeypatch):
    monkeypatch.setattr(server_health, "_pid_for_port", lambda port: 63264 if port == 3100 else None)
    original = server_health._state
    try:
        server_health._state = {
            "bpc": {
                "pid": None,
                "cmd": None,
                "started_at": None,
                "status": "unknown",
                "crashed_at": None,
                "port": 3100,
            }
        }

        server_health._poll_once()

        info = server_health._state["bpc"]
        assert info["pid"] == 63264
        assert info["status"] == "running"
        assert info["cmd"] == "external process on :3100"
    finally:
        server_health._state = original

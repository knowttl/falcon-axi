"""Every offline test runs with the network physically unavailable (docs/design/v1-python.md §7)."""

import os
import socket
from pathlib import Path

import pytest


class SocketUseInOfflineTest(AssertionError):
    pass


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for variable, directory in (
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
        ("APPDATA", "roaming"),
        ("LOCALAPPDATA", "local"),
    ):
        path = tmp_path / directory
        path.mkdir()
        monkeypatch.setenv(variable, str(path))
    for name in tuple(os.environ):
        if name.startswith("FALCON_"):
            monkeypatch.delenv(name)


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise SocketUseInOfflineTest("an offline test attempted to open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

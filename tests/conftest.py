"""Every offline test runs with the network physically unavailable (docs/design/v1-python.md §7)."""

import socket

import pytest


class SocketUseInOfflineTest(AssertionError):
    pass


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise SocketUseInOfflineTest("an offline test attempted to open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

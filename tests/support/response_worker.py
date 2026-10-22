"""Offline response-consumption boundary for the real deadline worker."""

import json
import sys
from collections.abc import Iterator
from threading import Event
from typing import Any
from unittest.mock import patch

import requests

from falcon_axi.transport.harness import _worker_reply


class UnfinishedBody:
    def stream(self, *args: Any, **kwargs: Any) -> Iterator[bytes]:
        yield b'{"done": false'
        sys.stderr.write("consuming response\n")
        sys.stderr.flush()
        Event().wait()


def response(*args: Any, **kwargs: Any) -> requests.Response:
    answer = requests.Response()
    answer.status_code = 200
    answer.headers["Content-Type"] = "application/json"
    if sys.argv[1] == "stall":
        answer.raw = UnfinishedBody()
    else:
        answer._content = b'{"id":"synthetic-job","done":true,"access_token":"synthetic-token"}'
    return answer


if __name__ == "__main__":
    with (
        patch("requests.sessions.Session.request", response),
        patch("socket.socket", side_effect=AssertionError("offline worker attempted network access")),
    ):
        json.dump(_worker_reply(json.load(sys.stdin)), sys.stdout)

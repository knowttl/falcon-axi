"""Execute an installed console script against synthetic HTTP, with sockets forbidden.

Run with the artifact environment's Python and -I, so neither the checkout nor
PYTHONPATH can supply falcon_axi. No released transport substitution is added.
"""

import json
import runpy
import socket
import sys
from pathlib import Path

import requests_mock

import falcon_axi


def refuse(*args, **kwargs):
    raise AssertionError("a packaged test attempted to open a socket")


socket.socket = refuse
socket.create_connection = refuse
plan = json.load(sys.stdin)
binary = Path(sys.argv[1])
assert Path(falcon_axi.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
sys.argv = [str(binary), *plan["argv"]]
with requests_mock.Mocker() as service:
    for route in plan["routes"]:
        service.register_uri(**route)
    try:
        runpy.run_path(str(binary), run_name="__main__")
    finally:
        Path(plan["history"]).write_text(
            json.dumps(
                [{"method": request.method, "path": request.path, "query": request.qs} for request in service.request_history]
            ),
            encoding="utf-8",
        )

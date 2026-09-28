"""Focused live CLI check against a disposable TLS CONNECT proxy, never a Falcon tenant.

Run with `uv run python tests/manual_cli_live.py`. All credentials and responses are synthetic.
"""

import json
import os
import shlex
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from socketserver import StreamRequestHandler, ThreadingTCPServer
from urllib.parse import parse_qs, urlsplit

EVIDENCE = os.environ.get("FALCON_AXI_TEST_EVIDENCE")
CID = "0123456789abcdef0123456789abcdef"
EVENT = {"cid": CID, "#repo.cid": CID, "ComputerName": "WIN-DC-01", "FileName": "powershell.exe"}
VULN = {
    "id": "synthetic-vuln-01",
    "cve": {"id": "CVE-2026-0001", "severity": "CRITICAL", "description": "synthetic critical vulnerability"},
    "host_info": {"hostname": "WIN-DC-01", "local_ip": "10.0.0.11"},
    "remediation": {"ids": ["synthetic-remediation-01"]},
    "status": "open",
}


class Proxy(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, certificate, key):
        super().__init__(address, Handler)
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(certificate, key)
        self.calls = []
        self.mode = "normal"


class Handler(StreamRequestHandler):
    def handle(self):
        connect = self.rfile.readline().decode("ascii").strip()
        if not connect.startswith("CONNECT "):
            raise AssertionError(connect)
        host = connect.split()[1]
        while self.rfile.readline() not in (b"\r\n", b"\n"):
            pass
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()
        with self.server.tls.wrap_socket(self.connection, server_side=True) as secure:
            incoming = secure.makefile("rb")
            start = incoming.readline().decode("ascii").strip()
            method, path, _ = start.split()
            headers = {}
            while line := incoming.readline():
                if line in (b"\r\n", b"\n"):
                    break
                name, value = line.decode("ascii").split(":", 1)
                headers[name.lower()] = value.strip()
            body = incoming.read(int(headers.get("content-length", "0")))
            query = parse_qs(urlsplit(path).query)
            self.server.calls.append((host, method, urlsplit(path).path, query, body))
            status = 200
            extra = {}
            payload = {}
            if path == "/oauth2/token":
                if self.server.mode == "unknown":
                    status = 308
                    extra = {"X-Cs-Region": "unverified-region", "Location": "https://attacker.example/oauth2/token"}
                elif self.server.mode == "missing":
                    status = 308
                    extra = {"Location": "https://attacker.example/oauth2/token"}
                elif self.server.mode == "second" or host.startswith("api.crowdstrike.com:"):
                    status = 308
                    extra = {"X-Cs-Region": "us-2", "Location": "https://attacker.example/oauth2/token"}
                else:
                    status = 201
                    payload = {"access_token": "synthetic-access-token", "expires_in": 1800}
            elif urlsplit(path).path == "/spotlight/combined/vulnerabilities/v1":
                if query.get("facet", []) in (["cve", "host_info", "remediation"], ["cve", "host_info"]):
                    record = VULN
                else:
                    record = {"id": VULN["id"], "cve": {"id": ""}}
                payload = {"resources": [record], "meta": {"pagination": {"total": 1}}}
            elif path == "/humio/api/v1/repositories/search-all/queryjobs/synthetic-job":
                payload = {
                    "done": True,
                    "cancelled": False,
                    "events": [EVENT],
                    "metaData": {
                        "eventCount": 1,
                        "processedEvents": 3,
                        "filterQuery": {"queryString": "#event_simpleName=ProcessRollup2 | head(1)"},
                    },
                }
            else:
                raise AssertionError(f"unexpected request: {method} {path}")
            data = b"" if status == 308 else json.dumps(payload).encode("utf-8")
            response = (
                f"HTTP/1.1 {status} Test\r\nContent-Length: {len(data)}\r\n"
                "Connection: close\r\nContent-Type: application/json\r\n"
            ).encode()
            for name, value in extra.items():
                response += f"{name}: {value}\r\n".encode()
            secure.sendall(response + b"\r\n" + data)


def main():
    evidence = Path(EVIDENCE) if EVIDENCE else None
    if evidence:
        evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
        root = Path(temporary)
        cert, key = root / "cert.pem", root / "key.pem"
        # Fixed commands and synthetic inputs are used only against the local test proxy.
        subprocess.run(  # noqa: S603
            [  # noqa: S607
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=api.crowdstrike.com",
                "-addext",
                "subjectAltName=DNS:api.crowdstrike.com,DNS:api.us-2.crowdstrike.com",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with Proxy(("127.0.0.1", 0), str(cert), str(key)) as proxy:
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            env = {
                "HOME": str(root),
                "PATH": os.environ["PATH"],
                "FALCON_CLIENT_ID": "synthetic-client-id",
                "FALCON_CLIENT_SECRET": "synthetic-client-secret",
                "HTTPS_PROXY": f"http://127.0.0.1:{proxy.server_address[1]}",
                "NO_PROXY": "",
                "REQUESTS_CA_BUNDLE": str(cert),
            }
            transcript = []

            def execute(label, args, expected, mode="normal"):
                proxy.mode = mode
                begin = len(proxy.calls)
                result = subprocess.run(  # noqa: S603
                    [sys.executable, "-m", "falcon_axi", *args],
                    cwd=Path.cwd(),
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=20,
                )
                calls = proxy.calls[begin:]
                assert result.returncode == expected, (label, result.stdout, result.stderr, calls)
                assert not result.stderr, (label, result.stderr)
                transcript.append((label, args, result.stdout, calls))
                return result.stdout, calls

            auth, calls = execute("D1: default region autodiscovers us-2 on 308", ["auth", "status"], 0)
            assert "re-targeted from us-1" in auth
            assert [call[0] for call in calls] == ["api.crowdstrike.com:443", "api.us-2.crowdstrike.com:443"]
            assert all("attacker" not in call[0] for call in proxy.calls)

            for mode, code, name in [
                ("unknown", "REGION_MISMATCH", "D1: unknown region refused"),
                ("missing", "ORIGIN_NOT_ALLOWED", "D1: headerless redirect refused"),
            ]:
                output, calls = execute(name, ["auth", "status"], 1, mode)
                assert f"code: {code}" in output and len(calls) == 1
            output, calls = execute("D1: repeated redirect refused", ["auth", "status"], 1, "second")
            assert "code: ORIGIN_NOT_ALLOWED" in output and len(calls) == 2

            default, calls = execute("D2: default vulnerability fields request facets", ["vuln", "list", "--status", "open"], 0)
            assert "CVE-2026-0001,CRITICAL,WIN-DC-01" in default
            assert calls[-1][3]["facet"] == ["cve", "host_info"]
            fields, calls = execute(
                "D2: selected extra fields request remediation facet",
                ["vuln", "list", "--status", "open", "--fields", "description,remediation,local_ip"],
                0,
            )
            assert "vulnerabilities[1]{id,cve,severity,hostname,description,remediation,local_ip}:" in fields
            assert "synthetic-remediation-01" in fields and "10.0.0.11" in fields
            assert calls[-1][3]["facet"] == ["cve", "host_info", "remediation"]
            output, calls = execute(
                "D2: unknown extra field fails before sending secrets",
                ["vuln", "list", "--status", "open", "--fields", "not-a-field"],
                2,
            )
            assert "code: VALIDATION_ERROR" in output and not calls

            events, calls = execute("CID: search event fields are masked", ["search", "status", "synthetic-job"], 0)
            assert "[redacted]" in events and CID not in events and "WIN-DC-01" in events
            assert len(calls) == 3 and calls[-1][2] == "/humio/api/v1/repositories/search-all/queryjobs/synthetic-job"
            assert all("attacker.example" not in call[0] for call in proxy.calls)
            if evidence:
                for index, (label, args, output, calls) in enumerate(transcript, 1):
                    shown = [(host, method, path, query) for host, method, path, query, _ in calls]
                    (evidence / f"cli-{index}.txt").write_text(
                        f"{label}\n$ python -m falcon_axi {shlex.join(args)}\n{output}\n"
                        f"HTTPS proxy requests (credential bodies omitted):\n{json.dumps(shown, indent=2)}\n"
                    )
            proxy.shutdown()
            thread.join()
    print("Real CLI completed eight isolated HTTP scenarios.")


if __name__ == "__main__":
    main()

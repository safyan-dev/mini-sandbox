"""Docker Engine API client over the Unix socket.

The controller talks to Docker through the Engine's HTTP API rather than
shelling out. This is the layer that matters for a sandbox: every restriction
we want is expressed as JSON in a request body, and the Engine turns those
fields into kernel syscalls inside the VM.

This module knows nothing about sandboxes; it only moves HTTP over the socket.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import struct
from pathlib import Path


class EngineError(RuntimeError):
    """The daemon is unreachable or the API returned an error status."""


def default_socket() -> str:
    """Find the Docker daemon socket the way the CLI would."""
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("unix://"):
        return host[len("unix://"):]

    candidates = [
        Path.home() / ".docker" / "run" / "docker.sock",
        Path("/var/run/docker.sock"),
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    return str(candidates[-1])


class _UnixHTTPConnection(http.client.HTTPConnection):
    """http.client connection that speaks HTTP over an AF_UNIX socket."""

    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._socket_path)
        except OSError as exc:
            sock.close()
            raise EngineError(
                "cannot reach Docker at %s: %s" % (self._socket_path, exc)
            ) from exc
        self.sock = sock


def demux(raw: bytes) -> tuple:
    """Split Docker's multiplexed log stream into (stdout, stderr).

    When a container is not a TTY, stdout and stderr share one stream with an
    8-byte header per frame: 1 byte stream id (1=stdout, 2=stderr), 3 padding,
    4-byte big-endian payload length.
    """
    out = bytearray()
    err = bytearray()
    index = 0
    while index + 8 <= len(raw):
        stream = raw[index]
        length = struct.unpack(">I", raw[index + 4:index + 8])[0]
        payload = raw[index + 8:index + 8 + length]
        if stream == 2:
            err.extend(payload)
        else:
            out.extend(payload)
        index += 8 + length
    return out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


class Client:
    """Minimal Docker Engine API client."""

    def __init__(self, socket_path: str | None = None, timeout: float = 60.0):
        self.socket_path = socket_path or default_socket()
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict | None = None,
        timeout: float | None = None,
    ) -> tuple:
        """Send one request. Returns (status, body_bytes)."""
        conn = _UnixHTTPConnection(self.socket_path, timeout or self.timeout)
        try:
            try:
                conn.request(method, path, body=body, headers=headers or {})
                response = conn.getresponse()
                return response.status, response.read()
            except (socket.timeout, TimeoutError) as exc:
                raise EngineError(
                    "%s %s did not finish within %.0fs"
                    % (method, path, timeout or self.timeout)
                ) from exc
        finally:
            conn.close()

    def json(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        timeout: float | None = None,
    ) -> dict:
        """Send a JSON request and decode the JSON response."""
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        status, raw = self.request(method, path, body, headers, timeout)
        if status >= 400:
            raise EngineError("%s %s -> %d: %s" % (method, path, status, _message(raw)))
        if not raw:
            return {}
        return json.loads(raw)

    def version(self) -> dict:
        return self.json("GET", "/version")


def _message(raw: bytes) -> str:
    try:
        return json.loads(raw).get("message", raw.decode("utf-8", "replace"))
    except (ValueError, AttributeError):
        return raw.decode("utf-8", "replace").strip() or "no message"

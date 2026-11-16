"""Minimal QMP unix-socket client."""
from __future__ import annotations

import json
import socket
from typing import Any


class QMP:
    def __init__(self, path: str, timeout: float = 15.0):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self._buf = b""
        try:
            greeting = self._read_obj()
            if "QMP" not in greeting:
                raise RuntimeError(f"unexpected QMP greeting: {greeting}")
            self.cmd("qmp_capabilities")
        except Exception:
            self.close()
            raise

    def _read_obj(self) -> dict[str, Any]:
        while True:
            if b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                return json.loads(line)
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("QMP socket closed")
            self._buf += chunk

    def cmd(self, execute: str, **arguments: Any) -> dict[str, Any]:
        msg: dict[str, Any] = {"execute": execute}
        if arguments:
            msg["arguments"] = arguments
        self.sock.sendall((json.dumps(msg) + "\n").encode())
        while True:
            obj = self._read_obj()
            if "event" in obj:
                continue
            return obj

    def hmp(self, command_line: str) -> str:
        reply = self.cmd("human-monitor-command", **{"command-line": command_line})
        return str(reply.get("return", ""))

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

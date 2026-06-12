from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone
from typing import Literal

DiagLevel = Literal["off", "errors", "info"]

_LEVEL_THRESHOLD: dict[DiagLevel, int] = {
    "off": 999,
    "errors": logging.ERROR,
    "info": logging.INFO,
}


class DiagnosticsBuffer:
    def __init__(self, maxlen: int = 500) -> None:
        self._ring: deque[dict] = deque(maxlen=maxlen)
        self._level: DiagLevel = "errors"
        self._seq: int = 0

    @property
    def level(self) -> DiagLevel:
        return self._level

    @level.setter
    def level(self, value: DiagLevel) -> None:
        self._level = value

    def threshold(self) -> int:
        return _LEVEL_THRESHOLD.get(self._level, 999)

    def append(self, entry: dict) -> None:
        self._seq += 1
        entry["_seq"] = self._seq
        self._ring.append(entry)

    def get_recent(self, limit: int = 200) -> list[dict]:
        entries = list(self._ring)[-limit:]
        return [{k: v for k, v in e.items() if k != "_seq"} for e in entries]

    def get_after(self, after_seq: int) -> list[dict]:
        return [
            {k: v for k, v in e.items() if k != "_seq"}
            for e in self._ring
            if e.get("_seq", 0) > after_seq
        ]

    @property
    def current_seq(self) -> int:
        return self._seq

    def clear(self) -> None:
        self._ring.clear()
        self._seq = 0


_buffer = DiagnosticsBuffer()


def get_buffer() -> DiagnosticsBuffer:
    return _buffer

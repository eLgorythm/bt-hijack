from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Device:
    address: str
    name: str | None = None
    rssi: int | None = None
    addr_type: str | None = None
    device_class: int | None = None
    services: list[str] = field(default_factory=list)
    paired: bool = False
    trusted: bool = False
    connected: bool = False
    vendor: str | None = None
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Device:
        return cls(**d)


@dataclass
class Profile:
    transport: str
    cod_major: str | None = None
    cod_minor: str | None = None
    services: list[str] = field(default_factory=list)
    le_services: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)


@dataclass
class AttackSuggestion:
    module: str
    transport: str
    name: str
    confidence: float
    notes: list[str] = field(default_factory=list)


@dataclass
class Report:
    source: str
    cmd: str
    arguments: dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    devices: list[dict[str, Any]] = field(default_factory=list)
    attacks: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def add_event(self, level: str, message: str, **fields: Any) -> None:
        entry: dict[str, Any] = {
            "t": round(time.time() - self.started_at, 3),
            "level": level,
            "msg": message,
        }
        entry.update(fields)
        self.events.append(entry)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
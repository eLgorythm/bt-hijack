from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TypeAlias

from bthj.models import Device

CapabilityBundle: TypeAlias = dict[str, bool | str | list[str]]


class BackendError(RuntimeError):
    pass


class UnsupportedBackend(BackendError):
    pass


class Backend(ABC):
    name: str = "base"
    capabilities: tuple[str, ...] = ()

    def check_capability(self, cap: str) -> bool:
        return cap in self.capabilities

    @abstractmethod
    def controller_info(self) -> CapabilityBundle:
        ...

    @abstractmethod
    def discover(self, timeout: int, passive: bool = False) -> list[Device]:
        ...

    @abstractmethod
    def set_name(self, name: str) -> None:
        ...

    @abstractmethod
    def set_class(self, device_class: int) -> None:
        ...

    @abstractmethod
    def reset_adapter(self) -> None:
        ...


def get_backend(name: str, dry_run: bool = False) -> Backend:
    if dry_run:
        return SimBackend()
    if name == "bluez" or name is None:
        from bthj.bluez_cli import BluezCLIBackend

        return BluezCLIBackend()
    if name == "sim":
        return SimBackend()
    if name == "ubertooth" or name == "nrf":
        raise UnsupportedBackend(
            f"backend '{name}' requires RF hardware and a protocol adapter; "
            "not yet wired in this build."
        )
    raise UnsupportedBackend(f"unknown backend '{name}'")


class SimBackend(Backend):
    name = "sim"
    capabilities = ("discovery", "fingerprint", "spoof_name", "classic", "ble", "hid_sink")

    def controller_info(self) -> CapabilityBundle:
        return {
            "product": "simulator",
            "hci_version": "99",
            "manufacturer": "n/a",
            "supports_le": True,
            "supports_classic": True,
            "name": "bthj-sim",
        }

    def discover(self, timeout: int, passive: bool = False) -> list[Device]:
        return [
            Device(
                address="AA:BB:CC:DD:EE:FF",
                name="sim-keyboard",
                rssi=-55,
                addr_type="public",
                device_class=0x000540,
                services=["00001800-0000-1000-8000-00805f9b34fb"],
            )
        ]

    def set_name(self, name: str) -> None:
        return None

    def set_class(self, device_class: int) -> None:
        return None

    def reset_adapter(self) -> None:
        return None
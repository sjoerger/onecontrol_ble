"""CAN bus device discovery for OneControl BLE Gateway."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

_LOGGER = logging.getLogger(__name__)


@dataclass
class DiscoveredDevice:
    """Represents a discovered CAN bus device."""

    can_address: int  # CAN bus address (0-255)
    device_id: int | None = None  # Device ID (from message type 2)
    device_type: int | None = None  # Device type byte
    product_id: int | None = None  # Product ID
    circuit_id: int | None = None  # Circuit ID
    protocol_version: int | None = None
    mac_address: bytes | None = None  # MAC address (6 bytes)
    last_seen: float = 0.0  # Timestamp of last message

    @property
    def unique_id(self) -> str:
        """Generate unique ID for this device."""
        if self.device_id is not None:
            return f"can_{self.can_address:02X}_dev_{self.device_id:04X}"
        return f"can_{self.can_address:02X}"

    @property
    def name(self) -> str:
        """Generate friendly name for this device."""
        if self.device_type is not None:
            type_name = _get_device_type_name(self.device_type)
            return f"{type_name} {self.can_address:02X}"
        return f"Device {self.can_address:02X}"


def _get_device_type_name(device_type: int) -> str:
    """Get friendly name for device type."""
    # Common device types (from C# code analysis)
    device_types = {
        0x11: "Dimmable Light",
        0x10: "Switch",
        0x20: "Cover",
        0x30: "Sensor",
        0x40: "Tank",
    }
    return device_types.get(device_type, f"Type 0x{device_type:02X}")


class CANMessageParser:
    """Parser for CAN bus messages over BLE."""

    def __init__(self, on_device_discovered: Callable[[DiscoveredDevice], None]) -> None:
        """Initialize the parser."""
        self.on_device_discovered = on_device_discovered
        self.devices: dict[int, DiscoveredDevice] = {}  # CAN address -> device

    def parse_message(self, data: bytes) -> None:
        """
        Parse a CAN message from decoded COBS data.
        
        CAN message format (from C# code):
        - First byte: Message type (0=STATUS, 1=STATUS_EX, 2=COMMAND, 3=TEXT_CONSOLE)
        - Source address is in CAN ID (extracted from BLE protocol)
        - Payload follows message type
        """
        if len(data) < 1:
            return

        message_type = data[0] & 0x1F  # Lower 5 bits
        # Note: CAN address would come from the CAN ID in the protocol layer
        # For now, we'll need to extract it from the message structure

        # Message type 2 = Device ID message
        if message_type == 0x02 and len(data) >= 7:
            self._parse_device_id(data)
        # Message type 3 = Status message
        elif message_type == 0x03:
            self._parse_status(data)

    def _parse_device_id(self, data: bytes) -> None:
        """Parse device ID message (type 2)."""
        # From C#: DeviceID = new DEVICE_ID(rx.GetUINT16(0), rx[2], rx[3], rx[6] >> 4, rx.GetUINT16(4), rx[6] & 0xF, rx[7])
        # Format: [ProductID:2][?][DeviceType][?][SessionID:2][?][Instance:4bits][?][?]
        if len(data) < 7:
            return

        product_id = int.from_bytes(data[1:3], byteorder="little")
        device_type = data[3] if len(data) > 3 else None
        # Extract more fields as needed

        # For now, create/update device entry
        # CAN address would need to come from message routing
        # This is a simplified version - full implementation needs CAN ID parsing
        _LOGGER.debug("Parsed device ID: product=0x%04X, type=0x%02X", product_id, device_type or 0)

    def _parse_status(self, data: bytes) -> None:
        """Parse status message (type 3)."""
        # Status payload is in data[1:]
        _LOGGER.debug("Status message: %s", data[1:].hex() if len(data) > 1 else "empty")


class DeviceDiscovery:
    """Manages CAN bus device discovery."""

    def __init__(self) -> None:
        """Initialize device discovery."""
        self.discovered_devices: dict[str, DiscoveredDevice] = {}
        self.parser = CANMessageParser(self._on_device_discovered)

    def _on_device_discovered(self, device: DiscoveredDevice) -> None:
        """Handle newly discovered device."""
        unique_id = device.unique_id
        if unique_id not in self.discovered_devices:
            _LOGGER.info(
                "Discovered new device: %s (CAN: 0x%02X, Type: 0x%02X)",
                device.name,
                device.can_address,
                device.device_type or 0,
            )
        self.discovered_devices[unique_id] = device

    def process_message(self, decoded_data: bytes) -> None:
        """Process a decoded COBS message."""
        self.parser.parse_message(decoded_data)

    def get_discovered_devices(self) -> list[DiscoveredDevice]:
        """Get list of all discovered devices."""
        return list(self.discovered_devices.values())


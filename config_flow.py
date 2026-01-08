"""Config flow for OneControl BLE Gateway integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS, CONF_NAME

from .const import (
    CONF_CYPHER,
    CONF_PIN,
    DEVICE_NAME_PREFIX,
    DISCOVERY_SERVICE_UUID,
    DOMAIN,
    LCI_MANUFACTURER_ID,
)

_LOGGER = logging.getLogger(__name__)


class OneControlBLEConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for OneControl BLE Gateway."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._discovered_devices: dict[str, BluetoothServiceInfoBleak] = {}
        self._pin: str | None = None

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle the bluetooth discovery step."""
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()

        if not self._is_onecontrol_gateway(discovery_info):
            return self.async_abort(reason="not_supported")

        cypher = self._extract_cypher(discovery_info)
        if not cypher:
            return self.async_abort(reason="no_cypher")

        self._discovered_devices[discovery_info.address] = discovery_info

        # Store discovery info for PIN step
        self.context["title_placeholders"] = {
            "name": discovery_info.name or discovery_info.address,
        }

        return await self.async_step_pairing_instructions()

    async def async_step_pairing_instructions(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show pairing instructions before PIN entry."""
        discovery_info = self._discovered_devices[self.unique_id]
        gateway_name = discovery_info.name or self.unique_id

        if user_input is not None:
            # User has read instructions and is ready to proceed
            return await self.async_step_pin()

        return self.async_show_form(
            step_id="pairing_instructions",
            description_placeholders={
                "name": gateway_name,
            },
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the user step to pick discovered device."""
        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            discovery_info = self._discovered_devices[address]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()

            cypher = self._extract_cypher(discovery_info)
            if not cypher:
                return self.async_abort(reason="no_cypher")

            # For user step, we need to ask for PIN too
            self._discovered_devices[address] = discovery_info
            await self.async_set_unique_id(address, raise_on_progress=False)
            self.unique_id = address
            self._pin = None  # Will be set in pin step
            return await self.async_step_pairing_instructions()

        current_addresses = self._async_current_ids()
        for discovery_info in async_discovered_service_info(self.hass):
            address = discovery_info.address
            if (
                address in current_addresses
                or address in self._discovered_devices
                or not self._is_onecontrol_gateway(discovery_info)
            ):
                continue

            cypher = self._extract_cypher(discovery_info)
            if cypher:
                self._discovered_devices[address] = discovery_info

        if not self._discovered_devices:
            return self.async_abort(reason="no_devices_found")

        # If only one device, auto-select it
        if len(self._discovered_devices) == 1:
            address = list(self._discovered_devices.keys())[0]
            discovery_info = self._discovered_devices[address]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()

            cypher = self._extract_cypher(discovery_info)
            if not cypher:
                return self.async_abort(reason="no_cypher")

            # For single device, we need to ask for PIN too
            self._discovered_devices[address] = discovery_info
            await self.async_set_unique_id(address, raise_on_progress=False)
            self.unique_id = address
            self._pin = None  # Will be set in pin step
            return await self.async_step_pairing_instructions()

        # Multiple devices - show selection
        return self.async_show_form(
            step_id="user",
            description_placeholders={
                "devices": "\n".join(
                    f"- {info.name} ({address})"
                    for address, info in self._discovered_devices.items()
                )
            },
        )

    async def async_step_pin(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle PIN entry step."""
        discovery_info = self._discovered_devices[self.unique_id]
        gateway_name = discovery_info.name or self.unique_id

        if user_input is not None:
            pin = user_input[CONF_PIN].strip()
            
            # Validate PIN format (should be 6 digits)
            if not pin.isdigit() or len(pin) != 6:
                return self.async_show_form(
                    step_id="pin",
                    data_schema=vol.Schema(
                        {
                            vol.Required(CONF_PIN, default=pin): str,
                        }
                    ),
                    description_placeholders={
                        "name": gateway_name,
                    },
                    errors={CONF_PIN: "pin_format_error"},
                )

            # Store PIN and proceed to confirm
            self._pin = pin
            return await self.async_step_confirm()

        return self.async_show_form(
            step_id="pin",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PIN): str,
                }
            ),
            description_placeholders={
                "name": gateway_name,
            },
        )

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle user-confirmation of discovered device."""
        discovery_info = self._discovered_devices[self.unique_id]
        gateway_name = discovery_info.name or self.unique_id

        if user_input is not None:
            cypher = self._extract_cypher(discovery_info)
            if not cypher:
                return self.async_abort(reason="no_cypher")

            return self.async_create_entry(
                title=gateway_name,
                data={
                    CONF_ADDRESS: self.unique_id,
                    CONF_CYPHER: cypher,
                    CONF_NAME: gateway_name,
                    CONF_PIN: self._pin,
                    "adapter": discovery_info.source,  # Track which adapter discovered it
                },
            )

        self._set_confirm_only()
        pin_status = "✅ Entered" if self._pin else "❌ Missing"
        return self.async_show_form(
            step_id="confirm",
            description_placeholders={
                "name": gateway_name,
                "address": self.unique_id,
                "pin_status": pin_status,
            },
        )

    @staticmethod
    def _is_onecontrol_gateway(discovery_info: BluetoothServiceInfoBleak) -> bool:
        """Check if device is an OneControl gateway."""
        # Check device name pattern
        if discovery_info.name:
            name_upper = discovery_info.name.upper()
            if name_upper.startswith(DEVICE_NAME_PREFIX.upper()):
                _LOGGER.debug(
                    "Found OneControl device by name: %s", discovery_info.name
                )
                return True

        # Check for OneControl BLE service UUID
        if discovery_info.service_uuids:
            if DISCOVERY_SERVICE_UUID.lower() in [
                uuid.lower() for uuid in discovery_info.service_uuids
            ]:
                _LOGGER.debug(
                    "Found OneControl device by service UUID: %s",
                    discovery_info.name,
                )
                return True

        # Check manufacturer data with LCI manufacturer ID
        if discovery_info.manufacturer_data:
            if LCI_MANUFACTURER_ID in discovery_info.manufacturer_data:
                _LOGGER.debug(
                    "Found OneControl device by manufacturer ID: %s",
                    discovery_info.name,
                )
                return True

        return False

    @staticmethod
    def _extract_cypher(discovery_info: BluetoothServiceInfoBleak) -> int | None:
        """Extract cypher from advertisement data."""
        if not discovery_info.manufacturer_data:
            _LOGGER.debug("No manufacturer data in advertisement")
            return None

        # For LCI Remote devices (manufacturer ID 1479 / 0x05C7)
        # Data format varies:
        # Format 1: 0300c301020144020230 (10 bytes)
        #   Bytes 0-1: Unknown (0300)
        #   Bytes 2-5: Cypher (c3010201 = 0x010201C3 little-endian)
        #   Bytes 6-9: Unknown (44020230)
        # Format 2: 05040c080010 (6 bytes)
        #   Bytes 0-1: Unknown (0504)
        #   Bytes 2-5: Cypher (0c080010 = 0x1000080C little-endian)

        if LCI_MANUFACTURER_ID in discovery_info.manufacturer_data:
            mfg_data = discovery_info.manufacturer_data[LCI_MANUFACTURER_ID]
            _LOGGER.debug(
                "LCI manufacturer data (hex): %s",
                mfg_data.hex() if isinstance(mfg_data, bytes) else mfg_data,
            )

            # Convert to bytes if needed
            if isinstance(mfg_data, str):
                mfg_data = bytes.fromhex(mfg_data)

            # Need at least 6 bytes (2 prefix + 4 cypher)
            if len(mfg_data) >= 6:
                # Cypher is at bytes 2-5 (little-endian) for both formats
                cypher = int.from_bytes(mfg_data[2:6], byteorder="little")
                _LOGGER.debug("Extracted cypher: 0x%08X", cypher)

                # Basic validation - cypher should be non-zero
                if cypher > 0:
                    return cypher

        _LOGGER.warning("Could not extract cypher from manufacturer data")
        return None


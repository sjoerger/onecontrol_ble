"""Light platform for OneControl BLE Gateway."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ColorMode,
    LightEntity,
    LightEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import OneControlBLECoordinator
from .device_discovery import DiscoveredDevice

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up OneControl lights from a config entry."""
    coordinator: OneControlBLECoordinator = hass.data[DOMAIN][entry.entry_id]

    # Wait a bit for device discovery to populate
    await asyncio.sleep(2.0)

    # Get discovered devices
    discovered = coordinator.get_discovered_devices()
    
    # Filter for light devices and create entities
    entities = []
    for device in discovered:
        # Check if it's a light device (device type 0x11 = dimmable, 0x10 = basic)
        if device.device_type in (0x10, 0x11):
            entities.append(OneControlLight(coordinator, device))
    
    # If no devices discovered yet, create a placeholder (will be updated when discovered)
    if not entities:
        _LOGGER.info("No lights discovered yet - will create entities as devices are discovered")
        # Optionally create a default entity that will be updated
        # entities.append(OneControlLight(coordinator, None, DEVICE_ID_INTERIOR_LIGHT))

    async_add_entities(entities)


class OneControlLight(LightEntity):
    """Representation of a OneControl light."""

    def __init__(
        self, coordinator: OneControlBLECoordinator, device: DiscoveredDevice
    ) -> None:
        """Initialize the light."""
        self.coordinator = coordinator
        self.device = device
        self._attr_name = device.name
        self._attr_unique_id = f"{coordinator.address}_{device.unique_id}"
        self._attr_color_mode = ColorMode.BRIGHTNESS if device.device_type == 0x11 else ColorMode.ONOFF
        self._attr_supported_color_modes = {self._attr_color_mode}
        self._attr_brightness = 255
        self._attr_is_on = False

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the light on."""
        brightness = kwargs.get(ATTR_BRIGHTNESS, self._attr_brightness or 255)
        
        # Command format: [command_type, can_address, brightness]
        # Command type 0x11 = Dimmable Light, 0x10 = Basic Switch
        command_type = 0x11 if self.device.device_type == 0x11 else 0x10
        command = bytes([command_type, self.device.can_address, brightness])
        
        await self.coordinator.async_send_command(command)
        self._attr_is_on = True
        if self._attr_color_mode == ColorMode.BRIGHTNESS:
            self._attr_brightness = brightness
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the light off."""
        command_type = 0x11 if self.device.device_type == 0x11 else 0x10
        command = bytes([command_type, self.device.can_address, 0x00])
        
        await self.coordinator.async_send_command(command)
        self._attr_is_on = False
        self.async_write_ha_state()


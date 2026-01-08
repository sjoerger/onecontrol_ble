"""OneControl BLE Gateway integration for Home Assistant."""

from __future__ import annotations

import logging

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import DOMAIN
from .coordinator import OneControlBLECoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.LIGHT, Platform.SWITCH, Platform.COVER, Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up OneControl BLE from a config entry."""
    coordinator = OneControlBLECoordinator(hass, entry)
    
    try:
        await coordinator.async_setup()
    except Exception as err:
        _LOGGER.error("Failed to setup OneControl BLE: %s", err)
        raise ConfigEntryNotReady(f"Failed to setup: {err}") from err
    
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator
    
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    
    if unload_ok:
        coordinator: OneControlBLECoordinator = hass.data[DOMAIN][entry.entry_id]
        await coordinator.async_shutdown()
        hass.data[DOMAIN].pop(entry.entry_id)
    
    return unload_ok


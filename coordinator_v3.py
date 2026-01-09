"""Coordinator for OneControl BLE Gateway - iOS-Style Retry Logic."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    establish_connection,
)

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import async_ble_device_from_address
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    AUTH_SERVICE_UUID,
    AUTH_STATE_FAILED,
    AUTH_STATE_LOCKED,
    AUTH_STATE_UNLOCKED,
    AUTH_TIMEOUT,
    CAN_SERVICE_UUID,
    CONF_PIN,
    CONNECTION_TIMEOUT,
    DATA_READ_CHAR_UUID,
    DATA_SERVICE_UUID,
    DATA_WRITE_CHAR_UUID,
    KEY_CHAR_UUID,
    PAIRING_TIMEOUT,
    SEED_CHAR_UUID,
    TEA_CONSTANT_1,
    TEA_CONSTANT_2,
    TEA_CONSTANT_3,
    TEA_CONSTANT_4,
    TEA_DELTA,
    TEA_ROUNDS,
    UNLOCK_CHAR_UUID,
)
from .device_discovery import DeviceDiscovery

_LOGGER = logging.getLogger(__name__)

# iOS app behavior constants
MAX_CONNECTION_ATTEMPTS = 4  # iOS app tries 4 times
RETRY_DELAY_SECONDS = 3.0  # iOS app waits ~3s between attempts
PER_ATTEMPT_TIMEOUT = 28.0  # iOS attempts take 16-29s each

# Authentication constants
HARDCODED_CIPHER = 0x8100080D
SEED_NOTIFY_CHAR_UUID = "00000011-0200-a58e-e411-afe28044e62c"
AUTH_KEY_LENGTH = 16


class OneControlBLECoordinator:
    """Coordinator for managing OneControl BLE Gateway connection."""

    def __init__(self, hass: HomeAssistant, config_entry) -> None:
        """Initialize the coordinator."""
        self.hass = hass
        self.config_entry = config_entry
        self.address = config_entry.data["address"]
        self.cypher = config_entry.data["cypher"]
        self.device_name = config_entry.data.get("name", self.address)
        self.pin = config_entry.data.get(CONF_PIN, "")
        self.adapter = config_entry.data.get("adapter")

        self.client: BleakClient | None = None
        self.auth_state = AUTH_STATE_LOCKED
        self._lock = asyncio.Lock()
        self._is_first_connection = True
        self._reconnect_task: asyncio.Task | None = None
        self.device_discovery = DeviceDiscovery()
        self._notification_handler: Callable[[int, bytes], None] | None = None
        self._connecting = False
        self._seed_received = asyncio.Event()
        self._received_seed: int | None = None

    async def async_setup(self) -> None:
        """Set up the coordinator."""
        _LOGGER.info(
            "Setting up OneControl BLE Gateway: %s (using iOS-style retry logic)",
            self.device_name,
        )

        # Validate PIN
        if not self.pin or len(self.pin) != 6 or not self.pin.isdigit():
            raise ConfigEntryNotReady(
                f"Invalid PIN format. PIN must be exactly 6 digits. Got: '{self.pin}'"
            )

        # Try initial connection with iOS-style retries
        if not await self.async_connect():
            raise ConfigEntryNotReady(
                "Failed to connect to device after multiple attempts. "
                "Please ensure the device is in pairing mode and try again."
            )

    async def async_connect(self) -> bool:
        """Connect to the BLE gateway with iOS-style retry logic."""
        async with self._lock:
            if self.client and self.client.is_connected:
                _LOGGER.debug("Already connected")
                return True

            # iOS app tries 4 times before giving up
            for attempt in range(1, MAX_CONNECTION_ATTEMPTS + 1):
                _LOGGER.info(
                    "🔄 Connection attempt %d/%d (iOS-style retry logic)",
                    attempt,
                    MAX_CONNECTION_ATTEMPTS,
                )
                
                try:
                    # On first attempt, check if device is already connected elsewhere
                    if attempt == 1:
                        await self._disconnect_if_already_connected()
                    
                    # Attempt single connection (with per-attempt timeout)
                    if await self._attempt_single_connection():
                        _LOGGER.info(
                            "✅ Successfully connected on attempt %d/%d",
                            attempt,
                            MAX_CONNECTION_ATTEMPTS,
                        )
                        self._is_first_connection = False
                        return True
                    
                except asyncio.TimeoutError:
                    _LOGGER.warning(
                        "⏱️  Attempt %d/%d timed out after %.1fs",
                        attempt,
                        MAX_CONNECTION_ATTEMPTS,
                        PER_ATTEMPT_TIMEOUT,
                    )
                except Exception as err:
                    error_str = str(err).lower()
                    # Check if this is a retry-able error (like iOS app does)
                    if any(word in error_str for word in ["authentication", "encryption", "key", "seed"]):
                        _LOGGER.warning(
                            "⚠️  Attempt %d/%d: Key/Seed exchange failed (retry-able) - %s",
                            attempt,
                            MAX_CONNECTION_ATTEMPTS,
                            err,
                        )
                    else:
                        _LOGGER.warning(
                            "⚠️  Attempt %d/%d failed: %s",
                            attempt,
                            MAX_CONNECTION_ATTEMPTS,
                            err,
                        )
                
                # Wait before retry (but not after last attempt)
                if attempt < MAX_CONNECTION_ATTEMPTS:
                    _LOGGER.info(
                        "Waiting %.1fs before retry...",
                        RETRY_DELAY_SECONDS,
                    )
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
            
            # All attempts failed
            _LOGGER.error(
                "❌ All %d connection attempts failed",
                MAX_CONNECTION_ATTEMPTS,
            )
            return False

    async def _disconnect_if_already_connected(self) -> None:
        """Disconnect device if it's already connected (iOS app does this implicitly)."""
        _LOGGER.debug("Checking if device is already connected elsewhere...")
        
        try:
            bluetoothctl_paired, bluetoothctl_connected = await self._async_check_paired_via_bluetoothctl()
            
            if bluetoothctl_connected:
                _LOGGER.warning(
                    "⚠️  Device is currently CONNECTED to another client - disconnecting..."
                )
                await self._async_disconnect_via_bluetoothctl()
                await asyncio.sleep(2.0)  # Wait for disconnect to complete
                _LOGGER.info("✅ Disconnected existing connection")
        except Exception as err:
            _LOGGER.debug("Could not check/disconnect existing connection: %s", err)

    async def _attempt_single_connection(self) -> bool:
        """Attempt a single connection (one retry attempt)."""
        self._connecting = True
        
        try:
            # Get fresh device reference
            fresh_device = async_ble_device_from_address(
                self.hass, self.address, connectable=True
            )
            if not fresh_device:
                fresh_device = async_ble_device_from_address(
                    self.hass, self.address, connectable=False
                )

            if not fresh_device:
                _LOGGER.error("Device %s not found in Bluetooth cache", self.address)
                return False
            
            # Log signal strength
            rssi = getattr(fresh_device, "rssi", None)
            if rssi is not None:
                _LOGGER.debug(f"Signal strength: {rssi} dBm")
            
            # Attempt connection with per-attempt timeout
            _LOGGER.debug(f"Attempting BLE connection (timeout: {PER_ATTEMPT_TIMEOUT}s)...")
            
            connection_start = asyncio.get_event_loop().time()
            
            self.client = await asyncio.wait_for(
                establish_connection(
                    client_class=BleakClientWithServiceCache,
                    device=fresh_device,
                    name=self.address,
                    disconnected_callback=self._on_disconnect,
                    use_services_cache=True,
                    ble_device_callback=lambda: async_ble_device_from_address(
                        self.hass, self.address, connectable=True
                    ) or async_ble_device_from_address(
                        self.hass, self.address, connectable=False
                    ),
                ),
                timeout=PER_ATTEMPT_TIMEOUT,
            )
            
            connection_time = asyncio.get_event_loop().time() - connection_start
            _LOGGER.debug(f"BLE connection established in {connection_time:.2f}s")

            if not self.client or not self.client.is_connected:
                _LOGGER.error("Connection established but client not connected")
                return False

            # Wait for service discovery
            _LOGGER.debug("Discovering services...")
            await asyncio.sleep(2.0)
            
            # Verify services are available
            if not self.client.services.services:
                _LOGGER.error("No services discovered")
                return False
            
            _LOGGER.debug(f"Discovered {len(self.client.services.services)} services")
            
            # Request MTU (iOS app does this)
            if hasattr(self.client, 'request_mtu'):
                try:
                    mtu = await self.client.request_mtu(185)
                    if mtu > 0:
                        _LOGGER.debug(f"MTU set to {mtu}")
                except Exception as mtu_err:
                    _LOGGER.debug(f"MTU request failed: {mtu_err}")
            
            # Authenticate (iOS app calls this "Key/Seed Exchange")
            _LOGGER.debug("Starting key/seed exchange (authentication)...")
            if not await self._async_authenticate():
                _LOGGER.error("Key/seed exchange failed")
                await self._async_disconnect()
                return False
            
            # Try to unlock gateway (optional - may not be required)
            if self.pin:
                _LOGGER.debug("Attempting gateway unlock with PIN...")
                if not await self._async_unlock_gateway():
                    _LOGGER.debug("Gateway unlock failed - but authentication succeeded, continuing...")
            
            # Verify connection is still stable
            if not self.client or not self.client.is_connected:
                _LOGGER.error("Device disconnected after authentication")
                return False

            # Subscribe to notifications
            await self._async_subscribe_notifications()

            _LOGGER.info("✅ Connection fully established and ready")
            return True

        except asyncio.TimeoutError:
            _LOGGER.debug("Connection attempt timed out")
            raise
        except Exception as err:
            _LOGGER.debug(f"Connection attempt error: {err}")
            raise
        finally:
            self._connecting = False

    async def _async_check_paired_via_bluetoothctl(self) -> tuple[bool, bool]:
        """Check if device is paired/connected via bluetoothctl command."""
        try:
            import subprocess
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "info", self.address,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            
            if proc.returncode != 0:
                return (False, False)
            
            output = stdout.decode().lower()
            is_paired = "paired: yes" in output
            is_connected = "connected: yes" in output
            
            return (is_paired, is_connected)
        except Exception:
            return (False, False)

    async def _async_disconnect_via_bluetoothctl(self) -> None:
        """Disconnect device via bluetoothctl."""
        try:
            import subprocess
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "disconnect", self.address,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except Exception as err:
            _LOGGER.debug(f"Error disconnecting via bluetoothctl: {err}")

    async def _async_unlock_gateway(self) -> bool:
        """Unlock the gateway using PIN (optional step)."""
        if not self.client or not self.pin:
            return False
        
        try:
            if not self.client.is_connected:
                return False
            
            can_service = self.client.services.get_service(CAN_SERVICE_UUID)
            if not can_service:
                return True  # Not all devices have this service
            
            unlock_char = can_service.get_characteristic(UNLOCK_CHAR_UUID)
            if not unlock_char:
                return True
            
            # Try to unlock
            pin_bytes = self.pin.encode('utf-8')
            try:
                await self.client.write_gatt_char(unlock_char, pin_bytes, response=True)
                await asyncio.sleep(0.5)
                return True
            except Exception as write_err:
                _LOGGER.debug(f"Unlock write failed: {write_err}")
                return True  # Don't fail connection if unlock fails
                
        except Exception:
            return True  # Don't fail connection if unlock fails

    async def _async_authenticate(self) -> bool:
        """Authenticate with the device (Key/Seed Exchange)."""
        if not self.client:
            return False

        try:
            # Get authentication service
            auth_service = self.client.services.get_service(AUTH_SERVICE_UUID)
            if not auth_service:
                _LOGGER.error("Authentication service not found")
                return False

            await asyncio.sleep(0.5)
            
            if not self.client.is_connected:
                return False
            
            # Get characteristics
            seed_notify_char = auth_service.get_characteristic(SEED_NOTIFY_CHAR_UUID)
            if not seed_notify_char:
                seed_notify_char = auth_service.get_characteristic(SEED_CHAR_UUID)
                if not seed_notify_char:
                    _LOGGER.error("Seed characteristic not found")
                    return False
            
            key_char = auth_service.get_characteristic(KEY_CHAR_UUID)
            if not key_char:
                _LOGGER.error("Key characteristic not found")
                return False

            self.auth_state = AUTH_STATE_LOCKED
            self._seed_received.clear()
            self._received_seed = None

            # Subscribe to seed notifications or read directly
            def seed_notification_handler(sender: int, data: bytearray) -> None:
                if len(data) >= 4:
                    seed = int.from_bytes(data[:4], byteorder="little")
                    _LOGGER.debug(f"Received SEED: 0x{seed:08X}")
                    self._received_seed = seed
                    self._seed_received.set()

            try:
                await self.client.start_notify(seed_notify_char, seed_notification_handler)
                await asyncio.sleep(0.5)
            except Exception:
                # Fall back to direct read
                try:
                    seed_data = await asyncio.wait_for(
                        self.client.read_gatt_char(seed_notify_char), timeout=AUTH_TIMEOUT
                    )
                    if seed_data == b"unlocked":
                        self.auth_state = AUTH_STATE_UNLOCKED
                        return True
                    if len(seed_data) >= 4:
                        self._received_seed = int.from_bytes(seed_data[:4], byteorder="little")
                        self._seed_received.set()
                except Exception as read_err:
                    _LOGGER.error(f"Could not read seed: {read_err}")
                    return False

            # Wait for seed
            if not self._seed_received.is_set():
                try:
                    await asyncio.wait_for(self._seed_received.wait(), timeout=AUTH_TIMEOUT)
                except asyncio.TimeoutError:
                    _LOGGER.error("Timeout waiting for SEED")
                    return False

            if not self.client.is_connected or self._received_seed is None:
                return False

            seed = self._received_seed
            
            # Encrypt seed using TEA
            encrypted_seed = self._tea_encrypt(HARDCODED_CIPHER, seed)

            # Build 16-byte auth key
            auth_key = bytearray(AUTH_KEY_LENGTH)
            auth_key[0:4] = encrypted_seed.to_bytes(4, byteorder="little")
            pin_bytes = self.pin.encode('ascii')
            if len(pin_bytes) != 6:
                _LOGGER.error(f"PIN must be 6 digits, got: {len(pin_bytes)}")
                return False
            auth_key[4:10] = pin_bytes

            if not self.client.is_connected:
                return False

            # Write auth key
            try:
                await self.client.write_gatt_char(key_char, bytes(auth_key), response=True)
                await asyncio.sleep(0.5)
            except Exception as write_err:
                _LOGGER.error(f"Failed to write auth key: {write_err}")
                return False

            if not self.client.is_connected:
                return False

            # Verify authentication
            try:
                verify_data = await asyncio.wait_for(
                    self.client.read_gatt_char(seed_notify_char), timeout=AUTH_TIMEOUT
                )
                
                if verify_data == b"unlocked":
                    self.auth_state = AUTH_STATE_UNLOCKED
                    return True
                else:
                    # Check if we can access protected services
                    try:
                        data_service = self.client.services.get_service(DATA_SERVICE_UUID)
                        if data_service:
                            self.auth_state = AUTH_STATE_UNLOCKED
                            return True
                    except Exception:
                        pass
                    
                    self.auth_state = AUTH_STATE_FAILED
                    return False
                    
            except Exception:
                # Some devices might not support verification - assume success
                self.auth_state = AUTH_STATE_UNLOCKED
                return True

        except Exception as err:
            _LOGGER.error(f"Authentication error: {err}")
            self.auth_state = AUTH_STATE_FAILED
            return False

    def _tea_encrypt(self, cypher: int, seed: int) -> int:
        """TEA encryption matching C# implementation."""
        delta = TEA_DELTA
        for _ in range(TEA_ROUNDS):
            seed = (
                seed
                + ((cypher << 4) + TEA_CONSTANT_1) ^ (cypher + delta) ^ ((cypher >> 5) + TEA_CONSTANT_2)
            ) & 0xFFFFFFFF
            cypher = (
                cypher
                + ((seed << 4) + TEA_CONSTANT_3) ^ (seed + delta) ^ ((seed >> 5) + TEA_CONSTANT_4)
            ) & 0xFFFFFFFF
            delta = (delta + TEA_DELTA) & 0xFFFFFFFF
        return seed

    def _on_disconnect(self, client: BleakClient) -> None:
        """Handle disconnection."""
        if self._connecting:
            return
        
        _LOGGER.warning(f"BLE device disconnected: {self.address}")
        self.auth_state = AUTH_STATE_LOCKED
        self.client = None

        if not self._is_first_connection:
            self._reconnect_task = asyncio.create_task(self._async_reconnect())

    async def _async_reconnect(self) -> None:
        """Attempt to reconnect after disconnection."""
        await asyncio.sleep(2.0)
        await self.async_connect()

    async def _async_disconnect(self) -> None:
        """Disconnect from the device."""
        if self.client:
            try:
                await self.client.disconnect()
            except Exception:
                pass
            self.client = None

    async def async_shutdown(self) -> None:
        """Shutdown the coordinator."""
        if self._reconnect_task:
            self._reconnect_task.cancel()
        await self._async_disconnect()

    async def async_send_command(self, command: bytes) -> None:
        """Send a CAN-over-BLE command."""
        if not self.client or not self.client.is_connected:
            _LOGGER.error("Cannot send command - not connected")
            return

        if self.auth_state != AUTH_STATE_UNLOCKED:
            _LOGGER.error("Cannot send command - not authenticated")
            return

        try:
            from .cobs import cobs_encode

            encoded = cobs_encode(command, prepend_start_frame=True, use_crc=True)
            
            data_service = self.client.services.get_service(DATA_SERVICE_UUID)
            if not data_service:
                _LOGGER.error("Data service not found")
                return

            write_char = data_service.get_characteristic(DATA_WRITE_CHAR_UUID)
            if not write_char:
                _LOGGER.error("Write characteristic not found")
                return

            await self.client.write_gatt_char(write_char, encoded, response=False)

        except Exception as err:
            _LOGGER.error(f"Error sending command: {err}")

    async def _async_subscribe_notifications(self) -> None:
        """Subscribe to BLE notifications for device discovery."""
        if not self.client or not self.client.is_connected:
            return

        try:
            from .cobs import cobs_decode

            data_service = self.client.services.get_service(DATA_SERVICE_UUID)
            if not data_service:
                return

            read_char = data_service.get_characteristic(DATA_READ_CHAR_UUID)
            if not read_char:
                return

            def notification_handler(sender: int, data: bytearray) -> None:
                try:
                    decoded = cobs_decode(bytes(data), use_crc=True)
                    if decoded:
                        self.device_discovery.process_message(decoded)
                except Exception as err:
                    _LOGGER.debug(f"Error processing notification: {err}")

            await self.client.start_notify(read_char, notification_handler)
            _LOGGER.debug("Subscribed to notifications")
            self._notification_handler = notification_handler

        except Exception as err:
            _LOGGER.error(f"Error subscribing to notifications: {err}")

    def get_discovered_devices(self):
        """Get list of discovered CAN bus devices."""
        return self.device_discovery.get_discovered_devices()

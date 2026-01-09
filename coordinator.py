"""Coordinator for OneControl BLE Gateway - Updated Authentication."""

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

# Updated authentication constants based on your research
HARDCODED_CIPHER = 0x8100080D  # The actual cipher used for TEA encryption
SEED_NOTIFY_CHAR_UUID = "00000011-0200-a58e-e411-afe28044e62c"  # Seed notification characteristic
AUTH_KEY_LENGTH = 16  # 16-byte auth key


class OneControlBLECoordinator:
    """Coordinator for managing OneControl BLE Gateway connection."""

    def __init__(self, hass: HomeAssistant, config_entry) -> None:
        """Initialize the coordinator."""
        self.hass = hass
        self.config_entry = config_entry
        self.address = config_entry.data["address"]
        self.cypher = config_entry.data["cypher"]  # Still extracted but may not be used for auth
        self.device_name = config_entry.data.get("name", self.address)
        self.pin = config_entry.data.get(CONF_PIN, "")  # 6-digit PIN for authentication
        self.adapter = config_entry.data.get("adapter")  # Track adapter from discovery

        self.client: BleakClient | None = None
        self.auth_state = AUTH_STATE_LOCKED
        self._lock = asyncio.Lock()
        self._is_first_connection = True
        self._reconnect_task: asyncio.Task | None = None
        self.device_discovery = DeviceDiscovery()
        self._notification_handler: Callable[[int, bytes], None] | None = None
        self._connecting = False
        self._dbus_bus = None
        self._pin_agent_path = None
        self._seed_received = asyncio.Event()  # Event to wait for seed notification
        self._received_seed: int | None = None  # Store received seed from notification

    async def async_setup(self) -> None:
        """Set up the coordinator."""
        _LOGGER.info(
            "Setting up OneControl BLE Gateway: %s (cypher from adv: 0x%08X, auth cipher: 0x%08X)",
            self.device_name,
            self.cypher,
            HARDCODED_CIPHER,
        )

        # Validate PIN
        if not self.pin or len(self.pin) != 6 or not self.pin.isdigit():
            raise ConfigEntryNotReady(
                f"Invalid PIN format. PIN must be exactly 6 digits. Got: '{self.pin}'"
            )

        # Try initial connection
        if not await self.async_connect():
            raise ConfigEntryNotReady(
                "Failed to connect to device. Please ensure the device is in pairing mode "
                "(press Connect button on RV control panel) and try again."
            )

    async def async_connect(self) -> bool:
        """Connect to the BLE gateway."""
        async with self._lock:
            if self.client and self.client.is_connected:
                _LOGGER.debug("Already connected")
                return True

            try:
                self._connecting = True
                _LOGGER.info(
                    "Connecting to %s (adapter=%s)",
                    self.address,
                    self.adapter or "auto",
                )

                # Get fresh device reference
                _LOGGER.debug("Getting fresh BLE device from HA Bluetooth integration...")
                fresh_device = async_ble_device_from_address(
                    self.hass, self.address, connectable=True
                )
                if not fresh_device:
                    _LOGGER.debug("Device not found with connectable=True, trying without...")
                    fresh_device = async_ble_device_from_address(
                        self.hass, self.address, connectable=False
                    )

                if not fresh_device:
                    _LOGGER.error(
                        "Device %s not found in Bluetooth cache. "
                        "Device may have gone out of range or stopped advertising.",
                        self.address,
                    )
                    return False
                
                # Check device properties
                rssi = getattr(fresh_device, "rssi", None)
                connectable = getattr(fresh_device, "connectable", None)
                adapter = fresh_device.details.get("source", "unknown") if hasattr(fresh_device, "details") else "unknown"
                
                _LOGGER.info(
                    "Fresh device: %s (RSSI: %s, adapter: %s, connectable: %s)",
                    fresh_device.name or self.address,
                    rssi if rssi is not None else "N/A",
                    adapter,
                    connectable if connectable is not None else "N/A",
                )
                
                # Force device to use discovery adapter if there's a mismatch
                if self.adapter and hasattr(fresh_device, "details"):
                    if adapter != self.adapter:
                        _LOGGER.warning(
                            "⚠️  Adapter mismatch: Device found on %s but discovered on %s. "
                            "Forcing adapter override.",
                            adapter,
                            self.adapter,
                        )
                        fresh_device.details["source"] = self.adapter
                        if hasattr(fresh_device, "source"):
                            fresh_device.source = self.adapter
                        _LOGGER.info("✅ Forced device to use discovery adapter: %s", self.adapter)
                
                # Warn if signal is weak
                if rssi is not None and rssi < -85:
                    _LOGGER.warning("⚠️  Weak signal detected (RSSI: %d) - device may be too far", rssi)
                
                # Check if device is already bonded
                is_already_bonded = False
                if hasattr(fresh_device, "details"):
                    is_already_bonded = fresh_device.details.get("bonded", False)
                    if is_already_bonded:
                        _LOGGER.info("✅ Device is already bonded - will skip pairing step")
                
                # Also check via bluetoothctl
                _LOGGER.debug("Checking paired/connected status via bluetoothctl...")
                try:
                    bluetoothctl_paired, bluetoothctl_connected = await self._async_check_paired_via_bluetoothctl()
                    if bluetoothctl_paired:
                        is_already_bonded = True
                        _LOGGER.info("✅ Device is already paired (via bluetoothctl)")
                        if bluetoothctl_connected:
                            _LOGGER.warning("⚠️  Device is currently CONNECTED - attempting to disconnect...")
                            try:
                                await self._async_disconnect_existing_connection()
                                await asyncio.sleep(2.0)
                                _LOGGER.info("✅ Disconnected existing connection")
                            except Exception as disconnect_err:
                                _LOGGER.warning(
                                    "Could not disconnect existing connection: %s",
                                    disconnect_err
                                )
                except Exception as check_err:
                    _LOGGER.debug("Error checking paired status: %s", check_err)
                
                # Check if using proxy adapter
                current_adapter = fresh_device.details.get("source", self.adapter) if hasattr(fresh_device, "details") else self.adapter
                is_proxy = self._is_proxy_adapter(current_adapter) or self._is_proxy_adapter(self.adapter)
                
                # Determine connection timeout
                if is_proxy:
                    connection_timeout = 30.0 if self._is_first_connection else 40.0
                    _LOGGER.info(
                        "Using proxy adapter (%s) - connection may take longer (timeout=%.1fs)...",
                        current_adapter or self.adapter,
                        connection_timeout,
                    )
                else:
                    connection_timeout = 30.0
                    _LOGGER.info(
                        "Using direct adapter (%s) - timeout=%.1fs...",
                        current_adapter or self.adapter,
                        connection_timeout,
                    )
                
                _LOGGER.info("Attempting BLE connection...")
                
                def get_ble_device_callback():
                    """Get fresh device and ensure it uses discovery adapter."""
                    device = async_ble_device_from_address(
                        self.hass, self.address, connectable=True
                    )
                    if not device:
                        device = async_ble_device_from_address(
                            self.hass, self.address, connectable=False
                        )
                    if device and self.adapter and hasattr(device, "details"):
                        if device.details.get("source") != self.adapter:
                            device.details["source"] = self.adapter
                            if hasattr(device, "source"):
                                device.source = self.adapter
                    return device
                
                connection_start_time = asyncio.get_event_loop().time()
                try:
                    self.client = await asyncio.wait_for(
                        establish_connection(
                            client_class=BleakClientWithServiceCache,
                            device=fresh_device,
                            name=self.address,
                            disconnected_callback=self._on_disconnect,
                            use_services_cache=True,
                            ble_device_callback=get_ble_device_callback,
                        ),
                        timeout=connection_timeout,
                    )
                    connection_time = asyncio.get_event_loop().time() - connection_start_time
                    _LOGGER.info("Connection established in %.2f seconds", connection_time)
                except asyncio.TimeoutError:
                    connection_time = asyncio.get_event_loop().time() - connection_start_time
                    _LOGGER.error(
                        "Connection timed out after %.2fs (timeout was %.1fs)",
                        connection_time,
                        connection_timeout
                    )
                    raise
                except Exception as conn_err:
                    connection_time = asyncio.get_event_loop().time() - connection_start_time
                    _LOGGER.error(
                        "Connection failed after %.2fs: %s",
                        connection_time,
                        conn_err,
                        exc_info=True,
                    )
                    raise

                if not self.client or not self.client.is_connected:
                    _LOGGER.error("Connection established but client not connected")
                    return False

                _LOGGER.info("✅ Connected to BLE gateway")
                
                # Wait for service discovery
                _LOGGER.info("Discovering services...")
                if not self.client or not self.client.is_connected:
                    _LOGGER.error("Device disconnected before service discovery")
                    return False
                
                await asyncio.sleep(1.0)
                
                # Request MTU
                if hasattr(self.client, 'request_mtu'):
                    try:
                        _LOGGER.info("Requesting MTU size 185...")
                        mtu = await self.client.request_mtu(185)
                        if mtu > 0:
                            _LOGGER.info("✅ MTU set to %d", mtu)
                        else:
                            _LOGGER.warning("MTU request failed, assuming default MTU 23")
                    except Exception as mtu_err:
                        _LOGGER.debug("MTU request not supported or failed: %s", mtu_err)
                
                # Unlock gateway with PIN (application-level unlock)
                if self.pin:
                    _LOGGER.info("Unlocking gateway with PIN (application-level unlock)...")
                    if not await self._async_unlock_gateway():
                        _LOGGER.warning("Failed to unlock gateway with PIN - continuing anyway")
                
                # Verify connection is still stable
                if not self.client or not self.client.is_connected:
                    _LOGGER.error("Device disconnected before authentication")
                    return False
                
                # Authenticate using 16-byte auth key
                if not await self._async_authenticate():
                    _LOGGER.error("Authentication failed")
                    await self._async_disconnect()
                    return False

                # Subscribe to notifications for device discovery
                await self._async_subscribe_notifications()

                self._is_first_connection = False
                self._connecting = False
                return True

            except asyncio.TimeoutError:
                self._connecting = False
                _LOGGER.error("Connection timeout")
                return False
            except Exception as err:
                self._connecting = False
                _LOGGER.error(
                    "Connection error: %s",
                    err,
                    exc_info=True,
                )
                return False

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
                _LOGGER.debug("bluetoothctl info failed: %s", stderr.decode())
                return (False, False)
            
            output = stdout.decode().lower()
            is_paired = "paired: yes" in output
            is_connected = "connected: yes" in output
            
            _LOGGER.debug("bluetoothctl check - paired: %s, connected: %s", is_paired, is_connected)
            return (is_paired, is_connected)
        except asyncio.TimeoutError:
            _LOGGER.debug("bluetoothctl info timed out")
            return (False, False)
        except Exception as err:
            _LOGGER.debug("Error checking paired status via bluetoothctl: %s", err)
            return (False, False)

    async def _async_disconnect_existing_connection(self) -> None:
        """Disconnect device if it's currently connected to another client."""
        try:
            import subprocess
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "disconnect", self.address,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            if proc.returncode == 0:
                _LOGGER.info("✅ Device disconnected via bluetoothctl")
            else:
                error_output = stderr.decode() if stderr else stdout.decode()
                _LOGGER.warning(f"bluetoothctl disconnect returned code {proc.returncode}: {error_output}")
        except Exception as err:
            _LOGGER.warning(f"Error disconnecting via bluetoothctl: {err}")
        
        await asyncio.sleep(3.0)

    def _is_proxy_adapter(self, adapter: str | None) -> bool:
        """Check if adapter is a Bluetooth proxy (ESP32/ESPHome)."""
        if not adapter:
            return False
        
        if adapter.startswith("hci"):
            return False
        
        if ":" in adapter:
            return False
        
        return False

    async def _async_unlock_gateway(self) -> bool:
        """Unlock the gateway using PIN (application-level unlock)."""
        if not self.client or not self.pin:
            return False
        
        _LOGGER.info("Unlocking gateway with PIN...")
        
        try:
            can_service = self.client.services.get_service(CAN_SERVICE_UUID)
            if not can_service:
                _LOGGER.debug("CAN service not found - device may not require unlock")
                return False
            
            unlock_char = can_service.get_characteristic(UNLOCK_CHAR_UUID)
            if not unlock_char:
                _LOGGER.warning("Unlock characteristic not found")
                return False
            
            # Check if already unlocked
            try:
                unlock_data = await asyncio.wait_for(
                    self.client.read_gatt_char(unlock_char), timeout=5.0
                )
                if unlock_data and len(unlock_data) > 0 and unlock_data[0] > 0:
                    _LOGGER.info("Gateway already unlocked")
                    return True
            except Exception as read_err:
                _LOGGER.debug("Could not read unlock status: %s", read_err)
            
            # Write PIN as UTF-8 bytes
            pin_bytes = self.pin.encode('utf-8')
            _LOGGER.debug("Writing PIN to unlock characteristic")
            
            write_success = False
            for attempt in range(2):
                try:
                    await self.client.write_gatt_char(unlock_char, pin_bytes, response=True)
                    write_success = True
                    break
                except Exception as write_err:
                    if attempt == 1:
                        _LOGGER.warning("Failed to write unlock characteristic: %s", write_err)
                    else:
                        _LOGGER.debug("Unlock write attempt %d failed: %s", attempt + 1, write_err)
            
            if not write_success:
                return False
            
            await asyncio.sleep(1.0)
            
            # Verify unlock
            verify_data = await asyncio.wait_for(
                self.client.read_gatt_char(unlock_char), timeout=5.0
            )
            
            if verify_data and len(verify_data) > 0 and verify_data[0] > 0:
                _LOGGER.info("✅ Gateway unlocked successfully")
                return True
            else:
                _LOGGER.warning("Gateway unlock verification failed")
                return False
                
        except Exception as err:
            _LOGGER.warning("Unlock error: %s", err)
            return False

    async def _async_authenticate(self) -> bool:
        """
        Authenticate with the device using 16-byte auth key.
        
        Protocol:
        1. Subscribe to seed notification characteristic (00000011)
        2. Gateway sends random SEED value (4 bytes) via notification
        3. Encrypt SEED using TEA with hardcoded cipher (0x8100080D)
        4. Build 16-byte auth key:
           - Bytes 0-3: TEA-encrypted SEED
           - Bytes 4-9: User's 6-digit PIN (as ASCII bytes)
           - Bytes 10-15: Padding (zeros)
        5. Write auth key to characteristic 00000013
        6. Gateway validates and grants access
        """
        if not self.client:
            return False

        _LOGGER.info("Authenticating with 16-byte auth key (cipher: 0x%08X, PIN: %s)...", 
                     HARDCODED_CIPHER, self.pin)

        try:
            # Ensure services are discovered
            if not self.client.services.services:
                _LOGGER.info("Services not discovered yet, waiting...")
                max_wait = 20 if self._is_proxy_adapter(self.adapter) else 10
                for attempt in range(max_wait):
                    await asyncio.sleep(0.5)
                    if self.client.services.services:
                        _LOGGER.info("Services discovered after %d attempts", attempt + 1)
                        break
                else:
                    _LOGGER.error("Service discovery timeout")
                    return False
            
            # Get authentication service
            auth_service = self.client.services.get_service(AUTH_SERVICE_UUID)
            if not auth_service:
                _LOGGER.error("Authentication service not found. Available services: %s", 
                            [str(s.uuid) for s in self.client.services.services])
                return False

            # Wait 500ms after getting service
            await asyncio.sleep(0.5)
            
            # Get seed notification characteristic (00000011)
            seed_notify_char = auth_service.get_characteristic(SEED_NOTIFY_CHAR_UUID)
            if not seed_notify_char:
                _LOGGER.error("Seed notification characteristic (0x11) not found")
                # Fall back to trying the read characteristic
                seed_notify_char = auth_service.get_characteristic(SEED_CHAR_UUID)
                if not seed_notify_char:
                    _LOGGER.error("No seed characteristic found at all")
                    return False
                _LOGGER.info("Using seed read characteristic (0x12) instead of notification (0x11)")
            
            # Get key write characteristic (00000013)
            key_char = auth_service.get_characteristic(KEY_CHAR_UUID)
            if not key_char:
                _LOGGER.error("Key characteristic not found")
                return False

            self.auth_state = AUTH_STATE_LOCKED
            self._seed_received.clear()
            self._received_seed = None

            # Subscribe to seed notifications
            def seed_notification_handler(sender: int, data: bytearray) -> None:
                """Handle seed notification."""
                try:
                    if len(data) >= 4:
                        seed = int.from_bytes(data[:4], byteorder="little")
                        _LOGGER.info("📨 Received SEED notification: 0x%08X", seed)
                        self._received_seed = seed
                        self._seed_received.set()
                    else:
                        _LOGGER.warning("Seed notification too short: %s", data.hex())
                except Exception as err:
                    _LOGGER.error("Error processing seed notification: %s", err)

            try:
                _LOGGER.info("Subscribing to seed notifications on characteristic 0x11...")
                await self.client.start_notify(seed_notify_char, seed_notification_handler)
                _LOGGER.info("✅ Subscribed to seed notifications")
            except Exception as notify_err:
                _LOGGER.warning("Could not subscribe to notifications: %s", notify_err)
                # Try reading seed directly instead
                _LOGGER.info("Falling back to reading seed directly...")
                try:
                    seed_data = await asyncio.wait_for(
                        self.client.read_gatt_char(seed_notify_char), timeout=AUTH_TIMEOUT
                    )
                    if seed_data == b"unlocked":
                        _LOGGER.info("Device already unlocked")
                        self.auth_state = AUTH_STATE_UNLOCKED
                        return True
                    if len(seed_data) >= 4:
                        self._received_seed = int.from_bytes(seed_data[:4], byteorder="little")
                        _LOGGER.info("📖 Read SEED directly: 0x%08X", self._received_seed)
                        self._seed_received.set()
                except Exception as read_err:
                    _LOGGER.error("Could not read seed: %s", read_err)
                    return False

            # Wait for seed notification (or use direct read result)
            if not self._seed_received.is_set():
                _LOGGER.info("Waiting for SEED notification (timeout: %ds)...", AUTH_TIMEOUT)
                try:
                    await asyncio.wait_for(self._seed_received.wait(), timeout=AUTH_TIMEOUT)
                except asyncio.TimeoutError:
                    _LOGGER.error("Timeout waiting for SEED notification")
                    return False

            if self._received_seed is None:
                _LOGGER.error("No seed received")
                return False

            seed = self._received_seed
            _LOGGER.info("Using SEED: 0x%08X", seed)

            # Encrypt seed using TEA with hardcoded cipher
            encrypted_seed = self._tea_encrypt(HARDCODED_CIPHER, seed)
            _LOGGER.info("Encrypted SEED: 0x%08X (cipher: 0x%08X)", encrypted_seed, HARDCODED_CIPHER)

            # Build 16-byte auth key
            auth_key = bytearray(AUTH_KEY_LENGTH)
            
            # Bytes 0-3: TEA-encrypted SEED (little-endian)
            auth_key[0:4] = encrypted_seed.to_bytes(4, byteorder="little")
            
            # Bytes 4-9: User's 6-digit PIN (as ASCII bytes)
            pin_bytes = self.pin.encode('ascii')
            if len(pin_bytes) != 6:
                _LOGGER.error("PIN must be exactly 6 digits, got: %d", len(pin_bytes))
                return False
            auth_key[4:10] = pin_bytes
            
            # Bytes 10-15: Padding (zeros) - already initialized to zeros
            
            _LOGGER.info("Built 16-byte auth key: %s", auth_key.hex())
            _LOGGER.debug("  Encrypted SEED (0-3): %s", auth_key[0:4].hex())
            _LOGGER.debug("  PIN (4-9): %s ('%s')", auth_key[4:10].hex(), self.pin)
            _LOGGER.debug("  Padding (10-15): %s", auth_key[10:16].hex())

            # Write auth key to characteristic 00000013
            _LOGGER.info("Writing 16-byte auth key to characteristic 0x13...")
            await self.client.write_gatt_char(key_char, bytes(auth_key), response=True)
            await asyncio.sleep(0.5)  # Wait after write

            # Verify authentication - try reading seed characteristic again
            # If authenticated, it should return "unlocked" or similar success indicator
            _LOGGER.info("Verifying authentication...")
            try:
                verify_data = await asyncio.wait_for(
                    self.client.read_gatt_char(seed_notify_char), timeout=AUTH_TIMEOUT
                )
                
                if verify_data == b"unlocked":
                    _LOGGER.info("✅ Authentication successful - device unlocked")
                    self.auth_state = AUTH_STATE_UNLOCKED
                    return True
                else:
                    # Some devices might not return "unlocked" - check if we can access protected characteristics
                    _LOGGER.info("Verify data: %s - checking if authentication succeeded...", verify_data.hex())
                    # Try accessing a protected characteristic to verify
                    try:
                        data_service = self.client.services.get_service(DATA_SERVICE_UUID)
                        if data_service:
                            _LOGGER.info("✅ Can access data service - authentication appears successful")
                            self.auth_state = AUTH_STATE_UNLOCKED
                            return True
                    except Exception:
                        pass
                    
                    _LOGGER.error("Authentication verification failed - expected 'unlocked', got: %s", verify_data.hex())
                    self.auth_state = AUTH_STATE_FAILED
                    return False
                    
            except Exception as verify_err:
                _LOGGER.warning("Could not verify authentication: %s", verify_err)
                # Try to proceed anyway - some devices might not support verification
                _LOGGER.info("Attempting to proceed without verification...")
                self.auth_state = AUTH_STATE_UNLOCKED
                return True

        except asyncio.TimeoutError:
            _LOGGER.error("Authentication timeout")
            self.auth_state = AUTH_STATE_FAILED
            return False
        except Exception as err:
            _LOGGER.error("Authentication error: %s", err, exc_info=True)
            self.auth_state = AUTH_STATE_FAILED
            return False

    def _tea_encrypt(self, cypher: int, seed: int) -> int:
        """
        TEA encryption as implemented in C# BleDeviceUnlockManager.cs.
        
        Key difference from standard TEA: delta is accumulated, not recalculated.
        """
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
            _LOGGER.debug("Disconnect during connection attempt (normal during retries)")
            return
        
        _LOGGER.warning("BLE device disconnected: %s", self.address)
        self.auth_state = AUTH_STATE_LOCKED
        self.client = None

        if not self._is_first_connection:
            _LOGGER.info("Will attempt to reconnect...")
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
            _LOGGER.debug("Command: %s -> Encoded: %s", command.hex(), encoded.hex())

            data_service = self.client.services.get_service(DATA_SERVICE_UUID)
            if not data_service:
                _LOGGER.error("Data service not found")
                return

            write_char = data_service.get_characteristic(DATA_WRITE_CHAR_UUID)
            if not write_char:
                _LOGGER.error("Write characteristic not found")
                return

            await self.client.write_gatt_char(write_char, encoded, response=False)
            _LOGGER.debug("Sent COBS-encoded command")

        except Exception as err:
            _LOGGER.error("Error sending command: %s", err, exc_info=True)

    async def _async_subscribe_notifications(self) -> None:
        """Subscribe to BLE notifications for device discovery."""
        if not self.client or not self.client.is_connected:
            return

        try:
            from .cobs import cobs_decode

            data_service = self.client.services.get_service(DATA_SERVICE_UUID)
            if not data_service:
                _LOGGER.error("Data service not found for notifications")
                return

            read_char = data_service.get_characteristic(DATA_READ_CHAR_UUID)
            if not read_char:
                _LOGGER.error("Read characteristic not found for notifications")
                return

            def notification_handler(sender: int, data: bytearray) -> None:
                """Handle incoming BLE notifications."""
                try:
                    decoded = cobs_decode(bytes(data), use_crc=True)
                    if decoded:
                        _LOGGER.debug("Received notification: %s", decoded.hex())
                        self.device_discovery.process_message(decoded)
                    else:
                        _LOGGER.debug("Failed to decode COBS frame")
                except Exception as err:
                    _LOGGER.warning("Error processing notification: %s", err)

            await self.client.start_notify(read_char, notification_handler)
            _LOGGER.info("✅ Subscribed to notifications for device discovery")
            self._notification_handler = notification_handler

        except Exception as err:
            _LOGGER.error("Error subscribing to notifications: %s", err, exc_info=True)

    def get_discovered_devices(self):
        """Get list of discovered CAN bus devices."""
        return self.device_discovery.get_discovered_devices()

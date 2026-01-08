"""Coordinator for OneControl BLE Gateway."""

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


class OneControlBLECoordinator:
    """Coordinator for managing OneControl BLE Gateway connection."""

    def __init__(self, hass: HomeAssistant, config_entry) -> None:
        """Initialize the coordinator."""
        self.hass = hass
        self.config_entry = config_entry
        self.address = config_entry.data["address"]
        self.cypher = config_entry.data["cypher"]
        self.device_name = config_entry.data.get("name", self.address)
        self.pin = config_entry.data.get(CONF_PIN, "")  # PIN for legacy gateway pairing
        self.adapter = config_entry.data.get("adapter")  # Track adapter from discovery

        self.client: BleakClient | None = None
        self.auth_state = AUTH_STATE_LOCKED
        self._lock = asyncio.Lock()
        self._is_first_connection = True
        self._reconnect_task: asyncio.Task | None = None
        self.device_discovery = DeviceDiscovery()
        self._notification_handler: Callable[[int, bytes], None] | None = None
        self._connecting = False  # Track if we're in the middle of connecting
        self._dbus_bus = None  # D-Bus connection for PIN agent
        self._pin_agent_path = None  # Path of registered PIN agent

    async def async_setup(self) -> None:
        """Set up the coordinator."""
        _LOGGER.info(
            "Setting up OneControl BLE Gateway: %s (cypher: 0x%08X)",
            self.device_name,
            self.cypher,
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
                self._connecting = True  # Mark that we're connecting
                _LOGGER.info(
                    "Connecting to %s (adapter=%s)",
                    self.address,
                    self.adapter or "auto",
                )

                # Get a FRESH device reference right before connecting (like working v7)
                # This ensures we get the most up-to-date device info from the correct adapter
                # For already-paired devices, don't require connectable=True - bonded devices
                # can be connected even if not actively advertising (C# uses PairingMethod.None)
                _LOGGER.debug("Getting fresh BLE device from HA Bluetooth integration...")
                # Try with connectable=True first (for devices in pairing mode or actively advertising)
                fresh_device = async_ble_device_from_address(
                    self.hass, self.address, connectable=True
                )
                # If not found, try without connectable requirement (bonded devices may not be advertising)
                # C# code can connect to bonded devices even if not actively advertising
                if not fresh_device:
                    _LOGGER.debug("Device not found with connectable=True, trying without (may be bonded but not advertising)...")
                    fresh_device = async_ble_device_from_address(
                        self.hass, self.address, connectable=False
                    )

                if not fresh_device:
                    _LOGGER.error(
                        "Device %s not found in Bluetooth cache. "
                        "Device may have gone out of range or stopped advertising. "
                        "Ensure device is powered on and in pairing mode.",
                        self.address,
                    )
                    _LOGGER.error(
                        "TIP: If device requires pairing, pair it manually first:\n"
                        "  ssh root@homeassistant.local -p 22222\n"
                        "  bluetoothctl\n"
                        "  # Press Connect button on RV, then:\n"
                        "  pair 24:DC:C3:ED:1E:0A\n"
                        "  trust 24:DC:C3:ED:1E:0A"
                    )
                    return False
                
                # Check device properties for diagnostics
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
                
                # CRITICAL: Force device to use discovery adapter if there's a mismatch
                # The device may only be connectable on the adapter where it was discovered
                if self.adapter and hasattr(fresh_device, "details"):
                    if adapter != self.adapter:
                        _LOGGER.warning(
                            "⚠️  Adapter mismatch: Device found on %s but discovered on %s. "
                            "Forcing adapter override - device may only be connectable on discovery adapter.",
                            adapter,
                            self.adapter,
                        )
                        # Override the source to force connection via discovery adapter
                        fresh_device.details["source"] = self.adapter
                        if hasattr(fresh_device, "source"):
                            fresh_device.source = self.adapter
                        _LOGGER.info("✅ Forced device to use discovery adapter: %s", self.adapter)
                    else:
                        _LOGGER.info("✅ Device already on discovery adapter: %s", adapter)
                
                # Warn if signal is weak
                if rssi is not None and rssi < -85:
                    _LOGGER.warning("⚠️  Weak signal detected (RSSI: %d) - device may be too far", rssi)
                
                # Check if device is already paired/bonded
                # Try HA details first, then D-Bus check (but don't fail if D-Bus check fails)
                is_already_bonded = False
                if hasattr(fresh_device, "details"):
                    is_already_bonded = fresh_device.details.get("bonded", False)
                    if is_already_bonded:
                        _LOGGER.info("✅ Device is already bonded (from HA details) - will skip pairing step")
                
                # Also check via D-Bus (more reliable, especially for direct adapters)
                # But don't fail if D-Bus check fails - device might be paired but not registered in D-Bus
                device_is_connected_elsewhere = False
                # CRITICAL: bluetoothctl shows "Connected: yes" - device is connected somewhere
                # Even if D-Bus can't find it, we should try to disconnect before connecting
                # This handles the case where device is connected but not registered in D-Bus
                _LOGGER.debug("Checking paired/connected status via D-Bus...")
                try:
                    is_paired, is_connected = await self._async_check_paired()
                    if is_paired:
                        is_already_bonded = True
                        _LOGGER.info("✅ Device is already paired (via D-Bus) - will skip pairing step")
                        if is_connected:
                            device_is_connected_elsewhere = True
                            _LOGGER.warning(
                                "⚠️  Device is currently CONNECTED to another client. "
                                "BLE devices typically only allow one connection at a time. "
                                "Attempting to disconnect existing connection..."
                            )
                            # Disconnect existing connection before attempting new one
                            try:
                                await self._async_disconnect_existing_connection()
                                # Wait a moment for disconnect to complete
                                await asyncio.sleep(2.0)
                                _LOGGER.info("✅ Disconnected existing connection - ready for new connection")
                            except Exception as disconnect_err:
                                _LOGGER.warning(
                                    "Could not disconnect existing connection: %s. "
                                    "You may need to manually disconnect from the OneControl app on your phone.",
                                    disconnect_err
                                )
                    else:
                        _LOGGER.debug("D-Bus check: device not found or not paired - checking bluetoothctl as fallback...")
                        # D-Bus can't find device, but it might still be paired (bluetoothctl shows it)
                        # Check bluetoothctl to verify actual pairing status
                        bluetoothctl_paired, bluetoothctl_connected = await self._async_check_paired_via_bluetoothctl()
                        if bluetoothctl_paired:
                            is_already_bonded = True
                            _LOGGER.info("✅ Device is already paired (via bluetoothctl fallback) - will skip pairing step")
                            if bluetoothctl_connected:
                                device_is_connected_elsewhere = True
                                _LOGGER.warning(
                                    "⚠️  Device is currently CONNECTED (per bluetoothctl). "
                                    "Attempting to disconnect existing connection..."
                                )
                                try:
                                    await self._async_disconnect_existing_connection()
                                    await asyncio.sleep(2.0)
                                    _LOGGER.info("✅ Disconnected existing connection - ready for new connection")
                                except Exception as disconnect_err:
                                    _LOGGER.warning(
                                        "Could not disconnect existing connection: %s. "
                                        "You may need to manually disconnect from the OneControl app on your phone.",
                                        disconnect_err
                                    )
                        else:
                            _LOGGER.debug("Device not paired per bluetoothctl either - will attempt pairing")
                except Exception as dbus_check_err:
                    _LOGGER.debug("D-Bus check failed: %s - checking bluetoothctl as fallback", dbus_check_err)
                    # D-Bus check failed, try bluetoothctl fallback
                    bluetoothctl_paired, bluetoothctl_connected = await self._async_check_paired_via_bluetoothctl()
                    if bluetoothctl_paired:
                        is_already_bonded = True
                        _LOGGER.info("✅ Device is already paired (via bluetoothctl fallback) - will skip pairing step")
                        if bluetoothctl_connected:
                            device_is_connected_elsewhere = True
                            _LOGGER.warning(
                                "⚠️  Device is currently CONNECTED (per bluetoothctl). "
                                "Attempting to disconnect existing connection..."
                            )
                            try:
                                await self._async_disconnect_existing_connection()
                                await asyncio.sleep(2.0)
                                _LOGGER.info("✅ Disconnected existing connection - ready for new connection")
                            except Exception as disconnect_err:
                                _LOGGER.warning(
                                    "Could not disconnect existing connection: %s. "
                                    "You may need to manually disconnect from the OneControl app on your phone.",
                                    disconnect_err
                                )
                    else:
                        _LOGGER.debug("Device not paired per bluetoothctl either - will attempt pairing")
                
                # Check if using proxy adapter (needed for pairing logic)
                current_adapter = fresh_device.details.get("source", self.adapter) if hasattr(fresh_device, "details") else self.adapter
                is_proxy = self._is_proxy_adapter(current_adapter) or self._is_proxy_adapter(self.adapter)
                
                # For proxy adapters, we can't check D-Bus, but bluetoothctl shows device is paired
                # Since the device is already paired, we'll skip pairing for proxies
                if not is_already_bonded and is_proxy:
                    _LOGGER.info("⚠️  Using proxy adapter - cannot verify paired status via D-Bus")
                    _LOGGER.info("⚠️  Assuming device is already paired (bluetoothctl shows Paired: yes)")
                    # Treat as already bonded to skip pairing step
                    is_already_bonded = True

                # Only register PIN agent if device is NOT already bonded and PIN is provided
                # If already bonded, pairing should happen automatically via the bond
                # For proxy adapters, skip PIN agent since D-Bus isn't available and device is already paired
                agent_registered = False
                if not is_already_bonded and not is_proxy and self.pin and self._is_first_connection:
                    _LOGGER.info("Registering D-Bus PIN agent before connection (device not yet bonded)...")
                    agent_registered = await self._async_register_pin_agent()
                    if agent_registered:
                        _LOGGER.info("✅ PIN agent registered - ready for automatic pairing")
                elif is_already_bonded:
                    _LOGGER.debug("Skipping PIN agent registration - device already bonded")
                elif is_proxy:
                    _LOGGER.debug("Skipping PIN agent registration - using proxy adapter (D-Bus not available)")
                
                # Connect using establish_connection
                # Match working v6/v7 pattern: use BleakClientWithServiceCache and ble_device_callback
                # v6/v7 success: 1-2s connect + 0.8s pair = ~3s total (with direct adapter)
                # With proxies, connection may take longer due to network latency
                # Use longer timeout for proxies, shorter for direct adapters
                # is_proxy already determined above
                
                # C# code uses 30 second timeout (linkedCts.CancelAfter(30000))
                # establish_connection has its own internal timeout (appears to be 20s)
                # Use 30s to match C# code and allow establish_connection's internal timeout to complete
                if is_proxy:
                    # Proxies need more time due to network latency
                    connection_timeout = 30.0 if self._is_first_connection else 40.0
                    _LOGGER.info(
                        "Using proxy adapter (%s) - connection may take longer (timeout=%.1fs for %s)...",
                        current_adapter or self.adapter,
                        connection_timeout,
                        "first connection" if self._is_first_connection else "reconnection",
                    )
                else:
                    # Match C# code timeout (30s) - establish_connection has internal 20s timeout
                    connection_timeout = 30.0
                    _LOGGER.info(
                        "Using direct adapter (%s) - timeout=%.1fs (matching C# code 30s timeout)...",
                        current_adapter or self.adapter,
                        connection_timeout,
                    )
                
                # Don't filter by connectable=True - device may be paired but not currently advertising
                # C# code doesn't check connectability, it just tries to connect
                # For already-paired devices, connection should work even if not actively advertising
                _LOGGER.debug("Attempting connection (device is paired per bluetoothctl)...")
                
                _LOGGER.info(
                    "Calling establish_connection (pairing window is 30-60s)...",
                )
                
                # Use Home Assistant's establish_connection (matching working v7 pattern)
                _LOGGER.info("Using HA's establish_connection...")
                
                # Create callback that ensures device uses correct adapter
                # Since bluetoothctl connect works, device IS connectable - use connectable=True
                # This matches how bluetoothctl connects to already-paired devices
                def get_ble_device_callback():
                    """Get fresh device and ensure it uses discovery adapter."""
                    # Try connectable=True first (device is connectable per bluetoothctl test)
                    device = async_ble_device_from_address(
                        self.hass, self.address, connectable=True
                    )
                    if device:
                        _LOGGER.debug("ble_device_callback: Found device with connectable=True")
                    # If not found with connectable=True, try without filter (for paired but not advertising)
                    if not device:
                        _LOGGER.debug("Device not found with connectable=True, trying without filter...")
                        device = async_ble_device_from_address(
                            self.hass, self.address, connectable=False
                        )
                        if device:
                            _LOGGER.debug("ble_device_callback: Found device with connectable=False")
                    if not device:
                        _LOGGER.warning("ble_device_callback: Device not found in HA cache at all!")
                    if device and self.adapter and hasattr(device, "details"):
                        if device.details.get("source") != self.adapter:
                            _LOGGER.debug(
                                "ble_device_callback: Forcing adapter %s (was %s)",
                                self.adapter,
                                device.details.get("source"),
                            )
                            device.details["source"] = self.adapter
                            if hasattr(device, "source"):
                                device.source = self.adapter
                    return device
                
                connection_start_time = asyncio.get_event_loop().time()
                try:
                    # Note: establish_connection from bleak-retry-connector may have its own internal timeout
                    # The 20s timeout we're seeing suggests it's using a default timeout internally
                    # We wrap it with asyncio.wait_for to enforce our timeout, but if establish_connection
                    # has its own timeout that's shorter, it will win
                    # 
                    # C# code just tries to connect - doesn't check connectability
                    # For already-paired devices, connection should work even if not actively advertising
                    _LOGGER.info(
                        "Attempting BLE connection (matching C# code - no connectability check)..."
                    )
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
                    error_msg = (
                        f"Connection timed out after {connection_time:.2f}s (timeout was {connection_timeout:.1f}s). "
                        "Device is paired per bluetoothctl but not connecting.\n"
                        "Possible causes:\n"
                        "  1. Device is CONNECTED to another client (phone/app) - disconnect from OneControl app first\n"
                        "  2. Device is not in pairing mode (press Connect button on RV panel)\n"
                        "  3. Device is out of range or not advertising\n"
                        "  4. Device needs to be 'woken up' even though it's paired\n"
                        "  5. Connectivity issue with Bluetooth adapter"
                    )
                    if device_is_connected_elsewhere:
                        error_msg += "\n\n⚠️  CRITICAL: Device is currently connected to another client. Please disconnect from the OneControl app on your phone, then try again."
                    _LOGGER.error(error_msg)
                    raise
                except Exception as conn_err:
                    connection_time = asyncio.get_event_loop().time() - connection_start_time
                    _LOGGER.error(
                        "Connection failed after %.2fs with exception: %s (type: %s)",
                        connection_time,
                        conn_err,
                        type(conn_err).__name__,
                        exc_info=True,
                    )
                    raise

                if not self.client or not self.client.is_connected:
                    _LOGGER.error("Connection established but client not connected")
                    return False

                _LOGGER.info("✅ Connected to BLE gateway")
                
                # CRITICAL: Match C# code sequence exactly
                # For already-paired devices: C# code does NOT pair after connection
                # For new devices: We still need to pair (initial onboarding)
                #
                # C# code sequence (for already-paired):
                # 1. Connects (done above)
                # 2. Gets service
                # 3. Requests MTU (185)
                # 4. Unlocks with PIN (application-level, not BLE pairing)
                # 5. Gets characteristics
                #
                # LAZY BONDING APPROACH (matching C# app):
                # C# app uses PairingMethod.None - doesn't explicitly pair
                # Android automatically bonds when accessing protected characteristics
                # We'll trigger bonding by attempting to read the protected seed characteristic
                # and handle Code=15 errors with retries (up to 30s like C# app)
                #
                # For already-bonded devices, this will work immediately
                # For new devices, bonding will happen automatically during seed read
                
                if not is_already_bonded:
                    _LOGGER.info("Device not yet bonded - will use lazy bonding (triggered by protected characteristic access)")
                    _LOGGER.info("This matches the C# app's approach - bonding happens automatically during authentication")
                else:
                    _LOGGER.info("Device already bonded - authentication should proceed immediately")
                
                # Skip explicit pairing - let lazy bonding handle it during authentication
                # This matches C# app's PairingMethod.None approach
                
                # Step 1: Discover services (needed before MTU request)
                _LOGGER.info("Discovering services...")
                
                # Verify connection before service discovery
                if not self.client or not self.client.is_connected:
                    _LOGGER.error("Device disconnected before service discovery")
                    return False
                
                await asyncio.sleep(1.0)  # Allow service discovery to complete
                
                # Step 2: Request MTU (matches C# code line 177)
                # C# code requests MTU 185 for V2+ gateways
                if hasattr(self.client, 'request_mtu'):
                    try:
                        _LOGGER.info("Requesting MTU size 185 (matching C# code)...")
                        mtu = await self.client.request_mtu(185)
                        if mtu > 0:
                            _LOGGER.info("✅ MTU set to %d", mtu)
                        else:
                            _LOGGER.warning("MTU request failed, assuming default MTU 23")
                    except Exception as mtu_err:
                        _LOGGER.debug("MTU request not supported or failed: %s (assuming default)", mtu_err)
                else:
                    _LOGGER.debug("Client doesn't support MTU request (may not be needed)")
                
                # Step 3: Unlock gateway with PIN (application-level unlock, NOT BLE pairing)
                # This matches C# code UnlockEcuAsync() - must happen BEFORE authentication
                # C# code does this after MTU request and before getting characteristics (line 185)
                if self.pin:
                    _LOGGER.info("Unlocking gateway with PIN (application-level unlock, matching C# code)...")
                    if not await self._async_unlock_gateway():
                        _LOGGER.warning("Failed to unlock gateway with PIN - continuing anyway")
                else:
                    _LOGGER.debug("No PIN provided - skipping unlock step (device may not require it)")
                
                # Unregister agent if we registered it (no longer needed after connection)
                if agent_registered:
                    await self._async_unregister_pin_agent()
                
                # Verify connection is still stable before authentication
                if not self.client or not self.client.is_connected:
                    _LOGGER.error("Device disconnected before authentication")
                    return False
                
                # Authenticate (TEA seed/key exchange)
                if not await self._async_authenticate():
                    _LOGGER.error("Authentication failed")
                    await self._async_disconnect()
                    return False

                # Subscribe to notifications for device discovery
                await self._async_subscribe_notifications()

                self._is_first_connection = False
                self._connecting = False  # Connection complete
                return True

            except asyncio.TimeoutError:
                self._connecting = False
                _LOGGER.error(
                    "Connection timeout (outer handler). "
                    "Device may not be in pairing mode. "
                    "Press the Connect button on your RV control panel."
                )
                return False
            except Exception as err:
                self._connecting = False
                _LOGGER.error(
                    "Connection error (outer handler): %s (type: %s)",
                    err,
                    type(err).__name__,
                    exc_info=True,
                )
                return False

    async def _async_register_pin_agent(self) -> bool:
        """Register D-Bus PIN agent before connection."""
        try:
            import dbus_next
            from dbus_next.aio import MessageBus
        except ImportError:
            _LOGGER.debug("dbus-next not available - cannot register PIN agent")
            return False

        try:
            _LOGGER.info("Connecting to D-Bus system bus for PIN agent...")
            self._dbus_bus = await MessageBus(bus_type=dbus_next.BusType.SYSTEM).connect()
            
            bluez_service = "org.bluez"
            agent_path = "/com/homeassistant/onecontrol/pinagent"
            
            # Create and export PIN agent
            agent = self._create_pin_agent(self._dbus_bus, agent_path, self.pin)
            
            # Register agent
            agent_manager_introspect = await self._dbus_bus.introspect(bluez_service, "/org/bluez")
            agent_manager_obj = self._dbus_bus.get_proxy_object(bluez_service, "/org/bluez", agent_manager_introspect)
            agent_manager = agent_manager_obj.get_interface("org.bluez.AgentManager1")
            
            await agent_manager.call_register_agent(
                agent_path,
                "KeyboardDisplay"  # Capability that supports PIN entry
            )
            await agent_manager.call_request_default_agent(agent_path)
            _LOGGER.info("✅ Registered PIN agent at %s", agent_path)
            self._pin_agent_path = agent_path
            return True
        except Exception as err:
            _LOGGER.error("Failed to register PIN agent: %s", err, exc_info=True)
            return False

    async def _async_unregister_pin_agent(self) -> None:
        """Unregister D-Bus PIN agent."""
        if not hasattr(self, '_pin_agent_path') or not self._pin_agent_path:
            return
        
        try:
            import dbus_next
            from dbus_next.aio import MessageBus
        except ImportError:
            return

        try:
            if not hasattr(self, '_dbus_bus') or not self._dbus_bus:
                return
            
            bluez_service = "org.bluez"
            agent_manager_introspect = await self._dbus_bus.introspect(bluez_service, "/org/bluez")
            agent_manager_obj = self._dbus_bus.get_proxy_object(bluez_service, "/org/bluez", agent_manager_introspect)
            agent_manager = agent_manager_obj.get_interface("org.bluez.AgentManager1")
            
            await agent_manager.call_unregister_agent(self._pin_agent_path)
            _LOGGER.debug("Unregistered PIN agent")
            self._pin_agent_path = None
        except Exception as err:
            _LOGGER.debug("Error unregistering PIN agent: %s", err)

    async def _async_check_paired_via_bluetoothctl(self) -> tuple[bool, bool]:
        """
        Check if device is paired/connected via bluetoothctl command (fallback when D-Bus fails).
        
        Returns:
            (is_paired, is_connected) tuple
        """
        try:
            import subprocess
            # Use bluetoothctl to check device info
            proc = await asyncio.create_subprocess_exec(
                "bluetoothctl", "info", self.address,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            
            if proc.returncode != 0:
                _LOGGER.debug("bluetoothctl info failed (device may not be found): %s", stderr.decode())
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

    async def _async_check_paired(self) -> tuple[bool, bool]:
        """
        Check if device is already paired and connected via D-Bus, with bluetoothctl fallback.
        
        Returns:
            (is_paired, is_connected) tuple
        """
        # Skip for proxies - they don't use BlueZ D-Bus
        if self._is_proxy_adapter(self.adapter):
            _LOGGER.debug("Skipping paired check for proxy adapter (D-Bus not available)")
            # For proxies, fall back to bluetoothctl
            return await self._async_check_paired_via_bluetoothctl()
        
        try:
            import dbus_next
            from dbus_next.aio import MessageBus
        except ImportError:
            _LOGGER.debug("dbus-next not available for paired check - using bluetoothctl fallback")
            return await self._async_check_paired_via_bluetoothctl()

        try:
            # Use a temporary bus connection for this check
            bus = await MessageBus(bus_type=dbus_next.BusType.SYSTEM).connect()
            
            bluez_service = "org.bluez"
            device_path = await self._find_device_path(bus, bluez_service, None, self.address)
            if device_path:
                device_introspect = await bus.introspect(bluez_service, device_path)
                device_obj = bus.get_proxy_object(bluez_service, device_path, device_introspect)
                device_interface = device_obj.get_interface("org.bluez.Device1")
                paired = await device_interface.get_paired()
                connected = await device_interface.get_connected()
                _LOGGER.debug("D-Bus check - paired: %s, connected: %s", paired, connected)
                return (bool(paired), bool(connected))
            else:
                _LOGGER.debug("Device path not found in D-Bus - device may not be registered yet, trying bluetoothctl fallback")
                # Fall back to bluetoothctl when D-Bus can't find device
                return await self._async_check_paired_via_bluetoothctl()
        except Exception as err:
            _LOGGER.debug("Error checking paired status via D-Bus: %s - trying bluetoothctl fallback", err)
            # Fall back to bluetoothctl on D-Bus error
            return await self._async_check_paired_via_bluetoothctl()

    async def _async_disconnect_existing_connection(self) -> None:
        """Disconnect device if it's currently connected to another client."""
        if self._is_proxy_adapter(self.adapter):
            _LOGGER.debug("Skipping disconnect for proxy adapter (D-Bus not available)")
            return
        
        # Try D-Bus method first (preferred)
        dbus_success = False
        try:
            import dbus_next
            from dbus_next.aio import MessageBus
        except ImportError:
            _LOGGER.debug("dbus-next not available for disconnect")
        else:
            try:
                bus = await MessageBus(bus_type=dbus_next.BusType.SYSTEM).connect()
                bluez_service = "org.bluez"
                device_path = await self._find_device_path(bus, bluez_service, None, self.address)
                
                if device_path:
                    device_introspect = await bus.introspect(bluez_service, device_path)
                    device_obj = bus.get_proxy_object(bluez_service, device_path, device_introspect)
                    device_interface = device_obj.get_interface("org.bluez.Device1")
                    
                    # Check if connected
                    connected = await device_interface.get_connected()
                    if connected:
                        _LOGGER.info("Disconnecting device from existing connection via D-Bus...")
                        # Try disconnect with retries
                        for attempt in range(3):
                            try:
                                await device_interface.call_disconnect()
                                await asyncio.sleep(0.5)
                                # Verify disconnect
                                still_connected = await device_interface.get_connected()
                                if not still_connected:
                                    _LOGGER.info("✅ Device disconnected via D-Bus")
                                    dbus_success = True
                                    break
                                elif attempt < 2:
                                    _LOGGER.debug(f"Device still connected, retrying... (attempt {attempt + 1}/3)")
                                    await asyncio.sleep(0.5)
                            except Exception as e:
                                _LOGGER.debug(f"D-Bus disconnect attempt {attempt + 1} failed: {e}")
                                if attempt < 2:
                                    await asyncio.sleep(0.5)
                        
                        if not dbus_success:
                            _LOGGER.warning("D-Bus disconnect did not succeed after retries")
                    else:
                        _LOGGER.debug("Device not connected - no need to disconnect")
                        dbus_success = True  # No action needed
                else:
                    _LOGGER.debug("Device path not found - cannot disconnect via D-Bus")
            except Exception as err:
                _LOGGER.debug("Error disconnecting device via D-Bus: %s", err)
        
        # Fallback to bluetoothctl command if D-Bus failed
        if not dbus_success:
            _LOGGER.info("Attempting disconnect via bluetoothctl command...")
            disconnect_succeeded = False
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
                    disconnect_succeeded = True
                else:
                    error_output = stderr.decode() if stderr else stdout.decode()
                    _LOGGER.warning(f"bluetoothctl disconnect returned code {proc.returncode}: {error_output}")
            except asyncio.TimeoutError:
                _LOGGER.warning("bluetoothctl disconnect timed out - device may be stuck in connected state")
            except Exception as err:
                _LOGGER.warning(f"Error disconnecting via bluetoothctl: {err}")
            
            # Wait for disconnect to settle, then verify
            await asyncio.sleep(3.0)  # Wait longer for disconnect to complete
            
            # Verify disconnect actually worked
            is_paired, is_connected = await self._async_check_paired_via_bluetoothctl()
            if is_connected:
                _LOGGER.warning(
                    "⚠️  Device still shows as connected after disconnect attempt. "
                    "This may be HA's Bluetooth integration holding the connection, "
                    "or a stale connection state in BlueZ. "
                    "Proceeding with connection attempt anyway - establish_connection may handle it."
                )
                _LOGGER.info(
                    "💡 If connection fails, try: "
                    "1. Restart HA's Bluetooth integration, or "
                    "2. Temporarily disable Bluetooth integration, disconnect via bluetoothctl, then re-enable"
                )
            else:
                if disconnect_succeeded:
                    _LOGGER.info("✅ Verified device is disconnected")
                else:
                    _LOGGER.info("✅ Device appears disconnected (may have been stale state)")

    async def _async_pair_immediately(self) -> bool:
        """
        Pair immediately after connection (v6/v7 working pattern).
        
        Strategy: Try client.pair() first (like v6/v7), even without PIN.
        bluetoothctl shows "LegacyPairing: no" - device may support "Just Works" pairing.
        This matches the timing that worked: pair before service discovery.
        """
        if not self.client:
            return False

        # CRITICAL: bluetoothctl shows "LegacyPairing: no"
        # This means the device may support "Just Works" pairing even if it advertises PairingMethod 1
        # Try client.pair() first WITHOUT requiring PIN (v6/v7 pattern)
        if hasattr(self.client, 'pair'):
            _LOGGER.info("Attempting pairing via client.pair() (v6/v7 pattern, no PIN required)...")
            try:
                pair_timeout = 10.0 if self._is_first_connection else 30.0
                await asyncio.wait_for(
                    self.client.pair(),
                    timeout=pair_timeout
                )
                _LOGGER.info("✅ Pairing succeeded via client.pair() (Just Works pairing)")
                return True
            except NotImplementedError:
                _LOGGER.debug("Platform doesn't support client.pair() - trying D-Bus")
            except asyncio.TimeoutError:
                _LOGGER.warning("Pairing via client.pair() timed out - trying D-Bus with PIN")
            except Exception as pair_err:
                _LOGGER.debug("client.pair() failed: %s - trying D-Bus with PIN", pair_err)
        
        # Fallback to D-Bus PIN agent only if PIN is provided and client.pair() failed
        # This handles cases where device actually requires PIN despite LegacyPairing: no
        if self.pin and not self._is_proxy_adapter(self.adapter):
            _LOGGER.info("Attempting pairing via D-Bus PIN agent (PIN: %s)...", self.pin)
            try:
                if await self._async_pair_via_dbus():
                    _LOGGER.info("✅ Pairing succeeded via D-Bus")
                    return True
            except Exception as dbus_err:
                _LOGGER.debug("D-Bus pairing failed: %s", dbus_err)
        
        # For proxies, pairing might happen automatically during characteristic access
        if self._is_proxy_adapter(self.adapter):
            _LOGGER.info("Pairing methods failed, but using proxy - may handle pairing automatically")
            return False
        
        if not self.pin:
            _LOGGER.warning("Pairing failed and no PIN provided - device may require PIN for pairing")
        
        _LOGGER.warning("All pairing methods failed")
        return False

    async def _async_pair(self) -> bool:
        """Legacy pairing method - kept for compatibility."""
        return await self._async_pair_immediately()

    def _is_proxy_adapter(self, adapter: str | None) -> bool:
        """Check if adapter is a Bluetooth proxy (ESP32/ESPHome)."""
        if not adapter:
            return False
        
        # Standard BlueZ adapters use "hci0", "hci1", etc.
        if adapter.startswith("hci"):
            return False  # Standard BlueZ adapter
        
        # HA's Bluetooth integration may report built-in adapters as MAC addresses
        # But we can't reliably distinguish MAC addresses from proxy identifiers
        # Better approach: Check if adapter contains known proxy patterns
        # ESPHome proxies often have specific identifiers, but MAC addresses are also common
        
        # For now, be conservative: Only treat as proxy if we're certain
        # Since user confirmed no proxy is connected, we'll assume MAC addresses are direct adapters
        # TODO: Improve detection when proxy is reconnected
        
        # If it looks like a MAC address (contains colons), it might be a built-in adapter
        # reported as MAC, or it could be a proxy. Without better info, assume direct adapter.
        if ":" in adapter:
            # Could be MAC address format - assume direct adapter for now
            # User confirmed no proxy, so this is likely the built-in adapter
            return False
        
        # If it's not hci* and not MAC-like, might be a proxy identifier
        # But since user says no proxy, return False
        return False

    async def _async_pair_via_dbus(self) -> bool:
        """Pair using D-Bus to provide PIN programmatically."""
        # Check if we're using a proxy - D-Bus pairing won't work with proxies
        if self._is_proxy_adapter(self.adapter):
            _LOGGER.info("Using Bluetooth proxy - D-Bus pairing not available. Will rely on lazy bonding.")
            return False  # Skip D-Bus pairing for proxies
        
        try:
            import dbus_next
            from dbus_next.aio import MessageBus
            from dbus_next import Variant
        except ImportError:
            _LOGGER.debug("dbus-next not available - cannot use D-Bus pairing")
            return False

        # Use existing D-Bus bus if available, otherwise create new one
        bus = None
        try:
            if hasattr(self, '_dbus_bus') and self._dbus_bus:
                bus = self._dbus_bus
                _LOGGER.debug("Using existing D-Bus connection")
            else:
                _LOGGER.info("Connecting to D-Bus system bus...")
                bus = await MessageBus(bus_type=dbus_next.BusType.SYSTEM).connect()
            
            # Get BlueZ adapter and device objects
            bluez_service = "org.bluez"
            adapter_path = await self._find_adapter_path(bus, bluez_service)
            if not adapter_path:
                _LOGGER.warning("Could not find BlueZ adapter")
                return False
            
            # Wait a bit for device to be registered in BlueZ after connection
            _LOGGER.info("Looking for device in BlueZ...")
            device_path = None
            for attempt in range(10):
                device_path = await self._find_device_path(bus, bluez_service, adapter_path, self.address)
                if device_path:
                    break
                await asyncio.sleep(0.5)
            
            if not device_path:
                _LOGGER.warning("Could not find device path for %s after connection - device may not be registered in BlueZ (possibly using proxy)", self.address)
                return False
            
            _LOGGER.info("Found device at path: %s", device_path)
            
            # Get device interface
            device_introspect = await bus.introspect(bluez_service, device_path)
            device_obj = bus.get_proxy_object(bluez_service, device_path, device_introspect)
            device_interface = device_obj.get_interface("org.bluez.Device1")
            
            # Set up PIN agent to provide PIN automatically
            agent_path = "/com/homeassistant/onecontrol/pinagent"
            agent = self._create_pin_agent(bus, agent_path, self.pin)
            
            # Register agent
            agent_manager_introspect = await bus.introspect(bluez_service, "/org/bluez")
            agent_manager_obj = bus.get_proxy_object(bluez_service, "/org/bluez", agent_manager_introspect)
            agent_manager = agent_manager_obj.get_interface("org.bluez.AgentManager1")
            
            await agent_manager.call_register_agent(
                agent_path,
                "KeyboardDisplay"  # Capability that supports PIN entry
            )
            await agent_manager.call_request_default_agent(agent_path)
            _LOGGER.info("Registered PIN agent")
            
            # Start pairing
            _LOGGER.info("Initiating pairing (device should be in pairing mode)...")
            try:
                await device_interface.call_pair()
                _LOGGER.info("Pairing request sent")
                
                # Wait for pairing to complete (up to 20 seconds)
                for i in range(20):
                    await asyncio.sleep(1.0)
                    # Check if device is paired
                    try:
                        paired = await device_interface.get_paired()
                        if paired:
                            _LOGGER.info("✅ Device is now paired")
                            # Trust the device
                            try:
                                await device_interface.set_trusted(Variant("b", True))
                                _LOGGER.info("✅ Device trusted")
                            except Exception as trust_err:
                                _LOGGER.debug("Could not set trusted (may be read-only): %s", trust_err)
                            return True
                    except Exception as check_err:
                        _LOGGER.debug("Error checking paired status: %s", check_err)
                        # Continue waiting
                
                _LOGGER.warning("Pairing timeout after 20 seconds - device may not be in pairing mode")
                return False
                
            except Exception as pair_err:
                _LOGGER.error("Pairing failed: %s", pair_err, exc_info=True)
                return False
            finally:
                # Unregister agent
                try:
                    await agent_manager.call_unregister_agent(agent_path)
                    _LOGGER.debug("Unregistered PIN agent")
                except Exception as unreg_err:
                    _LOGGER.debug("Error unregistering agent: %s", unreg_err)
                    
        except Exception as err:
            _LOGGER.error("D-Bus pairing error: %s", err, exc_info=True)
            return False
        finally:
            # Keep bus connection alive during pairing
            # Bus will be closed when function returns
            pass

    async def _find_adapter_path(self, bus, bluez_service: str) -> str | None:
        """Find the first available BlueZ adapter."""
        try:
            object_manager_introspect = await bus.introspect(bluez_service, "/")
            object_manager_obj = bus.get_proxy_object(bluez_service, "/", object_manager_introspect)
            object_manager = object_manager_obj.get_interface("org.freedesktop.DBus.ObjectManager")
            
            objects = await object_manager.call_get_managed_objects()
            for path, interfaces in objects.items():
                if "org.bluez.Adapter1" in interfaces:
                    return str(path)
            return None
        except Exception:
            return None

    async def _find_device_path(self, bus, bluez_service: str, adapter_path: str, address: str) -> str | None:
        """Find device path by address."""
        try:
            object_manager_introspect = await bus.introspect(bluez_service, "/")
            object_manager_obj = bus.get_proxy_object(bluez_service, "/", object_manager_introspect)
            object_manager = object_manager_obj.get_interface("org.freedesktop.DBus.ObjectManager")
            
            # Try multiple times - device may not be registered immediately after connection
            address_upper = address.upper()
            for attempt in range(5):
                try:
                    objects = await object_manager.call_get_managed_objects()
                except Exception as err:
                    _LOGGER.debug("Error getting managed objects (attempt %d): %s", attempt + 1, err)
                    if attempt < 4:
                        await asyncio.sleep(0.5)
                    continue
                
                for path, interfaces in objects.items():
                    # Only check paths that look like device paths and have Device1 interface
                    if "org.bluez.Device1" not in interfaces:
                        continue
                    
                    # Skip if path doesn't look like a device path (contains "dev_")
                    path_str = str(path)
                    if "dev_" not in path_str.lower():
                        continue
                    
                    try:
                        device_obj = bus.get_proxy_object(bluez_service, path_str, object_manager_introspect)
                        device_interface = device_obj.get_interface("org.bluez.Device1")
                        device_address = await device_interface.get_address()
                        if device_address.upper() == address_upper:
                            _LOGGER.debug("Found device path: %s (attempt %d)", path_str, attempt + 1)
                            return path_str
                    except Exception:
                        # Silently skip devices that can't be queried - don't spam logs
                        # Only log if this is the target device (which we can't know until we check address)
                        continue
                
                if attempt < 4:
                    await asyncio.sleep(0.5)  # Wait a bit before retrying
            
            return None
        except Exception as err:
            _LOGGER.debug("Error finding device path: %s", err)
            return None

    def _create_pin_agent(self, bus, agent_path: str, pin: str):
        """Create a D-Bus PIN agent to provide PIN automatically."""
        from dbus_next.service import ServiceInterface, method
        
        class PinAgent(ServiceInterface):
            def __init__(self, pin: str):
                super().__init__("org.bluez.Agent1")
                self.pin = pin
            
            @method()
            def Release(self):
                """Release the agent."""
                _LOGGER.debug("Agent released")
            
            @method()
            def RequestPinCode(self) -> "s":
                """Return PIN code when requested."""
                _LOGGER.info("🔑 PIN requested by BlueZ - providing: %s", self.pin)
                return self.pin
            
            @method()
            def DisplayPinCode(self, device: "o", pincode: "s"):
                """Display PIN code (not used for our case)."""
                _LOGGER.debug("DisplayPinCode called: %s", pincode)
            
            @method()
            def RequestPasskey(self) -> "u":
                """Return passkey when requested (6-digit numeric)."""
                _LOGGER.info("🔑 Passkey requested by BlueZ - providing: %s", self.pin)
                return int(self.pin)
            
            @method()
            def DisplayPasskey(self, device: "o", passkey: "u", entered: "q"):
                """Display passkey (not used for our case)."""
                _LOGGER.debug("DisplayPasskey called: %06d", passkey)
            
            @method()
            def RequestConfirmation(self, device: "o", passkey: "u") -> "b":
                """Confirm passkey (for Just Works pairing)."""
                _LOGGER.info("Confirmation requested for passkey: %06d", passkey)
                return True
            
            @method()
            def RequestAuthorization(self, device: "o") -> "b":
                """Request authorization."""
                _LOGGER.debug("Authorization requested")
                return True
            
            @method()
            def AuthorizeService(self, device: "o", uuid: "s") -> "b":
                """Authorize service."""
                _LOGGER.debug("Service authorization requested: %s", uuid)
                return True
            
            @method()
            def Cancel(self):
                """Cancel pairing request."""
                _LOGGER.warning("Pairing cancelled by BlueZ")
        
        # Export the agent on D-Bus
        agent = PinAgent(pin)
        bus.export(agent_path, agent)
        _LOGGER.info("Created PIN agent at %s", agent_path)
        return agent

    async def _async_unlock_gateway(self) -> bool:
        """
        Unlock the gateway using PIN (application-level unlock).
        
        This is NOT for BLE pairing - it's for unlocking the gateway's services
        after BLE connection is established. The PIN is written to the unlock
        characteristic (0x00000005) as UTF-8 bytes.
        
        Based on BleCommunicationsAdapter.UnlockEcuAsync() in decompiled code.
        """
        if not self.client or not self.pin:
            return False
        
        _LOGGER.info("Unlocking gateway with PIN (application-level unlock)...")
        
        try:
            # Get CAN service (unlock characteristic is in GUID_IDS_CAN_SERVICE, not auth service)
            can_service = self.client.services.get_service(CAN_SERVICE_UUID)
            if not can_service:
                _LOGGER.debug("CAN service not found for unlock - device may not require unlock")
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
            
            # Write PIN as UTF-8 bytes to unlock characteristic
            pin_bytes = self.pin.encode('utf-8')
            _LOGGER.debug("Writing PIN to unlock characteristic: %s", self.pin)
            
            # Try writing twice (as per decompiled code)
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
            
            # Wait 1 second (as per decompiled code)
            await asyncio.sleep(1.0)
            
            # Verify unlock by reading again
            verify_data = await asyncio.wait_for(
                self.client.read_gatt_char(unlock_char), timeout=5.0
            )
            
            if verify_data and len(verify_data) > 0 and verify_data[0] > 0:
                _LOGGER.info("✅ Gateway unlocked successfully")
                return True
            else:
                _LOGGER.warning("Gateway unlock verification failed - status: %s", verify_data.hex() if verify_data else "None")
                return False
                
        except asyncio.TimeoutError:
            _LOGGER.warning("Unlock timeout")
            return False
        except Exception as err:
            _LOGGER.warning("Unlock error: %s", err)
            return False

    async def _async_authenticate(self) -> bool:
        """Authenticate with the device using TEA encryption."""
        if not self.client:
            return False

        _LOGGER.info("Authenticating with device (cypher: 0x%08X)...", self.cypher)

        try:
            # Ensure services are discovered
            # With proxies, service discovery may need to be forced
            if not self.client.services.services:
                _LOGGER.info("Services not discovered yet, waiting...")
                # Force service discovery for proxies
                if self._is_proxy_adapter(self.adapter):
                    _LOGGER.debug("Forcing service discovery for proxy in authentication...")
                    try:
                        await self.client.get_services()
                    except Exception as sd_err:
                        _LOGGER.debug("Error forcing service discovery: %s", sd_err)
                
                max_wait = 20 if self._is_proxy_adapter(self.adapter) else 10
                for attempt in range(max_wait):
                    await asyncio.sleep(0.5)
                    if self.client.services.services:
                        _LOGGER.info("Services discovered after %d attempts", attempt + 1)
                        break
                else:
                    _LOGGER.error("Service discovery timeout after %d attempts", max_wait)
                    return False
            
            # Get authentication service
            # C# code: GetServiceAsync, then wait 500ms, then get characteristics (line 61-64, 80-81)
            auth_service = self.client.services.get_service(AUTH_SERVICE_UUID)
            if not auth_service:
                _LOGGER.error("Authentication service not found. Available services: %s", 
                            [str(s.uuid) for s in self.client.services.services])
                return False

            # CRITICAL: C# code waits 500ms AFTER getting service before getting characteristics
            # This ensures service is fully ready before accessing characteristics
            # Match C# BleDeviceUnlockManager.cs line 64: await Task.Delay(500, ct)
            await asyncio.sleep(0.5)  # 500ms delay after getting service (match C#)
            
            seed_char = auth_service.get_characteristic(SEED_CHAR_UUID)
            key_char = auth_service.get_characteristic(KEY_CHAR_UUID)

            if not seed_char or not key_char:
                _LOGGER.error("Seed or key characteristic not found. Service characteristics: %s",
                            [str(c.uuid) for c in auth_service.characteristics])
                return False

            self.auth_state = AUTH_STATE_LOCKED

            # Check connection state before reading
            if not self.client.is_connected:
                _LOGGER.error("Device disconnected before authentication")
                return False

            # LAZY BONDING: Read seed - this triggers bonding automatically (matching C# app)
            # C# app doesn't explicitly pair - it just tries to read and handles Code=15 errors
            # Code=15 means "bonding in progress" - we retry for up to 30 seconds (matching C#)
            seed_data = None
            bonding_start_time = time.time()
            max_bonding_time = 30.0  # Match C# app's 30s retry window (BleManager.cs line 311)
            retry_delay = 2.0  # Match C# app's 2s retry delay
            
            for attempt in range(20):  # Up to 20 attempts (20 * 2s = 40s max, but we'll stop at 30s)
                try:
                    # Check if we've exceeded the bonding timeout
                    elapsed = time.time() - bonding_start_time
                    if elapsed > max_bonding_time:
                        _LOGGER.warning("Bonding timeout after %.1f seconds (max: %.1f) - will try explicit pairing", elapsed, max_bonding_time)
                        break
                    
                    # Check connection before each attempt
                    if not self.client.is_connected:
                        _LOGGER.warning("Device disconnected during seed read (attempt %d)", attempt + 1)
                        if elapsed < max_bonding_time:
                            _LOGGER.info("Waiting %.1f seconds for bond to establish, then will retry...", retry_delay)
                            await asyncio.sleep(retry_delay)
                            # Try to reconnect if needed
                            if not self.client or not self.client.is_connected:
                                _LOGGER.error("Device still disconnected after wait - cannot continue")
                                return False
                            continue
                        else:
                            _LOGGER.error("Device disconnected during seed read (final attempt)")
                            return False
                    
                    # Try to read seed - this triggers lazy bonding
                    seed_data = await asyncio.wait_for(
                        self.client.read_gatt_char(seed_char), timeout=AUTH_TIMEOUT
                    )
                    
                    # Success! Bonding completed and we got the seed
                    if attempt > 0:
                        _LOGGER.info("✅ Seed read successful (bonding completed during attempt %d)", attempt + 1)
                    break
                    
                except Exception as err:
                    err_str = str(err)
                    
                    # Code=15 means "insufficient authentication" - bonding is in progress
                    # C# app retries these for up to 30s (BleManager.cs line 311)
                    if "Code=15" in err_str or "code 15" in err_str.lower() or "insufficient authentication" in err_str.lower():
                        elapsed = time.time() - bonding_start_time
                        if elapsed < max_bonding_time:
                            if attempt == 0:
                                _LOGGER.info("Bonding triggered by protected characteristic access - waiting for completion...")
                            else:
                                _LOGGER.debug(
                                    "Code=15 (bonding in progress) - attempt %d, elapsed: %.1fs (max: %.1fs)",
                                    attempt + 1, elapsed, max_bonding_time
                                )
                            await asyncio.sleep(retry_delay)  # Match C# ReadCharacteristicAsync retry delay
                            continue
                        else:
                            _LOGGER.warning("Code=15 retries exceeded time limit (%.1fs) - will try explicit pairing", elapsed)
                            # Fall through to try explicit pairing
                            break
                    
                    # Other errors - log and retry a few times
                    elapsed = time.time() - bonding_start_time
                    if attempt < 4 and elapsed < max_bonding_time:
                        _LOGGER.debug("Seed read attempt %d failed: %s (will retry)", attempt + 1, err)
                        if "not authorized" in err_str.lower() or "insufficient authentication" in err_str.lower() or "bonding" in err_str.lower():
                            await asyncio.sleep(5.0)  # Match C# BleBondingDelayMs = 5000
                        elif "Service Discovery" in err_str:
                            await asyncio.sleep(2.0)
                        else:
                            await asyncio.sleep(1.0)
                    else:
                        _LOGGER.warning("Seed read failed after %d attempts (%.1fs elapsed): %s", attempt + 1, elapsed, err)
                        break

            # If lazy bonding didn't work, try explicit pairing as fallback
            if seed_data is None:
                _LOGGER.warning("Lazy bonding failed - attempting explicit pairing as fallback...")
                pairing_succeeded = await self._async_pair_immediately()
                if pairing_succeeded:
                    _LOGGER.info("✅ Explicit pairing succeeded - retrying seed read...")
                    await asyncio.sleep(2.0)  # Wait for bond to establish
                    
                    # Retry seed read after explicit pairing
                    try:
                        seed_data = await asyncio.wait_for(
                            self.client.read_gatt_char(seed_char), timeout=AUTH_TIMEOUT
                        )
                        _LOGGER.info("✅ Seed read successful after explicit pairing")
                    except Exception as err:
                        _LOGGER.error("Seed read failed even after explicit pairing: %s", err)
                        if "not authorized" in str(err).lower() or "insufficient authentication" in str(err).lower():
                            if self._is_proxy_adapter(self.adapter):
                                _LOGGER.error(
                                    "Device requires pairing, but using Bluetooth proxy. "
                                    "Proxy pairing may require different approach. "
                                    "Try:\n"
                                    "  1. Ensure device is in pairing mode (press Connect button)\n"
                                    "  2. Remove and re-add integration while device is in pairing mode\n"
                                    "  3. Or pair device directly to a local adapter (not proxy) first"
                                )
                            else:
                                _LOGGER.error(
                                    "Device requires pairing. Please pair manually:\n"
                                    "  1. SSH to HA: ssh root@homeassistant.local -p 22222\n"
                                    "  2. Run: bluetoothctl\n"
                                    "  3. Press Connect button on RV, then:\n"
                                    "     pair %s\n"
                                    "     (Enter PIN when prompted: %s)\n"
                                    "  4. Run: trust %s\n"
                                    "  5. Retry integration setup",
                                    self.address,
                                    self.pin or "090336",
                                    self.address
                                )
                        return False
                else:
                    _LOGGER.error("Both lazy bonding and explicit pairing failed")
                    return False

            # Check if already unlocked
            if seed_data == b"unlocked":
                _LOGGER.info("Device already unlocked")
                self.auth_state = AUTH_STATE_UNLOCKED
                return True

            if len(seed_data) < 4:
                _LOGGER.error("Seed data too short: %s", seed_data.hex())
                return False

            # Extract seed (little-endian uint32)
            seed = int.from_bytes(seed_data[:4], byteorder="little")
            _LOGGER.debug("Read seed: 0x%08X", seed)

            # Encrypt seed using TEA
            key = self._tea_encrypt(self.cypher, seed)
            _LOGGER.debug("Computed key: 0x%08X", key)

            # Write key back
            key_data = key.to_bytes(4, byteorder="little")
            await self.client.write_gatt_char(key_char, key_data, response=True)
            # C# code waits 500ms after writing key (BleCharacteristicWriteDelayMs = 500)
            await asyncio.sleep(0.5)  # Match C# code

            # Verify unlock by reading seed again
            verify_data = await asyncio.wait_for(
                self.client.read_gatt_char(seed_char), timeout=AUTH_TIMEOUT
            )

            if verify_data == b"unlocked":
                _LOGGER.info("✅ Authentication successful")
                self.auth_state = AUTH_STATE_UNLOCKED
                return True

            _LOGGER.error(
                "Authentication failed - expected 'unlocked', got: %s",
                verify_data.hex(),
            )
            self.auth_state = AUTH_STATE_FAILED
            return False

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
        # Ignore disconnects during initial connection attempt (they're expected during retries)
        if self._connecting:
            _LOGGER.debug("Disconnect during connection attempt (this is normal during retries)")
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
        # Re-authentication is handled in async_connect() which calls _async_authenticate()
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

            # Encode command with COBS
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
                    # Decode COBS
                    decoded = cobs_decode(bytes(data), use_crc=True)
                    if decoded:
                        _LOGGER.debug("Received notification: %s", decoded.hex())
                        # Process for device discovery
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



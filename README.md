# PLEASE READ
This code is not functional in its present state - Jan 8th, 2026

# OneControl BLE Gateway - Home Assistant Integration

A fresh Home Assistant integration for controlling RV systems via OneControl BLE Gateway.

## Features

- **Automatic Discovery**: Discovers LCIRemote devices via Bluetooth
- **Adapter Tracking**: Uses the same Bluetooth adapter where device was discovered
- **Secure Pairing**: Handles BLE pairing with user guidance
- **TEA Authentication**: Implements correct TEA encryption from C# source
- **COBS Encoding**: Full COBS encoding/decoding with CRC8
- **CAN-over-BLE**: Sends CAN bus commands through BLE gateway
- **Device Discovery**: Automatically discovers CAN bus devices from status messages

## Installation

### HACS (Recommended)

1. Add this repository to HACS as a custom repository
2. Install "OneControl BLE Gateway"
3. Restart Home Assistant
4. Add integration via Settings → Devices & Services

### Manual Installation

1. Copy `custom_components/onecontrol_ble` to your Home Assistant `custom_components` directory
2. Restart Home Assistant
3. Add integration via Settings → Devices & Services

## Setup

1. **Press Connect Button**: On your RV control panel, press the "Connect" button
2. **Add Integration**: Within 30-60 seconds, add the integration in Home Assistant
3. **Select Device**: Choose your LCIRemote device from the discovered devices
4. **Wait for Connection**: The integration will automatically pair and authenticate

## Technical Details

### Protocol

- **BLE Transport**: Bluetooth Low Energy for communication
- **CAN Bus**: Underlying protocol for device control
- **TEA Encryption**: Custom TEA variant for authentication (delta accumulation)
- **COBS Framing**: Consistent Overhead Byte Stuffing with CRC8

### Service UUIDs

- **Authentication**: `00000010-0200-a58e-e411-afe28044e62c`
- **Data**: `00000030-0200-a58e-e411-afe28044e62c`
- **Discovery**: `00000041-0200-a58e-e411-afe28044e62c`

### Device Discovery

Devices are discovered by:
- Name pattern: `LCIRemote*`
- Manufacturer ID: `1479` (LCI/Lippert Components)
- Service UUID in advertisements

## Architecture

```
onecontrol_ble/
├── __init__.py          # Integration setup
├── config_flow.py      # Discovery and configuration
├── coordinator.py      # BLE connection, pairing, authentication
├── cobs.py             # COBS encoding/decoding with CRC8
├── device_discovery.py # CAN bus device discovery
├── const.py            # Constants and UUIDs
├── light.py            # Light entities (auto-discovered)
└── manifest.json       # Integration metadata
```

## Device Discovery

The integration automatically discovers devices on the CAN bus by:

1. **Subscribing to BLE Notifications**: After authentication, subscribes to the data read characteristic
2. **Decoding COBS Frames**: Incoming notifications are COBS-decoded
3. **Parsing MyRvLink Events**: Decoded data contains MyRvLink event messages
4. **Extracting Device Info**: From event types like:
   - `DeviceOnlineStatus` - Device came online
   - `DimmableLightStatus` - Dimmable light status updates
   - `RelayBasicLatchingStatus` - Switch/relay status
   - `TankSensorStatus` - Tank level sensors
   - And many more...

5. **Creating Entities Dynamically**: Entities are created based on discovered device types

### Discovery Process

- Devices are discovered as they send status messages
- Each device is tracked by its CAN address and device ID
- Entity platforms (light, switch, cover, sensor) automatically create entities for matching device types
- Discovery continues throughout the session - new devices are added as they appear

## Key Improvements from Previous Version

1. **Fresh Start**: Clean implementation based on C# decompiled code
2. **Adapter Tracking**: Properly tracks and uses the same adapter for connection
3. **Correct TEA**: Delta accumulation matches C# implementation exactly
4. **COBS with CRC8**: Full COBS implementation with CRC8 verification
5. **Better Error Messages**: Clear guidance for pairing and connection issues
6. **HACS Ready**: Proper structure for HACS installation

## Troubleshooting

### Connection Timeout

- Ensure device is in pairing mode (press Connect button)
- Check device is in range
- Verify Bluetooth adapter is working

### Pairing Failed

- Press Connect button on RV control panel
- Remove and re-add integration within 30 seconds
- Check logs for specific error messages

### Authentication Failed

- Verify cypher was extracted correctly from manufacturer data
- Check logs for TEA encryption details
- Ensure device is properly paired

## Development

Based on reverse-engineered C# code from the official OneControl mobile app.

## License

[Your License Here]


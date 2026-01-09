"""Constants for OneControl BLE Gateway integration."""

from typing import Final

# Integration domain
DOMAIN: Final = "onecontrol_ble"

# Configuration keys
CONF_ADDRESS: Final = "address"
CONF_CYPHER: Final = "cypher"
CONF_NAME: Final = "name"
CONF_PIN: Final = "pin"

# BLE Service UUIDs
# Authentication service (for seed/key exchange)
AUTH_SERVICE_UUID: Final = "00000010-0200-a58e-e411-afe28044e62c"
SEED_NOTIFY_CHAR_UUID: Final = "00000011-0200-a58e-e411-afe28044e62c"  # Seed via notification (NEW)
SEED_CHAR_UUID: Final = "00000012-0200-a58e-e411-afe28044e62c"  # Seed read characteristic (legacy)
KEY_CHAR_UUID: Final = "00000013-0200-a58e-e411-afe28044e62c"  # Auth key write

# Data service (for CAN-over-BLE communication)
DATA_SERVICE_UUID: Final = "00000030-0200-a58e-e411-afe28044e62c"
DATA_WRITE_CHAR_UUID: Final = "00000033-0200-a58e-e411-afe28044e62c"
DATA_READ_CHAR_UUID: Final = "00000034-0200-a58e-e411-afe28044e62c"

# Password unlock characteristic (for application-level unlock)
UNLOCK_CHAR_UUID: Final = "00000005-0200-a58e-e411-afe28044e62c"

# CAN service (contains unlock characteristic and CAN read/write)
CAN_SERVICE_UUID: Final = "00000000-0200-a58e-e411-afe28044e62c"

# Discovery service UUID (in advertisements)
DISCOVERY_SERVICE_UUID: Final = "00000041-0200-a58e-e411-afe28044e62c"

# Manufacturer ID
LCI_MANUFACTURER_ID: Final = 1479  # 0x05C7

# Device name patterns
DEVICE_NAME_PREFIX: Final = "LCIRemote"

# TEA Encryption constants (from C# BleDeviceUnlockManager.cs)
TEA_DELTA: Final = 0x9E3779B9  # 2654435769
TEA_CONSTANT_1: Final = 0x43729561  # 1131376761
TEA_CONSTANT_2: Final = 0x7265746E  # 1919510376
TEA_CONSTANT_3: Final = 0x7421ED44  # 1948272964
TEA_CONSTANT_4: Final = 0x5378A963  # 1400073827
TEA_ROUNDS: Final = 32

# Hardcoded cipher for TEA encryption (NEW - based on your research)
HARDCODED_CIPHER: Final = 0x8100080D

# Connection timeouts
CONNECTION_TIMEOUT: Final = 20.0
PAIRING_TIMEOUT: Final = 30.0
AUTH_TIMEOUT: Final = 10.0

# COBS/CRC settings (from C# code)
COBS_FRAME_CHAR: Final = 0x00
COBS_USE_CRC: Final = True
COBS_PREPEND_START_FRAME: Final = True

# MTU size
BLE_MTU_SIZE: Final = 185

# Authentication states
AUTH_STATE_LOCKED: Final = "locked"
AUTH_STATE_UNLOCKED: Final = "unlocked"
AUTH_STATE_AUTHENTICATING: Final = "authenticating"
AUTH_STATE_FAILED: Final = "failed"

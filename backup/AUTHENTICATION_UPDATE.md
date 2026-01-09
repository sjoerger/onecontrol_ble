# OneControl BLE Authentication Protocol Update

## Summary of Changes

This update implements the correct authentication protocol for OneControl BLE Gateway based on reverse-engineering findings.

## Key Changes

### 1. Authentication Protocol

**Old Method (4-byte key):**
- Read seed from characteristic `00000012`
- Encrypt with cypher from BLE advertisements
- Write 4-byte encrypted seed to `00000013`

**New Method (16-byte auth key):**
- Subscribe to notifications on characteristic `00000011` (seed notification)
- Gateway sends random SEED value (4 bytes) via notification
- Encrypt SEED using TEA with **hardcoded cipher `0x8100080D`** (not the advertised cypher)
- Build 16-byte auth key:
  - **Bytes 0-3:** TEA-encrypted SEED (little-endian)
  - **Bytes 4-9:** User's 6-digit PIN (as ASCII bytes, e.g., "090336")
  - **Bytes 10-15:** Padding (zeros)
- Write 16-byte auth key to characteristic `00000013`
- Gateway validates and grants access

### 2. New Constants

Added to `const.py`:
```python
SEED_NOTIFY_CHAR_UUID = "00000011-0200-a58e-e411-afe28044e62c"  # Seed notification
HARDCODED_CIPHER = 0x8100080D  # The actual cipher for TEA encryption
```

### 3. Modified Files

**coordinator_updated.py:**
- Implements notification-based seed reception
- Uses hardcoded cipher `0x8100080D` for TEA encryption
- Builds and sends 16-byte authentication key
- Falls back to direct read if notifications don't work
- Better error handling and logging

**const_updated.py:**
- Added `SEED_NOTIFY_CHAR_UUID` constant
- Added `HARDCODED_CIPHER` constant
- Preserved backward compatibility with legacy constants

## Authentication Flow

```
1. Connect to BLE device
   ↓
2. Discover services
   ↓
3. Request MTU (185 bytes)
   ↓
4. Unlock gateway with PIN (application-level, characteristic 0x0005)
   ↓
5. Subscribe to seed notifications (characteristic 0x0011)
   ↓
6. Wait for SEED notification from gateway
   ↓
7. Encrypt SEED with TEA using cipher 0x8100080D
   ↓
8. Build 16-byte auth key:
   [encrypted_seed(4)] + [pin_ascii(6)] + [zeros(6)]
   ↓
9. Write auth key to characteristic 0x0013
   ↓
10. Verify authentication (read seed again, expect "unlocked")
   ↓
11. Subscribe to data notifications for device discovery
```

## Example Auth Key

For PIN `090336` and encrypted seed `0x12345678`:

```
Byte Layout:
00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15
78 56 34 12 30 39 30 33 33 36 00 00 00 00 00 00
└─ seed ──┘ └───── PIN ──────┘ └─── padding ──┘
(little-end)  (ASCII: "090336")    (zeros)
```

Hex: `78 56 34 12 30 39 30 33 33 36 00 00 00 00 00 00`

## Migration Notes

### For Users
- **No action required** - the PIN you entered during setup will be used
- Ensure your PIN is exactly 6 digits (from the sticker on your OneControl unit)

### For Developers
1. Replace `coordinator.py` with `coordinator_updated.py`
2. Replace `const.py` with `const_updated.py`
3. No changes needed to other files
4. The advertised cypher is still extracted but not used for authentication
5. Backward compatibility maintained for devices that might use old protocol

## Testing Checklist

- [ ] Device discovery works
- [ ] PIN authentication succeeds
- [ ] Seed notification is received
- [ ] 16-byte auth key is correctly formatted
- [ ] Authentication verification passes
- [ ] Device control works after authentication
- [ ] Reconnection works after disconnect

## Troubleshooting

### Authentication Fails
- Verify PIN is exactly 6 digits
- Check that notifications are working on characteristic 0x0011
- Verify encrypted seed calculation
- Check auth key format (should be 16 bytes)

### No Seed Notification
- Code falls back to reading characteristic 0x0012 directly
- Check BLE notification subscription succeeded
- Verify characteristic 0x0011 exists on your device

### Wrong Cipher Used
- Verify using `0x8100080D` (hardcoded), not the advertised cypher
- Check TEA encryption implementation

## References

- Characteristic UUIDs based on protocol analysis
- TEA encryption matches C# implementation
- PIN format: 6-digit ASCII (e.g., "090336" = `30 39 30 33 33 36`)
- Auth key structure confirmed through testing

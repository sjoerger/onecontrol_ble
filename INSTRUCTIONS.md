# How to Apply Authentication Updates to Your Repository

## Quick Start (Automated)

1. Download all files from this session:
   - `coordinator_updated.py`
   - `const_updated.py`
   - `AUTHENTICATION_UPDATE.md`
   - `apply_auth_updates.sh`

2. Place them in your local clone of the repository

3. Run the script:
```bash
cd /path/to/onecontrol_ble
chmod +x apply_auth_updates.sh
./apply_auth_updates.sh
```

The script will:
- Backup original files
- Apply updates
- Show git status
- Prompt you to commit
- Create a properly formatted commit message

---

## Manual Instructions

If you prefer to apply changes manually:

### Step 1: Clone the Repository

```bash
git clone https://github.com/sjoerger/onecontrol_ble.git
cd onecontrol_ble
```

### Step 2: Create a New Branch (Optional but Recommended)

```bash
git checkout -b feat/16-byte-auth-protocol
```

### Step 3: Backup Original Files

```bash
cp coordinator.py coordinator.py.backup
cp const.py const.py.backup
```

### Step 4: Replace Files

Replace the contents of:
- `coordinator.py` with `coordinator_updated.py`
- `const.py` with `const_updated.py`

You can do this by:
- Copying the updated files over the originals, OR
- Opening each file and replacing the contents manually

### Step 5: Add Documentation (Optional)

```bash
# Create docs directory if it doesn't exist
mkdir -p docs

# Copy the authentication update documentation
cp AUTHENTICATION_UPDATE.md docs/
```

### Step 6: Review Changes

```bash
git diff coordinator.py
git diff const.py
```

### Step 7: Stage Changes

```bash
git add coordinator.py const.py
git add docs/AUTHENTICATION_UPDATE.md  # if you added it
```

### Step 8: Commit Changes

```bash
git commit -m "feat: implement 16-byte authentication protocol

- Subscribe to seed notifications on characteristic 0x0011
- Use hardcoded cipher 0x8100080D for TEA encryption
- Build 16-byte auth key: encrypted_seed(4) + PIN_ASCII(6) + padding(6)
- Add fallback to direct seed read if notifications fail
- Enhanced logging for authentication debugging

This implements the correct authentication protocol discovered through
reverse engineering of the OneControl BLE Gateway."
```

### Step 9: Push Changes

```bash
# If on main branch:
git push origin main

# If on feature branch:
git push origin feat/16-byte-auth-protocol

# Then create a Pull Request on GitHub if desired
```

---

## What Changed?

### coordinator.py
- **New authentication flow**: Uses notification-based seed reception
- **Hardcoded cipher**: Uses `0x8100080D` instead of advertised cypher
- **16-byte auth key**: Builds proper auth key with PIN and padding
- **Fallback mechanism**: Falls back to direct read if notifications fail
- **Enhanced logging**: Better debugging output for each auth step

### const.py
- **New constant**: `SEED_NOTIFY_CHAR_UUID = "00000011-..."`
- **New constant**: `HARDCODED_CIPHER = 0x8100080D`
- **Preserved compatibility**: All existing constants remain

---

## Testing After Update

1. Restart Home Assistant
2. Remove the integration
3. Re-add the integration with your 6-digit PIN
4. Check logs for authentication success:
   ```
   ✅ Received SEED notification: 0x...
   ✅ Built 16-byte auth key: ...
   ✅ Authentication successful
   ```

---

## Troubleshooting

### If authentication fails:
1. Check logs for "Received SEED notification"
2. Verify PIN is exactly 6 digits
3. Check auth key format in logs (should be 16 bytes)

### To restore original files:
```bash
cp coordinator.py.backup coordinator.py
cp const.py.backup const.py
git checkout coordinator.py const.py
```

---

## File Mapping

- `coordinator_updated.py` → replaces `coordinator.py`
- `const_updated.py` → replaces `const.py`
- `AUTHENTICATION_UPDATE.md` → new documentation file
- `apply_auth_updates.sh` → helper script (optional)

---

## Questions?

See `AUTHENTICATION_UPDATE.md` for detailed protocol documentation.

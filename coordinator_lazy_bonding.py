"""
Modified coordinator with lazy bonding approach (matching C# app).

Key changes:
1. Remove explicit pairing - don't call client.pair() at all
2. Trigger bonding by attempting to read protected characteristic
3. Handle Code=15 errors with extended retries (up to 30s like C#)
4. Only fall back to explicit pairing if lazy bonding completely fails
"""

# This is a reference implementation showing the lazy bonding approach
# The actual changes should be made to coordinator.py

# Key sequence (matching C# app):
# 1. Connect
# 2. Request MTU (if needed)
# 3. Discover services
# 4. Get auth service
# 5. Wait 500ms (C# line 64)
# 6. Get characteristics
# 7. Try to read seed - THIS TRIGGERS BONDING (lazy bonding)
# 8. Handle Code=15 errors with retries for up to 30s
# 9. Bonding completes during retry loop
# 10. Continue with authentication

# Modified _async_authenticate method:
async def _async_authenticate_lazy_bonding(self) -> bool:
    """Authenticate using lazy bonding (matching C# app approach)."""
    if not self.client:
        return False

    _LOGGER.info("Authenticating with device using lazy bonding (cypher: 0x%08X)...", self.cypher)

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
                _LOGGER.error("Service discovery timeout after %d attempts", max_wait)
                return False
        
        # Get authentication service
        auth_service = self.client.services.get_service(AUTH_SERVICE_UUID)
        if not auth_service:
            _LOGGER.error("Authentication service not found. Available services: %s", 
                        [str(s.uuid) for s in self.client.services.services])
            return False

        # CRITICAL: C# code waits 500ms AFTER getting service before getting characteristics
        await asyncio.sleep(0.5)  # Match C# BleDeviceUnlockManager.cs line 64
        
        seed_char = auth_service.get_characteristic(SEED_CHAR_UUID)
        key_char = auth_service.get_characteristic(KEY_CHAR_UUID)

        if not seed_char or not key_char:
            _LOGGER.error("Seed or key characteristic not found. Service characteristics: %s",
                        [str(c.uuid) for c in auth_service.characteristics])
            return False

        self.auth_state = AUTH_STATE_LOCKED

        # LAZY BONDING: Try to read seed - this should trigger bonding automatically
        # C# app doesn't explicitly pair - it just tries to read and handles Code=15 errors
        # Code=15 means "bonding in progress" - we retry for up to 30 seconds
        seed_data = None
        bonding_start_time = time.time()
        max_bonding_time = 30.0  # Match C# app's 30s retry window
        retry_delay = 2.0  # Match C# app's 2s retry delay
        
        for attempt in range(20):  # Up to 20 attempts (20 * 2s = 40s max, but we'll stop at 30s)
            try:
                # Check if we've exceeded the bonding timeout
                elapsed = time.time() - bonding_start_time
                if elapsed > max_bonding_time:
                    _LOGGER.error("Bonding timeout after %.1f seconds (max: %.1f)", elapsed, max_bonding_time)
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
                _LOGGER.info("✅ Seed read successful (bonding completed during attempt %d)", attempt + 1)
                break
                
            except Exception as err:
                err_str = str(err)
                
                # Code=15 means "insufficient authentication" - bonding is in progress
                # C# app retries these for up to 30s (BleManager.cs line 311)
                if "Code=15" in err_str or "code 15" in err_str.lower() or "insufficient authentication" in err_str.lower():
                    elapsed = time.time() - bonding_start_time
                    if elapsed < max_bonding_time:
                        _LOGGER.debug(
                            "Code=15 (bonding in progress) - attempt %d, elapsed: %.1fs (max: %.1fs)",
                            attempt + 1, elapsed, max_bonding_time
                        )
                        if attempt == 0:
                            _LOGGER.info("Bonding triggered by protected characteristic access - waiting for completion...")
                        await asyncio.sleep(retry_delay)  # Match C# ReadCharacteristicAsync retry delay
                        continue
                    else:
                        _LOGGER.warning("Code=15 retries exceeded time limit (%.1fs)", elapsed)
                        # Fall through to try explicit pairing
                        break
                
                # Other errors - log and retry a few times
                if attempt < 4:
                    _LOGGER.debug("Seed read attempt %d failed: %s (will retry)", attempt + 1, err)
                    if "not authorized" in err_str.lower() or "insufficient authentication" in err_str.lower():
                        await asyncio.sleep(5.0)  # Match C# BleBondingDelayMs = 5000
                    else:
                        await asyncio.sleep(1.0)
                else:
                    _LOGGER.error("Failed to read seed after %d attempts: %s", attempt + 1, err)
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
                except Exception as err:
                    _LOGGER.error("Seed read failed even after explicit pairing: %s", err)
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
        _LOGGER.info("Read seed: 0x%08X", seed)

        # Encrypt seed using TEA
        key = self._tea_encrypt(self.cypher, seed)
        _LOGGER.info("Computed key: 0x%08X", key)

        # Write key back
        key_data = key.to_bytes(4, byteorder="little")
        await self.client.write_gatt_char(key_char, key_data, response=True)
        await asyncio.sleep(0.5)  # Match C# BleCharacteristicWriteDelayMs = 500

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
        return False

    except asyncio.TimeoutError:
        _LOGGER.error("Authentication timeout")
        return False
    except Exception as err:
        _LOGGER.error("Authentication error: %s", err, exc_info=True)
        return False


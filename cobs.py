"""COBS encoding/decoding with CRC8 for OneControl BLE."""

from __future__ import annotations

import logging

_LOGGER = logging.getLogger(__name__)

# COBS constants (from C# CobsBase.cs)
FRAME_CHAR = 0x00
MAX_DATA_BYTES = 63  # 2^6 - 1 (numDataBits=6)
FRAME_BYTE_COUNT_LSB = 64  # 2^6
MAX_COMPRESSED_FRAME_BYTES = 192  # 255 - 63


def crc8_calculate(data: bytes) -> int:
    """
    Calculate CRC8 for data.
    
    Standard CRC8 with polynomial 0x07 (CRC-8).
    """
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x07
            else:
                crc <<= 1
            crc &= 0xFF
    return crc


def cobs_encode(data: bytes, prepend_start_frame: bool = True, use_crc: bool = True) -> bytes:
    """
    Encode data using COBS with CRC8.
    
    Based on C# CobsEncoder.cs implementation.
    """
    if not data:
        if prepend_start_frame:
            return bytes([FRAME_CHAR, FRAME_CHAR])
        return bytes([FRAME_CHAR])

    output = bytearray()
    
    # Prepend start frame character if requested
    if prepend_start_frame:
        output.append(FRAME_CHAR)
    
    # Calculate CRC8
    if use_crc:
        crc = crc8_calculate(data)
        # Append CRC to data for encoding
        data_with_crc = data + bytes([crc])
    else:
        data_with_crc = data
    
    # COBS encoding
    src_index = 0
    src_len = len(data_with_crc)
    
    while src_index < src_len:
        code_index = len(output)
        output.append(0xFF)  # Placeholder for code byte
        code = 1
        
        # Encode data bytes (up to MAX_DATA_BYTES or until frame char)
        while src_index < src_len and code < MAX_DATA_BYTES:
            byte_val = data_with_crc[src_index]
            if byte_val == FRAME_CHAR:
                break
            output.append(byte_val)
            src_index += 1
            code += 1
        
        # Handle frame characters
        while src_index < src_len and data_with_crc[src_index] == FRAME_CHAR:
            src_index += 1
            code += FRAME_BYTE_COUNT_LSB
            if code >= MAX_COMPRESSED_FRAME_BYTES:
                break
        
        # Set code byte
        output[code_index] = code & 0xFF
    
    # Append frame terminator
    output.append(FRAME_CHAR)
    
    return bytes(output)


def cobs_decode(data: bytes, use_crc: bool = True) -> bytes | None:
    """
    Decode COBS-encoded data with CRC8 verification.
    
    Based on C# CobsDecoder.cs implementation.
    """
    if not data:
        return None
    
    output = bytearray()
    code_byte = 0
    min_payload_size = 1 if use_crc else 0
    
    for byte_val in data:
        if byte_val == FRAME_CHAR:
            # Frame terminator - check if we have valid data
            if code_byte != 0:
                return None  # Invalid - code byte not consumed
            
            if len(output) <= min_payload_size:
                return None  # No data
            
            # Verify CRC if enabled
            if use_crc:
                if len(output) < 1:
                    return None
                received_crc = output.pop()
                calculated_crc = crc8_calculate(output)
                if received_crc != calculated_crc:
                    _LOGGER.warning(
                        "COBS CRC mismatch: received 0x%02X, calculated 0x%02X",
                        received_crc,
                        calculated_crc,
                    )
                    return None
            
            return bytes(output)
        
        if code_byte == 0:
            # Start of new code block
            code_byte = byte_val & 0xFF
        else:
            # Data byte
            code_byte -= 1
            output.append(byte_val)
        
        # Check if we need to insert frame characters
        if (code_byte & MAX_DATA_BYTES) == 0:
            while code_byte > 0:
                output.append(FRAME_CHAR)
                code_byte -= FRAME_BYTE_COUNT_LSB
    
    # No frame terminator found
    return None


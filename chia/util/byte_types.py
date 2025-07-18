# Package: utils

from __future__ import annotations


def hexstr_to_bytes(input_str: str) -> bytes:
    """
    Converts a hex string into bytes, removing the 0x if it's present.
    """
    if input_str.startswith(("0x", "0X")):
        return bytes.fromhex(input_str[2:])
    return bytes.fromhex(input_str)

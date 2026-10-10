// SPDX-License-Identifier: MIT
pragma solidity >=0.6.2 <0.9.0;

/// Byte-walking helpers: uint8(bytes1) reinterprets a byte, uint160(address)
/// is the address conversion, and `% 10` keeps a digit inside one byte.
library HexUtils {
    function toHexString(address value) internal pure returns (string memory) {
        bytes memory buffer = new bytes(40);
        uint160 v = uint160(value);
        for (uint256 i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(v >> (8 * (19 - i))));
            buffer[2 * i] = nibble(uint8(b) / 16);
            buffer[2 * i + 1] = nibble(uint8(b) % 16);
        }
        return string(buffer);
    }

    function nibble(uint8 b) internal pure returns (bytes1) {
        if (b < 10) return bytes1(b + 0x30);
        return bytes1(b + 0x57);
    }

    function digit(uint256 value) internal pure returns (bytes1) {
        return bytes1(uint8(48 + value % 10));
    }
}

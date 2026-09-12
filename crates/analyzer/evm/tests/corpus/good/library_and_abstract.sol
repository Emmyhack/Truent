// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// A math library and an abstract base: no state, no external calls.
library SafeMathLike {
    function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256) {
        require(denominator > 0, "division by zero");
        return (a * b) / denominator;
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

interface IPriceFeed {
    function latestAnswer() external view returns (int256);
    function getReserves() external view returns (uint112, uint112, uint32);
}

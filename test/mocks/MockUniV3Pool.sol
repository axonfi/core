// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Mock Uniswap V3 pool that returns a fixed TWAP tick for testing.
///      Deploy via vm.etch at the computed pool address.
contract MockUniV3Pool {
    uint128 public liquidity = 1_000_000e18; // non-zero liquidity

    int56 public tickCumulative0;
    int56 public tickCumulative1;

    /// @dev Set the tick cumulatives so that the TWAP tick = (c1 - c0) / period.
    function setTickCumulatives(int56 c0, int56 c1) external {
        tickCumulative0 = c0;
        tickCumulative1 = c1;
    }

    /// @dev Returns tick cumulatives for TWAP calculation.
    function observe(uint32[] calldata) external view returns (int56[] memory tickCumulatives, uint160[] memory) {
        tickCumulatives = new int56[](2);
        tickCumulatives[0] = tickCumulative0;
        tickCumulatives[1] = tickCumulative1;
        uint160[] memory empty = new uint160[](2);
        return (tickCumulatives, empty);
    }
}

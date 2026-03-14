// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../interfaces/IAxonRegistry.sol";
import "../interfaces/IUniswapV3Pool.sol";

/// @title TwapOracle — on-chain USD valuation via Uniswap V3 TWAP
/// @notice Converts any ERC-20 amount to a USDC-equivalent value for maxPerTxAmount enforcement.
///         Uses 30-minute TWAP from Uniswap V3 pools to resist single-block manipulation.
///
///         Routing:
///         1. token == USDC → return amount directly
///         2. token == WETH or NATIVE_ETH → WETH/USDC pool TWAP
///         3. Other tokens → try token/USDC pool, then multi-hop via token/WETH × WETH/USDC
///         4. No pool found → revert OracleUnavailable()
///
///         Owner can always rescue funds via withdraw() which has no oracle check.
library TwapOracle {
    error OracleNotConfigured();
    error OracleUnavailable();

    /// @dev Sentinel address for native ETH (matches AxonVault.NATIVE_ETH)
    address internal constant NATIVE_ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @dev TWAP observation window: 30 minutes
    uint32 internal constant TWAP_PERIOD = 1800;

    /// @dev Default fee tier to check: 0.3% (3000) — most common for major pairs
    uint24 internal constant FEE_TIER = 3000;

    /// @dev Additional fee tiers to try if the primary pool doesn't exist
    uint24 internal constant FEE_TIER_LOW = 500;
    uint24 internal constant FEE_TIER_HIGH = 10000;

    /// @dev Uniswap V3 pool init code hash (same on all chains)
    bytes32 internal constant POOL_INIT_CODE_HASH = 0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54;

    /// @notice Convert a token amount to its USDC-equivalent value using TWAP.
    /// @param registry The AxonRegistry address (provides V3 factory, USDC, WETH addresses)
    /// @param token    The token being valued
    /// @param amount   The raw amount in token base units
    /// @return usdValue The USDC-equivalent value (6 decimals, same as USDC)
    function getUsdValue(address registry, address token, uint256 amount) internal view returns (uint256 usdValue) {
        if (amount == 0) return 0;

        address usdc = IAxonRegistry(registry).usdcAddress();

        // Case 1: token IS USDC — value is the amount itself (no oracle needed)
        if (usdc != address(0) && token == usdc) return amount;

        address factory = IAxonRegistry(registry).uniswapV3Factory();
        address weth = IAxonRegistry(registry).wethAddress();

        // Oracle config not set — revert with distinct error so relayer can alert admin
        if (factory == address(0) || usdc == address(0) || weth == address(0)) {
            revert OracleNotConfigured();
        }

        // Case 2: token is native ETH or WETH — use WETH/USDC pool
        address effectiveToken = (token == NATIVE_ETH) ? weth : token;

        if (effectiveToken == weth) {
            return _getAmountFromTwap(factory, weth, usdc, amount);
        }

        // Case 3: Try direct token/USDC pool
        uint256 directValue = _tryTwap(factory, effectiveToken, usdc, amount);
        if (directValue > 0) return directValue;

        // Case 4: Multi-hop via WETH — token/WETH × WETH/USDC
        uint256 wethAmount = _tryTwap(factory, effectiveToken, weth, amount);
        if (wethAmount > 0) {
            uint256 hopValue = _tryTwap(factory, weth, usdc, wethAmount);
            if (hopValue > 0) return hopValue;
        }

        // No pool found at any fee tier — this token cannot be priced on-chain
        revert OracleUnavailable();
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// @dev Try to get TWAP price across multiple fee tiers. Returns 0 if no pool works.
    function _tryTwap(address factory, address tokenA, address tokenB, uint256 amount) internal view returns (uint256) {
        uint24[3] memory fees = [FEE_TIER, FEE_TIER_LOW, FEE_TIER_HIGH];
        for (uint256 i = 0; i < 3; i++) {
            address pool = _computePoolAddress(factory, tokenA, tokenB, fees[i]);
            if (pool.code.length == 0) continue; // pool not deployed

            // Check pool has liquidity
            try IUniswapV3Pool(pool).liquidity() returns (uint128 liq) {
                if (liq == 0) continue;
            } catch {
                continue;
            }

            // Try observe() — may revert if observations not initialized
            try IUniswapV3Pool(pool).observe(_secondsAgos()) returns (
                int56[] memory tickCumulatives, uint160[] memory
            ) {
                int24 arithmeticMeanTick = _computeMeanTick(tickCumulatives);
                return _getQuoteFromTick(arithmeticMeanTick, amount, tokenA, tokenB);
            } catch {
                // Observations not available — skip pool rather than use manipulable spot price
                continue;
            }
        }
        return 0;
    }

    /// @dev Get amount from TWAP — reverts if no pool works (used when we expect a pool to exist).
    function _getAmountFromTwap(address factory, address tokenA, address tokenB, uint256 amount)
        internal
        view
        returns (uint256)
    {
        uint256 result = _tryTwap(factory, tokenA, tokenB, amount);
        if (result == 0) revert OracleUnavailable();
        return result;
    }

    /// @dev Build the observe() secondsAgos array: [TWAP_PERIOD, 0]
    function _secondsAgos() internal pure returns (uint32[] memory secondsAgos) {
        secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;
    }

    /// @dev Compute arithmetic mean tick from cumulative tick values.
    function _computeMeanTick(int56[] memory tickCumulatives) internal pure returns (int24) {
        int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
        int24 meanTick = int24(tickDiff / int56(int32(TWAP_PERIOD)));
        // Round towards negative infinity (Uniswap convention)
        if (tickDiff < 0 && (tickDiff % int56(int32(TWAP_PERIOD)) != 0)) {
            meanTick--;
        }
        return meanTick;
    }

    /// @dev Convert an amount of tokenA to tokenB using a tick price.
    ///      Tick represents log_1.0001(tokenA/tokenB) when tokenA < tokenB (sorted order).
    function _getQuoteFromTick(int24 tick, uint256 amount, address tokenA, address tokenB)
        internal
        pure
        returns (uint256)
    {
        // Determine sorted order — Uniswap V3 pools always sort tokens
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);

        // price = 1.0001^tick represents token1/token0 (how much token1 per token0)
        // We use the ratio formula: price = (sqrtPrice)^2 / 2^192
        // For better precision with large amounts, split into two multiplications.

        uint160 sqrtPriceX96 = _getSqrtRatioAtTick(tick);

        // Use two _mulDiv calls to avoid uint256 overflow when squaring sqrtPriceX96.
        // Direct multiplication (sqrtPriceX96 * sqrtPriceX96) overflows for ticks above ~443636.
        if (tokenA == token0) {
            // tokenA is token0 → price = token1PerToken0 → multiply
            // result = amount * sqrtP / 2^96 * sqrtP / 2^96
            uint256 step1 = _mulDiv(amount, uint256(sqrtPriceX96), 1 << 96);
            return _mulDiv(step1, uint256(sqrtPriceX96), 1 << 96);
        } else {
            // tokenA is token1 → we need token0PerToken1 → divide
            // result = amount * 2^96 / sqrtP * 2^96 / sqrtP
            uint256 step1 = _mulDiv(amount, 1 << 96, uint256(sqrtPriceX96));
            return _mulDiv(step1, 1 << 96, uint256(sqrtPriceX96));
        }
    }

    /// @dev Minimal getSqrtRatioAtTick from Uniswap V3 TickMath (inlined for gas efficiency).
    function _getSqrtRatioAtTick(int24 tick) internal pure returns (uint160 sqrtPriceX96) {
        unchecked {
            uint256 absTick = tick < 0 ? uint256(-int256(tick)) : uint256(int256(tick));
            require(absTick <= 887272, "T");

            uint256 ratio =
                absTick & 0x1 != 0 ? 0xfffcb933bd6fad37aa2d162d1a594001 : 0x100000000000000000000000000000000;
            if (absTick & 0x2 != 0) ratio = (ratio * 0xfff97272373d413259a46990580e213a) >> 128;
            if (absTick & 0x4 != 0) ratio = (ratio * 0xfff2e50f5f656932ef12357cf3c7fdcc) >> 128;
            if (absTick & 0x8 != 0) ratio = (ratio * 0xffe5caca7e10e4e61c3624eaa0941cd0) >> 128;
            if (absTick & 0x10 != 0) ratio = (ratio * 0xffcb9843d60f6159c9db58835c926644) >> 128;
            if (absTick & 0x20 != 0) ratio = (ratio * 0xff973b41fa98c081472e6896dfb254c0) >> 128;
            if (absTick & 0x40 != 0) ratio = (ratio * 0xff2ea16466c96a3843ec78b326b52861) >> 128;
            if (absTick & 0x80 != 0) ratio = (ratio * 0xfe5dee046a99a2a811c461f1969c3053) >> 128;
            if (absTick & 0x100 != 0) ratio = (ratio * 0xfcbe86c7900a88aedcffc83b479aa3a4) >> 128;
            if (absTick & 0x200 != 0) ratio = (ratio * 0xf987a7253ac413176f2b074cf7815e54) >> 128;
            if (absTick & 0x400 != 0) ratio = (ratio * 0xf3392b0822b70005940c7a398e4b70f3) >> 128;
            if (absTick & 0x800 != 0) ratio = (ratio * 0xe7159475a2c29b7443b29c7fa6e889d9) >> 128;
            if (absTick & 0x1000 != 0) ratio = (ratio * 0xd097f3bdfd2022b8845ad8f792aa5825) >> 128;
            if (absTick & 0x2000 != 0) ratio = (ratio * 0xa9f746462d870fdf8a65dc1f90e061e5) >> 128;
            if (absTick & 0x4000 != 0) ratio = (ratio * 0x70d869a156d2a1b890bb3df62baf32f7) >> 128;
            if (absTick & 0x8000 != 0) ratio = (ratio * 0x31be135f97d08fd981231505542fcfa6) >> 128;
            if (absTick & 0x10000 != 0) ratio = (ratio * 0x9aa508b5b7a84e1c677de54f3e99bc9) >> 128;
            if (absTick & 0x20000 != 0) ratio = (ratio * 0x5d6af8dedb81196699c329225ee604) >> 128;
            if (absTick & 0x40000 != 0) ratio = (ratio * 0x2216e584f5fa1ea926041bedfe98) >> 128;
            if (absTick & 0x80000 != 0) ratio = (ratio * 0x48a170391f7dc42444e8fa2) >> 128;

            if (tick > 0) ratio = type(uint256).max / ratio;

            sqrtPriceX96 = uint160((ratio >> 32) + (ratio % (1 << 32) == 0 ? 0 : 1));
        }
    }

    /// @dev Compute pool address via CREATE2 (same as Uniswap V3 factory).
    function _computePoolAddress(address factory, address tokenA, address tokenB, uint24 fee)
        internal
        pure
        returns (address pool)
    {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        pool = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), factory, keccak256(abi.encode(t0, t1, fee)), POOL_INIT_CODE_HASH)
                    )
                )
            )
        );
    }

    /// @dev Full precision (a * b) / denominator with 512-bit intermediary.
    ///      Simplified from Uniswap's FullMath — sufficient for our price conversion.
    function _mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256 result) {
        // Handle simple case first
        uint256 prod0;
        uint256 prod1;
        assembly {
            let mm := mulmod(a, b, not(0))
            prod0 := mul(a, b)
            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
        }

        // If no overflow, simple division
        if (prod1 == 0) {
            require(denominator > 0);
            assembly {
                result := div(prod0, denominator)
            }
            return result;
        }

        require(denominator > prod1);

        uint256 remainder;
        assembly {
            remainder := mulmod(a, b, denominator)
        }
        assembly {
            prod1 := sub(prod1, gt(remainder, prod0))
            prod0 := sub(prod0, remainder)
        }

        uint256 twos = denominator & (0 - denominator);
        assembly {
            denominator := div(denominator, twos)
        }
        assembly {
            prod0 := div(prod0, twos)
        }
        assembly {
            twos := add(div(sub(0, twos), twos), 1)
        }
        prod0 |= prod1 * twos;

        uint256 inv = (3 * denominator) ^ 2;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;
        inv *= 2 - denominator * inv;

        result = prod0 * inv;
    }
}

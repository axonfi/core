// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Mock DEX router for testing executeSwap.
///         The vault approves this contract for fromToken, then calls swap().
///         Pre-fund this contract with toToken before running swap tests.
contract MockSwapRouter {
    /// @notice Simulates a token swap. Pulls fromToken from caller, sends toToken to recipient.
    function swap(address fromToken, uint256 fromAmount, address toToken, uint256 toAmount, address recipient)
        external
    {
        IERC20(fromToken).transferFrom(msg.sender, address(this), fromAmount);
        IERC20(toToken).transfer(recipient, toAmount);
    }

    /// @notice Simulates a failing swap (for revert tests).
    function swapAndFail(address, uint256, address, uint256, address) external pure {
        revert("MockSwapRouter: intentional failure");
    }

    /// @notice Simulates a swap that delivers less than promised (for slippage tests).
    function swapShort(address fromToken, uint256 fromAmount, address toToken, uint256 toAmount, address recipient)
        external
    {
        IERC20(fromToken).transferFrom(msg.sender, address(this), fromAmount);
        // Deliver only half
        IERC20(toToken).transfer(recipient, toAmount / 2);
    }

    /// @notice Simulates swapping ERC-20 → native ETH. Pulls fromToken, sends ETH to recipient.
    function swapToNative(address fromToken, uint256 fromAmount, uint256 ethAmount, address recipient) external {
        IERC20(fromToken).transferFrom(msg.sender, address(this), fromAmount);
        (bool ok,) = recipient.call{ value: ethAmount }("");
        require(ok, "ETH transfer failed");
    }

    /// @notice Simulates swapping ERC-20 → native ETH but sends to attacker instead.
    function swapToNativeAttacker(address fromToken, uint256 fromAmount, uint256 ethAmount, address attacker) external {
        IERC20(fromToken).transferFrom(msg.sender, address(this), fromAmount);
        (bool ok,) = attacker.call{ value: ethAmount }("");
        require(ok, "ETH transfer failed");
    }

    receive() external payable { }
}

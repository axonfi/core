// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Mock DeFi protocol for testing executeProtocol.
///         Simulates Ostium-like behavior: pulls collateral on openTrade, returns it on closeTrade.
contract MockProtocol {
    event TradeOpened(address indexed trader, address token, uint256 collateral, uint256 orderId);
    event TradeClosed(address indexed trader, uint256 orderId);
    event ActionExecuted(address indexed caller, bytes data);

    uint256 private _nextOrderId = 1;

    /// @notice Simulates opening a leveraged trade. Pulls collateral from caller.
    function openTrade(address token, uint256 collateral, uint256 pairIndex, bool isLong, uint256 leverage)
        external
        returns (uint256 orderId)
    {
        IERC20(token).transferFrom(msg.sender, address(this), collateral);
        orderId = _nextOrderId++;
        emit TradeOpened(msg.sender, token, collateral, orderId);
    }

    /// @notice Simulates closing a trade. No token transfer needed (PnL settled separately).
    function closeTrade(uint256 orderId) external {
        emit TradeClosed(msg.sender, orderId);
    }

    /// @notice Generic action that doesn't transfer tokens (for zero-amount tests).
    function noTokenAction(bytes calldata data) external {
        emit ActionExecuted(msg.sender, data);
    }

    /// @notice Payable action — receives ETH (simulates WETH.deposit, Lido.submit, etc.)
    function payableAction() external payable {
        emit PayableActionCalled(msg.sender, msg.value);
    }
    event PayableActionCalled(address indexed caller, uint256 value);

    /// @notice Always reverts (for failure tests).
    function failingAction() external pure {
        revert("MockProtocol: intentional failure");
    }

    receive() external payable { }
}

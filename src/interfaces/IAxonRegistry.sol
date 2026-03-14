// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IAxonRegistry {
    function isAuthorized(address relayer) external view returns (bool);
    function isApprovedSwapRouter(address router) external view returns (bool);
    function uniswapV3Factory() external view returns (address);
    function usdcAddress() external view returns (address);
    function wethAddress() external view returns (address);
    function isDefaultToken(address token) external view returns (bool);
    function isApprovedProtocol(address protocol) external view returns (bool);
}

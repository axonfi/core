// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "./interfaces/IAxonRegistry.sol";

/// @title AxonRegistry
/// @notice Axon-controlled registry of authorized relayers and approved swap routers.
///         All AxonVaults check against this registry before executing payments or swaps.
///         One registry is deployed per chain. Vaults store the registry address as immutable.
contract AxonRegistry is IAxonRegistry, Ownable2Step {
    uint256 public constant VERSION = 1;

    mapping(address => bool) private _authorizedRelayers;
    mapping(address => bool) private _approvedSwapRouters;

    // Default tokens — globally approved as protocols on all vaults.
    // Enables the two-step approval pattern (approve token → call DeFi protocol)
    // without the vault owner having to manually add common tokens.
    // O(1) lookup on the hot path (checked every executeProtocol call).
    // Full list reconstructable off-chain via DefaultTokenApproved/Revoked events.
    mapping(address => bool) private _isDefaultToken;

    // Globally approved protocols — usable in executeProtocol on all vaults.
    // Unlike default tokens, these allow ANY function call (not restricted to approve()).
    // Use for blue-chip protocols like WETH (deposit/withdraw), Aave, Compound, etc.
    mapping(address => bool) private _approvedProtocols;

    // Oracle config — used by vaults for on-chain TWAP price lookups
    address private _uniswapV3Factory;
    address private _usdcAddress;
    address private _wethAddress;

    event RelayerAdded(address indexed relayer);
    event RelayerRemoved(address indexed relayer);
    event SwapRouterAdded(address indexed router);
    event SwapRouterRemoved(address indexed router);
    event DefaultTokenApproved(address indexed token);
    event DefaultTokenRevoked(address indexed token);
    event ProtocolApproved(address indexed protocol);
    event ProtocolRevoked(address indexed protocol);
    event OracleConfigUpdated(address uniswapV3Factory, address usdc, address weth);

    error ZeroAddress();
    error AlreadyAuthorized();
    error NotAuthorized();
    error AlreadyApproved();
    error NotApproved();

    constructor(address initialOwner) Ownable(initialOwner) { }

    /// @dev Disabled — renouncing ownership would brick the registry.
    function renounceOwnership() public pure override {
        revert("AxonRegistry: renounce disabled");
    }

    // =========================================================================
    // Relayer management
    // =========================================================================

    /// @notice Authorize a relayer address. Only callable by Axon (owner).
    function addRelayer(address relayer) external onlyOwner {
        if (relayer == address(0)) revert ZeroAddress();
        if (_authorizedRelayers[relayer]) revert AlreadyAuthorized();
        _authorizedRelayers[relayer] = true;
        emit RelayerAdded(relayer);
    }

    /// @notice Revoke a relayer address. Only callable by Axon (owner).
    function removeRelayer(address relayer) external onlyOwner {
        if (!_authorizedRelayers[relayer]) revert NotAuthorized();
        _authorizedRelayers[relayer] = false;
        emit RelayerRemoved(relayer);
    }

    /// @notice Returns true if the address is an authorized Axon relayer.
    function isAuthorized(address relayer) external view override returns (bool) {
        return _authorizedRelayers[relayer];
    }

    // =========================================================================
    // Swap router management
    // =========================================================================

    /// @notice Approve a swap router (e.g. Uniswap, 1inch). Only callable by Axon (owner).
    function addSwapRouter(address router) external onlyOwner {
        if (router == address(0)) revert ZeroAddress();
        if (_approvedSwapRouters[router]) revert AlreadyApproved();
        _approvedSwapRouters[router] = true;
        emit SwapRouterAdded(router);
    }

    /// @notice Revoke a swap router. Only callable by Axon (owner).
    function removeSwapRouter(address router) external onlyOwner {
        if (!_approvedSwapRouters[router]) revert NotApproved();
        _approvedSwapRouters[router] = false;
        emit SwapRouterRemoved(router);
    }

    /// @notice Returns true if the address is an approved swap router.
    function isApprovedSwapRouter(address router) external view override returns (bool) {
        return _approvedSwapRouters[router];
    }

    // =========================================================================
    // Default token management
    // =========================================================================

    /// @notice Approve a token globally. Immediately usable in executeProtocol on all vaults.
    function approveDefaultToken(address token) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        if (_isDefaultToken[token]) revert AlreadyApproved();
        _isDefaultToken[token] = true;
        emit DefaultTokenApproved(token);
    }

    /// @notice Revoke a default token. Immediately blocked on all vaults.
    function revokeDefaultToken(address token) external onlyOwner {
        if (!_isDefaultToken[token]) revert NotApproved();
        _isDefaultToken[token] = false;
        emit DefaultTokenRevoked(token);
    }

    /// @notice Returns true if the token is a default token. Called by vaults on executeProtocol.
    function isDefaultToken(address token) external view override returns (bool) {
        return _isDefaultToken[token];
    }

    // =========================================================================
    // Global protocol management
    // =========================================================================

    /// @notice Approve a protocol globally. Usable in executeProtocol on all vaults.
    ///         Unlike default tokens, these allow any function call (not just approve).
    function approveProtocol(address protocol) external onlyOwner {
        if (protocol == address(0)) revert ZeroAddress();
        if (_approvedProtocols[protocol]) revert AlreadyApproved();
        _approvedProtocols[protocol] = true;
        emit ProtocolApproved(protocol);
    }

    /// @notice Revoke a globally approved protocol.
    function revokeProtocol(address protocol) external onlyOwner {
        if (!_approvedProtocols[protocol]) revert NotApproved();
        _approvedProtocols[protocol] = false;
        emit ProtocolRevoked(protocol);
    }

    /// @notice Returns true if the protocol is globally approved.
    function isApprovedProtocol(address protocol) external view override returns (bool) {
        return _approvedProtocols[protocol];
    }

    // =========================================================================
    // Oracle config (TWAP price lookups)
    // =========================================================================

    /// @notice Set the oracle config for on-chain TWAP price lookups.
    ///         Must be called after deployment for non-USDC maxPerTxAmount checks to work.
    function setOracleConfig(address uniV3Factory, address usdc, address weth) external onlyOwner {
        if (uniV3Factory == address(0) || usdc == address(0) || weth == address(0)) revert ZeroAddress();
        _uniswapV3Factory = uniV3Factory;
        _usdcAddress = usdc;
        _wethAddress = weth;
        emit OracleConfigUpdated(uniV3Factory, usdc, weth);
    }

    /// @notice Uniswap V3 factory for TWAP pool lookups.
    function uniswapV3Factory() external view override returns (address) {
        return _uniswapV3Factory;
    }

    /// @notice USDC address on this chain (base denomination for maxPerTxAmount).
    function usdcAddress() external view override returns (address) {
        return _usdcAddress;
    }

    /// @notice WETH address on this chain (used for multi-hop TWAP pricing).
    function wethAddress() external view override returns (address) {
        return _wethAddress;
    }
}

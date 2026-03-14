// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "./AxonVault.sol";

/// @title AxonVaultFactory
/// @notice Deploys AxonVault clones via EIP-1167 minimal proxies with CREATE2.
///         One factory is deployed per chain by Axon. All vaults on this chain
///         share the same AxonRegistry (set in each vault at initialization).
///
///         Vault addresses are deterministic: same owner + same nonce = same address
///         across all chains (given the factory is at the same address).
contract AxonVaultFactory is Ownable2Step {
    using Clones for address;

    /// @notice The vault implementation contract that all clones delegate to.
    address public immutable implementation;

    /// @notice The AxonRegistry address used by all vaults deployed from this factory.
    address public immutable axonRegistry;

    /// @notice Cached vault VERSION (constant across all clones, read once at construction).
    uint16 public immutable vaultVersion;

    /// @notice All vaults ever deployed from this factory, in order of deployment.
    address[] public allVaults;

    /// @notice Vaults deployed by each Owner address.
    mapping(address => address[]) public ownerVaults;

    event VaultDeployed(address indexed owner, address indexed vault, uint16 version, address axonRegistry);

    error ZeroAddress();

    constructor(address _axonRegistry, address factoryOwner) Ownable(factoryOwner) {
        if (_axonRegistry == address(0)) revert ZeroAddress();
        axonRegistry = _axonRegistry;

        // Deploy the vault implementation (never used directly, only as clone target)
        implementation = address(new AxonVault());
        vaultVersion = AxonVault(payable(implementation)).VERSION();
    }

    /// @dev Disabled — renouncing ownership would brick the factory.
    function renounceOwnership() public pure override {
        revert("AxonVaultFactory: renounce disabled");
    }

    /// @notice Deploy a new AxonVault clone for the caller (the Owner).
    ///         Uses CREATE2 with salt = keccak256(owner, nonce) for deterministic addresses.
    function deployVault() external returns (address vault) {
        uint256 nonce = ownerVaults[msg.sender].length;
        bytes32 salt = keccak256(abi.encodePacked(msg.sender, nonce));

        vault = implementation.cloneDeterministic(salt);
        AxonVault(payable(vault)).initialize(msg.sender, axonRegistry);

        allVaults.push(vault);
        ownerVaults[msg.sender].push(vault);

        emit VaultDeployed(msg.sender, vault, vaultVersion, axonRegistry);
    }

    /// @notice Predict the address of a vault before deployment.
    /// @param owner The vault owner address.
    /// @param nonce The owner's vault index (0 for first vault, 1 for second, etc.).
    function predictVaultAddress(address owner, uint256 nonce) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(owner, nonce));
        return implementation.predictDeterministicAddress(salt);
    }

    /// @notice Total number of vaults deployed from this factory.
    function vaultCount() external view returns (uint256) {
        return allVaults.length;
    }

    /// @notice Number of vaults deployed by a specific Owner.
    function ownerVaultCount(address owner) external view returns (uint256) {
        return ownerVaults[owner].length;
    }
}

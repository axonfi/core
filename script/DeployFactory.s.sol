// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/AxonVaultFactory.sol";

/// @notice Deploys a new AxonVaultFactory pointing to an existing AxonRegistry.
///         Supports --trezor/--ledger (omit PRIVATE_KEY) or raw key (set PRIVATE_KEY).
contract DeployFactory is Script {
    function run() external {
        uint256 deployerKey = vm.envOr("PRIVATE_KEY", uint256(0));
        bool useHardwareWallet = deployerKey == 0;
        address deployer = useHardwareWallet ? msg.sender : vm.addr(deployerKey);
        address registry = vm.envAddress("AXON_REGISTRY");

        console2.log("=== Deploy Factory ===");
        console2.log("Registry:", registry);
        console2.log("Owner:   ", deployer);

        if (useHardwareWallet) {
            vm.startBroadcast();
        } else {
            vm.startBroadcast(deployerKey);
        }
        AxonVaultFactory factory = new AxonVaultFactory(registry, deployer);
        vm.stopBroadcast();

        console2.log("Factory: ", address(factory));
        console2.log("Registry:", factory.axonRegistry());
    }
}

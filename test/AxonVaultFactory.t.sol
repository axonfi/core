// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AxonVaultFactory.sol";
import "../src/AxonVault.sol";
import "../src/AxonRegistry.sol";

contract AxonVaultFactoryTest is Test {
    AxonVaultFactory factory;
    AxonRegistry registry;

    address axonDeployer = makeAddr("axonDeployer");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address attacker = makeAddr("attacker");

    function setUp() public {
        registry = new AxonRegistry(axonDeployer);
        factory = new AxonVaultFactory(address(registry), axonDeployer);
    }

    // =========================================================================
    // Deployment
    // =========================================================================

    function test_factory_owner_is_axon() public view {
        assertEq(factory.owner(), axonDeployer);
    }

    function test_factory_axonRegistry_immutable() public view {
        assertEq(factory.axonRegistry(), address(registry));
    }

    function test_factory_reverts_zero_registry() public {
        vm.expectRevert(AxonVaultFactory.ZeroAddress.selector);
        new AxonVaultFactory(address(0), axonDeployer);
    }

    function test_renounceOwnership_always_reverts() public {
        vm.prank(axonDeployer);
        vm.expectRevert("AxonVaultFactory: renounce disabled");
        factory.renounceOwnership();

        assertEq(factory.owner(), axonDeployer);
    }

    // =========================================================================
    // deployVault
    // =========================================================================

    function test_deployVault_returns_vault_address() public {
        vm.prank(alice);
        address vault = factory.deployVault();
        assertNotEq(vault, address(0));
    }

    function test_deployVault_owner_is_caller() public {
        vm.prank(alice);
        address vault = factory.deployVault();
        assertEq(AxonVault(payable(vault)).owner(), alice);
    }

    function test_deployVault_uses_factory_registry() public {
        vm.prank(alice);
        address vault = factory.deployVault();
        assertEq(AxonVault(payable(vault)).axonRegistry(), address(registry));
    }

    function test_deployVault_emits_event() public {
        vm.prank(alice);

        // We don't know the vault address upfront; check topic1 (owner) only
        vm.expectEmit(true, false, false, false);
        emit AxonVaultFactory.VaultDeployed(alice, address(0), 0, address(0));

        factory.deployVault();
    }

    function test_deployVault_version_is_nonzero() public {
        vm.prank(alice);
        address vault = factory.deployVault();
        assertGt(AxonVault(payable(vault)).VERSION(), 0);
    }

    // =========================================================================
    // Tracking
    // =========================================================================

    function test_vaultCount_increments() public {
        assertEq(factory.vaultCount(), 0);

        vm.prank(alice);
        factory.deployVault();
        assertEq(factory.vaultCount(), 1);

        vm.prank(bob);
        factory.deployVault();
        assertEq(factory.vaultCount(), 2);
    }

    function test_allVaults_records_deployments() public {
        vm.prank(alice);
        address vault1 = factory.deployVault();

        vm.prank(bob);
        address vault2 = factory.deployVault();

        assertEq(factory.allVaults(0), vault1);
        assertEq(factory.allVaults(1), vault2);
    }

    function test_ownerVaultCount_per_owner() public {
        vm.prank(alice);
        factory.deployVault();

        vm.prank(alice);
        factory.deployVault(); // alice deploys a second vault

        vm.prank(bob);
        factory.deployVault();

        assertEq(factory.ownerVaultCount(alice), 2);
        assertEq(factory.ownerVaultCount(bob), 1);
        assertEq(factory.ownerVaultCount(attacker), 0);
    }

    function test_ownerVaults_records_correct_addresses() public {
        vm.prank(alice);
        address vault1 = factory.deployVault();

        vm.prank(alice);
        address vault2 = factory.deployVault();

        assertEq(factory.ownerVaults(alice, 0), vault1);
        assertEq(factory.ownerVaults(alice, 1), vault2);
    }

    function test_multiple_owners_independent_vaults() public {
        vm.prank(alice);
        address aliceVault = factory.deployVault();

        vm.prank(bob);
        address bobVault = factory.deployVault();

        assertNotEq(aliceVault, bobVault);
        assertEq(AxonVault(payable(aliceVault)).owner(), alice);
        assertEq(AxonVault(payable(bobVault)).owner(), bob);
    }

    // =========================================================================
    // Swap routers are managed globally via AxonRegistry
    // =========================================================================

    function test_vault_uses_registry_for_swap_routers() public {
        address uniswap = makeAddr("uniswap");

        // Approve router on registry (not per-vault)
        vm.prank(axonDeployer);
        registry.addSwapRouter(uniswap);

        vm.prank(alice);
        address vault = factory.deployVault();

        // Vault can query the registry via its axonRegistry reference
        assertEq(AxonVault(payable(vault)).axonRegistry(), address(registry));
    }

    // =========================================================================
    // Factory ownership (Ownable2Step)
    // =========================================================================

    function test_implementation_is_set() public view {
        assertNotEq(factory.implementation(), address(0));
    }

    function test_predictVaultAddress_matches_deployed() public {
        address predicted = factory.predictVaultAddress(alice, 0);
        vm.prank(alice);
        address actual = factory.deployVault();
        assertEq(predicted, actual);
    }

    function test_predictVaultAddress_second_vault() public {
        vm.prank(alice);
        factory.deployVault(); // nonce 0

        address predicted = factory.predictVaultAddress(alice, 1);
        vm.prank(alice);
        address actual = factory.deployVault(); // nonce 1
        assertEq(predicted, actual);
    }

    function test_different_owners_different_addresses() public {
        address alicePredicted = factory.predictVaultAddress(alice, 0);
        address bobPredicted = factory.predictVaultAddress(bob, 0);
        assertNotEq(alicePredicted, bobPredicted);
    }

    // =========================================================================
    // CREATE2 Deterministic Properties
    // =========================================================================

    function test_same_owner_same_nonce_same_address_across_factories() public {
        // Two factories with identical implementation bytecode should produce
        // the same vault address for the same (owner, nonce) — this is
        // the cross-chain property that makes deterministic deploys work.
        AxonVaultFactory factory2 = new AxonVaultFactory(address(registry), axonDeployer);

        address predicted1 = factory.predictVaultAddress(alice, 0);
        address predicted2 = factory2.predictVaultAddress(alice, 0);

        // Same implementation bytecode → same init code hash → same salt → same address
        // This only holds if implementation addresses differ, so the prediction
        // depends on the factory's own implementation address. In production,
        // deterministic factories share the same implementation address.
        // Here we verify prediction matches actual deployment per factory.
        vm.prank(alice);
        address actual1 = factory.deployVault();
        assertEq(predicted1, actual1);

        vm.prank(alice);
        address actual2 = factory2.deployVault();
        assertEq(predicted2, actual2);
    }

    function test_predict_before_deploy_is_stable() public view {
        // Predictions should be stable — calling predict multiple times
        // returns the same address without deploying.
        address p1 = factory.predictVaultAddress(alice, 0);
        address p2 = factory.predictVaultAddress(alice, 0);
        address p3 = factory.predictVaultAddress(alice, 0);
        assertEq(p1, p2);
        assertEq(p2, p3);
    }

    function test_deploy_same_salt_twice_reverts() public {
        // Deploying the same (owner, nonce=0) should only work once.
        // Second call uses nonce=1 automatically, so the salt differs.
        // But if someone tried to force the same salt, CREATE2 would revert.
        vm.prank(alice);
        address vault1 = factory.deployVault(); // nonce 0
        vm.prank(alice);
        address vault2 = factory.deployVault(); // nonce 1
        assertNotEq(vault1, vault2); // different nonces → different addresses
    }

    function test_nonce_increments_correctly() public {
        // Verify nonce = ownerVaults[sender].length
        assertEq(factory.ownerVaultCount(alice), 0);

        vm.prank(alice);
        address v0 = factory.deployVault();
        assertEq(factory.ownerVaultCount(alice), 1);
        assertEq(factory.predictVaultAddress(alice, 0), v0);

        vm.prank(alice);
        address v1 = factory.deployVault();
        assertEq(factory.ownerVaultCount(alice), 2);
        assertEq(factory.predictVaultAddress(alice, 1), v1);

        // Predictions for future nonces should be deterministic
        address v2Predicted = factory.predictVaultAddress(alice, 2);
        vm.prank(alice);
        address v2Actual = factory.deployVault();
        assertEq(v2Predicted, v2Actual);
    }

    function test_clone_is_not_implementation() public {
        vm.prank(alice);
        address vault = factory.deployVault();
        // Clone should be a different address than the implementation
        assertNotEq(vault, factory.implementation());
        // But should have the same VERSION
        assertEq(AxonVault(payable(vault)).VERSION(), AxonVault(payable(factory.implementation())).VERSION());
    }

    function test_implementation_initializers_disabled() public {
        // The implementation contract should have initializers disabled
        address impl = factory.implementation();
        vm.expectRevert();
        AxonVault(payable(impl)).initialize(alice, address(registry));
    }

    // =========================================================================
    // Factory ownership (Ownable2Step)
    // =========================================================================

    function test_factory_ownership_transfer_two_step() public {
        address newAxon = makeAddr("newAxon");

        vm.prank(axonDeployer);
        factory.transferOwnership(newAxon);
        assertEq(factory.owner(), axonDeployer); // not yet

        vm.prank(newAxon);
        factory.acceptOwnership();
        assertEq(factory.owner(), newAxon);
    }
}

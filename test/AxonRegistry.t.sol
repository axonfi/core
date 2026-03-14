// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AxonRegistry.sol";

contract AxonRegistryTest is Test {
    AxonRegistry registry;

    address owner = makeAddr("owner");
    address relayerA = makeAddr("relayerA");
    address relayerB = makeAddr("relayerB");
    address routerA = makeAddr("routerA");
    address routerB = makeAddr("routerB");
    address attacker = makeAddr("attacker");

    function setUp() public {
        registry = new AxonRegistry(owner);
    }

    // =========================================================================
    // Deployment
    // =========================================================================

    function test_owner_is_set() public view {
        assertEq(registry.owner(), owner);
    }

    function test_no_relayers_authorized_at_deploy() public view {
        assertFalse(registry.isAuthorized(relayerA));
    }

    function test_no_swap_routers_approved_at_deploy() public view {
        assertFalse(registry.isApprovedSwapRouter(routerA));
    }

    // =========================================================================
    // addRelayer
    // =========================================================================

    function test_addRelayer_authorizes_address() public {
        vm.prank(owner);
        registry.addRelayer(relayerA);
        assertTrue(registry.isAuthorized(relayerA));
    }

    function test_addRelayer_emits_event() public {
        vm.expectEmit(true, false, false, false);
        emit AxonRegistry.RelayerAdded(relayerA);

        vm.prank(owner);
        registry.addRelayer(relayerA);
    }

    function test_addRelayer_multiple() public {
        vm.startPrank(owner);
        registry.addRelayer(relayerA);
        registry.addRelayer(relayerB);
        vm.stopPrank();

        assertTrue(registry.isAuthorized(relayerA));
        assertTrue(registry.isAuthorized(relayerB));
    }

    function test_addRelayer_reverts_zero_address() public {
        vm.prank(owner);
        vm.expectRevert(AxonRegistry.ZeroAddress.selector);
        registry.addRelayer(address(0));
    }

    function test_addRelayer_reverts_already_authorized() public {
        vm.startPrank(owner);
        registry.addRelayer(relayerA);
        vm.expectRevert(AxonRegistry.AlreadyAuthorized.selector);
        registry.addRelayer(relayerA);
        vm.stopPrank();
    }

    function test_addRelayer_reverts_non_owner() public {
        vm.prank(attacker);
        vm.expectRevert();
        registry.addRelayer(relayerA);
    }

    // =========================================================================
    // removeRelayer
    // =========================================================================

    function test_removeRelayer_deauthorizes_address() public {
        vm.startPrank(owner);
        registry.addRelayer(relayerA);
        registry.removeRelayer(relayerA);
        vm.stopPrank();

        assertFalse(registry.isAuthorized(relayerA));
    }

    function test_removeRelayer_emits_event() public {
        vm.prank(owner);
        registry.addRelayer(relayerA);

        vm.expectEmit(true, false, false, false);
        emit AxonRegistry.RelayerRemoved(relayerA);

        vm.prank(owner);
        registry.removeRelayer(relayerA);
    }

    function test_removeRelayer_does_not_affect_other_relayers() public {
        vm.startPrank(owner);
        registry.addRelayer(relayerA);
        registry.addRelayer(relayerB);
        registry.removeRelayer(relayerA);
        vm.stopPrank();

        assertFalse(registry.isAuthorized(relayerA));
        assertTrue(registry.isAuthorized(relayerB));
    }

    function test_removeRelayer_reverts_not_authorized() public {
        vm.prank(owner);
        vm.expectRevert(AxonRegistry.NotAuthorized.selector);
        registry.removeRelayer(relayerA);
    }

    function test_removeRelayer_reverts_non_owner() public {
        vm.prank(owner);
        registry.addRelayer(relayerA);

        vm.prank(attacker);
        vm.expectRevert();
        registry.removeRelayer(relayerA);
    }

    // =========================================================================
    // addSwapRouter
    // =========================================================================

    function test_addSwapRouter_approves_address() public {
        vm.prank(owner);
        registry.addSwapRouter(routerA);
        assertTrue(registry.isApprovedSwapRouter(routerA));
    }

    function test_addSwapRouter_emits_event() public {
        vm.expectEmit(true, false, false, false);
        emit AxonRegistry.SwapRouterAdded(routerA);

        vm.prank(owner);
        registry.addSwapRouter(routerA);
    }

    function test_addSwapRouter_multiple() public {
        vm.startPrank(owner);
        registry.addSwapRouter(routerA);
        registry.addSwapRouter(routerB);
        vm.stopPrank();

        assertTrue(registry.isApprovedSwapRouter(routerA));
        assertTrue(registry.isApprovedSwapRouter(routerB));
    }

    function test_addSwapRouter_reverts_zero_address() public {
        vm.prank(owner);
        vm.expectRevert(AxonRegistry.ZeroAddress.selector);
        registry.addSwapRouter(address(0));
    }

    function test_addSwapRouter_reverts_already_approved() public {
        vm.startPrank(owner);
        registry.addSwapRouter(routerA);
        vm.expectRevert(AxonRegistry.AlreadyApproved.selector);
        registry.addSwapRouter(routerA);
        vm.stopPrank();
    }

    function test_addSwapRouter_reverts_non_owner() public {
        vm.prank(attacker);
        vm.expectRevert();
        registry.addSwapRouter(routerA);
    }

    // =========================================================================
    // removeSwapRouter
    // =========================================================================

    function test_removeSwapRouter_revokes_address() public {
        vm.startPrank(owner);
        registry.addSwapRouter(routerA);
        registry.removeSwapRouter(routerA);
        vm.stopPrank();

        assertFalse(registry.isApprovedSwapRouter(routerA));
    }

    function test_removeSwapRouter_emits_event() public {
        vm.prank(owner);
        registry.addSwapRouter(routerA);

        vm.expectEmit(true, false, false, false);
        emit AxonRegistry.SwapRouterRemoved(routerA);

        vm.prank(owner);
        registry.removeSwapRouter(routerA);
    }

    function test_removeSwapRouter_does_not_affect_other_routers() public {
        vm.startPrank(owner);
        registry.addSwapRouter(routerA);
        registry.addSwapRouter(routerB);
        registry.removeSwapRouter(routerA);
        vm.stopPrank();

        assertFalse(registry.isApprovedSwapRouter(routerA));
        assertTrue(registry.isApprovedSwapRouter(routerB));
    }

    function test_removeSwapRouter_reverts_not_approved() public {
        vm.prank(owner);
        vm.expectRevert(AxonRegistry.NotApproved.selector);
        registry.removeSwapRouter(routerA);
    }

    function test_removeSwapRouter_reverts_non_owner() public {
        vm.prank(owner);
        registry.addSwapRouter(routerA);

        vm.prank(attacker);
        vm.expectRevert();
        registry.removeSwapRouter(routerA);
    }

    // =========================================================================
    // Relayers and routers are independent
    // =========================================================================

    function test_relayer_and_router_are_independent() public {
        vm.startPrank(owner);
        registry.addRelayer(relayerA);
        registry.addSwapRouter(routerA);
        vm.stopPrank();

        assertTrue(registry.isAuthorized(relayerA));
        assertFalse(registry.isApprovedSwapRouter(relayerA));
        assertTrue(registry.isApprovedSwapRouter(routerA));
        assertFalse(registry.isAuthorized(routerA));
    }

    // =========================================================================
    // Ownership transfer (Ownable2Step)
    // =========================================================================

    function test_ownership_transfer_requires_acceptance() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        registry.transferOwnership(newOwner);

        // Still original owner until accepted
        assertEq(registry.owner(), owner);

        vm.prank(newOwner);
        registry.acceptOwnership();

        assertEq(registry.owner(), newOwner);
    }

    function test_renounceOwnership_always_reverts() public {
        vm.prank(owner);
        vm.expectRevert("AxonRegistry: renounce disabled");
        registry.renounceOwnership();

        // Still owned
        assertEq(registry.owner(), owner);
    }

    function test_pending_owner_cannot_act_before_accepting() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        registry.transferOwnership(newOwner);

        // newOwner tries to add relayer before accepting — should fail
        vm.prank(newOwner);
        vm.expectRevert();
        registry.addRelayer(relayerA);
    }

    // =========================================================================
    // approveDefaultToken
    // =========================================================================

    address tokenA = makeAddr("tokenA");
    address tokenB = makeAddr("tokenB");
    address tokenC = makeAddr("tokenC");

    function test_approveDefaultToken_marks_as_default() public {
        vm.prank(owner);
        registry.approveDefaultToken(tokenA);
        assertTrue(registry.isDefaultToken(tokenA));
    }

    function test_approveDefaultToken_emits_event() public {
        vm.expectEmit(true, false, false, false);
        emit AxonRegistry.DefaultTokenApproved(tokenA);

        vm.prank(owner);
        registry.approveDefaultToken(tokenA);
    }

    function test_approveDefaultToken_multiple() public {
        vm.startPrank(owner);
        registry.approveDefaultToken(tokenA);
        registry.approveDefaultToken(tokenB);
        registry.approveDefaultToken(tokenC);
        vm.stopPrank();

        assertTrue(registry.isDefaultToken(tokenA));
        assertTrue(registry.isDefaultToken(tokenB));
        assertTrue(registry.isDefaultToken(tokenC));
    }

    function test_approveDefaultToken_reverts_zero_address() public {
        vm.prank(owner);
        vm.expectRevert(AxonRegistry.ZeroAddress.selector);
        registry.approveDefaultToken(address(0));
    }

    function test_approveDefaultToken_reverts_duplicate() public {
        vm.startPrank(owner);
        registry.approveDefaultToken(tokenA);
        vm.expectRevert(AxonRegistry.AlreadyApproved.selector);
        registry.approveDefaultToken(tokenA);
        vm.stopPrank();
    }

    function test_approveDefaultToken_reverts_non_owner() public {
        vm.prank(attacker);
        vm.expectRevert();
        registry.approveDefaultToken(tokenA);
    }

    // =========================================================================
    // revokeDefaultToken
    // =========================================================================

    function test_revokeDefaultToken_clears_mapping() public {
        vm.startPrank(owner);
        registry.approveDefaultToken(tokenA);
        registry.revokeDefaultToken(tokenA);
        vm.stopPrank();

        assertFalse(registry.isDefaultToken(tokenA));
    }

    function test_revokeDefaultToken_emits_event() public {
        vm.prank(owner);
        registry.approveDefaultToken(tokenA);

        vm.expectEmit(true, false, false, false);
        emit AxonRegistry.DefaultTokenRevoked(tokenA);

        vm.prank(owner);
        registry.revokeDefaultToken(tokenA);
    }

    function test_revokeDefaultToken_does_not_affect_other_tokens() public {
        vm.startPrank(owner);
        registry.approveDefaultToken(tokenA);
        registry.approveDefaultToken(tokenB);
        registry.revokeDefaultToken(tokenA);
        vm.stopPrank();

        assertFalse(registry.isDefaultToken(tokenA));
        assertTrue(registry.isDefaultToken(tokenB));
    }

    function test_revokeDefaultToken_allows_re_add() public {
        vm.startPrank(owner);
        registry.approveDefaultToken(tokenA);
        registry.revokeDefaultToken(tokenA);
        registry.approveDefaultToken(tokenA);
        vm.stopPrank();

        assertTrue(registry.isDefaultToken(tokenA));
    }

    function test_revokeDefaultToken_reverts_not_in_list() public {
        vm.prank(owner);
        vm.expectRevert(AxonRegistry.NotApproved.selector);
        registry.revokeDefaultToken(tokenA);
    }

    function test_revokeDefaultToken_reverts_non_owner() public {
        vm.prank(owner);
        registry.approveDefaultToken(tokenA);

        vm.prank(attacker);
        vm.expectRevert();
        registry.revokeDefaultToken(tokenA);
    }

    // =========================================================================
    // isDefaultToken — false at deploy
    // =========================================================================

    function test_no_default_tokens_at_deploy() public view {
        assertFalse(registry.isDefaultToken(tokenA));
    }

    // =========================================================================
    // Default tokens are independent from relayers/routers
    // =========================================================================

    function test_default_tokens_independent_from_relayers_and_routers() public {
        vm.startPrank(owner);
        registry.approveDefaultToken(tokenA);
        registry.addRelayer(relayerA);
        registry.addSwapRouter(routerA);
        vm.stopPrank();

        // Token is not a relayer or router
        assertFalse(registry.isAuthorized(tokenA));
        assertFalse(registry.isApprovedSwapRouter(tokenA));

        // Relayer/router is not a default token
        assertFalse(registry.isDefaultToken(relayerA));
        assertFalse(registry.isDefaultToken(routerA));
    }
}

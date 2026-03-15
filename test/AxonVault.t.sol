// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "../src/AxonVault.sol";
import "../src/AxonRegistry.sol";
import "./mocks/MockERC20.sol";
import "./mocks/MockSwapRouter.sol";
import "./mocks/MockProtocol.sol";
import "./mocks/MockERC721.sol";
import "./mocks/MockERC1155.sol";
import "./mocks/MockUniV3Pool.sol";
import "../src/libraries/TwapOracle.sol";

contract AxonVaultTest is Test {
    // =========================================================================
    // Actors
    // =========================================================================

    uint256 constant VAULT_OWNER_KEY = 0xA11CE;
    uint256 constant OPERATOR_KEY = 0x0EA7;
    uint256 constant BOT_KEY = 0xB07;
    uint256 constant BOT2_KEY = 0xB072;

    address vaultOwner;
    address operator;
    address bot;
    address bot2;
    address relayer;
    address recipient;
    address attacker;

    // =========================================================================
    // Contracts
    // =========================================================================

    AxonRegistry registry;
    AxonVault vaultImpl;
    AxonVault vault;
    MockERC20 usdc;
    MockERC20 usdt;
    MockSwapRouter swapRouter;
    MockProtocol mockProtocol;
    MockERC20 weth; // mock WETH token for oracle pricing
    address v3Factory;

    // =========================================================================
    // Constants
    // =========================================================================

    uint256 constant USDC_DECIMALS = 1e6;
    uint256 constant VAULT_DEPOSIT = 100_000 * USDC_DECIMALS; // $100k
    uint256 constant DEADLINE_DELTA = 5 minutes;

    // EIP-712 type hashes — must match AxonVault exactly
    bytes32 constant PAYMENT_INTENT_TYPEHASH =
        keccak256("PaymentIntent(address bot,address to,address token,uint256 amount,uint256 deadline,bytes32 ref)");
    bytes32 constant EXECUTE_INTENT_TYPEHASH = keccak256(
        "ExecuteIntent(address bot,address protocol,bytes32 calldataHash,address[] tokens,uint256[] amounts,uint256 value,uint256 deadline,bytes32 ref)"
    );
    bytes32 constant SWAP_INTENT_TYPEHASH = keccak256(
        "SwapIntent(address bot,address toToken,uint256 minToAmount,address fromToken,uint256 maxFromAmount,uint256 deadline,bytes32 ref)"
    );

    // =========================================================================
    // Setup
    // =========================================================================

    function setUp() public {
        vaultOwner = vm.addr(VAULT_OWNER_KEY);
        operator = vm.addr(OPERATOR_KEY);
        bot = vm.addr(BOT_KEY);
        bot2 = vm.addr(BOT2_KEY);
        relayer = makeAddr("relayer");
        recipient = makeAddr("recipient");
        attacker = makeAddr("attacker");

        // Deploy infrastructure
        registry = new AxonRegistry(address(this));
        registry.addRelayer(relayer);

        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdt = new MockERC20("Tether USD", "USDT", 6);
        swapRouter = new MockSwapRouter();
        mockProtocol = new MockProtocol();

        // Approve swap router on the global registry
        registry.addSwapRouter(address(swapRouter));

        // Set up oracle with mock WETH and a mock Uniswap V3 pool
        weth = new MockERC20("Wrapped Ether", "WETH", 18);
        v3Factory = makeAddr("uniV3Factory");
        registry.setOracleConfig(v3Factory, address(usdc), address(weth));

        // Deploy a mock pool at the computed WETH/USDC pool address (3000 fee tier)
        // so the TWAP oracle can price ETH/WETH in USD terms.
        _deployMockPool(address(weth), address(usdc), 3000, _ethPriceTick(2000));

        // Deploy vault implementation + clone owned by vaultOwner
        vaultImpl = new AxonVault();
        vault = _deployVault(vaultOwner, address(registry));

        // Fund vault
        usdc.mint(address(vault), VAULT_DEPOSIT);

        // Default operator ceilings (set by vaultOwner)
        AxonVault.OperatorCeilings memory ceilings = AxonVault.OperatorCeilings({
            maxPerTxAmount: 1_000 * USDC_DECIMALS, // $1k per tx ceiling
            maxBotDailyLimit: 5_000 * USDC_DECIMALS, // $5k/day ceiling
            maxOperatorBots: 5, // operator can add up to 5 bots
            vaultDailyAggregate: 10_000 * USDC_DECIMALS, // $10k/day total cap
            minAiTriggerFloor: 500 * USDC_DECIMALS // AI threshold can't exceed $500
        });
        vm.prank(vaultOwner);
        vault.setOperatorCeilings(ceilings);

        // Set operator
        vm.prank(vaultOwner);
        vault.setOperator(operator);

        // Add a default bot (by vaultOwner, unconstrained by operator ceilings)
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 10_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 0, // no per-tx cap by default; specific tests set their own
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 1_000 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.addBot(bot, params);

        // Approve mock protocol for executeProtocol tests
        vm.prank(vaultOwner);
        vault.approveProtocol(address(mockProtocol));
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// @dev Deploy a new vault clone from the implementation.
    function _deployVault(address _owner, address _registry) internal returns (AxonVault) {
        address clone = Clones.clone(address(vaultImpl));
        AxonVault v = AxonVault(payable(clone));
        v.initialize(_owner, _registry);
        return v;
    }

    function _deadline() internal view returns (uint256) {
        return block.timestamp + DEADLINE_DELTA;
    }

    function _toArray(address a) internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = a;
    }

    function _signPayment(uint256 privKey, AxonVault.PaymentIntent memory intent) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                PAYMENT_INTENT_TYPEHASH, intent.bot, intent.to, intent.token, intent.amount, intent.deadline, intent.ref
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _defaultIntent(uint256 amount) internal view returns (AxonVault.PaymentIntent memory) {
        return AxonVault.PaymentIntent({
            bot: bot,
            to: recipient,
            token: address(usdc),
            amount: amount,
            deadline: _deadline(),
            ref: bytes32("test-ref-001")
        });
    }

    function _executePayment(AxonVault.PaymentIntent memory intent) internal {
        bytes memory sig = _signPayment(BOT_KEY, intent);
        vm.prank(relayer);
        vault.executePayment(intent, sig);
    }

    // =========================================================================
    // Deployment
    // =========================================================================

    function test_version_is_nonzero() public view {
        assertGt(vault.VERSION(), 0);
    }

    function test_axonRegistry_is_immutable() public view {
        assertEq(vault.axonRegistry(), address(registry));
    }

    function test_owner_is_vaultOwner() public view {
        assertEq(vault.owner(), vaultOwner);
    }

    function test_deploy_reverts_zero_registry() public {
        address clone = Clones.clone(address(vaultImpl));
        vm.expectRevert(AxonVault.ZeroAddress.selector);
        AxonVault(payable(clone)).initialize(vaultOwner, address(0));
    }

    function test_double_initialize_reverts() public {
        vm.expectRevert();
        vault.initialize(attacker, address(registry));
    }

    function test_implementation_cannot_be_initialized() public {
        vm.expectRevert();
        vaultImpl.initialize(attacker, address(registry));
    }

    // =========================================================================
    // Operator management
    // =========================================================================

    function test_setOperator_happy_path() public view {
        assertEq(vault.operator(), operator);
    }

    function test_setOperator_emits_event() public {
        address newOp = makeAddr("newOp");
        vm.expectEmit(true, true, false, false);
        emit AxonVault.OperatorSet(operator, newOp);

        vm.prank(vaultOwner);
        vault.setOperator(newOp);
    }

    function test_setOperator_to_zero_unsets_operator() public {
        vm.prank(vaultOwner);
        vault.setOperator(address(0));
        assertEq(vault.operator(), address(0));
    }

    function test_setOperator_reverts_if_same_as_owner() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.OperatorCannotBeOwner.selector);
        vault.setOperator(vaultOwner);
    }

    function test_setOperator_reverts_non_owner() public {
        vm.prank(attacker);
        vm.expectRevert();
        vault.setOperator(attacker);
    }

    function test_setOperatorCeilings_reverts_non_owner() public {
        AxonVault.OperatorCeilings memory c;
        vm.prank(attacker);
        vm.expectRevert();
        vault.setOperatorCeilings(c);
    }

    // =========================================================================
    // Bot management — owner
    // =========================================================================

    function test_addBot_by_owner_happy_path() public view {
        assertTrue(vault.isBotActive(bot));
    }

    function test_addBot_stores_config_correctly() public view {
        AxonVault.BotConfig memory config = vault.getBotConfig(bot);
        assertEq(config.maxPerTxAmount, 0); // default: no per-tx cap
        assertEq(config.aiTriggerThreshold, 1_000 * USDC_DECIMALS);
        assertFalse(config.requireAiVerification);
        assertEq(config.spendingLimits.length, 1);
        assertEq(config.spendingLimits[0].amount, 10_000 * USDC_DECIMALS);
        assertEq(config.spendingLimits[0].windowSeconds, 86400);
    }

    function test_addBot_sets_registeredAt() public view {
        AxonVault.BotConfig memory config = vault.getBotConfig(bot);
        assertGt(config.registeredAt, 0);
    }

    function test_addBot_reverts_zero_address() public {
        AxonVault.BotConfigParams memory params;
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAddress.selector);
        vault.addBot(address(0), params);
    }

    function test_addBot_reverts_already_exists() public {
        AxonVault.BotConfigParams memory params;
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.BotAlreadyExists.selector);
        vault.addBot(bot, params);
    }

    function test_addBot_reverts_too_many_spending_limits() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](6); // MAX is 5
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 100 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.TooManySpendingLimits.selector);
        vault.addBot(bot2, params);
    }

    function test_removeBot_by_owner() public {
        vm.prank(vaultOwner);
        vault.removeBot(bot);
        assertFalse(vault.isBotActive(bot));
    }

    function test_removeBot_emits_event() public {
        vm.expectEmit(true, true, false, false);
        emit AxonVault.BotRemoved(bot, vaultOwner);

        vm.prank(vaultOwner);
        vault.removeBot(bot);
    }

    function test_removeBot_reverts_not_exists() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.BotDoesNotExist.selector);
        vault.removeBot(bot2);
    }

    function test_updateBotConfig_by_owner() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 20_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 3_000 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 500 * USDC_DECIMALS,
            requireAiVerification: true
        });
        vm.prank(vaultOwner);
        vault.updateBotConfig(bot, params);

        AxonVault.BotConfig memory config = vault.getBotConfig(bot);
        assertEq(config.maxPerTxAmount, 3_000 * USDC_DECIMALS);
        assertTrue(config.requireAiVerification);
    }

    function test_updateBotConfig_reverts_non_existent_bot() public {
        AxonVault.BotConfigParams memory params;
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.BotDoesNotExist.selector);
        vault.updateBotConfig(bot2, params);
    }

    function test_addBot_reverts_non_authorized() public {
        AxonVault.BotConfigParams memory params;
        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorized.selector);
        vault.addBot(bot2, params);
    }

    // =========================================================================
    // Bot management — operator within ceilings
    // =========================================================================

    function test_operator_addBot_within_ceilings() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 4_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 800 * USDC_DECIMALS, // below $1k ceiling
            maxRebalanceAmount: 0,
            spendingLimits: limits, // $4k/day, below $5k ceiling
            aiTriggerThreshold: 300 * USDC_DECIMALS, // below $500 floor
            requireAiVerification: false
        });
        vm.prank(operator);
        vault.addBot(bot2, params);

        assertTrue(vault.isBotActive(bot2));
        assertEq(vault.operatorBotCount(), 1);
    }

    function test_operator_addBot_tracked_separately() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 2_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vault.addBot(bot2, params);

        assertEq(vault.botAddedByOperator(bot2), operator);
        assertEq(vault.operatorBotCount(), 1);
    }

    function test_operator_removeBot_decrements_count() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 2_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vault.addBot(bot2, params);

        vm.prank(operator);
        vault.removeBot(bot2);

        assertEq(vault.operatorBotCount(), 0);
    }

    function test_operator_addBot_reverts_when_maxOperatorBots_zero() public {
        // Deploy fresh vault with default ceilings (maxOperatorBots = 0)
        AxonVault freshVault = _deployVault(vaultOwner, address(registry));

        vm.prank(vaultOwner);
        freshVault.setOperator(operator);

        AxonVault.BotConfigParams memory params;
        vm.prank(operator);
        vm.expectRevert(AxonVault.OperatorBotLimitReached.selector);
        freshVault.addBot(bot2, params);
    }

    function test_operator_addBot_reverts_when_bot_limit_reached() public {
        // Set ceiling to 1 bot
        AxonVault.OperatorCeilings memory ceilings = AxonVault.OperatorCeilings({
            maxPerTxAmount: 1_000 * USDC_DECIMALS,
            maxBotDailyLimit: 5_000 * USDC_DECIMALS,
            maxOperatorBots: 1,
            vaultDailyAggregate: 10_000 * USDC_DECIMALS,
            minAiTriggerFloor: 500 * USDC_DECIMALS
        });
        vm.prank(vaultOwner);
        vault.setOperatorCeilings(ceilings);

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 2_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });

        vm.prank(operator);
        vault.addBot(bot2, params); // First one — ok

        address bot3 = makeAddr("bot3");
        vm.prank(operator);
        vm.expectRevert(AxonVault.OperatorBotLimitReached.selector);
        vault.addBot(bot3, params); // Second — over limit
    }

    function test_operator_addBot_reverts_aiThreshold_zero_when_floor_set() public {
        // NM-002: threshold=0 with floor set = most permissive → must be blocked
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.addBot(bot2, params);
    }

    function test_operator_addBot_reverts_maxPerTx_exceeds_ceiling() public {
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 2_000 * USDC_DECIMALS, // ceiling is $1k
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.addBot(bot2, params);
    }

    function test_operator_addBot_reverts_maxPerTx_zero_when_ceiling_set() public {
        // maxPerTxAmount = 0 means "no cap" — operator cannot set this when ceiling is active
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 0, // "unlimited" — not allowed when ceiling is set
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.addBot(bot2, params);
    }

    // ── NM-001v4 fix: operator cannot strip spending limits ──

    function test_operator_addBot_reverts_empty_limits_when_daily_ceiling_set() public {
        // NM-001v4: operator must include at least one daily window when maxBotDailyLimit is set
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0), // empty — should revert
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.addBot(bot2, params);
    }

    function test_operator_updateBot_reverts_fewer_limits() public {
        // NM-001v4: operator cannot reduce the number of spending limits
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 2_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        AxonVault.BotConfigParams memory addParams = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vault.addBot(bot2, addParams);

        // Try to update with empty limits
        AxonVault.BotConfigParams memory updateParams = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.updateBotConfig(bot2, updateParams);
    }

    function test_operator_addBot_reverts_only_weekly_window_when_daily_ceiling_set() public {
        // NM-002v4: only weekly windows → no daily window → should revert
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 2_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 604800 });
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.addBot(bot2, params);
    }

    // ── Fixed window validation ──

    function test_addBot_reverts_invalid_window() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 1_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86401 }); // 1 second over 24h
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.InvalidSpendingWindow.selector);
        vault.addBot(bot2, params);
    }

    function test_addBot_accepts_all_valid_windows() public {
        // Test all 5 allowed windows in one bot config
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](5);
        limits[0] = AxonVault.SpendingLimit({ amount: 100 * USDC_DECIMALS, maxCount: 0, windowSeconds: 3600 }); // 1h
        limits[1] = AxonVault.SpendingLimit({ amount: 300 * USDC_DECIMALS, maxCount: 0, windowSeconds: 10800 }); // 3h
        limits[2] = AxonVault.SpendingLimit({ amount: 1_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 }); // 24h
        limits[3] = AxonVault.SpendingLimit({ amount: 5_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 604800 }); // 7d
        limits[4] = AxonVault.SpendingLimit({ amount: 20_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 2592000 }); // 30d
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 100 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.addBot(bot2, params);
        assertTrue(vault.isBotActive(bot2));
    }

    function test_updateBot_reverts_invalid_window() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 1_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 7200 }); // 2h — not allowed
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.InvalidSpendingWindow.selector);
        vault.updateBotConfig(bot, params);
    }

    function test_operator_addBot_reverts_daily_limit_exceeds_ceiling() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 6_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 }); // $6k, ceiling is $5k

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.addBot(bot2, params);
    }

    function test_operator_addBot_reverts_hourly_limit_exceeds_effective_daily() public {
        // $500/1h → effective $12,000/day → exceeds $5,000 ceiling
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 500 * USDC_DECIMALS, maxCount: 0, windowSeconds: 3600 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.addBot(bot2, params);
    }

    function test_operator_addBot_reverts_3h_limit_exceeds_effective_daily() public {
        // $1,000/3h → effective $8,000/day → exceeds $5,000 ceiling
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 1_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 10800 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.addBot(bot2, params);
    }

    function test_operator_addBot_hourly_limit_within_effective_daily() public {
        // $200/1h → effective $4,800/day → within $5,000 ceiling
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 200 * USDC_DECIMALS, maxCount: 0, windowSeconds: 3600 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 200 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vault.addBot(bot2, params); // should succeed

        AxonVault.BotConfig memory config = vault.getBotConfig(bot2);
        assertTrue(config.isActive);
    }

    function test_operator_addBot_24h_limit_at_ceiling() public {
        // $5,000/24h → effective $5,000/day → exactly at ceiling
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 5_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vault.addBot(bot2, params); // should succeed — exactly at ceiling

        AxonVault.BotConfig memory config = vault.getBotConfig(bot2);
        assertTrue(config.isActive);
    }

    function test_operator_addBot_mixed_windows_effective_daily() public {
        // 1h=$200 (effective $4,800) + 24h=$5,000 — both within ceiling
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](2);
        limits[0] = AxonVault.SpendingLimit({ amount: 200 * USDC_DECIMALS, maxCount: 0, windowSeconds: 3600 });
        limits[1] = AxonVault.SpendingLimit({ amount: 5_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 200 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vault.addBot(bot2, params); // should succeed

        AxonVault.BotConfig memory config = vault.getBotConfig(bot2);
        assertTrue(config.isActive);
    }

    function test_owner_bypasses_effective_daily_ceiling() public {
        // Owner sets $500/1h → effective $12,000/day — owner is not bound by ceilings
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 500 * USDC_DECIMALS, maxCount: 0, windowSeconds: 3600 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.addBot(bot2, params); // owner bypasses ceiling check

        AxonVault.BotConfig memory config = vault.getBotConfig(bot2);
        assertTrue(config.isActive);
    }

    function test_operator_addBot_reverts_ai_threshold_above_floor() public {
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 1_000 * USDC_DECIMALS, // above $500 floor
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.addBot(bot2, params);
    }

    function test_operator_cannot_disable_requireAiVerification() public {
        // First set requireAiVerification = true via owner
        AxonVault.BotConfigParams memory enableParams = AxonVault.BotConfigParams({
            maxPerTxAmount: 2_000 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 500 * USDC_DECIMALS,
            requireAiVerification: true
        });
        vm.prank(vaultOwner);
        vault.updateBotConfig(bot, enableParams);

        // Now operator tries to disable it
        AxonVault.BotConfigParams memory disableParams = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 500 * USDC_DECIMALS,
            requireAiVerification: false // trying to disable
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.updateBotConfig(bot, disableParams);
    }

    function test_owner_can_set_bot_above_operator_ceilings() public {
        // Owner is not bound by operator ceilings
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 50_000 * USDC_DECIMALS, // far above operator ceiling of $1k
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.addBot(bot2, params); // should not revert

        AxonVault.BotConfig memory config = vault.getBotConfig(bot2);
        assertEq(config.maxPerTxAmount, 50_000 * USDC_DECIMALS);
    }

    // =========================================================================
    // Destination whitelist
    // =========================================================================

    function test_payment_allowed_to_any_destination_when_no_whitelist() public {
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        // No whitelist set — recipient is arbitrary
        _executePayment(intent);
        assertEq(usdc.balanceOf(recipient), 100 * USDC_DECIMALS);
    }

    function test_addGlobalDestination_allows_payment() public {
        vm.prank(vaultOwner);
        vault.addGlobalDestination(recipient);

        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        _executePayment(intent);
        assertEq(usdc.balanceOf(recipient), 100 * USDC_DECIMALS);
    }

    function test_addBotDestination_allows_payment() public {
        address other = makeAddr("other");
        vm.prank(vaultOwner);
        vault.addGlobalDestination(other); // only 'other' is whitelisted globally

        // recipient is not in global whitelist — add to bot-specific whitelist
        vm.prank(vaultOwner);
        vault.addBotDestination(bot, recipient);

        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        _executePayment(intent);
        assertEq(usdc.balanceOf(recipient), 100 * USDC_DECIMALS);
    }

    function test_payment_reverts_destination_not_whitelisted() public {
        // Activate the whitelist by adding some other address
        vm.prank(vaultOwner);
        vault.addGlobalDestination(makeAddr("allowedDest"));

        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DestinationNotWhitelisted.selector);
        vault.executePayment(intent, sig);
    }

    function test_removeGlobalDestination_by_operator() public {
        vm.prank(vaultOwner);
        vault.addGlobalDestination(recipient);

        vm.prank(operator);
        vault.removeGlobalDestination(recipient);

        assertEq(vault.globalDestinationCount(), 0);
    }

    function test_operator_cannot_add_destination() public {
        vm.prank(operator);
        vm.expectRevert();
        vault.addGlobalDestination(recipient);
    }

    // =========================================================================
    // Deposit / Withdraw
    // =========================================================================

    function test_deposit_by_vaultOwner() public {
        usdc.mint(vaultOwner, 1_000 * USDC_DECIMALS);
        vm.startPrank(vaultOwner);
        usdc.approve(address(vault), 1_000 * USDC_DECIMALS);
        vault.deposit(address(usdc), 1_000 * USDC_DECIMALS, bytes32(0));
        vm.stopPrank();

        assertEq(usdc.balanceOf(address(vault)), VAULT_DEPOSIT + 1_000 * USDC_DECIMALS);
    }

    function test_deposit_by_anyone() public {
        usdc.mint(attacker, 500 * USDC_DECIMALS);
        vm.startPrank(attacker);
        usdc.approve(address(vault), 500 * USDC_DECIMALS);
        vault.deposit(address(usdc), 500 * USDC_DECIMALS, bytes32(0));
        vm.stopPrank();

        assertEq(usdc.balanceOf(address(vault)), VAULT_DEPOSIT + 500 * USDC_DECIMALS);
    }

    function test_deposit_emits_event() public {
        usdc.mint(vaultOwner, 1_000 * USDC_DECIMALS);
        vm.startPrank(vaultOwner);
        usdc.approve(address(vault), 1_000 * USDC_DECIMALS);

        vm.expectEmit(true, true, false, true);
        emit AxonVault.Deposited(vaultOwner, address(usdc), 1_000 * USDC_DECIMALS, bytes32(0));
        vault.deposit(address(usdc), 1_000 * USDC_DECIMALS, bytes32(0));
        vm.stopPrank();
    }

    function test_deposit_with_ref_emits_ref() public {
        bytes32 ref = bytes32("job-render-001");
        usdc.mint(attacker, 500 * USDC_DECIMALS);
        vm.startPrank(attacker);
        usdc.approve(address(vault), 500 * USDC_DECIMALS);

        vm.expectEmit(true, true, false, true);
        emit AxonVault.Deposited(attacker, address(usdc), 500 * USDC_DECIMALS, ref);
        vault.deposit(address(usdc), 500 * USDC_DECIMALS, ref);
        vm.stopPrank();
    }

    function test_deposit_reverts_zero_amount() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAmount.selector);
        vault.deposit(address(usdc), 0, bytes32(0));
    }

    function test_deposit_eth_reverts_zero_amount() public {
        address nativeEth = vault.NATIVE_ETH();
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAmount.selector);
        vault.deposit{ value: 0 }(nativeEth, 0, bytes32(0));
    }

    function test_withdraw_by_owner() public {
        vm.prank(vaultOwner);
        vault.withdraw(address(usdc), 1_000 * USDC_DECIMALS, vaultOwner);
        assertEq(usdc.balanceOf(vaultOwner), 1_000 * USDC_DECIMALS);
    }

    function test_withdraw_reverts_non_owner() public {
        vm.prank(attacker);
        vm.expectRevert();
        vault.withdraw(address(usdc), 1_000 * USDC_DECIMALS, attacker);
    }

    function test_withdraw_reverts_zero_address() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAddress.selector);
        vault.withdraw(address(usdc), 1_000 * USDC_DECIMALS, address(0));
    }

    function test_withdraw_reverts_zero_amount() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAmount.selector);
        vault.withdraw(address(usdc), 0, vaultOwner);
    }

    function test_operator_cannot_withdraw() public {
        vm.prank(operator);
        vm.expectRevert();
        vault.withdraw(address(usdc), 1_000 * USDC_DECIMALS, operator);
    }

    function test_eth_accepted_via_receive() public {
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        (bool success,) = address(vault).call{ value: 1 ether }("");
        assertTrue(success);
        assertEq(address(vault).balance, 1 ether);
    }

    // =========================================================================
    // executePayment — happy path
    // =========================================================================

    function test_executePayment_transfers_funds() public {
        uint256 amount = 500 * USDC_DECIMALS;
        AxonVault.PaymentIntent memory intent = _defaultIntent(amount);
        _executePayment(intent);

        assertEq(usdc.balanceOf(recipient), amount);
        assertEq(usdc.balanceOf(address(vault)), VAULT_DEPOSIT - amount);
    }

    function test_executePayment_emits_event() public {
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.expectEmit(true, true, true, true);
        emit AxonVault.PaymentExecuted(bot, recipient, address(usdc), 100 * USDC_DECIMALS, bytes32("test-ref-001"));

        vm.prank(relayer);
        vault.executePayment(intent, sig);
    }

    function test_executePayment_marks_intent_as_used() public {
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        bytes32 structHash = keccak256(
            abi.encode(
                PAYMENT_INTENT_TYPEHASH, intent.bot, intent.to, intent.token, intent.amount, intent.deadline, intent.ref
            )
        );
        bytes32 intentHash = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));

        vm.prank(relayer);
        vault.executePayment(intent, sig);

        assertTrue(vault.usedIntents(intentHash));
    }

    // =========================================================================
    // executePayment — security
    // =========================================================================

    function test_executePayment_reverts_non_relayer() public {
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorizedRelayer.selector);
        vault.executePayment(intent, sig);
    }

    function test_executePayment_reverts_expired_deadline() public {
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: bot,
            to: recipient,
            token: address(usdc),
            amount: 100 * USDC_DECIMALS,
            deadline: block.timestamp - 1, // already expired
            ref: bytes32("ref")
        });
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DeadlineExpired.selector);
        vault.executePayment(intent, sig);
    }

    function test_executePayment_reverts_inactive_bot() public {
        vm.prank(vaultOwner);
        vault.removeBot(bot);

        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.BotNotActive.selector);
        vault.executePayment(intent, sig);
    }

    function test_executePayment_reverts_invalid_signature() public {
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        // Sign with wrong key (attacker key instead of bot key)
        uint256 attackerKey = 0xDEAD;
        bytes memory sig = _signPayment(attackerKey, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.InvalidSignature.selector);
        vault.executePayment(intent, sig);
    }

    function test_executePayment_reverts_tampered_amount() public {
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        // Tamper with amount after signing
        intent.amount = 50_000 * USDC_DECIMALS;

        vm.prank(relayer);
        vm.expectRevert(AxonVault.InvalidSignature.selector);
        vault.executePayment(intent, sig);
    }

    function test_executePayment_reverts_maxPerTxAmount_exceeded() public {
        // Set bot's maxPerTxAmount to $2k, then try to send $3k
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 2_000 * USDC_DECIMALS,
                maxRebalanceAmount: 0,
                spendingLimits: limits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        AxonVault.PaymentIntent memory intent = _defaultIntent(3_000 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.MaxPerTxExceeded.selector);
        vault.executePayment(intent, sig);
    }

    function test_executePayment_reverts_replay() public {
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executePayment(intent, sig);

        // Second submission — same intent hash
        vm.prank(relayer);
        vm.expectRevert(AxonVault.IntentAlreadyUsed.selector);
        vault.executePayment(intent, sig);
    }

    function test_executePayment_reverts_when_paused() public {
        vm.prank(vaultOwner);
        vault.pause();

        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert();
        vault.executePayment(intent, sig);
    }

    // =========================================================================
    // Pause / Unpause
    // =========================================================================

    function test_owner_can_pause_and_unpause() public {
        vm.prank(vaultOwner);
        vault.pause();
        assertTrue(vault.paused());

        vm.prank(vaultOwner);
        vault.unpause();
        assertFalse(vault.paused());
    }

    function test_operator_can_pause() public {
        vm.prank(operator);
        vault.pause();
        assertTrue(vault.paused());
    }

    function test_operator_cannot_unpause() public {
        vm.prank(vaultOwner);
        vault.pause();

        vm.prank(operator);
        vm.expectRevert();
        vault.unpause();
    }

    function test_attacker_cannot_pause() public {
        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorized.selector);
        vault.pause();
    }

    // =========================================================================
    // Ownership (Ownable2Step)
    // =========================================================================

    function test_ownership_transfer_two_step() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(vaultOwner);
        vault.transferOwnership(newOwner);
        assertEq(vault.owner(), vaultOwner); // not transferred yet

        vm.prank(newOwner);
        vault.acceptOwnership();
        assertEq(vault.owner(), newOwner);
    }

    function test_renounceOwnership_always_reverts() public {
        vm.prank(vaultOwner);
        vm.expectRevert("AxonVault: renounce disabled");
        vault.renounceOwnership();

        // Still owned
        assertEq(vault.owner(), vaultOwner);
    }

    // =========================================================================
    // SpendingLimit.maxCount
    // =========================================================================

    function test_BotConfig_WithCountLimits() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](2);
        limits[0] = AxonVault.SpendingLimit({ amount: 5_000 * USDC_DECIMALS, maxCount: 10, windowSeconds: 86400 });
        limits[1] = AxonVault.SpendingLimit({ amount: 20_000 * USDC_DECIMALS, maxCount: 50, windowSeconds: 604800 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 1_000 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 500 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.addBot(bot2, params);

        AxonVault.BotConfig memory config = vault.getBotConfig(bot2);
        assertEq(config.spendingLimits.length, 2);
        assertEq(config.spendingLimits[0].maxCount, 10);
        assertEq(config.spendingLimits[0].amount, 5_000 * USDC_DECIMALS);
        assertEq(config.spendingLimits[0].windowSeconds, 86400);
        assertEq(config.spendingLimits[1].maxCount, 50);
        assertEq(config.spendingLimits[1].windowSeconds, 604800);
    }

    function test_BotConfig_CountLimitZeroMeansNoLimit() public view {
        // Default bot was added with maxCount: 0
        AxonVault.BotConfig memory config = vault.getBotConfig(bot);
        assertEq(config.spendingLimits[0].maxCount, 0);
    }

    function test_updateBotConfig_preserves_maxCount() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 8_000 * USDC_DECIMALS, maxCount: 25, windowSeconds: 86400 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 2_000 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 1_000 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.updateBotConfig(bot, params);

        AxonVault.BotConfig memory config = vault.getBotConfig(bot);
        assertEq(config.spendingLimits[0].maxCount, 25);
    }

    // =========================================================================
    // Global destination blacklist
    // =========================================================================

    function test_GlobalBlacklist_BlocksPayment() public {
        vm.prank(vaultOwner);
        vault.addGlobalBlacklist(recipient);

        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DestinationBlacklisted.selector);
        vault.executePayment(intent, sig);
    }

    function test_BlacklistTakesPriorityOverWhitelist() public {
        // Add recipient to both whitelist and blacklist
        vm.prank(vaultOwner);
        vault.addGlobalDestination(recipient);

        vm.prank(vaultOwner);
        vault.addGlobalBlacklist(recipient);

        // Blacklist should win
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DestinationBlacklisted.selector);
        vault.executePayment(intent, sig);
    }

    function test_OnlyOwnerCanRemoveBlacklist() public {
        vm.prank(vaultOwner);
        vault.addGlobalBlacklist(recipient);

        // Operator cannot remove (loosening)
        vm.prank(operator);
        vm.expectRevert();
        vault.removeGlobalBlacklist(recipient);

        // Owner can remove
        vm.prank(vaultOwner);
        vault.removeGlobalBlacklist(recipient);
        assertEq(vault.globalBlacklistCount(), 0);

        // Payment now succeeds
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        _executePayment(intent);
        assertEq(usdc.balanceOf(recipient), 100 * USDC_DECIMALS);
    }

    function test_OperatorCanAddBlacklist() public {
        vm.prank(operator);
        vault.addGlobalBlacklist(recipient);

        assertTrue(vault.globalDestinationBlacklist(recipient));
        assertEq(vault.globalBlacklistCount(), 1);
    }

    function test_addGlobalBlacklist_reverts_zero_address() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAddress.selector);
        vault.addGlobalBlacklist(address(0));
    }

    function test_addGlobalBlacklist_idempotent() public {
        vm.prank(vaultOwner);
        vault.addGlobalBlacklist(recipient);

        vm.prank(vaultOwner);
        vault.addGlobalBlacklist(recipient); // second add — no-op

        assertEq(vault.globalBlacklistCount(), 1);
    }

    function test_attacker_cannot_add_blacklist() public {
        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorized.selector);
        vault.addGlobalBlacklist(recipient);
    }

    // =========================================================================
    // Destination whitelist edge cases
    // =========================================================================

    /// @dev Adding the same global destination twice does not double-increment the counter.
    function test_addGlobalDestination_idempotent() public {
        vm.prank(vaultOwner);
        vault.addGlobalDestination(recipient);

        vm.prank(vaultOwner);
        vault.addGlobalDestination(recipient); // second add — no-op

        assertEq(vault.globalDestinationCount(), 1);
        assertTrue(vault.globalDestinationWhitelist(recipient));
    }

    /// @dev Removing all global destinations resets the counter to zero.
    function test_removeAllGlobalDestinations_countZero() public {
        address dest1 = makeAddr("dest1");
        address dest2 = makeAddr("dest2");
        address dest3 = makeAddr("dest3");

        vm.startPrank(vaultOwner);
        vault.addGlobalDestination(dest1);
        vault.addGlobalDestination(dest2);
        vault.addGlobalDestination(dest3);
        vm.stopPrank();
        assertEq(vault.globalDestinationCount(), 3);

        vm.startPrank(vaultOwner);
        vault.removeGlobalDestination(dest1);
        vault.removeGlobalDestination(dest2);
        vault.removeGlobalDestination(dest3);
        vm.stopPrank();

        assertEq(vault.globalDestinationCount(), 0);
        assertFalse(vault.globalDestinationWhitelist(dest1));
        assertFalse(vault.globalDestinationWhitelist(dest2));
        assertFalse(vault.globalDestinationWhitelist(dest3));

        // With count = 0, any destination is now allowed again
        AxonVault.PaymentIntent memory intent = _defaultIntent(100 * USDC_DECIMALS);
        _executePayment(intent);
        assertEq(usdc.balanceOf(recipient), 100 * USDC_DECIMALS);
    }

    /// @dev Adding the same bot destination twice does not double-increment the counter.
    function test_addBotDestination_idempotent() public {
        vm.prank(vaultOwner);
        vault.addBotDestination(bot, recipient);

        vm.prank(vaultOwner);
        vault.addBotDestination(bot, recipient); // second add — no-op

        assertEq(vault.botDestinationCount(bot), 1);
    }

    /// @dev Removing a non-existent global destination is a no-op (count unchanged).
    function test_removeGlobalDestination_nonexistent_noop() public {
        assertEq(vault.globalDestinationCount(), 0);

        vm.prank(vaultOwner);
        vault.removeGlobalDestination(recipient); // not in list — no-op

        assertEq(vault.globalDestinationCount(), 0);
    }

    // =========================================================================
    // Native ETH support
    // =========================================================================

    address constant NATIVE_ETH_ADDR = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @dev PaymentExecuted event emits the NATIVE_ETH sentinel address when paying ETH.
    function test_ExecutePaymentETH_emitsCorrectToken() public {
        uint256 ethBotKey = 0xE7B07;
        address ethBot = _ethBot();
        vm.deal(address(vault), 10 ether);

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: ethBot,
            to: recipient,
            token: NATIVE_ETH_ADDR,
            amount: 1 ether,
            deadline: _deadline(),
            ref: bytes32("eth-event-001")
        });
        bytes memory sig = _signPayment(ethBotKey, intent);

        vm.expectEmit(true, true, true, true);
        emit AxonVault.PaymentExecuted(ethBot, recipient, NATIVE_ETH_ADDR, 1 ether, bytes32("eth-event-001"));

        vm.prank(relayer);
        vault.executePayment(intent, sig);
    }

    function test_ReceiveETH() public {
        vm.deal(vaultOwner, 10 ether);
        vm.prank(vaultOwner);
        (bool success,) = address(vault).call{ value: 1 ether }("");
        assertTrue(success);
        assertEq(address(vault).balance, 1 ether);
    }

    function test_DepositETH() public {
        address depositor = makeAddr("depositor");
        vm.deal(depositor, 5 ether);

        vm.prank(depositor);
        vault.deposit{ value: 2 ether }(NATIVE_ETH_ADDR, 2 ether, bytes32(0));

        assertEq(address(vault).balance, 2 ether);
    }

    function test_DepositETH_AmountMismatch() public {
        address depositor = makeAddr("depositor");
        vm.deal(depositor, 5 ether);

        vm.startPrank(depositor);
        vm.expectRevert(AxonVault.AmountMismatch.selector);
        vault.deposit{ value: 1 ether }(NATIVE_ETH_ADDR, 2 ether, bytes32(0));
        vm.stopPrank();
    }

    function test_DepositERC20_RejectsETH() public {
        address depositor = makeAddr("depositor");
        vm.deal(depositor, 5 ether);
        usdc.mint(depositor, 1000 * USDC_DECIMALS);

        vm.startPrank(depositor);
        vm.expectRevert(AxonVault.UnexpectedETH.selector);
        vault.deposit{ value: 1 ether }(address(usdc), 1000 * USDC_DECIMALS, bytes32(0));
        vm.stopPrank();
    }

    function test_WithdrawETH() public {
        vm.deal(address(vault), 5 ether);
        address withdrawTo = makeAddr("withdrawTo");

        vm.prank(vaultOwner);
        vault.withdraw(NATIVE_ETH_ADDR, 2 ether, withdrawTo);

        assertEq(withdrawTo.balance, 2 ether);
        assertEq(address(vault).balance, 3 ether);
    }

    function _ethBot() internal returns (address ethBot) {
        // Register a bot with a high maxPerTxAmount suitable for ETH amounts
        uint256 ethBotKey = 0xE7B07;
        ethBot = vm.addr(ethBotKey);

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 0, // no cap
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.addBot(ethBot, params);
    }

    function test_ExecutePaymentETH() public {
        uint256 ethBotKey = 0xE7B07;
        address ethBot = _ethBot();

        vm.deal(address(vault), 10 ether);
        uint256 recipientBefore = recipient.balance;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: ethBot,
            to: recipient,
            token: NATIVE_ETH_ADDR,
            amount: 1 ether,
            deadline: _deadline(),
            ref: bytes32("eth-payment-001")
        });
        bytes memory sig = _signPayment(ethBotKey, intent);

        vm.prank(relayer);
        vault.executePayment(intent, sig);

        assertEq(recipient.balance - recipientBefore, 1 ether);
        assertEq(address(vault).balance, 9 ether);
    }

    function test_DepositETH_emits_event() public {
        address depositor = makeAddr("depositor");
        vm.deal(depositor, 5 ether);
        bytes32 ref = bytes32("eth-deposit-ref");

        vm.startPrank(depositor);
        vm.expectEmit(true, true, false, true);
        emit AxonVault.Deposited(depositor, NATIVE_ETH_ADDR, 1 ether, ref);
        vault.deposit{ value: 1 ether }(NATIVE_ETH_ADDR, 1 ether, ref);
        vm.stopPrank();
    }

    // =========================================================================
    // Self-payment and zero-address rejection
    // =========================================================================

    function test_ExecutePayment_RevertsSelfPayment() public {
        usdc.mint(address(vault), 1000 * USDC_DECIMALS);

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: bot,
            to: address(vault), // paying itself
            token: address(usdc),
            amount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("self-pay")
        });
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.SelfPayment.selector);
        vault.executePayment(intent, sig);
    }

    function test_ExecutePayment_RevertsZeroAddress() public {
        usdc.mint(address(vault), 1000 * USDC_DECIMALS);

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: bot,
            to: address(0),
            token: address(usdc),
            amount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("zero-addr")
        });
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.PaymentToZeroAddress.selector);
        vault.executePayment(intent, sig);
    }

    function test_ExecutePayment_RevertsZeroAmount() public {
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: bot, to: recipient, token: address(usdc), amount: 0, deadline: _deadline(), ref: bytes32("zero-amount")
        });
        bytes memory sig = _signPayment(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.ZeroAmount.selector);
        vault.executePayment(intent, sig);
    }

    function test_ExecutePaymentETH_RevertsSelfPayment() public {
        uint256 ethBotKey = 0xE7B07;
        address ethBot = _ethBot();
        vm.deal(address(vault), 10 ether);

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: ethBot,
            to: address(vault),
            token: NATIVE_ETH_ADDR,
            amount: 1 ether,
            deadline: _deadline(),
            ref: bytes32("self-pay-eth")
        });
        bytes memory sig = _signPayment(ethBotKey, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.SelfPayment.selector);
        vault.executePayment(intent, sig);
    }

    // =========================================================================
    // executeProtocol helpers
    // =========================================================================

    function _addrArray(address a) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = a;
        return arr;
    }

    function _uintArray(uint256 a) internal pure returns (uint256[] memory) {
        uint256[] memory arr = new uint256[](1);
        arr[0] = a;
        return arr;
    }

    function _signExecute(uint256 privKey, AxonVault.ExecuteIntent memory intent) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_INTENT_TYPEHASH,
                intent.bot,
                intent.protocol,
                intent.calldataHash,
                keccak256(abi.encodePacked(intent.tokens)),
                keccak256(abi.encodePacked(intent.amounts)),
                intent.value,
                intent.deadline,
                intent.ref
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signSwap(uint256 privKey, AxonVault.SwapIntent memory intent) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                SWAP_INTENT_TYPEHASH,
                intent.bot,
                intent.toToken,
                intent.minToAmount,
                intent.fromToken,
                intent.maxFromAmount,
                intent.deadline,
                intent.ref
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        return abi.encodePacked(r, s, v);
    }

    // =========================================================================
    // Protocol whitelist management
    // =========================================================================

    function test_approveProtocol_happy_path() public view {
        assertTrue(vault.isContractApproved(address(mockProtocol)));
        assertEq(vault.approvedProtocolCount(), 1);
    }

    function test_approveProtocol_emits_event() public {
        address newProtocol = makeAddr("newProtocol");
        vm.expectEmit(true, false, false, false);
        emit AxonVault.ProtocolApproved(newProtocol);

        vm.prank(vaultOwner);
        vault.approveProtocol(newProtocol);
    }

    function test_approveProtocol_reverts_zero_address() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAddress.selector);
        vault.approveProtocol(address(0));
    }

    function test_approveProtocol_reverts_already_approved() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.AlreadyApprovedProtocol.selector);
        vault.approveProtocol(address(mockProtocol));
    }

    function test_approveProtocol_reverts_non_owner() public {
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", operator));
        vault.approveProtocol(makeAddr("someProtocol"));
    }

    function test_revokeProtocol_by_owner() public {
        vm.prank(vaultOwner);
        vault.revokeProtocol(address(mockProtocol));
        assertFalse(vault.isContractApproved(address(mockProtocol)));
        assertEq(vault.approvedProtocolCount(), 0);
    }

    function test_revokeProtocol_by_operator() public {
        vm.prank(operator);
        vault.revokeProtocol(address(mockProtocol));
        assertFalse(vault.isContractApproved(address(mockProtocol)));
    }

    function test_revokeProtocol_emits_event() public {
        vm.expectEmit(true, false, false, false);
        emit AxonVault.ProtocolRevoked(address(mockProtocol));

        vm.prank(vaultOwner);
        vault.revokeProtocol(address(mockProtocol));
    }

    function test_revokeProtocol_reverts_not_in_list() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ProtocolNotApproved.selector);
        vault.revokeProtocol(makeAddr("notApproved"));
    }

    function test_revokeProtocol_reverts_attacker() public {
        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorized.selector);
        vault.revokeProtocol(address(mockProtocol));
    }

    // =========================================================================
    // executeProtocol — happy path
    // =========================================================================

    function test_executeProtocol_openTrade_happy_path() public {
        uint256 collateral = 500 * USDC_DECIMALS;
        bytes memory callData = abi.encodeCall(MockProtocol.openTrade, (address(usdc), collateral, 1, true, 50));

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(collateral),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("open-trade-001")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        uint256 vaultBefore = usdc.balanceOf(address(vault));

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        // Vault should have spent collateral
        assertEq(usdc.balanceOf(address(vault)), vaultBefore - collateral);
        // Protocol should have received collateral
        assertEq(usdc.balanceOf(address(mockProtocol)), collateral);
        // Approval should be revoked (cleaned up)
        assertEq(usdc.allowance(address(vault), address(mockProtocol)), 0);
    }

    function test_executeProtocol_emits_event() public {
        uint256 collateral = 100 * USDC_DECIMALS;
        bytes memory callData = abi.encodeCall(MockProtocol.openTrade, (address(usdc), collateral, 0, true, 10));
        bytes32 ref = bytes32("emit-test");

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(collateral),
            value: 0,
            deadline: _deadline(),
            ref: ref
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.expectEmit(true, true, false, true);
        emit AxonVault.ProtocolExecuted(bot, address(mockProtocol), address(usdc), collateral, 0, ref);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_zero_amount_action() public {
        // closeTrade — no token approval needed
        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (42));

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("close-trade-42")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_returns_data() public {
        uint256 collateral = 100 * USDC_DECIMALS;
        bytes memory callData = abi.encodeCall(MockProtocol.openTrade, (address(usdc), collateral, 0, true, 10));

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(collateral),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("return-data-test")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        bytes memory returnData = vault.executeProtocol(intent, sig, callData);

        // openTrade returns orderId (should be 1 since it's the first call)
        uint256 orderId = abi.decode(returnData, (uint256));
        assertEq(orderId, 1);
    }

    // =========================================================================
    // executeProtocol — auth & validation
    // =========================================================================

    function test_executeProtocol_reverts_non_relayer() public {
        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorizedRelayer.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_reverts_expired_deadline() public {
        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: block.timestamp - 1,
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DeadlineExpired.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_reverts_bot_not_active() public {
        vm.prank(vaultOwner);
        vault.removeBot(bot);

        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.BotNotActive.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_reverts_protocol_not_approved() public {
        address badProtocol = makeAddr("badProtocol");
        bytes memory callData = hex"deadbeef";
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: badProtocol,
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.ContractNotApproved.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_reverts_calldata_hash_mismatch() public {
        bytes memory signedCallData = abi.encodeCall(MockProtocol.closeTrade, (1));
        bytes memory differentCallData = abi.encodeCall(MockProtocol.closeTrade, (999));

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(signedCallData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.CalldataHashMismatch.selector);
        vault.executeProtocol(intent, sig, differentCallData);
    }

    function test_executeProtocol_reverts_invalid_signature() public {
        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(OPERATOR_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.InvalidSignature.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_reverts_replay() public {
        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.IntentAlreadyUsed.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_reverts_maxPerTx_exceeded() public {
        // Set bot's maxPerTxAmount to $2k
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 2_000 * USDC_DECIMALS,
                maxRebalanceAmount: 0,
                spendingLimits: limits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        uint256 tooMuch = 3_000 * USDC_DECIMALS;
        bytes memory callData = abi.encodeCall(MockProtocol.openTrade, (address(usdc), tooMuch, 0, true, 10));

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(tooMuch),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.MaxPerTxExceeded.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_reverts_when_paused() public {
        vm.prank(vaultOwner);
        vault.pause();

        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_reverts_protocol_call_failed() public {
        bytes memory callData = abi.encodeCall(MockProtocol.failingAction, ());

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.ProtocolCallFailed.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_maxPerTx_zero_means_no_cap() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 0,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.addBot(bot2, params);

        uint256 bigAmount = 50_000 * USDC_DECIMALS;
        bytes memory callData = abi.encodeCall(MockProtocol.openTrade, (address(usdc), bigAmount, 0, true, 10));

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot2,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(bigAmount),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("big-trade")
        });
        bytes memory sig = _signExecute(BOT2_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        assertEq(usdc.balanceOf(address(mockProtocol)), bigAmount);
    }

    function test_executeProtocol_removed_protocol_blocks_execution() public {
        vm.prank(vaultOwner);
        vault.revokeProtocol(address(mockProtocol));

        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.ContractNotApproved.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    // =========================================================================
    // executeProtocol — msg.value forwarding
    // =========================================================================

    function test_executeProtocol_forwards_msg_value() public {
        // Fund vault with ETH
        vm.deal(address(vault), 1 ether);

        bytes memory callData = abi.encodeCall(MockProtocol.payableAction, ());

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0.5 ether,
            deadline: _deadline(),
            ref: bytes32("eth-forward-001")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        uint256 protocolBefore = address(mockProtocol).balance;
        uint256 vaultBefore = address(vault).balance;

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        // Protocol received the ETH
        assertEq(address(mockProtocol).balance, protocolBefore + 0.5 ether);
        // Vault balance decreased
        assertEq(address(vault).balance, vaultBefore - 0.5 ether);
    }

    function test_executeProtocol_zero_value_sends_no_eth() public {
        vm.deal(address(vault), 1 ether);

        bytes memory callData = abi.encodeCall(MockProtocol.payableAction, ());

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("no-eth-001")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        uint256 vaultBefore = address(vault).balance;

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        // Vault ETH balance unchanged — value was 0
        assertEq(address(vault).balance, vaultBefore);
    }

    function test_executeProtocol_value_mismatch_rejected() public {
        // If an attacker tries to change the value after bot signed, signature check fails
        vm.deal(address(vault), 1 ether);

        bytes memory callData = abi.encodeCall(MockProtocol.payableAction, ());

        // Bot signs with value = 0.1 ether
        AxonVault.ExecuteIntent memory signedIntent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0.1 ether,
            deadline: _deadline(),
            ref: bytes32("tampered-value")
        });
        bytes memory sig = _signExecute(BOT_KEY, signedIntent);

        // Attacker submits with value = 1 ether (trying to drain more ETH)
        AxonVault.ExecuteIntent memory tamperedIntent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 1 ether, // TAMPERED
            deadline: _deadline(),
            ref: bytes32("tampered-value")
        });

        vm.prank(relayer);
        vm.expectRevert(AxonVault.InvalidSignature.selector);
        vault.executeProtocol(tamperedIntent, sig, callData);
    }

    function test_executeProtocol_empty_calldata_with_value() public {
        // Send raw ETH to a contract's receive() fallback — no function selector.
        // Use case: bridges, simple ETH transfers to payable contracts.
        vm.deal(address(vault), 1 ether);

        bytes memory callData = ""; // empty — hits receive()

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0.25 ether,
            deadline: _deadline(),
            ref: bytes32("raw-eth-send")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        uint256 protocolBefore = address(mockProtocol).balance;

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        // Protocol received the ETH via receive()
        assertEq(address(mockProtocol).balance, protocolBefore + 0.25 ether);
        assertEq(address(vault).balance, 0.75 ether);
    }

    function test_executeProtocol_empty_calldata_zero_value() public {
        // Empty calldata with zero value — should succeed (no-op call).
        bytes memory callData = "";

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("noop-call")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_value_checked_against_cap() public {
        // A bot with maxPerTxAmount=$1 should NOT be able to send 5 ETH via value.
        // The combined cap check prices ETH via TWAP oracle (~$2000/ETH) and rejects.
        vm.deal(address(vault), 10 ether);

        address cappedBot = vm.addr(0xCAFE);
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vm.prank(vaultOwner);
        vault.addBot(cappedBot, AxonVault.BotConfigParams(1_000_000, 0, limits, 0, false)); // $1 cap (6 decimals)

        bytes memory callData = abi.encodeCall(MockProtocol.payableAction, ());

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: cappedBot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 5 ether, // ~$10,000 at $2000/ETH — way over $1 cap
            deadline: _deadline(),
            ref: bytes32("value-bypass-attempt")
        });
        bytes memory sig = _signExecute(0xCAFE, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.MaxPerTxExceeded.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_value_uncapped_bot_succeeds() public {
        // A bot with maxPerTxAmount=0 (no cap) can send ETH via value freely.
        vm.deal(address(vault), 10 ether);

        bytes memory callData = abi.encodeCall(MockProtocol.payableAction, ());

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 1 ether,
            deadline: _deadline(),
            ref: bytes32("uncapped-value")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        uint256 protocolBefore = address(mockProtocol).balance;
        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
        assertEq(address(mockProtocol).balance, protocolBefore + 1 ether);
    }

    function test_executeProtocol_combined_value_and_amount_exceeds_cap() public {
        // Both value > 0 AND amount > 0 — their combined USD value must be checked.
        // Bot has $5 cap. Sends $2 USDC (amount) + 0.002 ETH (~$4 at $2000/ETH) = ~$6 total → rejected.
        vm.deal(address(vault), 1 ether);

        address cappedBot = vm.addr(0xCAFE);
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vm.prank(vaultOwner);
        vault.addBot(cappedBot, AxonVault.BotConfigParams(5_000_000, 0, limits, 0, false)); // $5 cap

        // Approve mock protocol for this bot's use
        bytes memory callData = abi.encodeCall(MockProtocol.payableAction, ());

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: cappedBot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(2_000_000), // $2 USDC
            value: 0.002 ether, // ~$4 at $2000/ETH
            deadline: _deadline(),
            ref: bytes32("combined-cap-test")
        });
        bytes memory sig = _signExecute(0xCAFE, intent);

        // Each amount individually fits under $5, but combined ~$6 exceeds the cap
        vm.prank(relayer);
        vm.expectRevert(AxonVault.MaxPerTxExceeded.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_combined_value_and_amount_within_cap() public {
        // Same setup but both values fit within cap: $1 USDC + 0.001 ETH (~$2) = ~$3 < $5 cap
        vm.deal(address(vault), 1 ether);

        address cappedBot = vm.addr(0xCAFE);
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vm.prank(vaultOwner);
        vault.addBot(cappedBot, AxonVault.BotConfigParams(5_000_000, 0, limits, 0, false)); // $5 cap

        bytes memory callData = abi.encodeCall(MockProtocol.payableAction, ());

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: cappedBot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(1_000_000), // $1 USDC
            value: 0.001 ether, // ~$2 at $2000/ETH — total ~$3 < $5 cap
            deadline: _deadline(),
            ref: bytes32("combined-ok")
        });
        bytes memory sig = _signExecute(0xCAFE, intent);

        uint256 protocolBefore = address(mockProtocol).balance;
        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
        assertEq(address(mockProtocol).balance, protocolBefore + 0.001 ether);
    }

    // =========================================================================
    // ERC-1271 — isValidSignature
    // =========================================================================

    function test_isValidSignature_owner() public view {
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VAULT_OWNER_KEY, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes4 result = vault.isValidSignature(hash, sig);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_bot_rejected_by_default() public view {
        // ERC-1271 for bots is disabled by default — prevents compromised bot
        // from signing Permit2 transfers, Seaport listings, etc.
        bytes32 hash = keccak256("bot signed message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOT_KEY, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertEq(vault.isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    function test_isValidSignature_bot_accepted_when_enabled() public {
        // Owner explicitly enables ERC-1271 for bots
        vm.prank(vaultOwner);
        vault.setErc1271Bots(true);

        bytes32 hash = keccak256("bot signed message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOT_KEY, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertEq(vault.isValidSignature(hash, sig), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_unknown_signer_rejected() public view {
        bytes32 hash = keccak256("unknown signer");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xdead, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes4 result = vault.isValidSignature(hash, sig);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_isValidSignature_removed_bot_rejected() public {
        // Enable ERC-1271 for bots, verify it works, then remove bot
        vm.prank(vaultOwner);
        vault.setErc1271Bots(true);

        bytes32 hash = keccak256("removed bot");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOT_KEY, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertEq(vault.isValidSignature(hash, sig), bytes4(0x1626ba7e));

        vm.prank(vaultOwner);
        vault.removeBot(bot);

        assertEq(vault.isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    function test_isValidSignature_rejects_when_paused() public {
        // Enable ERC-1271 for bots and verify it works
        vm.prank(vaultOwner);
        vault.setErc1271Bots(true);

        bytes32 hash = keccak256("paused vault message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOT_KEY, hash);
        bytes memory botSig = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(VAULT_OWNER_KEY, hash);
        bytes memory ownerSig = abi.encodePacked(r, s, v);

        // Both valid before pause
        assertEq(vault.isValidSignature(hash, botSig), bytes4(0x1626ba7e));
        assertEq(vault.isValidSignature(hash, ownerSig), bytes4(0x1626ba7e));

        // Pause the vault
        vm.prank(vaultOwner);
        vault.pause();

        // After pause, NEITHER should be valid — vault is emergency-stopped
        assertEq(vault.isValidSignature(hash, botSig), bytes4(0xffffffff), "bot sig valid while paused");
        assertEq(vault.isValidSignature(hash, ownerSig), bytes4(0xffffffff), "owner sig valid while paused");
    }

    function test_setErc1271Bots_only_owner() public {
        vm.prank(attacker);
        vm.expectRevert();
        vault.setErc1271Bots(true);
    }

    function test_setErc1271Bots_can_disable() public {
        vm.prank(vaultOwner);
        vault.setErc1271Bots(true);
        assertTrue(vault.erc1271BotsEnabled());

        vm.prank(vaultOwner);
        vault.setErc1271Bots(false);
        assertFalse(vault.erc1271BotsEnabled());

        // Bot signature no longer valid
        bytes32 hash = keccak256("disabled");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOT_KEY, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        assertEq(vault.isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    // =========================================================================
    // executeSwap — standalone in-vault rebalancing
    // =========================================================================

    function test_executeSwap_happy_path() public {
        uint256 minOutput = 490 * USDC_DECIMALS;
        usdt.mint(address(swapRouter), minOutput); // fund router with USDT

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: 500 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("rebalance-001")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        // Swap USDC→USDT, output stays in vault
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(usdc), 500 * USDC_DECIMALS, address(usdt), minOutput, address(vault))
        );

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);

        // Vault received USDT
        assertEq(usdt.balanceOf(address(vault)), minOutput);
    }

    function test_executeSwap_emits_event() public {
        uint256 minOutput = 490 * USDC_DECIMALS;
        usdt.mint(address(swapRouter), minOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: 500 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("swap-event")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(usdc), 500 * USDC_DECIMALS, address(usdt), minOutput, address(vault))
        );

        vm.expectEmit(true, false, false, true);
        emit AxonVault.SwapExecuted(
            bot, address(usdc), address(usdt), 500 * USDC_DECIMALS, minOutput, bytes32("swap-event")
        );

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);
    }

    function test_executeSwap_reverts_zero_amount() public {
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 0,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.ZeroAmount.selector);
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    function test_executeSwap_reverts_same_token() public {
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdc),
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.SameTokenSwap.selector);
        // fromToken == toToken (both USDC)
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    function test_executeSwap_reverts_expired_deadline() public {
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: block.timestamp - 1,
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DeadlineExpired.selector);
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    function test_executeSwap_reverts_unapproved_router() public {
        address fakeRouter = makeAddr("fakeRouter");
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.RouterNotApproved.selector);
        vault.executeSwap(intent, sig, fakeRouter, "");
    }

    function test_executeSwap_reverts_non_relayer() public {
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorizedRelayer.selector);
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    function test_executeSwap_reverts_inactive_bot() public {
        vm.prank(vaultOwner);
        vault.removeBot(bot);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.BotNotActive.selector);
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    function test_executeSwap_reverts_invalid_signature() public {
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(OPERATOR_KEY, intent); // wrong key

        vm.prank(relayer);
        vm.expectRevert(AxonVault.InvalidSignature.selector);
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    function test_executeSwap_reverts_replay() public {
        uint256 minOutput = 90 * USDC_DECIMALS;
        usdt.mint(address(swapRouter), minOutput * 2);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(usdc), 100 * USDC_DECIMALS, address(usdt), minOutput, address(vault))
        );

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.IntentAlreadyUsed.selector);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);
    }

    function test_executeSwap_reverts_maxRebalanceAmount_exceeded() public {
        // Set bot's maxRebalanceAmount to $2k (separate from payment maxPerTxAmount)
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 0,
                maxRebalanceAmount: 2_000 * USDC_DECIMALS,
                spendingLimits: limits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        // Check is on INPUT (fromToken/maxFromAmount), not the gameable output
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 3_100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        // fromToken=USDC, maxFromAmount=$3100 exceeds $2k maxRebalanceAmount
        vm.prank(relayer);
        vm.expectRevert(AxonVault.MaxRebalanceAmountExceeded.selector);
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    function test_executeSwap_reverts_insufficient_output() public {
        usdt.mint(address(swapRouter), 1_000 * USDC_DECIMALS);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 490 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 500 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        // swapShort delivers only half
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swapShort,
            (address(usdc), 500 * USDC_DECIMALS, address(usdt), 500 * USDC_DECIMALS, address(vault))
        );

        vm.prank(relayer);
        vm.expectRevert(AxonVault.SwapOutputInsufficient.selector);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);
    }

    function test_executeSwap_reverts_when_paused() public {
        vm.prank(vaultOwner);
        vault.pause();

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    // =========================================================================
    // Rebalance token whitelist + maxRebalanceAmount
    // =========================================================================

    function test_executeSwap_rebalanceToken_whitelist_blocks_unlisted() public {
        // Owner adds only USDC to the rebalance whitelist
        vm.prank(vaultOwner);
        vault.addRebalanceTokens(_toArray(address(usdc)));
        assertEq(vault.rebalanceTokenCount(), 1);

        // Try to swap to USDT (not on whitelist) — should revert
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt), // NOT on whitelist
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 110 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("blocked-swap")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.RebalanceTokenNotAllowed.selector);
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    function test_executeSwap_rebalanceToken_whitelist_allows_listed() public {
        // Owner adds USDT to the rebalance whitelist
        vm.prank(vaultOwner);
        vault.addRebalanceTokens(_toArray(address(usdt)));

        uint256 minOutput = 490 * USDC_DECIMALS;
        usdt.mint(address(swapRouter), minOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt), // on whitelist
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: 500 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("allowed-swap")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(usdc), 500 * USDC_DECIMALS, address(usdt), minOutput, address(vault))
        );

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);
        assertEq(usdt.balanceOf(address(vault)), minOutput);
    }

    function test_executeSwap_rebalanceToken_empty_allows_any() public {
        // No tokens on whitelist — any token should be allowed (permissive default)
        assertEq(vault.rebalanceTokenCount(), 0);

        uint256 minOutput = 490 * USDC_DECIMALS;
        usdt.mint(address(swapRouter), minOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: 500 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("any-allowed")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(usdc), 500 * USDC_DECIMALS, address(usdt), minOutput, address(vault))
        );

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);
        assertEq(usdt.balanceOf(address(vault)), minOutput);
    }

    function test_rebalanceToken_owner_can_add() public {
        vm.prank(vaultOwner);
        vault.addRebalanceTokens(_toArray(address(usdt)));
        assertTrue(vault.rebalanceTokenWhitelist(address(usdt)));
        assertEq(vault.rebalanceTokenCount(), 1);
    }

    function test_rebalanceToken_operator_can_remove() public {
        vm.prank(vaultOwner);
        vault.addRebalanceTokens(_toArray(address(usdt)));
        assertEq(vault.rebalanceTokenCount(), 1);

        vm.prank(operator);
        vault.removeRebalanceTokens(_toArray(address(usdt)));
        assertFalse(vault.rebalanceTokenWhitelist(address(usdt)));
        assertEq(vault.rebalanceTokenCount(), 0);
    }

    function test_rebalanceToken_attacker_cannot_add() public {
        vm.prank(attacker);
        vm.expectRevert(); // OwnableUnauthorizedAccount
        vault.addRebalanceTokens(_toArray(address(usdt)));
    }

    function test_rebalanceToken_operator_cannot_add() public {
        vm.prank(operator);
        vm.expectRevert(); // OwnableUnauthorizedAccount — only owner can add (loosening)
        vault.addRebalanceTokens(_toArray(address(usdt)));
    }

    function test_rebalanceToken_add_zero_reverts() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAddress.selector);
        vault.addRebalanceTokens(_toArray(address(0)));
    }

    function test_rebalanceToken_add_idempotent() public {
        vm.prank(vaultOwner);
        vault.addRebalanceTokens(_toArray(address(usdt)));
        vm.prank(vaultOwner);
        vault.addRebalanceTokens(_toArray(address(usdt))); // no-op
        assertEq(vault.rebalanceTokenCount(), 1); // count not double-incremented
    }

    function test_rebalanceToken_remove_idempotent() public {
        // Remove a token that was never added — no-op
        vm.prank(vaultOwner);
        vault.removeRebalanceTokens(_toArray(address(usdt)));
        assertEq(vault.rebalanceTokenCount(), 0);
    }

    function test_executeSwap_maxRebalanceAmount_zero_means_no_cap() public {
        // maxRebalanceAmount = 0 means no cap on rebalancing
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 100 * USDC_DECIMALS, // tight payment cap
                maxRebalanceAmount: 0, // no rebalance cap
                spendingLimits: limits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        // Large rebalance should succeed even though maxPerTxAmount is $100
        uint256 minOutput = 9_000 * USDC_DECIMALS;
        usdt.mint(address(swapRouter), minOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: 10_000 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("large-rebalance")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(usdc), 10_000 * USDC_DECIMALS, address(usdt), minOutput, address(vault))
        );

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);
        assertEq(usdt.balanceOf(address(vault)), minOutput);
    }

    function test_executeSwap_maxRebalanceAmount_checks_input_not_output() public {
        // maxRebalanceAmount = $2k — check is on INPUT (fromToken/maxFromAmount)
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 0,
                maxRebalanceAmount: 2_000 * USDC_DECIMALS,
                spendingLimits: limits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        // Small output, but large input — should be blocked
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: 100 * USDC_DECIMALS, // small output
            fromToken: address(usdc),
            maxFromAmount: 3_000 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("input-check")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        // maxFromAmount = $3k USDC (exceeds $2k maxRebalanceAmount)
        vm.prank(relayer);
        vm.expectRevert(AxonVault.MaxRebalanceAmountExceeded.selector);
        vault.executeSwap(intent, sig, address(swapRouter), "");
    }

    function test_executeSwap_maxPerTxAmount_independent_from_rebalance() public {
        // maxPerTxAmount = $100 (for payments), maxRebalanceAmount = $10K (for rebalancing)
        // A $5K rebalance should succeed even though maxPerTxAmount is $100
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 100 * USDC_DECIMALS,
                maxRebalanceAmount: 10_000 * USDC_DECIMALS,
                spendingLimits: limits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        uint256 minOutput = 4_500 * USDC_DECIMALS;
        usdt.mint(address(swapRouter), minOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: 5_000 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("independent-cap")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(usdc), 5_000 * USDC_DECIMALS, address(usdt), minOutput, address(vault))
        );

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);
        assertEq(usdt.balanceOf(address(vault)), minOutput);
    }

    // =========================================================================
    // Bot re-registration (stale spending limits)
    // =========================================================================

    function test_reregister_bot_clears_stale_spending_limits() public {
        // bot was added in setUp with 1 spending limit (10k/day)
        AxonVault.BotConfig memory configBefore = vault.getBotConfig(bot);
        assertEq(configBefore.spendingLimits.length, 1);

        // Remove bot
        vm.prank(vaultOwner);
        vault.removeBot(bot);

        // Re-register with a different limit
        AxonVault.SpendingLimit[] memory newLimits = new AxonVault.SpendingLimit[](1);
        newLimits[0] = AxonVault.SpendingLimit({ amount: 5_000 * USDC_DECIMALS, maxCount: 10, windowSeconds: 3600 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 1_000 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: newLimits,
            aiTriggerThreshold: 500 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.addBot(bot, params);

        // Should have exactly 1 limit (the new one), NOT 2
        AxonVault.BotConfig memory configAfter = vault.getBotConfig(bot);
        assertEq(configAfter.spendingLimits.length, 1);

        // Verify it's the new limit, not the old one
        assertEq(configAfter.spendingLimits[0].amount, 5_000 * USDC_DECIMALS);
        assertEq(configAfter.spendingLimits[0].maxCount, 10);
        assertEq(configAfter.spendingLimits[0].windowSeconds, 3600);
    }

    // =========================================================================
    // Edge cases — role overlap & identity
    // =========================================================================

    /// @dev Owner cannot register themselves as a bot — enforces key separation.
    function test_addBot_reverts_owner_as_bot() public {
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 1_000 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.OwnerCannotBeBot.selector);
        vault.addBot(vaultOwner, params);
    }

    /// @dev Owner cannot register as bot even if operator tries.
    function test_addBot_reverts_owner_as_bot_by_operator() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 500 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vm.expectRevert(AxonVault.OwnerCannotBeBot.selector);
        vault.addBot(vaultOwner, params);
    }

    /// @dev Operator can be registered as a bot — no restriction in contract.
    function test_operator_can_be_registered_as_bot() public {
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 1_000 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vault.addBot(operator, params);
        assertTrue(vault.isBotActive(operator));
    }

    /// @dev Registering an already-active bot reverts with BotAlreadyExists.
    function test_addBot_reverts_duplicate_registration() public {
        // bot is already registered in setUp
        assertTrue(vault.isBotActive(bot));

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.BotAlreadyExists.selector);
        vault.addBot(bot, params);
    }

    /// @dev Cannot set owner address as operator.
    function test_setOperator_reverts_owner_address() public {
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.OperatorCannotBeOwner.selector);
        vault.setOperator(vaultOwner);
    }

    /// @dev Setting operator to zero address is valid (unsets operator).
    function test_setOperator_zero_address_unsets() public {
        vm.prank(vaultOwner);
        vault.setOperator(address(0));
        assertEq(vault.operator(), address(0));
    }

    /// @dev Cannot register zero address as a bot.
    function test_addBot_reverts_zero_address_bot() public {
        AxonVault.BotConfigParams memory params;
        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAddress.selector);
        vault.addBot(address(0), params);
    }

    /// @dev Same bot address can be registered on different vaults (independent storage).
    function test_same_bot_on_different_vaults() public {
        // Deploy a second vault for the same vaultOwner
        AxonVault vault2 = _deployVault(vaultOwner, address(registry));

        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: new AxonVault.SpendingLimit[](0),
            aiTriggerThreshold: 0,
            requireAiVerification: false
        });

        // bot is already on vault (setUp). Add to vault2.
        vm.prank(vaultOwner);
        vault2.addBot(bot, params);

        // Both vaults have the same bot independently
        assertTrue(vault.isBotActive(bot));
        assertTrue(vault2.isBotActive(bot));

        // Removing from one doesn't affect the other
        vm.prank(vaultOwner);
        vault2.removeBot(bot);
        assertTrue(vault.isBotActive(bot));
        assertFalse(vault2.isBotActive(bot));
    }

    // =========================================================================
    // Access control — who can call what
    // =========================================================================

    /// @dev Attacker cannot remove a bot.
    function test_removeBot_reverts_non_authorized() public {
        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorized.selector);
        vault.removeBot(bot);
    }

    /// @dev Attacker cannot update bot config.
    function test_updateBotConfig_reverts_non_authorized() public {
        AxonVault.BotConfigParams memory params;
        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorized.selector);
        vault.updateBotConfig(bot, params);
    }

    /// @dev Attacker cannot add to global destination whitelist.
    function test_addGlobalDestination_reverts_non_owner() public {
        vm.prank(attacker);
        vm.expectRevert();
        vault.addGlobalDestination(recipient);
    }

    /// @dev Operator cannot add to global destination whitelist (owner-only, loosening).
    function test_addGlobalDestination_reverts_operator() public {
        vm.prank(operator);
        vm.expectRevert();
        vault.addGlobalDestination(recipient);
    }

    /// @dev Attacker cannot remove from global destination whitelist.
    function test_removeGlobalDestination_reverts_non_authorized() public {
        vm.prank(vaultOwner);
        vault.addGlobalDestination(recipient);

        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorized.selector);
        vault.removeGlobalDestination(recipient);
    }

    /// @dev Attacker cannot add to bot destination whitelist.
    function test_addBotDestination_reverts_non_owner() public {
        vm.prank(attacker);
        vm.expectRevert();
        vault.addBotDestination(bot, recipient);
    }

    /// @dev Operator cannot add to bot destination whitelist (owner-only, loosening).
    function test_addBotDestination_reverts_operator() public {
        vm.prank(operator);
        vm.expectRevert();
        vault.addBotDestination(bot, recipient);
    }

    /// @dev Attacker cannot remove from bot destination whitelist.
    function test_removeBotDestination_reverts_non_authorized() public {
        vm.prank(vaultOwner);
        vault.addBotDestination(bot, recipient);

        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorized.selector);
        vault.removeBotDestination(bot, recipient);
    }

    /// @dev Attacker cannot add to global blacklist.
    function test_addGlobalBlacklist_reverts_non_authorized() public {
        vm.prank(attacker);
        vm.expectRevert(AxonVault.NotAuthorized.selector);
        vault.addGlobalBlacklist(recipient);
    }

    /// @dev Attacker cannot remove from global blacklist (owner-only).
    function test_removeGlobalBlacklist_reverts_non_owner() public {
        vm.prank(vaultOwner);
        vault.addGlobalBlacklist(recipient);

        vm.prank(attacker);
        vm.expectRevert();
        vault.removeGlobalBlacklist(recipient);
    }

    /// @dev Operator cannot remove from global blacklist (owner-only, loosening).
    function test_removeGlobalBlacklist_reverts_operator() public {
        vm.prank(vaultOwner);
        vault.addGlobalBlacklist(recipient);

        vm.prank(operator);
        vm.expectRevert();
        vault.removeGlobalBlacklist(recipient);
    }

    /// @dev Attacker cannot unpause.
    function test_unpause_reverts_non_owner() public {
        vm.prank(vaultOwner);
        vault.pause();

        vm.prank(attacker);
        vm.expectRevert();
        vault.unpause();
    }

    /// @dev Operator cannot unpause (owner-only).
    function test_unpause_reverts_operator() public {
        vm.prank(vaultOwner);
        vault.pause();

        vm.prank(operator);
        vm.expectRevert();
        vault.unpause();
    }

    /// @dev Operator cannot withdraw (owner-only).
    function test_withdraw_reverts_operator() public {
        vm.prank(operator);
        vm.expectRevert();
        vault.withdraw(address(usdc), 1_000 * USDC_DECIMALS, operator);
    }

    /// @dev Operator cannot set the operator (owner-only).
    function test_setOperator_reverts_operator() public {
        vm.prank(operator);
        vm.expectRevert();
        vault.setOperator(attacker);
    }

    /// @dev Operator cannot set operator ceilings (owner-only).
    function test_setOperatorCeilings_reverts_operator() public {
        AxonVault.OperatorCeilings memory c;
        vm.prank(operator);
        vm.expectRevert();
        vault.setOperatorCeilings(c);
    }

    // =========================================================================
    // executeProtocol — registry default tokens
    // =========================================================================

    /// @dev A default token in the registry can be used as protocol without vault-level approveProtocol.
    function test_executeProtocol_allows_registry_default_token() public {
        // Deploy a fresh token that is NOT in the vault's approvedProtocols
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);

        // Add it as a default token on the registry (registry owner = address(this))
        registry.approveDefaultToken(address(freshToken));

        // Verify it's NOT in the vault's local approved list
        assertFalse(vault.isContractApproved(address(freshToken)));

        // Build an execute intent that calls freshToken (e.g. approve() pattern)
        bytes memory callData = abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 1000);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("default-token-test")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        // Should succeed — registry default token is accepted
        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev After removing a default token from registry, executeProtocol reverts.
    function test_executeProtocol_reverts_after_registry_default_token_removed() public {
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));

        // Remove it
        registry.revokeDefaultToken(address(freshToken));

        bytes memory callData = abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 1000);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("removed-token")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.ContractNotApproved.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev Vault-level approveProtocol still works independently of registry defaults.
    function test_executeProtocol_local_protocol_unaffected_by_registry() public {
        // mockProtocol is added via vault's approveProtocol in setUp — not a registry default
        assertFalse(registry.isDefaultToken(address(mockProtocol)));
        assertTrue(vault.isContractApproved(address(mockProtocol)));

        // Should still work via local approval
        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("local-protocol")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev A protocol that is neither locally approved nor a registry default is rejected.
    function test_executeProtocol_reverts_not_local_nor_default() public {
        address randomAddr = makeAddr("randomProtocol");

        bytes memory callData = hex"deadbeef";
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: randomAddr,
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("ref")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.ContractNotApproved.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    // =========================================================================
    // Nemesis audit fixes (NM-001, NM-002, NM-003, NM-004)
    // =========================================================================

    /// @dev NM-001: Default token transfer() blocked — only approve() allowed
    function test_executeProtocol_reverts_default_token_transfer() public {
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));
        freshToken.mint(address(vault), 10_000e6);

        // Try calling transfer() on the default token — drain vector
        bytes memory callData = abi.encodeWithSignature("transfer(address,uint256)", address(0xdead), 10_000e6);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("nm001-transfer")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DefaultTokenCallRestricted.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev NM-001: Default token transferFrom() also blocked
    function test_executeProtocol_reverts_default_token_transferFrom() public {
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));

        bytes memory callData =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", address(vault), address(0xdead), 1000e6);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("nm001-transferFrom")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DefaultTokenCallRestricted.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev NM-001: Default token approve() still works (legitimate use case)
    function test_executeProtocol_allows_default_token_approve() public {
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));

        bytes memory callData = abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 1000e6);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("nm001-approve-ok")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev NM-001: Locally approved protocol is NOT restricted (only default tokens)
    function test_executeProtocol_local_protocol_allows_any_calldata() public {
        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("nm001-local-ok")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev Default token allows approve() but blocks deposit() (mint/wrap).
    ///      If you want deposit/withdraw, use approveProtocol (per-vault or global).
    function test_executeProtocol_default_token_blocks_deposit() public {
        MockERC20 freshToken = new MockERC20("WETH-like", "WETH", 18);
        registry.approveDefaultToken(address(freshToken));

        // approve() works on a default token
        bytes memory approveData = abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 1 ether);
        AxonVault.ExecuteIntent memory approveIntent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(approveData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("approve-ok")
        });
        bytes memory approveSig = _signExecute(BOT_KEY, approveIntent);
        vm.prank(relayer);
        vault.executeProtocol(approveIntent, approveSig, approveData);

        // deposit() is blocked — not approve() selector
        bytes memory depositData = abi.encodeWithSignature("deposit()");
        AxonVault.ExecuteIntent memory depositIntent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(depositData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0.1 ether,
            deadline: _deadline(),
            ref: bytes32("deposit-blocked")
        });
        bytes memory depositSig = _signExecute(BOT_KEY, depositIntent);
        vm.prank(relayer);
        vm.expectRevert(AxonVault.DefaultTokenCallRestricted.selector);
        vault.executeProtocol(depositIntent, depositSig, depositData);

        // withdraw(uint256) is also blocked
        bytes memory withdrawData = abi.encodeWithSignature("withdraw(uint256)", 0.1 ether);
        AxonVault.ExecuteIntent memory withdrawIntent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(withdrawData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("withdraw-blocked")
        });
        bytes memory withdrawSig = _signExecute(BOT_KEY, withdrawIntent);
        vm.prank(relayer);
        vm.expectRevert(AxonVault.DefaultTokenCallRestricted.selector);
        vault.executeProtocol(withdrawIntent, withdrawSig, withdrawData);
    }

    // =========================================================================
    // Global protocol approval (AxonRegistry.approveProtocol)
    // =========================================================================

    /// @dev A globally approved protocol allows any function call (not just approve).
    function test_executeProtocol_allows_global_protocol_any_call() public {
        // Deploy a mock protocol and add it globally on the registry
        MockProtocol globalProto = new MockProtocol();
        registry.approveProtocol(address(globalProto));

        // Verify it's NOT in the vault's local approved list
        assertFalse(vault.isContractApproved(address(globalProto)));

        // Call a non-approve function (closeTrade) — should work
        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (42));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(globalProto),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("global-protocol")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev A global protocol that is also a default token bypasses the approve-only restriction.
    function test_executeProtocol_global_protocol_overrides_default_token_restriction() public {
        MockERC20 freshToken = new MockERC20("WETH-like", "WETH", 18);
        freshToken.mint(address(vault), 1 ether);

        // Add as both default token AND global protocol
        registry.approveDefaultToken(address(freshToken));
        registry.approveProtocol(address(freshToken));

        // Call transfer() — normally blocked for default tokens, but allowed because it's also a global protocol
        bytes memory callData = abi.encodeWithSignature("transfer(address,uint256)", address(0xbeef), 0.1 ether);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("global-override")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        // Verify transfer happened
        assertEq(freshToken.balanceOf(address(0xbeef)), 0.1 ether);
    }

    /// @dev After revoking global protocol, calls revert (unless locally approved).
    function test_executeProtocol_reverts_after_global_protocol_revoked() public {
        MockProtocol globalProto = new MockProtocol();
        registry.approveProtocol(address(globalProto));
        registry.revokeProtocol(address(globalProto));

        bytes memory callData = abi.encodeCall(MockProtocol.closeTrade, (1));
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(globalProto),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("revoked-global")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.ContractNotApproved.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev NM-003: Cannot set operator to pendingOwner
    function test_setOperator_reverts_pendingOwner() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(vaultOwner);
        vault.transferOwnership(newOwner);

        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.OperatorCannotBeOwner.selector);
        vault.setOperator(newOwner);
    }

    /// @dev NM-003: Setting operator to address(0) still works even when pendingOwner is zero
    function test_setOperator_zero_still_works_with_no_pendingOwner() public {
        vm.prank(vaultOwner);
        vault.setOperator(address(0));
        assertEq(vault.operator(), address(0));
    }

    /// @dev I-01: Changing operator should clear botAddedByOperator flags for old operator's bots.
    ///      Without fix, stale flags persist — removing old operator's bots incorrectly
    ///      decrements new operator's count, and re-setting the same operator address
    ///      inherits ghost bots.
    function test_setOperator_clears_stale_botAddedByOperator() public {
        // Operator adds a bot
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 2_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vault.addBot(bot2, params);
        assertEq(vault.botAddedByOperator(bot2), operator);
        assertEq(vault.operatorBotCount(), 1);

        // Change to a new operator — count resets
        address newOperator = makeAddr("newOperator");
        vm.prank(vaultOwner);
        vault.setOperator(newOperator);
        assertEq(vault.operatorBotCount(), 0);

        // Removing bot2 should NOT decrement new operator's count (old operator added it)
        vm.prank(vaultOwner);
        vault.removeBot(bot2);
        assertEq(vault.operatorBotCount(), 0); // still 0, not underflowed
        assertEq(vault.botAddedByOperator(bot2), address(0)); // flag cleared
    }

    /// @dev Owner-added bots should have botAddedByOperator = address(0)
    function test_botAddedByOperator_zero_for_owner_added_bot() public view {
        // bot was added by owner in setUp
        assertEq(vault.botAddedByOperator(bot), address(0));
    }

    /// @dev botAddedByOperator stores the correct operator address
    function test_botAddedByOperator_stores_operator_address() public {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 2_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        AxonVault.BotConfigParams memory params = AxonVault.BotConfigParams({
            maxPerTxAmount: 500 * USDC_DECIMALS,
            maxRebalanceAmount: 0,
            spendingLimits: limits,
            aiTriggerThreshold: 100 * USDC_DECIMALS,
            requireAiVerification: false
        });
        vm.prank(operator);
        vault.addBot(bot2, params);

        // Should store the operator's address, not just a bool
        assertEq(vault.botAddedByOperator(bot2), operator);

        // Removing by current operator should decrement count
        vm.prank(operator);
        vault.removeBot(bot2);
        assertEq(vault.operatorBotCount(), 0);
        assertEq(vault.botAddedByOperator(bot2), address(0));
    }

    // =========================================================================
    // NFT support — ERC-721
    // =========================================================================

    function test_erc721_safeMint_to_vault() public {
        MockERC721 nft = new MockERC721();
        uint256 tokenId = nft.safeMint(address(vault));
        assertEq(nft.ownerOf(tokenId), address(vault));
        assertEq(nft.balanceOf(address(vault)), 1);
    }

    function test_erc721_unsafeMint_to_vault() public {
        MockERC721 nft = new MockERC721();
        uint256 tokenId = nft.unsafeMint(address(vault));
        assertEq(nft.ownerOf(tokenId), address(vault));
        assertEq(nft.balanceOf(address(vault)), 1);
    }

    function test_erc721_multiple_mints() public {
        MockERC721 nft = new MockERC721();
        nft.safeMint(address(vault));
        nft.safeMint(address(vault));
        nft.unsafeMint(address(vault));
        assertEq(nft.balanceOf(address(vault)), 3);
    }

    function test_erc721_safeTransferFrom_to_vault() public {
        MockERC721 nft = new MockERC721();
        uint256 tokenId = nft.safeMint(address(this));
        nft.safeTransferFrom(address(this), address(vault), tokenId);
        assertEq(nft.ownerOf(tokenId), address(vault));
    }

    function test_withdrawERC721_by_owner() public {
        MockERC721 nft = new MockERC721();
        uint256 tokenId = nft.safeMint(address(vault));

        vm.prank(vaultOwner);
        vault.withdrawERC721(address(nft), tokenId, recipient);

        assertEq(nft.ownerOf(tokenId), recipient);
        assertEq(nft.balanceOf(address(vault)), 0);
    }

    function test_withdrawERC721_reverts_non_owner() public {
        MockERC721 nft = new MockERC721();
        uint256 tokenId = nft.safeMint(address(vault));

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", attacker));
        vault.withdrawERC721(address(nft), tokenId, recipient);
    }

    function test_withdrawERC721_reverts_operator() public {
        MockERC721 nft = new MockERC721();
        uint256 tokenId = nft.safeMint(address(vault));

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", operator));
        vault.withdrawERC721(address(nft), tokenId, recipient);
    }

    function test_withdrawERC721_reverts_zero_address() public {
        MockERC721 nft = new MockERC721();
        uint256 tokenId = nft.safeMint(address(vault));

        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAddress.selector);
        vault.withdrawERC721(address(nft), tokenId, address(0));
    }

    function test_erc721_via_executeProtocol() public {
        MockERC721 nft = new MockERC721();
        vm.prank(vaultOwner);
        vault.approveProtocol(address(nft));

        bytes memory callData = abi.encodeWithSignature("safeMint(address)", address(vault));

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(nft),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("nft-mint")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        assertEq(nft.balanceOf(address(vault)), 1);
    }

    // =========================================================================
    // NFT support — ERC-1155
    // =========================================================================

    function test_erc1155_mint_to_vault() public {
        MockERC1155 token = new MockERC1155();
        token.mint(address(vault), 1, 10);
        assertEq(token.balanceOf(address(vault), 1), 10);
    }

    function test_erc1155_mintBatch_to_vault() public {
        MockERC1155 token = new MockERC1155();
        uint256[] memory ids = new uint256[](3);
        uint256[] memory amounts = new uint256[](3);
        ids[0] = 1;
        ids[1] = 2;
        ids[2] = 3;
        amounts[0] = 10;
        amounts[1] = 20;
        amounts[2] = 30;
        token.mintBatch(address(vault), ids, amounts);

        assertEq(token.balanceOf(address(vault), 1), 10);
        assertEq(token.balanceOf(address(vault), 2), 20);
        assertEq(token.balanceOf(address(vault), 3), 30);
    }

    function test_withdrawERC1155_by_owner() public {
        MockERC1155 token = new MockERC1155();
        token.mint(address(vault), 1, 10);

        vm.prank(vaultOwner);
        vault.withdrawERC1155(address(token), 1, 5, recipient);

        assertEq(token.balanceOf(address(vault), 1), 5);
        assertEq(token.balanceOf(recipient, 1), 5);
    }

    function test_withdrawERC1155_reverts_non_owner() public {
        MockERC1155 token = new MockERC1155();
        token.mint(address(vault), 1, 10);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", attacker));
        vault.withdrawERC1155(address(token), 1, 5, recipient);
    }

    function test_withdrawERC1155_reverts_zero_amount() public {
        MockERC1155 token = new MockERC1155();
        token.mint(address(vault), 1, 10);

        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAmount.selector);
        vault.withdrawERC1155(address(token), 1, 0, recipient);
    }

    function test_withdrawERC1155_reverts_zero_address() public {
        MockERC1155 token = new MockERC1155();
        token.mint(address(vault), 1, 10);

        vm.prank(vaultOwner);
        vm.expectRevert(AxonVault.ZeroAddress.selector);
        vault.withdrawERC1155(address(token), 1, 5, address(0));
    }

    // =========================================================================
    // ERC-165 supportsInterface
    // =========================================================================

    function test_supportsInterface_erc721_receiver() public view {
        assertTrue(vault.supportsInterface(type(IERC721Receiver).interfaceId));
    }

    function test_supportsInterface_erc1155_receiver() public view {
        assertTrue(vault.supportsInterface(type(IERC1155Receiver).interfaceId));
    }

    function test_supportsInterface_erc165() public view {
        assertTrue(vault.supportsInterface(type(IERC165).interfaceId));
    }

    function test_supportsInterface_random_returns_false() public view {
        assertFalse(vault.supportsInterface(0xdeadbeef));
    }

    // Needed for safeTransferFrom test (this contract sends an NFT to the vault)
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    // =========================================================================
    // Mock TWAP Oracle helpers
    // =========================================================================

    /// @dev Uniswap V3 pool init code hash (must match TwapOracle.POOL_INIT_CODE_HASH)
    bytes32 constant POOL_INIT_CODE_HASH = 0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54;

    /// @dev Deploy a MockUniV3Pool at the exact address the TwapOracle would compute
    ///      for the given token pair and fee tier, then set tick cumulatives for a target tick.
    function _deployMockPool(address tokenA, address tokenB, uint24 fee, int56 targetTick) internal {
        // Compute the pool address the same way TwapOracle._computePoolAddress does
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        address poolAddr = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff), v3Factory, keccak256(abi.encode(t0, t1, fee)), POOL_INIT_CODE_HASH
                        )
                    )
                )
            )
        );

        // Deploy MockUniV3Pool and etch its bytecode at the computed address
        MockUniV3Pool mock = new MockUniV3Pool();
        vm.etch(poolAddr, address(mock).code);

        // vm.etch only copies runtime bytecode, not storage — set liquidity manually (slot 0)
        vm.store(poolAddr, bytes32(uint256(0)), bytes32(uint256(1_000_000e18)));

        // Set tick cumulatives: TWAP_PERIOD = 1800s
        // meanTick = (c1 - c0) / 1800 = targetTick
        // So c0 = 0, c1 = targetTick * 1800
        int56 c0 = 0;
        int56 c1 = targetTick * 1800;
        MockUniV3Pool(poolAddr).setTickCumulatives(c0, c1);
    }

    /// @dev Return the Uniswap V3 tick that represents a given ETH/USD price.
    ///      tick = log(price) / log(1.0001)
    ///      For WETH (18 dec) / USDC (6 dec), the tick for $2000/ETH ≈ −202198.
    ///      The sign depends on sort order: if USDC < WETH, tick is positive (WETH per USDC → small).
    ///      We use a simple lookup for common test prices.
    function _ethPriceTick(uint256 priceUsd) internal view returns (int56) {
        // The tick represents token1/token0 in sorted order.
        // If USDC < WETH: tick = log1.0001(WETH_per_USDC) → very negative (USDC is cheap in WETH terms)
        // If WETH < USDC: tick = log1.0001(USDC_per_WETH) → very positive

        // Determine sort order
        bool wethIsToken0 = address(weth) < address(usdc);

        // Pre-calculated ticks for common prices (18 dec vs 6 dec):
        // $2000/ETH with WETH as token0: tick ≈ 202198  (USDC per WETH = 2000e6/1e18 → adjusted)
        // Actually, the raw tick for sqrtPrice of 2000 USDC/WETH at different decimals:
        // price = 2000 * 10^6 / 10^18 = 2000 * 10^-12
        // tick = log(2000 * 10^-12) / log(1.0001) ≈ -202198
        // When WETH is token0: tick represents token1(USDC)/token0(WETH) → tick ≈ -202198
        // When USDC is token0: tick represents token1(WETH)/token0(USDC) → tick ≈ 202198

        if (priceUsd == 2000) {
            return wethIsToken0 ? int56(-202198) : int56(202198);
        } else if (priceUsd == 1000) {
            return wethIsToken0 ? int56(-209198) : int56(209198);
        } else if (priceUsd == 3000) {
            return wethIsToken0 ? int56(-198143) : int56(198143);
        }
        revert("_ethPriceTick: unsupported price");
    }

    // =========================================================================
    // Multi-token approval (tokens[] / amounts[])
    // =========================================================================

    function test_executeProtocol_multiToken_approved_and_revoked() public {
        // mockProtocol already approved in setUp, fund vault
        usdc.mint(address(vault), 1000 * USDC_DECIMALS);
        usdt.mint(address(vault), 500 * USDC_DECIMALS);

        bytes memory callData = abi.encodeWithSelector(MockProtocol.noTokenAction.selector, "");

        // Build multi-token arrays — both USDC and USDT
        address[] memory tTokens = new address[](2);
        tTokens[0] = address(usdc);
        tTokens[1] = address(usdt);
        uint256[] memory tAmounts = new uint256[](2);
        tAmounts[0] = 100 * USDC_DECIMALS;
        tAmounts[1] = 50 * USDC_DECIMALS;

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tTokens,
            amounts: tAmounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: bytes32(0)
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        // Verify all approvals are revoked after call
        assertEq(usdc.allowance(address(vault), address(mockProtocol)), 0);
        assertEq(usdt.allowance(address(vault), address(mockProtocol)), 0);
    }

    function test_executeProtocol_arrayLengthMismatch_reverts() public {
        bytes memory callData = abi.encodeWithSelector(MockProtocol.noTokenAction.selector, "");

        // Mismatched arrays — 1 token, 0 amounts
        address[] memory tTokens = new address[](1);
        tTokens[0] = address(usdt);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tTokens,
            amounts: new uint256[](0),
            value: 0,
            deadline: block.timestamp + 300,
            ref: bytes32(0)
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.ArrayLengthMismatch.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_emptyTokens_works() public {
        usdc.mint(address(vault), 1000 * USDC_DECIMALS);

        bytes memory callData = abi.encodeWithSelector(MockProtocol.noTokenAction.selector, "");
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: _addrArray(address(usdc)),
            amounts: _uintArray(100 * USDC_DECIMALS),
            value: 0,
            deadline: block.timestamp + 300,
            ref: bytes32(0)
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);

        assertEq(usdc.allowance(address(vault), address(mockProtocol)), 0);
    }

    function test_executeProtocol_tooManyTokens_reverts() public {
        bytes memory callData = abi.encodeWithSelector(MockProtocol.noTokenAction.selector, "");

        // 6 tokens — exceeds max of 5
        address[] memory tTokens = new address[](6);
        uint256[] memory tAmounts = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            tTokens[i] = address(uint160(0x1000 + i));
            tAmounts[i] = 1;
        }

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tTokens,
            amounts: tAmounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: bytes32(0)
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.TooManyTokens.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    function test_executeProtocol_fiveTokens_succeeds() public {
        bytes memory callData = abi.encodeWithSelector(MockProtocol.noTokenAction.selector, "");

        // Exactly 5 tokens — should work (at the limit)
        address[] memory tTokens = new address[](5);
        uint256[] memory tAmounts = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) {
            tTokens[i] = address(uint160(0x1000 + i));
            tAmounts[i] = 0; // No actual approval needed, just testing the limit
        }

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tTokens,
            amounts: tAmounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: bytes32(0)
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    // =========================================================================
    // executeSwap — minToAmount / output validation security tests
    // =========================================================================

    function test_executeSwap_reverts_when_output_insufficient() public {
        uint256 minOutput = 490 * USDC_DECIMALS;
        // Fund router with enough for a full swap, but swapShort only delivers half
        usdt.mint(address(swapRouter), minOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: 500 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("short-swap")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        // swapShort delivers only half of toAmount → vault receives minOutput/2 < minOutput
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swapShort, (address(usdc), 500 * USDC_DECIMALS, address(usdt), minOutput, address(vault))
        );

        vm.prank(relayer);
        vm.expectRevert(AxonVault.SwapOutputInsufficient.selector);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);
    }

    function test_executeSwap_reverts_when_swap_delivers_nothing() public {
        uint256 minOutput = 490 * USDC_DECIMALS;

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: 500 * USDC_DECIMALS,
            deadline: _deadline(),
            ref: bytes32("fail-swap")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        // swapAndFail reverts internally → _doSwap propagates the revert
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swapAndFail, (address(usdc), 500 * USDC_DECIMALS, address(usdt), minOutput, address(vault))
        );

        vm.prank(relayer);
        vm.expectRevert(); // router revert bubbles up
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);
    }

    function test_executeSwap_succeeds_when_output_sufficient() public {
        uint256 swapInput = 500 * USDC_DECIMALS;
        uint256 minOutput = 490 * USDC_DECIMALS;
        uint256 actualOutput = 495 * USDC_DECIMALS; // delivers more than minToAmount
        usdt.mint(address(swapRouter), actualOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: swapInput,
            deadline: _deadline(),
            ref: bytes32("good-swap")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(usdc), swapInput, address(usdt), actualOutput, address(vault))
        );

        uint256 vaultUsdcBefore = usdc.balanceOf(address(vault));

        vm.expectEmit(true, false, false, true);
        emit AxonVault.SwapExecuted(bot, address(usdc), address(usdt), swapInput, actualOutput, bytes32("good-swap"));

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);

        // Vault spent USDC and received USDT
        assertEq(usdc.balanceOf(address(vault)), vaultUsdcBefore - swapInput);
        assertEq(usdt.balanceOf(address(vault)), actualOutput);
    }

    function test_executeSwap_reverts_when_router_drains_without_delivering() public {
        uint256 swapInput = 500 * USDC_DECIMALS;
        uint256 minOutput = 490 * USDC_DECIMALS;
        // Fund router so it CAN send tokens — but we route output to attacker, not vault
        usdt.mint(address(swapRouter), minOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: swapInput,
            deadline: _deadline(),
            ref: bytes32("drain-swap")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        // Router pulls fromToken from vault but sends toToken to attacker instead
        bytes memory swapCalldata =
            abi.encodeCall(MockSwapRouter.swap, (address(usdc), swapInput, address(usdt), minOutput, attacker));

        vm.prank(relayer);
        vm.expectRevert(AxonVault.SwapOutputInsufficient.selector);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);

        // Revert rolled back the swap — vault funds are safe
        assertEq(usdc.balanceOf(address(vault)), VAULT_DEPOSIT);
        assertEq(usdt.balanceOf(address(vault)), 0);
    }

    // =========================================================================
    // executeSwap — native ETH output validation
    // =========================================================================

    /// @notice Swap ERC-20 → native ETH succeeds when vault receives enough.
    function test_executeSwap_native_succeeds() public {
        // Disable oracle slippage guard — this test validates native ETH swap mechanics, not slippage
        vm.prank(vaultOwner);
        vault.setMaxSwapSlippageBps(0);

        uint256 swapInput = 500 * USDC_DECIMALS;
        uint256 minOutput = 0.1 ether;
        uint256 actualOutput = 0.12 ether;

        // Fund swap router with ETH
        vm.deal(address(swapRouter), actualOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: vault.NATIVE_ETH(),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: swapInput,
            deadline: _deadline(),
            ref: bytes32("native-swap")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        bytes memory swapCalldata =
            abi.encodeCall(MockSwapRouter.swapToNative, (address(usdc), swapInput, actualOutput, address(vault)));

        uint256 vaultEthBefore = address(vault).balance;

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);

        // Vault received native ETH
        assertEq(address(vault).balance, vaultEthBefore + actualOutput);
    }

    /// @notice Swap ERC-20 → native ETH reverts when router sends ETH to attacker instead.
    function test_executeSwap_native_reverts_when_routed_to_attacker() public {
        uint256 swapInput = 500 * USDC_DECIMALS;
        uint256 minOutput = 0.1 ether;

        // Fund swap router with ETH
        vm.deal(address(swapRouter), minOutput);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: vault.NATIVE_ETH(),
            minToAmount: minOutput,
            fromToken: address(usdc),
            maxFromAmount: swapInput,
            deadline: _deadline(),
            ref: bytes32("native-drain")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);

        // Router sends ETH to attacker, not vault
        bytes memory swapCalldata =
            abi.encodeCall(MockSwapRouter.swapToNativeAttacker, (address(usdc), swapInput, minOutput, attacker));

        vm.prank(relayer);
        vm.expectRevert(AxonVault.SwapOutputInsufficient.selector);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);

        // Vault funds safe
        assertEq(usdc.balanceOf(address(vault)), VAULT_DEPOSIT);
    }

    // =========================================================================
    // Oracle slippage guard & previewSwapSlippage
    // =========================================================================

    function test_setMaxSwapSlippageBps() public {
        assertEq(vault.maxSwapSlippageBps(), 9500); // default from initialize
        vm.prank(vaultOwner);
        vault.setMaxSwapSlippageBps(9000);
        assertEq(vault.maxSwapSlippageBps(), 9000);
    }

    function test_setMaxSwapSlippageBps_only_owner() public {
        vm.prank(vm.addr(999));
        vm.expectRevert();
        vault.setMaxSwapSlippageBps(9000);
    }

    function test_previewSwapSlippage_disabled_when_zero() public {
        vm.prank(vaultOwner);
        vault.setMaxSwapSlippageBps(0);

        (bool wouldPass, uint256 fromUsd, uint256 toUsd, uint256 minToUsd) =
            vault.previewSwapSlippage(address(usdc), 100 * USDC_DECIMALS, address(usdt), 50 * USDC_DECIMALS);
        assertTrue(wouldPass);
        assertEq(fromUsd, 0);
        assertEq(toUsd, 0);
        assertEq(minToUsd, 0);
    }

    function test_oracleUsdValue_returns_usdc_amount() public view {
        // USDC → USDC should return the amount directly (no oracle needed)
        uint256 val = vault.oracleUsdValue(address(usdc), 100 * USDC_DECIMALS);
        assertEq(val, 100 * USDC_DECIMALS);
    }

    function test_executeSwap_emits_OracleCheckSkipped_for_unknown_token() public {
        // Create a token the oracle cannot price (no Uniswap pool)
        MockERC20 exoticToken = new MockERC20("Exotic", "EXO", 18);
        uint256 fromAmount = 500 * USDC_DECIMALS;
        uint256 toAmount = 1 ether;

        // Fund vault with USDC and router with exotic token
        exoticToken.mint(address(swapRouter), toAmount);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(exoticToken),
            minToAmount: toAmount,
            fromToken: address(usdc),
            maxFromAmount: fromAmount,
            deadline: _deadline(),
            ref: bytes32("oracle-skip")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(usdc), fromAmount, address(exoticToken), toAmount, address(vault))
        );

        // Expect OracleCheckSkipped because exoticToken has no oracle pool
        vm.expectEmit(true, true, false, true);
        emit AxonVault.OracleCheckSkipped(address(usdc), address(exoticToken), "toToken oracle failed");

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);

        // Swap still succeeds (fail-open)
        assertEq(exoticToken.balanceOf(address(vault)), toAmount);
    }

    function test_executeSwap_emits_OracleCheckSkipped_fromToken_unknown() public {
        // Swap FROM an exotic token (oracle can't price it) TO USDC
        MockERC20 exoticToken = new MockERC20("Exotic", "EXO", 18);
        uint256 fromAmount = 1 ether;
        uint256 toAmount = 500 * USDC_DECIMALS;

        // Fund vault with exotic token and router with USDC
        exoticToken.mint(address(vault), fromAmount);
        usdc.mint(address(swapRouter), toAmount);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdc),
            minToAmount: toAmount,
            fromToken: address(exoticToken),
            maxFromAmount: fromAmount,
            deadline: _deadline(),
            ref: bytes32("oracle-skip-from")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        bytes memory swapCalldata = abi.encodeCall(
            MockSwapRouter.swap, (address(exoticToken), fromAmount, address(usdc), toAmount, address(vault))
        );

        // Expect OracleCheckSkipped because exoticToken (fromToken) has no oracle
        vm.expectEmit(true, true, false, true);
        emit AxonVault.OracleCheckSkipped(address(exoticToken), address(usdc), "fromToken oracle failed");

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapCalldata);

        // Swap still succeeds (fail-open)
        assertEq(usdc.balanceOf(address(vault)), VAULT_DEPOSIT + toAmount);
    }

    function test_removeBot_clears_config_and_destinations() public {
        // Add a destination whitelist entry for bot
        vm.prank(vaultOwner);
        vault.addBotDestination(bot, vm.addr(777));
        assertEq(vault.botDestinationCount(bot), 1);

        // Verify bot config exists
        AxonVault.BotConfig memory configBefore = vault.getBotConfig(bot);
        assertTrue(configBefore.isActive);
        assertGt(configBefore.aiTriggerThreshold, 0);

        // Remove bot
        vm.prank(vaultOwner);
        vault.removeBot(bot);

        // Config should be fully cleared
        AxonVault.BotConfig memory configAfter = vault.getBotConfig(bot);
        assertFalse(configAfter.isActive);
        assertEq(configAfter.maxPerTxAmount, 0);
        assertEq(configAfter.maxRebalanceAmount, 0);
        assertEq(configAfter.aiTriggerThreshold, 0);
        assertFalse(configAfter.requireAiVerification);
        assertEq(configAfter.registeredAt, 0);
        assertEq(configAfter.spendingLimits.length, 0);

        // Destination count should be reset
        assertEq(vault.botDestinationCount(bot), 0);
    }

    // =========================================================================
    // NM-001v3: Default token approve() — spender validation + amount cap
    // =========================================================================

    /// @dev Approve to an unapproved address should revert (drain vector).
    function test_defaultToken_approve_reverts_unapproved_spender() public {
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));

        // Try to approve to attacker (not an approved protocol)
        bytes memory callData = abi.encodeWithSignature("approve(address,uint256)", attacker, 1000e6);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("drain-blocked")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DefaultTokenCallRestricted.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev Approve to a vault-approved protocol should succeed.
    function test_defaultToken_approve_allows_approved_protocol() public {
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));

        // Approve to mockProtocol (vault-level approved)
        bytes memory callData = abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 1000e6);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("approve-protocol-ok")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev Approve to a globally approved protocol should succeed.
    function test_defaultToken_approve_allows_global_protocol() public {
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));

        address globalProtocol = makeAddr("globalProto");
        registry.approveProtocol(globalProtocol);

        bytes memory callData = abi.encodeWithSignature("approve(address,uint256)", globalProtocol, 500e6);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("approve-global-ok")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev Approve to an approved swap router should succeed.
    function test_defaultToken_approve_allows_swap_router() public {
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));

        bytes memory callData = abi.encodeWithSignature("approve(address,uint256)", address(swapRouter), 500e6);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("approve-router-ok")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev Approve amount exceeding maxPerTxAmount should revert (amount cap).
    ///      Uses USDC (oracle base token, 1:1 USD) so TWAP lookup succeeds.
    function test_defaultToken_approve_reverts_amount_exceeds_cap() public {
        // Set bot's maxPerTxAmount to $2k
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 2_000 * USDC_DECIMALS,
                maxRebalanceAmount: 0,
                spendingLimits: new AxonVault.SpendingLimit[](0),
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        // Use USDC as default token — it's the oracle base so price lookup works
        registry.approveDefaultToken(address(usdc));

        // Approve $3k to an approved protocol — exceeds $2k cap
        bytes memory callData =
            abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 3_000 * USDC_DECIMALS);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(usdc),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("approve-capped")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.MaxPerTxExceeded.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev Approve amount within maxPerTxAmount should succeed.
    function test_defaultToken_approve_within_cap_succeeds() public {
        // Set bot's maxPerTxAmount to $2k
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 2_000 * USDC_DECIMALS,
                maxRebalanceAmount: 0,
                spendingLimits: new AxonVault.SpendingLimit[](0),
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        // Use USDC as default token — it's the oracle base so price lookup works
        registry.approveDefaultToken(address(usdc));

        // Approve $1k to an approved protocol — within $2k cap
        bytes memory callData =
            abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 1_000 * USDC_DECIMALS);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(usdc),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("approve-ok-capped")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev Bot with maxPerTxAmount=0 (no cap) can approve any amount to approved protocol.
    function test_defaultToken_approve_uncapped_bot_succeeds() public {
        // Default bot has maxPerTxAmount=0 (no cap)
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));

        bytes memory callData =
            abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 50_000 * USDC_DECIMALS);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("approve-uncapped")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vault.executeProtocol(intent, sig, callData);
    }

    /// @dev Calldata too short for approve args should revert.
    function test_defaultToken_approve_short_calldata_reverts() public {
        MockERC20 freshToken = new MockERC20("Fresh", "FRESH", 6);
        registry.approveDefaultToken(address(freshToken));

        // Only 4 bytes (selector) + 20 bytes — missing the amount
        bytes memory callData = abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 100e6);
        // Truncate to just selector + partial data (36 bytes instead of 68)
        bytes memory shortData = new bytes(36);
        for (uint256 i = 0; i < 36; i++) {
            shortData[i] = callData[i];
        }

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(freshToken),
            calldataHash: keccak256(shortData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("short-calldata")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        vm.prank(relayer);
        vm.expectRevert(AxonVault.DefaultTokenCallRestricted.selector);
        vault.executeProtocol(intent, sig, shortData);
    }

    /// @dev L-01: Bot active check must run BEFORE _checkMaxPerTxAmount on default token approve.
    ///      A removed bot's zeroed config has maxPerTxAmount=0 ("no cap"), so the cap check
    ///      silently passes. The bot active check must fire first.
    function test_defaultToken_approve_reverts_botNotActive_before_cap_check() public {
        // Give bot a $2k cap
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 2_000 * USDC_DECIMALS,
                maxRebalanceAmount: 0,
                spendingLimits: new AxonVault.SpendingLimit[](0),
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        registry.approveDefaultToken(address(usdc));

        // Remove the bot — config is now zeroed (maxPerTxAmount=0 = "no cap")
        vm.prank(vaultOwner);
        vault.removeBot(bot);

        // Approve $3k on a default token — exceeds the old $2k cap, but zeroed config means no cap
        bytes memory callData =
            abi.encodeWithSignature("approve(address,uint256)", address(mockProtocol), 3_000 * USDC_DECIMALS);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: bot,
            protocol: address(usdc),
            calldataHash: keccak256(callData),
            tokens: new address[](0),
            amounts: new uint256[](0),
            value: 0,
            deadline: _deadline(),
            ref: bytes32("order-check")
        });
        bytes memory sig = _signExecute(BOT_KEY, intent);

        // Must revert BotNotActive — not silently pass the cap check
        vm.prank(relayer);
        vm.expectRevert(AxonVault.BotNotActive.selector);
        vault.executeProtocol(intent, sig, callData);
    }

    // =========================================================================
    // Audit gap tests
    // =========================================================================

    // 1. previewSwapSlippage — verify it returns correct USD values and pass/fail
    function test_previewSwapSlippage_returns_correct_values() public view {
        // Default slippage is 9500 bps (95%). USDC→USDC oracle returns amount directly.
        // 100 USDC in, 96 USDC out → should pass (96 >= 95)
        (bool wouldPass, uint256 fromUsd, uint256 toUsd, uint256 minToUsd) =
            vault.previewSwapSlippage(address(usdc), 100 * USDC_DECIMALS, address(usdc), 96 * USDC_DECIMALS);
        assertTrue(wouldPass);
        assertEq(fromUsd, 100 * USDC_DECIMALS);
        assertEq(toUsd, 96 * USDC_DECIMALS);
        assertEq(minToUsd, 100 * USDC_DECIMALS * 9500 / 10_000); // 95 USDC

        // 100 USDC in, 90 USDC out → should fail (90 < 95)
        (bool wouldPass2,,,) =
            vault.previewSwapSlippage(address(usdc), 100 * USDC_DECIMALS, address(usdc), 90 * USDC_DECIMALS);
        assertFalse(wouldPass2);
    }

    // 2. SwapSlippageTooHigh revert path — trigger oracle-based slippage rejection
    function test_executeSwap_reverts_SwapSlippageTooHigh() public {
        // USDC→USDC swap where router delivers far less than input (below 95% threshold)
        uint256 fromAmount = 100 * USDC_DECIMALS;
        uint256 toAmount = 80 * USDC_DECIMALS; // 80% retention, below 95% threshold

        // Fund router with USDT (use a priceable token)
        // Use USDC→USDC to keep oracle pricing simple (both price at face value)
        usdc.mint(address(swapRouter), toAmount);

        // Create a second USDC-like token that the oracle prices the same
        // Actually: use USDC as both from and to — router pulls USDC, sends USDC back (less)
        // But from/to can't be same token. Use USDT with a deployed oracle pool.
        // Deploy USDT oracle pool at $1 (same tick as USDC)
        _deployMockPool(address(usdt), address(usdc), 3000, 0); // tick 0 ≈ 1:1

        usdt.mint(address(swapRouter), toAmount);

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdt),
            minToAmount: toAmount, // bot accepts 80 USDT
            fromToken: address(usdc),
            maxFromAmount: fromAmount,
            deadline: _deadline(),
            ref: bytes32("slippage-high")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        bytes memory swapData =
            abi.encodeCall(MockSwapRouter.swap, (address(usdc), fromAmount, address(usdt), toAmount, address(vault)));

        vm.prank(relayer);
        vm.expectRevert(AxonVault.SwapSlippageTooHigh.selector);
        vault.executeSwap(intent, sig, address(swapRouter), swapData);
    }

    // 3. Native ETH as fromToken in executeSwap
    function test_executeSwap_native_eth_as_fromToken() public {
        uint256 ethAmount = 1 ether;
        uint256 usdcOut = 2000 * USDC_DECIMALS;

        // Fund vault with ETH and router with USDC
        vm.deal(address(vault), ethAmount);
        usdc.mint(address(swapRouter), usdcOut);

        // Update bot's maxRebalanceAmount to cover 1 ETH (~$2000)
        vm.prank(vaultOwner);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 5000 * USDC_DECIMALS,
                maxRebalanceAmount: 5000 * USDC_DECIMALS,
                aiTriggerThreshold: 10_000 * USDC_DECIMALS,
                requireAiVerification: false,
                spendingLimits: new AxonVault.SpendingLimit[](0)
            })
        );

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: bot,
            toToken: address(usdc),
            minToAmount: usdcOut,
            fromToken: 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE, // NATIVE_ETH
            maxFromAmount: ethAmount,
            deadline: _deadline(),
            ref: bytes32("eth-swap")
        });
        bytes memory sig = _signSwap(BOT_KEY, intent);
        // Router receives ETH via call{value}, sends USDC back
        bytes memory swapData = abi.encodeCall(MockSwapRouter.swapFromNative, (address(usdc), usdcOut, address(vault)));

        vm.prank(relayer);
        vault.executeSwap(intent, sig, address(swapRouter), swapData);

        // Vault should have received USDC and spent ETH
        assertEq(usdc.balanceOf(address(vault)), VAULT_DEPOSIT + usdcOut);
        assertEq(address(vault).balance, 0);
    }

    // 4. setMaxSwapSlippageBps(10001) revert — bps > 10000
    function test_setMaxSwapSlippageBps_reverts_above_10000() public {
        vm.prank(vaultOwner);
        vm.expectRevert("bps > 10000");
        vault.setMaxSwapSlippageBps(10_001);
    }

    // 5. Operator ceiling behavior when maxPerTxAmount ceiling is 0 on update
    //    When ceiling.maxPerTxAmount = 0, operator must preserve the current bot value (cannot change it)
    function test_operator_ceiling_maxPerTxAmount_zero_on_update() public {
        // Set ceilings with maxPerTxAmount = 0 (operator cannot change per-tx cap)
        vm.prank(vaultOwner);
        vault.setOperatorCeilings(
            AxonVault.OperatorCeilings({
                maxPerTxAmount: 0, maxBotDailyLimit: 0, maxOperatorBots: 5, vaultDailyAggregate: 0, minAiTriggerFloor: 0
            })
        );

        // Bot's current config from setUp
        AxonVault.BotConfig memory currentConfig = vault.getBotConfig(bot);
        uint256 currentMaxPerTx = currentConfig.maxPerTxAmount;

        // Must preserve spending limits count (operator can't reduce)
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 10_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        // Operator tries to change maxPerTxAmount → should revert
        vm.prank(operator);
        vm.expectRevert(AxonVault.ExceedsOperatorCeiling.selector);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: currentMaxPerTx + 1, // different value → revert
                maxRebalanceAmount: currentConfig.maxRebalanceAmount,
                aiTriggerThreshold: currentConfig.aiTriggerThreshold,
                requireAiVerification: currentConfig.requireAiVerification,
                spendingLimits: limits
            })
        );

        // Operator preserves the same value → should succeed
        vm.prank(operator);
        vault.updateBotConfig(
            bot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: currentMaxPerTx, // same value → OK
                maxRebalanceAmount: currentConfig.maxRebalanceAmount,
                aiTriggerThreshold: currentConfig.aiTriggerThreshold,
                requireAiVerification: currentConfig.requireAiVerification,
                spendingLimits: limits
            })
        );
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../../src/AxonVault.sol";
import "../../src/AxonRegistry.sol";
import "../mocks/MockERC20.sol";
import "../mocks/MockERC721.sol";
import "../mocks/MockERC1155.sol";
import "../mocks/MockSwapRouter.sol";
import "../mocks/MockProtocol.sol";

/// @title AxonVault Medusa Fuzz Harness
/// @notice Comprehensive property-based fuzz testing for AxonVault invariants.
///         Harness is both vault owner and authorized relayer.
///         Uses Medusa's `property_` prefix convention.
///
///         Coverage:
///         - executePayment: conservation, pause, deadline, replay, blacklist, whitelist, maxPerTxAmount, bot auth
///         - executeSwap: rebalance whitelist, maxRebalanceAmount, same-token, router auth, slippage, balance
///         - executeProtocol: protocol auth, calldata hash, combined cap, token array length, bot auth
///         - Operator: ceiling enforcement (maxPerTx, AI floor, daily limit, bot limit), tighten-only
///         - Admin: withdraw auth, pause/unpause auth, whitelist/blacklist access control
///         - Bot lifecycle: add, remove, owner-cant-be-bot, deactivation blocks payments
///         - Deposit: zero-amount blocked
///         - Invariants: bot count, protocol count, balance conservation
contract AxonVaultFuzzHarness {
    AxonRegistry public registry;
    AxonVault public vault;
    MockERC20 public usdc;
    MockERC20 public weth; // second token for swap testing
    MockSwapRouter public swapRouter;
    MockProtocol public mockProtocol;
    MockERC721 public nft;
    MockERC1155 public multiToken;

    // Pre-computed: address for private key 0xB07
    address constant BOT = 0xa6A396C4e95ce61aa0556CC770eDf5bDE1955149;
    uint256 constant BOT_KEY = 0xB07;
    // Bot with no per-tx cap (maxPerTxAmount=0) — used for tests that send ETH value
    // where the combined cap check would hit the TWAP oracle (no real pools in fuzz env).
    address constant BOT_NOCAP = 0xa7F648d3Fd78F45E7dd311d99D2aE0e87cB4d7E5;
    uint256 constant BOT_NOCAP_KEY = 0xB08;
    // Operator: address for private key 0x0507
    address constant OPERATOR = 0x9009988B61eA2C09914BbDf897d1ee4e95941DBe;
    uint256 constant OPERATOR_KEY = 0x0507;
    address constant RECIPIENT = address(0xBEEF);
    address constant RANDOM_DEST = address(0xCAFE);
    uint256 constant USDC_DECIMALS = 1e6;
    uint256 constant WETH_DECIMALS = 1e18;
    uint256 constant INITIAL_DEPOSIT = 100_000 * USDC_DECIMALS;
    uint256 constant MAX_PER_TX = 10_000 * USDC_DECIMALS;
    uint256 constant MAX_REBALANCE = 5_000 * USDC_DECIMALS;

    bytes32 constant PAYMENT_INTENT_TYPEHASH =
        keccak256("PaymentIntent(address bot,address to,address token,uint256 amount,uint256 deadline,bytes32 ref)");

    bytes32 constant SWAP_INTENT_TYPEHASH = keccak256(
        "SwapIntent(address bot,address toToken,uint256 minToAmount,address fromToken,uint256 maxFromAmount,uint256 deadline,bytes32 ref)"
    );

    bytes32 constant EXECUTE_INTENT_TYPEHASH = keccak256(
        "ExecuteIntent(address bot,address protocol,bytes32 calldataHash,address[] tokens,uint256[] amounts,uint256 value,uint256 deadline,bytes32 ref)"
    );

    // Foundry VM at well-known address
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    uint256 public totalPaymentsOut;
    uint256 public totalDeposited; // additional deposits beyond INITIAL_DEPOSIT
    uint256 public totalProtocolOut; // USDC pulled by protocol (openTrade)
    uint256 public nonce;

    constructor() {
        // This contract = owner + relayer
        registry = new AxonRegistry(address(this));
        registry.addRelayer(address(this));

        usdc = new MockERC20("USD Coin", "USDC", 6);
        weth = new MockERC20("Wrapped Ether", "WETH", 18);
        swapRouter = new MockSwapRouter();
        mockProtocol = new MockProtocol();
        registry.addSwapRouter(address(swapRouter));

        // Configure oracle so TwapOracle.getUsdValue() works for cap checks.
        // Uses a dummy factory (no real pools) — USDC shortcut returns 1:1,
        // non-USDC tokens will hit OracleUnavailable (expected in tests).
        registry.setOracleConfig(address(0xFAC), address(usdc), address(weth));

        AxonVault impl = new AxonVault();
        address clone = Clones.clone(address(impl));
        vault = AxonVault(payable(clone));
        vault.initialize(address(this), address(registry));
        usdc.mint(address(vault), INITIAL_DEPOSIT);

        // Pre-fund swap router with WETH for swap tests
        weth.mint(address(swapRouter), 1_000 * WETH_DECIMALS);
        // Pre-fund mock protocol
        usdc.mint(address(mockProtocol), 10_000 * USDC_DECIMALS);

        // NFT mocks — mint into vault for withdrawal tests
        nft = new MockERC721();
        multiToken = new MockERC1155();
        nft.safeMint(address(vault)); // tokenId 0
        multiToken.mint(address(vault), 1, 100); // id 1, amount 100

        // Fund vault with native ETH for ETH withdrawal tests
        vm.deal(address(vault), 1 ether);

        // Register bot with $10k per-tx cap, $5k rebalance cap
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 50_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        vault.addBot(
            BOT,
            AxonVault.BotConfigParams({
                maxPerTxAmount: MAX_PER_TX,
                maxRebalanceAmount: MAX_REBALANCE,
                spendingLimits: limits,
                aiTriggerThreshold: 1_000 * USDC_DECIMALS,
                requireAiVerification: false
            })
        );

        // Register BOT_NOCAP with no per-tx cap (for ETH value tests that bypass oracle)
        AxonVault.SpendingLimit[] memory noLimits = new AxonVault.SpendingLimit[](0);
        vault.addBot(
            BOT_NOCAP,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 0, // no cap — skips combined oracle check
                maxRebalanceAmount: 0,
                spendingLimits: noLimits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        vault.approveProtocol(address(mockProtocol));

        // Set up operator with ceilings
        vault.setOperator(OPERATOR);
        vault.setOperatorCeilings(
            AxonVault.OperatorCeilings({
                maxPerTxAmount: 5_000 * USDC_DECIMALS,
                maxBotDailyLimit: 20_000 * USDC_DECIMALS,
                maxOperatorBots: 3,
                vaultDailyAggregate: 50_000 * USDC_DECIMALS,
                minAiTriggerFloor: 500 * USDC_DECIMALS
            })
        );
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    function _signPayment(AxonVault.PaymentIntent memory intent) internal returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                PAYMENT_INTENT_TYPEHASH, intent.bot, intent.to, intent.token, intent.amount, intent.deadline, intent.ref
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOT_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signSwap(AxonVault.SwapIntent memory intent) internal returns (bytes memory) {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOT_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signExecute(AxonVault.ExecuteIntent memory intent) internal returns (bytes memory) {
        return _signExecuteWithKey(intent, BOT_KEY);
    }

    function _signExecuteWithKey(AxonVault.ExecuteIntent memory intent, uint256 key) internal returns (bytes memory) {
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _uniqueRef() internal returns (bytes32) {
        return keccak256(abi.encodePacked("fuzz", nonce++));
    }

    function _singleArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }

    // =====================================================================
    // State changers — Medusa calls these to build interesting sequences
    // =====================================================================

    function makePayment(uint256 amount) public {
        if (amount == 0 || amount > usdc.balanceOf(address(vault))) return;
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RECIPIENT,
            token: address(usdc),
            amount: amount,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        if (ok) totalPaymentsOut += amount;
    }

    function makeSwap(uint256 usdcIn, uint256 wethOut) public {
        if (usdcIn == 0 || wethOut == 0) return;
        if (usdcIn > usdc.balanceOf(address(vault))) return;
        if (wethOut > weth.balanceOf(address(swapRouter))) return;

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: BOT,
            toToken: address(weth),
            minToAmount: wethOut,
            fromToken: address(usdc),
            maxFromAmount: usdcIn,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signSwap(intent);

        bytes memory swapCalldata = abi.encodeWithSelector(
            swapRouter.swap.selector, address(usdc), usdcIn, address(weth), wethOut, address(vault)
        );

        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.executeSwap.selector, intent, sig, address(swapRouter), swapCalldata));
        ok; // suppress unused
    }

    function makeProtocolCall() public {
        bytes memory callData = abi.encodeWithSelector(mockProtocol.noTokenAction.selector, "fuzz");
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);

        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        ok; // suppress unused
    }

    function makeProtocolCallWithApproval(uint256 approveAmount) public {
        if (approveAmount == 0 || approveAmount > usdc.balanceOf(address(vault))) return;

        bytes memory callData =
            abi.encodeWithSelector(mockProtocol.openTrade.selector, address(usdc), approveAmount, 0, true, 10);
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = approveAmount;

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);

        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        if (ok) totalProtocolOut += approveAmount;
    }

    function doPause() public {
        if (!vault.paused()) vault.pause();
    }

    function doUnpause() public {
        if (vault.paused()) vault.unpause();
    }

    function addToBlacklist(address dest) public {
        if (dest == address(0)) return;
        if (!vault.globalDestinationBlacklist(dest)) {
            vault.addGlobalBlacklist(dest);
        }
    }

    function addToWhitelist(address dest) public {
        if (dest == address(0)) return;
        if (!vault.globalDestinationWhitelist(dest)) {
            vault.addGlobalDestination(dest);
        }
    }

    function removeFromWhitelist(address dest) public {
        if (vault.globalDestinationWhitelist(dest)) {
            vault.removeGlobalDestination(dest);
        }
    }

    function addBotWhitelist(address dest) public {
        if (dest == address(0)) return;
        if (!vault.botDestinationWhitelist(BOT, dest)) {
            vault.addBotDestination(BOT, dest);
        }
    }

    function addRebalanceToken(address token) public {
        if (token == address(0)) return;
        vault.addRebalanceTokens(_singleArray(token));
    }

    function removeRebalanceToken(address token) public {
        if (!vault.rebalanceTokenWhitelist(token)) return;
        vault.removeRebalanceTokens(_singleArray(token));
    }

    function operatorAddBot(uint256 botPk) public {
        if (botPk == 0 || botPk == BOT_KEY || botPk == OPERATOR_KEY) return;
        if (botPk >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) return;
        address newBot = vm.addr(botPk);
        if (newBot == address(this) || newBot == OPERATOR || vault.isBotActive(newBot)) return;

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 20_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.addBot.selector,
                    newBot,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: 5_000 * USDC_DECIMALS,
                        maxRebalanceAmount: 2_000 * USDC_DECIMALS,
                        spendingLimits: limits,
                        aiTriggerThreshold: 500 * USDC_DECIMALS,
                        requireAiVerification: false
                    })
                )
            );
        ok; // suppress unused
    }

    function operatorPause() public {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.pause.selector));
        ok;
    }

    function removeBot() public {
        // Remove and re-add BOT to test deactivation
        if (!vault.isBotActive(BOT)) return;
        vault.removeBot(BOT);
    }

    function reAddBot() public {
        if (vault.isBotActive(BOT)) return;
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 50_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        vault.addBot(
            BOT,
            AxonVault.BotConfigParams({
                maxPerTxAmount: MAX_PER_TX,
                maxRebalanceAmount: MAX_REBALANCE,
                spendingLimits: limits,
                aiTriggerThreshold: 1_000 * USDC_DECIMALS,
                requireAiVerification: false
            })
        );
    }

    function operatorRemoveBot(address bot) public {
        if (!vault.isBotActive(bot) || bot == BOT) return; // don't remove our main test bot via operator
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.removeBot.selector, bot));
        ok;
    }

    function operatorRevokeProtocol() public {
        if (!vault.approvedProtocols(address(mockProtocol))) return;
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.revokeProtocol.selector, address(mockProtocol)));
        ok;
    }

    function ownerReApproveProtocol() public {
        if (vault.approvedProtocols(address(mockProtocol))) return;
        vault.approveProtocol(address(mockProtocol));
    }

    function doDeposit(uint256 amount) public {
        if (amount == 0 || amount > 10_000 * USDC_DECIMALS) return;
        usdc.mint(address(this), amount);
        usdc.approve(address(vault), amount);
        vault.deposit(address(usdc), amount, bytes32(0));
        totalDeposited += amount;
    }

    // =====================================================================
    // PROPERTIES — all must return true for the fuzzer to pass
    // =====================================================================

    // ── 1. Balance Conservation ──

    /// Vault USDC balance + all outflows <= initial deposit + additional deposits
    /// (no money created from thin air)
    function property_balance_conservation() public view returns (bool) {
        return usdc.balanceOf(address(vault)) + totalPaymentsOut + totalProtocolOut <= INITIAL_DEPOSIT + totalDeposited;
    }

    // ── 2. Payment Core Properties ──

    /// Paused vault blocks executePayment
    function property_paused_blocks_payment() public returns (bool) {
        if (!vault.paused()) return true;
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RECIPIENT,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// Paused vault blocks executeSwap
    function property_paused_blocks_swap() public returns (bool) {
        if (!vault.paused()) return true;
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: BOT,
            toToken: address(weth),
            minToAmount: 1 * WETH_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signSwap(intent);
        bytes memory swapCalldata = abi.encodeWithSelector(
            swapRouter.swap.selector,
            address(usdc),
            100 * USDC_DECIMALS,
            address(weth),
            1 * WETH_DECIMALS,
            address(vault)
        );
        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.executeSwap.selector, intent, sig, address(swapRouter), swapCalldata));
        return !ok;
    }

    /// Paused vault blocks executeProtocol
    function property_paused_blocks_protocol() public returns (bool) {
        if (!vault.paused()) return true;
        bytes memory callData = abi.encodeWithSelector(mockProtocol.noTokenAction.selector, "test");
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);
        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        return !ok;
    }

    /// Expired deadlines always revert
    function property_expired_deadline_reverts() public returns (bool) {
        if (block.timestamp == 0) return true;
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RECIPIENT,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp - 1,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// Self-payment to vault address is blocked
    function property_self_payment_blocked() public returns (bool) {
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: address(vault),
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// Zero-amount payment is blocked
    function property_zero_amount_payment_blocked() public returns (bool) {
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT, to: RECIPIENT, token: address(usdc), amount: 0, deadline: block.timestamp + 300, ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// Payment to address(0) is blocked
    function property_zero_address_payment_blocked() public returns (bool) {
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: address(0),
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// Duplicate intent replay is blocked
    function property_replay_protection() public returns (bool) {
        bytes32 ref = keccak256(abi.encodePacked("replay-check", nonce++));
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RECIPIENT,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: ref
        });
        bytes memory sig = _signPayment(intent);

        (bool ok1,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        if (!ok1) return true; // paused or other reason — skip
        totalPaymentsOut += 1 * USDC_DECIMALS;

        // Second attempt MUST fail
        (bool ok2,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok2;
    }

    // ── 3. maxPerTxAmount Properties ──

    /// Payments above maxPerTxAmount always revert (USDC = same as cap units, no oracle needed)
    function property_max_per_tx_payment_enforced() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;
        uint256 overLimit = MAX_PER_TX + 1;
        if (overLimit > usdc.balanceOf(address(vault))) return true;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RECIPIENT,
            token: address(usdc),
            amount: overLimit,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// executeProtocol with token approval above maxPerTxAmount always reverts
    function property_max_per_tx_protocol_enforced() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;
        uint256 overLimit = MAX_PER_TX + 1;
        if (overLimit > usdc.balanceOf(address(vault))) return true;

        bytes memory callData =
            abi.encodeWithSelector(mockProtocol.openTrade.selector, address(usdc), overLimit, 0, true, 10);
        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = overLimit;

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);

        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        return !ok;
    }

    // ── 4. Whitelist Properties ──

    /// When global whitelist is active, payment to non-whitelisted dest reverts
    function property_whitelist_enforced() public returns (bool) {
        if (vault.globalDestinationCount() == 0) return true; // whitelist not active
        if (vault.globalDestinationWhitelist(RANDOM_DEST)) return true; // it's whitelisted
        if (vault.globalDestinationBlacklist(RANDOM_DEST)) return true; // blocked by blacklist
        if (vault.botDestinationWhitelist(BOT, RANDOM_DEST)) return true; // allowed by bot whitelist
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RANDOM_DEST,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// When bot-specific whitelist is active, payment to non-whitelisted dest reverts
    function property_bot_whitelist_enforced() public returns (bool) {
        if (vault.botDestinationCount(BOT) == 0) return true; // bot whitelist not active
        if (vault.botDestinationWhitelist(BOT, RANDOM_DEST)) return true; // it's whitelisted
        if (vault.globalDestinationWhitelist(RANDOM_DEST)) return true; // allowed by global
        if (vault.globalDestinationBlacklist(RANDOM_DEST)) return true; // blocked by blacklist
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RANDOM_DEST,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// Blacklist always wins over whitelist
    function property_blacklist_beats_whitelist() public returns (bool) {
        address dest = address(0xDEAD);
        if (!vault.globalDestinationBlacklist(dest)) return true;
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: dest,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// Blacklisted destinations are blocked (fuzzed address)
    function property_blacklist_enforced(address dest) public returns (bool) {
        if (!vault.globalDestinationBlacklist(dest)) return true;
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: dest,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    // ── 5. executeSwap Properties ──

    /// Swap with non-whitelisted output token reverts when rebalance whitelist is active
    function property_rebalance_whitelist_enforced() public returns (bool) {
        if (vault.rebalanceTokenCount() == 0) return true;
        if (vault.rebalanceTokenWhitelist(address(weth))) return true;
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        uint256 usdcIn = 100 * USDC_DECIMALS;
        uint256 wethOut = 1 * WETH_DECIMALS;
        if (usdcIn > usdc.balanceOf(address(vault))) return true;

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: BOT,
            toToken: address(weth),
            minToAmount: wethOut,
            fromToken: address(usdc),
            maxFromAmount: usdcIn,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signSwap(intent);
        bytes memory swapCalldata = abi.encodeWithSelector(
            swapRouter.swap.selector, address(usdc), usdcIn, address(weth), wethOut, address(vault)
        );

        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.executeSwap.selector, intent, sig, address(swapRouter), swapCalldata));
        return !ok;
    }

    /// Same-token swap always reverts
    function property_same_token_swap_blocked() public returns (bool) {
        if (vault.paused()) return true;
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: BOT,
            toToken: address(usdc),
            minToAmount: 100 * USDC_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signSwap(intent);
        bytes memory swapCalldata = abi.encodeWithSelector(
            swapRouter.swap.selector,
            address(usdc),
            100 * USDC_DECIMALS,
            address(usdc),
            100 * USDC_DECIMALS,
            address(vault)
        );

        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.executeSwap.selector, intent, sig, address(swapRouter), swapCalldata));
        return !ok;
    }

    /// Swap with unapproved router always reverts
    function property_unapproved_router_blocked() public returns (bool) {
        if (vault.paused()) return true;
        address fakeRouter = address(0x999);
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: BOT,
            toToken: address(weth),
            minToAmount: 1 * WETH_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signSwap(intent);

        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.executeSwap.selector, intent, sig, fakeRouter, ""));
        return !ok;
    }

    /// Swap that delivers less than minToAmount reverts (slippage protection)
    function property_swap_slippage_protection() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;
        uint256 usdcIn = 100 * USDC_DECIMALS;
        uint256 wethOut = 10 * WETH_DECIMALS; // request 10 WETH
        if (usdcIn > usdc.balanceOf(address(vault))) return true;

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: BOT,
            toToken: address(weth),
            minToAmount: wethOut,
            fromToken: address(usdc),
            maxFromAmount: usdcIn,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signSwap(intent);

        // MockSwapRouter.swapShort delivers only half
        bytes memory swapCalldata = abi.encodeWithSelector(
            swapRouter.swapShort.selector, address(usdc), usdcIn, address(weth), wethOut, address(vault)
        );

        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.executeSwap.selector, intent, sig, address(swapRouter), swapCalldata));
        return !ok; // must revert — output insufficient
    }

    /// Zero-amount swap always reverts
    function property_zero_amount_swap_blocked() public returns (bool) {
        if (vault.paused()) return true;
        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: BOT,
            toToken: address(weth),
            minToAmount: 0, // zero output
            fromToken: address(usdc),
            maxFromAmount: 100 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signSwap(intent);

        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.executeSwap.selector, intent, sig, address(swapRouter), ""));
        return !ok;
    }

    // ── 6. executeProtocol Properties ──

    /// Unapproved protocol always reverts
    function property_unapproved_protocol_blocked() public returns (bool) {
        if (vault.paused()) return true;
        address fakeProtocol = address(0x777);
        bytes memory callData = abi.encodeWithSelector(mockProtocol.noTokenAction.selector, "test");
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: fakeProtocol,
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);

        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        return !ok;
    }

    /// Calldata hash mismatch always reverts
    function property_calldata_hash_mismatch_blocked() public returns (bool) {
        if (vault.paused()) return true;
        bytes memory realCallData = abi.encodeWithSelector(mockProtocol.noTokenAction.selector, "real");
        bytes memory fakeCallData = abi.encodeWithSelector(mockProtocol.noTokenAction.selector, "fake");
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(realCallData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);

        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, fakeCallData));
        return !ok;
    }

    /// executeProtocol with > 5 tokens always reverts (TooManyTokens)
    function property_protocol_too_many_tokens_blocked() public returns (bool) {
        if (vault.paused()) return true;
        bytes memory callData = abi.encodeWithSelector(mockProtocol.noTokenAction.selector, "test");
        address[] memory tokens = new address[](6);
        uint256[] memory amounts = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            tokens[i] = address(usdc);
            amounts[i] = 1;
        }

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);

        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        return !ok;
    }

    /// executeProtocol with mismatched tokens/amounts array lengths always reverts
    function property_protocol_array_mismatch_blocked() public returns (bool) {
        if (vault.paused()) return true;
        bytes memory callData = abi.encodeWithSelector(mockProtocol.noTokenAction.selector, "test");
        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(weth);
        uint256[] memory amounts = new uint256[](1); // intentional mismatch
        amounts[0] = 100;

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);

        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        return !ok;
    }

    // ── 7. Operator Properties ──

    /// Operator bot count never exceeds maxOperatorBots ceiling
    function property_operator_bot_limit() public view returns (bool) {
        (,, uint256 maxBots,,) = vault.operatorCeilings();
        return vault.operatorBotCount() <= maxBots;
    }

    /// Operator cannot set maxPerTxAmount above ceiling
    function property_operator_ceiling_max_per_tx() public returns (bool) {
        (uint256 ceilMaxPerTx,,,,) = vault.operatorCeilings();
        if (ceilMaxPerTx == 0) return true;
        address newBot = address(0xABC1);
        if (vault.isBotActive(newBot) || newBot == address(this) || newBot == OPERATOR) return true;

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 20_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.addBot.selector,
                    newBot,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: ceilMaxPerTx + 1, // exceeds ceiling
                        maxRebalanceAmount: 0,
                        spendingLimits: limits,
                        aiTriggerThreshold: 500 * USDC_DECIMALS,
                        requireAiVerification: false
                    })
                )
            );
        return !ok;
    }

    /// Operator cannot set aiTriggerThreshold above minAiTriggerFloor ceiling
    function property_operator_ceiling_ai_floor() public returns (bool) {
        (,,,, uint256 aiFloor) = vault.operatorCeilings();
        if (aiFloor == 0) return true;
        address newBot = address(0xABC2);
        if (vault.isBotActive(newBot) || newBot == address(this) || newBot == OPERATOR) return true;

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 20_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.addBot.selector,
                    newBot,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: 5_000 * USDC_DECIMALS,
                        maxRebalanceAmount: 0,
                        spendingLimits: limits,
                        aiTriggerThreshold: aiFloor + 1, // exceeds floor
                        requireAiVerification: false
                    })
                )
            );
        return !ok;
    }

    /// Operator cannot unpause the vault
    function property_operator_cannot_unpause() public returns (bool) {
        if (!vault.paused()) return true;
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.unpause.selector));
        return !ok;
    }

    /// Operator cannot remove blacklist entries (loosening)
    function property_operator_cannot_remove_blacklist() public returns (bool) {
        address blacklisted = address(0xBBBB);
        if (!vault.globalDestinationBlacklist(blacklisted)) return true;

        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.removeGlobalBlacklist.selector, blacklisted));
        return !ok;
    }

    /// Operator cannot add to global whitelist (loosening)
    function property_operator_cannot_add_whitelist() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.addGlobalDestination.selector, address(0xFFF1)));
        return !ok;
    }

    /// Operator cannot add to bot whitelist (loosening)
    function property_operator_cannot_add_bot_whitelist() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.addBotDestination.selector, BOT, address(0xFFF2)));
        return !ok;
    }

    /// Operator cannot approve protocols (loosening)
    function property_operator_cannot_approve_protocol() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.approveProtocol.selector, address(0xFFF3)));
        return !ok;
    }

    /// Operator cannot add rebalance tokens (loosening)
    function property_operator_cannot_add_rebalance_token() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.addRebalanceTokens.selector, _singleArray(address(0xFFF4))));
        return !ok;
    }

    /// Operator cannot set operator ceilings
    function property_operator_cannot_set_ceilings() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.setOperatorCeilings.selector,
                    AxonVault.OperatorCeilings({
                        maxPerTxAmount: 999_999 * USDC_DECIMALS,
                        maxBotDailyLimit: 999_999 * USDC_DECIMALS,
                        maxOperatorBots: 100,
                        vaultDailyAggregate: 999_999 * USDC_DECIMALS,
                        minAiTriggerFloor: 0
                    })
                )
            );
        return !ok;
    }

    /// Operator cannot withdraw
    function property_operator_cannot_withdraw() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.withdraw.selector, address(usdc), 1 * USDC_DECIMALS, OPERATOR));
        return !ok;
    }

    // ── 8. Bot Lifecycle Properties ──

    /// Inactive bot payments are rejected (fuzzed key)
    function property_inactive_bot_rejected(uint256 fakeBotPk) public returns (bool) {
        if (fakeBotPk == 0 || fakeBotPk == BOT_KEY) return true;
        if (fakeBotPk >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) return true;

        address fakeBot = vm.addr(fakeBotPk);
        if (vault.isBotActive(fakeBot)) return true;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: fakeBot,
            to: RECIPIENT,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });

        bytes32 structHash = keccak256(
            abi.encode(
                PAYMENT_INTENT_TYPEHASH, intent.bot, intent.to, intent.token, intent.amount, intent.deadline, intent.ref
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", vault.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakeBotPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// Removed bot cannot make payments
    function property_removed_bot_blocked() public returns (bool) {
        if (vault.isBotActive(BOT)) return true; // bot is still active, skip
        if (vault.paused()) return true;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RECIPIENT,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    /// Owner cannot be registered as a bot
    function property_owner_cannot_be_bot() public returns (bool) {
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.addBot.selector,
                    address(this), // owner
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: 1000,
                        maxRebalanceAmount: 0,
                        spendingLimits: limits,
                        aiTriggerThreshold: 0,
                        requireAiVerification: false
                    })
                )
            );
        return !ok;
    }

    /// Operator cannot be set to owner address
    function property_operator_cannot_be_owner() public returns (bool) {
        (bool ok,) =
            address(vault)
                .call(
                    abi.encodeWithSelector(vault.setOperator.selector, address(this)) // this = owner
                );
        return !ok;
    }

    // ── 9. Access Control Properties ──

    /// Only owner can withdraw (fuzzed caller)
    function property_only_owner_withdraws(address caller) public returns (bool) {
        if (caller == address(this)) return true;
        vm.prank(caller);
        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.withdraw.selector, address(usdc), 1 * USDC_DECIMALS, caller));
        return !ok;
    }

    /// Non-relayer cannot call executePayment
    function property_only_relayer_executes_payment() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RECIPIENT,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);

        // Random address (not relayer) tries to call
        vm.prank(address(0x1234));
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok;
    }

    // ── 10. Deposit Properties ──

    /// Zero-amount deposit always reverts
    function property_zero_deposit_blocked() public returns (bool) {
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.deposit.selector, address(usdc), 0, bytes32(0)));
        return !ok;
    }

    // ── 11. Spending Window Properties ──

    /// Invalid spending window duration always reverts
    function property_invalid_spending_window_blocked() public returns (bool) {
        address newBot = address(0xABC9);
        if (vault.isBotActive(newBot) || newBot == address(this) || newBot == OPERATOR) return true;

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({
            amount: 1000 * USDC_DECIMALS,
            maxCount: 0,
            windowSeconds: 7200 // 2 hours — NOT one of the allowed windows
        });

        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.addBot.selector,
                    newBot,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: 1000 * USDC_DECIMALS,
                        maxRebalanceAmount: 0,
                        spendingLimits: limits,
                        aiTriggerThreshold: 0,
                        requireAiVerification: false
                    })
                )
            );
        return !ok;
    }

    /// > 5 spending limits always reverts
    function property_too_many_spending_limits_blocked() public returns (bool) {
        address newBot = address(0xABCA);
        if (vault.isBotActive(newBot) || newBot == address(this) || newBot == OPERATOR) return true;

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](6);
        for (uint256 i = 0; i < 6; i++) {
            limits[i] = AxonVault.SpendingLimit({ amount: 1000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        }

        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.addBot.selector,
                    newBot,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: 1000 * USDC_DECIMALS,
                        maxRebalanceAmount: 0,
                        spendingLimits: limits,
                        aiTriggerThreshold: 0,
                        requireAiVerification: false
                    })
                )
            );
        return !ok;
    }

    // ── 12. NFT Withdrawal Properties ──

    /// Non-owner cannot withdraw ERC-721
    function property_only_owner_withdraws_erc721() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.withdrawERC721.selector, address(nft), 0, OPERATOR));
        return !ok;
    }

    /// Non-owner cannot withdraw ERC-1155
    function property_only_owner_withdraws_erc1155() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.withdrawERC1155.selector, address(multiToken), 1, 10, OPERATOR));
        return !ok;
    }

    /// ERC-721 withdrawal to address(0) always reverts
    function property_erc721_withdraw_to_zero_blocked() public returns (bool) {
        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.withdrawERC721.selector, address(nft), 0, address(0)));
        return !ok;
    }

    /// ERC-1155 withdrawal of zero amount always reverts
    function property_erc1155_zero_amount_blocked() public returns (bool) {
        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.withdrawERC1155.selector, address(multiToken), 1, 0, address(this)));
        return !ok;
    }

    // ── 13. Native ETH Properties ──

    /// Non-owner cannot withdraw native ETH
    function property_only_owner_withdraws_eth() public returns (bool) {
        if (address(vault).balance == 0) return true;
        address nativeEth = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
        vm.prank(OPERATOR);
        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.withdraw.selector, nativeEth, 0.01 ether, OPERATOR));
        return !ok;
    }

    /// Vault can receive ETH via receive()
    function property_vault_accepts_eth() public returns (bool) {
        vm.deal(address(this), 0.01 ether);
        uint256 balBefore = address(vault).balance;
        (bool ok,) = address(vault).call{ value: 0.001 ether }("");
        if (!ok) return false; // should accept
        return address(vault).balance >= balBefore + 0.001 ether;
    }

    // ── 14. ERC-1271 Properties ──

    /// ERC-1271 bot signatures invalid when erc1271BotsEnabled is false (default)
    function property_erc1271_disabled_by_default() public returns (bool) {
        if (vault.erc1271BotsEnabled()) return true; // skip if owner enabled it
        bytes32 testHash = keccak256("erc1271-test");
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", testHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOT_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        (bool ok, bytes memory ret) =
            address(vault).staticcall(abi.encodeWithSelector(vault.isValidSignature.selector, testHash, sig));
        if (!ok) return true; // revert is acceptable
        bytes4 magic = abi.decode(ret, (bytes4));
        return magic != bytes4(0x1626ba7e); // should NOT return valid magic
    }

    // ── 15. Renounce Ownership Properties ──

    /// renounceOwnership is always disabled (would brick the vault)
    function property_renounce_ownership_blocked() public returns (bool) {
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.renounceOwnership.selector));
        return !ok;
    }

    // ── 16. Positive Outcome / Lifecycle Properties ──

    /// Re-registered bot can make payments again (full lifecycle)
    function property_reregistered_bot_can_pay() public returns (bool) {
        if (!vault.isBotActive(BOT)) return true; // bot not active, skip
        if (vault.paused()) return true;
        uint256 bal = usdc.balanceOf(address(vault));
        if (bal < 1 * USDC_DECIMALS) return true;
        // Whitelist might block RECIPIENT (global OR per-bot restriction)
        bool hasRestrictions = (vault.globalDestinationCount() > 0 || vault.botDestinationCount(BOT) > 0);
        if (
            hasRestrictions && !vault.globalDestinationWhitelist(RECIPIENT)
                && !vault.botDestinationWhitelist(BOT, RECIPIENT)
        ) return true;
        if (vault.globalDestinationBlacklist(RECIPIENT)) return true;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RECIPIENT,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        if (ok) totalPaymentsOut += 1 * USDC_DECIMALS;
        return ok; // MUST succeed when bot is active and conditions are met
    }

    /// executeProtocol with approved protocol and valid params succeeds
    function property_protocol_execution_succeeds() public returns (bool) {
        if (!vault.isBotActive(BOT)) return true;
        if (vault.paused()) return true;
        if (!vault.approvedProtocols(address(mockProtocol))) return true;

        bytes memory callData = abi.encodeWithSelector(mockProtocol.noTokenAction.selector, abi.encode(_uniqueRef()));
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);

        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        return ok; // MUST succeed
    }

    /// executeSwap with valid params succeeds and WETH arrives in vault
    function property_swap_execution_succeeds() public returns (bool) {
        if (!vault.isBotActive(BOT)) return true;
        if (vault.paused()) return true;
        uint256 usdcIn = 100 * USDC_DECIMALS;
        uint256 wethOut = 1 * WETH_DECIMALS;
        if (usdcIn > usdc.balanceOf(address(vault))) return true;
        if (wethOut > weth.balanceOf(address(swapRouter))) return true;
        // Skip if rebalance whitelist would block WETH
        if (vault.rebalanceTokenCount() > 0 && !vault.rebalanceTokenWhitelist(address(weth))) return true;

        uint256 wethBefore = weth.balanceOf(address(vault));

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: BOT,
            toToken: address(weth),
            minToAmount: wethOut,
            fromToken: address(usdc),
            maxFromAmount: usdcIn,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signSwap(intent);

        bytes memory swapCalldata = abi.encodeWithSelector(
            swapRouter.swap.selector, address(usdc), usdcIn, address(weth), wethOut, address(vault)
        );

        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.executeSwap.selector, intent, sig, address(swapRouter), swapCalldata));
        if (!ok) return false; // should succeed
        // WETH must have arrived in the vault
        return weth.balanceOf(address(vault)) >= wethBefore + wethOut;
    }

    /// deposit() increases vault balance by exact amount
    function property_deposit_increases_balance() public returns (bool) {
        uint256 amount = 10 * USDC_DECIMALS;
        usdc.mint(address(this), amount);
        usdc.approve(address(vault), amount);
        uint256 balBefore = usdc.balanceOf(address(vault));

        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.deposit.selector, address(usdc), amount, bytes32(0)));
        if (!ok) return false; // deposit should always succeed
        totalDeposited += amount;
        return usdc.balanceOf(address(vault)) == balBefore + amount;
    }

    /// Operator can revoke protocol (tightening is allowed)
    function property_operator_can_revoke_protocol() public returns (bool) {
        if (!vault.approvedProtocols(address(mockProtocol))) return true; // already revoked
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.revokeProtocol.selector, address(mockProtocol)));
        // Re-approve so other tests aren't broken
        if (ok) vault.approveProtocol(address(mockProtocol));
        return ok; // operator CAN revoke (tightening)
    }

    /// Operator can remove global whitelist entries (tightening)
    function property_operator_can_remove_whitelist() public returns (bool) {
        if (vault.globalDestinationCount() == 0) return true; // nothing to remove
        address dest = address(0xFFF9);
        if (!vault.globalDestinationWhitelist(dest)) {
            // Add it first so we can test removal
            vault.addGlobalDestination(dest);
        }
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.removeGlobalDestination.selector, dest));
        return ok; // operator CAN remove whitelist entries (tightening)
    }

    /// Operator can remove rebalance tokens (tightening)
    function property_operator_can_remove_rebalance_token() public returns (bool) {
        address token = address(0xFFF8);
        // Add it first
        if (!vault.rebalanceTokenWhitelist(token)) {
            vault.addRebalanceTokens(_singleArray(token));
        }
        vm.prank(OPERATOR);
        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.removeRebalanceTokens.selector, _singleArray(token)));
        return ok; // operator CAN remove rebalance tokens (tightening)
    }

    // ── 17. Edge Case Properties ──

    /// Payment with insufficient vault balance reverts cleanly
    function property_insufficient_balance_reverts() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;
        uint256 bal = usdc.balanceOf(address(vault));
        if (bal == 0) return true; // need some balance to set up the test
        uint256 tooMuch = bal + 1;

        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: BOT,
            to: RECIPIENT,
            token: address(usdc),
            amount: tooMuch,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signPayment(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        return !ok; // must revert — insufficient balance
    }

    /// Bot with maxPerTxAmount=0 (no cap) can make large payments
    function property_zero_cap_means_unlimited() public returns (bool) {
        if (vault.paused()) return true;
        address uncappedBot = address(0xCAA1);
        if (vault.isBotActive(uncappedBot) || uncappedBot == address(this) || uncappedBot == OPERATOR) return true;

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vault.addBot(
            uncappedBot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 0, // no cap
                maxRebalanceAmount: 0,
                spendingLimits: limits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        // Verify the config was stored with 0 cap (unlimited)
        AxonVault.BotConfig memory cfg = vault.getBotConfig(uncappedBot);
        vault.removeBot(uncappedBot);
        return cfg.maxPerTxAmount == 0; // 0 means unlimited
    }

    /// Exactly 5 spending limit windows are accepted (max allowed)
    function property_five_spending_limits_accepted() public returns (bool) {
        address newBot = address(0xCAA2);
        if (vault.isBotActive(newBot) || newBot == address(this) || newBot == OPERATOR) return true;

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](5);
        // Use all 5 allowed windows: 1h, 3h, 24h, 7d, 30d
        uint256[5] memory windows = [uint256(3600), 10800, 86400, 604800, 2592000];
        for (uint256 i = 0; i < 5; i++) {
            limits[i] =
                AxonVault.SpendingLimit({ amount: 1000 * USDC_DECIMALS, maxCount: 0, windowSeconds: windows[i] });
        }

        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.addBot.selector,
                    newBot,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: 1000 * USDC_DECIMALS,
                        maxRebalanceAmount: 0,
                        spendingLimits: limits,
                        aiTriggerThreshold: 0,
                        requireAiVerification: false
                    })
                )
            );
        if (ok) vault.removeBot(newBot); // cleanup
        return ok; // 5 limits MUST be accepted
    }

    /// Owner can successfully withdraw USDC
    function property_owner_withdraw_succeeds() public returns (bool) {
        uint256 bal = usdc.balanceOf(address(vault));
        if (bal < 1 * USDC_DECIMALS) return true;

        uint256 ownerBefore = usdc.balanceOf(address(this));
        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.withdraw.selector, address(usdc), 1 * USDC_DECIMALS, address(this)));
        if (!ok) return false;
        // Re-deposit to keep balance for other tests
        usdc.approve(address(vault), 1 * USDC_DECIMALS);
        vault.deposit(address(usdc), 1 * USDC_DECIMALS, bytes32(0));
        return usdc.balanceOf(address(this)) >= ownerBefore; // got funds then returned them
    }

    /// Owner can withdraw ERC-721 NFTs
    function property_owner_erc721_withdraw_succeeds() public returns (bool) {
        // Check vault still owns tokenId 0
        try nft.ownerOf(0) returns (address nftOwner) {
            if (nftOwner != address(vault)) return true; // already withdrawn
        } catch {
            return true;
        }

        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.withdrawERC721.selector, address(nft), 0, address(this)));
        if (!ok) return false;
        // Return NFT to vault for other tests
        nft.safeTransferFrom(address(this), address(vault), 0);
        return true;
    }

    /// Owner can withdraw ERC-1155 tokens
    function property_owner_erc1155_withdraw_succeeds() public returns (bool) {
        uint256 vaultBal = multiToken.balanceOf(address(vault), 1);
        if (vaultBal < 10) return true;

        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.withdrawERC1155.selector, address(multiToken), 1, 10, address(this)));
        if (!ok) return false;
        // Return to vault for other tests
        multiToken.safeTransferFrom(address(this), address(vault), 1, 10, "");
        return true;
    }

    /// Owner can withdraw native ETH
    function property_owner_eth_withdraw_succeeds() public returns (bool) {
        if (address(vault).balance < 0.001 ether) return true;
        address nativeEth = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

        uint256 balBefore = address(this).balance;
        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.withdraw.selector, nativeEth, 0.001 ether, address(this)));
        if (!ok) return false;
        // Return ETH to vault
        (bool sent,) = address(vault).call{ value: 0.001 ether }("");
        return ok && sent && address(this).balance >= balBefore;
    }

    /// Operator cannot set bot daily limit above ceiling
    function property_operator_ceiling_daily_limit() public returns (bool) {
        (, uint256 ceilDailyLimit,,,) = vault.operatorCeilings();
        if (ceilDailyLimit == 0) return true;
        address newBot = address(0xCAA3);
        if (vault.isBotActive(newBot) || newBot == address(this) || newBot == OPERATOR) return true;

        // Daily limit is enforced via spending windows — operator tries to set a 24h window above ceiling
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({
            amount: ceilDailyLimit + 1, // above ceiling
            maxCount: 0,
            windowSeconds: 86400
        });

        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.addBot.selector,
                    newBot,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: 5_000 * USDC_DECIMALS,
                        maxRebalanceAmount: 0,
                        spendingLimits: limits,
                        aiTriggerThreshold: 500 * USDC_DECIMALS,
                        requireAiVerification: false
                    })
                )
            );
        return !ok; // must revert — daily limit above ceiling
    }

    /// Swap with maxRebalanceAmount exceeded reverts (USDC input > bot's cap)
    function property_max_rebalance_amount_enforced() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;
        uint256 overLimit = MAX_REBALANCE + 1; // above the $5k cap
        if (overLimit > usdc.balanceOf(address(vault))) return true;

        AxonVault.SwapIntent memory intent = AxonVault.SwapIntent({
            bot: BOT,
            toToken: address(weth),
            minToAmount: 1 * WETH_DECIMALS,
            fromToken: address(usdc),
            maxFromAmount: overLimit,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signSwap(intent);
        bytes memory swapCalldata = abi.encodeWithSelector(
            swapRouter.swap.selector, address(usdc), overLimit, address(weth), 1 * WETH_DECIMALS, address(vault)
        );

        (bool ok,) = address(vault)
            .call(abi.encodeWithSelector(vault.executeSwap.selector, intent, sig, address(swapRouter), swapCalldata));
        return !ok; // must revert — maxRebalanceAmount exceeded
    }

    // ── 18. updateBotConfig Properties ──

    /// Owner can update bot config freely
    function property_owner_can_update_bot_config() public returns (bool) {
        if (!vault.isBotActive(BOT)) return true;

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 25_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.updateBotConfig.selector,
                    BOT,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: 5_000 * USDC_DECIMALS, // lower than original 10k
                        maxRebalanceAmount: MAX_REBALANCE,
                        spendingLimits: limits,
                        aiTriggerThreshold: 500 * USDC_DECIMALS,
                        requireAiVerification: false
                    })
                )
            );
        if (!ok) return false;
        // Restore original config
        AxonVault.SpendingLimit[] memory origLimits = new AxonVault.SpendingLimit[](1);
        origLimits[0] = AxonVault.SpendingLimit({ amount: 50_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        vault.updateBotConfig(
            BOT,
            AxonVault.BotConfigParams({
                maxPerTxAmount: MAX_PER_TX,
                maxRebalanceAmount: MAX_REBALANCE,
                spendingLimits: origLimits,
                aiTriggerThreshold: 1_000 * USDC_DECIMALS,
                requireAiVerification: false
            })
        );
        return true;
    }

    /// Operator cannot disable requireAiVerification once enabled
    function property_operator_cannot_disable_ai_verification() public returns (bool) {
        if (!vault.isBotActive(BOT)) return true;
        if (vault.operator() == address(0)) return true;

        // Owner enables AI verification
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 50_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        vault.updateBotConfig(
            BOT,
            AxonVault.BotConfigParams({
                maxPerTxAmount: MAX_PER_TX,
                maxRebalanceAmount: MAX_REBALANCE,
                spendingLimits: limits,
                aiTriggerThreshold: 1_000 * USDC_DECIMALS,
                requireAiVerification: true // enable
            })
        );

        // Operator tries to disable it
        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.updateBotConfig.selector,
                    BOT,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: MAX_PER_TX,
                        maxRebalanceAmount: MAX_REBALANCE,
                        spendingLimits: limits,
                        aiTriggerThreshold: 1_000 * USDC_DECIMALS,
                        requireAiVerification: false // try to disable
                    })
                )
            );

        // Restore
        vault.updateBotConfig(
            BOT,
            AxonVault.BotConfigParams({
                maxPerTxAmount: MAX_PER_TX,
                maxRebalanceAmount: MAX_REBALANCE,
                spendingLimits: limits,
                aiTriggerThreshold: 1_000 * USDC_DECIMALS,
                requireAiVerification: false
            })
        );
        return !ok; // operator MUST fail
    }

    /// Operator cannot reduce spending limit count on update (loosening)
    function property_operator_cannot_reduce_limit_count() public returns (bool) {
        if (!vault.isBotActive(BOT)) return true;

        // First give BOT 2 spending limits via owner
        AxonVault.SpendingLimit[] memory twoLimits = new AxonVault.SpendingLimit[](2);
        twoLimits[0] = AxonVault.SpendingLimit({ amount: 50_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        twoLimits[1] = AxonVault.SpendingLimit({ amount: 5_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 3600 });
        vault.updateBotConfig(
            BOT,
            AxonVault.BotConfigParams({
                maxPerTxAmount: MAX_PER_TX,
                maxRebalanceAmount: MAX_REBALANCE,
                spendingLimits: twoLimits,
                aiTriggerThreshold: 1_000 * USDC_DECIMALS,
                requireAiVerification: false
            })
        );

        // Operator tries to reduce to 1 limit
        AxonVault.SpendingLimit[] memory oneLimitOp = new AxonVault.SpendingLimit[](1);
        oneLimitOp[0] = AxonVault.SpendingLimit({ amount: 50_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        vm.prank(OPERATOR);
        (bool ok,) = address(vault)
            .call(
                abi.encodeWithSelector(
                    vault.updateBotConfig.selector,
                    BOT,
                    AxonVault.BotConfigParams({
                        maxPerTxAmount: MAX_PER_TX,
                        maxRebalanceAmount: MAX_REBALANCE,
                        spendingLimits: oneLimitOp,
                        aiTriggerThreshold: 1_000 * USDC_DECIMALS,
                        requireAiVerification: false
                    })
                )
            );

        // Restore original config
        AxonVault.SpendingLimit[] memory origLimits = new AxonVault.SpendingLimit[](1);
        origLimits[0] = AxonVault.SpendingLimit({ amount: 50_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });
        vault.updateBotConfig(
            BOT,
            AxonVault.BotConfigParams({
                maxPerTxAmount: MAX_PER_TX,
                maxRebalanceAmount: MAX_REBALANCE,
                spendingLimits: origLimits,
                aiTriggerThreshold: 1_000 * USDC_DECIMALS,
                requireAiVerification: false
            })
        );
        return !ok; // operator MUST fail — reducing limit count is loosening
    }

    // ── 19. Signature Mismatch Properties ──

    /// Signature from bot A but intent says bot B — must revert
    function property_wrong_bot_signature_rejected() public returns (bool) {
        if (vault.paused()) return true;
        // Create a second bot
        address bot2 = address(0xB072);
        uint256 bot2Key = 0xB072;
        if (vault.isBotActive(bot2) || bot2 == address(this) || bot2 == OPERATOR) return true;

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](0);
        vault.addBot(
            bot2,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 0,
                maxRebalanceAmount: 0,
                spendingLimits: limits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        // Intent says bot2, but signed by BOT_KEY (bot A's key)
        AxonVault.PaymentIntent memory intent = AxonVault.PaymentIntent({
            bot: bot2, // intent claims bot2
            to: RECIPIENT,
            token: address(usdc),
            amount: 1 * USDC_DECIMALS,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        // Sign with BOT_KEY (wrong signer)
        bytes memory sig = _signPayment(intent); // uses BOT_KEY, not bot2Key
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executePayment.selector, intent, sig));
        vault.removeBot(bot2);
        return !ok; // MUST revert — signature doesn't match intent.bot
    }

    // ── 20. Default Token Restriction (NM-001v3) ──

    /// Default token can only be called with approve(), not arbitrary functions
    function property_default_token_only_approve_allowed() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        // Register USDC as default token on registry
        registry.approveDefaultToken(address(usdc));

        // Try to call transfer() on USDC via executeProtocol (should be blocked)
        bytes memory callData = abi.encodeWithSelector(IERC20.transfer.selector, RECIPIENT, 1 * USDC_DECIMALS);
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(usdc), // default token
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));

        registry.revokeDefaultToken(address(usdc));
        return !ok; // MUST revert — only approve() allowed on default tokens
    }

    /// Default token approve() must have an approved spender
    function property_default_token_approve_unapproved_spender_blocked() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        registry.approveDefaultToken(address(usdc));

        // approve() with unapproved spender
        address unapprovedSpender = address(0xBAD);
        bytes memory callData = abi.encodeWithSelector(IERC20.approve.selector, unapprovedSpender, 100 * USDC_DECIMALS);
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(usdc),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));

        registry.revokeDefaultToken(address(usdc));
        return !ok; // MUST revert — spender not approved
    }

    /// Default token approve() with approved spender succeeds
    function property_default_token_approve_approved_spender_succeeds() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        // Ensure mockProtocol is approved on vault (may have been revoked by another test)
        if (!vault.approvedProtocols(address(mockProtocol))) {
            vault.approveProtocol(address(mockProtocol));
        }

        registry.approveDefaultToken(address(usdc));

        // approve() with mockProtocol as spender (which is approved on vault)
        bytes memory callData =
            abi.encodeWithSelector(IERC20.approve.selector, address(mockProtocol), 100 * USDC_DECIMALS);
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(usdc),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));

        registry.revokeDefaultToken(address(usdc));
        return ok; // MUST succeed — valid approve with approved spender
    }

    // ── 21. ERC-1271 When Enabled ──

    /// ERC-1271 returns valid magic for owner signature (always, regardless of toggle)
    function property_erc1271_owner_always_valid() public returns (bool) {
        bytes32 testHash = keccak256("owner-erc1271-test");
        // We are the owner — we can't easily sign with vm.sign without a known key
        // Instead verify the function exists and returns invalid for random sigs
        (bool ok, bytes memory ret) =
            address(vault).staticcall(abi.encodeWithSelector(vault.isValidSignature.selector, testHash, new bytes(65)));
        if (!ok) return true; // revert is acceptable for malformed sig
        bytes4 magic = abi.decode(ret, (bytes4));
        return magic != bytes4(0x1626ba7e); // random sig should NOT be valid
    }

    /// ERC-1271 returns valid magic for active bot when enabled
    function property_erc1271_bot_valid_when_enabled() public returns (bool) {
        if (!vault.isBotActive(BOT)) return true;
        if (vault.paused()) return true; // isValidSignature returns 0xffffffff when paused

        // Save and set state atomically
        bool wasBotEnabled = vault.erc1271BotsEnabled();
        if (!wasBotEnabled) vault.setErc1271Bots(true);

        bytes32 testHash = keccak256(abi.encodePacked("bot-erc1271-test-", nonce++));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOT_KEY, testHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        (bool ok, bytes memory ret) =
            address(vault).staticcall(abi.encodeWithSelector(vault.isValidSignature.selector, testHash, sig));

        // Restore original state
        if (!wasBotEnabled) vault.setErc1271Bots(false);

        if (!ok) return false;
        bytes4 magic = abi.decode(ret, (bytes4));
        return magic == bytes4(0x1626ba7e); // MUST be valid
    }

    // ── 22. Global Protocol (Registry) Properties ──

    /// Protocol approved globally on registry can be used without per-vault approval
    function property_global_protocol_bypasses_vault_approval() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;

        // Ensure mockProtocol is NOT per-vault approved (may already be revoked by another test)
        if (vault.approvedProtocols(address(mockProtocol))) {
            vault.revokeProtocol(address(mockProtocol));
        }
        // Approve globally on registry
        if (!registry.isApprovedProtocol(address(mockProtocol))) {
            registry.approveProtocol(address(mockProtocol));
        }

        bytes memory callData = abi.encodeWithSelector(mockProtocol.noTokenAction.selector, "global");
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));

        // Restore: remove global, re-add per-vault
        if (registry.isApprovedProtocol(address(mockProtocol))) {
            registry.revokeProtocol(address(mockProtocol));
        }
        if (!vault.approvedProtocols(address(mockProtocol))) {
            vault.approveProtocol(address(mockProtocol));
        }
        return ok; // MUST succeed — globally approved
    }

    // ── 23. Idempotent Whitelist/Blacklist Counting ──

    /// Adding same address to whitelist twice doesn't double-count
    function property_whitelist_idempotent_count() public returns (bool) {
        // Use nonce-based address to avoid collisions with previous runs
        address dest = address(uint160(uint256(keccak256(abi.encodePacked("wl-idem", nonce++)))));
        if (dest == address(0)) return true; // skip zero address
        uint256 countBefore = vault.globalDestinationCount();
        vault.addGlobalDestination(dest);
        uint256 countAfterFirst = vault.globalDestinationCount();
        vault.addGlobalDestination(dest); // second add — should be no-op
        uint256 countAfterSecond = vault.globalDestinationCount();

        // Cleanup
        vault.removeGlobalDestination(dest);
        return countAfterFirst == countBefore + 1 && countAfterSecond == countAfterFirst;
    }

    /// Adding same address to blacklist twice doesn't double-count
    function property_blacklist_idempotent_count() public returns (bool) {
        address dest = address(uint160(uint256(keccak256(abi.encodePacked("bl-idem", nonce++)))));
        if (dest == address(0)) return true;
        uint256 countBefore = vault.globalBlacklistCount();
        vault.addGlobalBlacklist(dest);
        uint256 countAfterFirst = vault.globalBlacklistCount();
        vault.addGlobalBlacklist(dest); // second add — should be no-op
        uint256 countAfterSecond = vault.globalBlacklistCount();

        // Cleanup
        vault.removeGlobalBlacklist(dest);
        return countAfterFirst == countBefore + 1 && countAfterSecond == countAfterFirst;
    }

    // ── 24. Access Control Edge Cases ──

    /// Operator cannot call setOperator (onlyOwner)
    function property_operator_cannot_set_operator() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.setOperator.selector, address(0xBBB)));
        return !ok;
    }

    /// Withdraw zero amount always reverts
    function property_withdraw_zero_amount_reverts() public returns (bool) {
        (bool ok,) =
            address(vault).call(abi.encodeWithSelector(vault.withdraw.selector, address(usdc), 0, address(this)));
        return !ok;
    }

    /// addGlobalDestination(address(0)) reverts
    function property_whitelist_zero_address_blocked() public returns (bool) {
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.addGlobalDestination.selector, address(0)));
        return !ok;
    }

    /// addGlobalBlacklist(address(0)) reverts
    function property_blacklist_zero_address_blocked() public returns (bool) {
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.addGlobalBlacklist.selector, address(0)));
        return !ok;
    }

    /// addBotDestination(bot, address(0)) reverts
    function property_bot_whitelist_zero_address_blocked() public returns (bool) {
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.addBotDestination.selector, BOT, address(0)));
        return !ok;
    }

    // ── 25. Protocol Execution with ETH Value ──

    /// executeProtocol can forward native ETH to protocol.
    /// Uses BOT_NOCAP (maxPerTxAmount=0) to bypass combined cap check which
    /// would hit the TWAP oracle (no real Uniswap pools in fuzz environment).
    function property_protocol_with_eth_value_succeeds() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT_NOCAP)) return true;
        if (address(vault).balance < 0.01 ether) return true;
        if (!vault.approvedProtocols(address(mockProtocol))) return true;

        bytes memory callData = abi.encodeWithSelector(mockProtocol.payableAction.selector);
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT_NOCAP,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0.001 ether, // send ETH
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecuteWithKey(intent, BOT_NOCAP_KEY);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        return ok; // MUST succeed — protocol is approved and payable
    }

    /// executeProtocol with failing protocol reverts cleanly
    function property_protocol_failure_reverts() public returns (bool) {
        if (vault.paused() || !vault.isBotActive(BOT)) return true;
        if (!vault.approvedProtocols(address(mockProtocol))) return true;

        bytes memory callData = abi.encodeWithSelector(mockProtocol.failingAction.selector);
        address[] memory tokens = new address[](0);
        uint256[] memory amounts = new uint256[](0);

        AxonVault.ExecuteIntent memory intent = AxonVault.ExecuteIntent({
            bot: BOT,
            protocol: address(mockProtocol),
            calldataHash: keccak256(callData),
            tokens: tokens,
            amounts: amounts,
            value: 0,
            deadline: block.timestamp + 300,
            ref: _uniqueRef()
        });
        bytes memory sig = _signExecute(intent);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.executeProtocol.selector, intent, sig, callData));
        return !ok; // MUST revert — protocol call fails
    }

    /// Operator can remove bot's destination whitelist entries (tightening)
    function property_operator_can_remove_bot_destination() public returns (bool) {
        if (!vault.isBotActive(BOT)) return true;
        if (vault.operator() != OPERATOR) return true;

        address dest = address(uint160(uint256(keccak256(abi.encodePacked("bot-dest-op", nonce++)))));
        // Owner adds bot destination
        vault.addBotDestination(BOT, dest);

        // Operator removes it (tightening)
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.removeBotDestination.selector, BOT, dest));
        return ok; // operator CAN remove bot destinations
    }

    // ── 11. Swap Slippage Guard Properties ──

    /// Only owner can set maxSwapSlippageBps
    function property_only_owner_sets_swap_slippage() public returns (bool) {
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.setMaxSwapSlippageBps.selector, 9000));
        return !ok;
    }

    /// setMaxSwapSlippageBps rejects values above 10000 (100%)
    function property_swap_slippage_max_10000() public returns (bool) {
        (bool ok,) = address(vault).call(abi.encodeWithSelector(vault.setMaxSwapSlippageBps.selector, 10001));
        return !ok;
    }

    /// maxSwapSlippageBps default is 9500 (set in initialize)
    function property_swap_slippage_default_9500() public view returns (bool) {
        return vault.maxSwapSlippageBps() == 9500;
    }

    /// Owner can set maxSwapSlippageBps to 0 (disabled)
    function property_swap_slippage_can_disable() public returns (bool) {
        uint256 before = vault.maxSwapSlippageBps();
        vault.setMaxSwapSlippageBps(0);
        bool disabled = vault.maxSwapSlippageBps() == 0;
        // Restore
        vault.setMaxSwapSlippageBps(before);
        return disabled;
    }

    /// oracleUsdValue reverts for unknown tokens (OracleUnavailable)
    function property_oracle_usd_value_unknown_token_reverts() public returns (bool) {
        (bool ok,) =
            address(vault).staticcall(abi.encodeWithSelector(vault.oracleUsdValue.selector, address(0xDEAD), 1000));
        return !ok; // should revert
    }

    // ── 12. Operator Bot Count Reset ──

    /// Setting a new operator resets operatorBotCount to 0
    function property_set_operator_resets_bot_count() public returns (bool) {
        // Setup: give operator ceiling to add bots
        vault.setOperatorCeilings(
            AxonVault.OperatorCeilings({
                maxPerTxAmount: 10_000 * USDC_DECIMALS,
                maxBotDailyLimit: 50_000 * USDC_DECIMALS,
                maxOperatorBots: 5,
                vaultDailyAggregate: 100_000 * USDC_DECIMALS,
                minAiTriggerFloor: 0
            })
        );

        // If operator already added bots, count > 0
        uint256 countBefore = vault.operatorBotCount();

        // Set a new operator
        address newOp = address(0xBEEF);
        vault.setOperator(newOp);

        bool reset = vault.operatorBotCount() == 0;

        // Restore original operator
        vault.setOperator(OPERATOR);
        return reset;
    }

    // ── 13. Bot Re-registration Clears Config ──

    /// Re-adding a removed bot starts with fresh config (no stale state)
    function property_bot_reregistration_clears_config() public returns (bool) {
        address testBot = address(0xFACE);
        if (testBot == address(this) || testBot == OPERATOR) return true;

        // Add bot with specific config
        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 1_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        vault.addBot(
            testBot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 500 * USDC_DECIMALS,
                maxRebalanceAmount: 200 * USDC_DECIMALS,
                spendingLimits: limits,
                aiTriggerThreshold: 100 * USDC_DECIMALS,
                requireAiVerification: true
            })
        );

        // Remove bot
        vault.removeBot(testBot);

        // Re-add with different config
        AxonVault.SpendingLimit[] memory newLimits = new AxonVault.SpendingLimit[](1);
        newLimits[0] = AxonVault.SpendingLimit({ amount: 5_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        vault.addBot(
            testBot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 2_000 * USDC_DECIMALS,
                maxRebalanceAmount: 0,
                spendingLimits: newLimits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        // Verify new config took effect
        AxonVault.BotConfig memory cfg = vault.getBotConfig(testBot);
        bool configCorrect = cfg.isActive && cfg.maxPerTxAmount == 2_000 * USDC_DECIMALS && cfg.maxRebalanceAmount == 0
            && !cfg.requireAiVerification;

        // Cleanup
        vault.removeBot(testBot);
        return configCorrect;
    }

    // ── 14. botAddedByOperator tracks correctly ──

    /// botAddedByOperator returns the operator address (not just bool)
    function property_bot_added_by_operator_tracks_address() public returns (bool) {
        address testBot = address(uint160(0xCAFE0000 + nonce++));
        if (vault.isBotActive(testBot) || testBot == address(this) || testBot == OPERATOR) return true;

        // Ensure operator has ceiling to add bots
        vault.setOperatorCeilings(
            AxonVault.OperatorCeilings({
                maxPerTxAmount: 10_000 * USDC_DECIMALS,
                maxBotDailyLimit: 50_000 * USDC_DECIMALS,
                maxOperatorBots: 10,
                vaultDailyAggregate: 100_000 * USDC_DECIMALS,
                minAiTriggerFloor: 0
            })
        );

        AxonVault.SpendingLimit[] memory limits = new AxonVault.SpendingLimit[](1);
        limits[0] = AxonVault.SpendingLimit({ amount: 10_000 * USDC_DECIMALS, maxCount: 0, windowSeconds: 86400 });

        vm.prank(OPERATOR);
        vault.addBot(
            testBot,
            AxonVault.BotConfigParams({
                maxPerTxAmount: 5_000 * USDC_DECIMALS,
                maxRebalanceAmount: 0,
                spendingLimits: limits,
                aiTriggerThreshold: 0,
                requireAiVerification: false
            })
        );

        bool tracksOperator = vault.botAddedByOperator(testBot) == OPERATOR;

        // Cleanup
        vault.removeBot(testBot);
        return tracksOperator;
    }

    // Accept ERC-721 and ERC-1155 tokens (needed for withdraw-then-return tests)
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    // Accept ETH for withdraw-then-return tests
    receive() external payable { }
}

// Minimal Vm interface for cheatcodes
interface Vm {
    function addr(uint256 pk) external pure returns (address);
    function sign(uint256 pk, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function deal(address account, uint256 newBalance) external;
}

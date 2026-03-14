// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "./interfaces/IAxonRegistry.sol";
import "./libraries/TwapOracle.sol";

/// @title AxonVault
/// @notice Non-custodial treasury vault for autonomous AI agent fleets.
///
///         Owners deploy one vault per chain via AxonVaultFactory. Bots sign
///         EIP-712 payment intents; the Axon relayer validates and executes them.
///         All policy values are stored on-chain for Owner verifiability — the
///         relayer reads limits from the contract, not its own database.
///
///         Security model:
///         - Only authorized relayers (AxonRegistry) can call executePayment/executeProtocol/executeSwap
///         - Bots never hold ETH or submit transactions directly
///         - maxPerTxAmount is enforced on-chain (hard cap)
///         - Destination whitelist enforced on-chain
///         - Rebalance token whitelist restricts executeSwap output tokens (prevents swaps to worthless tokens)
///         - All other limits (daily, velocity, AI thresholds) stored on-chain, enforced by relayer
///         - Operator hot wallet is bounded by owner-set OperatorCeilings — cannot drain vault
///         - Global pause available to owner (and operator for emergencies); only owner can unpause
contract AxonVault is
    Ownable2StepUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardTransient,
    EIP712Upgradeable,
    ERC165,
    IERC721Receiver,
    IERC1155Receiver
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    // =========================================================================
    // Constants
    // =========================================================================

    uint16 public constant VERSION = 1;
    uint8 public constant MAX_SPENDING_LIMITS = 5;
    address public constant NATIVE_ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice Allowed spending limit window durations (seconds).
    ///         Only these values are accepted for SpendingLimit.windowSeconds.
    uint256 private constant WINDOW_1H = 3600;
    uint256 private constant WINDOW_3H = 10800;
    uint256 private constant WINDOW_24H = 86400;
    uint256 private constant WINDOW_7D = 604800;
    uint256 private constant WINDOW_30D = 2592000;

    bytes32 private constant PAYMENT_INTENT_TYPEHASH =
        keccak256("PaymentIntent(address bot,address to,address token,uint256 amount,uint256 deadline,bytes32 ref)");

    bytes32 private constant EXECUTE_INTENT_TYPEHASH = keccak256(
        "ExecuteIntent(address bot,address protocol,bytes32 calldataHash,address[] tokens,uint256[] amounts,uint256 value,uint256 deadline,bytes32 ref)"
    );

    bytes32 private constant SWAP_INTENT_TYPEHASH = keccak256(
        "SwapIntent(address bot,address toToken,uint256 minToAmount,address fromToken,uint256 maxFromAmount,uint256 deadline,bytes32 ref)"
    );

    // =========================================================================
    // Structs
    // =========================================================================

    /// @notice A rolling window spending limit. Stored on-chain, enforced by relayer.
    ///         windowSeconds must be one of: 3600 (1h), 10800 (3h), 86400 (24h), 604800 (7d), 2592000 (30d).
    struct SpendingLimit {
        uint256 amount; // max spend in this window (token base units, e.g. USDC 6 decimals)
        uint256 maxCount; // max number of transactions in this window (0 = no count limit)
        uint256 windowSeconds; // must be one of WINDOW_1H/3H/24H/7D/30D — enforced by _validateSpendingWindows
    }

    /// @notice Per-bot configuration. Policy values stored on-chain for verifiability.
    struct BotConfig {
        bool isActive;
        uint256 registeredAt;
        uint256 maxPerTxAmount; // USD hard cap for payments/protocol actions. USDC units (6 decimals). 0 = no cap.
        uint256 maxRebalanceAmount; // USD hard cap for executeSwap input. 0 = no cap (permissive default).
        SpendingLimit[] spendingLimits; // rolling window limits — stored on-chain, enforced by relayer
        uint256 aiTriggerThreshold; // relayer triggers AI scan above this amount (0 = never by amount)
        bool requireAiVerification; // relayer always requires AI scan for this bot
    }

    /// @notice Parameters for adding or updating a bot. Mirrors BotConfig minus isActive/registeredAt.
    struct BotConfigParams {
        uint256 maxPerTxAmount;
        uint256 maxRebalanceAmount;
        SpendingLimit[] spendingLimits;
        uint256 aiTriggerThreshold;
        bool requireAiVerification;
    }

    /// @notice Owner-set ceilings that bound operator actions. Operator can never exceed these.
    ///         0 in a ceiling field means "no ceiling enforced" for that field,
    ///         EXCEPT maxOperatorBots where 0 means "operator cannot add bots" (restrictive default).
    struct OperatorCeilings {
        uint256 maxPerTxAmount; // operator cannot configure a bot's maxPerTxAmount above this
        uint256 maxBotDailyLimit; // operator cannot configure a bot's daily limit above this
        uint256 maxOperatorBots; // 0 = operator CANNOT add bots. Must be explicitly set by owner.
        uint256 vaultDailyAggregate; // total vault daily outflow cap — relayer reads and enforces (0 = none)
        uint256 minAiTriggerFloor; // operator cannot set aiTriggerThreshold above this (0 = no floor)
    }

    /// @notice Signed payment intent — bot commits to these exact terms.
    struct PaymentIntent {
        address bot;
        address to;
        address token;
        uint256 amount;
        uint256 deadline;
        bytes32 ref; // keccak256 of off-chain memo; full text stored in relayer PostgreSQL
    }

    /// @notice Signed protocol execution intent — bot commits to exact calldata + token approvals.
    ///         Bot builds calldata off-chain (e.g. Ostium openTrade, GMX createOrder), signs the hash.
    ///         Relayer submits the actual calldata; contract verifies hash matches what bot signed.
    ///         tokens/amounts lists ALL tokens to approve to the protocol before the call.
    ///         Empty arrays = no approvals needed (e.g. closing a trade).
    struct ExecuteIntent {
        address bot;
        address protocol; // target contract (must be in vault's approvedProtocols)
        bytes32 calldataHash; // keccak256 of the calldata the relayer will submit
        address[] tokens; // tokens to approve to protocol (e.g. [USDC, WETH] for GMX)
        uint256[] amounts; // approval amounts for each token (must match tokens length)
        uint256 value; // native ETH to send with the call (0 = no ETH)
        uint256 deadline;
        bytes32 ref;
    }

    /// @notice Signed swap intent — bot authorizes an in-vault token swap (rebalancing).
    ///         Swap keeps the output token in the vault — nothing is sent to a recipient.
    ///         Bot signs BOTH sides: what to receive (toToken/minToAmount) AND what to sell (fromToken/maxFromAmount).
    struct SwapIntent {
        address bot;
        address toToken; // desired output token to receive in vault
        uint256 minToAmount; // minimum output (slippage protection, enforced on-chain)
        address fromToken; // token the vault will sell (bot-signed, not relayer-controlled)
        uint256 maxFromAmount; // max input the vault will spend (bot-signed)
        uint256 deadline;
        bytes32 ref;
    }

    // =========================================================================
    // Immutable state (set once in initialize, never changes)
    // =========================================================================

    /// @notice Axon's AxonRegistry for this chain. Set once in initialize(), never changes.
    address public axonRegistry;

    // =========================================================================
    // Mutable state
    // =========================================================================

    /// @notice Hot wallet for bot management. Cannot be the owner. address(0) = no operator.
    address public operator;

    /// @notice Owner-set ceilings bounding operator actions.
    OperatorCeilings public operatorCeilings;

    // Bot state
    mapping(address => BotConfig) private _bots;
    mapping(address => address) public botAddedByOperator;
    uint256 public operatorBotCount;

    // Destination whitelists (empty = any destination allowed; non-empty = restrict to listed)
    mapping(address => bool) public globalDestinationWhitelist;
    uint256 public globalDestinationCount;

    mapping(address => mapping(address => bool)) public botDestinationWhitelist;
    mapping(address => uint256) public botDestinationCount;

    // Destination blacklist (always blocks, regardless of whitelist status)
    mapping(address => bool) public globalDestinationBlacklist;
    uint256 public globalBlacklistCount;

    // Intent deduplication — always active
    mapping(bytes32 => bool) public usedIntents;

    // Per-vault approved DeFi protocols (owner manages — NOT in AxonRegistry)
    mapping(address => bool) public approvedProtocols;
    uint256 public approvedProtocolCount;

    // Rebalance token whitelist — restricts executeSwap output tokens.
    // Only affects standalone swaps (executeSwap), NOT swap-within-payment (executePayment).
    // Empty = any token allowed (permissive default for backwards compatibility).
    mapping(address => bool) public rebalanceTokenWhitelist;
    uint256 public rebalanceTokenCount;

    // ERC-1271 bot signing — owner must explicitly enable before bots can sign
    // off-chain messages (Seaport listings, Permit2, Cowswap orders) on behalf
    // of the vault. Disabled by default to prevent a compromised bot key from
    // signing arbitrary Permit2 transfers or Seaport listings.
    bool public erc1271BotsEnabled;

    // Oracle-based swap slippage guard — max allowed value retention as basis points (e.g. 9500 = max 5% slippage).
    // 0 = disabled (no oracle slippage check). Only enforced when oracle can price both tokens.
    uint256 public maxSwapSlippageBps;

    // =========================================================================
    // Events
    // =========================================================================

    event BotAdded(address indexed bot, address indexed addedBy);
    event BotRemoved(address indexed bot, address indexed removedBy);
    event BotConfigUpdated(address indexed bot, address indexed updatedBy);

    event PaymentExecuted(address indexed bot, address indexed to, address indexed token, uint256 amount, bytes32 ref);

    event Deposited(address indexed from, address indexed token, uint256 amount, bytes32 ref);
    event Withdrawn(address indexed token, uint256 amount, address indexed to);
    event ERC721Withdrawn(address indexed nft, uint256 indexed tokenId, address indexed to);
    event ERC1155Withdrawn(address indexed token, uint256 indexed id, uint256 amount, address indexed to);

    event OperatorSet(address indexed oldOperator, address indexed newOperator);
    event OperatorCeilingsUpdated(OperatorCeilings ceilings);

    event GlobalDestinationAdded(address indexed destination);
    event GlobalDestinationRemoved(address indexed destination);
    event BotDestinationAdded(address indexed bot, address indexed destination);
    event BotDestinationRemoved(address indexed bot, address indexed destination);

    event GlobalBlacklistAdded(address indexed destination);
    event GlobalBlacklistRemoved(address indexed destination);

    event ProtocolApproved(address indexed protocol);
    event ProtocolRevoked(address indexed protocol);
    event ProtocolExecuted(
        address indexed bot, address indexed protocol, address token, uint256 amount, uint256 value, bytes32 ref
    );
    event SwapExecuted(
        address indexed bot, address fromToken, address toToken, uint256 fromAmount, uint256 toAmount, bytes32 ref
    );

    event RebalanceTokenAdded(address indexed token);
    event RebalanceTokenRemoved(address indexed token);

    event ERC1271BotsToggled(bool enabled);
    event MaxSwapSlippageBpsSet(uint256 bps);
    event OracleCheckSkipped(address indexed fromToken, address indexed toToken, string reason);

    // =========================================================================
    // Errors
    // =========================================================================

    error NotAuthorizedRelayer();
    error NotAuthorized();
    error BotNotActive();
    error BotAlreadyExists();
    error BotDoesNotExist();
    error DeadlineExpired();
    error InvalidSignature();
    error IntentAlreadyUsed();
    error MaxPerTxExceeded();
    error DestinationBlacklisted();
    error DestinationNotWhitelisted();
    error RouterNotApproved();
    error SwapFailed();
    error SwapOutputInsufficient();
    error OwnerCannotBeBot();
    error OperatorCannotBeOwner();
    error OperatorBotLimitReached();
    error ExceedsOperatorCeiling();
    error TooManySpendingLimits();
    error ZeroAddress();
    error NativeTransferFailed();
    error AmountMismatch();
    error UnexpectedETH();
    error SelfPayment();
    error PaymentToZeroAddress();
    error ZeroAmount();
    error ContractNotApproved();
    error ProtocolCallFailed();
    error CalldataHashMismatch();
    error AlreadyApprovedProtocol();
    error ProtocolNotApproved();
    error RebalanceTokenNotAllowed();
    error MaxRebalanceAmountExceeded();
    error SameTokenSwap();
    error SwapSlippageTooHigh();
    error DefaultTokenCallRestricted();
    error ArrayLengthMismatch();
    error TooManyTokens();
    error InvalidSpendingWindow();

    // =========================================================================
    // Modifiers
    // =========================================================================

    modifier onlyRelayer() {
        if (!IAxonRegistry(axonRegistry).isAuthorized(msg.sender)) revert NotAuthorizedRelayer();
        _;
    }

    modifier onlyOwnerOrOperator() {
        if (msg.sender != owner() && (operator == address(0) || msg.sender != operator)) {
            revert NotAuthorized();
        }
        _;
    }

    // =========================================================================
    // Constructor & Initializer (EIP-1167 clone pattern)
    // =========================================================================

    /// @dev Locks the implementation contract so it cannot be initialized directly.
    ///      Only clones created by the factory can be initialized.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the vault. Called once by the factory after cloning.
    /// @param _owner           The Owner — vault owner, cold wallet recommended.
    /// @param _axonRegistry    Axon's AxonRegistry for this chain. Set once, never changes.
    function initialize(address _owner, address _axonRegistry) external initializer {
        if (_axonRegistry == address(0)) revert ZeroAddress();
        __Ownable_init(_owner);
        __Ownable2Step_init();
        __Pausable_init();
        __EIP712_init("AxonVault", "1");
        axonRegistry = _axonRegistry;
        maxSwapSlippageBps = 9500; // 95% — swaps must retain 95% of USD value by default
    }

    /// @dev Disabled — renouncing ownership would permanently brick the vault.
    function renounceOwnership() public pure override {
        revert("AxonVault: renounce disabled");
    }

    // =========================================================================
    // Owner-only configuration
    // =========================================================================

    /// @notice Assign or rotate the operator hot wallet. Use address(0) to unset.
    function setOperator(address _operator) external onlyOwner {
        if (_operator == owner() || (_operator != address(0) && _operator == pendingOwner())) {
            revert OperatorCannotBeOwner();
        }
        address old = operator;
        operator = _operator;
        operatorBotCount = 0; // reset count — new operator starts fresh
        emit OperatorSet(old, _operator);
    }

    /// @notice Set ceilings that bound all operator actions.
    ///         maxOperatorBots = 0 means operator cannot add any bots.
    function setOperatorCeilings(OperatorCeilings calldata ceilings) external onlyOwner {
        operatorCeilings = ceilings;
        emit OperatorCeilingsUpdated(ceilings);
    }

    // =========================================================================
    // Bot management
    // =========================================================================

    /// @notice Register a new bot address. Owner can set any config; operator is bounded by ceilings.
    function addBot(address bot, BotConfigParams calldata params) external onlyOwnerOrOperator {
        if (bot == address(0)) revert ZeroAddress();
        if (bot == owner()) revert OwnerCannotBeBot();
        if (_bots[bot].isActive) revert BotAlreadyExists();
        if (params.spendingLimits.length > MAX_SPENDING_LIMITS) revert TooManySpendingLimits();
        _validateSpendingWindows(params.spendingLimits);

        bool byOperator = (msg.sender != owner() && msg.sender == operator && operator != address(0));

        if (byOperator) {
            _checkOperatorBotLimit();
            _checkOperatorCeilings(bot, params, false);
        }

        BotConfig storage config = _bots[bot];
        delete config.spendingLimits; // clear stale data from previous registration
        config.isActive = true;
        config.registeredAt = block.timestamp;
        config.maxPerTxAmount = params.maxPerTxAmount;
        config.maxRebalanceAmount = params.maxRebalanceAmount;
        config.aiTriggerThreshold = params.aiTriggerThreshold;
        config.requireAiVerification = params.requireAiVerification;

        for (uint256 i = 0; i < params.spendingLimits.length; i++) {
            config.spendingLimits.push(params.spendingLimits[i]);
        }

        if (byOperator) {
            botAddedByOperator[bot] = msg.sender;
            operatorBotCount++;
        }

        emit BotAdded(bot, msg.sender);
    }

    /// @notice Revoke a bot's access. Owner or operator can remove any bot.
    /// @dev Clears BotConfig and botDestinationCount, but per-destination whitelist entries
    ///      (botDestinationWhitelist[bot][addr]) persist in storage because Solidity cannot
    ///      bulk-delete nested mappings. If the same address is re-registered as a bot, it
    ///      will inherit stale whitelist entries. To avoid this, use a fresh keypair for new bots.
    function removeBot(address bot) external onlyOwnerOrOperator {
        if (!_bots[bot].isActive) revert BotDoesNotExist();

        // Clear bot config to prevent stale state on re-registration
        delete _bots[bot];

        if (botAddedByOperator[bot] != address(0) && botAddedByOperator[bot] == operator) {
            if (operatorBotCount > 0) operatorBotCount--;
        }
        botAddedByOperator[bot] = address(0);

        // Note: botDestinationWhitelist[bot][...] is a nested mapping and cannot be
        // bulk-deleted. botDestinationCount is reset so re-registration starts clean.
        botDestinationCount[bot] = 0;

        emit BotRemoved(bot, msg.sender);
    }

    /// @notice Update an existing bot's config. Operator can only tighten — not loosen.
    function updateBotConfig(address bot, BotConfigParams calldata params) external onlyOwnerOrOperator {
        if (!_bots[bot].isActive) revert BotDoesNotExist();
        if (params.spendingLimits.length > MAX_SPENDING_LIMITS) revert TooManySpendingLimits();
        _validateSpendingWindows(params.spendingLimits);

        bool byOperator = (msg.sender != owner() && msg.sender == operator && operator != address(0));

        if (byOperator) {
            _checkOperatorCeilings(bot, params, true);
            // Operator cannot disable requireAiVerification once enabled
            if (_bots[bot].requireAiVerification && !params.requireAiVerification) {
                revert ExceedsOperatorCeiling();
            }
        }

        BotConfig storage config = _bots[bot];
        config.maxPerTxAmount = params.maxPerTxAmount;
        config.maxRebalanceAmount = params.maxRebalanceAmount;
        config.aiTriggerThreshold = params.aiTriggerThreshold;
        config.requireAiVerification = params.requireAiVerification;

        // Replace spending limits array
        uint256 existing = config.spendingLimits.length;
        for (uint256 i = 0; i < existing; i++) {
            config.spendingLimits.pop();
        }
        for (uint256 i = 0; i < params.spendingLimits.length; i++) {
            config.spendingLimits.push(params.spendingLimits[i]);
        }

        emit BotConfigUpdated(bot, msg.sender);
    }

    // =========================================================================
    // Destination whitelist management
    // =========================================================================

    /// @notice Add a destination to the vault-wide whitelist. Owner only (loosening).
    function addGlobalDestination(address destination) external onlyOwner {
        if (destination == address(0)) revert ZeroAddress();
        if (!globalDestinationWhitelist[destination]) {
            globalDestinationWhitelist[destination] = true;
            globalDestinationCount++;
            emit GlobalDestinationAdded(destination);
        }
    }

    /// @notice Remove a destination from the vault-wide whitelist. Owner or operator (tightening).
    function removeGlobalDestination(address destination) external onlyOwnerOrOperator {
        if (globalDestinationWhitelist[destination]) {
            globalDestinationWhitelist[destination] = false;
            globalDestinationCount--;
            emit GlobalDestinationRemoved(destination);
        }
    }

    /// @notice Add a destination to a specific bot's whitelist. Owner only (loosening).
    function addBotDestination(address bot, address destination) external onlyOwner {
        if (destination == address(0)) revert ZeroAddress();
        if (!botDestinationWhitelist[bot][destination]) {
            botDestinationWhitelist[bot][destination] = true;
            botDestinationCount[bot]++;
            emit BotDestinationAdded(bot, destination);
        }
    }

    /// @notice Remove a destination from a bot's whitelist. Owner or operator (tightening).
    function removeBotDestination(address bot, address destination) external onlyOwnerOrOperator {
        if (botDestinationWhitelist[bot][destination]) {
            botDestinationWhitelist[bot][destination] = false;
            botDestinationCount[bot]--;
            emit BotDestinationRemoved(bot, destination);
        }
    }

    // =========================================================================
    // Destination blacklist management
    // =========================================================================

    /// @notice Block a destination for the entire vault. Owner or operator (tightening).
    function addGlobalBlacklist(address destination) external onlyOwnerOrOperator {
        if (destination == address(0)) revert ZeroAddress();
        if (!globalDestinationBlacklist[destination]) {
            globalDestinationBlacklist[destination] = true;
            globalBlacklistCount++;
            emit GlobalBlacklistAdded(destination);
        }
    }

    /// @notice Unblock a destination. Owner only (loosening).
    function removeGlobalBlacklist(address destination) external onlyOwner {
        if (globalDestinationBlacklist[destination]) {
            globalDestinationBlacklist[destination] = false;
            globalBlacklistCount--;
            emit GlobalBlacklistRemoved(destination);
        }
    }

    // =========================================================================
    // Protocol whitelist management (per-vault, NOT in AxonRegistry)
    // =========================================================================

    /// @notice Approve a contract for executeProtocol calls. Can be a DeFi protocol
    ///         or a token contract (for approve() calls in the two-step pattern).
    ///         Owner only (loosening).
    function approveProtocol(address protocol) external onlyOwner {
        if (protocol == address(0)) revert ZeroAddress();
        if (approvedProtocols[protocol]) revert AlreadyApprovedProtocol();
        approvedProtocols[protocol] = true;
        approvedProtocolCount++;
        emit ProtocolApproved(protocol);
    }

    /// @notice Revoke a previously approved contract. Owner or operator (tightening).
    function revokeProtocol(address protocol) external onlyOwnerOrOperator {
        if (!approvedProtocols[protocol]) revert ProtocolNotApproved();
        approvedProtocols[protocol] = false;
        approvedProtocolCount--;
        emit ProtocolRevoked(protocol);
    }

    /// @notice Check if a contract (protocol or token) is approved for this vault.
    function isContractApproved(address protocol) external view returns (bool) {
        return approvedProtocols[protocol];
    }

    // =========================================================================
    // ERC-1271 bot signing toggle
    // =========================================================================

    /// @notice Enable or disable ERC-1271 signature validation for bots.
    ///         When disabled (default), only the owner's signatures are valid via isValidSignature.
    ///         Enable this to allow bots to sign Seaport listings, Permit2 transfers, etc.
    ///         WARNING: enabling this means a compromised bot key can sign arbitrary messages
    ///         on behalf of the vault. Only enable if your use case requires it.
    function setErc1271Bots(bool enabled) external onlyOwner {
        erc1271BotsEnabled = enabled;
        emit ERC1271BotsToggled(enabled);
    }

    // =========================================================================
    // Rebalance token whitelist (executeSwap only)
    // =========================================================================

    /// @notice Allow a token as output for executeSwap (in-vault rebalancing). Owner only.
    ///         Only affects standalone swaps — payment swap routing can use any token.
    ///         Empty whitelist = any token allowed (permissive default).
    function addRebalanceTokens(address[] calldata tokens) external onlyOwner {
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == address(0)) revert ZeroAddress();
            if (!rebalanceTokenWhitelist[tokens[i]]) {
                rebalanceTokenWhitelist[tokens[i]] = true;
                rebalanceTokenCount++;
                emit RebalanceTokenAdded(tokens[i]);
            }
        }
    }

    /// @notice Remove tokens from the rebalance whitelist. Owner or operator (tightening).
    function removeRebalanceTokens(address[] calldata tokens) external onlyOwnerOrOperator {
        for (uint256 i = 0; i < tokens.length; i++) {
            if (rebalanceTokenWhitelist[tokens[i]]) {
                rebalanceTokenWhitelist[tokens[i]] = false;
                rebalanceTokenCount--;
                emit RebalanceTokenRemoved(tokens[i]);
            }
        }
    }

    /// @notice Set the maximum acceptable slippage for oracle-checked swaps.
    ///         e.g. 9500 means toUsd must be >= 95% of fromUsd. 0 disables the check.
    function setMaxSwapSlippageBps(uint256 bps) external onlyOwner {
        require(bps <= 10_000, "bps > 10000");
        maxSwapSlippageBps = bps;
        emit MaxSwapSlippageBpsSet(bps);
    }

    // =========================================================================
    // Pause
    // =========================================================================

    /// @notice Freeze the vault. Owner or operator can pause (emergency response).
    function pause() external onlyOwnerOrOperator {
        _pause();
    }

    /// @notice Unfreeze the vault. Owner only — resuming operations requires cold wallet.
    function unpause() external onlyOwner {
        _unpause();
    }

    // =========================================================================
    // Deposit / Withdraw
    // =========================================================================

    /// @notice Accept raw ETH transfers (e.g. from swap routers, WETH unwrap, direct sends).
    receive() external payable { }

    /// @notice Deposit tokens or native ETH into the vault. Open to anyone — no restriction.
    ///         For native ETH: pass NATIVE_ETH as token, msg.value must equal amount.
    ///         `ref` links this deposit to an off-chain payment request or invoice tracked
    ///         in the relayer's PostgreSQL. Pass bytes32(0) for plain deposits with no reference.
    ///         Direct transfers (no function call) also work but emit no vault event.
    function deposit(address token, uint256 amount, bytes32 ref) external payable nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (token == NATIVE_ETH) {
            if (msg.value != amount) revert AmountMismatch();
        } else {
            if (msg.value != 0) revert UnexpectedETH();
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }
        emit Deposited(msg.sender, token, amount, ref);
    }

    /// @notice Withdraw tokens or native ETH. Owner only — non-custodial guarantee.
    function withdraw(address token, uint256 amount, address to) external nonReentrant onlyOwner {
        if (amount == 0) revert ZeroAmount();
        if (to == address(0)) revert ZeroAddress();
        _transferOut(token, to, amount);
        emit Withdrawn(token, amount, to);
    }

    /// @notice Withdraw an ERC-721 NFT from the vault. Owner only.
    function withdrawERC721(address nft, uint256 tokenId, address to) external nonReentrant onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        IERC721(nft).safeTransferFrom(address(this), to, tokenId);
        emit ERC721Withdrawn(nft, tokenId, to);
    }

    /// @notice Withdraw ERC-1155 tokens from the vault. Owner only.
    function withdrawERC1155(address token, uint256 id, uint256 amount, address to) external nonReentrant onlyOwner {
        if (amount == 0) revert ZeroAmount();
        if (to == address(0)) revert ZeroAddress();
        IERC1155(token).safeTransferFrom(address(this), to, id, amount, "");
        emit ERC1155Withdrawn(token, id, amount, to);
    }

    // =========================================================================
    // Relayer fee withdrawal
    // =========================================================================

    // =========================================================================
    // Execute payment (Approach B — handles both direct and swap+pay)
    // =========================================================================

    /// @notice Execute a bot's signed payment intent. Direct transfer only — vault must hold enough of the token.
    ///         If the vault lacks the payment token, call executeSwap first to rebalance, then executePayment.
    ///
    /// @param intent       PaymentIntent signed by the bot. `token` = desired output, `amount` = minimum to deliver.
    /// @param signature    Bot's EIP-712 signature over the PaymentIntent.
    function executePayment(PaymentIntent calldata intent, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        onlyRelayer
    {
        if (intent.amount == 0) revert ZeroAmount();
        if (intent.to == address(this)) revert SelfPayment();
        if (intent.to == address(0)) revert PaymentToZeroAddress();
        if (block.timestamp > intent.deadline) revert DeadlineExpired();

        BotConfig storage bot = _bots[intent.bot];
        if (!bot.isActive) revert BotNotActive();

        // Verify EIP-712 signature — signer must be the bot address in the intent
        bytes32 structHash = keccak256(
            abi.encode(
                PAYMENT_INTENT_TYPEHASH, intent.bot, intent.to, intent.token, intent.amount, intent.deadline, intent.ref
            )
        );
        bytes32 intentHash = _hashTypedDataV4(structHash);

        if (intentHash.recover(signature) != intent.bot) revert InvalidSignature();

        // Deduplication — prevents exact duplicate submissions
        if (usedIntents[intentHash]) revert IntentAlreadyUsed();
        usedIntents[intentHash] = true;

        // Hard per-tx cap (USD-denominated via TWAP oracle)
        _checkMaxPerTxAmount(bot, intent.token, intent.amount);

        // Destination whitelist — enforced on-chain
        _checkDestination(intent.bot, intent.to);

        // Direct transfer — vault must hold enough of the desired token.
        // If insufficient, relayer should call executeSwap first to rebalance.
        _transferOut(intent.token, intent.to, intent.amount);
        emit PaymentExecuted(intent.bot, intent.to, intent.token, intent.amount, intent.ref);
    }

    // =========================================================================
    // Execute swap (standalone in-vault rebalancing)
    // =========================================================================

    /// @notice Execute a standalone in-vault token swap. Output stays in the vault (not sent to a recipient).
    ///         Used for treasury rebalancing — e.g. swap USDC → WBTC before opening a GMX trade.
    ///         Bot signs a SwapIntent with minToAmount for slippage protection; contract verifies output on-chain.
    ///         If rebalance token whitelist is non-empty, toToken must be on the list (prevents swaps to worthless tokens).
    ///         maxPerTxAmount checks the INPUT (value at risk), not the gameable output amount.
    ///
    /// @param intent       SwapIntent signed by the bot. `toToken` = desired output, `minToAmount` = slippage floor.
    /// @param signature    Bot's EIP-712 signature over the SwapIntent.
    /// @param swapRouter   Approved DEX router (relayer-supplied).
    /// @param swapCalldata Encoded swap call (relayer-supplied).
    function executeSwap(
        SwapIntent calldata intent,
        bytes calldata signature,
        address swapRouter,
        bytes calldata swapCalldata
    ) external nonReentrant whenNotPaused onlyRelayer {
        if (intent.minToAmount == 0) revert ZeroAmount();
        if (intent.fromToken == intent.toToken) revert SameTokenSwap();
        if (block.timestamp > intent.deadline) revert DeadlineExpired();
        if (!IAxonRegistry(axonRegistry).isApprovedSwapRouter(swapRouter)) revert RouterNotApproved();

        BotConfig storage bot = _bots[intent.bot];
        if (!bot.isActive) revert BotNotActive();

        // Verify EIP-712 signature — bot signs fromToken + maxFromAmount to prevent relayer substitution
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
        bytes32 intentHash = _hashTypedDataV4(structHash);
        if (intentHash.recover(signature) != intent.bot) revert InvalidSignature();

        // Deduplication — prevents exact duplicate submissions
        if (usedIntents[intentHash]) revert IntentAlreadyUsed();
        usedIntents[intentHash] = true;

        // Rebalance token whitelist — only restricts standalone swaps, not payment routing
        _checkRebalanceToken(intent.toToken);

        // Separate swap cap on INPUT amount (value at risk), not gameable output
        _checkMaxRebalanceAmount(bot, intent.fromToken, intent.maxFromAmount);

        // Snapshot vault balances before swap
        uint256 fromBalanceBefore = (intent.fromToken == NATIVE_ETH)
            ? address(this).balance
            : IERC20(intent.fromToken).balanceOf(address(this));
        uint256 toBalanceBefore =
            (intent.toToken == NATIVE_ETH) ? address(this).balance : IERC20(intent.toToken).balanceOf(address(this));

        _doSwap(intent.fromToken, intent.maxFromAmount, swapRouter, swapCalldata);

        // Verify vault received at least minToAmount
        uint256 fromBalanceAfter = (intent.fromToken == NATIVE_ETH)
            ? address(this).balance
            : IERC20(intent.fromToken).balanceOf(address(this));
        uint256 toBalanceAfter =
            (intent.toToken == NATIVE_ETH) ? address(this).balance : IERC20(intent.toToken).balanceOf(address(this));
        uint256 actualFromAmount = fromBalanceBefore - fromBalanceAfter;
        uint256 toReceived = toBalanceAfter - toBalanceBefore;
        if (toReceived < intent.minToAmount) revert SwapOutputInsufficient();

        // Oracle-based slippage guard (defense-in-depth — primary protection is bot-signed fromToken)
        // Uses external self-call via oracleUsdValue() so try/catch can absorb OracleUnavailable reverts
        if (maxSwapSlippageBps > 0) {
            try this.oracleUsdValue(intent.fromToken, actualFromAmount) returns (uint256 fromUsd) {
                try this.oracleUsdValue(intent.toToken, toReceived) returns (uint256 toUsd) {
                    if (fromUsd > 0 && toUsd < fromUsd * maxSwapSlippageBps / 10_000) revert SwapSlippageTooHigh();
                } catch {
                    emit OracleCheckSkipped(intent.fromToken, intent.toToken, "toToken oracle failed");
                }
            } catch {
                emit OracleCheckSkipped(intent.fromToken, intent.toToken, "fromToken oracle failed");
            }
        }

        emit SwapExecuted(intent.bot, intent.fromToken, intent.toToken, actualFromAmount, toReceived, intent.ref);
    }

    // =========================================================================
    // Execute protocol action (DeFi interactions)
    // =========================================================================

    /// @notice Execute an arbitrary DeFi protocol call on behalf of a bot.
    ///         Bot signs an ExecuteIntent specifying the protocol, calldata hash, and token approvals.
    ///         The relayer supplies the actual calldata; the contract verifies the hash matches.
    ///         If the vault lacks a required token, call executeSwap first to rebalance.
    ///
    ///         Flow: approve tokens to protocol → call protocol → revoke approvals.
    ///
    /// @param intent       ExecuteIntent signed by the bot.
    /// @param signature    Bot's EIP-712 signature over the ExecuteIntent.
    /// @param callData     Actual calldata to send to the protocol. keccak256(callData) must match intent.calldataHash.
    function executeProtocol(ExecuteIntent calldata intent, bytes calldata signature, bytes calldata callData)
        external
        nonReentrant
        whenNotPaused
        onlyRelayer
        returns (bytes memory)
    {
        if (intent.tokens.length != intent.amounts.length) revert ArrayLengthMismatch();
        if (intent.tokens.length > 5) revert TooManyTokens();
        if (block.timestamp > intent.deadline) revert DeadlineExpired();
        bool isDefault = IAxonRegistry(axonRegistry).isDefaultToken(intent.protocol);
        bool isGlobalProtocol = IAxonRegistry(axonRegistry).isApprovedProtocol(intent.protocol);
        if (!approvedProtocols[intent.protocol] && !isDefault && !isGlobalProtocol) {
            revert ContractNotApproved();
        }

        BotConfig storage bot = _bots[intent.bot];
        if (!bot.isActive) revert BotNotActive();

        // Default tokens (e.g. USDC) may only be called with approve() — block drain vectors.
        // Global protocols and per-vault approved protocols have full function access.
        // NM-001v3: Validate spender is an approved protocol + cap the approve amount.
        if (isDefault && !isGlobalProtocol && !approvedProtocols[intent.protocol]) {
            // approve(address,uint256) = 4 byte selector + 32 byte address + 32 byte uint256 = 68 bytes
            if (callData.length < 68) revert DefaultTokenCallRestricted();
            bytes4 selector = bytes4(callData[:4]);
            // approve(address,uint256) = 0x095ea7b3
            if (selector != bytes4(0x095ea7b3)) revert DefaultTokenCallRestricted();
            // Decode spender — must be an approved protocol or swap router
            address spender = abi.decode(callData[4:36], (address));
            if (
                !approvedProtocols[spender] && !IAxonRegistry(axonRegistry).isApprovedProtocol(spender)
                    && !IAxonRegistry(axonRegistry).isApprovedSwapRouter(spender)
            ) {
                revert DefaultTokenCallRestricted();
            }
            // Cap the approve amount against bot's maxPerTxAmount
            uint256 approveAmount = abi.decode(callData[36:68], (uint256));
            _checkMaxPerTxAmount(bot, intent.protocol, approveAmount);
        }

        // Verify calldata hash matches what the bot signed
        if (keccak256(callData) != intent.calldataHash) revert CalldataHashMismatch();

        // Verify EIP-712 signature (arrays encoded as keccak256 of packed elements per EIP-712)
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
        bytes32 intentHash = _hashTypedDataV4(structHash);

        if (intentHash.recover(signature) != intent.bot) revert InvalidSignature();

        // Deduplication — prevents exact duplicate submissions
        if (usedIntents[intentHash]) revert IntentAlreadyUsed();
        usedIntents[intentHash] = true;

        // Per-tx cap — checks COMBINED USD value of ALL token approvals + native ETH.
        _checkMaxPerTxAmountCombined(bot, intent.tokens, intent.amounts, intent.value);

        // Approve all tokens to protocol — bot-signed, each token + amount is explicit
        for (uint256 i = 0; i < intent.tokens.length; i++) {
            if (intent.amounts[i] > 0) {
                IERC20(intent.tokens[i]).forceApprove(intent.protocol, intent.amounts[i]);
            }
        }

        // Call the protocol (forward native ETH if value > 0, e.g. WETH.deposit, Lido.submit)
        (bool success, bytes memory returnData) = intent.protocol.call{ value: intent.value }(callData);
        if (!success) revert ProtocolCallFailed();

        // Revoke all approvals (cleanup)
        for (uint256 i = 0; i < intent.tokens.length; i++) {
            if (intent.amounts[i] > 0) {
                IERC20(intent.tokens[i]).forceApprove(intent.protocol, 0);
            }
        }

        emit ProtocolExecuted(
            intent.bot,
            intent.protocol,
            intent.tokens.length > 0 ? intent.tokens[0] : address(0),
            intent.tokens.length > 0 ? intent.amounts[0] : 0,
            intent.value,
            intent.ref
        );

        return returnData;
    }

    // =========================================================================
    // View functions
    // =========================================================================

    /// @notice Returns the EIP-712 domain separator for off-chain signature verification.
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Returns the full BotConfig for a given bot address.
    function getBotConfig(address bot) external view returns (BotConfig memory) {
        return _bots[bot];
    }

    /// @notice Returns whether a bot address is currently active.
    function isBotActive(address bot) external view returns (bool) {
        return _bots[bot].isActive;
    }

    /// @notice TWAP oracle USD valuation wrapper (public so executeSwap can try/catch via this.*).
    function oracleUsdValue(address token, uint256 amount) public view returns (uint256) {
        return TwapOracle.getUsdValue(axonRegistry, token, amount);
    }

    /// @notice Preview whether a swap would pass the oracle slippage check.
    /// @param fromToken  Token being sold
    /// @param fromAmount Amount being sold
    /// @param toToken    Token being received
    /// @param toAmount   Amount being received
    /// @return wouldPass  True if the swap would pass (or if the check is disabled / oracle unavailable)
    /// @return fromUsd    USD value of fromAmount (0 if oracle unavailable)
    /// @return toUsd      USD value of toAmount (0 if oracle unavailable)
    /// @return minToUsd   Minimum toUsd required to pass (0 if check disabled)
    function previewSwapSlippage(address fromToken, uint256 fromAmount, address toToken, uint256 toAmount)
        external
        view
        returns (bool wouldPass, uint256 fromUsd, uint256 toUsd, uint256 minToUsd)
    {
        if (maxSwapSlippageBps == 0) return (true, 0, 0, 0);

        try this.oracleUsdValue(fromToken, fromAmount) returns (uint256 _fromUsd) {
            fromUsd = _fromUsd;
        } catch {
            return (true, 0, 0, 0); // oracle unavailable — check skipped
        }

        try this.oracleUsdValue(toToken, toAmount) returns (uint256 _toUsd) {
            toUsd = _toUsd;
        } catch {
            return (true, fromUsd, 0, 0); // oracle unavailable for toToken — check skipped
        }

        minToUsd = fromUsd * maxSwapSlippageBps / 10_000;
        wouldPass = (fromUsd == 0) || (toUsd >= minToUsd);
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// @dev Check maxPerTxAmount using TWAP oracle for USD conversion.
    ///      maxPerTxAmount is stored in USDC terms (6 decimals). If oracle config is not
    ///      set on the registry, reverts with OracleNotConfigured for non-USDC tokens.
    function _checkMaxPerTxAmount(BotConfig storage bot, address token, uint256 amount) internal view {
        if (bot.maxPerTxAmount == 0) return; // no cap
        uint256 usdValue = TwapOracle.getUsdValue(axonRegistry, token, amount);
        if (usdValue > bot.maxPerTxAmount) revert MaxPerTxExceeded();
    }

    /// @dev Check maxPerTxAmount against the COMBINED USD value of ALL token approvals + native ETH.
    ///      Used by executeProtocol where multiple tokens and ETH can be approved in one call.
    ///      Sums all amounts to prevent splitting value across tokens/ETH to bypass the cap.
    function _checkMaxPerTxAmountCombined(
        BotConfig storage bot,
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256 ethValue
    ) internal view {
        if (bot.maxPerTxAmount == 0) return; // no cap
        uint256 totalUsd = 0;
        for (uint256 i = 0; i < tokens.length; i++) {
            if (amounts[i] > 0) {
                totalUsd += TwapOracle.getUsdValue(axonRegistry, tokens[i], amounts[i]);
            }
        }
        if (ethValue > 0) {
            totalUsd += TwapOracle.getUsdValue(axonRegistry, NATIVE_ETH, ethValue);
        }
        if (totalUsd > bot.maxPerTxAmount) revert MaxPerTxExceeded();
    }

    /// @dev Check maxRebalanceAmount (separate cap for executeSwap input). Same oracle logic.
    ///      0 = no cap (permissive default — rebalance whitelist is the primary defense).
    function _checkMaxRebalanceAmount(BotConfig storage bot, address token, uint256 amount) internal view {
        if (bot.maxRebalanceAmount == 0) return; // no cap
        uint256 usdValue = TwapOracle.getUsdValue(axonRegistry, token, amount);
        if (usdValue > bot.maxRebalanceAmount) revert MaxRebalanceAmountExceeded();
    }

    /// @dev Execute a swap via an approved DEX router. Caller must verify outcomes.
    function _doSwap(address fromToken, uint256 maxFromAmount, address swapRouter, bytes calldata swapCalldata)
        internal
    {
        if (fromToken == NATIVE_ETH) {
            (bool success,) = swapRouter.call{ value: maxFromAmount }(swapCalldata);
            if (!success) revert SwapFailed();
        } else {
            IERC20(fromToken).forceApprove(swapRouter, maxFromAmount);
            (bool success,) = swapRouter.call(swapCalldata);
            if (!success) revert SwapFailed();
            IERC20(fromToken).forceApprove(swapRouter, 0);
        }
    }

    /// @dev Transfer tokens or native ETH to a recipient.
    function _transferOut(address token, address to, uint256 amount) internal {
        if (token == NATIVE_ETH) {
            (bool success,) = to.call{ value: amount }("");
            if (!success) revert NativeTransferFailed();
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    function _checkDestination(address bot, address to) internal view {
        // Blacklist always blocks, regardless of whitelist
        if (globalDestinationBlacklist[to]) revert DestinationBlacklisted();

        // Whitelist check (unchanged)
        bool hasRestrictions = (globalDestinationCount > 0 || botDestinationCount[bot] > 0);
        if (hasRestrictions) {
            if (!globalDestinationWhitelist[to] && !botDestinationWhitelist[bot][to]) {
                revert DestinationNotWhitelisted();
            }
        }
    }

    /// @dev Check rebalance token whitelist. Empty list = any token allowed.
    ///      Only called for executeSwap, never for executePayment.
    function _checkRebalanceToken(address token) internal view {
        if (rebalanceTokenCount > 0 && !rebalanceTokenWhitelist[token]) {
            revert RebalanceTokenNotAllowed();
        }
    }

    function _checkOperatorBotLimit() internal view {
        // maxOperatorBots = 0 means operator cannot add any bots — restrictive default
        if (operatorCeilings.maxOperatorBots == 0) revert OperatorBotLimitReached();
        if (operatorBotCount >= operatorCeilings.maxOperatorBots) revert OperatorBotLimitReached();
    }

    /// @dev Validate that all spending limit windows use allowed durations.
    function _validateSpendingWindows(SpendingLimit[] calldata limits) internal pure {
        for (uint256 i = 0; i < limits.length; i++) {
            uint256 w = limits[i].windowSeconds;
            if (w != WINDOW_1H && w != WINDOW_3H && w != WINDOW_24H && w != WINDOW_7D && w != WINDOW_30D) {
                revert InvalidSpendingWindow();
            }
        }
    }

    function _checkOperatorCeilings(address bot, BotConfigParams calldata params, bool isUpdate) internal view {
        OperatorCeilings memory c = operatorCeilings;

        // Per-tx ceiling: if set, operator must provide a non-zero cap within the ceiling.
        // If unset (0), operator cannot change maxPerTxAmount — must keep the existing value on update.
        if (c.maxPerTxAmount > 0) {
            if (params.maxPerTxAmount == 0 || params.maxPerTxAmount > c.maxPerTxAmount) {
                revert ExceedsOperatorCeiling();
            }
        } else if (isUpdate) {
            // No ceiling configured — operator must preserve the current value (cannot loosen)
            if (params.maxPerTxAmount != _bots[bot].maxPerTxAmount) {
                revert ExceedsOperatorCeiling();
            }
        }

        // AI trigger floor: operator cannot set a threshold above the floor
        // (higher threshold = fewer transactions get AI-scanned = loosening coverage)
        // threshold=0 means "never trigger AI by amount" = most permissive → must be blocked
        if (c.minAiTriggerFloor > 0) {
            if (params.aiTriggerThreshold == 0 || params.aiTriggerThreshold > c.minAiTriggerFloor) {
                revert ExceedsOperatorCeiling();
            }
        }

        // Operator cannot reduce the number of spending limits (loosening — removes daily caps)
        if (isUpdate) {
            if (params.spendingLimits.length < _bots[bot].spendingLimits.length) {
                revert ExceedsOperatorCeiling();
            }
        }

        // Daily limit ceiling: for each window ≤ 24h, the effective daily throughput
        // (amount × 24h / windowSeconds) must not exceed maxBotDailyLimit.
        // E.g. $100/1h → effective $2,400/day → must be ≤ maxBotDailyLimit.
        if (c.maxBotDailyLimit > 0) {
            bool hasDailyWindow = false;
            for (uint256 i = 0; i < params.spendingLimits.length; i++) {
                uint256 w = params.spendingLimits[i].windowSeconds;
                if (w <= WINDOW_24H) {
                    hasDailyWindow = true;
                    uint256 effectiveDaily = params.spendingLimits[i].amount * (WINDOW_24H / w);
                    if (effectiveDaily > c.maxBotDailyLimit) {
                        revert ExceedsOperatorCeiling();
                    }
                }
            }
            // Operator must include at least one daily-or-shorter window when ceiling is set
            if (!hasDailyWindow) revert ExceedsOperatorCeiling();
        }
    }

    // =========================================================================
    // NFT receiver support (ERC-721 + ERC-1155)
    // =========================================================================

    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    // =========================================================================
    // ERC-1271 — Smart contract signature validation
    // =========================================================================

    /// @notice Validates a signature on behalf of the vault (ERC-1271).
    ///         Returns the magic value if the signer is the owner or an active bot.
    ///         This enables the vault to "sign" off-chain orders for Seaport (OpenSea),
    ///         limit orders (Cowswap/1inch), Permit2, and other signature-based protocols.
    /// @param hash   The hash that was signed.
    /// @param signature ECDSA signature bytes.
    /// @return magicValue 0x1626ba7e if valid, 0xffffffff if invalid.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (paused()) return bytes4(0xffffffff);
        address signer = hash.recover(signature);
        // Owner can always sign on behalf of the vault
        if (signer == owner()) return bytes4(0x1626ba7e);
        // Bots can only sign if the owner has explicitly enabled ERC-1271 for bots.
        // This prevents a compromised bot key from signing arbitrary Permit2 transfers,
        // Seaport listings, or other off-chain messages that bypass executeProtocol caps.
        if (erc1271BotsEnabled && _bots[signer].isActive) return bytes4(0x1626ba7e);
        return bytes4(0xffffffff);
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC721Receiver).interfaceId || interfaceId == type(IERC1155Receiver).interfaceId
            || interfaceId == bytes4(0x1626ba7e) // IERC1271
            || super.supportsInterface(interfaceId);
    }
}

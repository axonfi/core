// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/AxonRegistry.sol";
import "../src/AxonVaultFactory.sol";

/// @notice Deploys AxonRegistry and AxonVaultFactory, then registers default swap routers.
///
/// Environment variables:
///   PRIVATE_KEY   — deployer's private key (testnet only; omit when using --trezor/--ledger)
///   OWNER_ADDRESS — address that will own both contracts (defaults to deployer)
///                   On mainnet this should be a Safe multisig address.
///
/// Usage:
///   # Testnet (Base Sepolia)
///   forge script script/Deploy.s.sol \
///     --rpc-url base_sepolia \
///     --broadcast \
///     --verify \
///     -vvvv
///
///   # Mainnet with Trezor (no PRIVATE_KEY needed)
///   forge script script/Deploy.s.sol \
///     --rpc-url arb_mainnet \
///     --broadcast \
///     --trezor \
///     --verify \
///     -vvvv
contract Deploy is Script {
    address constant DETERMINISTIC_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() external {
        // ── Deployer key ─────────────────────────────────────────────────────
        // If PRIVATE_KEY is set, use it (testnet). Otherwise assume --trezor/--ledger.
        uint256 deployerKey = vm.envOr("PRIVATE_KEY", uint256(0));
        bool useHardwareWallet = deployerKey == 0;
        address deployer = useHardwareWallet ? msg.sender : vm.addr(deployerKey);

        // ── Owner address ─────────────────────────────────────────────────────
        // Defaults to the deployer. On mainnet with Trezor, the Trezor IS the owner.
        address owner = vm.envOr("OWNER_ADDRESS", deployer);

        // ── Pre-flight log ────────────────────────────────────────────────────
        console2.log("=== Axon Deployment ===");
        console2.log("Chain ID   :", block.chainid);
        console2.log("Deployer   :", deployer);
        console2.log("Owner      :", owner);
        console2.log("  (owner == deployer:", owner == deployer, ")");

        // ── Deploy via deterministic deployer (CREATE2) ─────────────────────
        // Uses the Arachnid deterministic deployment proxy (exists on all EVM chains).
        // Same salt + same bytecode + same owner = same addresses on every chain.
        bytes32 salt = keccak256("axon-v1");

        if (useHardwareWallet) {
            vm.startBroadcast();
        } else {
            vm.startBroadcast(deployerKey);
        }

        // Verify the deterministic deployer exists on this chain
        require(DETERMINISTIC_DEPLOYER.code.length > 0, "Deterministic deployer not found on this chain");

        // Deploy Registry via CREATE2 (skip if already deployed — bytecode unchanged across versions)
        bytes memory registryInitCode = abi.encodePacked(type(AxonRegistry).creationCode, abi.encode(owner));
        address registryAddr = _computeCreate2(DETERMINISTIC_DEPLOYER, salt, registryInitCode);
        bool registryIsNew = registryAddr.code.length == 0;

        if (registryIsNew) {
            (bool regOk,) = DETERMINISTIC_DEPLOYER.call(abi.encodePacked(salt, registryInitCode));
            require(regOk && registryAddr.code.length > 0, "Registry CREATE2 deploy failed");
            console2.log("Registry deployed (new)");
        } else {
            console2.log("Registry already deployed (reusing)");
        }
        AxonRegistry registry = AxonRegistry(registryAddr);

        // Deploy Factory via CREATE2 (uses registry address in constructor args)
        // Factory includes AxonVault bytecode, so a new vault version = new factory address.
        bytes memory factoryInitCode =
            abi.encodePacked(type(AxonVaultFactory).creationCode, abi.encode(registryAddr, owner));
        address factoryAddr = _computeCreate2(DETERMINISTIC_DEPLOYER, salt, factoryInitCode);

        if (factoryAddr.code.length == 0) {
            (bool facOk,) = DETERMINISTIC_DEPLOYER.call(abi.encodePacked(salt, factoryInitCode));
            require(facOk && factoryAddr.code.length > 0, "Factory CREATE2 deploy failed");
            console2.log("Factory deployed (new)");
        } else {
            console2.log("Factory already deployed (reusing)");
        }
        AxonVaultFactory factory = AxonVaultFactory(factoryAddr);

        // ── Configure registry (only on first deploy — these revert if already set) ──
        if (registryIsNew) {
            // ── Register default swap routers ─────────────────────────────────────
            // Uniswap V3 SwapRouter02 — the primary swap router for all chains.
            // These are added to the global registry so all vaults can swap immediately.
            if (block.chainid == 8453) {
                // Base mainnet
                registry.addSwapRouter(0x2626664c2603336E57B271c5C0b26F421741e481);
            } else if (block.chainid == 84532) {
                // Base Sepolia
                registry.addSwapRouter(0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4);
            } else if (block.chainid == 42161) {
                // Arbitrum One
                registry.addSwapRouter(0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45);
            } else if (block.chainid == 421614) {
                // Arbitrum Sepolia
                registry.addSwapRouter(0x101F443B4d1b059569D643917553c771E1b9663E);
            }

            // ── Set oracle config for TWAP price lookups ────────────────────────────
            // Required for USD-denominated maxPerTxAmount enforcement on non-USDC tokens.
            if (block.chainid == 8453) {
                // Base mainnet
                registry.setOracleConfig(
                    0x33128a8fC17869897dcE68Ed026d694621f6FDfD, // Uniswap V3 Factory
                    0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913, // USDC
                    0x4200000000000000000000000000000000000006 // WETH
                );
            } else if (block.chainid == 84532) {
                // Base Sepolia
                registry.setOracleConfig(
                    0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24, // Uniswap V3 Factory (Base Sepolia)
                    0x036CbD53842c5426634e7929541eC2318f3dCF7e, // USDC
                    0x4200000000000000000000000000000000000006 // WETH
                );
            } else if (block.chainid == 42161) {
                // Arbitrum One
                registry.setOracleConfig(
                    0x1F98431c8aD98523631AE4a59f267346ea31F984, // Uniswap V3 Factory
                    0xaf88d065e77c8cC2239327C5EDb3A432268e5831, // USDC
                    0x82aF49447D8a07e3bd95BD0d56f35241523fBab1 // WETH
                );
            } else if (block.chainid == 421614) {
                // Arbitrum Sepolia
                registry.setOracleConfig(
                    0x248AB79Bbb9bC29bB72f7Cd42F17e054Fc40188e, // Uniswap V3 Factory
                    0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d, // USDC
                    0x82aF49447D8a07e3bd95BD0d56f35241523fBab1 // WETH
                );
            }

            // ── Approve default tokens ──────────────────────────────────────────
            // Keep in sync with @axonfi/sdk DEFAULT_APPROVED_TOKENS in packages/sdk-ts/src/tokens.ts
            if (block.chainid == 8453) {
                // Base mainnet — keep in sync with @axonfi/sdk DEFAULT_APPROVED_TOKENS
                registry.approveDefaultToken(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913); // USDC
                registry.approveDefaultToken(0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2); // USDT
                registry.approveDefaultToken(0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb); // DAI
                registry.approveDefaultToken(0x4200000000000000000000000000000000000006); // WETH
                registry.approveDefaultToken(0x0555E30da8f98308EdB960aa94C0Db47230d2B9c); // WBTC
                registry.approveDefaultToken(0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf); // cbBTC
                registry.approveDefaultToken(0xc1CBa3fCea344f92D9239c08C0568f6F2F0ee452); // wstETH
                registry.approveDefaultToken(0x04C0599Ae5A44757c0af6F9eC3b93da8976c150A); // weETH
                registry.approveDefaultToken(0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22); // cbETH
                registry.approveDefaultToken(0xB6fe221Fe9EeF5aBa221c348bA20A1Bf5e73624c); // rETH
            } else if (block.chainid == 84532) {
                // Base Sepolia — only tokens with testnet addresses
                registry.approveDefaultToken(0x036CbD53842c5426634e7929541eC2318f3dCF7e); // USDC
                registry.approveDefaultToken(0x323e78f944A9a1FcF3a10efcC5319DBb0bB6e673); // USDT
                registry.approveDefaultToken(0x819FfeCD4e64f193e959944Bcd57eeDC7755e17a); // DAI
                registry.approveDefaultToken(0x4200000000000000000000000000000000000006); // WETH
            } else if (block.chainid == 42161) {
                // Arbitrum One — keep in sync with @axonfi/sdk DEFAULT_APPROVED_TOKENS
                registry.approveDefaultToken(0xaf88d065e77c8cC2239327C5EDb3A432268e5831); // USDC
                registry.approveDefaultToken(0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9); // USDT
                registry.approveDefaultToken(0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1); // DAI
                registry.approveDefaultToken(0x82aF49447D8a07e3bd95BD0d56f35241523fBab1); // WETH
                registry.approveDefaultToken(0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f); // WBTC
                registry.approveDefaultToken(0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf); // cbBTC
                registry.approveDefaultToken(0x5979D7b546E38E414F7E9822514be443A4800529); // wstETH
                registry.approveDefaultToken(0x35751007a407ca6FEFfE80b3cB397736D2cf4dbe); // weETH
                registry.approveDefaultToken(0x1DEBd73E752bEaF79865Fd6446b0c970EaE7732f); // cbETH
                registry.approveDefaultToken(0xEC70Dcb4A1EFa46b8F2D97C310C9c4790ba5ffA8); // rETH
            } else if (block.chainid == 421614) {
                // Arbitrum Sepolia — only tokens with testnet addresses
                registry.approveDefaultToken(0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d); // USDC
                registry.approveDefaultToken(0x980B62Da83eFf3D4576C647993b0c1D7faf17c73); // WETH
            }

            // ── Approve global protocols ────────────────────────────────────────
            // These are usable in executeProtocol on ALL vaults (any function call allowed).
            // Unlike default tokens (approve-only), global protocols support full interaction.
            // Only WETH is globally approved — it's a basic utility (deposit/withdraw).
            // Complex DeFi protocols (Aave, Compound, Lido) remain per-vault opt-in
            // via vault.approveProtocol() for a smaller attack surface.
            if (block.chainid == 8453) {
                registry.approveProtocol(0x4200000000000000000000000000000000000006); // WETH
            } else if (block.chainid == 84532) {
                registry.approveProtocol(0x4200000000000000000000000000000000000006); // WETH
            } else if (block.chainid == 42161) {
                registry.approveProtocol(0x82aF49447D8a07e3bd95BD0d56f35241523fBab1); // WETH
            } else if (block.chainid == 421614) {
                registry.approveProtocol(0x980B62Da83eFf3D4576C647993b0c1D7faf17c73); // WETH
            }
        } // end registryIsNew

        vm.stopBroadcast();

        // ── Post-deployment log ───────────────────────────────────────────────
        console2.log("");
        console2.log("=== Deployed Addresses ===");
        console2.log("AxonRegistry    :", address(registry));
        console2.log("AxonVaultFactory:", address(factory));
        console2.log("");
        console2.log("=== Verification ===");
        console2.log("registry.owner()         :", registry.owner());
        console2.log("factory.owner()          :", factory.owner());
        console2.log("factory.axonRegistry()   :", factory.axonRegistry());
        console2.log("factory.implementation() :", factory.implementation());
        console2.log("factory.vaultCount()     :", factory.vaultCount());
    }

    /// @dev Compute the CREATE2 address for a given deployer, salt, and init code.
    function _computeCreate2(address deployer, bytes32 _salt, bytes memory initCode) internal pure returns (address) {
        return
            address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, _salt, keccak256(initCode))))));
    }
}

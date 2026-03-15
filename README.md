# Axon Smart Contracts

Non-custodial vault contracts for autonomous AI agents. Built with [Foundry](https://book.getfoundry.sh/).

## Overview

Axon lets bot operators deploy per-owner vaults, register bot public keys, define spending policies, and let their bots make gasless payments via EIP-712 signed intents — without bots ever touching private keys or gas.

## Contracts

| Contract | Description |
| --- | --- |
| `AxonVault` | Per-owner treasury vault. Holds funds, enforces bot auth and spending caps, verifies EIP-712 signed intents. |
| `AxonVaultFactory` | Deploys vault clones via EIP-1167 minimal proxies with CREATE2 deterministic addresses. |
| `AxonRegistry` | Protocol-wide configuration: authorized executors, approved swap routers, TWAP oracle config, default tokens. |

## Key Features

- **Three intent types:** `executePayment` (direct + swap), `executeProtocol` (DeFi interactions with optional ETH), `executeSwap` (in-vault rebalancing)
- **EIP-712 signatures:** Bots sign typed intents off-chain, never submit transactions
- **Operator role:** Delegated hot wallet that can tighten policies (add bots, lower limits, pause) but never loosen them
- **Spending limits:** Per-bot, multi-window (1h/3h/24h/7d/30d), with configurable AI verification thresholds
- **Destination controls:** Global + per-bot whitelist, global blacklist (blacklist always wins)
- **TWAP oracle:** USD-denominated `maxPerTxAmount` enforcement for non-stablecoin tokens
- **ERC-1271:** Vault validates owner and bot signatures for off-chain protocols (Seaport, CoWSwap, Permit2)
- **2-step ownership:** Ownable2Step transfer with renounce blocked

## Development

```bash
# Install dependencies
forge install

# Build
forge build

# Run tests (323 unit tests)
forge test

# Run tests with gas report
forge test --gas-report

# Format
forge fmt
```

## Testing

Unit tests cover all contract functions, access control, and edge cases:

```bash
forge test -vvv
```

Property-based fuzz testing with [Medusa](https://github.com/crytic/medusa) (88 invariant properties):

```bash
medusa fuzz
```

The fuzz harness at `test/fuzz/AxonVaultFuzzHarness.sol` covers: balance conservation, payment/swap/protocol execution, operator ceiling enforcement, bot lifecycle, whitelist/blacklist integrity, signature validation, ERC-1271, and more.

## Deployed Contracts

### Arbitrum One (mainnet)

| Contract | Address |
| --- | --- |
| AxonRegistry | [`0xbc1b61653EDB3906310D4AC8a789E144B1C5A0Ff`](https://arbiscan.io/address/0xbc1b61653EDB3906310D4AC8a789E144B1C5A0Ff) |
| AxonVaultFactory | [`0x271cf17A42435Dc08f320c85834C08a3cb71A10d`](https://arbiscan.io/address/0x271cf17A42435Dc08f320c85834C08a3cb71A10d) |
| Vault Implementation | [`0x236ea8301d2fC3e177e2C198E67CAFcECE6e1ed0`](https://arbiscan.io/address/0x236ea8301d2fC3e177e2C198E67CAFcECE6e1ed0) |

### Testnets (Base Sepolia + Arbitrum Sepolia)

| Contract | Address |
| --- | --- |
| AxonRegistry | [`0xf47E517B78FA7a1045E9857CD39cDC024a1a59b4`](https://sepolia.basescan.org/address/0xf47E517B78FA7a1045E9857CD39cDC024a1a59b4) |
| AxonVaultFactory | [`0x2df2982445bd4dc38d496cec621c9b514b469792`](https://sepolia.basescan.org/address/0x2df2982445bd4dc38d496cec621c9b514b469792) |
| Vault Implementation | [`0x9c427EbEBE9Acd98ac49e166E3AB159a7e1648F5`](https://sepolia.basescan.org/address/0x9c427EbEBE9Acd98ac49e166E3AB159a7e1648F5) |

> Testnet contracts share deterministic addresses on both Base Sepolia (84532) and Arbitrum Sepolia (421614) via CREATE2.

## Architecture

```
Owner deploys vault via Factory (CREATE2)
  └─ Vault holds ERC-20 tokens + native ETH
      ├─ Owner: full control (withdraw, configure, pause)
      ├─ Operator: tighten-only (add bots within ceilings, lower limits, pause)
      └─ Bots: sign EIP-712 intents (PaymentIntent, ExecuteIntent, SwapIntent)
          └─ Authorized executor calls vault with bot's signature
              └─ Vault verifies: bot active + sig valid + deadline OK + caps enforced
```

## Security Model

| Actor | Controls | Risk if Compromised |
| --- | --- | --- |
| Owner (HW wallet / multisig) | Full vault control, bot whitelist, withdrawal | Catastrophic but hardened |
| Operator (hot wallet) | Add bots within ceilings, tighten limits, pause | Limited by ceilings |
| Bot key | Signs payment intents only | Bounded by per-tx caps + spending limits |

## License

MIT

## Links

- [Website](https://axonfi.xyz)
- [Dashboard](https://app.axonfi.xyz)
- [npm — @axonfi/sdk](https://www.npmjs.com/package/@axonfi/sdk)
- [PyPI — axonfi](https://pypi.org/project/axonfi/)
- [Twitter/X — @axonfixyz](https://x.com/axonfixyz)

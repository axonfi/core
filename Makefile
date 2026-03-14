# Axon Contracts — development commands

.PHONY: build test fmt slither aderyn mythril echidna medusa fuzz audit clean

build:
	forge build

test:
	forge test

fmt:
	forge fmt

clean:
	forge clean

# --- Security analysis ---

slither:
	slither . --foundry-out-directory out/

aderyn:
	aderyn .

mythril:
	myth analyze src/AxonVault.sol --solc-json mythril.config.json --solv 0.8.25 --execution-timeout 300

echidna:
	echidna . --contract AxonVaultEchidna --config echidna.yaml --test-mode property

medusa:
	medusa fuzz

# Run all static analyzers + fuzzers
audit: slither aderyn mythril echidna medusa

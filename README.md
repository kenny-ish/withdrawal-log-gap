# withdrawal-log-gap

This small command-line auditor checks whether an OP Stack RPC returned every `MessagePassed` withdrawal in an inclusive block range by reconciling the nonce state before and after the range, recomputing each withdrawal hash, and checking the `sentMessages` mapping. It uses only the caller-provided JSON-RPC endpoint and Python 3.10 or newer standard library code.

## Example

Both examples below were run against `https://mainnet.optimism.io` on 2026-10-10 UTC. The first covers an older Optimism Mainnet range and the second covers a recent range. The contract is the OP Stack `L2ToL1MessagePasser` predeploy. No exchange address is involved.

    python withdrawal_log_gap.py --rpc-url https://mainnet.optimism.io --from-block 130000880 --to-block 130000882
    {
      "chain_id": 10,
      "end_hash": "0x5cc3e18571221213a5a4dd5861b68cbe82415a1aeaa15faf5e4180ef704e05e2",
      "expected_events": 1,
      "from_block": 130000880,
      "missing_ranges": [],
      "next_nonce_after": 23126,
      "next_nonce_before": 23125,
      "observed_events": 1,
      "status": "ok",
      "to_block": 130000882,
      "unset_hashes": []
    }

    python withdrawal_log_gap.py --rpc-url https://mainnet.optimism.io --from-block 158021868 --to-block 158021872
    {
      "chain_id": 10,
      "end_hash": "0x86c3d8f1dc828aba19056b8362cdf3211cf2a7d9c4d9b38ba208d2980c5a99a9",
      "expected_events": 1,
      "from_block": 158021868,
      "missing_ranges": [],
      "next_nonce_after": 34975,
      "next_nonce_before": 34974,
      "observed_events": 1,
      "status": "ok",
      "to_block": 158021872,
      "unset_hashes": []
    }

The offline tests use compact event fields from both live cases in `fixture.json` and construct the ABI response in the test. This keeps the fixed data small while retaining live block and transaction identifiers.

## Usage

- `--rpc-url`: required HTTP or HTTPS JSON-RPC URL. The caller chooses the provider.
- `--from-block`, `--to-block`: required inclusive decimal block numbers. The start must be at least 1.
- `--chain-id`: expected chain ID, default `10`.
- `--chunk`: block span per `eth_getLogs` request, default `2000`.
- `--timeout`: seconds per HTTP request, default `30`.

Exit code `0` means the range reconciled. Exit code `1` means a nonce gap or unset withdrawal hash was found. Exit code `2` means the audit could not be completed. Historical state access is required at block `from - 1` and at `to`. Use finalized ranges. RPC errors are not treated as empty results.

## How it works

The tool reads `messageNonce()` at the boundary blocks, collects only `MessagePassed` logs from the system predeploy, and sorts them by block, transaction, and log order. It requires version 1 nonces and checks that the low 240 bits cover the boundary interval exactly once. Missing ranges include leading and trailing gaps, so an empty log response is reported as a mismatch when state says an event should exist.

For every event it recomputes the withdrawal hash with a small in-file Ethereum Keccak-256 implementation and Solidity ABI encoding, then calls `sentMessages(bytes32)` at the end block. It rejects malformed logs, duplicate log identities, noncanonical block hashes, version changes, and a changing boundary chain. The check is an RPC consistency audit, not an L1 finality proof. A dishonest or inconsistent RPC can still provide matching false data, and a mismatch can also indicate an incompatible contract upgrade.

The event and hashing rules follow the OP Stack contracts: [L2ToL1MessagePasser](https://github.com/ethereum-optimism/optimism/blob/develop/packages/contracts-bedrock/src/L2/L2ToL1MessagePasser.sol), [Encoding](https://github.com/ethereum-optimism/optimism/blob/develop/packages/contracts-bedrock/src/libraries/Encoding.sol), and [Hashing](https://github.com/ethereum-optimism/optimism/blob/develop/packages/contracts-bedrock/src/libraries/Hashing.sol).

## Tests

`python -m unittest -v`

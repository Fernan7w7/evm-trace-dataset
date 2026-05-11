# Justification — 3.1 Timestamp / Block Dependency
**Source:** Not-So-Smart-Contracts

| Contract | Vulnerable Usage | Block Attribute |
|---|---|---|
| `theRun.sol` | `randomGen()` seeds randomness from `block.timestamp` (stored as `constant salt`) and `block.number`/`blockhash`; result used in CHECK→transfer path to award the WinningPot | `block.timestamp`, `block.number`, `blockhash` |
| `Lottery.sol` | `OpenAddressLottery` seeds the secret from `block.timestamp`, `block.difficulty`, `block.coinbase`, and `blockhash` at construction/reseed; seed used in CHECK→transfer path to award payout | Multiple block attributes |
| `SpankChain_Payment.sol` | All settlement and timeout gates use `now` (alias for `block.timestamp`) via `require(now > ...)` checks that control ETH and token releases | `block.timestamp` (`now`) |

**Note on Lottery.sol:** This contract was deployed as a honeypot, but the block.timestamp/blockhash-based seed is the actual core mechanism used in a real CHECK→transfer path. The block dependency vulnerability is genuine regardless of the honeypot framing.

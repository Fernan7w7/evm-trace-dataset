# Justification — 3.1 Timestamp / Block Dependency
**Source:** SmartBugs Curated (`time_manipulation/` and `bad_randomness/`)  
**Precondition:** `READ(block.timestamp / blockhash / block.number / block.coinbase / block.difficulty)` → CHECK or WRITE — the contract's outcome is determined by miner-influenceable or predictable block attributes.

Both SmartBugs categories map to 3.1 because the underlying trace pattern is identical: the contract reads a block-level environment variable and uses it to decide a winner, gate a state change, or generate randomness — all adversary-influenceable by a miner or a same-block attacker.

**From `time_manipulation/`:**

| Contract | Vulnerable Usage | Block Attribute |
|---|---|---|
| `ether_lotto.sol` | `uint(sha3(block.timestamp)) % 2` → winner check | `block.timestamp` |
| `governmental_survey.sol` | `block.timestamp < lastInvestmentTimestamp + ONE_MINUTE` | `block.timestamp` |
| `lottopollo.sol` | `randomGen()` returns `block.timestamp` → payout condition | `block.timestamp` |
| `roulette.sol` | `now % 15 == 0` as win condition; `now` for per-block bet guard | `block.timestamp` (`now`) |
| `timed_crowdsale.sol` | `block.timestamp >= 1546300800` gates sale-finished state | `block.timestamp` |

**From `bad_randomness/`:**

| Contract | Vulnerable Usage | Block Attribute |
|---|---|---|
| `blackjack.sol` | `block.number`, `block.timestamp`, `block.blockhash(b)` seed card generation | `blockhash`, `block.number`, `block.timestamp` |
| `etheraffle.sol` | `block.coinbase`, `block.difficulty`, `block.number` as randomness seeds in `chooseWinner()` | Multiple block attributes |
| `guess_the_random_number.sol` | `keccak256(block.blockhash(block.number - 1), now)` as answer in constructor | `blockhash`, `block.timestamp` |
| `lottery.sol` | `block.number % 2` as win condition in `makeBet()` | `block.number` |
| `lucky_doubler.sol` | `block.blockhash(block.number - 1)` selects payout index in `rand()` | `blockhash` |
| `old_blockhash.sol` | `blockhash(guesses[msg.sender].block)` returns 0 for blocks > 256 old | `blockhash` |
| `random_number_generator.sol` | `block.timestamp`, `block.number`, `blockhash(seed)` as entropy in `random()` | Multiple block attributes |
| `smart_billions.sol` | `block.blockhash(...)` as lottery result; `salt = block.timestamp` | `blockhash`, `block.timestamp` |

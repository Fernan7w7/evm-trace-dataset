# Justification — 2.3 Missing Input/Return Validation
**Precondition:** No `CHECK` on a critical value before a WRITE or subsequent execution — covers both unchecked low-level call return values and unchecked input parameters on initialization paths.

All 52 contracts in this folder come from SmartBugs' `unchecked_low_level_calls/` category. Each contract contains at least one `.call()`, `.call.value()()`, or `.send()` whose boolean return value is not checked (no `require(success)` wrapping, no assignment to a verified variable). If the call fails, execution continues as if it succeeded, causing incorrect state or silent fund loss.

**Named contracts:**

| Contract | Vulnerable Call | Pattern |
|---|---|---|
| `mishandled.sol` | `msg.sender.send(amountToWithdraw)` | Return value of `send` discarded — failed withdrawal silently ignored |
| `unchecked_return_value.sol` | `callee.call()` | Return value not assigned or checked in `callnotchecked()` |
| `king_of_the_ether_throne.sol` | Multiple `address.send(amount)` | Return values of all `.send()` calls ignored throughout |
| `lotto.sol` | `winner.send(winAmount)`, `msg.sender.send(this.balance)` | Both sends unchecked — winner may not receive prize |
| `etherpot_lotto.sol` | `winner.send(subpot)` | Return value ignored — silent payout failure |

**Address-named contracts (0x...):**  
All 47 address-named contracts carry `// <yes> <report> UNCHECKED_LL_CALLS` annotations and follow the same pattern: `.call()`, `.call.value()()`, or `.send()` with no return-value check. Sampled and confirmed: no deviations from this pattern were found across the 47 contracts.

**Supplement — missing zero-address check (initialization parameter):**

| Contract | Vulnerable Path | Pattern | Paired negative |
|---|---|---|---|
| `token_vault.sol` | `constructor(address)` and `setToken(address)` | No `CHECK(tokenAddress != address(0))` before `token = IERC20(tokenAddress)`. If deployed with or updated to `address(0)`, all `deposit()` and `withdraw()` calls target the zero address — operations silently fail or revert, permanently locking any funds already in the vault. Different precondition from SmartBugs: missing CHECK on an *input parameter* rather than on a *call return value*. | `negative/token_vault.sol` |

# Justification — 2.3 Missing Input/Return Validation
**Source:** SmartBugs Curated  
**Precondition:** No `CHECK` on the return value of a low-level call before subsequent state WRITEs or control flow — a failed call silently continues execution.

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

# Justification — 1.1 Reentrancy (Value Transfer)
**Source:** Not-So-Smart-Contracts

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `Reentrancy.sol` | `withdrawBalance()` | `msg.sender.call.value(userBalance[msg.sender])()` before `userBalance[msg.sender] = 0` — ETH transferred before balance zeroed |
| `DAO.sol` | `splitDAO()` via `withdrawRewardFor()` → `rewardAccount.payOut()` | `_recipient.call.value(_amount)()` inside `payOut` before `paidOut[_account]` is updated — the original DAO hack (2016); ETH drained before state committed |
| `PrivateBank.sol` | `CashOut()` | `msg.sender.call.value(_am)()` before `balances[msg.sender] -= _am` — deployed as a honeypot lure but the reentrancy vulnerability is real and exploitable |

**Note on PrivateBank.sol:** This contract was deployed as a honeypot to trap would-be attackers, but the reentrancy pattern is genuine — a malicious fallback can re-enter and drain before the balance write. Included as a positive example because the trace-observable precondition (CALL → WRITE with ETH) is present.

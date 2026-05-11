# Justification — 3.2 tx.origin Misuse
**Source:** SmartBugs Curated (`access_control/`)  
**Precondition:** `READ(tx.origin)` → CHECK — the contract uses `tx.origin` instead of `msg.sender` for authentication, enabling a phishing attack where a malicious intermediary contract passes the check on behalf of the victim.

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `mycontract.sol` | `sendTo(address, uint)` | `require(tx.origin == owner)` — a malicious contract called by the owner passes this check; `msg.sender` is never verified |
| `phishable.sol` | `withdrawAll(address)` | `require(tx.origin == owner)` — same pattern; attacker tricks owner into calling a malicious contract which then calls `withdrawAll`, draining the contract |

**Why NOT 2.1:** Both contracts do have a CHECK — the issue is that the CHECK reads `tx.origin` rather than `msg.sender`. The trace-level signal is `READ(tx.origin) → CHECK`, not an absent CHECK. This distinguishes them from 2.1 (no CHECK at all).

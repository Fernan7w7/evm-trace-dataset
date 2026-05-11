# Justification — 1.4 DoS via External Call
**Source:** SmartBugs Curated  
**Precondition:** `CALL` appears before a REVERT path with no guard — a malicious recipient's fallback reverting permanently blocks state advancement for all other participants.

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `auction.sol` | `bid()` | `currentFrontrunner.send(currentBid)` (CALL) is required to succeed before `currentFrontrunner` and `currentBid` are updated. A malicious contract that reverts in its fallback locks the auction permanently. |
| `send_loop.sol` | `refundAll()` | Loops over `refundAddresses` calling `.send()` and `require`-ing success on each. One malicious address reverting its fallback breaks the entire refund loop, locking all other users' funds. |

**Out-of-scope DoS contracts (gas exhaustion — NOT included):**  
`dos_address.sol`, `dos_number.sol`, `dos_simple.sol`, `list_dos.sol` — these are gas-limit exhaustion attacks (unbounded loops/arrays), which fall under the "Gas/resource consumption" exclusion category and produce no CALL→REVERT trace pattern.

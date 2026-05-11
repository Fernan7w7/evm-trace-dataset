# Justification — 1.2 Reentrancy (State Only)
**Source:** SmartBugs Curated  
**Precondition:** `CALL → WRITE` where the CALL carries **no ETH value** — the re-entry window exploits a state variable update, not a balance drain.

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `modifier_reentrancy.sol` | `supportsToken()` callback in `airDrop` modifier | The `Bank(msg.sender).supportsToken()` external call (no value) re-enters `airDrop`, granting double token credit to `tokenBalance[msg.sender]` before the modifier sets `claimed[msg.sender] = true` |

**Why NOT 1.1:** The external call `Bank(msg.sender).supportsToken()` transfers no ETH — there is no TRANSFER op in the trace. The exploit is purely a state manipulation (double-crediting `tokenBalance`) triggered by re-entering through the modifier guard before it completes.

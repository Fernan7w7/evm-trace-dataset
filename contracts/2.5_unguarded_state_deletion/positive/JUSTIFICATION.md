# Justification — 2.5 Unguarded State Deletion
**Precondition:** A `delete` operation on critical state is reachable without a `CHECK(authorization)` before it. `delete` resets a storage slot to its zero/default value, making the result indistinguishable from "never set" — the state is irreversibly gone.

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `bare_delete.sol` | `removeBalance(address)` | Textbook case — public function, single `delete balances[user]`, no guard of any kind. Any caller can zero any address's balance. |
| `staking.sol` | `unstake(address)` → `_clearStake(address)` | Inter-procedural case — the public entry point has surrounding logic but no `msg.sender` check. The `delete stakes[user]` lives in the internal helper `_clearStake`, one call level below the public surface. A per-function analyzer may miss the absent guard. |
| `membership.sol` | `removeMember(address)` | Struct-delete case — one `delete members[account]` simultaneously zeroes four critical fields (`role`, `joinDate`, `votingPower`, `active`). More destructive than any single-field write; `addMember` and `updateRole` are gated by `onlyOwner` but `removeMember` is not. |
| `dao.sol` | `cancelProposal(uint256)` | Wrong-check case — a `require` exists before the `delete` but it tests existence (`proposer != address(0)`) rather than the caller's identity. A naive "does a CHECK precede DELETE" detector passes this contract; correct analysis must verify the check is on authorization, not merely on state existence. |

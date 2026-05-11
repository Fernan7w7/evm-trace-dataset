# Justification — 2.4 Unprotected Selfdestruct
**Source:** SmartBugs Curated  
**Precondition:** No `CHECK(owner)` or any caller guard before `SELFDESTRUCT` — any address can destroy the contract and forward its ETH balance.

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `simple_suicide.sol` | `suicideAnyone()` | Calls `selfdestruct(msg.sender)` directly with no `require`, `onlyOwner` modifier, or any other CHECK on `msg.sender` — any caller can permanently destroy the contract and drain its balance to themselves. |

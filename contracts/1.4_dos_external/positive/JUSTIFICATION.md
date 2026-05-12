# Justification — 1.4 DoS via External Call
**Precondition:** `CALL` appears on a required execution path with no fallback — a malicious recipient whose fallback always reverts permanently blocks state advancement for all other participants.

**Key distinction:** The vulnerability is not that the call fails — calls can legitimately fail. The vulnerability is that the contract's logic *depends* on the call succeeding (`require(success)`), with no alternative path. One permanently-reverting recipient is enough to freeze the entire contract.

| Contract | Vulnerable Function | Pattern | Paired negative |
|---|---|---|---|
| `auction.sol` | `bid()` | `currentFrontrunner.send(currentBid)` required to succeed before state updates. Reverting fallback locks auction permanently. | source only |
| `send_loop.sol` | `refundAll()` | `require(refundAddresses[x].send(...))` inside loop — one reverting address blocks all other refunds. | source only |
| `king_of_ether.sol` | `claimThrone()` | Push ETH to previous king before state advances. Reverting king freezes the throne forever. Fix: pull payment pattern — store refund in mapping, separate `withdraw()`. | `negative/king_of_ether.sol` |
| `distribution.sol` | `distribute()` | Loop over recipients with `require(success)` on each transfer. One reverting recipient permanently blocks distribution to everyone else. Fix: drop `require`; emit `TransferFailed` and continue. | `negative/distribution.sol` |

**Out-of-scope DoS contracts (gas exhaustion — NOT included):**  
`dos_address.sol`, `dos_number.sol`, `dos_simple.sol`, `list_dos.sol` — gas-limit exhaustion attacks (unbounded loops/arrays), which produce no CALL→REVERT trace pattern.

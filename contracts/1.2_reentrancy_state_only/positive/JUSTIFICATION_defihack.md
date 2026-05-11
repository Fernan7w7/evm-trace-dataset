# Justification — 1.2 Reentrancy (State Only)
**Source:** DeFiHackLabs

All six exploit the CALL→WRITE precondition with **no ETH value transferred during the re-entry**. The attacker's callback manipulates state variables (share counts, borrow limits, reserve balances) before the victim contract finishes its update.

| Contract | Incident | Pattern |
|---|---|---|
| `SpankChain_exp.sol` | SpankChain 2018-10 | Malicious token's `transfer()` re-enters `LCOpenTimeout()` before the channel state is closed; no ETH transferred during re-entry — state-only manipulation of channel records |
| `BurgerSwap_exp.sol` | BurgerSwap 2021-05 | Malicious token's `transferFrom()` re-enters `swapExactTokensForTokens()` before reserves are updated via `enter()`; no ETH — token reserve state manipulated |
| `Grim_exp.sol` | Grim Finance 2021-12 | `depositFor()` uses attacker-supplied token; malicious `transferFrom()` re-enters `depositFor()` before shares are minted — double share minting, no ETH |
| `HundredFinance_exp.sol` | Hundred Finance 2022-03 | ERC-677 `onTokenTransfer` fires during `redeem()` before state updates; attacker re-enters `borrow()` on the xDAI market — borrow limit not yet updated, no ETH in re-entry |
| `Paribus_exp.sol` | Paribus 2023-04 | Compound v2 fork: `pETH.redeem()` sends ETH triggering attacker `receive()` before borrow limit updates; attacker re-enters `borrow()` — shares/borrow state manipulated, not ETH balance drained directly |
| `dForce_exp.sol` | dForce 2023-02 | Curve `remove_liquidity()` sends ETH triggering attacker fallback before pool reserves sync; attacker calls `liquidateBorrow()` against the stale collateral price — read-only reentrancy exploiting the oracle state window |

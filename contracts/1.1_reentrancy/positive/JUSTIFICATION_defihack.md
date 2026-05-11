# Justification — 1.1 Reentrancy (Value Transfer)
**Source:** DeFiHackLabs

All six are exploit PoC scripts (Foundry test contracts) that reproduce real-world DeFi hacks. Each demonstrates a CALL→WRITE reentrancy where ETH is transferred to the attacker before a state variable (balance, borrow limit, share count) is updated.

| Contract | Incident | Pattern |
|---|---|---|
| `LendfMe_exp.sol` | LendfMe / dForce 2020-04 | ERC-777 `tokensToSend` hook fires on `withdraw()` before the crETH balance is decremented; attacker re-enters `withdraw()` to drain ETH |
| `Cream_exp.sol` | Cream Finance / AMP 2021-08 | ERC-777 `tokensReceived` callback fires during `borrow()` before the AMP borrow limit updates; attacker re-enters `borrow()` for additional funds |
| `XSURGE_exp.sol` | XSURGE 2021-08 | `surge.sell()` sends ETH via `.call` to attacker's `receive()` before internal balances decrease; attacker immediately re-buys at deflated price |
| `Agave_exp.sol` | Agave Finance 2022-03 | Aave v2 fork: `liquidationCall()` triggers `onTokenTransfer` during aToken burn before collateral state finalizes; attacker re-enters `borrow()` against stale collateral |
| `JAY_exp.sol` | JAY Token 2022-12 | `buyJay()` calls attacker's fake ERC-721 `transferFrom()` which re-enters `sell()` before the buy state settles; ETH drained via the re-entry |
| `Curve_exp01.sol` | Curve Finance pETH/ETH 2023-07 | Vyper compiler reentrancy-lock bug: `remove_liquidity()` re-enters `add_liquidity()` via ETH `receive()` before the lock engages; ETH CALL→WRITE in the pool |

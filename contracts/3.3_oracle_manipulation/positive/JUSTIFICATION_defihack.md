# Justification — 3.3 Price Oracle Manipulation
**Source:** DeFiHackLabs

All seven exploit the `READ(external price) → WRITE` pattern: the attacker manipulates the price source (via flash loan, AMM imbalance, or read-only reentrancy) before the victim contract reads it, causing an incorrect WRITE (over-borrow, over-withdraw, or miscalculated payout).

| Contract | Incident | Pattern |
|---|---|---|
| `HarvestFinance_exp.sol` | Harvest Finance 2020-10 | Flash-loans USDC/USDT, moves Curve y-pool price in a loop; Harvest vault reads the Curve pool spot price as its oracle — flash loan → READ(Curve spot price) → WRITE(deposit/withdraw profit) |
| `bEarn_exp.sol` | bEarn Finance 2021-05 | Flash-loans BUSD, loops `deposit()+emergencyWithdraw()` — the vault fails to sync the Alpaca LP price between operations; stale READ(Alpaca price) → WRITE(inflated withdrawal amount) |
| `Spartan_exp.sol` | Spartan Protocol 2021-05 | Flash-loans WBNB to pump pool balances, then calls `removeLiquidity()` which reads raw `balanceOf()` as spot price — READ(inflated balance) → WRITE(withdraw more than deposited) |
| `Cream_2_exp.sol` | Cream Finance 2021-10 | Flash-loans DAI+WETH, inflates yUSD vault's `pricePerShare` by donating assets, then borrows against over-valued crYUSD collateral — READ(manipulated pricePerShare) → WRITE(over-borrow) |
| `Market_exp.sol` | Market.xyz 2022-10 | Curve `remove_liquidity()` sends ETH triggering attacker `receive()` before pool balances sync; attacker borrows miMATIC using the inflated Beefy/Curve LP collateral price — read-only reentrancy → stale READ(LP price) → WRITE(over-borrow) |
| `Sentiment_exp.sol` | Sentiment 2023-04 | Balancer `exitPool()` sends ETH triggering attacker fallback before pool balances update; attacker borrows from Sentiment using the stale over-valued Balancer LP oracle price — read-only reentrancy oracle manipulation |
| `Conic_exp.sol` | Conic Finance 2023-07 | Curve `remove_liquidity()` sends ETH triggering attacker `receive()` before the virtual price updates; attacker calls `handleDepeggedCurvePool()` using the stale inflated LP price — read-only reentrancy → stale READ(virtualPrice) → WRITE |

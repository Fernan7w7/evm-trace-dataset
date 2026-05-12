# Justification — 3.3 Price Oracle Manipulation (Synthetic)
**Precondition:** `READ(external price)` → `WRITE` — the contract acts on a price it reads from an external source, and the attacker manipulates what that source returns before the read occurs.

**Trace status:** `future_work` — Class 3 detection requires READ operation emission in the behavior extractor. These contracts are included as evaluation targets for when that capability is implemented. See `JUSTIFICATION_defihack.md` for real-world exploit instances.

**Distinction from 3.4:** In 3.3 the attacker manipulates the *source* of the read (flash-loans reserves, waits for oracle staleness). In 3.4 the source is honest but the contract reads a *cached* internal value that was correct at some earlier point and is now outdated.

| Contract | Vulnerable Function | Pattern | Paired negative |
|---|---|---|---|
| `spot_price_oracle.sol` | `borrow()` via `getTokenPriceInEth()` | Reads Uniswap V2 `getReserves()` spot price directly. Attacker flash-loans ETH, inflates reserve1 in the same transaction, calls `borrow()` while price is manipulated, then repays the flash loan. Collateral appears over-valued; attacker exits with excess ETH. | `negative/spot_price_oracle.sol` — replaces spot read with a keeper-updated TWAP over a configurable window; borrow() reverts if TWAP is older than MAX_TWAP_AGE |
| `stale_oracle.sol` | `borrow()` via `getEthPriceUsd()` | Reads Chainlink `latestRoundData()` but discards `updatedAt`. If the feed goes stale, the contract keeps using the last known price. Attacker waits for the feed to stop updating, then exploits the divergence between stale price and true market price. | `negative/stale_oracle.sol` — adds `require(block.timestamp - updatedAt <= MAX_STALENESS)` before using the price |

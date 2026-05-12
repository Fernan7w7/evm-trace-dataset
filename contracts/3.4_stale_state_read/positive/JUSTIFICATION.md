# Justification — 3.4 Stale State Read
**Precondition:** `READ(state var)` → `WRITE` where the read value can be outdated by the time it is acted on — either because an intervening external call changed the state, or because a stored snapshot no longer reflects the current on-chain reality.

**Trace status:** `future_work` — Class 3 detection requires READ operation emission in the behavior extractor. These contracts are included as evaluation targets for when that capability is implemented.

**Distinction from 3.3:** In 3.4 the external price source is honest and up to date — the problem is that the contract either caches the value before a call that may change it, or persists the value across time without ever refreshing it. No attacker manipulation of the source is required.

**Distinction from 1.1 (reentrancy):** In 1.1 the external call re-enters the *same function* before a state update completes. In 3.4 the external call may modify state through any authorised path, and the original function then continues with a local cache that no longer matches storage. No re-entrancy loop is required — a single callback is sufficient.

| Contract | Vulnerable Function | Stale Read | Paired negative |
|---|---|---|---|
| `cached_balance.sol` | `claimYield()` | `stakes[msg.sender]` is cached before `boostCalc.getMultiplier()` is called. If the external call updates the stake (via an authorised callback), the cached value is stale and the payout is computed on the wrong amount. | `negative/cached_balance.sol` — moves the `stakes[msg.sender]` READ to after the external call returns |
| `price_snapshot.sol` | `borrow()` | A credit line stores the ETH/USD price at open in `snapshotPrice` and uses it for all collateral valuations indefinitely. If ETH price falls after the line is opened, borrowers can draw down credit that the current collateral no longer supports. | `negative/price_snapshot.sol` — removes `snapshotPrice` from the valuation formula; `borrow()` re-reads current oracle price with a staleness check on every call |

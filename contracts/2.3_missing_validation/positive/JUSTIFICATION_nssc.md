# Justification — 2.3 Missing Input/Return Validation
**Source:** Not-So-Smart-Contracts

| Contract | Vulnerable Call | Pattern |
|---|---|---|
| `KingOfTheEtherThrone.sol` | Multiple `address.send(compensation)` throughout `claimThrone()` | Return values of all `.send()` calls are ignored; a failed send to a previous monarch (e.g., a contract with a reverting fallback) silently swallows the loss with no revert or error handling, causing silent fund loss |

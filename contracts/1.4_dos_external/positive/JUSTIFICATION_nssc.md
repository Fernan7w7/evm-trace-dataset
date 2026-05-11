# Justification — 1.4 DoS via External Call
**Source:** Not-So-Smart-Contracts

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `nssc_auction.sol` | `DosAuction.bid()` | Calls `currentFrontrunner.send(currentBid)` and requires it succeeds before advancing `currentFrontrunner` to the new bidder. A malicious contract that reverts in its fallback permanently locks the auction — no new bids can be accepted. |
| `list_dos.sol` | `CrowdFundBad.refundDos()` | Iterates the full creditor list calling `transfer()` inside `require()` in a loop. A single reverting recipient at any index halts the entire refund pass, freezing all other creditors' funds. |

**Note:** `nssc_auction.sol` is renamed from the original `auction.sol` to avoid a filename conflict with the SmartBugs copy already present in this folder.

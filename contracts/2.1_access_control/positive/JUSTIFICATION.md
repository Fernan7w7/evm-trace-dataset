# Justification — 2.1 Access Control Bypass
**Source:** SmartBugs Curated  
**Precondition:** No `CHECK(msg.sender)` before a sensitive WRITE or CALL — any external caller can invoke a privileged function.

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `incorrect_constructor_name1.sol` | `IamMissing()` | Misnamed constructor sets `owner = msg.sender` with no caller guard — anyone can call it and hijack ownership |
| `incorrect_constructor_name2.sol` | `missing()` | Same pattern — misnamed constructor, no `CHECK(msg.sender)` before `owner = msg.sender` |
| `incorrect_constructor_name3.sol` | `Constructor()` | Same pattern — capitalised name not recognized as constructor pre-0.5.0 |
| `multiowned_vulnerable.sol` | `newOwner(address)` | Adds any caller as owner — no `onlyOwner` or equivalent CHECK before WRITE to owners array |
| `parity_wallet_bug_2.sol` | `WalletLibrary.initWallet()` | `only_uninitialized` modifier does not check `msg.sender`; anyone can call `initWallet` before legitimate initialization and seize ownership |
| `rubixi.sol` | `DynamicPyramid()` | Misnamed constructor sets `creator = msg.sender`; no CHECK before WRITE — any caller can become creator |
| `unprotected0.sol` | `changeOwner(address)` | Writes `owner = _newOwner` with no modifier or require checking `msg.sender == owner` |
| `wallet_02_refund_nosub.sol` | `refund()` | Transfers `balances[msg.sender]` without zeroing the balance first and without a guard — effectively no CHECK before ETH CALL |
| `wallet_03_wrong_constructor.sol` | `initWallet()` | Misnamed constructor pattern — no CHECK before `creator = msg.sender` WRITE |

**Out-of-scope access_control contracts (NOT included):**  
- `arbitrary_location_write_simple.sol` — array-length underflow enabling arbitrary storage slot write (arithmetic/storage collision)  
- `mapping_write.sol` — arbitrary storage slot write via large mapping key (storage collision)  
- `wallet_04_confused_sign.sol` — wrong comparison operator (`>=` instead of `<=`) — logic/arithmetic error  
These three do not match the "no CHECK(msg.sender) before WRITE/CALL" precondition and fall under excluded arithmetic/language categories.

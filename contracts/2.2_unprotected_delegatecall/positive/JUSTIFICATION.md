# Justification — 2.2 Unprotected Delegatecall
**Source:** SmartBugs Curated  
**Precondition:** No `CHECK(target)` or `CHECK(caller)` before a DELEGATECALL — an attacker supplies a malicious target address or data that overwrites storage in the calling contract's context.

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `FibonacciBalance.sol` | fallback function | `fibonacciLibrary.delegatecall(msg.data)` — caller controls `msg.data` entirely; no CHECK on what function is called. Attacker can invoke `setStart(uint)` to overwrite the `start` storage slot (slot 0, which maps to `fibonacciLibrary` address), redirecting all future delegatecalls to an attacker-controlled contract. |
| `parity_wallet_bug_1.sol` | fallback function | `_walletLibrary.delegatecall(msg.data)` with no check on caller or data — the library's `initWallet` can be called by anyone via delegatecall to seize ownership of the wallet (real-world Parity multisig hack, 2017). |
| `proxy.sol` | `forward(address callee, bytes _data)` | `callee.delegatecall(_data)` with no check on `callee` — any caller can delegatecall to any arbitrary address with arbitrary data, executing code in the proxy's storage context. |

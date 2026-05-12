# Justification — 2.2 Unprotected Delegatecall
**Precondition:** No `CHECK(caller)` or `CHECK(target)` before a DELEGATECALL — an attacker supplies a malicious target address or data that executes arbitrary code in the calling contract's storage context.

**Distinction from 1.3:** Category 1.3 focuses on the storage corruption *mechanism* — ordering, uninitialized proxies, and layout collisions. Category 2.2 is an access control failure: the guard is simply absent. The attacker does not need to exploit ordering or structural mismatches; they walk straight through the missing check.

| Contract | Vulnerable Function | Pattern | Paired negative |
|---|---|---|---|
| `FibonacciBalance.sol` | fallback | `fibonacciLibrary.delegatecall(msg.data)` — caller controls `msg.data` entirely; no CHECK on what function is called. Attacker invokes `setStart(uint)` to overwrite the `fibonacciLibrary` address slot, redirecting all future delegatecalls. | source only |
| `parity_wallet_bug_1.sol` | fallback | `_walletLibrary.delegatecall(msg.data)` with no check on caller or data — `initWallet` can be called by anyone to seize wallet ownership (real-world Parity multisig hack, 2017). | source only |
| `proxy.sol` | `forward(address callee, bytes _data)` | `callee.delegatecall(_data)` with no check on `callee` — any caller can delegatecall to any arbitrary address. | source only |
| `execute.sol` | `execute(address target, bytes data)` | Same structural pattern as `proxy.sol` but in 0.8.x with the full header format. Any caller, any target — one call overwrites the owner slot. | `negative/execute.sol` |
| `library_registry.sol` | `registerLib(bytes32 name, address lib)` | The delegatecall target is chosen via a mapping any caller can write to. The missing guard is one step before the delegatecall — on the registry write — making it harder for a per-function analyzer to locate. Attacker sets the library to their malicious contract, then calls `executeOp()`. | `negative/library_registry.sol` |

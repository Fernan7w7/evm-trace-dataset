# Justification — 2.1 Access Control Bypass
**Source:** Not-So-Smart-Contracts

| Contract | Vulnerable Function | Pattern |
|---|---|---|
| `Unprotected.sol` | `changeOwner(address)` | No `onlyOwner` modifier or `require(msg.sender == owner)` — any caller can overwrite the `owner` state variable |
| `WalletLibrary.sol` | `initWallet()` / `initMultiowned()` | Public functions with no access guard; any caller can reinitialize the wallet's owner list post-deployment (real-world Parity multisig hack, 2017) |
| `incorrect_constructor.sol` | `IamMissing()` | Misnamed constructor is a callable public function; no CHECK before `owner = msg.sender` WRITE — anyone can seize ownership |
| `Rubixi.sol` | `DynamicPyramid()` | Same misnamed-constructor pattern: `DynamicPyramid()` was the original name before renaming to Rubixi; the old name became a public function callable by anyone |

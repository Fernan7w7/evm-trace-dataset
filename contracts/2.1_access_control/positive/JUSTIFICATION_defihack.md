# Justification — 2.1 Access Control Bypass
**Source:** DeFiHackLabs

All nine exploit a privileged function reachable without a CHECK on `msg.sender` or an ownership guard.

| Contract | Incident | Pattern |
|---|---|---|
| `Parity_first_hack_exp.sol` | Parity Multisig 2017-07 | `initWallet()` has no owner check; attacker calls it to become owner then drains the wallet via `execute()` — $30M stolen |
| `Parity_kill_exp.sol` | Parity Multisig 2017-11 | Same unprotected `initWallet()` on the shared WalletLibrary; attacker calls `initWallet()` then `kill()` to self-destruct the library, freezing $280M |
| `Bancor_exp.sol` | Bancor 2020-06 | `safeTransferFrom()` deployed as `public` with no caller check; anyone can drain tokens from any victim who approved the contract |
| `Pickle_exp.sol` | Pickle Finance 2020-11 | `swapExactJarForJar()` accepts arbitrary `targets[]` and `datas[]` with no caller validation; attacker passes malicious call data to execute privileged operations in the contract's context |
| `88mph_exp.sol` | 88mph 2021-06 | NFT contract's `init()` has no initialized guard; attacker reinitializes to become owner, then mints/burns tokens freely |
| `PolyNetwork_exp.sol` | Poly Network 2021-08 | Cross-chain manager calls `EthCrossChainData` without checking the target; attacker crafts a proof that triggers `putCurEpochConPubKeyBytes()`, bypassing `onlyOwner` on the data contract — $600M breach |
| `DaoMaker_exp.sol` | DaoMaker 2021-09 | `init()` has no `onlyOwner`/initialized guard; attacker reinitializes the contract to become owner then calls `emergencyExit()` to drain tokens |
| `Visor_exp.sol` | Visor Finance 2021-12 | `IRewardsHypervisor.deposit()` accepts an arbitrary `from` address with no `msg.sender` check; attacker passes a fake `owner()` contract to mint unlimited vVISR shares |
| `Templedao_exp.sol` | TempleDAO 2022-10 | `migrateStake()` has no caller restriction; attacker calls it directly to claim all staked LP tokens then immediately withdraws |

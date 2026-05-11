# evm-trace-dataset

A curated, labeled dataset of Ethereum smart contracts organized by a trace-based vulnerability taxonomy. Built as the evaluation benchmark for **TRACE** (Trace-based Reasoning for Automated Contract Examination), an LLM-augmented smart contract vulnerability detection pipeline.

---

## Overview

| Source | Contracts | IDs Covered | Solidity Version |
|---|---|---|---|
| SmartBugs Curated | 113 | 1.1, 1.2, 1.4, 2.1, 2.2, 2.3, 2.4, 3.1, 3.2 | 0.4.x–0.5.x |
| Not-So-Smart-Contracts | 13 | 1.1, 1.4, 2.1, 2.3, 3.1 | 0.4.x |
| DeFiHackLabs | 28 | 1.1, 1.2, 2.1, 3.3 | 0.7.x–0.8.x |
| Original (this work) | ~50 | 1.3, 1.5, 2.2, 2.4, 2.5, 3.4 + supplements | 0.8.x |
| **Total** | **~205** | **All 14 IDs** | Mixed |

---

## Repository Structure

```
evm-trace-dataset/
│
├── README.md
├── labels.json
├── taxonomy.md
│
├── contracts/
│   ├── 1.1_reentrancy/
│   │   ├── positive/
│   │   └── negative/
│   ├── 1.2_reentrancy_state_only/
│   │   ├── positive/
│   │   └── negative/
│   ├── 1.3_delegatecall_corruption/
│   │   ├── positive/
│   │   └── negative/
│   ├── 1.4_dos_external/
│   │   ├── positive/
│   │   └── negative/
│   ├── 1.5_silent_termination/
│   │   ├── positive/
│   │   └── negative/
│   ├── 2.1_access_control/
│   │   ├── positive/
│   │   └── negative/
│   ├── 2.2_unprotected_delegatecall/
│   │   ├── positive/
│   │   └── negative/
│   ├── 2.3_missing_validation/
│   │   ├── positive/
│   │   └── negative/
│   ├── 2.4_unprotected_selfdestruct/
│   │   ├── positive/
│   │   └── negative/
│   ├── 2.5_unguarded_deletion/
│   │   ├── positive/
│   │   └── negative/
│   ├── 3.1_block_dependency/
│   │   ├── positive/
│   │   └── negative/
│   ├── 3.2_txorigin_misuse/
│   │   ├── positive/
│   │   └── negative/
│   ├── 3.3_oracle_manipulation/
│   │   ├── positive/
│   │   └── negative/
│   └── 3.4_stale_state_read/
│       ├── positive/
│       └── negative/
│
└── stats/
    ├── dataset_summary.csv
    └── coverage.md
```

---

## Taxonomy

Contracts are labeled according to a trace-based vulnerability taxonomy organized into three classes over an 11-type operation system. See `Taxonomy.md` for the full reference.

### Class 1 — Operation Ordering Violations

The attacker exploits a window created by two operations appearing in the wrong sequence.

| ID | Vulnerability | Precondition | Attack Vector | Op Types | Coverage |
|---|---|---|---|---|---|
| 1.1 | Reentrancy (value transfer) | `CALL → WRITE` | Malicious fallback re-enters before balance update | CALL, TRANSFER, WRITE | ✅ |
| 1.2 | Reentrancy (state only) | `CALL → WRITE` (no value) | Malicious fallback manipulates state before WRITE | CALL, WRITE | ✅ |
| 1.3 | Delegatecall state corruption | `DELEGATECALL → WRITE` | Attacker-controlled target overwrites storage | DELEGATECALL, WRITE | ⚠️ Original only |
| 1.4 | DoS via external call | `CALL` before REVERT path | Malicious fallback blocks state advancement | CALL, WRITE, REVERT | ✅ |
| 1.5 | Silent termination | `SELFDESTRUCT` before `EMIT` | Contract terminates without event trace | SELFDESTRUCT, EMIT | ⚠️ Original only |

### Class 2 — Guard Absence Violations

The attacker walks a path with no `CHECK` before a sensitive operation.

| ID | Vulnerability | Precondition | Attack Vector | Op Types | Coverage |
|---|---|---|---|---|---|
| 2.1 | Access control bypass | No `CHECK(msg.sender)` before WRITE/CALL | Direct call to restricted function | CHECK, WRITE, CALL | ✅ |
| 2.2 | Unprotected delegatecall | No `CHECK(target)` before DELEGATECALL | Caller supplies malicious target | DELEGATECALL, CHECK | ✅ |
| 2.3 | Missing input/return validation | No `CHECK(amount/address/return)` before WRITE | Zero address or bad value passes unchecked | CHECK, WRITE | ✅ |
| 2.4 | Unprotected selfdestruct | No `CHECK(owner)` before SELFDESTRUCT | Anyone triggers self-destruct | CHECK, SELFDESTRUCT | ✅ |
| 2.5 | Unguarded state deletion | No `CHECK(auth)` before DELETE | Attacker triggers delete on critical state | CHECK, DELETE | ⚠️ Original only |

### Class 3 — State Visibility Violations *(Future Work)*

The attacker poisons what the contract reads from the environment before it acts on it. Requires READ operation emission in the behavior extractor.

| ID | Vulnerability | Precondition | Attack Vector | Op Types | Coverage |
|---|---|---|---|---|---|
| 3.1 | Timestamp / block dependency | `READ(block.timestamp)` → CHECK/WRITE | Miner influences block attributes | READ, CHECK, WRITE | ✅ |
| 3.2 | tx.origin misuse | `READ(tx.origin)` → CHECK | Phishing contract in call chain | READ, CHECK | ✅ |
| 3.3 | Price oracle manipulation | `READ(external price)` → WRITE | Flash loan distorts price feed | READ, WRITE, STATICCALL | ✅ |
| 3.4 | Stale state read | `READ(state var)` → WRITE | Stale value read between updates | READ, WRITE | ⚠️ Original only |

---

## Labels

All ground truth labels are stored in `labels.json`. Each entry follows this schema:

```json
{
  "contracts/1.1_reentrancy/positive/dao.sol": {
    "vulnerable": true,
    "taxonomy_id": "1.1",
    "source": "smartbugs",
    "solidity_version": "0.4.x",
    "fuzzer_confirmed": false,
    "notes": "DAO exploit reproduction — SWC-107"
  }
}
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `vulnerable` | bool | True = positive case, False = negative/patched |
| `taxonomy_id` | string | Taxonomy ID (e.g. "1.1", "2.3") |
| `source` | string | `smartbugs`, `not_so_smart_contracts`, `defihacklabs`, `original` |
| `solidity_version` | string | Pragma version (e.g. "0.4.x", "0.8.x") |
| `fuzzer_confirmed` | bool | Whether exploit confirmed by Echidna or Medusa |
| `notes` | string | Source reference, SWC mapping, or context |

---

## Sources

**SmartBugs Curated**
J. Ferreira, P. Cruz, T. Durieux, R. Abreu. *SmartBugs: A Framework to Analyze Solidity Smart Contracts.* ASE 2020.
https://github.com/smartbugs/smartbugs-curated

**Not-So-Smart-Contracts**
Trail of Bits. *Not So Smart Contracts.*
https://github.com/crytic/not-so-smart-contracts

**DeFiHackLabs**
Web3 Security Community. *DeFi Hacks Analysis — Root Cause.*
https://github.com/SunWeb3Sec/DeFiHackLabs

**Original contracts (this work)**
Written to cover taxonomy IDs with no existing benchmark. Solidity 0.8.x. Each contract includes a header comment describing the vulnerability, the precondition, and the patching strategy used for the negative variant.

---

## Known Limitations

- **Solidity version skew:** SmartBugs and Not-So-Smart-Contracts are predominantly 0.4.x–0.5.x. Original contracts use 0.8.x. Tool compatibility across versions should be treated as a confound in evaluation.
- **Limited sources for 1.5, 2.5, 3.4:** These IDs have no corresponding entries in existing taxonomies or benchmarks. Contracts are original and empirical exploitability is unconfirmed.
- **No negative contracts in SmartBugs:** SmartBugs Curated contains only vulnerable contracts. Negative cases are either patched variants or independently sourced safe contracts.
- **Dataset scale:** ~205 contracts is sufficient for proof-of-concept evaluation. Expansion via Code4rena/Sherlock/Immunefi audit reports is planned future work.

---

## Related

**TRACE pipeline:** https://github.com/Fernan7w7/LLM-assisted-analysis

---

## Citation

```
Fernando Centurión Ayala. A Trace-Based Taxonomy and LLM-Augmented Detection
Pipeline for Ethereum Vulnerabilities. 2026.
```

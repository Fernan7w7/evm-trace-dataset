# evm-trace-dataset

A curated, labeled dataset of Ethereum smart contracts organized by a trace-based vulnerability taxonomy. Built as the evaluation benchmark for **TRACE** (Trace-based Reasoning for Automated Contract Examination), an LLM-augmented smart contract vulnerability detection pipeline.

---

## Overview

| Source | Contracts | IDs Covered | Solidity Version |
|---|---|---|---|
| SmartBugs Curated | ~120 | 1.1, 1.4, 2.1, 2.3, 3.1, 3.2 | 0.4.x |
| Not-So-Smart-Contracts | ~25 | 1.1, 1.3, 2.1, 2.2, 2.4 | 0.4–0.5.x |
| DeFiHackLabs | ~10 | 1.1, 2.1, 3.3 | Mixed |
| Original (this work) | ~50 | 1.3, 1.5, 2.2, 2.4, 2.5, 3.4 + supplements | 0.8.x |
| **Total** | **~205** | **All 13 IDs** | Mixed |

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

Contracts are labeled according to a trace-based vulnerability taxonomy organized into three classes over an 11-type operation system. See `taxonomy.md` for the full reference.

| ID | Class | Vulnerability | Dataset Coverage |
|---|---|---|---|
| 1.1 | Class 1 — Ordering | Reentrancy (all variants) | ✅ |
| 1.3 | Class 1 — Ordering | Delegatecall state corruption | ✅ |
| 1.4 | Class 1 — Ordering | DoS via external call | ✅ |
| 1.5 | Class 1 — Ordering | Silent termination | ⚠️ Limited sources — original contracts only |
| 2.1 | Class 2 — Guard absence | Access control bypass | ✅ |
| 2.2 | Class 2 — Guard absence | Unprotected delegatecall | ✅ |
| 2.3 | Class 2 — Guard absence | Missing input/return validation | ✅ |
| 2.4 | Class 2 — Guard absence | Unprotected selfdestruct | ✅ |
| 2.5 | Class 2 — Guard absence | Unguarded state deletion | ⚠️ Limited sources — original contracts only |
| 3.1 | Class 3 — State visibility | Timestamp / block dependency | ✅ |
| 3.2 | Class 3 — State visibility | tx.origin misuse | ✅ |
| 3.3 | Class 3 — State visibility | Price oracle manipulation | ✅ |
| 3.4 | Class 3 — State visibility | Stale state read | ⚠️ Limited sources — original contracts only |

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

**TRACE pipeline:** https://github.com/Fernan7w7/trace-pipeline

---

## Citation

```
Fernando Centurión Ayala. A Trace-Based Taxonomy and LLM-Augmented Detection
Pipeline for Ethereum Vulnerabilities. 2026.
```

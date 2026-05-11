# Trace-Based Vulnerability Taxonomy

Quick reference for the taxonomy used to label all contracts in **evm-trace-dataset**. This taxonomy was developed as part of the **TRACE** (Trace-based Reasoning for Automated Contract Examination) project. For the full formal derivation, completeness argument, and prior taxonomy comparison, see the accompanying paper.

---

## Operation Type System

The taxonomy is defined over 11 operation types grounded in the EVM instruction set [Wood, 2014]. Each type represents a distinct class of EVM-observable behavior with an independent security implication.

| Type | Description | Status |
|---|---|---|
| CHECK | Guard condition — `require()`, `if()`, modifier | Implemented |
| WRITE | State variable modification via assignment | Implemented |
| CALL | External call — `.call{}`, `.send()`, `.transfer()` | Implemented |
| DELEGATECALL | Proxy call executing in caller's storage context | Implemented |
| READ | Environment or state read — `block.timestamp`, `tx.origin`, oracle calls | Future work |
| EMIT | Event emission after state change | Future work |
| SELFDESTRUCT | Contract termination and ETH forwarding | Future work |
| STATICCALL | Read-only external call | Future work |
| TRANSFER | Value-bearing call distinguished from generic CALL | Future work |
| DELETE | State removal via `delete` | Future work |
| REVERT | Explicit termination — `revert()`, `assert()` | Future work |

---

## Vulnerability Classes

### Class 1 — Operation Ordering Violations

The attacker exploits a window created by two operations appearing in the wrong sequence. The precondition is an observable ordering in the trace: a sensitive operation occurs before a state update that should have preceded it.

### Class 2 — Guard Absence Violations

The attacker walks through a path with no CHECK before a sensitive operation. The precondition is the absence of a CHECK in the trace.

### Class 3 — State Visibility Violations

The attacker poisons what the contract reads from the environment before the contract acts on it. The precondition is a READ whose value is adversary-influenceable. Detection requires extending the behavior extractor to emit READ operations.

---

## Taxonomy IDs

### Class 1 — Operation Ordering Violations

| ID | Vulnerability | Precondition | Attack Vector | Op Types | IR Signal | TRACE Status | Dataset |
|---|---|---|---|---|---|---|---|
| 1.1 | Reentrancy (value transfer) | CALL → WRITE | Malicious fallback re-enters before balance update | CALL, TRANSFER, WRITE | `cei_safe_order = False` | Implemented | ✅ |
| 1.2 | Reentrancy (state only) | CALL → WRITE (no value) | Malicious fallback manipulates state before WRITE | CALL, WRITE | `cei_safe_order = False` | Implemented | ✅ |
| 1.3 | Delegatecall state corruption | DELEGATECALL → WRITE | Attacker-controlled target overwrites storage | DELEGATECALL, WRITE | `has_delegatecall = True` + WRITE follows | Implemented | ✅ |
| 1.4 | DoS via external call | CALL before REVERT path | Malicious fallback blocks state advancement | CALL, WRITE, REVERT | `has_external_call = True`, no revert guard | Implemented | ✅ |
| 1.5 | Silent termination | SELFDESTRUCT before EMIT | Contract terminates without event trace | SELFDESTRUCT, EMIT | SELFDESTRUCT with no prior EMIT | Future work | ⚠️ |

**Note on 1.1 / 1.2:** Reentrancy is split by whether ETH value is transferred. 1.1 involves a value-bearing CALL (balance drain); 1.2 exploits state-only re-entry with no ETH transfer. The structural precondition is identical (CALL → WRITE); the op type signature distinguishes them.

**Note on 1.5:** No corresponding entry exists in SWC, OpenSCV, or Iuliano & Di Nucci (2026). This ID represents a structurally possible operation sequence pattern derived from EVM semantics. Practical exploitability is an open empirical question.

---

### Class 2 — Guard Absence Violations

| ID | Vulnerability | Precondition | IR Signal | TRACE Status | Dataset |
|---|---|---|---|---|---|
| 2.1 | Access control bypass | No CHECK(msg.sender) before WRITE/CALL | `has_auth_check = False` | Implemented | ✅ |
| 2.2 | Unprotected delegatecall | No CHECK(target) before DELEGATECALL | `has_auth_check = False` + DELEGATECALL | Implemented | ✅ |
| 2.3 | Missing input/return validation | No CHECK(amount/address/return) before WRITE | `has_zero_address_check = False` or `has_amount_check = False` | Implemented | ✅ |
| 2.4 | Unprotected selfdestruct | No CHECK(owner) before SELFDESTRUCT | No CHECK before SELFDESTRUCT | Future work | ✅ |
| 2.5 | Unguarded state deletion | No CHECK(authorization) before DELETE | No CHECK before DELETE | Future work | ⚠️ |

**Note on 2.5:** No corresponding entry exists in SWC, OpenSCV, or Iuliano & Di Nucci (2026). Same status as 1.5 — structurally possible, empirically unconfirmed.

---

### Class 3 — State Visibility Violations

| ID | Vulnerability | Precondition | IR Signal | TRACE Status | Dataset |
|---|---|---|---|---|---|
| 3.1 | Timestamp / block dependency | READ(block attributes) → CHECK/WRITE | READ emission required | Future work | ✅ |
| 3.2 | tx.origin misuse | READ(tx.origin) → CHECK | READ emission required | Future work | ✅ |
| 3.3 | Price oracle manipulation | READ(external price) → WRITE | READ emission required | Future work | ✅ |
| 3.4 | Stale state read | READ(state var) → WRITE | READ emission required | Future work | ⚠️ |

---

## Scope Boundary

The taxonomy covers vulnerabilities expressible as operation sequence patterns over EVM-observable behaviors. Six categories fall outside this boundary by design:

| Exclusion Category | Examples |
|---|---|
| Gas / resource consumption | DoS with block gas limit, gas-costly loops |
| Arithmetic errors | Integer overflow/underflow, division errors |
| Mempool-level vulnerabilities | Front-running, transaction ordering dependence |
| Compiler / language-level issues | Visibility errors, deprecated syntax, pragma issues |
| External state manipulation | Forced ETH via SELFDESTRUCT, pre-sent ETH |
| Cryptographic verification | Signature replay, hash collisions, malleability |

---

## Mapping to Existing Taxonomies

| ID | SWC | OpenSCV | Notes |
|---|---|---|---|
| 1.1 | SWC-107 | ✓ | Both cover; all reentrancy variants collapsed here |
| 1.3 | SWC-112 (partial) | ✓ | SWC-112 conflates 1.3 and 2.2 — separated by precondition |
| 1.4 | SWC-113 | ✓ | Direct mapping |
| 1.5 | — | — | No prior entry — structurally possible, empirically unconfirmed |
| 2.1 | SWC-105 | ✓ | SWC splits across entries — unified here |
| 2.2 | SWC-112 (partial) | ✓ | Separated from 1.3 — SWC conflates both |
| 2.3 | SWC-104 | ✓ | SWC-104 covers unchecked call return only — broader here |
| 2.4 | SWC-106 | ✓ | Direct mapping |
| 2.5 | — | — | No prior entry — structurally possible, empirically unconfirmed |
| 3.1 | SWC-116 | ✓ | Direct mapping |
| 3.2 | SWC-115 | ✓ | Direct mapping |
| 3.3 | — | ✓ | No SWC entry; OpenSCV covers |
| 3.4 | — | — | No prior entry |

---

## References

- G. Wood. *Ethereum: A Secure Decentralised Generalised Transaction Ledger.* Ethereum Yellow Paper, 2014.
- Smart Contract Security. *SWC Registry.* 2020. https://swcregistry.io
- F. R. Vidal, N. Ivaki, N. Laranjeiro. *OpenSCV: An Open Hierarchical Taxonomy for Smart Contract Vulnerabilities.* Empirical Software Engineering, 2024.
- G. Iuliano, D. Di Nucci. *Smart Contract Vulnerabilities, Tools, and Benchmarks: An Updated Systematic Literature Review.* Journal of Systems and Software, 2026.

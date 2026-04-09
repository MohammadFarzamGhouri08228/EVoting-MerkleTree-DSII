# E-VoteVerify+
### A Merkle-Tree Based Tamper-Evident Voting Verification System

> **This project is not merely a voting application; it is a study of tamper-evident data structures for secure verification.**

Developed as a **Data Structures II** final project. The focus is on applying core DS concepts — hash tables and Merkle trees — to build a system where any voter can cryptographically verify their ballot was counted, without exposing anyone else's vote.

---

## Project Idea

A voter casts a ballot. The ballot gets hashed and stored as a leaf in a global Merkle Tree. The voter receives a receipt ID. Later, they can use that receipt ID to:

1. Generate a **Merkle proof** — the set of sibling hashes along the path from their ballot to the root
2. **Verify** that proof by recomputing the root and comparing it to the public root
3. Detect **tampering** — if any ballot is modified, the root changes and old proofs break

This demonstrates two fundamental data structures working together:

| Data Structure | Role in This Project |
|---|---|
| Hash Table / Dictionary | Voter registry, receipt-to-index lookup, duplicate vote prevention |
| Merkle Tree | Stores all ballot hashes, generates inclusion proofs, detects tampering |

---

## Core Data Structures & Complexity

### Hash Table (Voter Registry)
- Insert voter: **O(1)** average
- Check if already voted: **O(1)** average
- Look up ballot index by receipt ID: **O(1)** average

### Merkle Tree
- Build tree from n ballots: **O(n)**
- Generate inclusion proof: **O(log n)**
- Verify proof: **O(log n)**
- Tamper propagation up the tree: **O(log n)**

---

## Features

- Voter registration simulation
- Vote casting with duplicate prevention
- Ballot hashing using SHA-256 (receipt ID + candidate + salt + timestamp)
- Global Merkle Tree construction (one tree for all ballots)
- Merkle proof generation by receipt ID
- Merkle proof verification (recomputes root from proof)
- Tampering simulation and detection
- Terminal visualization of tree levels and proof path
- Scripted demo for presentation
- Basic test suite

---

## Proposed Feature Additions: MMR and SMT

To enhance the scalability and real-time capabilities of E-VoteVerify, we propose implementing a **Merkle Mountain Range (MMR)** to transition the vote log toward an append-only streaming architecture. Unlike a standard Merkle tree that is most natural for fixed batches, an MMR dynamically merges balanced subtrees as new ballots arrive. This gives the system amortized **O(1)** append work while preserving **O(log n)** proof generation and verification.

In parallel, we propose integrating a **Sparse Merkle Tree (SMT)** for voter eligibility management. The current hash-table-based registry is efficient, but it cannot generate a cryptographic proof that a voter token is absent from the roll. An SMT enables both **proof of inclusion** and **proof of non-inclusion**, allowing the system to prove that a token exists or does not exist in the committed voter registry using a logarithmic hash path.

### Why these additions matter

- **MMR** enables continuous vote ingestion without rebuilding the full tree after every append
- **MMR** supports historical-state verification by preserving append-only commitment history
- **SMT** upgrades voter eligibility from a trusted boolean lookup to a verifiable cryptographic commitment
- **SMT** makes invalid-voter rejection auditable through non-inclusion proofs

### Expected algorithmic value

| Area | Current structure | Proposed structure | Benefit |
|---|---|---|---|
| Vote ingestion | Standard Merkle tree | MMR | Amortized **O(1)** append |
| Vote proof | Merkle inclusion proof | MMR inclusion proof | Maintains **O(log n)** verification |
| Eligibility lookup | Hash table boolean check | SMT inclusion/non-inclusion proof | Adds cryptographic auditability |
| Invalid voter handling | "Not found" result | SMT non-inclusion proof | Tamper-evident rejection logic |

---

## File Structure

```
EVoting-MerkleTree-DSII/
│
├── main.py              # Entry point — launches CLI or demo
├── votingsystem.py      # Central controller — orchestrates all workflows
├── merkletree.py        # Merkle Tree implementation (build, proof, verify, visualize)
├── ballot.py            # Ballot class — hashing and record representation
├── voter_registry.py    # Hash table layer — voter storage and receipt-to-index mapping
├── utils.py             # SHA-256 helper, salt generator, timestamp, formatting
├── demo.py              # Scripted demo scenario for presentation
│
├── data/                # Optional sample voter/ballot datasets (JSON)
├── tests/               # Unit tests for each module
└── README.md
```

---

## Demo Workflow

```
1. Register sample voters
2. Cast votes (each creates a hashed ballot)
3. Build the global Merkle Tree from all ballot hashes
4. Display the root hash
5. Select one receipt ID
6. Generate and display the Merkle proof path
7. Verify the proof — confirm it matches the root
8. Tamper with one ballot
9. Show that verification now fails / root has changed
```

---

## How to Run

```bash
python main.py
```

Or run the scripted demo directly:

```bash
python demo.py
```

---

## Development Plan

The next development cycle is divided into **6 phases** across **4 team members** so the current system can be extended with MMR and SMT in a controlled way.

---

## Phase 1 - Architecture and Interface Freeze
**Goal:** Define shared interfaces and invariants before implementation begins.

**Owners:** Member 1 + Member 4

### Detailed subtasks
- [ ] Review the current vote-casting and verification flow in `votingsystem.py`
- [ ] Identify where the code assumes a single batch-built Merkle tree
- [ ] Define a common proof format for Merkle tree, MMR, and SMT verification outputs
- [ ] Define the public commitment format for:
  - vote log root / MMR root
  - voter registry root / SMT root
- [ ] Decide whether classic Merkle tree mode remains for comparison or is fully replaced
- [ ] Fix the SMT keying strategy using hashed voter tokens and a fixed-depth path
- [ ] Write invariants for append-only vote storage and proof-of-non-inclusion correctness

**Deliverable:** Short design specification with stable interfaces, proof schema, and module boundaries.

---

## Phase 2 - Merkle Mountain Range Implementation
**Goal:** Add append-only vote commitment support using an MMR.

**Owner:** Member 1

### Detailed subtasks
- [ ] Create `mmr.py` with an `MMR` class
- [ ] Implement peak tracking and subtree merge logic
- [ ] Implement `append(leaf_hash)` with repeated merges of equal-height peaks
- [ ] Implement root aggregation logic for publishing a single commitment
- [ ] Implement `get_peaks()` for debugging and presentation
- [ ] Implement `generate_proof(leaf_index)` for MMR inclusion proofs
- [ ] Implement `verify_proof(leaf_hash, proof, root)` for independent verification
- [ ] Test edge cases:
  - empty MMR
  - one leaf
  - odd/even append sequences
  - proof validity after additional appends

**Deliverable:** Working MMR module with append, root generation, and proof support.

---

## Phase 3 - Sparse Merkle Tree Implementation
**Goal:** Add cryptographic voter eligibility management with inclusion and non-inclusion proofs.

**Owner:** Member 2

### Detailed subtasks
- [ ] Create `smt.py` with a `SparseMerkleTree` class
- [ ] Precompute default empty hashes for each tree depth
- [ ] Implement token-to-bitpath conversion using SHA-256
- [ ] Implement `insert(voter_token)` for eligible voter registration
- [ ] Implement `generate_inclusion_proof(voter_token)`
- [ ] Implement `generate_non_inclusion_proof(voter_token)`
- [ ] Implement inclusion and non-inclusion proof verification methods
- [ ] Export the SMT root for publication and audit
- [ ] Test edge cases:
  - empty tree
  - first insertion
  - long shared prefixes
  - absent-token verification

**Deliverable:** SMT module capable of proving voter presence or absence in the committed registry.

---

## Phase 4 - System Integration
**Goal:** Connect MMR and SMT to the existing election workflow.

**Owner:** Member 3

### Detailed subtasks
- [ ] Refactor `votingsystem.py` so vote commitment storage is separate from voter eligibility checks
- [ ] Replace batch tree rebuild flow with streaming MMR appends during `cast_vote(...)`
- [ ] Integrate SMT-backed eligibility validation before a vote is accepted
- [ ] Store receipt metadata so each receipt maps to an MMR leaf index
- [ ] Add support for publishing:
  - MMR root for vote-log commitment
  - SMT root for voter-roll commitment
- [ ] Add verification methods for:
  - vote inclusion proof
  - voter inclusion proof
  - voter non-inclusion proof
- [ ] Preserve the current demo flow where possible so comparison remains easy

**Deliverable:** End-to-end voting workflow backed by MMR for votes and SMT for voter eligibility.

---

## Phase 5 - CLI, Demo, and Visualization
**Goal:** Make the new structures easy to present and inspect.

**Owner:** Member 4

### Detailed subtasks
- [ ] Update the CLI to display current MMR and SMT roots
- [ ] Add commands to inspect MMR peaks and proof paths
- [ ] Add commands to inspect SMT inclusion/non-inclusion proofs
- [ ] Build a presentation-ready demo that shows:
  - voter registration into SMT
  - vote streaming into MMR
  - successful inclusion verification
  - failed eligibility check with non-inclusion proof
- [ ] Add clean terminal output and screenshots for documentation

**Deliverable:** Demo-ready interface and visualization layer for the new cryptographic structures.

---

## Phase 6 - Testing, Benchmarking, and Documentation
**Goal:** Validate correctness and document the algorithmic improvements clearly.

**Owners:** All 4 members

### Detailed subtasks
- [ ] Write unit tests for MMR append, merge, root, and proof behavior
- [ ] Write unit tests for SMT insertion, inclusion proof, and non-inclusion proof behavior
- [ ] Write integration tests for end-to-end voting with MMR + SMT enabled
- [ ] Add regression tests if the original Merkle-tree mode is retained
- [ ] Benchmark:
  - standard Merkle rebuild vs MMR append
  - hash-table lookup vs SMT proof generation
- [ ] Update `README.md` and report material with:
  - complexity comparison table
  - architecture summary
  - historical-state verification explanation
  - proof-of-non-inclusion explanation
- [ ] Run a final review pass on naming, comments, and edge cases

**Deliverable:** Tested, benchmarked, and fully documented upgraded project.

---

## Team Responsibilities Summary

| Member | Primary Focus | Supporting Focus | Deliverables |
|---|---|---|---|
| Member 1 | MMR design and implementation | Architecture review | `mmr.py`, append logic, MMR proofs |
| Member 2 | SMT design and implementation | Proof verification review | `smt.py`, inclusion/non-inclusion proofs |
| Member 3 | Integration into voting workflow | Integration tests | `votingsystem.py` refactor, receipt-index mapping |
| Member 4 | CLI, demo, and documentation | Interface planning | visualization, demo flow, README/report updates |

### Coordination notes
- Member 1 and Member 2 should align early on proof object structure so verification APIs stay consistent
- Member 3 should begin integration only after Phase 1 interfaces are frozen
- Member 4 can start CLI/documentation scaffolding early and plug in real outputs as modules stabilize
- All 4 members should own tests for their module first, then cross-review each other's work in Phase 6

---

## Technologies Used

- **Python 3.x** — no external libraries required
- `hashlib` — SHA-256 ballot hashing
- `time` / `uuid` — timestamps and receipt ID generation
- `random` / `secrets` — salt generation
- Built-in `dict` — hash table for voter registry

---

## Academic Context

This project was built for **Data Structures II** to demonstrate:

- How a **hash table** enables O(1) voter and receipt lookups
- How a **Merkle tree** enables O(log n) tamper-evident inclusion proofs
- How combining these two structures creates a verifiable, integrity-preserving data pipeline

The focus is entirely on the data structure design and algorithm correctness, not on building a production-ready election platform.

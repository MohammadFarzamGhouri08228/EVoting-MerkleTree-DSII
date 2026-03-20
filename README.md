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

The project is divided into **5 phases** across **3 team members**.

---

## Phase 1 — Foundation & Data Layer
**Goal:** Establish core data representations and utility functions.

**Owner: Team Member 1**

### Steps:
- [ ] Set up project folder structure (all files, empty stubs)
- [ ] Implement `utils.py`
  - SHA-256 hash helper function
  - Random salt generator
  - Timestamp generator
  - Pretty-print formatting helpers
- [ ] Implement `ballot.py`
  - `Ballot` class with fields: `receipt_id`, `candidate`, `salt`, `timestamp`
  - `to_string()` — canonical string representation for hashing
  - `to_hash()` — SHA-256 hash of the ballot string
  - `to_dict()` — for display and serialization
- [ ] Implement `voter_registry.py`
  - `VoterRegistry` class backed by Python dictionaries (hash tables)
  - `register_voter(voter_id)` — add a voter as eligible
  - `has_voted(voter_id)` — check duplicate vote
  - `mark_voted(voter_id)` — update voter status
  - `store_receipt(receipt_id, ballot_index)` — map receipt to position
  - `get_ballot_index(receipt_id)` — O(1) lookup
  - Comments explaining hash table behavior and O(1) complexity

**Deliverable:** Working `ballot.py`, `voter_registry.py`, and `utils.py` with a small test script confirming ballot hashing and registry lookups work correctly.

---

## Phase 2 — Merkle Tree Construction
**Goal:** Implement the full Merkle Tree from scratch.

**Owner: Team Member 2**

### Steps:
- [ ] Implement `merkletree.py`
  - `MerkleTree` class
  - Accept a list of leaf hashes on initialization
  - `build()` — construct tree bottom-up, level by level, store all levels
  - `get_root()` — return the final root hash
  - Handle odd number of leaves (duplicate last leaf)
  - `print_tree()` — display all levels in a readable terminal format
  - Comment each method with its time complexity

**Example terminal output for `print_tree()`:**
```
Level 0 (Root):
  [ABCD1234...]

Level 1:
  [AAA...] [BBB...]

Level 2 (Leaves):
  [h0] [h1] [h2] [h3]
```

**Deliverable:** `merkletree.py` that correctly builds a tree from sample hashes and prints all levels clearly.

---

## Phase 3 — Proof Generation & Verification
**Goal:** Implement Merkle proof generation, verification, and proof visualization.

**Owner: Team Member 3**

### Steps:
- [ ] Add `generate_proof(leaf_index)` to `MerkleTree`
  - Walk up from the leaf level to the root
  - At each level, collect the sibling hash and its direction (`left` or `right`)
  - Return a list of `(sibling_hash, direction)` tuples
- [ ] Add `verify_proof(leaf_hash, proof, root)` to `MerkleTree`
  - Recompute the root by combining `leaf_hash` with each sibling in order
  - Return `True` if the result matches `root`, `False` otherwise
- [ ] Add `print_proof_path(receipt_id, proof)` to visualization
  - Display the ballot being verified
  - Show each step: current hash + sibling hash → combined → next hash
  - Mark the final result as MATCH or MISMATCH

**Example proof path output:**
```
Verifying receipt: RCP-00042
  Step 1: [ballot_hash] + [sibling] → [parent_hash]
  Step 2: [parent_hash] + [sibling] → [grandparent_hash]
  Step 3: [grandparent_hash] + [sibling] → [root_hash]
Result: ROOT MATCH — Vote verified successfully.
```

**Deliverable:** Working proof generation and verification methods, plus clear terminal visualization of the proof path.

---

## Phase 4 — System Integration & CLI
**Goal:** Connect all modules together into a working system with a usable interface.

**Owner: Team Member 1 + Team Member 2 (joint)**

### Steps:
- [ ] Implement `votingsystem.py`
  - `VotingSystem` class
  - `register_voter(voter_id)` — delegates to `VoterRegistry`
  - `cast_vote(voter_id, candidate)` — creates `Ballot`, hashes it, stores receipt
  - `build_tree()` — collects all ballot hashes, builds `MerkleTree`
  - `generate_proof(receipt_id)` — looks up ballot index, delegates to `MerkleTree`
  - `verify_vote(receipt_id)` — runs proof, prints result
  - `tamper_vote(receipt_id, new_candidate)` — modifies a ballot, rebuilds or marks dirty
  - `display_summary()` — show vote counts and root hash
- [ ] Implement `main.py`
  - Simple numbered menu: Register / Vote / Build Tree / Verify / Tamper / Demo / Quit
  - Handles user input and calls `VotingSystem` methods
  - Clear section headers for readability during demo

**Deliverable:** Fully integrated system that can be run with `python main.py` and supports all core operations interactively.

---

## Phase 5 — Demo, Tests & Documentation
**Goal:** Polish the project for submission and live presentation.

**Owner: Team Member 3 (primary) + all for review**

### Steps:
- [ ] Implement `demo.py`
  - Hardcoded scenario: 5 voters, 5 votes, 2 candidates
  - Automatically builds tree, picks one receipt, generates proof, verifies it
  - Then tampers with a ballot and shows verification failure
  - Designed to be run from start to finish in under 2 minutes during demo
- [ ] Write tests in `tests/`
  - `test_ballot.py` — hashing consistency, field storage
  - `test_voter_registry.py` — insert, lookup, duplicate detection
  - `test_merkletree.py` — tree build, root correctness, odd leaf count
  - `test_proof.py` — proof generation, verification pass/fail, tamper detection
- [ ] Add complexity comments to all key methods
- [ ] Finalize `README.md`
  - Update with actual usage examples
  - Include sample terminal output screenshots
  - Write complexity table (final version)
- [ ] Code cleanup and review pass (all 3 members)

**Deliverable:** A clean, demo-ready project with passing tests, full README, and a scripted demo that clearly illustrates every core concept.

---

## Team Responsibilities Summary

| Phase | Focus | Owner |
|---|---|---|
| Phase 1 | Ballot, Voter Registry, Utils | Member 1 |
| Phase 2 | Merkle Tree construction + visualization | Member 2 |
| Phase 3 | Proof generation, verification, path display | Member 3 |
| Phase 4 | VotingSystem integration + CLI | Member 1 & 2 |
| Phase 5 | Demo script, tests, README polish | Member 3 (+ all review) |

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

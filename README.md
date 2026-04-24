# E-VoteVerify+
### A Merkle-Tree Based Tamper-Evident Voting Verification System

> **This project is not merely a voting application; it is a study of tamper-evident data structures for secure verification.**

**Language:** C++17 (no external libraries — standard library only)
**Course:** Data Structures II — Final Project
**Team:** 3 members

---

## Project Idea

A voter casts a ballot. The ballot is hashed with SHA-256 and stored as a leaf in a global Merkle Tree. The voter receives a receipt ID. Later, they can use that receipt ID to:

1. **Generate a Merkle proof** — the set of sibling hashes along the path from their ballot to the root
2. **Verify** that proof by recomputing the root and comparing it to the public root
3. **Detect tampering** — if any ballot is modified, the root changes and old proofs break

This demonstrates two fundamental data structures working together:

| Data Structure | Role in This Project |
|---|---|
| Hash Table (`std::unordered_map`) | Voter registry, receipt-to-index lookup, duplicate vote prevention |
| Merkle Tree (custom implementation) | Stores all ballot hashes, generates inclusion proofs, detects tampering |

---

## Core Data Structures & Complexity

### Hash Table (Voter Registry)
| Operation | Complexity |
|---|---|
| Register voter | O(1) average |
| Check if already voted | O(1) average |
| Look up ballot index by receipt ID | O(1) average |

### Merkle Tree
| Operation | Complexity |
|---|---|
| Build tree from n ballots | O(n) |
| Generate inclusion proof | O(log n) |
| Verify proof | O(log n) |
| Tamper propagation | O(log n) |

---

## Features

- Voter registration with duplicate prevention
- Vote casting with per-ballot SHA-256 hashing (receipt + voter + candidate + salt + timestamp)
- Global Merkle Tree construction (one tree for all ballots, not per-candidate)
- Merkle proof generation by receipt ID
- Merkle proof verification (step-by-step root recomputation)
- Tampering simulation — modify a ballot, show root change, show proof failure
- Terminal visualization of tree levels and proof path
- Full CLI menu

---

## File Structure

```
EVoting-MerkleTree-DSII/
│
├── main.cpp              # CLI entry point — menu, user input, calls VotingSystem
├── voting_system.hpp     # Central controller — orchestrates all workflows
├── merkle_tree.hpp       # Merkle Tree: build, proof, verify, visualize
├── voter_registry.hpp    # Hash table layer: voter storage, receipt-to-index map
├── ballot.hpp            # Ballot struct: fields, canonical string, SHA-256 hash
├── sha256.hpp            # Self-contained SHA-256 (no external libraries)
│
├── votingsystem.py       # Legacy Python reference (original repo, superseded)
├── requirements.txt      # Python deps for legacy file only
└── README.md
```

---

## How to Build & Run

### Install a C++ compiler (Windows)

**Option A — MinGW-w64 (recommended for students):**
1. Download from https://winlibs.com or install via [MSYS2](https://www.msys2.org/)
2. Add the `bin` folder to your system PATH
3. Verify: `g++ --version`

**Option B — Visual Studio:**
1. Install [Visual Studio Community](https://visualstudio.microsoft.com/) with the "Desktop development with C++" workload
2. Open a "Developer Command Prompt" and use `cl` instead of `g++`

### Compile

```bash
g++ -std=c++17 -O2 -o evoteverify main.cpp
```

With MSVC:
```bash
cl /std:c++17 /EHsc /O2 /Fe:evoteverify.exe main.cpp
```

### Run

```bash
./evoteverify        # Linux / macOS
evoteverify.exe      # Windows
```

---

## Demo Workflow

```
1.  Register 4-5 voters          (option 1, repeated)
2.  Cast votes                   (option 2, repeated)
3.  Build Merkle Tree            (option 3)
4.  Display tree levels          (option 4)
5.  Copy one receipt ID          (option 8)
6.  Verify vote — proof PASSES   (option 5)
7.  Tamper with that ballot      (option 6)
8.  Verify vote — proof FAILS    (option 5, same receipt)
9.  Display updated summary      (option 7)
```

---

## Development Plan

The project is divided into **5 phases** across **3 team members**.

---

## Phase 1 — Foundation & Data Layer ✅ Complete
**Goal:** Core data representations and utility functions.

**Owner: Member 1**

| Task | Status |
|---|---|
| Project folder structure and file stubs | Done |
| `sha256.hpp` — self-contained SHA-256 (no libraries) | Done |
| `ballot.hpp` — Ballot struct with `to_hash()`, `to_canonical()`, `to_display()` | Done |
| `voter_registry.hpp` — hash table layer (two `unordered_map` instances) | Done |

---

## Phase 2 — Merkle Tree Construction ✅ Complete
**Goal:** Full Merkle Tree implementation from scratch.

**Owner: Member 2**

| Task | Status |
|---|---|
| `merkle_tree.hpp` — `MerkleTree` class | Done |
| `build()` — bottom-up construction, O(n), handles odd leaf counts | Done |
| `get_root()` — returns root hash | Done |
| `print_tree()` — terminal display of all levels | Done |

---

## Phase 3 — Proof Generation & Verification ✅ Complete
**Goal:** Merkle proof pipeline with visual output.

**Owner: Member 3**

| Task | Status |
|---|---|
| `generate_proof(leaf_index)` — O(log n) sibling collection | Done |
| `verify_proof(leaf_hash, proof, root)` — O(log n) root recomputation | Done |
| `print_proof_path()` — step-by-step terminal visualization | Done |

---

## Phase 4 — System Integration & CLI 🔄 In Progress
**Goal:** Wire all modules together into a usable CLI program.

**Owner: Member 1 & Member 2 (joint)**

| Task | Status |
|---|---|
| `voting_system.hpp` — `VotingSystem` class wiring all modules | Done |
| `register_voter()`, `cast_vote()`, `build_tree()` methods | Done |
| `verify_vote()`, `tamper_vote()`, `display_summary()` methods | Done |
| `main.cpp` — numbered menu, user input handling | Done |
| End-to-end testing of full workflow | Pending |
| Edge case handling (empty tree, bad receipt ID, etc.) | Pending |

---

## Phase 5 — Demo, Tests & Documentation 📋 Pending
**Goal:** Polish for submission and live presentation.

**Owner: Member 3 (primary) + all review**

| Task | Status |
|---|---|
| `demo.cpp` — scripted scenario (hardcoded voters, votes, tamper, verify) | Pending |
| `tests/test_ballot.cpp` — hashing consistency, field storage | Pending |
| `tests/test_voter_registry.cpp` — insert, lookup, duplicate detection | Pending |
| `tests/test_merkle_tree.cpp` — build, root, odd leaves, proof correctness | Pending |
| Complexity comments review across all files | Pending |
| README sample output screenshots | Pending |
| Final code review pass (all 3 members) | Pending |

---

## Team Responsibilities Summary

| Phase | Focus | Owner |
|---|---|---|
| Phase 1 | SHA-256, Ballot, Voter Registry | Member 1 |
| Phase 2 | Merkle Tree construction + print | Member 2 |
| Phase 3 | Proof generation, verification, visualization | Member 3 |
| Phase 4 | VotingSystem integration + CLI | Member 1 & 2 |
| Phase 5 | Demo script, tests, README polish | Member 3 + all review |

---

## Technologies

- **C++17** — all implementation
- `std::unordered_map` — hash table for voter registry and receipt map
- `std::vector` — dynamic storage for tree levels and ballot list
- `std::string`, `<sstream>`, `<iomanip>` — SHA-256 output formatting
- `<random>`, `<chrono>` — salt and timestamp generation
- No external libraries required

---

## Academic Context

This project was built for **Data Structures II** to demonstrate:

- How a **hash table** enables O(1) voter and receipt lookups
- How a **Merkle tree** enables O(log n) tamper-evident inclusion proofs
- How combining these two structures creates a verifiable, integrity-preserving data pipeline

The focus is entirely on the data structure design and algorithm correctness, not on building a production-ready election platform.

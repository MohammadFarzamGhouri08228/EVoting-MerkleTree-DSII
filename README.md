# E-VoteVerify+

This project is a DSII voting verification system built around hashed ballots and tamper-evident data structures. A vote is turned into a SHA-256 leaf, stored in a Merkle-based structure, and later verified by recomputing the path back to the published root.

## Project Idea

The goal of the project is to show how data structures can be used to protect vote integrity.

- The main voting flow uses a **Merkle Tree** to store ballot hashes, generate inclusion proofs, and detect tampering when any ballot changes.
- The live simulation uses an **MMR (Merkle Mountain Range)** to support append-heavy voting activity while still producing verifiable roots and proof paths.
- The voter-status side uses a **Sparse Merkle Tree**. If your notes call this **SSR**, this is the same part of the project: it tracks voter verification state in a sparse key space and allows proof-based checks before voting.

## Functionality

- Register voters and prevent duplicate voting
- Cast votes and hash each ballot
- Build and display the Merkle Tree
- Generate and verify Merkle proofs for a receipt
- Simulate tampering and show how verification fails
- Run a live browser visualization for the Merkle Tree, MMR, and Sparse Merkle Tree views

## Frontend and Backend

- **Backend:** The backend is written in C++17. It handles voter registration, ballot hashing, Merkle Tree logic, MMR simulation, Sparse Merkle Tree checks, proof generation, verification, and the local HTTP server used for visualization.
- **Frontend:** The frontend is the browser-based visualization layer served locally by the C++ backend. It displays the Merkle Tree, MMR simulation, proof paths, and live verification state through interactive web pages.

## Compile

### Main voting system

```powershell
g++ -std=c++17 -O2 -I. -o evoteverify.exe src/main.cpp src/ballot.cpp src/voter_registry.cpp src/merkle_tree.cpp src/live_visualization_server.cpp src/sha256.cpp -lws2_32
```

Run:

```powershell
.\evoteverify.exe
```

### MMR simulation

```powershell
g++ -std=c++17 -O2 -I. -Isim -o mmr_sim.exe src/main_sim.cpp src/mmr_simulation.cpp src/merkle_mountain_range.cpp src/sparse_merkle_tree.cpp src/sha256.cpp -lws2_32
```

Run:

```powershell
.\mmr_sim.exe
```

## Shortcut We Used

To compile and run everything more quickly, use:

```powershell
.\run_dashboard.bat
```

This launches `run_dashboard.ps1`, which:

- rebuilds `mmr_sim.exe` if its source files changed
- rebuilds `evoteverify_web.exe` if its source files changed
- starts the MMR simulator on `http://127.0.0.1:9090/`
- starts the visualization homepage on `http://127.0.0.1:8080/`
- opens the browser automatically

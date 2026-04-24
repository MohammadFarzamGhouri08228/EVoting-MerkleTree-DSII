#pragma once
// =============================================================================
// voting_system.hpp  —  Central controller / application logic
//
// VotingSystem wires together VoterRegistry, MerkleTree, and Ballot.
// It is the only class that main.cpp needs to touch.
//
// Merkle Tree operations used:
//   cast_vote()         → tree_.insert()      (adds one leaf node)
//   build_tree()        → tree_.build()       (full O(n) construction)
//   tamper_vote()       → tree_.update()      (O(log n) parent-pointer walk)
//   invalidate_ballot() → tree_.delete_leaf() (O(log n) parent-pointer walk)
//   verify_vote()       → tree_.generate_proof() + print_proof_path()
// =============================================================================
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <unordered_map>
#include <random>
#include <chrono>
#include <fstream>
#include "ballot.hpp"
#include "voter_registry.hpp"
#include "merkle_tree.hpp"

class VotingSystem {

    VoterRegistry       registry_;
    MerkleTree          tree_;
    std::vector<Ballot> ballots_;

    // Published election root snapshot: updated on build_tree(), each live
    // cast_vote() insert, invalidate_ballot(), and delete_ballot().
    // Intentionally NOT updated by tamper_vote() — voters who saved the old
    // root see a proof MISMATCH until officials publish a new snapshot (e.g.
    // by running build_tree() again, which re-commits to current ballots).
    std::string         last_built_root_;
    bool                tree_built_ = false;

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    static std::mt19937& rng() {
        static std::mt19937 gen(
            static_cast<unsigned>(
                std::chrono::steady_clock::now().time_since_epoch().count()
            )
        );
        return gen;
    }

    static std::string make_salt() {
        std::uniform_int_distribution<uint32_t> dist;
        std::ostringstream oss;
        oss << std::hex << std::setfill('0')
            << std::setw(8) << dist(rng())
            << std::setw(8) << dist(rng());
        return oss.str();
    }

    static std::string make_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto sec = std::chrono::duration_cast<std::chrono::seconds>(
                       now.time_since_epoch()).count();
        return std::to_string(sec);
    }

    static std::string make_receipt_id(const std::string& voter_id) {
        std::string seed = voter_id + make_salt() + make_timestamp();
        return "RCP-" + sha256(seed).substr(0, 12);
    }

    static std::string short_h(const std::string& h) {
        return (h.size() > 16) ? h.substr(0, 16) + "..." : h;
    }

    // Returns the hash that should represent this ballot in the Merkle Tree.
    // Valid ballots → their SHA-256 ballot hash.
    // Invalidated ballots → the sentinel hash (so the tree stays consistent
    //   when build_tree() is called after some ballots have been deleted).
    static std::string ballot_leaf_hash(const Ballot& b) {
        return b.valid ? b.to_hash() : MerkleTree::deleted_sentinel();
    }

public:

    // ------------------------------------------------------------------
    // Register a voter  —  O(1) average (hash table insert)
    // ------------------------------------------------------------------
    bool register_voter(const std::string& voter_id) {
        // ── Input validation ──────────────────────────────────────────
        if (voter_id.size() < 2) {
            std::cout << "  [!] Voter ID is too short (minimum 2 characters).\n";
            std::cout << "      Example IDs: V001, alice, voter_7\n";
            return false;
        }
        if (voter_id.find('|') != std::string::npos) {
            std::cout << "  [!] Voter ID must not contain the '|' character.\n";
            return false;
        }
        for (char c : voter_id) {
            if (std::isspace(static_cast<unsigned char>(c))) {
                std::cout << "  [!] Voter ID must not contain spaces.\n";
                std::cout << "      Tip: use underscores instead, e.g. \"john_doe\"\n";
                return false;
            }
        }

        // ── Duplicate check ───────────────────────────────────────────
        if (!registry_.register_voter(voter_id)) {
            bool already_voted = registry_.has_voted(voter_id);
            std::cout << "  [!] '" << voter_id << "' is already registered.\n";
            if (already_voted)
                std::cout << "      This voter has already cast their ballot.\n";
            else
                std::cout << "      This voter is registered but has not voted yet.\n"
                          << "      They may cast a vote using option 2.\n";
            return false;
        }

        // ── Success ───────────────────────────────────────────────────
        int total = registry_.voter_count();
        std::cout << "\n";
        std::cout << "  +-------- Registration Confirmed ----------------------------+\n";
        std::cout << "  |  Voter ID  : " << voter_id                                << "\n";
        std::cout << "  |  Status    : Eligible to vote                             |\n";
        std::cout << "  |  Registry  : " << total << " voter(s) now registered\n";
        std::cout << "  +------------------------------------------------------------+\n";
        std::cout << "  [>] Next: use option 2 to cast a vote for this voter.\n";
        return true;
    }

    // ------------------------------------------------------------------
    // Cast a vote  —  O(1) eligibility check + O(log n) / O(n) tree insert
    //
    // If the Merkle Tree is already built, the new ballot's hash is inserted
    // as a leaf node using tree_.insert(), which:
    //   - Takes O(log n) when the current leaf count is odd
    //     (attaches the new leaf as right child of the last "duplicated" leaf,
    //      then walks up via parent pointers recomputing each ancestor).
    //   - Takes O(n) when the current leaf count is even
    //     (full rebuild, because integrating a new "duplicate" subtree may
    //      restructure the entire right spine).
    //
    // If the tree has not been built yet, the ballot is queued and the tree
    // will be built in full on the next build_tree() call.
    // ------------------------------------------------------------------
    std::string cast_vote(const std::string& voter_id,
                          const std::string& candidate) {
        if (!registry_.is_registered(voter_id)) {
            std::cout << "  [!] '" << voter_id << "' is not registered.\n";
            return "";
        }
        if (registry_.has_voted(voter_id)) {
            std::cout << "  [!] '" << voter_id << "' has already voted.\n";
            return "";
        }

        Ballot b;
        b.voter_id   = voter_id;
        b.candidate  = candidate;
        b.salt       = make_salt();
        b.timestamp  = make_timestamp();
        b.receipt_id = make_receipt_id(voter_id);

        int index = static_cast<int>(ballots_.size());
        ballots_.push_back(b);

        registry_.mark_voted(voter_id);
        registry_.store_receipt(b.receipt_id, index);

        std::cout << "  [+] Vote cast  |  candidate: " << candidate
                  << "  |  receipt: " << b.receipt_id << "\n";
        std::cout << "      Ballot hash: " << short_h(b.to_hash()) << "\n";

        if (tree_built_) {
            // Tree is live — insert the new leaf incrementally using node pointers.
            int prev_count = tree_.leaf_count();
            tree_.insert(b.to_hash());
            last_built_root_ = tree_.get_root();

            bool was_log_n = (prev_count % 2 == 1);
            std::cout << "      Leaf inserted into Merkle Tree  ("
                      << (was_log_n ? "O(log n) — odd-count fast path"
                                    : "O(n) — even-count rebuild")
                      << ")\n";
            std::cout << "      New root: " << short_h(tree_.get_root()) << "\n";
        } else {
            std::cout << "      [Tree not yet built -- use option 3 to build]\n";
        }

        return b.receipt_id;
    }

    // ------------------------------------------------------------------
    // Build the global Merkle Tree from scratch  —  O(n)
    // ------------------------------------------------------------------
    void build_tree() {
        if (ballots_.empty()) {
            std::cout << "  [!] No ballots to build a tree from.\n";
            return;
        }

        std::vector<std::string> leaves;
        leaves.reserve(ballots_.size());
        for (const auto& b : ballots_)
            leaves.push_back(ballot_leaf_hash(b));   // sentinel for invalidated

        tree_.build(leaves);
        last_built_root_ = tree_.get_root();
        tree_built_      = true;

        std::cout << "  [+] Merkle Tree built  |  " << ballots_.size()
                  << " ballot(s)  |  levels: " << tree_.level_count() << "\n";
        std::cout << "      Root: " << tree_.get_root() << "\n";

        int tampered_n = 0;
        for (const auto& b : ballots_)
            if (b.valid && b.tampered) ++tampered_n;
        if (tampered_n > 0) {
            std::cout << "  [!] " << tampered_n << " ballot(s) marked [*** TAMPERED ***].\n";
            std::cout << "      This build sets a NEW published root that includes those changes.\n";
            std::cout << "      Option 5 will now MATCH for those ballots against this snapshot.\n";
        }
    }

    // ------------------------------------------------------------------
    // Load Dataset (Batch Registration and Voting)
    // ------------------------------------------------------------------
    void load_dataset(const std::string& filepath) {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            std::cout << "  [!] Failed to open dataset file: " << filepath << "\n";
            return;
        }

        std::string line;
        int registered_count = 0;
        int voted_count = 0;

        std::getline(file, line);   // skip header
        std::cout << "  [*] Loading dataset from " << filepath << "...\n";

        while (std::getline(file, line)) {
            if (line.empty()) continue;

            std::stringstream ss(line);
            std::string voter_id, candidate;

            if (std::getline(ss, voter_id, ',') && std::getline(ss, candidate)) {
                if (!candidate.empty() && candidate.back() == '\r')
                    candidate.pop_back();

                if (registry_.register_voter(voter_id))
                    registered_count++;

                if (!registry_.has_voted(voter_id)) {
                    Ballot b;
                    b.voter_id   = voter_id;
                    b.candidate  = candidate;
                    b.salt       = make_salt();
                    b.timestamp  = make_timestamp();
                    b.receipt_id = make_receipt_id(voter_id);

                    int index = static_cast<int>(ballots_.size());
                    ballots_.push_back(b);

                    registry_.mark_voted(voter_id);
                    registry_.store_receipt(b.receipt_id, index);
                    voted_count++;
                }
            }
        }

        tree_built_ = false;   // batch load: require explicit build_tree()

        std::cout << "  [+] Dataset loaded successfully!\n";
        std::cout << "      - Voters registered: " << registered_count << "\n";
        std::cout << "      - Votes cast:        " << voted_count << "\n";
        std::cout << "  [*] Don't forget to build the Merkle Tree (Option 3)!\n";
    }

    // ------------------------------------------------------------------
    // Verify a vote by receipt ID  —  O(log n)
    //
    // Generates a Merkle proof by walking UP via parent pointers, then
    // verifies it against last_built_root_.
    // If the ballot has been invalidated, the proof shows a MISMATCH
    // (the tree holds the sentinel hash, not the original ballot hash).
    // ------------------------------------------------------------------
    void verify_vote(const std::string& receipt_id) {
        if (!tree_built_) {
            std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
            return;
        }
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }

        const Ballot& b = ballots_[idx];

        if (!b.valid) {
            std::cout << "  [!] This ballot has been INVALIDATED by an election authority.\n";
            std::cout << "      Proof will show MISMATCH (sentinel hash vs. original hash).\n";
        }
        if (b.tampered) {
            std::cout << "  [!!!] This ballot is flagged [*** TAMPERED ***].\n";
            std::cout << "        The candidate field was altered after the tree was built.\n";
            std::cout << "        The proof below will show MISMATCH against the original root.\n";
        }

        // Leaf + proof follow the LIVE tree; last_built_root_ is the published
        // snapshot. After tamper_vote(), snapshot != live root → MISMATCH.
        std::string leaf  = b.to_hash();
        auto        proof = tree_.generate_proof(idx);
        bool ok = tree_.print_proof_path(receipt_id, leaf, proof, last_built_root_);

        if (!ok && b.tampered && b.valid) {
            std::cout << "  +------ Why this failed (tamper demo) -----------------------+\n";
            std::cout << "  | The ballot was changed after the published root snapshot.   |\n";
            std::cout << "  | Proof steps still combine to the LIVE tree root:            |\n";
            std::cout << "  |   " << short_h(tree_.get_root()) << "\n";
            std::cout << "  | but verification checks against the PUBLISHED snapshot:     |\n";
            std::cout << "  |   " << short_h(last_built_root_) << "\n";
            std::cout << "  | Holders of the old snapshot see MISMATCH = tamper detected. |\n";
            std::cout << "  +-------------------------------------------------------------+\n\n";
        }
    }

    // True iff Merkle proof for this receipt matches the published snapshot (no I/O).
    // For dry-run / tests: false after tamper_vote() until build_tree() refreshes snapshot.
    bool proof_matches_published_snapshot(const std::string& receipt_id) const {
        if (!tree_built_) return false;
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) return false;
        const Ballot& b = ballots_[idx];
        auto proof = tree_.generate_proof(idx);
        return MerkleTree::verify_proof(b.to_hash(), proof, last_built_root_);
    }

    // ------------------------------------------------------------------
    // Tamper simulation  —  O(log n) via tree_.update()
    // ------------------------------------------------------------------
    void tamper_vote(const std::string& receipt_id,
                     const std::string& new_candidate) {
        // ── Guards ────────────────────────────────────────────────────
        if (!tree_built_) {
            std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
            std::cout << "      The tree must exist so the tampered hash can propagate.\n";
            return;
        }
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }
        if (!ballots_[idx].valid) {
            std::cout << "  [!] Ballot is already invalidated -- cannot tamper.\n";
            return;
        }
        if (ballots_[idx].candidate == new_candidate) {
            std::cout << "  [!] New candidate is identical to the current one -- no change made.\n";
            return;
        }

        std::string old_root    = tree_.get_root();
        std::string orig_cand   = ballots_[idx].candidate;
        std::string orig_hash   = ballots_[idx].to_hash();

        std::cout << "\n";
        std::cout << "  +====== TAMPERING SIMULATION ===============================+\n";
        std::cout << "  | Target receipt  : " << receipt_id                       << "\n";
        std::cout << "  | Voter           : " << ballots_[idx].voter_id           << "\n";
        std::cout << "  | Original vote   : " << orig_cand                        << "\n";
        std::cout << "  | Original hash   : " << short_h(orig_hash)               << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        // ── Mutate the ballot in memory ───────────────────────────────
        if (!ballots_[idx].tampered)
            ballots_[idx].pre_tamper_candidate = ballots_[idx].candidate;
        ballots_[idx].candidate = new_candidate;
        ballots_[idx].tampered  = true;           // mark for all future displays

        std::cout << "  | Tampered vote   : " << ballots_[idx].candidate          << "\n";
        std::cout << "  | New hash        : " << short_h(ballots_[idx].to_hash()) << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | Propagating tampered hash up the tree via parent pointers...\n";

        // O(log n): mutates leaf node, then follows parent pointers upward.
        tree_.update(idx, ballots_[idx].to_hash());

        // Intentionally do NOT update last_built_root_ — the snapshot keeps
        // the pre-tamper root so verify_vote() correctly shows MISMATCH.
        std::string new_root = tree_.get_root();
        std::cout << "  | Old root (snapshot) : " << old_root  << "\n";
        std::cout << "  | New root (live)     : " << new_root  << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | [!!] TAMPER DETECTED: Root hash has CHANGED.\n";
        std::cout << "  |      This ballot is now flagged [*** TAMPERED ***].\n";
        std::cout << "  |      It will appear tagged in all receipt lists and summary.\n";
        std::cout << "  |      Run option 5 (Verify vote) on this receipt to see\n";
        std::cout << "  |      the proof MISMATCH that exposes the tampering.\n";
        std::cout << "  +===========================================================+\n\n";
    }

    // ------------------------------------------------------------------
    // Invalidate a ballot  —  O(log n) via tree_.delete_leaf()
    //
    // Marks the ballot as invalid, replaces its leaf node hash with the
    // sentinel value, then walks UP via parent pointers recomputing each
    // ancestor.  The leaf node STAYS in the tree at its original position,
    // preserving all other ballots' proofs.
    //
    // After invalidation:
    //   • The election root changes (detectable by anyone holding the old root).
    //   • verify_vote() on this ballot shows MISMATCH, proving invalidation.
    //   • The vote tally excludes this ballot.
    // ------------------------------------------------------------------
    void invalidate_ballot(const std::string& receipt_id) {
        if (!tree_built_) {
            std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
            return;
        }
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }
        if (!ballots_[idx].valid) {
            std::cout << "  [!] Ballot is already invalidated.\n";
            return;
        }

        std::string old_root = tree_.get_root();

        std::cout << "\n";
        std::cout << "  +====== BALLOT INVALIDATION ================================+\n";
        std::cout << "  | Receipt   : " << receipt_id                               << "\n";
        std::cout << "  | Voter     : " << ballots_[idx].voter_id                   << "\n";
        std::cout << "  | Candidate : " << ballots_[idx].candidate                  << "\n";
        std::cout << "  | Leaf hash : " << short_h(ballots_[idx].to_hash())         << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | Replacing leaf with sentinel & propagating via parent ptrs...\n";

        // Mark the Ballot struct as invalid
        ballots_[idx].valid     = false;
        ballots_[idx].tampered  = false;
        ballots_[idx].pre_tamper_candidate.clear();

        // O(log n): sets sentinel hash on leaf node, walks up via parent pointers
        tree_.delete_leaf(idx);

        last_built_root_ = tree_.get_root();   // root has changed — update snapshot

        std::cout << "  | Sentinel  : " << short_h(MerkleTree::deleted_sentinel()) << "\n";
        std::cout << "  | Old root  : " << old_root                                << "\n";
        std::cout << "  | New root  : " << last_built_root_                        << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | [OK] Ballot invalidated. Root has changed.\n";
        std::cout << "  |      Verify vote to confirm (MISMATCH expected).\n";
        std::cout << "  +===========================================================+\n\n";
    }

    // ------------------------------------------------------------------
    // Delete a ballot  --  O(log n) via tree_.delete_leaf()
    //
    // Similar to invalidate_ballot, but completely removes the vote AND
    // unmarks the voter so they can vote again.
    // ------------------------------------------------------------------
    void delete_ballot(const std::string& receipt_id) {
        if (!tree_built_) {
            std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
            return;
        }
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }
        if (!ballots_[idx].valid) {
            std::cout << "  [!] Ballot is already deleted or invalidated.\n";
            return;
        }

        std::string old_root = tree_.get_root();

        std::cout << "\n";
        std::cout << "  +====== BALLOT DELETION ====================================+\n";
        std::cout << "  | Receipt   : " << receipt_id                               << "\n";
        std::cout << "  | Voter     : " << ballots_[idx].voter_id                   << "\n";
        std::cout << "  | Candidate : " << ballots_[idx].candidate                  << "\n";
        std::cout << "  | Leaf hash : " << short_h(ballots_[idx].to_hash())         << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | 1. Freeing voter to vote again...\n";
        
        registry_.unmark_voted(ballots_[idx].voter_id);
        ballots_[idx].valid     = false;
        ballots_[idx].tampered  = false;
        ballots_[idx].pre_tamper_candidate.clear();

        std::cout << "  | 2. Nullifying leaf and updating tree via parent ptrs...\n";

        // O(log n): sets sentinel hash on leaf node, walks up via parent pointers
        tree_.delete_leaf(idx);

        last_built_root_ = tree_.get_root();   // root has changed — update snapshot

        std::cout << "  | Sentinel  : " << short_h(MerkleTree::deleted_sentinel()) << "\n";
        std::cout << "  | Old root  : " << old_root                                << "\n";
        std::cout << "  | New root  : " << last_built_root_                        << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | [OK] Ballot deleted. The voter may now cast a new vote.\n";
        std::cout << "  +===========================================================+\n\n";
    }

    // ------------------------------------------------------------------
    // Display a summary of the current election state.
    // ------------------------------------------------------------------
    void display_summary() const {
        std::unordered_map<std::string, int> tally;
        int valid_count    = 0;
        int invalid_count  = 0;
        int tampered_count = 0;

        for (const auto& b : ballots_) {
            if (b.valid) {
                tally[b.candidate]++;
                valid_count++;
                if (b.tampered) tampered_count++;
            } else {
                invalid_count++;
            }
        }

        std::cout << "\n";
        std::cout << "  +-------- Election Summary ----------------------------------+\n";
        std::cout << "  | Registered voters  : " << registry_.voter_count()         << "\n";
        std::cout << "  | Total ballots cast : " << ballots_.size()                 << "\n";
        std::cout << "  |   Valid            : " << valid_count                     << "\n";
        std::cout << "  |   Invalidated      : " << invalid_count                   << "\n";
        if (tampered_count > 0)
            std::cout << "  |   Tampered (demo)  : " << tampered_count
                      << "  <-- integrity compromised!\n";
        std::cout << "  | Vote tally (valid ballots — including any tampered ones):\n";
        for (const auto& kv : tally) {
            int tcount = 0;
            for (const auto& b : ballots_)
                if (b.valid && b.tampered && b.candidate == kv.first) ++tcount;
            std::cout << "  |   " << kv.first << " : " << kv.second << " vote(s)";
            if (tcount > 0)
                std::cout << "  (" << tcount << " tampered)  [*** TAMPERED ***]";
            std::cout << "\n";
        }
        if (tree_built_)
            std::cout << "  | Merkle root : " << tree_.get_root() << "\n";
        else
            std::cout << "  | Merkle root : (not yet built -- run option 3)\n";
        std::cout << "  +------------------------------------------------------------+\n\n";
    }

    // ------------------------------------------------------------------
    // Accessors / helpers for main.cpp
    // ------------------------------------------------------------------

    void print_tree()     const { tree_.print_tree(); }
    void print_registry() const { registry_.print_registry(); }

    bool is_tree_built() const { return tree_built_; }
    int  ballot_count()  const { return static_cast<int>(ballots_.size()); }

    // Returns all receipt IDs with status tags for display in the menu.
    struct ReceiptInfo {
        std::string receipt_id;
        std::string voter_id;
        std::string candidate;
        std::string pre_tamper_candidate;
        bool        valid;
        bool        tampered;
    };

    std::vector<ReceiptInfo> all_receipt_info() const {
        std::vector<ReceiptInfo> out;
        out.reserve(ballots_.size());
        for (const auto& b : ballots_)
            out.push_back({ b.receipt_id, b.voter_id, b.candidate,
                            b.pre_tamper_candidate, b.valid, b.tampered });
        return out;
    }

    bool receipt_info_for(const std::string& receipt_id, ReceiptInfo& out) const {
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) return false;
        const auto& b = ballots_[idx];
        out = { b.receipt_id, b.voter_id, b.candidate,
                b.pre_tamper_candidate, b.valid, b.tampered };
        return true;
    }

    // Plain receipt list (backward-compatible helper).
    std::vector<std::string> all_receipts() const {
        std::vector<std::string> out;
        out.reserve(ballots_.size());
        for (const auto& b : ballots_)
            out.push_back(b.receipt_id);
        return out;
    }
};

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

    // Root snapshot taken at the last build_tree() call (or after insert/
    // delete/update operations that keep the tree current).
    // Proofs are always verified against this snapshot so that tampering
    // (which changes the live root) is correctly detected.
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
        if (!registry_.register_voter(voter_id)) {
            std::cout << "  [!] '" << voter_id << "' is already registered.\n";
            return false;
        }
        std::cout << "  [+] Registered voter: " << voter_id << "\n";
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
            std::cout << "      [Tree not yet built — use option 3 to build]\n";
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

        // Use the original ballot hash as the claimed leaf content.
        // If the ballot was invalidated, the tree holds the sentinel instead,
        // so the proof will correctly fail — demonstrating delete_leaf() worked.
        std::string leaf  = b.to_hash();
        auto        proof = tree_.generate_proof(idx);
        tree_.print_proof_path(receipt_id, leaf, proof, last_built_root_);
    }

    // ------------------------------------------------------------------
    // Tamper simulation  —  O(log n) via tree_.update()
    // ------------------------------------------------------------------
    void tamper_vote(const std::string& receipt_id,
                     const std::string& new_candidate) {
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }
        if (!ballots_[idx].valid) {
            std::cout << "  [!] Ballot is already invalidated — cannot tamper.\n";
            return;
        }

        std::string old_root = tree_built_ ? tree_.get_root() : "(tree not built)";

        std::cout << "\n";
        std::cout << "  +====== TAMPERING SIMULATION ===============================+\n";
        std::cout << "  | Target receipt  : " << receipt_id                       << "\n";
        std::cout << "  | Original vote   : " << ballots_[idx].candidate          << "\n";
        std::cout << "  | Original hash   : " << short_h(ballots_[idx].to_hash()) << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        ballots_[idx].candidate = new_candidate;

        std::cout << "  | Tampered vote   : " << ballots_[idx].candidate          << "\n";
        std::cout << "  | New hash        : " << short_h(ballots_[idx].to_hash()) << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | Propagating tampered hash up the tree via parent pointers...\n";

        // O(log n): mutates leaf node, then follows parent pointers upward.
        tree_.update(idx, ballots_[idx].to_hash());

        std::string new_root = tree_.get_root();
        std::cout << "  | Old root : " << old_root << "\n";
        std::cout << "  | New root : " << new_root << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        if (old_root != new_root && old_root != "(tree not built)")
            std::cout << "  | [!!] TAMPER DETECTED: Root hash has CHANGED.\n";

        std::cout << "  |      Any proof generated against the old root is INVALID.\n";
        std::cout << "  |      Run 'Verify vote' again to confirm failure.\n";
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
        ballots_[idx].valid = false;

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
    // Display a summary of the current election state.
    // ------------------------------------------------------------------
    void display_summary() const {
        std::unordered_map<std::string, int> tally;
        int valid_count   = 0;
        int invalid_count = 0;

        for (const auto& b : ballots_) {
            if (b.valid) {
                tally[b.candidate]++;
                valid_count++;
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
        std::cout << "  | Vote tally (valid ballots only):\n";
        for (const auto& kv : tally)
            std::cout << "  |   " << kv.first << " : " << kv.second << " vote(s)\n";
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

    // Returns all receipt IDs with a status tag for display in the menu.
    struct ReceiptInfo {
        std::string receipt_id;
        bool        valid;
    };

    std::vector<ReceiptInfo> all_receipt_info() const {
        std::vector<ReceiptInfo> out;
        out.reserve(ballots_.size());
        for (const auto& b : ballots_)
            out.push_back({ b.receipt_id, b.valid });
        return out;
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

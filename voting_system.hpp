#pragma once
// =============================================================================
// voting_system.hpp  —  Central controller / application logic
//
// VotingSystem wires together VoterRegistry, MerkleTree, and Ballot.
// It is the only class that main.cpp (or demo.cpp) needs to touch.
//
// Workflow:
//   register_voter()  →  cast_vote()  →  build_tree()
//   →  verify_vote()  →  tamper_vote()  →  verify_vote()  (shows failure)
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

    // Root snapshot taken at the last build_tree() call.
    // Used to detect when tampering has changed the root.
    std::string         last_built_root_;
    bool                tree_built_ = false;

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    // Seed a Mersenne Twister once from the steady clock.
    static std::mt19937& rng() {
        static std::mt19937 gen(
            static_cast<unsigned>(
                std::chrono::steady_clock::now().time_since_epoch().count()
            )
        );
        return gen;
    }

    // 16-character random hex string used as a ballot salt.
    static std::string make_salt() {
        std::uniform_int_distribution<uint32_t> dist;
        std::ostringstream oss;
        oss << std::hex << std::setfill('0')
            << std::setw(8) << dist(rng())
            << std::setw(8) << dist(rng());
        return oss.str();
    }

    // Seconds since Unix epoch as a string.
    static std::string make_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto sec = std::chrono::duration_cast<std::chrono::seconds>(
                       now.time_since_epoch()).count();
        return std::to_string(sec);
    }

    // Receipt ID: "RCP-" + first 12 characters of SHA-256(voter_id + salt + time).
    static std::string make_receipt_id(const std::string& voter_id) {
        std::string seed = voter_id + make_salt() + make_timestamp();
        return "RCP-" + sha256(seed).substr(0, 12);
    }

    // Truncated hash for readable console output.
    static std::string short_h(const std::string& h) {
        return (h.size() > 16) ? h.substr(0, 16) + "..." : h;
    }

public:

    // ------------------------------------------------------------------
    // Register a voter
    // O(1) average — delegates to hash table insert
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
    // Cast a vote
    // Checks eligibility (O(1)), creates and stores a Ballot.
    // Returns the receipt ID string, or "" on failure.
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
        tree_built_ = false;   // tree must be rebuilt to reflect the new ballot

        std::cout << "  [+] Vote cast  |  candidate: " << candidate
                  << "  |  receipt: " << b.receipt_id << "\n";
        std::cout << "      Ballot hash: " << short_h(b.to_hash()) << "\n";
        return b.receipt_id;
    }

    // ------------------------------------------------------------------
    // Build the global Merkle Tree
    // Takes all ballot hashes as leaves and builds the tree bottom-up.
    // O(n) — n = number of ballots
    // ------------------------------------------------------------------
    void build_tree() {
        if (ballots_.empty()) {
            std::cout << "  [!] No ballots to build a tree from.\n";
            return;
        }
        std::vector<std::string> leaves;
        leaves.reserve(ballots_.size());
        for (const auto& b : ballots_)
            leaves.push_back(b.to_hash());

        tree_.build(leaves);
        last_built_root_ = tree_.get_root();
        tree_built_      = true;

        std::cout << "  [+] Merkle Tree built  |  " << ballots_.size()
                  << " ballot(s)  |  levels: " << tree_.level_count() << "\n";
        std::cout << "      Root: " << tree_.get_root() << "\n";
    }

    // ------------------------------------------------------------------
    // Load Dataset (Batch Registration and Voting)
    // Reads a CSV file formatted as: voter_id,candidate
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

        // Optionally skip the header if it exists
        std::getline(file, line); // Assuming first line is header: voter_id,candidate

        std::cout << "  [*] Loading dataset from " << filepath << "...\n";

        while (std::getline(file, line)) {
            if (line.empty()) continue;

            std::stringstream ss(line);
            std::string voter_id, candidate;

            if (std::getline(ss, voter_id, ',') && std::getline(ss, candidate)) {
                // Trim carriage returns (Windows CRLF issues)
                if (!candidate.empty() && candidate.back() == '\r') {
                    candidate.pop_back();
                }

                // Register voter silently (avoid console spam)
                if (registry_.register_voter(voter_id)) {
                    registered_count++;
                }

                // Cast vote silently
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
        
        tree_built_ = false; // Need to rebuild tree after batch voting

        std::cout << "  [+] Dataset loaded successfully!\n";
        std::cout << "      - Voters registered: " << registered_count << "\n";
        std::cout << "      - Votes cast:        " << voted_count << "\n";
        std::cout << "  [*] Don't forget to build the Merkle Tree (Option 3)!\n";
    }

    // ------------------------------------------------------------------
    // Verify a vote by receipt ID
    // Generates the Merkle proof for the ballot and verifies it against
    // the current root. Displays the full proof path.
    // O(log n)
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
        const Ballot& b   = ballots_[idx];
        std::string leaf  = b.to_hash();
        auto proof        = tree_.generate_proof(idx);
        tree_.print_proof_path(receipt_id, leaf, proof, last_built_root_);
    }

    // ------------------------------------------------------------------
    // Tamper simulation
    // Modifies a ballot's candidate field (simulating a data attack),
    // rebuilds the tree, and shows how the root changes.
    // Any proof generated before tampering will now fail verification.
    // ------------------------------------------------------------------
    void tamper_vote(const std::string& receipt_id,
                     const std::string& new_candidate) {
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }
        std::string old_root = tree_built_ ? tree_.get_root() : "(tree not built)";

        std::cout << "\n";
        std::cout << "  +====== TAMPERING SIMULATION ===============================+\n";
        std::cout << "  | Target receipt  : " << receipt_id                       << "\n";
        std::cout << "  | Original vote   : " << ballots_[idx].candidate          << "\n";
        std::cout << "  | Original hash   : " << short_h(ballots_[idx].to_hash()) << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        // --- Perform the tamper ---
        ballots_[idx].candidate = new_candidate;

        std::cout << "  | Tampered vote   : " << ballots_[idx].candidate          << "\n";
        std::cout << "  | New hash        : " << short_h(ballots_[idx].to_hash()) << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | Rebuilding tree with tampered data...\n";

        // Rebuild tree with the modified leaf
        std::vector<std::string> leaves;
        for (const auto& b : ballots_)
            leaves.push_back(b.to_hash());
        tree_.build(leaves);
        tree_built_ = true;

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
    // Display a summary of the current election state.
    // ------------------------------------------------------------------
    void display_summary() const {
        // Count votes per candidate in O(n)
        std::unordered_map<std::string, int> tally;
        for (const auto& b : ballots_)
            tally[b.candidate]++;

        std::cout << "\n";
        std::cout << "  +-------- Election Summary ----------------------------------+\n";
        std::cout << "  | Registered voters : " << registry_.voter_count()  << "\n";
        std::cout << "  | Ballots cast      : " << ballots_.size()          << "\n";
        std::cout << "  | Vote tally:\n";
        for (const auto& kv : tally)
            std::cout << "  |   " << kv.first << " : " << kv.second << " vote(s)\n";
        if (tree_built_)
            std::cout << "  | Merkle root : " << tree_.get_root() << "\n";
        else
            std::cout << "  | Merkle root : (not yet built -- run option 3)\n";
        std::cout << "  +------------------------------------------------------------+\n\n";
    }

    // Expose tree printing for menu option
    void print_tree() const { tree_.print_tree(); }

    // Expose registry for menu option
    void print_registry() const { registry_.print_registry(); }

    // Return all receipt IDs so the CLI can list them
    std::vector<std::string> all_receipts() const {
        std::vector<std::string> out;
        out.reserve(ballots_.size());
        for (const auto& b : ballots_)
            out.push_back(b.receipt_id);
        return out;
    }

    bool is_tree_built()  const { return tree_built_; }
    int  ballot_count()   const { return static_cast<int>(ballots_.size()); }
};

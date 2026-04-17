#pragma once
// =============================================================================
// voter_registry.hpp  —  Hash-table based voter and receipt storage
//
// This class IS the hash table layer of the project.
// It wraps two std::unordered_map instances (which are C++ hash tables)
// to provide O(1) average-case insert and lookup for:
//   1. Voter eligibility and duplicate-vote prevention
//   2. Receipt-ID to ballot-index mapping (used by proof generation)
//
// Complexity summary:
//   register_voter()    : O(1) average
//   is_registered()     : O(1) average
//   has_voted()         : O(1) average
//   mark_voted()        : O(1) average
//   store_receipt()     : O(1) average
//   get_ballot_index()  : O(1) average
// =============================================================================
#include <string>
#include <unordered_map>
#include <iostream>

class VoterRegistry {

    // Hash Table 1: voter_id  →  has_voted (bool)
    // Used for: eligibility check, duplicate-vote prevention
    std::unordered_map<std::string, bool> voters_;

    // Hash Table 2: receipt_id  →  ballot index (int)
    // Used for: fast lookup during proof generation and verification
    std::unordered_map<std::string, int> receipt_map_;

public:

    // Register a new voter as eligible (has_voted = false).
    // Returns false (no-op) if the voter is already registered.
    // O(1) average — single hash table insert
    bool register_voter(const std::string& voter_id) {
        if (voters_.count(voter_id)) return false;
        voters_[voter_id] = false;
        return true;
    }

    // Check whether a voter ID exists in the registry.
    // O(1) average — hash table lookup
    bool is_registered(const std::string& voter_id) const {
        return voters_.count(voter_id) > 0;
    }

    // Check whether a registered voter has already voted.
    // O(1) average — hash table lookup
    bool has_voted(const std::string& voter_id) const {
        auto it = voters_.find(voter_id);
        if (it == voters_.end()) return false;
        return it->second;
    }

    // Mark a voter's status as voted.
    // O(1) average — hash table update
    void mark_voted(const std::string& voter_id) {
        voters_[voter_id] = true;
    }

    // Store the mapping: receipt_id  →  ballot_index.
    // Called immediately after a ballot is appended to the ballot list.
    // O(1) average — hash table insert
    void store_receipt(const std::string& receipt_id, int ballot_index) {
        receipt_map_[receipt_id] = ballot_index;
    }

    // Retrieve the ballot index for a given receipt ID.
    // Returns -1 if the receipt ID is not found.
    // O(1) average — hash table lookup
    int get_ballot_index(const std::string& receipt_id) const {
        auto it = receipt_map_.find(receipt_id);
        if (it == receipt_map_.end()) return -1;
        return it->second;
    }

    int voter_count()  const { return static_cast<int>(voters_.size()); }
    int receipt_count() const { return static_cast<int>(receipt_map_.size()); }

    // Print the current registry state (for demo/debug).
    void print_registry() const {
        std::cout << "\n  Voter Registry  (" << voter_count() << " registered)\n";
        std::cout << "  " << std::string(44, '-') << "\n";
        for (const auto& kv : voters_)
            std::cout << "    " << kv.first
                      << "  --  " << (kv.second ? "VOTED" : "eligible") << "\n";
        std::cout << "\n";
    }
};

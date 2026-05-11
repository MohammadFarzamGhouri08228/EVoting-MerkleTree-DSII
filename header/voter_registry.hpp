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
        // implemented in voter_registry.cpp
        return register_voter_impl(voter_id);
    }

    // Check whether a voter ID exists in the registry.
    // O(1) average — hash table lookup
    bool is_registered(const std::string& voter_id) const {
        return is_registered_impl(voter_id);
    }

    // Check whether a registered voter has already voted.
    // O(1) average — hash table lookup
    bool has_voted(const std::string& voter_id) const {
        return has_voted_impl(voter_id);
    }

    // Mark a voter's status as voted.
    // O(1) average — hash table update
    void mark_voted(const std::string& voter_id) {
        mark_voted_impl(voter_id);
    }

    // Unmark a voter's status (allow them to vote again).
    // O(1) average — hash table update
    void unmark_voted(const std::string& voter_id) {
        unmark_voted_impl(voter_id);
    }

    // Store the mapping: receipt_id  →  ballot_index.
    // Called immediately after a ballot is appended to the ballot list.
    // O(1) average — hash table insert
    void store_receipt(const std::string& receipt_id, int ballot_index) {
        store_receipt_impl(receipt_id, ballot_index);
    }

    // Retrieve the ballot index for a given receipt ID.
    // Returns -1 if the receipt ID is not found.
    // O(1) average — hash table lookup
    int get_ballot_index(const std::string& receipt_id) const {
        return get_ballot_index_impl(receipt_id);
    }

    int voter_count()  const;
    int receipt_count() const;

    // Print the current registry state (for demo/debug).
    void print_registry() const;

private:
    // implementation helpers defined in voter_registry.cpp
    bool register_voter_impl(const std::string& voter_id);
    bool is_registered_impl(const std::string& voter_id) const;
    bool has_voted_impl(const std::string& voter_id) const;
    void mark_voted_impl(const std::string& voter_id);
    void unmark_voted_impl(const std::string& voter_id);
    void store_receipt_impl(const std::string& receipt_id, int ballot_index);
    int get_ballot_index_impl(const std::string& receipt_id) const;
};

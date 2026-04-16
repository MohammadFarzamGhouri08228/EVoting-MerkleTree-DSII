#pragma once
// =============================================================================
// ballot.hpp  —  Ballot record representation
//
// A Ballot is the fundamental data unit of the voting system.
// It stores voter and vote information, and produces a SHA-256 hash
// that becomes a leaf node in the global Merkle Tree.
//
// Design note:
//   The salt field prevents two identical votes from producing the same hash,
//   ensuring each ballot is cryptographically unique even if two voters
//   choose the same candidate at the same time.
// =============================================================================
#include <string>
#include <sstream>
#include "sha256.hpp"

struct Ballot {
    std::string receipt_id;   // unique ID given to voter after casting
    std::string voter_id;     // the voter who cast this ballot
    std::string candidate;    // chosen candidate
    std::string salt;         // random salt — ensures hash uniqueness
    std::string timestamp;    // seconds since epoch at time of casting

    // -------------------------------------------------------------------------
    // Canonical string: all fields joined by '|' delimiter.
    // This is what gets hashed. The delimiter prevents field-boundary collisions.
    // -------------------------------------------------------------------------
    std::string to_canonical() const {
        return receipt_id + "|" + voter_id + "|" + candidate + "|" + salt + "|" + timestamp;
    }

    // -------------------------------------------------------------------------
    // SHA-256 hash of the canonical string.
    // This 64-character hex string becomes a LEAF NODE in the Merkle Tree.
    // Time complexity: O(L) where L = length of canonical string
    // -------------------------------------------------------------------------
    std::string to_hash() const {
        return sha256(to_canonical());
    }

    // Human-readable one-line summary for display in the CLI.
    std::string to_display() const {
        return "[" + receipt_id + "] voter=" + voter_id +
               "  candidate=" + candidate +
               "  ts=" + timestamp;
    }
};

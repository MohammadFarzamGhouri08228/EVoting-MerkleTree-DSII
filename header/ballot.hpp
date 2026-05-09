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
#include "header/sha256.hpp"

struct Ballot {
    std::string receipt_id;   // unique ID given to voter after casting
    std::string voter_id;     // the voter who cast this ballot
    std::string candidate;    // chosen candidate
    std::string salt;         // random salt — ensures hash uniqueness
    std::string timestamp;    // seconds since epoch at time of casting
    bool        valid    = true;  // false after invalidate_ballot() / delete_ballot()
    bool        tampered = false; // true after tamper_vote() is called (demo flag)
    // Honest vote at cast time; set once on first tamper (for CLI dry-run labels).
    std::string pre_tamper_candidate;

    // -------------------------------------------------------------------------
    // Canonical string: all fields joined by '|' delimiter.
    // This is what gets hashed. The delimiter prevents field-boundary collisions.
    // -------------------------------------------------------------------------
    std::string to_canonical() const;

    // -------------------------------------------------------------------------
    // SHA-256 hash of the canonical string.
    // This 64-character hex string becomes a LEAF NODE in the Merkle Tree.
    // Time complexity: O(L) where L = length of canonical string
    // -------------------------------------------------------------------------
    std::string to_hash() const;

    // Human-readable one-line summary for display in the CLI.
    std::string to_display() const;
};

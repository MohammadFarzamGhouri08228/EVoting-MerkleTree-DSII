#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include "mmr.h"
#include "smt.h"

// ─────────────────────────────────────────────
//  Ballot
// ─────────────────────────────────────────────

struct Ballot {
    std::string receiptId;
    std::string candidate;
    std::string voterId;
    std::string salt;
    std::string timestamp;
    std::string hash; // SHA256(receiptId + candidate + salt + timestamp)

    Ballot(const std::string& receiptId,
           const std::string& candidate,
           const std::string& voterId);
};

// ─────────────────────────────────────────────
//  Receipt metadata (receipt -> MMR leaf index)
// ─────────────────────────────────────────────

struct ReceiptMeta {
    std::string receiptId;
    uint64_t    leafIndex  = 0;
    std::string ballotHash;
    std::string candidate;
};

// ─────────────────────────────────────────────
//  Result types
// ─────────────────────────────────────────────

struct RegisterResult {
    bool        success = false;
    std::string token;
    std::string message;
};

struct CastResult {
    bool        success    = false;
    std::string receiptId;
    uint64_t    leafIndex  = 0;
    std::string ballotHash;
    std::string message;
    SMTProof    nonInclusionProof; // populated on rejection
};

struct VoteProofResult {
    bool        success    = false;
    std::string receiptId;
    uint64_t    leafIndex  = 0;
    std::string ballotHash;
    std::string mmrRoot;
    MMRProof    proof;
    std::string message;
};

struct VoterProofResult {
    bool        success = false;
    std::string token;
    std::string smtRoot;
    SMTProof    proof;
    std::string message;
};

// ─────────────────────────────────────────────
//  VoterRegistry
//  Manages voter tokens + SMT-backed eligibility
// ─────────────────────────────────────────────

class VoterRegistry {
public:
    // Register a voter by their unique ID. Returns false if already registered.
    bool registerVoter(const std::string& uniqueId);

    // Check if a unique ID is registered.
    bool isRegistered(const std::string& uniqueId) const;

    // Check if a hashed token is registered.
    bool isRegisteredToken(const std::string& token) const;

    // Get the hashed token for a unique ID.
    std::string getToken(const std::string& uniqueId) const;

    // Commitment
    std::string getSMTRoot() const;

    // Proofs
    SMTProof proveInclusion(const std::string& token) const;
    SMTProof proveNonInclusion(const std::string& token) const;
    bool verifyInclusion(const SMTProof& proof) const;
    bool verifyNonInclusion(const SMTProof& proof) const;

private:
    SMT                                smt_;
    std::unordered_set<std::string>    tokenSet_;
    std::unordered_map<std::string, std::string> tokenToId_;
};

// ─────────────────────────────────────────────
//  VotingSystem
//  Central controller — orchestrates everything
// ─────────────────────────────────────────────

class VotingSystem {
public:
    VotingSystem();

    // ── Candidates ──────────────────────────
    void addCandidate(const std::string& name);
    std::vector<std::string> getCandidates() const;
    std::unordered_map<std::string, int> getVoteCounts() const;

    // ── Registration ────────────────────────
    RegisterResult registerVoter(const std::string& uniqueId);

    // ── Voting ──────────────────────────────
    // voterToken = SHA256(uniqueId), obtained at registration
    CastResult castVote(const std::string& voterToken,
                        const std::string& candidate);

    // ── Commitments ─────────────────────────
    std::string getMMRRoot() const;
    std::string getSMTRoot() const;
    void publishRoots() const;

    // ── Verification ────────────────────────
    VoteProofResult  proveVoteInclusion(const std::string& receiptId) const;
    VoterProofResult proveVoterInclusion(const std::string& voterToken) const;
    VoterProofResult proveVoterNonInclusion(const std::string& voterToken) const;

    // ── Debug / Display ──────────────────────
    std::vector<std::string> getMMRPeaks() const;
    void printVoteProofResult(const VoteProofResult& r) const;
    void printVoterProofResult(const VoterProofResult& r) const;

private:
    VoterRegistry   registry_;
    MMR             mmr_;

    std::unordered_set<std::string>              candidates_;
    std::unordered_set<std::string>              hasVoted_;
    std::unordered_map<std::string, std::string> tokenToReceipt_;
    std::unordered_map<std::string, ReceiptMeta> receiptIndex_;
    std::vector<Ballot>                          ballots_;
    std::unordered_map<std::string, int>         voteCounts_;
};

#include "voter.h"
#include "utils.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <iomanip>

// ─────────────────────────────────────────────
//  Ballot
// ─────────────────────────────────────────────

Ballot::Ballot(const std::string& receiptId,
               const std::string& candidate,
               const std::string& voterId)
    : receiptId(receiptId), candidate(candidate), voterId(voterId)
{
    salt      = generateSalt();
    timestamp = currentTimestamp();
    // Hash = SHA256(receiptId + candidate + salt + timestamp)
    hash      = sha256(receiptId + candidate + salt + timestamp);
}

// ─────────────────────────────────────────────
//  VoterRegistry
// ─────────────────────────────────────────────

bool VoterRegistry::registerVoter(const std::string& uniqueId) {
    std::string token = sha256(uniqueId);
    if (tokenSet_.count(token)) return false; // already registered
    tokenSet_.insert(token);
    tokenToId_[token] = uniqueId;
    smt_.insert(token);
    return true;
}

bool VoterRegistry::isRegistered(const std::string& uniqueId) const {
    return tokenSet_.count(sha256(uniqueId)) > 0;
}

bool VoterRegistry::isRegisteredToken(const std::string& token) const {
    return tokenSet_.count(token) > 0;
}

std::string VoterRegistry::getToken(const std::string& uniqueId) const {
    return sha256(uniqueId);
}

std::string VoterRegistry::getSMTRoot() const {
    return smt_.getRoot();
}

SMTProof VoterRegistry::proveInclusion(const std::string& token) const {
    return smt_.generateInclusionProof(token);
}

SMTProof VoterRegistry::proveNonInclusion(const std::string& token) const {
    return smt_.generateNonInclusionProof(token);
}

bool VoterRegistry::verifyInclusion(const SMTProof& proof) const {
    return SMT::verifyProof(proof, smt_.getRoot());
}

bool VoterRegistry::verifyNonInclusion(const SMTProof& proof) const {
    return SMT::verifyProof(proof, smt_.getRoot());
}

// ─────────────────────────────────────────────
//  VotingSystem
// ─────────────────────────────────────────────

VotingSystem::VotingSystem() {}

// ── Registration ──────────────────────────────

RegisterResult VotingSystem::registerVoter(const std::string& uniqueId) {
    RegisterResult r;
    if (registry_.isRegistered(uniqueId)) {
        r.success = false;
        r.message = "Already registered.";
        return r;
    }
    bool ok = registry_.registerVoter(uniqueId);
    if (!ok) {
        r.success = false;
        r.message = "Registration failed.";
        return r;
    }
    r.success = true;
    r.token   = registry_.getToken(uniqueId);
    r.message = "Registered successfully. Your voter token: " + r.token;
    return r;
}

// ── Vote casting ──────────────────────────────

CastResult VotingSystem::castVote(const std::string& voterToken,
                                   const std::string& candidate) {
    CastResult r;

    // 1. SMT eligibility check
    if (!registry_.isRegisteredToken(voterToken)) {
        // Generate a non-inclusion proof to make rejection auditable
        SMTProof niProof = registry_.proveNonInclusion(voterToken);
        r.success = false;
        r.message = "Voter token not found in registry.";
        r.nonInclusionProof = niProof;
        return r;
    }

    // 2. Duplicate vote check
    if (hasVoted_.count(voterToken)) {
        r.success = false;
        r.message = "This token has already cast a vote.";
        return r;
    }

    // 3. Candidate validation
    if (candidates_.find(candidate) == candidates_.end()) {
        r.success = false;
        r.message = "Invalid candidate: " + candidate;
        return r;
    }

    // 4. Create ballot and hash it
    std::string receiptId = generateReceiptId();
    Ballot ballot(receiptId, candidate, voterToken);

    // 5. Append to MMR (streaming — no batch rebuild)
    uint64_t leafIndex = mmr_.append(ballot.hash);

    // 6. Store receipt metadata
    ReceiptMeta meta;
    meta.receiptId  = receiptId;
    meta.leafIndex  = leafIndex;
    meta.ballotHash = ballot.hash;
    meta.candidate  = candidate;
    receiptIndex_[receiptId] = meta;

    // 7. Mark voter as having voted
    hasVoted_.insert(voterToken);
    tokenToReceipt_[voterToken] = receiptId;

    // 8. Store ballot
    ballots_.push_back(ballot);

    r.success   = true;
    r.receiptId = receiptId;
    r.leafIndex = leafIndex;
    r.ballotHash = ballot.hash;
    r.message   = "Vote cast successfully. Receipt ID: " + receiptId;
    return r;
}

// ── Commitments ───────────────────────────────

std::string VotingSystem::getMMRRoot() const {
    return mmr_.getRoot();
}

std::string VotingSystem::getSMTRoot() const {
    return registry_.getSMTRoot();
}

void VotingSystem::publishRoots() const {
    std::cout << "\n╔══════════════════════════════════════════════════════════╗\n";
    std::cout <<   "║              CURRENT COMMITMENT ROOTS                    ║\n";
    std::cout <<   "╠══════════════════════════════════════════════════════════╣\n";
    std::cout <<   "║ MMR Root (vote log):                                     ║\n";
    std::cout <<   "║  " << getMMRRoot() << "  ║\n";
    std::cout <<   "║ SMT Root (voter roll):                                   ║\n";
    std::cout <<   "║  " << getSMTRoot() << "  ║\n";
    std::cout <<   "╚══════════════════════════════════════════════════════════╝\n\n";
}

// ── Verification ──────────────────────────────

VoteProofResult VotingSystem::proveVoteInclusion(const std::string& receiptId) const {
    VoteProofResult r;
    auto it = receiptIndex_.find(receiptId);
    if (it == receiptIndex_.end()) {
        r.success = false;
        r.message = "Receipt ID not found.";
        return r;
    }

    const ReceiptMeta& meta = it->second;
    MMRProof proof = mmr_.generateProof(meta.leafIndex);
    bool valid = MMR::verifyProof(proof, mmr_.getRoot());

    r.success    = valid;
    r.receiptId  = receiptId;
    r.leafIndex  = meta.leafIndex;
    r.ballotHash = meta.ballotHash;
    r.mmrRoot    = mmr_.getRoot();
    r.proof      = proof;
    r.message    = valid ? "Vote inclusion verified." : "Proof verification FAILED.";
    return r;
}

VoterProofResult VotingSystem::proveVoterInclusion(const std::string& voterToken) const {
    VoterProofResult r;
    if (!registry_.isRegisteredToken(voterToken)) {
        r.success = false;
        r.message = "Token not in registry.";
        return r;
    }
    SMTProof proof = registry_.proveInclusion(voterToken);
    bool valid = SMT::verifyProof(proof, registry_.getSMTRoot());
    r.success  = valid;
    r.token    = voterToken;
    r.smtRoot  = registry_.getSMTRoot();
    r.proof    = proof;
    r.message  = valid ? "Voter inclusion verified." : "Proof verification FAILED.";
    return r;
}

VoterProofResult VotingSystem::proveVoterNonInclusion(const std::string& voterToken) const {
    VoterProofResult r;
    if (registry_.isRegisteredToken(voterToken)) {
        r.success = false;
        r.message = "Token IS in registry — cannot generate non-inclusion proof.";
        return r;
    }
    SMTProof proof = registry_.proveNonInclusion(voterToken);
    bool valid = SMT::verifyProof(proof, registry_.getSMTRoot());
    r.success  = valid;
    r.token    = voterToken;
    r.smtRoot  = registry_.getSMTRoot();
    r.proof    = proof;
    r.message  = valid ? "Voter non-inclusion verified (token provably absent)."
                       : "Proof verification FAILED.";
    return r;
}

// ── Candidates ────────────────────────────────

void VotingSystem::addCandidate(const std::string& name) {
    candidates_.insert(name);
    voteCounts_[name] = 0;
}

std::vector<std::string> VotingSystem::getCandidates() const {
    return std::vector<std::string>(candidates_.begin(), candidates_.end());
}

std::unordered_map<std::string, int> VotingSystem::getVoteCounts() const {
    std::unordered_map<std::string, int> counts;
    for (const auto& b : ballots_)
        counts[b.candidate]++;
    return counts;
}

// ── MMR Peaks (debug/display) ─────────────────

std::vector<std::string> VotingSystem::getMMRPeaks() const {
    return mmr_.getPeaks();
}

// ── Display helpers ───────────────────────────

void VotingSystem::printVoteProofResult(const VoteProofResult& r) const {
    std::cout << "\n── Vote Inclusion Proof ──────────────────────────────────\n";
    std::cout << "Receipt ID  : " << r.receiptId  << "\n";
    std::cout << "Leaf Index  : " << r.leafIndex  << "\n";
    std::cout << "Ballot Hash : " << r.ballotHash << "\n";
    std::cout << "MMR Root    : " << r.mmrRoot    << "\n";
    std::cout << "Proof Steps : " << r.proof.path.size() << "\n";
    std::cout << "Result      : " << (r.success ? "✓ VALID" : "✗ INVALID") << "\n";
    std::cout << "Message     : " << r.message << "\n";
    std::cout << "─────────────────────────────────────────────────────────\n";
}

void VotingSystem::printVoterProofResult(const VoterProofResult& r) const {
    std::cout << "\n── Voter Proof ───────────────────────────────────────────\n";
    std::cout << "Token       : " << r.token.substr(0, 16) << "...\n";
    std::cout << "SMT Root    : " << r.smtRoot << "\n";
    std::cout << "Proof Type  : " << (r.proof.isInclusion ? "Inclusion" : "Non-Inclusion") << "\n";
    std::cout << "Result      : " << (r.success ? "✓ VALID" : "✗ INVALID") << "\n";
    std::cout << "Message     : " << r.message << "\n";
    std::cout << "─────────────────────────────────────────────────────────\n";
}

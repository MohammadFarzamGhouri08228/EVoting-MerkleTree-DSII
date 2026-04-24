#include "smt.h"
#include "utils.h"
#include <stdexcept>

SMT::SMT() {
    // Precompute default empty hashes bottom-up
    // defaults_[SMT_DEPTH] = hash of an empty leaf
    defaults_[SMT_DEPTH] = sha256("__empty_leaf__");
    for (int d = SMT_DEPTH - 1; d >= 0; d--)
        defaults_[d] = mergeHashes(defaults_[d + 1], defaults_[d + 1]);
    root_ = defaults_[0];
}

std::string SMT::mergeHashes(const std::string& left, const std::string& right) {
    return sha256(left + right);
}

std::string SMT::tokenToPath(const std::string& token) {
    // Hash the token to get a deterministic 256-bit path
    std::string h = sha256(token);
    std::string bits;
    bits.reserve(SMT_DEPTH);
    for (char c : h) {
        int val = (c >= '0' && c <= '9') ? (c - '0') : (c - 'a' + 10);
        for (int b = 3; b >= 0; b--)
            bits += ((val >> b) & 1) ? '1' : '0';
    }
    return bits; // exactly 256 bits
}

std::string SMT::getNode(const std::string& path) const {
    auto it = nodes_.find(path);
    if (it != nodes_.end()) return it->second;
    // Return default for this depth
    return defaults_[path.size()];
}

void SMT::insert(const std::string& voterToken) {
    std::string bitPath = tokenToPath(voterToken);
    std::string leafHash = sha256("__leaf__" + voterToken);

    // Store the leaf
    nodes_[bitPath] = leafHash;

    // Recompute all ancestors bottom-up
    recomputeRoot(bitPath);
}

void SMT::recomputeRoot(const std::string& bitPath) {
    // Start from the leaf and walk up
    std::string current = nodes_[bitPath];
    std::string path = bitPath;

    for (int d = SMT_DEPTH; d > 0; d--) {
        char bit = path[d - 1];
        std::string parentPath = path.substr(0, d - 1);
        std::string siblingPath = parentPath + (bit == '0' ? '1' : '0');
        std::string siblingHash = getNode(siblingPath);

        std::string parentHash;
        if (bit == '0')
            parentHash = mergeHashes(current, siblingHash);
        else
            parentHash = mergeHashes(siblingHash, current);

        nodes_[parentPath] = parentHash;
        current = parentHash;
        path = parentPath;
    }

    root_ = current;
}

bool SMT::contains(const std::string& voterToken) const {
    std::string bitPath = tokenToPath(voterToken);
    return nodes_.count(bitPath) > 0;
}

SMTProof SMT::generateInclusionProof(const std::string& voterToken) const {
    SMTProof proof;
    proof.token = voterToken;
    proof.isInclusion = true;
    proof.root = root_;

    std::string bitPath = tokenToPath(voterToken);
    if (!nodes_.count(bitPath)) {
        proof.valid = false;
        return proof;
    }

    std::string path = bitPath;
    for (int d = SMT_DEPTH; d > 0; d--) {
        char bit = path[d - 1];
        std::string parentPath = path.substr(0, d - 1);
        std::string siblingPath = parentPath + (bit == '0' ? '1' : '0');

        SMTProofNode node;
        node.hash = getNode(siblingPath);
        node.isLeft = (bit == '1'); // if we are right child, sibling is left
        proof.path.push_back(node);

        path = parentPath;
    }

    proof.valid = true;
    return proof;
}

SMTProof SMT::generateNonInclusionProof(const std::string& voterToken) const {
    SMTProof proof;
    proof.token = voterToken;
    proof.isInclusion = false;
    proof.root = root_;

    std::string bitPath = tokenToPath(voterToken);
    if (nodes_.count(bitPath)) {
        // Token exists — cannot generate non-inclusion proof
        proof.valid = false;
        return proof;
    }

    // Same proof path as inclusion — verifier checks leaf == default
    std::string path = bitPath;
    for (int d = SMT_DEPTH; d > 0; d--) {
        char bit = path[d - 1];
        std::string parentPath = path.substr(0, d - 1);
        std::string siblingPath = parentPath + (bit == '0' ? '1' : '0');

        SMTProofNode node;
        node.hash = getNode(siblingPath);
        node.isLeft = (bit == '1');
        proof.path.push_back(node);

        path = parentPath;
    }

    proof.valid = true;
    return proof;
}

bool SMT::verifyProof(const SMTProof& proof, const std::string& root) {
    if (!proof.valid) return false;

    std::string bitPath = tokenToPath(proof.token);

    // Determine starting hash
    std::string current;
    if (proof.isInclusion) {
        current = sha256("__leaf__" + proof.token);
    } else {
        // For non-inclusion, leaf must equal the default empty leaf hash
        // We use a fixed-depth SMT so default leaf is known
        current = sha256("__empty_leaf__");
    }

    // Walk up using the proof path
    std::string path = bitPath;
    for (int d = SMT_DEPTH; d > 0; d--) {
        if ((int)(SMT_DEPTH - d) >= (int)proof.path.size()) break;
        const SMTProofNode& node = proof.path[SMT_DEPTH - d];
        char bit = path[d - 1];

        std::string parentHash;
        if (bit == '0')
            parentHash = sha256(current + node.hash);
        else
            parentHash = sha256(node.hash + current);

        current = parentHash;
        path = path.substr(0, d - 1);
    }

    return current == root;
}

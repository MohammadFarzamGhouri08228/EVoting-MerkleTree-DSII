#pragma once
#include <string>
#include <vector>
#include <unordered_map>

static constexpr int SMT_DEPTH = 256; // SHA-256 bit depth

struct SMTProofNode {
    std::string hash;
    bool        isLeft; // true = this sibling is on the left
};

struct SMTProof {
    std::string              token;       // the voter token being proven
    std::vector<SMTProofNode> path;       // sibling hashes from leaf to root
    bool                     isInclusion; // true = inclusion, false = non-inclusion
    std::string              root;
    bool                     valid = false;
};

class SMT {
public:
    SMT();

    // Insert a voter token into the tree.
    void insert(const std::string& voterToken);

    // Check presence without a proof.
    bool contains(const std::string& voterToken) const;

    // Generate an inclusion proof (token must exist).
    SMTProof generateInclusionProof(const std::string& voterToken) const;

    // Generate a non-inclusion proof (token must NOT exist).
    SMTProof generateNonInclusionProof(const std::string& voterToken) const;

    // Verify any SMTProof against a given root.
    static bool verifyProof(const SMTProof& proof, const std::string& root);

    // Get the current root commitment.
    std::string getRoot() const { return root_; }

private:
    // Sparse node store: path-string -> hash
    // Path string is a bitstring like "010110..." of length 0..256
    std::unordered_map<std::string, std::string> nodes_;

    // Precomputed default hashes for each depth (default_[d] = hash of empty subtree at depth d)
    std::string defaults_[SMT_DEPTH + 1];

    std::string root_;

    // Convert token to 256-bit path string
    static std::string tokenToPath(const std::string& token);

    // Get node hash at a given path (returns default if absent)
    std::string getNode(const std::string& path) const;

    // Recompute root after an insertion
    void recomputeRoot(const std::string& bitPath);

    static std::string mergeHashes(const std::string& left, const std::string& right);
};

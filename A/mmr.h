#pragma once
#include <string>
#include <vector>
#include <cstdint>

// A single node in the MMR proof path
struct MMRProofNode {
    std::string hash;
    bool isLeft; // true = this sibling is on the left
};

struct MMRProof {
    uint64_t    leafIndex;
    std::string leafHash;
    std::vector<MMRProofNode> path;
    std::string root;
    bool        valid = false;
};

class MMR {
public:
    MMR();

    // Append a new leaf hash. Returns the leaf index (0-based).
    uint64_t append(const std::string& leafHash);

    // Aggregate all peaks into a single root commitment.
    std::string getRoot() const;

    // Return current peak hashes (for debugging / display).
    std::vector<std::string> getPeaks() const;

    // Generate an inclusion proof for the leaf at leafIndex.
    MMRProof generateProof(uint64_t leafIndex) const;

    // Verify an inclusion proof against a given root.
    static bool verifyProof(const MMRProof& proof, const std::string& root);

    uint64_t size() const { return nodes_.size(); }

private:
    // All nodes stored flat: leaves + internal nodes appended in order
    std::vector<std::string> nodes_;
    // Heights of each node (0 = leaf)
    std::vector<uint64_t>    heights_;
    // Indices of current peaks (highest nodes of each perfect subtree)
    std::vector<uint64_t>    peaks_;

    static std::string mergeHashes(const std::string& left, const std::string& right);
    uint64_t heightOf(uint64_t index) const;
};

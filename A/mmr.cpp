#include "mmr.h"
#include "utils.h"
#include <stdexcept>
#include <algorithm>

MMR::MMR() {}

std::string MMR::mergeHashes(const std::string& left, const std::string& right) {
    return sha256(left + right);
}

uint64_t MMR::heightOf(uint64_t index) const {
    if (index >= heights_.size()) return 0;
    return heights_[index];
}

uint64_t MMR::append(const std::string& leafHash) {
    uint64_t idx = nodes_.size();
    nodes_.push_back(leafHash);
    heights_.push_back(0);
    peaks_.push_back(idx);

    // Repeatedly merge the last two peaks if they have equal height
    while (peaks_.size() >= 2) {
        uint64_t r = peaks_[peaks_.size() - 1];
        uint64_t l = peaks_[peaks_.size() - 2];
        if (heights_[l] != heights_[r]) break;

        // Merge
        peaks_.pop_back();
        peaks_.pop_back();

        std::string parentHash = mergeHashes(nodes_[l], nodes_[r]);
        uint64_t parentIdx = nodes_.size();
        nodes_.push_back(parentHash);
        heights_.push_back(heights_[l] + 1);
        peaks_.push_back(parentIdx);
    }

    return idx; // return the leaf's node index
}

std::string MMR::getRoot() const {
    if (peaks_.empty()) return sha256("empty");
    // Bag the peaks: fold right-to-left
    std::string root = nodes_[peaks_.back()];
    for (int i = (int)peaks_.size() - 2; i >= 0; i--)
        root = mergeHashes(nodes_[peaks_[i]], root);
    return root;
}

std::vector<std::string> MMR::getPeaks() const {
    std::vector<std::string> result;
    for (uint64_t p : peaks_)
        result.push_back(nodes_[p]);
    return result;
}

MMRProof MMR::generateProof(uint64_t leafIndex) const {
    MMRProof proof;
    proof.leafIndex = leafIndex;

    if (leafIndex >= nodes_.size() || heights_[leafIndex] != 0) {
        proof.valid = false;
        return proof;
    }

    proof.leafHash = nodes_[leafIndex];

    // Walk up the tree: find siblings
    uint64_t current = leafIndex;
    uint64_t currentHeight = 0;

    // We need to find which peak subtree this leaf belongs to
    // Strategy: find the peak that covers this leaf
    // A peak at index p with height h covers 2^(h+1)-1 nodes ending at p
    uint64_t subtreeStart = 0;
    uint64_t peakIdx = peaks_[0];

    for (uint64_t p : peaks_) {
        uint64_t h = heights_[p];
        uint64_t subtreeSize = (1ULL << (h + 1)) - 1;
        // The subtree rooted at p covers nodes [p - subtreeSize + 1 .. p]
        uint64_t start = p + 1 - subtreeSize;
        if (leafIndex >= start && leafIndex <= p) {
            peakIdx = p;
            subtreeStart = start;
            break;
        }
    }

    // Now generate path from leaf to peak root within this subtree
    current = leafIndex;
    currentHeight = 0;

    while (current != peakIdx) {
        uint64_t h = currentHeight;
        uint64_t subtreeSize = (1ULL << (h + 1)) - 1;
        // Determine if current is a left or right child
        // Parent is at current + subtreeSize (if current is left child)
        // or current + 1 (if current is right child of height-h subtree)

        uint64_t leftChildSize = (1ULL << h) - 1; // size of left subtree at height h-1... 
        // Simpler: in our flat append-order layout:
        // A node at index i with height h:
        //   left child  = i - 2^h        (index)
        //   right child = i - 1          (index)
        // So from a child, parent of left child (at index lc, height h-1):
        //   parent = lc + 2^h  where 2^h = subtreeSize of right child + 1

        // Find parent of current
        uint64_t siblingIdx;
        uint64_t parentIdx;
        uint64_t rightSubtreeSize = (1ULL << (currentHeight + 1)) - 1;

        // Check if current is a left child:
        // parent would be at current + rightSubtreeSize
        if (current + rightSubtreeSize < nodes_.size() &&
            heights_[current + rightSubtreeSize] == currentHeight + 1) {
            // current is left child
            parentIdx = current + rightSubtreeSize;
            siblingIdx = parentIdx - 1; // right child = parent - 1
            MMRProofNode node;
            node.hash = nodes_[siblingIdx];
            node.isLeft = false; // sibling is on the right
            proof.path.push_back(node);
        } else {
            // current is right child
            // sibling (left child) is at current - (rightSubtreeSize - 1) ... 
            // parent = current + 1
            parentIdx = current + 1;
            siblingIdx = parentIdx - rightSubtreeSize; // left child
            MMRProofNode node;
            node.hash = nodes_[siblingIdx];
            node.isLeft = true; // sibling is on the left
            proof.path.push_back(node);
        }

        current = parentIdx;
        currentHeight++;
    }

    // Now bag the remaining peaks
    // Find the peak position in the peaks_ array
    bool foundPeak = false;
    for (int i = (int)peaks_.size() - 1; i >= 0; i--) {
        if (peaks_[i] == peakIdx) {
            // Bag peaks to the right first, then to the left
            // Bagging order: fold remaining peaks into root
            // We include sibling peaks as proof nodes
            // Right peaks (none past the last)
            for (int j = i + 1; j < (int)peaks_.size(); j++) {
                MMRProofNode node;
                node.hash = nodes_[peaks_[j]];
                node.isLeft = false;
                proof.path.push_back(node);
            }
            // Left peaks
            for (int j = i - 1; j >= 0; j--) {
                MMRProofNode node;
                node.hash = nodes_[peaks_[j]];
                node.isLeft = true;
                proof.path.push_back(node);
            }
            foundPeak = true;
            break;
        }
    }

    proof.root = getRoot();
    proof.valid = true;
    return proof;
}

bool MMR::verifyProof(const MMRProof& proof, const std::string& root) {
    if (!proof.valid) return false;
    std::string current = proof.leafHash;
    for (const auto& node : proof.path) {
        if (node.isLeft)
            current = mergeHashes(node.hash, current);
        else
            current = mergeHashes(current, node.hash);
    }
    return current == root;
}

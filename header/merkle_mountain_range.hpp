#pragma once
// =============================================================================
// merkle_mountain_range.hpp  --  Node-based Merkle Mountain Range (MMR)
//
// Data-structure idea:
// A Merkle Mountain Range is an append-only forest of perfect binary Merkle
// trees. Each perfect tree root is called a "peak". The number of leaves
// decides which peaks exist, similar to the binary representation of n.
//
// Example with 11 leaves:
//   11 = 8 + 2 + 1
//   peaks_ stores three perfect-tree roots with heights 3, 1, and 0.
//
// Why use it here?
// - append() is efficient because only equal-height peaks merge.
// - old leaves keep stable positions, which is useful for proofs.
// - the final root commits to all peaks, so any changed leaf changes the root.
// =============================================================================
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "header/sha256.hpp"

struct MMRNode {
    // Hash stored at this node. For a leaf, this is hash(vote data).
    // For an internal node, this is hash(left_child_hash || right_child_hash).
    std::string  hash;

    // Tree pointers. parent lets proof generation walk upward from a leaf.
    MMRNode*     left   = nullptr;
    MMRNode*     right  = nullptr;
    MMRNode*     parent = nullptr;

    // Height 0 means leaf. A parent of two height-h nodes has height h + 1.
    int          height = 0;

    explicit MMRNode(const std::string& h, int ht = 0) : hash(h), height(ht) {}
    bool is_leaf() const { return height == 0; }

    // Recompute this internal node from its children. This is not used for
    // leaf-only tamper demos, where ancestors are intentionally left stale.
    void recompute() { if (left && right) hash = sha256(left->hash + right->hash); }
};

class MerkleMMR {
    // Roots of the current perfect Merkle trees.
    // Their heights are unique and usually appear from largest to smallest.
    std::vector<MMRNode*> peaks_;

    // Direct pointers to all leaf nodes in insertion order.
    // leaves_[i] is the i-th appended vote hash.
    std::vector<MMRNode*> leaves_;

    // Number of leaves. Kept separately for quick access and clarity.
    size_t n_ = 0;

    // Owns every allocated node so the destructor can free the whole forest.
    std::vector<MMRNode*> all_nodes_;

    // A trusted audit checkpoint. We keep leaf hashes and root so rollback can
    // reconstruct the exact last-known-good MMR after tamper detection.
    struct Snapshot {
        size_t leaf_count = 0;
        std::vector<std::string> leaf_hashes;
        std::string root;
    };
    std::vector<Snapshot> snapshots_;

    // Hash-combine function used consistently for Merkle parents and peak bagging.
    static std::string combine(const std::string& l, const std::string& r) { return sha256(l + r); }
    static std::string short_h(const std::string& h, size_t len = 10) { return (h.size() > len) ? h.substr(0, len) + ".." : h; }

    // Allocate through make_node() so all_nodes_ always owns every node.
    MMRNode* make_node(const std::string& h, int height) { auto* n = new MMRNode(h, height); all_nodes_.push_back(n); return n; }

    // Deletes the entire MMR forest and resets it to empty.
    void free_all() { for (auto* n : all_nodes_) delete n; all_nodes_.clear(); peaks_.clear(); leaves_.clear(); n_ = 0; }
    MMRNode* merge_top_two();

public:
    MerkleMMR()  = default;
    ~MerkleMMR() { free_all(); }
    MerkleMMR(const MerkleMMR&)            = delete;
    MerkleMMR& operator=(const MerkleMMR&) = delete;

    // Move support transfers raw-node ownership from one MMR object to another.
    MerkleMMR(MerkleMMR&& o) noexcept
        : peaks_(std::move(o.peaks_)), leaves_(std::move(o.leaves_)),
          n_(o.n_), all_nodes_(std::move(o.all_nodes_)),
          snapshots_(std::move(o.snapshots_)) { o.n_ = 0; }
    MerkleMMR& operator=(MerkleMMR&& o) noexcept {
        if (this != &o) {
            free_all();
            peaks_     = std::move(o.peaks_);
            leaves_    = std::move(o.leaves_);
            n_         = o.n_;
            all_nodes_ = std::move(o.all_nodes_);
            snapshots_ = std::move(o.snapshots_);
            o.n_ = 0;
        }
        return *this;
    }

    // Insert a new leaf at the end. Equal-height peaks merge like binary carry.
    void append(const std::string& leaf_hash);

    // Bag all peak hashes into one commitment root for the whole MMR.
    std::string get_root() const;

    // Proof contains:
    // - intra_proof: sibling hashes from leaf up to its peak
    // - peak_hashes: all peak hashes needed to recompute the final MMR root
    // - leaf_peak_idx: which peak contains the proved leaf
    struct Proof {
        std::vector<std::pair<std::string, std::string>> intra_proof;
        std::vector<std::string> peak_hashes;
        int leaf_peak_idx = 0;
    };

    // Generate a Merkle proof for leaves_[leaf_index].
    Proof generate_proof(int leaf_index) const;

    // Restore the MMR to its first new_leaf_count leaves.
    // This is implemented by rebuilding from saved leaf hashes.
    void rollback(size_t new_leaf_count);

    // Save the current leaf hashes and root as an audit checkpoint.
    void take_snapshot();
    size_t snapshot_count() const;

    // Compare a stored checkpoint root against the current live root.
    bool is_tampered_since_snapshot(size_t snapshot_index) const;

    // Rebuild the MMR from a stored checkpoint.
    void rollback_to_snapshot(size_t snapshot_index);

    // Make a copy for current interval, compare with live peaks, and rotate snapshots.
    // Returns true if tampering detected; if tampering, invalidated_from is set
    // to the leaf count to which the MMR was rolled back.
    bool check_and_rotate_interval(size_t &invalidated_from);

    // Verify a proof by rebuilding the leaf's peak, replacing that peak hash,
    // bagging all peaks, and comparing the result to expected_root.
    static bool verify_proof(const std::string& leaf_hash, const Proof& proof, const std::string& expected_root);

    size_t leaf_count()  const { return n_; }
    int    peak_count()  const { return static_cast<int>(peaks_.size()); }
    bool   is_empty()    const { return n_ == 0; }
    int    max_height()  const { return peaks_.empty() ? 0 : peaks_.front()->height; }
    void print_tree() const;
    void print_proof(int leaf_index, const Proof& proof, bool verified) const;

    // --- Simulation helpers ---
    const std::vector<MMRNode*>& peaks()  const { return peaks_; }
    const std::vector<MMRNode*>& leaves() const { return leaves_; }

    // Change a leaf hash WITHOUT propagating upward. This creates a detectable
    // inconsistency between the leaf vector and the already-computed peaks.
    void tamper_leaf_only(size_t leaf_index, const std::string& new_hash);
};

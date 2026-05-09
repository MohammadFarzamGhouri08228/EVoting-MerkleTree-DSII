#pragma once
// =============================================================================
// merkle_mountain_range.hpp  --  Node-based Merkle Mountain Range (MMR)
// =============================================================================
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "header/sha256.hpp"

struct MMRNode {
    std::string  hash;
    MMRNode*     left   = nullptr;
    MMRNode*     right  = nullptr;
    MMRNode*     parent = nullptr;
    int          height = 0;
    explicit MMRNode(const std::string& h, int ht = 0) : hash(h), height(ht) {}
    bool is_leaf() const { return height == 0; }
    void recompute() { if (left && right) hash = sha256(left->hash + right->hash); }
};

class MerkleMMR {
    std::vector<MMRNode*> peaks_;
    std::vector<MMRNode*> leaves_;
    size_t n_ = 0;
    std::vector<MMRNode*> all_nodes_;
    struct Snapshot { size_t leaf_count = 0; std::vector<std::string> leaf_hashes; std::string root; };
    std::vector<Snapshot> snapshots_;

    static std::string combine(const std::string& l, const std::string& r) { return sha256(l + r); }
    static std::string short_h(const std::string& h, size_t len = 10) { return (h.size() > len) ? h.substr(0, len) + ".." : h; }
    MMRNode* make_node(const std::string& h, int height) { auto* n = new MMRNode(h, height); all_nodes_.push_back(n); return n; }
    void free_all() { for (auto* n : all_nodes_) delete n; all_nodes_.clear(); peaks_.clear(); leaves_.clear(); n_ = 0; }
    MMRNode* merge_top_two();
public:
    MerkleMMR()  = default;
    ~MerkleMMR() { free_all(); }
    MerkleMMR(const MerkleMMR&)            = delete;
    MerkleMMR& operator=(const MerkleMMR&) = delete;
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
    void append(const std::string& leaf_hash);
    std::string get_root() const;
    struct Proof { std::vector<std::pair<std::string, std::string>> intra_proof; std::vector<std::string> peak_hashes; int leaf_peak_idx = 0; };
    Proof generate_proof(int leaf_index) const;
    void rollback(size_t new_leaf_count);
    void take_snapshot();
    size_t snapshot_count() const;
    bool is_tampered_since_snapshot(size_t snapshot_index) const;
    void rollback_to_snapshot(size_t snapshot_index);
    // Make a copy for current interval, compare with live peaks, and rotate snapshots.
    // Returns true if tampering detected; if tampering, `invalidated_from` is set
    // to the leaf count to which the MMR was rolled back (all votes after that are invalid).
    bool check_and_rotate_interval(size_t &invalidated_from);
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
    // Change a leaf hash WITHOUT propagating upward — creates detectable inconsistency
    void tamper_leaf_only(size_t leaf_index, const std::string& new_hash);
};

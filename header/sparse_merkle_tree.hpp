#pragma once
// =============================================================================
// sparse_merkle_tree.hpp  --  Node-based Sparse Merkle Tree (SMT)
// =============================================================================
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include "header/sha256.hpp"

struct SMTNode {
    std::string  hash;
    SMTNode*     left       = nullptr;
    SMTNode*     right      = nullptr;
    SMTNode*     parent     = nullptr;
    int          depth      = 0;
    bool         is_deleted = false;
    explicit SMTNode(const std::string& h, int d = 0) : hash(h), depth(d) {}
    bool is_leaf_node() const { return !left && !right; }
};

class SparseMerkleTree {
    int                      D_;
    SMTNode*                 root_       = nullptr;
    std::vector<std::string> default_hash_;
    std::vector<SMTNode*>    all_nodes_;
    static std::string combine(const std::string& l, const std::string& r) { return sha256(l + r); }
    static std::string short_h(const std::string& h, size_t len = 10) { return (h.size() > len) ? h.substr(0, len) + ".." : h; }
    SMTNode* make_node(const std::string& h, int depth) { auto* n = new SMTNode(h, depth); all_nodes_.push_back(n); return n; }
    void free_all() { for (auto* n : all_nodes_) delete n; all_nodes_.clear(); root_ = nullptr; }
    std::string child_hash(const SMTNode* node, bool go_right) const { const SMTNode* child = go_right ? node->right : node->left; if (child) return child->hash; return default_hash_[node->depth + 1]; }
    void recompute(SMTNode* node) const { node->hash = combine(child_hash(node, false), child_hash(node, true)); }
    bool bit_at(uint64_t key, int level) const { return (key >> (D_ - 1 - level)) & 1ULL; }
    void precompute_defaults() { default_hash_.resize(D_ + 1); default_hash_[D_] = sha256("EMPTY_LEAF"); for (int d = D_ - 1; d >= 0; --d) default_hash_[d] = combine(default_hash_[d + 1], default_hash_[d + 1]); }
public:
    explicit SparseMerkleTree(int depth = 16) : D_(depth) { if (depth < 1 || depth > 63) throw std::invalid_argument("depth must be 1..63"); precompute_defaults(); }
    ~SparseMerkleTree() { free_all(); }
    SparseMerkleTree(const SparseMerkleTree&) = delete; SparseMerkleTree& operator=(const SparseMerkleTree&) = delete;
    void insert(uint64_t key, const std::string& value_hash);
    std::string get(uint64_t key) const;
    void erase(uint64_t key);
    std::vector<std::pair<std::string, std::string>> generate_proof(uint64_t key) const;
    static bool verify_proof(const std::string& leaf_hash,const std::vector<std::pair<std::string, std::string>>& proof,const std::string& expected_root);
    std::string get_root() const { return root_ ? root_->hash : default_hash_[0]; }
    int  depth()        const { return D_; }
    bool is_built()     const { return root_ != nullptr; }
    int  node_count()   const { return static_cast<int>(all_nodes_.size()); }
    std::string empty_hash_at(int d) const { if (d < 0 || d > D_) throw std::out_of_range("depth out of range"); return default_hash_[d]; }
    void print_tree() const;
    void print_proof(uint64_t key,const std::string& leaf_hash,const std::vector<std::pair<std::string, std::string>>& proof) const;
};

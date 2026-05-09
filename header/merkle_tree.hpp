#pragma once
#include <algorithm>
#include <string>
#include <vector>
#include <queue>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include "header/sha256.hpp"

struct MerkleNode {
    std::string  hash;
    MerkleNode*  left       = nullptr;
    MerkleNode*  right      = nullptr;
    MerkleNode*  parent     = nullptr;
    bool         is_deleted = false;

    explicit MerkleNode(const std::string& h) : hash(h) {}

    bool is_leaf() const { return !left && !right; }

    void recompute() {
        if (left && right) hash = sha256(left->hash + right->hash);
        else if (left)     hash = sha256(left->hash + left->hash);
    }
};

class MerkleTree {
    MerkleNode* root_ = nullptr;
    std::vector<MerkleNode*> leaves_;
    std::vector<MerkleNode*> all_nodes_;

    static std::string combine(const std::string& l, const std::string& r) {
        return sha256(l + r);
    }

    static std::string short_h(const std::string& h, size_t len = 10) {
        return (h.size() > len) ? h.substr(0, len) + ".." : h;
    }

    MerkleNode* make_node(const std::string& h) {
        auto* n = new MerkleNode(h);
        all_nodes_.push_back(n);
        return n;
    }

    void free_all() {
        for (auto* n : all_nodes_) delete n;
        all_nodes_.clear();
        leaves_.clear();
        root_ = nullptr;
    }

    static int height(const MerkleNode* n) {
        if (!n) return 0;
        return 1 + std::max(height(n->left), height(n->right));
    }

    std::vector<std::vector<MerkleNode*>> bfs_levels() const {
        std::vector<std::vector<MerkleNode*>> levels;
        if (!root_) return levels;

        std::queue<MerkleNode*> q;
        q.push(root_);
        while (!q.empty()) {
            int sz = static_cast<int>(q.size());
            std::vector<MerkleNode*> lvl;
            lvl.reserve(sz);
            for (int i = 0; i < sz; ++i) {
                MerkleNode* cur = q.front();
                q.pop();
                lvl.push_back(cur);
                if (cur->left)  q.push(cur->left);
                if (cur->right) q.push(cur->right);
            }
            levels.push_back(std::move(lvl));
        }
        return levels;
    }

    int total_nodes() const {
        int c = 0;
        for (const auto& lvl : bfs_levels())
            c += static_cast<int>(lvl.size());
        return c;
    }

    static std::string json_escape(const std::string& s) {
        std::ostringstream out;
        for (char ch : s) {
            switch (ch) {
                case '\\': out << "\\\\"; break;
                case '"':  out << "\\\""; break;
                case '\b': out << "\\b"; break;
                case '\f': out << "\\f"; break;
                case '\n': out << "\\n"; break;
                case '\r': out << "\\r"; break;
                case '\t': out << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(ch) < 0x20) {
                        out << "\\u"
                            << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<int>(static_cast<unsigned char>(ch))
                            << std::dec << std::setfill(' ');
                    } else {
                        out << ch;
                    }
            }
        }
        return out.str();
    }

    std::string visualization_json_for(
        const MerkleNode* node,
        int level,
        const std::unordered_map<const MerkleNode*, int>& leaf_index_map,
        const std::vector<std::string>& voter_ids,
        const std::vector<std::string>& candidates,
        const std::vector<std::string>& receipt_ids,
        const std::vector<bool>& tampered_flags) const
    {
        std::ostringstream oss;
        const bool is_root = (node == root_);
        const bool is_leaf = node->is_leaf();
        const bool is_deleted = node->is_deleted;

        std::string kind = "internal";
        if (is_root) kind = "root";
        else if (is_deleted) kind = "deleted";
        else if (is_leaf) kind = "leaf";

        std::string label;
        if (is_root) label = "ROOT: " + short_h(node->hash, 8);
        else if (is_deleted) label = "[NULLIFIED]";
        else if (is_leaf) label = "LEAF: " + short_h(node->hash, 8);
        else label = "Lvl " + std::to_string(level) + ": " + short_h(node->hash, 8);

        oss << "{";
        oss << "\"name\":\"" << json_escape(label) << "\",";
        oss << "\"kind\":\"" << kind << "\",";
        oss << "\"hash\":\"" << json_escape(node->hash) << "\",";
        oss << "\"shortHash\":\"" << json_escape(short_h(node->hash, 12)) << "\",";
        oss << "\"level\":" << level << ",";
        oss << "\"deleted\":" << (is_deleted ? "true" : "false");

        if (is_leaf) {
            auto it = leaf_index_map.find(node);
            if (it != leaf_index_map.end()) {
                const int idx = it->second;
                oss << ",\"leafIndex\":" << idx;
                if (idx >= 0 && idx < static_cast<int>(voter_ids.size())) {
                    oss << ",\"voterId\":\"" << json_escape(voter_ids[idx]) << "\"";
                    oss << ",\"candidate\":\"" << json_escape(candidates[idx]) << "\"";
                    oss << ",\"receiptId\":\"" << json_escape(receipt_ids[idx]) << "\"";
                    oss << ",\"tampered\":" << (tampered_flags[idx] ? "true" : "false");
                }
            }
        }

        std::vector<std::string> children;
        if (node->left) {
            children.push_back(visualization_json_for(
                node->left, level + 1, leaf_index_map,
                voter_ids, candidates, receipt_ids, tampered_flags));
        }
        if (node->right) {
            children.push_back(visualization_json_for(
                node->right, level + 1, leaf_index_map,
                voter_ids, candidates, receipt_ids, tampered_flags));
        }

        if (!children.empty()) {
            oss << ",\"children\":[";
            for (size_t i = 0; i < children.size(); ++i) {
                if (i) oss << ",";
                oss << children[i];
            }
            oss << "]";
        }

        oss << "}";
        return oss.str();
    }

public:
    static std::string deleted_sentinel();

    MerkleTree() = default;
    ~MerkleTree();

    MerkleTree(const MerkleTree&) = delete;
    MerkleTree& operator=(const MerkleTree&) = delete;

    void build(const std::vector<std::string>& leaf_hashes);
    void insert(const std::string& leaf_hash);
    void update(int leaf_index, const std::string& new_hash);
    void delete_leaf(int leaf_index);
    void rollback(int new_leaf_count);

    std::vector<std::pair<std::string, std::string>> generate_proof(int leaf_index) const;
    static bool verify_proof(
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& root_hash);

    std::string get_root() const { return root_ ? root_->hash : ""; }
    bool is_built() const { return root_ != nullptr; }
    int leaf_count() const { return static_cast<int>(leaves_.size()); }
    int level_count() const { return height(root_); }

    std::string get_leaf_hash(int leaf_index) const;
    bool is_leaf_deleted(int leaf_index) const;

    std::string export_visualization_json(
        const std::vector<std::string>& voter_ids,
        const std::vector<std::string>& candidates,
        const std::vector<std::string>& receipt_ids,
        const std::vector<bool>& tampered_flags) const;

    void print_tree_visual() const;
    void print_tree() const;

    bool print_proof_path(
        const std::string& receipt_id,
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& root_to_check) const;
};

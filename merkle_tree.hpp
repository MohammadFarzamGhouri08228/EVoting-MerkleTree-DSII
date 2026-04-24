#pragma once
#include <algorithm>
#include <string>
#include <vector>
#include <queue>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "sha256.hpp"

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

public:
    static std::string deleted_sentinel() {
        static const std::string s = sha256("NULLIFIED_BALLOT");
        return s;
    }

    MerkleTree() = default;
    ~MerkleTree() { free_all(); }

    MerkleTree(const MerkleTree&) = delete;
    MerkleTree& operator=(const MerkleTree&) = delete;

    void build(const std::vector<std::string>& leaf_hashes) {
        free_all();
        if (leaf_hashes.empty()) return;

        std::vector<MerkleNode*> current;
        current.reserve(leaf_hashes.size());
        for (const auto& h : leaf_hashes) {
            MerkleNode* leaf = make_node(h);
            if (h == deleted_sentinel()) leaf->is_deleted = true;
            leaves_.push_back(leaf);
            current.push_back(leaf);
        }

        while (current.size() > 1) {
            std::vector<MerkleNode*> next;
            next.reserve((current.size() + 1) / 2);

            for (size_t i = 0; i < current.size(); i += 2) {
                MerkleNode* left = current[i];
                bool has_right = (i + 1 < current.size());
                MerkleNode* right = has_right ? current[i + 1] : nullptr;

                std::string parent_hash = has_right
                    ? combine(left->hash, right->hash)
                    : combine(left->hash, left->hash);

                MerkleNode* parent = make_node(parent_hash);
                parent->left = left;
                parent->right = right;
                left->parent = parent;
                if (right) right->parent = parent;

                next.push_back(parent);
            }
            current = std::move(next);
        }

        root_ = current[0];
    }

    void insert(const std::string& leaf_hash) {
        if (leaves_.empty()) {
            root_ = make_node(leaf_hash);
            leaves_.push_back(root_);
            return;
        }

        if (leaves_.size() == 1) {
            MerkleNode* new_leaf = make_node(leaf_hash);
            MerkleNode* new_root = make_node(combine(root_->hash, new_leaf->hash));

            new_root->left = root_;
            new_root->right = new_leaf;
            root_->parent = new_root;
            new_leaf->parent = new_root;

            leaves_.push_back(new_leaf);
            root_ = new_root;
            return;
        }

        if (leaves_.size() % 2 == 1) {
            MerkleNode* new_leaf = make_node(leaf_hash);
            MerkleNode* par = leaves_.back()->parent;

            par->right = new_leaf;
            new_leaf->parent = par;
            leaves_.push_back(new_leaf);

            par->recompute();
            MerkleNode* cur = par->parent;
            while (cur) {
                cur->recompute();
                cur = cur->parent;
            }
            return;
        }

        std::vector<std::string> hashes;
        hashes.reserve(leaves_.size() + 1);
        for (auto* l : leaves_) hashes.push_back(l->hash);
        hashes.push_back(leaf_hash);
        build(hashes);
    }

    void update(int leaf_index, const std::string& new_hash) {
        if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
            throw std::out_of_range("leaf_index out of range.");

        leaves_[leaf_index]->hash = new_hash;

        MerkleNode* cur = leaves_[leaf_index]->parent;
        while (cur) {
            cur->recompute();
            cur = cur->parent;
        }
    }

    void delete_leaf(int leaf_index) {
        if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
            throw std::out_of_range("leaf_index out of range.");

        MerkleNode* leaf = leaves_[leaf_index];
        leaf->hash = deleted_sentinel();
        leaf->is_deleted = true;

        MerkleNode* cur = leaf->parent;
        while (cur) {
            cur->recompute();
            cur = cur->parent;
        }
    }

    std::vector<std::pair<std::string, std::string>> generate_proof(int leaf_index) const {
        if (!root_)
            throw std::logic_error("Tree has not been built yet.");
        if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
            throw std::out_of_range("leaf_index out of range.");

        std::vector<std::pair<std::string, std::string>> proof;
        MerkleNode* cur = leaves_[leaf_index];

        while (cur->parent) {
            MerkleNode* parent = cur->parent;
            if (parent->left == cur) {
                std::string sibling = parent->right ? parent->right->hash : cur->hash;
                proof.push_back({sibling, "R"});
            } else {
                proof.push_back({parent->left->hash, "L"});
            }
            cur = cur->parent;
        }

        return proof;
    }

    static bool verify_proof(
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& root_hash)
    {
        std::string current = leaf_hash;
        for (const auto& step : proof) {
            const std::string& sibling = step.first;
            const std::string& direction = step.second;
            current = (direction == "R") ? combine(current, sibling)
                                         : combine(sibling, current);
        }
        return current == root_hash;
    }

    std::string get_root() const { return root_ ? root_->hash : ""; }
    bool is_built() const { return root_ != nullptr; }
    int leaf_count() const { return static_cast<int>(leaves_.size()); }
    int level_count() const { return height(root_); }

    std::string get_leaf_hash(int leaf_index) const {
        if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
            throw std::out_of_range("leaf_index out of range.");
        return leaves_[leaf_index]->hash;
    }

    bool is_leaf_deleted(int leaf_index) const {
        if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
            return false;
        return leaves_[leaf_index]->is_deleted;
    }

    void print_tree_visual() const {
        if (!is_built()) {
            std::cout << "  [!] Tree not built yet.\n";
            return;
        }

        auto levels = bfs_levels();
        const int total_lvls = static_cast<int>(levels.size());
        const int console_w = 78;
        const int node_w = 18;
        const int nodes_per_row = std::max(1, console_w / node_w);

        std::cout << "\n";
        for (int li = 0; li < total_lvls; ++li) {
            const auto& nodes = levels[li];
            const bool is_root = (li == 0);
            const bool is_leaves = (li == total_lvls - 1);

            std::string title = is_root ? "Level 0 (Root)"
                              : is_leaves ? "Level " + std::to_string(li) + " (Leaves)"
                                          : "Level " + std::to_string(li);

            std::cout << "  " << title << " - " << nodes.size()
                      << " node" << (nodes.size() == 1 ? "" : "s") << "\n";
            std::cout << "  " << std::string(console_w, '-') << "\n";

            for (size_t i = 0; i < nodes.size(); ++i) {
                if (i % nodes_per_row == 0)
                    std::cout << "    ";

                std::string label;
                if (nodes[i]->is_deleted) {
                    label = "[" + std::to_string(i) + ":DELETED]";
                } else if (is_root) {
                    label = "[root:" + short_h(nodes[i]->hash, 8) + "]";
                } else if (is_leaves) {
                    label = "[L" + std::to_string(i) + ":" + short_h(nodes[i]->hash, 8) + "]";
                } else {
                    label = "[" + std::to_string(i) + ":" + short_h(nodes[i]->hash, 8) + "]";
                }

                std::cout << std::left << std::setw(node_w) << label;
                if ((i + 1) % nodes_per_row == 0 || i == nodes.size() - 1)
                    std::cout << "\n";
            }

            std::cout << "\n";
        }
    }

    void print_tree() const {
        if (!is_built()) {
            std::cout << "  [!] Tree has not been built yet.\n";
            return;
        }

        auto levels = bfs_levels();
        const int n = leaf_count();
        const int h = level_count();
        const int tn = total_nodes();
        const bool balanced = (n > 0) && ((n & (n - 1)) == 0);

        std::cout << "\n";
        std::cout << "  ==================== MERKLE TREE VIEW ====================\n";
        std::cout << "  This is the tree from top to bottom.\n";
        std::cout << "  The root is the final fingerprint of all ballots.\n";
        std::cout << "  Each lower level combines into the level above it.\n\n";

        std::cout << "  Overview\n";
        std::cout << "  --------\n";
        std::cout << "  Leaves      : " << n << "\n";
        std::cout << "  Levels      : " << h << "\n";
        std::cout << "  Total nodes : " << tn << "\n";
        std::cout << "  Shape       : " << (balanced ? "Perfectly balanced" : "Nearly balanced") << "\n";
        std::cout << "  Root hash   : " << get_root() << "\n\n";

        std::cout << "  Level Summary\n";
        std::cout << "  -------------\n";
        for (size_t li = 0; li < levels.size(); ++li) {
            const auto& nodes = levels[li];

            std::ostringstream preview;
            int show = std::min(static_cast<int>(nodes.size()), 3);
            for (int j = 0; j < show; ++j) {
                if (nodes[j]->is_deleted) preview << "[DELETED]";
                else preview << short_h(nodes[j]->hash, 10);
                if (j < show - 1) preview << "  ";
            }
            if (static_cast<int>(nodes.size()) > 3)
                preview << "  ...+" << (nodes.size() - 3) << " more";

            std::string label = (li == 0) ? "Root"
                               : (li == levels.size() - 1) ? "Leaves"
                                                            : "Level " + std::to_string(li);
            std::cout << "  " << std::left << std::setw(10) << label
                      << "  nodes: " << std::setw(4) << nodes.size()
                      << " preview: " << preview.str() << "\n";
        }

        std::cout << "\n";
        std::cout << "  Detailed Layout\n";
        std::cout << "  ---------------\n";
        print_tree_visual();
    }

    bool print_proof_path(
        const std::string& receipt_id,
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& root_to_check) const
    {
        std::cout << "\n";
        std::cout << "  ================== VERIFICATION WALKTHROUGH ==================\n";
        std::cout << "  Receipt        : " << receipt_id << "\n";
        std::cout << "  Starting hash  : " << leaf_hash << "\n";
        std::cout << "  Published root : " << root_to_check << "\n";
        std::cout << "  Steps needed   : " << proof.size() << "\n\n";

        std::string current = leaf_hash;
        for (size_t i = 0; i < proof.size(); ++i) {
            const std::string& sibling = proof[i].first;
            const std::string& direction = proof[i].second;
            std::string parent_hash;
            const std::string side = (direction == "R") ? "right" : "left";

            if (direction == "R") parent_hash = combine(current, sibling);
            else                  parent_hash = combine(sibling, current);

            std::cout << "  Step " << (i + 1) << ": combine the current hash with the "
                      << side << " sibling\n";
            std::cout << "    current : " << short_h(current, 24) << "\n";
            std::cout << "    sibling : " << short_h(sibling, 24) << "\n";
            std::cout << "    result  : " << short_h(parent_hash, 24) << "\n\n";
            current = parent_hash;
        }

        const bool match = (current == root_to_check);
        std::cout << "  Result Summary\n";
        std::cout << "  --------------\n";
        std::cout << "  Computed root  : " << current << "\n";
        std::cout << "  Published root : " << root_to_check << "\n";

        if (match) {
            std::cout << "  Status         : MATCH\n";
            std::cout << "  Meaning        : This ballot matches the published tree.\n";
        } else {
            std::cout << "  Status         : MISMATCH\n";
            std::cout << "  Meaning        : This ballot no longer matches the published tree.\n";
            std::cout << "  Possible cause : tampering, invalidation, deletion, or a newer rebuild.\n";
        }
        std::cout << "  =============================================================\n\n";
        return match;
    }
};

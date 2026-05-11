#include "header/sparse_merkle_tree.hpp"

void SparseMerkleTree::insert(uint64_t key, const std::string& value_hash) {
    if (!root_) root_ = make_node(default_hash_[0], 0);

    SMTNode* cur = root_;
    for (int level = 0; level < D_; ++level) {
        bool go_right = bit_at(key, level);
        if (go_right) {
            if (!cur->right) cur->right = make_node(default_hash_[level + 1], level + 1);
            cur->right->parent = cur;
            cur = cur->right;
        } else {
            if (!cur->left) cur->left = make_node(default_hash_[level + 1], level + 1);
            cur->left->parent = cur;
            cur = cur->left;
        }
    }

    cur->hash = value_hash;
    cur->is_deleted = false;

    // Recompute up to root
    SMTNode* node = cur->parent;
    while (node) { recompute(node); node = node->parent; }
}

std::string SparseMerkleTree::get(uint64_t key) const {
    const SMTNode* cur = root_;
    if (!cur) return default_hash_[D_];
    for (int level = 0; level < D_; ++level) {
        bool go_right = bit_at(key, level);
        cur = go_right ? cur->right : cur->left;
        if (!cur) return default_hash_[D_];
    }
    return cur->hash;
}

void SparseMerkleTree::erase(uint64_t key) {
    SMTNode* cur = root_;
    if (!cur) return;
    for (int level = 0; level < D_; ++level) {
        bool go_right = bit_at(key, level);
        cur = go_right ? cur->right : cur->left;
        if (!cur) return;
    }
    cur->hash = default_hash_[D_];
    cur->is_deleted = true;
    SMTNode* node = cur->parent;
    while (node) { recompute(node); node = node->parent; }
}

std::vector<std::pair<std::string, std::string>> SparseMerkleTree::generate_proof(uint64_t key) const {
    std::vector<std::pair<std::string, std::string>> proof;
    if (!root_) {
        // return proof of defaults
        for (int i = 0; i < D_; ++i) proof.push_back({default_hash_[D_], "R"});
        return proof;
    }

    const SMTNode* cur = root_;
    std::vector<const SMTNode*> stack;
    stack.reserve(D_);
    for (int level = 0; level < D_; ++level) {
        stack.push_back(cur);
        bool go_right = bit_at(key, level);
        cur = go_right ? cur->right : cur->left;
        if (!cur) cur = nullptr;
    }

    // Build proof bottom-up
    for (int level = D_ - 1; level >= 0; --level) {
        const SMTNode* parent = stack[level];
        bool go_right = bit_at(key, level);
        std::string sibling = parent ? child_hash(parent, !go_right) : default_hash_[D_];
        std::string dir = go_right ? "L" : "R"; // if we went right, sibling is left => "L"
        proof.push_back({sibling, dir});
    }

    return proof;
}

bool SparseMerkleTree::verify_proof(const std::string& leaf_hash,const std::vector<std::pair<std::string, std::string>>& proof,const std::string& expected_root) {
    std::string current = leaf_hash;
    for (const auto& step : proof) {
        const std::string& sibling = step.first;
        const std::string& direction = step.second;
        current = (direction == "R") ? combine(current, sibling) : combine(sibling, current);
    }
    return current == expected_root;
}

void SparseMerkleTree::print_tree() const {
    std::cout << "SparseMerkleTree depth=" << D_ << " node_count=" << all_nodes_.size() << " root=" << get_root() << "\n";
}

void SparseMerkleTree::print_proof(uint64_t key,const std::string& leaf_hash,const std::vector<std::pair<std::string, std::string>>& proof) const {
    std::cout << "Proof for key=" << key << " leaf=" << leaf_hash << " steps=" << proof.size() << "\n";
    for (size_t i = 0; i < proof.size(); ++i) {
        std::cout << "  [" << i << "] " << proof[i].second << " " << proof[i].first << "\n";
    }
}

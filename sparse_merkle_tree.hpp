#pragma once
// =============================================================================
// sparse_merkle_tree.hpp  --  Node-based Sparse Merkle Tree (SMT)
//
// A Sparse Merkle Tree is a complete binary tree of fixed depth D whose key
// space is {0 .. 2^D - 1}.  Nodes are allocated lazily — only positions that
// have been explicitly inserted exist as heap objects.  Every other position is
// a *virtual* empty node whose hash equals a precomputed default for its depth.
//
// Structural contrast with merkle_tree.hpp:
//   Standard Merkle tree : depth grows with n; all leaf positions filled.
//   Sparse Merkle tree   : depth is FIXED (D bits); most positions are empty.
//
// Core operations:
//
//   insert(key, value_hash)   O(D)   Walks the D-bit key top-down, allocating
//                                    MerkleNode objects along the path.  On the
//                                    way back up, recomputes each ancestor via
//                                    parent pointers — same mechanic as update()
//                                    in merkle_tree.hpp.
//
//   get(key)                  O(D)   Walks the key top-down via pointers.
//                                    Returns default_hash(0) if key is absent.
//
//   erase(key)                O(D)   Replaces the leaf hash with the empty
//                                    sentinel, marks is_deleted=true, recomputes
//                                    ancestors upward — mirrors delete_leaf().
//
//   generate_proof(key)       O(D)   Walks DOWN the key via pointers.  At each
//                                    level the sibling is either a real node's
//                                    hash or the precomputed default for that
//                                    depth.  Proof length = D steps exactly.
//
//   verify_proof(...)         O(D)   One SHA-256 per step (static, no traversal).
//
// Empty-node defaults:
//   default_hash_[0]  = sha256("EMPTY_LEAF")            -- leaf level
//   default_hash_[d]  = sha256(default_hash_[d-1] +     -- inner levels
//                               default_hash_[d-1])
//   These are precomputed once in the constructor so sibling lookups are O(1).
// =============================================================================
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include "sha256.hpp"

// =============================================================================
// SMTNode  —  a single allocated node in the sparse tree
//
// Leaf nodes  : left == right == nullptr
//               hash  = sha256(value_hash)  after insert()
//               hash  = default_hash_[0]    after erase() / never inserted
//
// Inner nodes : left or right may be nullptr (child is a virtual empty node)
//               hash  = sha256(left_hash + right_hash)
//               where left_hash / right_hash are the real child hash if that
//               child exists, or default_hash_[depth_of_child] otherwise.
//
// parent pointer — enables O(D) upward recomputation without re-traversing.
// depth          — distance from the ROOT (root.depth == 0, leaves.depth == D).
// =============================================================================
struct SMTNode {
    std::string  hash;
    SMTNode*     left       = nullptr;
    SMTNode*     right      = nullptr;
    SMTNode*     parent     = nullptr;
    int          depth      = 0;     // 0 = root, D = leaf
    bool         is_deleted = false; // true on leaf after erase()

    explicit SMTNode(const std::string& h, int d = 0) : hash(h), depth(d) {}

    bool is_leaf_node() const { return !left && !right; }
};

// =============================================================================
// SparseMerkleTree
// =============================================================================
class SparseMerkleTree {

    // Fixed depth: key space = 2^D_.  Typical production value is 256.
    // We keep it small (default 16) so demos and tests are fast.
    int                      D_;
    SMTNode*                 root_       = nullptr;

    // Precomputed default hashes for each depth level.
    // default_hash_[D_] = sha256("EMPTY_LEAF")
    // default_hash_[d]  = sha256(default_hash_[d+1] + default_hash_[d+1])
    // Index convention: default_hash_[d] is the hash of a virtual subtree
    // rooted at depth d whose every leaf is empty.
    std::vector<std::string> default_hash_;   // size D_+1

    // All allocated nodes — only used by the destructor.
    std::vector<SMTNode*>    all_nodes_;

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    static std::string combine(const std::string& l, const std::string& r) {
        return sha256(l + r);
    }

    static std::string short_h(const std::string& h, size_t len = 10) {
        return (h.size() > len) ? h.substr(0, len) + ".." : h;
    }

    SMTNode* make_node(const std::string& h, int depth) {
        auto* n = new SMTNode(h, depth);
        all_nodes_.push_back(n);
        return n;
    }

    void free_all() {
        for (auto* n : all_nodes_) delete n;
        all_nodes_.clear();
        root_ = nullptr;
    }

    // Returns the hash of the LEFT or RIGHT child of `node` at depth `node->depth`.
    // If that child pointer is null, returns the precomputed default for depth+1.
    std::string child_hash(const SMTNode* node, bool go_right) const {
        const SMTNode* child = go_right ? node->right : node->left;
        if (child) return child->hash;
        return default_hash_[node->depth + 1];  // virtual empty subtree
    }

    // Recompute `node`'s hash from its two children (real or virtual).
    void recompute(SMTNode* node) const {
        node->hash = combine(child_hash(node, false),   // left
                             child_hash(node, true));   // right
    }

    // Returns bit `level` of `key` (MSB-first, level 0 = most significant bit).
    // This is the only place key arithmetic appears; all tree navigation uses pointers.
    bool bit_at(uint64_t key, int level) const {
        // Bit 0 of the key selects the path at depth D_-1 (last step).
        // Bit D_-1 selects the path at depth 0 (first step from root).
        return (key >> (D_ - 1 - level)) & 1ULL;
    }

    // Precompute default hashes bottom-up.
    void precompute_defaults() {
        default_hash_.resize(D_ + 1);
        default_hash_[D_] = sha256("EMPTY_LEAF");          // leaf level
        for (int d = D_ - 1; d >= 0; --d)
            default_hash_[d] = combine(default_hash_[d + 1], default_hash_[d + 1]);
    }

public:

    // `depth` is the number of key bits (tree height).
    // Key space = [0 .. 2^depth - 1].
    // Maximum supported depth is 63 (fits in uint64_t).
    explicit SparseMerkleTree(int depth = 16) : D_(depth) {
        if (depth < 1 || depth > 63)
            throw std::invalid_argument("depth must be 1..63");
        precompute_defaults();
        // Root starts as a virtual node — no allocation needed yet.
        // We materialise the root on first insert so the tree is truly lazy.
    }

    ~SparseMerkleTree() { free_all(); }

    SparseMerkleTree(const SparseMerkleTree&)            = delete;
    SparseMerkleTree& operator=(const SparseMerkleTree&) = delete;

    // ------------------------------------------------------------------
    // insert()  —  O(D)
    //
    // Walks D levels top-down via pointers, creating SMTNodes on demand.
    // On the way back, calls recompute() at each ancestor via parent pointer.
    //
    // value_hash : the caller-supplied hash of the value being stored.
    //              (caller is responsible for SHA-256-ing the raw value first,
    //               consistent with how leaf hashes are passed in merkle_tree.hpp)
    // ------------------------------------------------------------------
    void insert(uint64_t key, const std::string& value_hash) {
        if (key >= (1ULL << D_))
            throw std::out_of_range("key exceeds key space for this depth");

        // Materialise root if this is the very first insert
        if (!root_) {
            root_ = make_node(default_hash_[0], 0);
        }

        SMTNode* cur = root_;

        // Walk DOWN D levels, creating nodes as needed
        for (int level = 0; level < D_; ++level) {
            bool go_right = bit_at(key, level);

            SMTNode*& child_ptr = go_right ? cur->right : cur->left;
            int       child_depth = level + 1;

            if (!child_ptr) {
                // Allocate a new node with the virtual default hash for this depth
                child_ptr = make_node(default_hash_[child_depth], child_depth);
                child_ptr->parent = cur;
            }
            cur = child_ptr;
        }

        // cur is now the leaf node at depth D_
        cur->hash       = value_hash;
        cur->is_deleted = false;

        // Walk UP via parent pointers recomputing each ancestor — same as
        // update() / delete_leaf() in merkle_tree.hpp
        SMTNode* ancestor = cur->parent;
        while (ancestor) {
            recompute(ancestor);
            ancestor = ancestor->parent;   // pointer hop
        }
    }

    // ------------------------------------------------------------------
    // get()  —  O(D)
    //
    // Returns the hash stored at `key`, or the leaf-level default hash
    // if the key was never inserted (or was erased).
    // ------------------------------------------------------------------
    std::string get(uint64_t key) const {
        if (key >= (1ULL << D_))
            throw std::out_of_range("key exceeds key space for this depth");
        if (!root_) return default_hash_[D_];

        const SMTNode* cur = root_;
        for (int level = 0; level < D_; ++level) {
            bool go_right = bit_at(key, level);
            const SMTNode* child = go_right ? cur->right : cur->left;
            if (!child) return default_hash_[D_];   // hit a virtual subtree
            cur = child;
        }
        return cur->hash;   // real leaf
    }

    // ------------------------------------------------------------------
    // erase()  —  O(D)
    //
    // Replaces the leaf hash with the empty sentinel and marks is_deleted.
    // Recomputes ancestors upward via parent pointers — mirrors delete_leaf().
    // The node stays allocated (pruning would require checking sibling subtrees
    // for emptiness, which adds complexity without changing asymptotic cost).
    // ------------------------------------------------------------------
    void erase(uint64_t key) {
        if (key >= (1ULL << D_))
            throw std::out_of_range("key exceeds key space for this depth");
        if (!root_) return;

        SMTNode* cur = root_;
        for (int level = 0; level < D_; ++level) {
            bool     go_right  = bit_at(key, level);
            SMTNode* child     = go_right ? cur->right : cur->left;
            if (!child) return;   // key was never inserted — nothing to erase
            cur = child;
        }

        // Leaf found — mark deleted, restore default leaf hash
        cur->hash       = default_hash_[D_];
        cur->is_deleted = true;

        SMTNode* ancestor = cur->parent;
        while (ancestor) {
            recompute(ancestor);
            ancestor = ancestor->parent;
        }
    }

    // ------------------------------------------------------------------
    // generate_proof()  —  O(D)
    //
    // Walks DOWN the key, collecting the sibling hash at each level.
    // The sibling is either a real allocated node's hash or the precomputed
    // default for that depth — no index arithmetic, only pointer comparisons.
    //
    // Returns D proof steps, each: { sibling_hash, "L" | "R" }
    //   "R" means the sibling is to the RIGHT of the current path node
    //        (i.e. the path went LEFT at this level).
    //   "L" means the sibling is to the LEFT.
    //
    // This matches the convention in merkle_tree.hpp::generate_proof() exactly.
    // ------------------------------------------------------------------
    std::vector<std::pair<std::string, std::string>>
    generate_proof(uint64_t key) const {
        if (key >= (1ULL << D_))
            throw std::out_of_range("key exceeds key space for this depth");

        std::vector<std::pair<std::string, std::string>> proof;
        proof.reserve(D_);

        // We collect siblings top-down, then reverse so the proof runs
        // leaf → root (same order as merkle_tree.hpp).
        const SMTNode* cur = root_;

        for (int level = 0; level < D_; ++level) {
            bool go_right = bit_at(key, level);
            int  sibling_depth = level + 1;

            std::string sib_hash;
            std::string direction;

            if (!cur) {
                // Entire subtree is virtual
                sib_hash  = default_hash_[sibling_depth];
                direction = go_right ? "L" : "R";
            } else {
                // Sibling is the child we are NOT following
                bool        sib_is_right = !go_right;
                const SMTNode* sib_node  = sib_is_right ? cur->right : cur->left;
                sib_hash  = sib_node ? sib_node->hash : default_hash_[sibling_depth];
                direction = sib_is_right ? "R" : "L";

                // Descend
                const SMTNode* next = go_right ? cur->right : cur->left;
                cur = next;   // may become nullptr — handled above next iteration
            }

            proof.push_back({ sib_hash, direction });
        }

        // Reverse so index 0 is the leaf-level sibling (leaf→root order)
        std::reverse(proof.begin(), proof.end());
        return proof;
    }

    // ------------------------------------------------------------------
    // verify_proof()  —  O(D)  (static — no tree traversal)
    //
    // Identical logic to merkle_tree.hpp::verify_proof().
    // ------------------------------------------------------------------
    static bool verify_proof(
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& expected_root)
    {
        std::string current = leaf_hash;
        for (const auto& step : proof) {
            const std::string& sibling   = step.first;
            const std::string& direction = step.second;
            current = (direction == "R") ? combine(current, sibling)
                                         : combine(sibling, current);
        }
        return current == expected_root;
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------
    std::string get_root() const {
        return root_ ? root_->hash : default_hash_[0];
    }

    int  depth()        const { return D_; }
    bool is_built()     const { return root_ != nullptr; }
    int  node_count()   const { return static_cast<int>(all_nodes_.size()); }

    // The precomputed hash of an entirely empty subtree rooted at depth `d`.
    std::string empty_hash_at(int d) const {
        if (d < 0 || d > D_)
            throw std::out_of_range("depth out of range");
        return default_hash_[d];
    }

    // ------------------------------------------------------------------
    // print_tree()  —  summary + top-of-path diagnostics
    // ------------------------------------------------------------------
    void print_tree() const {
        std::cout << "\n";
        std::cout << "  +==============================================================+\n";
        std::cout << "  |           SPARSE MERKLE TREE  --  STATUS REPORT             |\n";
        std::cout << "  +==============================================================+\n";

        auto row_fn = [](const std::string& key, const std::string& val) {
            std::cout << "  |  " << std::left << std::setw(16) << key
                      << ": " << std::setw(42) << val << " |\n";
        };

        row_fn("Depth (D)",    std::to_string(D_) + " bits");
        row_fn("Key space",    "2^" + std::to_string(D_) + " = " +
                               std::to_string(1ULL << std::min(D_, 62)) + " slots");
        row_fn("Allocated",    std::to_string(node_count()) + " nodes (rest are virtual)");
        row_fn("Root hash",    short_h(get_root(), 48));
        row_fn("Empty-root",   short_h(default_hash_[0], 48));
        row_fn("Empty-leaf",   short_h(default_hash_[D_], 48));

        std::cout << "  +==============================================================+\n\n";
    }

    void print_proof(
        uint64_t key,
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof) const
    {
        std::cout << "\n  +====== SMT Inclusion Proof ================================+\n";
        std::cout << "  | Key        : " << key << "\n";
        std::cout << "  | Leaf hash  : " << short_h(leaf_hash, 50) << "\n";
        std::cout << "  | Steps      : " << proof.size() << "  (depth = " << D_ << ")\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        std::string current = leaf_hash;
        for (size_t i = 0; i < proof.size(); ++i) {
            const std::string& sibling   = proof[i].first;
            const std::string& direction = proof[i].second;
            std::string parent_hash;

            std::cout << "  |  Step " << std::setw(3) << (i + 1) << " / " << proof.size()
                      << "  sibling is " << (direction == "R" ? "RIGHT" : "LEFT ") << " : "
                      << short_h(sibling, 20) << "\n";

            if (direction == "R") parent_hash = combine(current, sibling);
            else                  parent_hash = combine(sibling, current);
            current = parent_hash;
        }

        bool match = (current == get_root());
        std::cout << "  |\n";
        std::cout << "  | Computed root : " << current    << "\n";
        std::cout << "  | Expected root : " << get_root() << "\n";
        std::cout << "  | Result : "
                  << (match ? "[OK]  VERIFIED" : "[!!] MISMATCH") << "\n";
        std::cout << "  +===========================================================+\n\n";
    }
};

#pragma once
// =============================================================================
// merkle_tree.hpp  --  Node-based Merkle Tree implementation
//
// Every position in the tree is a heap-allocated MerkleNode object connected
// by raw left / right / parent pointers.  There are NO flat array-index tricks
// for tree navigation — all structural operations follow pointers.
//
// Core operations and complexity:
//
//   build()          O(n)       Allocates 2n-1 MerkleNodes, links all by pointer.
//
//   insert()         O(log n)   When current leaf count is ODD: the last leaf was
//                               "duplicated" (parent->right == nullptr).  The new
//                               leaf is attached directly as that parent's right
//                               child, then parent pointers are followed upward
//                               and each ancestor is recomputed — no array scan.
//
//                    O(n)       When current leaf count is EVEN: every existing
//                               pair is already filled, so the new leaf starts a
//                               new "duplicate" subtree whose integration may
//                               restructure the entire right spine.  A full rebuild
//                               is the clean solution (also what the PDF cites as
//                               the standard approach for this case).
//
//   update()         O(log n)   Mutates one leaf node's hash in-place, then walks
//                               UP via parent pointers calling recompute() at each
//                               ancestor.  Zero array access.
//
//   delete_leaf()    O(log n)   Replaces the target leaf's hash with a sentinel
//                               value ("NULLIFIED BALLOT"), marks is_deleted=true,
//                               then walks UP via parent pointers and recomputes
//                               every ancestor — exactly like update().
//
//   generate_proof() O(log n)   Walks UP from the leaf to the root via parent
//                               pointers.  At each level, determines LEFT/RIGHT by
//                               comparing pointers (parent->left == cur), then
//                               records the sibling's hash.  Zero index math.
//
//   verify_proof()   O(log n)   One SHA-256 per proof step (static — no traversal).
//
//   print_tree()     O(n)       BFS traversal visits every MerkleNode once.
// =============================================================================
#include <string>
#include <vector>
#include <queue>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>
#include "sha256.hpp"

// =============================================================================
// MerkleNode  —  a single node in the Merkle binary tree
//
// Leaf nodes  : left == right == nullptr
//               hash = SHA-256(ballot canonical string)
//               is_deleted = true  after delete_leaf() is called
//
// Inner nodes : left != nullptr
//               hash = SHA-256(left->hash || right->hash)
//               When a level has an odd count, the last node has right == nullptr
//               and recompute() hashes (left->hash || left->hash) — the standard
//               "duplicate last node" rule used by Bitcoin and RFC 6962.
//
// parent pointer — enables O(log n) upward re-hashing without revisiting leaves.
// =============================================================================
struct MerkleNode {
    std::string  hash;
    MerkleNode*  left       = nullptr;
    MerkleNode*  right      = nullptr;
    MerkleNode*  parent     = nullptr;
    bool         is_deleted = false;   // true only on leaf nodes after delete_leaf()

    explicit MerkleNode(const std::string& h) : hash(h) {}

    bool is_leaf() const { return !left && !right; }

    // Recompute this internal node's hash from its children via pointer dereference.
    // If right is null (odd-level duplication), hash the left child with itself.
    void recompute() {
        if      (left && right) hash = sha256(left->hash + right->hash);
        else if (left)          hash = sha256(left->hash + left->hash);
    }
};

// =============================================================================
// MerkleTree
// =============================================================================
class MerkleTree {

    MerkleNode*              root_      = nullptr;

    // leaves_[i] is a direct pointer to the i-th leaf node (ballot index i).
    // Indexed access is only used to locate the starting node; all traversal
    // from that node is done through parent / left / right pointers.
    std::vector<MerkleNode*> leaves_;

    // All allocated nodes — only used by the destructor for cleanup.
    std::vector<MerkleNode*> all_nodes_;

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

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

    // Recursive height (root counts as level 1).
    static int height(const MerkleNode* n) {
        if (!n) return 0;
        return 1 + std::max(height(n->left), height(n->right));
    }

    // BFS: returns all nodes grouped by level, root level first.
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
                MerkleNode* cur = q.front(); q.pop();
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
        for (const auto& lvl : bfs_levels()) c += static_cast<int>(lvl.size());
        return c;
    }

public:

    // The sentinel hash stored in a deleted leaf node.
    // SHA-256("NULLIFIED_BALLOT") — chosen so it can never collide with a real ballot hash.
    static std::string deleted_sentinel() {
        static const std::string s = sha256("NULLIFIED_BALLOT");
        return s;
    }

    MerkleTree()  = default;
    ~MerkleTree() { free_all(); }

    MerkleTree(const MerkleTree&)            = delete;
    MerkleTree& operator=(const MerkleTree&) = delete;

    // ------------------------------------------------------------------
    // build()  —  O(n)
    //
    // Allocates one MerkleNode per leaf hash, then builds internal nodes
    // level-by-level using pointer links (left, right, parent).
    // ------------------------------------------------------------------
    void build(const std::vector<std::string>& leaf_hashes) {
        free_all();
        if (leaf_hashes.empty()) return;

        // ── Create leaf nodes ──────────────────────────────────────────
        std::vector<MerkleNode*> current;
        current.reserve(leaf_hashes.size());
        for (const auto& h : leaf_hashes) {
            MerkleNode* leaf = make_node(h);
            // Mark as deleted if hash matches the sentinel
            if (h == deleted_sentinel()) leaf->is_deleted = true;
            leaves_.push_back(leaf);
            current.push_back(leaf);
        }

        // ── Build internal nodes bottom-up via pointer linking ─────────
        while (current.size() > 1) {
            std::vector<MerkleNode*> next;
            next.reserve((current.size() + 1) / 2);

            for (size_t i = 0; i < current.size(); i += 2) {
                MerkleNode* left     = current[i];
                bool        has_right = (i + 1 < current.size());
                MerkleNode* right    = has_right ? current[i + 1] : nullptr;

                std::string ph = has_right ? combine(left->hash, right->hash)
                                           : combine(left->hash, left->hash);
                MerkleNode* parent = make_node(ph);

                parent->left  = left;
                parent->right = right;      // nullptr when duplicated
                left->parent  = parent;
                if (right) right->parent = parent;

                next.push_back(parent);
            }
            current = std::move(next);
        }

        root_ = current[0];
    }

    // ------------------------------------------------------------------
    // insert()  —  O(log n) when leaf count is odd / O(n) when even
    //
    // ODD count case (O(log n) — authentic pointer-navigated insert):
    //   The last existing leaf was "duplicated" (parent->right == nullptr).
    //   The new leaf becomes the real right child of that parent.
    //   Then parent pointers are followed upward and recompute() is called
    //   at every ancestor — no array is scanned at all.
    //
    //   Example: 3 leaves → 4 leaves
    //     Before: root → (P01 → L0,L1) , (P22 → L2,null)
    //     After : root → (P01 → L0,L1) , (P22 → L2,L3)   ← only right spine recomputed
    //
    // EVEN count case (O(n) rebuild):
    //   All existing pairs are filled; the new leaf needs a "duplicate"
    //   parent that must then be merged into level 1, which may cascade
    //   through the entire right spine.  A full rebuild is the clean and
    //   standard solution (consistent with what the PDF cites).
    // ------------------------------------------------------------------
    void insert(const std::string& leaf_hash) {
        // ── Empty tree ─────────────────────────────────────────────────
        if (leaves_.empty()) {
            root_ = make_node(leaf_hash);
            leaves_.push_back(root_);
            return;
        }

        // ── Single leaf (= root, no parent) ───────────────────────────
        if (leaves_.size() == 1) {
            MerkleNode* new_leaf = make_node(leaf_hash);
            std::string ph       = combine(root_->hash, new_leaf->hash);
            MerkleNode* new_root = make_node(ph);

            new_root->left   = root_;
            new_root->right  = new_leaf;
            root_->parent    = new_root;
            new_leaf->parent = new_root;

            leaves_.push_back(new_leaf);
            root_ = new_root;
            return;
        }

        // ── ODD leaf count → O(log n) pointer-navigated insert ─────────
        if (leaves_.size() % 2 == 1) {
            // The last leaf was duplicated: its parent's right child is null.
            MerkleNode* new_leaf = make_node(leaf_hash);
            MerkleNode* par      = leaves_.back()->parent;   // pointer hop

            // Attach the new leaf as the real right child
            par->right       = new_leaf;
            new_leaf->parent = par;
            leaves_.push_back(new_leaf);

            // Walk UP via parent pointers and recompute each ancestor
            par->recompute();
            MerkleNode* cur = par->parent;
            while (cur) {
                cur->recompute();   // uses cur->left->hash and cur->right->hash
                cur = cur->parent;  // pointer hop — no index math
            }
            return;
        }

        // ── EVEN leaf count → O(n) rebuild ─────────────────────────────
        // All pairs are filled; integrating a new "duplicate" subtree
        // restructures the right spine.  Rebuild from the full leaf list.
        std::vector<std::string> hashes;
        hashes.reserve(leaves_.size() + 1);
        for (auto* l : leaves_) hashes.push_back(l->hash);
        hashes.push_back(leaf_hash);
        build(hashes);
    }

    // ------------------------------------------------------------------
    // update()  —  O(log n)
    //
    // Mutates the target leaf node's hash directly, then walks UP via
    // parent pointers calling recompute() at every ancestor.
    // Used by tamper_vote() — demonstrates a hash change cascading to root.
    // ------------------------------------------------------------------
    void update(int leaf_index, const std::string& new_hash) {
        if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
            throw std::out_of_range("leaf_index out of range.");

        leaves_[leaf_index]->hash = new_hash;   // mutate leaf in-place

        MerkleNode* cur = leaves_[leaf_index]->parent;
        while (cur) {
            cur->recompute();       // hash from children via pointer dereference
            cur = cur->parent;      // climb one level via pointer
        }
    }

    // ------------------------------------------------------------------
    // delete_leaf()  —  O(log n)
    //
    // Replaces the leaf's hash with the sentinel value ("NULLIFIED BALLOT"),
    // marks the node as deleted, then walks UP via parent pointers and
    // recomputes every ancestor — identical mechanics to update().
    //
    // The leaf node STAYS in the tree at its position.  This preserves all
    // other ballots' positions and proofs.  A voter verifying a deleted
    // ballot will see a MISMATCH (sentinel vs. original hash), proving the
    // ballot was invalidated.
    // ------------------------------------------------------------------
    void delete_leaf(int leaf_index) {
        if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
            throw std::out_of_range("leaf_index out of range.");

        MerkleNode* leaf   = leaves_[leaf_index];
        leaf->hash         = deleted_sentinel();
        leaf->is_deleted   = true;

        // Propagate the sentinel hash upward — same as update()
        MerkleNode* cur = leaf->parent;
        while (cur) {
            cur->recompute();
            cur = cur->parent;
        }
    }

    // ------------------------------------------------------------------
    // generate_proof()  —  O(log n)
    //
    // Walks from the target leaf UP to the root via parent pointers.
    // Determines LEFT/RIGHT by comparing pointer identity (parent->left == cur).
    // Records sibling hash and direction at each level.
    // Zero index arithmetic — pure pointer traversal.
    // ------------------------------------------------------------------
    std::vector<std::pair<std::string, std::string>>
    generate_proof(int leaf_index) const {
        if (!root_)
            throw std::logic_error("Tree has not been built yet.");
        if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
            throw std::out_of_range("leaf_index out of range.");

        std::vector<std::pair<std::string, std::string>> proof;
        MerkleNode* cur = leaves_[leaf_index];

        while (cur->parent) {
            MerkleNode* parent = cur->parent;           // pointer hop

            if (parent->left == cur) {
                // Current is LEFT child → sibling is on the RIGHT
                std::string sib = parent->right ? parent->right->hash : cur->hash;
                proof.push_back({ sib, "R" });
            } else {
                // Current is RIGHT child → sibling is on the LEFT
                proof.push_back({ parent->left->hash, "L" });
            }

            cur = cur->parent;   // climb one level via pointer
        }
        return proof;
    }

    // ------------------------------------------------------------------
    // verify_proof()  —  O(log n)  (static — no tree traversal needed)
    // ------------------------------------------------------------------
    static bool verify_proof(
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& root_hash)
    {
        std::string current = leaf_hash;
        for (const auto& step : proof) {
            const std::string& sibling   = step.first;
            const std::string& direction = step.second;
            current = (direction == "R") ? combine(current, sibling)
                                         : combine(sibling, current);
        }
        return current == root_hash;
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------
    std::string get_root()      const { return root_ ? root_->hash : ""; }
    bool        is_built()      const { return root_ != nullptr; }
    int         leaf_count()    const { return static_cast<int>(leaves_.size()); }
    int         level_count()   const { return height(root_); }

    // Direct access to a leaf node's current hash (may be sentinel if deleted).
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

    // =========================================================================
    // VISUALIZATION  —  all traversal is BFS over MerkleNode pointers
    // =========================================================================

    void print_tree_visual() const {
        if (!is_built()) {
            std::cout << "  [!] Tree not built yet.\n";
            return;
        }

        auto levels    = bfs_levels();
        int  total_lvls = static_cast<int>(levels.size());

        const int VIS_ROWS = std::min(total_lvls, 4);
        const int SLOT_W   = 12;
        int bottom_slots   = 1 << (VIS_ROWS - 1);
        int total_w        = bottom_slots * SLOT_W;

        std::cout << "\n";

        for (int row = 0; row < VIS_ROWS; row++) {
            const auto& lvl = levels[row];
            int n_slots  = 1 << row;
            int slot_w   = total_w / n_slots;
            int n_show   = std::min(n_slots, static_cast<int>(lvl.size()));

            std::string line(total_w, ' ');
            for (int j = 0; j < n_show; j++) {
                std::string label;
                if (row == 0)
                    label = "[ROOT:" + short_h(lvl[j]->hash, 6) + "]";
                else if (lvl[j]->is_deleted)
                    label = "[DELETED]";
                else
                    label = "[" + short_h(lvl[j]->hash, 8) + "]";

                int center = j * slot_w + slot_w / 2;
                int start  = center - static_cast<int>(label.size()) / 2;
                start = std::max(0, std::min(start, total_w - static_cast<int>(label.size())));
                for (int k = 0; k < static_cast<int>(label.size()) && start + k < total_w; k++)
                    line[start + k] = label[k];
            }
            std::cout << "  " << line << "\n";

            if (row < VIS_ROWS - 1) {
                int next_slot_w = slot_w / 2;
                int n_conn = (slot_w >= 24) ? 2 : 1;
                for (int cr = 0; cr < n_conn; cr++) {
                    float t = (float)(cr + 1) / (float)(n_conn + 1);
                    std::string cline(total_w, ' ');
                    for (int j = 0; j < n_show; j++) {
                        int pc  = j * slot_w + slot_w / 2;
                        int lcc = (2 * j    ) * next_slot_w + next_slot_w / 2;
                        int rcc = (2 * j + 1) * next_slot_w + next_slot_w / 2;
                        int sp  = (int)std::round(pc + t * (lcc - pc));
                        int bp  = (int)std::round(pc + t * (rcc - pc));
                        if (sp >= 0 && sp < total_w) cline[sp] = '/';
                        if (bp >= 0 && bp < total_w) cline[bp] = '\\';
                    }
                    std::cout << "  " << cline << "\n";
                }
            }
        }

        if (total_lvls > VIS_ROWS) {
            int hidden = total_lvls - VIS_ROWS;
            std::string pad(total_w / 3, ' ');
            std::cout << "  " << pad
                      << "... (" << hidden << " more level"
                      << (hidden > 1 ? "s" : "") << "  |  "
                      << leaf_count() << " leaves total) ...\n";
        }
        std::cout << "\n";
    }

    void print_tree() const {
        if (!is_built()) {
            std::cout << "  [!] Tree has not been built yet.\n";
            return;
        }

        auto   levels    = bfs_levels();
        int    n         = leaf_count();
        int    h         = level_count();
        int    tn        = total_nodes();
        bool   balanced  = (n > 0) && ((n & (n - 1)) == 0);
        double log2n     = (n > 1) ? std::log2((double)n) : 0.0;

        std::cout << "\n";
        std::cout << "  +==============================================================+\n";
        std::cout << "  |                MERKLE TREE  --  STATUS REPORT               |\n";
        std::cout << "  +==============================================================+\n";

        auto row_fn = [](const std::string& key, const std::string& val) {
            std::cout << "  |  " << std::left << std::setw(16) << key
                      << ": " << std::setw(42) << val << " |\n";
        };

        row_fn("Leaves",      std::to_string(n));
        row_fn("Height",      std::to_string(h) + " levels");
        row_fn("Total nodes", std::to_string(tn));

        {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(2) << log2n
                << "  (min tree height = " << (int)std::ceil(log2n) + 1 << ")";
            row_fn("log2(leaves)", oss.str());
        }

        row_fn("Balanced", balanced
            ? "YES  --  perfect binary tree (power of 2 leaves)"
            : "NEAR --  odd leaves duplicated via ceil rule");

        std::cout << "  |  " << std::left << std::setw(16) << "Root hash"
                  << ": " << get_root().substr(0, 50) << ".. |\n";
        std::cout << std::right;
        std::cout << "  +--------------------------------------------------------------+\n";

        std::cout << "\n";
        std::cout << "  Level Breakdown  (Root -> Leaves):\n";
        std::cout << "  +---------+-------+-----------+------------------------------------+\n";
        std::cout << "  |  Label  |  Lvl  |   Nodes   |  Hash preview (up to 3 nodes)      |\n";
        std::cout << "  +---------+-------+-----------+------------------------------------+\n";

        int total_lvls = static_cast<int>(levels.size());
        for (int li = 0; li < total_lvls; ++li) {
            const auto& nodes = levels[li];

            std::string lbl;
            if      (li == 0)              lbl = "ROOT   ";
            else if (li == total_lvls - 1) lbl = "LEAVES ";
            else {
                lbl = "Lvl " + std::to_string(li);
                lbl.resize(7, ' ');
            }

            std::ostringstream preview;
            int show = std::min(static_cast<int>(nodes.size()), 3);
            for (int j = 0; j < show; j++) {
                if (nodes[j]->is_deleted)
                    preview << "[DELETED]  ";
                else
                    preview << short_h(nodes[j]->hash, 10);
                if (j < show - 1) preview << "  ";
            }
            if (static_cast<int>(nodes.size()) > 3)
                preview << "  ...+" << (nodes.size() - 3) << " more";

            int display_lvl = total_lvls - 1 - li;
            std::cout << "  | " << std::left << std::setw(7)  << lbl
                      << " | "  << std::right << std::setw(5) << display_lvl
                      << " | "  << std::right << std::setw(9) << nodes.size()
                      << " | "  << std::left  << std::setw(34) << preview.str()
                      << " |\n" << std::right;
        }
        std::cout << "  +---------+-------+-----------+------------------------------------+\n";

        std::cout << "\n  ASCII Diagram";
        if (level_count() <= 4)
            std::cout << "  (full tree -- " << level_count() << " levels):\n";
        else
            std::cout << "  (top " << std::min(4, level_count())
                      << " of " << level_count()
                      << " levels -- tree too deep for full display):\n";

        print_tree_visual();
    }

    void print_proof_path(
        const std::string& receipt_id,
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& root_to_check) const
    {
        std::string path_summary = "LEAF";
        for (const auto& step : proof)
            path_summary += " -(" + step.second + ")-> ";
        path_summary += "ROOT";

        std::cout << "\n";
        std::cout << "  +====== Merkle Inclusion Proof =============================+\n";
        std::cout << "  | Receipt    : " << receipt_id  << "\n";
        std::cout << "  | Leaf hash  : " << leaf_hash   << "\n";
        std::cout << "  | Proof steps: " << proof.size()
                  << "  (tree height = " << level_count() << " levels)\n";
        std::cout << "  | Path       : " << path_summary << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        std::string current = leaf_hash;
        for (size_t i = 0; i < proof.size(); ++i) {
            const std::string& sibling   = proof[i].first;
            const std::string& direction = proof[i].second;
            std::string parent_hash;

            std::cout << "  |\n";
            std::cout << "  |  Step " << (i + 1) << " / " << proof.size()
                      << "  (sibling is " << (direction == "R" ? "RIGHT" : "LEFT") << "):\n";

            if (direction == "R") {
                parent_hash = combine(current, sibling);
                std::cout << "  |    [current] (left ) : " << short_h(current, 20) << "\n";
                std::cout << "  |    [sibling] (right) : " << short_h(sibling, 20) << "\n";
            } else {
                parent_hash = combine(sibling, current);
                std::cout << "  |    [sibling] (left ) : " << short_h(sibling, 20) << "\n";
                std::cout << "  |    [current] (right) : " << short_h(current, 20) << "\n";
            }
            std::cout << "  |    SHA256(L + R)      : " << short_h(parent_hash, 20) << "\n";
            current = parent_hash;
        }

        bool match = (current == root_to_check);
        std::cout << "  |\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | Computed root  : " << current       << "\n";
        std::cout << "  | Expected root  : " << root_to_check << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        if (match) {
            std::cout << "  | Result : [OK]  MATCH  --  Vote VERIFIED successfully.    |\n";
        } else {
            std::cout << "  | Result : [!!] MISMATCH  -- Proof INVALID.                |\n";
            std::cout << "  |          Root changed: ballot may have been tampered or   |\n";
            std::cout << "  |          invalidated by an election authority.            |\n";
        }
        std::cout << "  +===========================================================+\n\n";
    }
};

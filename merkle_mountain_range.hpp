#pragma once
// =============================================================================
// merkle_mountain_range.hpp  --  Node-based Merkle Mountain Range (MMR)
//
// A Merkle Mountain Range is an append-only structure that maintains a list of
// perfect binary trees called "peaks".  For n appended leaves, the peak sizes
// correspond exactly to the set bits of n in binary.
//
//   Example: n = 11  (binary 1011)
//     Three peaks: heights 3, 1, 0  (sizes 8, 2, 1)
//
//                peak[2]           peak[1]    peak[0]
//            [h=3 root]          [h=1 root]  [leaf]
//             L0..L7              L8  L9      L10
//
// Structural contrast with merkle_tree.hpp:
//   Standard Merkle tree : single root; odd-count → duplication.
//   MMR                  : multiple peaks; no duplication ever.
//                          "root" is the hash of all peak hashes (bagging).
//
// Core operations:
//
//   append(leaf_hash)       O(log n)   Adds a new leaf node.  While the last
//                                      two peaks have equal height, they are
//                                      merged by pointer into a new parent —
//                                      exactly like insert(odd) in merkle_tree.hpp
//                                      but without any rebuild.
//
//   get_root()              O(log n)   Bags the peaks: folds their hashes
//                                      left-to-right with sha256.  The peak list
//                                      has at most log2(n) entries.
//
//   generate_proof(i)       O(log n)   Walks UP from leaf i via parent pointers
//                                      within its peak (same as merkle_tree.hpp),
//                                      then appends the other peaks' hashes for
//                                      the bagging step.
//
//   verify_proof(...)       O(log n)   Reconstructs the peak root bottom-up,
//                                      then bags to reproduce the MMR root.
//
// All tree navigation uses parent / left / right pointer dereferences.
// No array-index tricks are used for structural traversal.
// =============================================================================
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "sha256.hpp"

// =============================================================================
// MMRNode  —  a single node in one of the MMR peaks
//
// Leaf nodes  : left == right == nullptr
//               hash = caller-supplied leaf hash
//
// Inner nodes : left != nullptr, right != nullptr   (MMR has NO duplication)
//               hash = sha256(left->hash + right->hash)
//
// parent pointer — enables O(log n) upward recomputation after append().
// height         — 0 for leaves, +1 for each level up.
// =============================================================================
struct MMRNode {
    std::string  hash;
    MMRNode*     left   = nullptr;
    MMRNode*     right  = nullptr;
    MMRNode*     parent = nullptr;
    int          height = 0;   // 0 = leaf

    explicit MMRNode(const std::string& h, int ht = 0) : hash(h), height(ht) {}

    bool is_leaf() const { return height == 0; }

    // Recompute from children (only called on inner nodes — MMR never duplicates)
    void recompute() {
        if (left && right) hash = sha256(left->hash + right->hash);
    }
};

// =============================================================================
// MerkleMMR
// =============================================================================
class MerkleMMR {

    // peaks_[i] is the ROOT node of the i-th perfect binary tree.
    // peaks_[0] is the tallest (oldest) peak; peaks_.back() is the shortest.
    // After every append(), peaks_ is maintained in STRICTLY DECREASING height order.
    std::vector<MMRNode*> peaks_;

    // leaves_[i] is a direct pointer to the i-th appended leaf node.
    // Used only as a starting point for generate_proof(); all traversal
    // from that point is done through parent pointers.
    std::vector<MMRNode*> leaves_;

    // Leaf count == leaves_.size()
    size_t n_ = 0;

    // All allocated nodes — only used by the destructor.
    std::vector<MMRNode*> all_nodes_;

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    static std::string combine(const std::string& l, const std::string& r) {
        return sha256(l + r);
    }

    static std::string short_h(const std::string& h, size_t len = 10) {
        return (h.size() > len) ? h.substr(0, len) + ".." : h;
    }

    MMRNode* make_node(const std::string& h, int height) {
        auto* n = new MMRNode(h, height);
        all_nodes_.push_back(n);
        return n;
    }

    void free_all() {
        for (auto* n : all_nodes_) delete n;
        all_nodes_.clear();
        peaks_.clear();
        leaves_.clear();
        n_ = 0;
    }

    // Merge the last two peaks (they must be equal height).
    // Creates a new parent node and links left/right/parent pointers.
    // Returns the merged peak node.
    MMRNode* merge_top_two() {
        // The two peaks to merge are peaks_[end-2] and peaks_[end-1]
        MMRNode* left  = peaks_[peaks_.size() - 2];
        MMRNode* right = peaks_[peaks_.size() - 1];

        MMRNode* parent = make_node(combine(left->hash, right->hash),
                                    left->height + 1);
        parent->left   = left;
        parent->right  = right;
        left->parent   = parent;
        right->parent  = parent;

        // Remove the two merged peaks, push the new parent
        peaks_.pop_back();
        peaks_.pop_back();
        peaks_.push_back(parent);

        return parent;
    }

public:

    MerkleMMR()  = default;
    ~MerkleMMR() { free_all(); }

    MerkleMMR(const MerkleMMR&)            = delete;
    MerkleMMR& operator=(const MerkleMMR&) = delete;

    // ------------------------------------------------------------------
    // append()  —  O(log n)
    //
    // Allocates one leaf MMRNode.  Then, while the last two peaks have
    // equal height, merges them into a new parent via pointer linking.
    // At most log2(n) merges occur — one per bit of n that carries.
    //
    // This is the append-only analogue of insert(odd) in merkle_tree.hpp,
    // but never requires a rebuild because MMR never duplicates nodes.
    // ------------------------------------------------------------------
    void append(const std::string& leaf_hash) {
        MMRNode* leaf = make_node(leaf_hash, 0);
        leaves_.push_back(leaf);
        peaks_.push_back(leaf);
        ++n_;

        // Merge peaks of equal height — same as carry propagation in binary addition.
        // At most O(log n) merges total across all appends (amortised O(1) each).
        while (peaks_.size() >= 2 &&
               peaks_[peaks_.size() - 2]->height == peaks_[peaks_.size() - 1]->height)
        {
            merge_top_two();   // all pointer-based, no index recomputation
        }
    }

    // ------------------------------------------------------------------
    // get_root()  —  O(log n)
    //
    // "Bags the peaks": folds all peak hashes left-to-right with sha256.
    // This is the standard MMR root definition (also used by Grin / OpenTimestamps).
    //
    // With a single peak (n is a power of 2), bagging returns that peak's hash
    // directly — identical to a standard Merkle root.
    // ------------------------------------------------------------------
    std::string get_root() const {
        if (peaks_.empty()) return "";
        std::string acc = peaks_[0]->hash;
        for (size_t i = 1; i < peaks_.size(); ++i)
            acc = combine(acc, peaks_[i]->hash);
        return acc;
    }

    // ------------------------------------------------------------------
    // generate_proof()  —  O(log n)
    //
    // Step 1 — Intra-peak proof  (identical to merkle_tree.hpp::generate_proof)
    //   Walks UP from leaf `i` to its peak root via parent pointers.
    //   At each step, determines LEFT/RIGHT by pointer comparison, records sibling.
    //
    // Step 2 — Bagging proof
    //   Records the hashes of all other peaks in left-to-right order.
    //   verify_proof() uses these to re-bag and check against the MMR root.
    //
    // Returns:
    //   .intra_proof  : sibling steps within the leaf's peak (leaf → peak root)
    //   .peak_hashes  : hashes of all peaks, in order (the leaf's own peak's
    //                   position is marked so verify_proof can re-bag)
    //   .leaf_peak_idx: index into peak_hashes of the peak containing leaf i
    // ------------------------------------------------------------------

    struct Proof {
        std::vector<std::pair<std::string, std::string>> intra_proof;
        std::vector<std::string>                         peak_hashes;
        int                                              leaf_peak_idx = 0;
    };

    Proof generate_proof(int leaf_index) const {
        if (leaf_index < 0 || leaf_index >= static_cast<int>(n_))
            throw std::out_of_range("leaf_index out of range");

        Proof proof;

        // ── Step 1: walk UP from leaf to its peak root via parent pointers ──
        MMRNode* cur = leaves_[leaf_index];

        while (cur->parent) {
            MMRNode* parent = cur->parent;   // pointer hop

            if (parent->left == cur) {
                // cur is LEFT child → sibling is RIGHT
                proof.intra_proof.push_back({ parent->right->hash, "R" });
            } else {
                // cur is RIGHT child → sibling is LEFT
                proof.intra_proof.push_back({ parent->left->hash, "L" });
            }
            cur = cur->parent;   // pointer hop — same as merkle_tree.hpp
        }
        // cur is now the peak root for this leaf

        // ── Step 2: collect all peak hashes; find which peak is ours ─────
        for (int p = 0; p < static_cast<int>(peaks_.size()); ++p) {
            proof.peak_hashes.push_back(peaks_[p]->hash);
            if (peaks_[p] == cur) proof.leaf_peak_idx = p;
        }

        return proof;
    }

    // ------------------------------------------------------------------
    // verify_proof()  —  O(log n)  (static — no tree traversal)
    //
    // Step 1: reconstruct the leaf's peak root from intra_proof
    //         (same loop as merkle_tree.hpp::verify_proof).
    // Step 2: substitute the reconstructed peak root into the peak list
    //         and re-bag to get the MMR root.  Compare with expected_root.
    // ------------------------------------------------------------------
    static bool verify_proof(
        const std::string&  leaf_hash,
        const Proof&        proof,
        const std::string&  expected_root)
    {
        // Step 1 — climb within the peak
        std::string current = leaf_hash;
        for (const auto& step : proof.intra_proof) {
            const std::string& sibling   = step.first;
            const std::string& direction = step.second;
            current = (direction == "R") ? combine(current, sibling)
                                         : combine(sibling, current);
        }
        // current == reconstructed peak root

        // Step 2 — re-bag
        if (proof.leaf_peak_idx < 0 ||
            proof.leaf_peak_idx >= static_cast<int>(proof.peak_hashes.size()))
            return false;

        std::string bag = "";
        for (int p = 0; p < static_cast<int>(proof.peak_hashes.size()); ++p) {
            std::string ph = (p == proof.leaf_peak_idx) ? current
                                                        : proof.peak_hashes[p];
            bag = bag.empty() ? ph : combine(bag, ph);
        }

        return bag == expected_root;
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------
    size_t leaf_count()  const { return n_; }
    int    peak_count()  const { return static_cast<int>(peaks_.size()); }
    bool   is_empty()    const { return n_ == 0; }

    // Height of the tallest peak (== floor(log2(n)) when n > 0)
    int    max_height()  const {
        return peaks_.empty() ? 0 : peaks_.front()->height;
    }

    // ------------------------------------------------------------------
    // print_tree()  —  summary + per-peak breakdown
    // ------------------------------------------------------------------
    void print_tree() const {
        std::cout << "\n";
        std::cout << "  +==============================================================+\n";
        std::cout << "  |         MERKLE MOUNTAIN RANGE  --  STATUS REPORT            |\n";
        std::cout << "  +==============================================================+\n";

        auto row_fn = [](const std::string& key, const std::string& val) {
            std::cout << "  |  " << std::left << std::setw(16) << key
                      << ": " << std::setw(42) << val << " |\n";
        };

        row_fn("Leaves",       std::to_string(n_));
        row_fn("Peaks",        std::to_string(peaks_.size()));
        row_fn("Max height",   std::to_string(max_height()));
        row_fn("Total nodes",  std::to_string(all_nodes_.size()));
        row_fn("MMR root",     short_h(get_root(), 48));

        std::cout << "  +--------------------------------------------------------------+\n";
        std::cout << "  |  Peak breakdown  (tallest → shortest):                       |\n";
        std::cout << "  +---------+----------+------------------------------------------+\n";
        std::cout << "  |  Peak # |  Height  |  Root hash (preview)                     |\n";
        std::cout << "  +---------+----------+------------------------------------------+\n";

        for (int p = 0; p < static_cast<int>(peaks_.size()); ++p) {
            int leaves_in_peak = 1 << peaks_[p]->height;
            std::ostringstream info;
            info << short_h(peaks_[p]->hash, 30)
                 << "  (" << leaves_in_peak << " leaf" << (leaves_in_peak > 1 ? "ves" : "") << ")";
            std::cout << "  | " << std::right << std::setw(7) << p
                      << " | " << std::right << std::setw(8) << peaks_[p]->height
                      << " | " << std::left  << std::setw(40) << info.str()
                      << " |\n";
        }

        std::cout << "  +---------+----------+------------------------------------------+\n\n";
    }

    void print_proof(
        int leaf_index,
        const Proof& proof,
        bool verified) const
    {
        std::cout << "\n  +====== MMR Inclusion Proof =================================+\n";
        std::cout << "  | Leaf index : " << leaf_index << "\n";
        std::cout << "  | Intra steps: " << proof.intra_proof.size()
                  << "  (within its peak)\n";
        std::cout << "  | Peak count : " << proof.peak_hashes.size() << "\n";
        std::cout << "  | Leaf peak  : peaks_[" << proof.leaf_peak_idx << "]\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        std::cout << "  |  Intra-peak path (leaf -> peak root):\n";
        for (size_t i = 0; i < proof.intra_proof.size(); ++i) {
            std::cout << "  |    Step " << (i + 1) << " : sibling "
                      << (proof.intra_proof[i].second == "R" ? "RIGHT" : "LEFT ")
                      << " = " << short_h(proof.intra_proof[i].first, 20) << "\n";
        }

        std::cout << "  |  Bagging peaks:\n";
        for (size_t p = 0; p < proof.peak_hashes.size(); ++p) {
            std::cout << "  |    peaks_[" << p << "] = " << short_h(proof.peak_hashes[p], 20);
            if (static_cast<int>(p) == proof.leaf_peak_idx)
                std::cout << "  <- leaf's peak (reconstructed)";
            std::cout << "\n";
        }

        std::cout << "  |\n";
        std::cout << "  | Result : "
                  << (verified ? "[OK]  VERIFIED" : "[!!] MISMATCH") << "\n";
        std::cout << "  +===========================================================+\n\n";
    }
};

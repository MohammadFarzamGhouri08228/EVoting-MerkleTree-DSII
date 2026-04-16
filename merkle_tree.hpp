#pragma once
// =============================================================================
// merkle_tree.hpp  —  Global Merkle Tree implementation
//
// Stores all ballot hashes as leaf nodes, combines them bottom-up into a
// single root hash, and supports Merkle proof generation and verification.
//
// Structure:
//   levels_[0]          = leaf hashes  (one per ballot)
//   levels_[1]          = parent nodes of leaves
//   ...
//   levels_.back()[0]   = root hash    (represents the entire ballot set)
//
// Complexity:
//   build()             : O(n)       — n = number of leaf hashes
//   generate_proof()    : O(log n)   — one sibling per level
//   verify_proof()      : O(log n)   — one hash per level
//   print_tree()        : O(n)       — visits every node once
// =============================================================================
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include "sha256.hpp"

class MerkleTree {

    // All levels of the tree.
    // levels_[0]  = leaves (bottom)
    // levels_.back() = root level (top, always size 1)
    std::vector<std::vector<std::string>> levels_;

    // Combine two child hashes into one parent hash.
    // Parent = SHA-256(left_hash + right_hash)
    static std::string combine(const std::string& left, const std::string& right) {
        return sha256(left + right);
    }

    // Display helper: truncate a hash for readable terminal output.
    static std::string short_h(const std::string& h, size_t len = 10) {
        return (h.size() > len) ? h.substr(0, len) + ".." : h;
    }

public:

    // -------------------------------------------------------------------------
    // Build the tree bottom-up from leaf hashes.
    //
    // Algorithm:
    //   At each level, pair adjacent nodes and hash them together.
    //   If a level has an odd number of nodes, the last node is paired
    //   with itself (duplicated) to maintain a complete binary structure.
    //
    // O(n) — total nodes across all levels ≈ 2n
    // -------------------------------------------------------------------------
    void build(const std::vector<std::string>& leaf_hashes) {
        levels_.clear();
        if (leaf_hashes.empty()) return;

        levels_.push_back(leaf_hashes);          // level 0 = leaves

        while (levels_.back().size() > 1) {
            const auto& prev = levels_.back();
            std::vector<std::string> next;

            for (size_t i = 0; i < prev.size(); i += 2) {
                const std::string& left  = prev[i];
                // If odd number of nodes, duplicate the last one
                const std::string& right = (i + 1 < prev.size()) ? prev[i + 1] : prev[i];
                next.push_back(combine(left, right));
            }
            levels_.push_back(next);
        }
    }

    // Return the root hash (empty string if tree not built).
    std::string get_root() const {
        if (levels_.empty()) return "";
        return levels_.back()[0];
    }

    bool is_built()    const { return !levels_.empty(); }
    int  leaf_count()  const { return levels_.empty() ? 0 : (int)levels_[0].size(); }
    int  level_count() const { return (int)levels_.size(); }

    // -------------------------------------------------------------------------
    // Generate a Merkle proof for the leaf at leaf_index.
    //
    // A Merkle proof is the list of sibling hashes along the path from the
    // target leaf to the root. Each entry is:
    //   (sibling_hash, direction)
    // where direction:
    //   "R" = sibling is on the RIGHT  → parent = SHA-256(current + sibling)
    //   "L" = sibling is on the LEFT   → parent = SHA-256(sibling + current)
    //
    // O(log n) — one entry per tree level
    // -------------------------------------------------------------------------
    std::vector<std::pair<std::string, std::string>>
    generate_proof(int leaf_index) const {
        if (!is_built())
            throw std::logic_error("Tree has not been built yet.");
        if (leaf_index < 0 || leaf_index >= leaf_count())
            throw std::out_of_range("leaf_index out of range.");

        std::vector<std::pair<std::string, std::string>> proof;
        int idx = leaf_index;

        for (int lvl = 0; lvl < (int)levels_.size() - 1; ++lvl) {
            const auto& cur = levels_[lvl];

            int    sibling_idx;
            std::string direction;

            if (idx % 2 == 0) {
                // Current node is a LEFT child → sibling is to the right
                sibling_idx = idx + 1;
                direction   = "R";
            } else {
                // Current node is a RIGHT child → sibling is to the left
                sibling_idx = idx - 1;
                direction   = "L";
            }

            // Handle duplicated last node on odd-sized levels
            if (sibling_idx >= (int)cur.size())
                sibling_idx = idx;

            proof.push_back({ cur[sibling_idx], direction });
            idx /= 2;   // move to parent index on next level
        }
        return proof;
    }

    // -------------------------------------------------------------------------
    // Verify a Merkle proof.
    //
    // Recomputes the root by combining leaf_hash with each sibling in the proof
    // list (in order, honouring direction). Returns true if the result equals
    // the provided root hash.
    //
    // O(log n) — one SHA-256 call per proof step
    // -------------------------------------------------------------------------
    static bool verify_proof(
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& root)
    {
        std::string current = leaf_hash;
        for (const auto& step : proof) {
            const std::string& sibling   = step.first;
            const std::string& direction = step.second;
            if (direction == "R")
                current = combine(current, sibling);   // current is left child
            else
                current = combine(sibling, current);   // current is right child
        }
        return current == root;
    }

    // -------------------------------------------------------------------------
    // Print all tree levels in a readable top-down format.
    // Labels: ROOT → intermediate levels → LEAF
    // -------------------------------------------------------------------------
    void print_tree() const {
        if (!is_built()) {
            std::cout << "  [!] Tree has not been built yet.\n";
            return;
        }
        std::cout << "\n";
        std::cout << "  +----- Merkle Tree  (" << leaf_count()
                  << " leaves, " << level_count() << " levels) -----+\n";

        // Print from top (root) down to leaves
        for (int lvl = (int)levels_.size() - 1; lvl >= 0; --lvl) {
            std::string label;
            if (lvl == (int)levels_.size() - 1) label = " ROOT  ";
            else if (lvl == 0)                  label = " LEAVES";
            else                                label = " Lvl " + std::to_string(lvl) + " ";

            std::cout << "  |" << label << " [" << lvl << "] : ";
            for (const auto& h : levels_[lvl])
                std::cout << " " << short_h(h, 10);
            std::cout << "\n";
        }
        std::cout << "  +---------------------------------------------------+\n";
        std::cout << "  Full root: " << get_root() << "\n\n";
    }

    // -------------------------------------------------------------------------
    // Visualise a proof path step-by-step in the terminal.
    //
    // Shows each combination step from leaf to root and reports whether the
    // recomputed root matches the expected root (root_to_check).
    //
    // Use root_to_check = get_root() for normal verification.
    // Use the OLD root (saved before tampering) to demonstrate that a tampered
    // ballot breaks the proof.
    // -------------------------------------------------------------------------
    void print_proof_path(
        const std::string& receipt_id,
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& root_to_check) const
    {
        std::cout << "\n";
        std::cout << "  +====== Merkle Proof  ======================================+\n";
        std::cout << "  | Receipt : " << receipt_id << "\n";
        std::cout << "  | Leaf    : " << leaf_hash  << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        std::string current = leaf_hash;
        for (size_t i = 0; i < proof.size(); ++i) {
            const std::string& sibling   = proof[i].first;
            const std::string& direction = proof[i].second;
            std::string parent;

            std::cout << "  | Step " << (i + 1) << ":\n";
            if (direction == "R") {
                parent = combine(current, sibling);
                std::cout << "  |   current (left)  : " << short_h(current, 20) << "\n";
                std::cout << "  |   sibling (right) : " << short_h(sibling, 20) << "\n";
            } else {
                parent = combine(sibling, current);
                std::cout << "  |   sibling (left)  : " << short_h(sibling, 20) << "\n";
                std::cout << "  |   current (right) : " << short_h(current, 20) << "\n";
            }
            std::cout << "  |   parent          : " << short_h(parent, 20) << "\n";
            current = parent;
        }

        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | Computed root : " << current       << "\n";
        std::cout << "  | Expected root : " << root_to_check << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        bool match = (current == root_to_check);
        if (match)
            std::cout << "  | Result : [OK]  MATCH  --  Vote VERIFIED successfully.\n";
        else
            std::cout << "  | Result : [!!] MISMATCH  --  Proof INVALID (tamper detected?).\n";
        std::cout << "  +===========================================================+\n\n";
    }
};

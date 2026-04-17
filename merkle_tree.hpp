#pragma once
// =============================================================================
// merkle_tree.hpp  --  Global Merkle Tree implementation
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
//   build()             : O(n)       -- n = number of leaf hashes
//   generate_proof()    : O(log n)   -- one sibling per level
//   verify_proof()      : O(log n)   -- one hash per level
//   print_tree()        : O(n)       -- visits every node once
// =============================================================================
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>
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

    // Truncate a hash to `len` chars + ".." suffix for readable terminal output.
    static std::string short_h(const std::string& h, size_t len = 10) {
        return (h.size() > len) ? h.substr(0, len) + ".." : h;
    }

    // Total node count across all levels.
    int total_nodes() const {
        int c = 0;
        for (const auto& lvl : levels_) c += (int)lvl.size();
        return c;
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
    // O(n) -- total nodes across all levels ~= 2n
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
                // Odd count: duplicate the last node (ceil rule)
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
    //   "R" = sibling is on the RIGHT  -> parent = SHA-256(current + sibling)
    //   "L" = sibling is on the LEFT   -> parent = SHA-256(sibling + current)
    //
    // O(log n) -- one entry per tree level
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

            int sibling_idx;
            std::string direction;

            if (idx % 2 == 0) {
                // Current node is a LEFT child -> sibling is to the right
                sibling_idx = idx + 1;
                direction   = "R";
            } else {
                // Current node is a RIGHT child -> sibling is to the left
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
    // O(log n) -- one SHA-256 call per proof step
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
                current = combine(current, sibling);
            else
                current = combine(sibling, current);
        }
        return current == root;
    }

    // =========================================================================
    // VISUALIZATION
    // =========================================================================

    // -------------------------------------------------------------------------
    // print_tree_visual()
    //
    // Draws an ASCII binary tree diagram showing the top 4 levels of the tree
    // (root down). For small trees that fit in 4 levels (<=8 leaves) the full
    // tree is shown. For larger trees the bottom row represents subtree-roots
    // and a note shows the remaining depth.
    //
    // Layout:
    //   - Bottom display row has 2^(VIS_ROWS-1) slots, each SLOT_W chars wide.
    //   - Node labels are centered in their slot.
    //   - "/" and "\" connector rows link each parent to its two children.
    // -------------------------------------------------------------------------
    void print_tree_visual() const {
        if (!is_built()) {
            std::cout << "  [!] Tree not built yet.\n";
            return;
        }

        const int VIS_ROWS = std::min(level_count(), 4); // levels to draw
        const int SLOT_W   = 12;  // chars per bottom-slot

        // Bottom row slot count = 2^(VIS_ROWS-1)
        int bottom_slots = 1 << (VIS_ROWS - 1);
        int total_w      = bottom_slots * SLOT_W;

        std::cout << "\n";

        for (int row = 0; row < VIS_ROWS; row++) {
            // row 0 = actual root, row VIS_ROWS-1 = deepest drawn level
            int actual_lvl = level_count() - 1 - row;
            const auto& lvl = levels_[actual_lvl];

            int n_slots  = 1 << row;          // slots at this row = 2^row
            int slot_w   = total_w / n_slots;
            int n_show   = std::min(n_slots, (int)lvl.size());

            // ── Build node line ────────────────────────────────────
            std::string line(total_w, ' ');

            for (int j = 0; j < n_show; j++) {
                std::string label;
                if (row == 0)
                    label = "[ROOT:" + short_h(lvl[j], 6) + "]";  // 16 chars
                else
                    label = "[" + short_h(lvl[j], 8) + "]";        // 12 chars

                int center = j * slot_w + slot_w / 2;
                int start  = center - (int)label.size() / 2;
                start = std::max(0, std::min(start, total_w - (int)label.size()));

                for (int k = 0; k < (int)label.size() && start + k < total_w; k++)
                    line[start + k] = label[k];
            }
            std::cout << "  " << line << "\n";

            // ── Draw connector lines to next row ───────────────────
            if (row < VIS_ROWS - 1) {
                int next_slot_w = slot_w / 2;
                // Use 2 connector rows when slots are wide enough, else 1
                int n_conn = (slot_w >= 24) ? 2 : 1;

                for (int cr = 0; cr < n_conn; cr++) {
                    float t = (float)(cr + 1) / (float)(n_conn + 1);
                    std::string cline(total_w, ' ');

                    for (int j = 0; j < n_show; j++) {
                        int pc  = j * slot_w        + slot_w       / 2;
                        int lcc = (2 * j    ) * next_slot_w + next_slot_w / 2;
                        int rcc = (2 * j + 1) * next_slot_w + next_slot_w / 2;

                        int sp = (int)std::round(pc + t * (lcc - pc));
                        int bp = (int)std::round(pc + t * (rcc - pc));

                        if (sp >= 0 && sp < total_w) cline[sp] = '/';
                        if (bp >= 0 && bp < total_w) cline[bp] = '\\';
                    }
                    std::cout << "  " << cline << "\n";
                }
            }
        }

        // ── Truncation note for deep trees ────────────────────────
        if (level_count() > VIS_ROWS) {
            int hidden = level_count() - VIS_ROWS;
            std::string pad(total_w / 3, ' ');
            std::cout << "  " << pad
                      << "... (" << hidden << " more level"
                      << (hidden > 1 ? "s" : "") << "  |  "
                      << leaf_count() << " leaves total) ...\n";
        }
        std::cout << "\n";
    }

    // -------------------------------------------------------------------------
    // print_tree()
    //
    // Full display: statistics header + level breakdown table + ASCII diagram.
    // -------------------------------------------------------------------------
    void print_tree() const {
        if (!is_built()) {
            std::cout << "  [!] Tree has not been built yet.\n";
            return;
        }

        int  n        = leaf_count();
        int  h        = level_count();
        int  tn       = total_nodes();
        bool balanced = (n > 0) && ((n & (n - 1)) == 0);
        double log2n  = (n > 1) ? std::log2((double)n) : 0.0;

        // ── Statistics header ──────────────────────────────────────
        std::cout << "\n";
        std::cout << "  +==============================================================+\n";
        std::cout << "  |                MERKLE TREE  --  STATUS REPORT               |\n";
        std::cout << "  +==============================================================+\n";

        auto row = [](const std::string& key, const std::string& val) {
            std::cout << "  |  " << std::left << std::setw(16) << key
                      << ": " << std::setw(42) << val << " |\n";
        };

        row("Leaves",      std::to_string(n));
        row("Height",      std::to_string(h) + " levels");
        row("Total nodes", std::to_string(tn));

        {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(2) << log2n
                << "  (min tree height = " << (int)std::ceil(log2n) + 1 << ")";
            row("log2(leaves)", oss.str());
        }

        row("Balanced", balanced
            ? "YES  --  perfect binary tree (power of 2 leaves)"
            : "NEAR --  odd leaves duplicated via ceil rule");

        std::cout << "  |  " << std::left << std::setw(16) << "Root hash"
                  << ": " << get_root().substr(0, 50) << ".. |\n";
        std::cout << std::right;
        std::cout << "  +--------------------------------------------------------------+\n";

        // ── Level breakdown table ──────────────────────────────────
        std::cout << "\n";
        std::cout << "  Level Breakdown  (Root -> Leaves):\n";
        std::cout << "  +---------+-------+-----------+------------------------------------+\n";
        std::cout << "  |  Label  |  Lvl  |   Nodes   |  Hash preview (up to 3 nodes)      |\n";
        std::cout << "  +---------+-------+-----------+------------------------------------+\n";

        for (int lvl = (int)levels_.size() - 1; lvl >= 0; --lvl) {
            const auto& nodes = levels_[lvl];

            std::string lbl;
            if      (lvl == (int)levels_.size() - 1) lbl = "ROOT   ";
            else if (lvl == 0)                        lbl = "LEAVES ";
            else {
                lbl = "Lvl " + std::to_string(lvl);
                lbl.resize(7, ' ');
            }

            // Build preview string
            std::ostringstream preview;
            int show = std::min((int)nodes.size(), 3);
            for (int j = 0; j < show; j++) {
                preview << short_h(nodes[j], 10);
                if (j < show - 1) preview << "  ";
            }
            if ((int)nodes.size() > 3)
                preview << "  ...+" << (nodes.size() - 3) << " more";

            std::cout << "  | " << std::left << std::setw(7)  << lbl
                      << " | "  << std::right << std::setw(5) << lvl
                      << " | "  << std::right << std::setw(9) << nodes.size()
                      << " | "  << std::left  << std::setw(34) << preview.str()
                      << " |\n" << std::right;
        }
        std::cout << "  +---------+-------+-----------+------------------------------------+\n";

        // ── ASCII diagram ──────────────────────────────────────────
        std::cout << "\n  ASCII Diagram";
        if (level_count() <= 4)
            std::cout << "  (full tree -- " << level_count() << " levels):\n";
        else
            std::cout << "  (top " << std::min(4, level_count())
                      << " of " << level_count() << " levels -- tree too deep for full display):\n";

        print_tree_visual();
    }

    // -------------------------------------------------------------------------
    // print_proof_path()
    //
    // Visualises a Merkle proof step-by-step in the terminal.
    //
    // Shows a compact path summary (LEAF -> L/R -> ... -> ROOT), then each
    // combination step from leaf to root, and reports whether the recomputed
    // root matches root_to_check.
    //
    // Use root_to_check = get_root() for normal verification.
    // Use the OLD root (saved before tampering) to show proof failure.
    // -------------------------------------------------------------------------
    void print_proof_path(
        const std::string& receipt_id,
        const std::string& leaf_hash,
        const std::vector<std::pair<std::string, std::string>>& proof,
        const std::string& root_to_check) const
    {
        // ── Path direction summary ─────────────────────────────────
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

        // ── Step-by-step combination ───────────────────────────────
        std::string current = leaf_hash;
        for (size_t i = 0; i < proof.size(); ++i) {
            const std::string& sibling   = proof[i].first;
            const std::string& direction = proof[i].second;
            std::string parent;

            std::cout << "  |\n";
            std::cout << "  |  Step " << (i + 1) << " / " << proof.size()
                      << "  (sibling is " << (direction == "R" ? "RIGHT" : "LEFT") << "):\n";

            if (direction == "R") {
                parent = combine(current, sibling);
                std::cout << "  |    [current] (left ) : " << short_h(current, 20) << "\n";
                std::cout << "  |    [sibling] (right) : " << short_h(sibling, 20) << "\n";
            } else {
                parent = combine(sibling, current);
                std::cout << "  |    [sibling] (left ) : " << short_h(sibling, 20) << "\n";
                std::cout << "  |    [current] (right) : " << short_h(current, 20) << "\n";
            }
            std::cout << "  |    SHA256(L + R)      : " << short_h(parent, 20) << "\n";
            current = parent;
        }

        // ── Final verification ─────────────────────────────────────
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
            std::cout << "  |          Root changed: ballot may have been tampered.     |\n";
        }
        std::cout << "  +===========================================================+\n\n";
    }
};

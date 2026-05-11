#include "header/merkle_mountain_range.hpp"
#include <stdexcept>

void MerkleMMR::append(const std::string& leaf_hash) {
    // Step 1: every append starts as a height-0 peak.
    // At this instant the new leaf is also a complete tree by itself.
    MMRNode* leaf = make_node(leaf_hash, 0);
    leaves_.push_back(leaf);
    peaks_.push_back(leaf);
    n_ = leaves_.size();

    // Step 2: merge peaks while the last two have equal height.
    //
    // This is the key MMR operation. It behaves like binary addition:
    // adding one leaf can cause a chain of "carries".
    //
    // Example:
    //   before append: peaks heights [2, 1, 0]
    //   append leaf:  peaks heights [2, 1, 0, 0]
    //   merge 0+0 -> 1: [2, 1, 1]
    //   merge 1+1 -> 2: [2, 2]
    //   merge 2+2 -> 3: [3]
    //
    // Because each merge doubles a perfect tree, the forest always remains
    // a list of perfect binary Merkle trees.
    while (peaks_.size() >= 2) {
        MMRNode* r = peaks_.back();
        MMRNode* l = peaks_[peaks_.size() - 2];
        if (l->height != r->height) break;

        peaks_.pop_back();
        peaks_.pop_back();

        std::string parent_hash = combine(l->hash, r->hash);
        MMRNode* parent = make_node(parent_hash, l->height + 1);

        // Link children and parent so proofs can later walk from a leaf upward.
        parent->left = l;
        parent->right = r;
        l->parent = parent;
        r->parent = parent;

        peaks_.push_back(parent);
    }
}

std::string MerkleMMR::get_root() const {
    if (peaks_.empty()) return sha256("empty");

    // An MMR has several peak roots, not just one tree root.
    // "Bagging" combines these peak hashes into one final commitment.
    // Folding right-to-left must match verify_proof().
    std::string root = peaks_.back()->hash;
    for (int i = static_cast<int>(peaks_.size()) - 2; i >= 0; --i)
        root = combine(peaks_[i]->hash, root);
    return root;
}

MerkleMMR::Proof MerkleMMR::generate_proof(int leaf_index) const {
    if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
        throw std::out_of_range("leaf_index out of range");

    Proof proof;

    // Locate which peak contains this leaf.
    // A peak of height h contains 2^h leaves, so we can scan peaks and count
    // leaf ranges until leaf_index falls inside one range.
    int acc = 0;
    int peak_idx = 0;
    for (size_t i = 0; i < peaks_.size(); ++i) {
        int leaves_in_peak = 1 << peaks_[i]->height; // 2^h leaves
        if (leaf_index >= acc && leaf_index < acc + leaves_in_peak) {
            peak_idx = static_cast<int>(i);
            break;
        }
        acc += leaves_in_peak;
    }

    // Build the intra-peak Merkle proof.
    // Starting from the target leaf, move upward to the peak root and record
    // each sibling hash. The direction tells verification which side the
    // sibling belongs on during recomputation.
    MMRNode* peak_root = peaks_[peak_idx];
    MMRNode* cur = leaves_[leaf_index];
    while (cur != peak_root) {
        MMRNode* parent = cur->parent;
        if (!parent) break;
        if (parent->left == cur) {
            std::string sibling = parent->right ? parent->right->hash : cur->hash;
            proof.intra_proof.push_back({sibling, "R"});
        } else {
            proof.intra_proof.push_back({parent->left->hash, "L"});
        }
        cur = parent;
    }

    // Store all peak hashes so the verifier can bag them into the final MMR root.
    // The proved leaf only reconstructs one peak; the other peak hashes are
    // needed to recompute the whole MMR commitment.
    proof.peak_hashes.reserve(peaks_.size());
    for (auto* p : peaks_) proof.peak_hashes.push_back(p->hash);
    proof.leaf_peak_idx = peak_idx;

    return proof;
}

void MerkleMMR::rollback(size_t new_leaf_count) {
    if (new_leaf_count > n_) throw std::out_of_range("new_leaf_count exceeds current leaf count");
    if (new_leaf_count == n_) return;

    // Keep only the trusted prefix of leaf hashes, then rebuild the MMR.
    // Rebuilding is heavier than pointer-trimming, but it is simple and safe:
    // append() recreates correct peaks and parent links from the trusted leaves.
    std::vector<std::string> hashes;
    hashes.reserve(new_leaf_count);
    for (size_t i = 0; i < new_leaf_count; ++i) hashes.push_back(leaves_[i]->hash);

    free_all();
    for (const auto& h : hashes) append(h);
}

void MerkleMMR::take_snapshot() {
    // A snapshot is an audit checkpoint. It stores enough information to
    // reconstruct the exact MMR leaf sequence from a known-good interval.
    Snapshot s;
    s.leaf_count = n_;
    s.leaf_hashes.reserve(leaves_.size());
    for (auto* l : leaves_) s.leaf_hashes.push_back(l->hash);
    s.root = get_root();
    snapshots_.push_back(std::move(s));
}

size_t MerkleMMR::snapshot_count() const { return snapshots_.size(); }

bool MerkleMMR::is_tampered_since_snapshot(size_t snapshot_index) const {
    if (snapshot_index >= snapshots_.size()) throw std::out_of_range("snapshot_index out of range");
    return snapshots_[snapshot_index].root != get_root();
}

void MerkleMMR::rollback_to_snapshot(size_t snapshot_index) {
    if (snapshot_index >= snapshots_.size()) throw std::out_of_range("snapshot_index out of range");
    const Snapshot& s = snapshots_[snapshot_index];

    // Restore by deleting the live forest and replaying the checkpoint leaves.
    free_all();
    for (const auto& h : s.leaf_hashes) append(h);
}

bool MerkleMMR::verify_proof(const std::string& leaf_hash, const Proof& proof, const std::string& expected_root) {
    // Step 1: reconstruct the root of the target leaf's peak.
    // Direction "R" means sibling is on the right: hash(current || sibling).
    // Direction "L" means sibling is on the left: hash(sibling || current).
    std::string current = leaf_hash;
    for (const auto& step : proof.intra_proof) {
        const std::string& sibling = step.first;
        const std::string& dir = step.second;
        current = (dir == "R") ? combine(current, sibling) : combine(sibling, current);
    }

    // Step 2: replace the original peak hash with the reconstructed one.
    // If the proof is honest, this value should match that peak's real hash.
    std::vector<std::string> peaks = proof.peak_hashes;
    if (proof.leaf_peak_idx < 0 || proof.leaf_peak_idx >= static_cast<int>(peaks.size())) return false;
    peaks[proof.leaf_peak_idx] = current;

    // Step 3: bag all peaks into the overall MMR root and compare it to the
    // published/expected root.
    std::string root = peaks.back();
    for (int i = static_cast<int>(peaks.size()) - 2; i >= 0; --i) root = combine(peaks[i], root);
    return root == expected_root;
}

void MerkleMMR::print_tree() const {
    std::cout << "MMR leaves=" << leaves_.size() << " peaks=" << peaks_.size() << " root=" << get_root() << "\n";
}

void MerkleMMR::print_proof(int leaf_index, const Proof& proof, bool verified) const {
    std::cout << "Proof for leaf=" << leaf_index << " verified=" << (verified ? "YES" : "NO") << "\n";
    std::cout << " Intra-steps: " << proof.intra_proof.size() << "\n";
    for (size_t i = 0; i < proof.intra_proof.size(); ++i) {
        std::cout << "  [" << i << "] " << proof.intra_proof[i].second << " " << proof.intra_proof[i].first << "\n";
    }
    std::cout << " Peak hashes: " << proof.peak_hashes.size() << " (leaf_peak_idx=" << proof.leaf_peak_idx << ")\n";
}

// Helper: build peak hashes from a vector of leaf hashes without mutating this MMR.
// This is used during audit: we independently recompute what the peaks SHOULD be
// from the leaf vector, then compare that to the live peak/root state.
static std::vector<std::string> build_peaks_from_leaves(const std::vector<std::string>& leaf_hashes) {
    struct Temp { std::string hash; int height; };
    std::vector<Temp> peaks;
    peaks.reserve(leaf_hashes.size());
    for (const auto &h : leaf_hashes) {
        // Same binary-carry merge idea as append(), but using lightweight Temp nodes.
        peaks.push_back(Temp{h, 0});
        while (peaks.size() >= 2) {
            auto &a = peaks[peaks.size()-2];
            auto &b = peaks[peaks.size()-1];
            if (a.height != b.height) break;
            std::string parent = sha256(a.hash + b.hash);
            int ph = a.height + 1;
            peaks.pop_back(); peaks.pop_back();
            peaks.push_back(Temp{parent, ph});
        }
    }
    std::vector<std::string> out; out.reserve(peaks.size());
    for (auto &p : peaks) out.push_back(p.hash);
    return out;
}

bool MerkleMMR::check_and_rotate_interval(size_t &invalidated_from) {
    // This function is the interval audit.
    //
    // Safety-first design:
    // 1. Copy the current leaf hashes.
    // 2. Recompute the expected MMR root from those copied leaves.
    // 3. Compare against the live MMR state and previous trusted snapshot.
    // 4. If anything is inconsistent, rollback to the previous snapshot.

    // ---- Step 1: Copy leaf vector from the live MMR ----
    Snapshot current_copy;
    current_copy.leaf_count = leaves_.size();
    current_copy.leaf_hashes.reserve(leaves_.size());
    for (auto* l : leaves_) current_copy.leaf_hashes.push_back(l->hash);

    // ---- Step 2: Generate peaks from the copied leaves ----
    auto copied_peak_hashes = build_peaks_from_leaves(current_copy.leaf_hashes);

    // Bag copied peaks into a single root (right-to-left fold)
    std::string copied_root = copied_peak_hashes.empty() ? sha256("empty") : copied_peak_hashes.back();
    for (int i = static_cast<int>(copied_peak_hashes.size()) - 2; i >= 0; --i)
        copied_root = sha256(copied_peak_hashes[i] + copied_root);
    current_copy.root = copied_root;

    // ---- First interval: no previous copy exists yet ----
    if (snapshots_.empty()) {
        snapshots_.push_back(current_copy);
        invalidated_from = 0;
        return false;
    }

    // ---- We now have two copies: previous (index 0) and current ----
    const Snapshot& prev = snapshots_[0];
    bool tampered = false;

    // ---- Check 1: Node count — did the leaf count shrink unexpectedly? ----
    if (current_copy.leaf_count < prev.leaf_count) {
        tampered = true;
    }

    // ---- Check 2: Earlier-node integrity ----
    // Compare every leaf that existed at the previous interval.
    // If ANY earlier leaf hash changed (even if count is the same), it's tampering.
    if (!tampered) {
        size_t overlap = std::min(prev.leaf_count, current_copy.leaf_count);
        for (size_t i = 0; i < overlap; ++i) {
            if (prev.leaf_hashes[i] != current_copy.leaf_hashes[i]) {
                tampered = true;
                break;
            }
        }
    }

    // ---- Check 3: Root comparison ----
    // Compare the root built from the copied leaves against the live peaks root.
    // A leaf-only tamper (no propagation) makes these diverge.
    if (!tampered) {
        std::string live_root = get_root();
        if (copied_root != live_root) {
            tampered = true;
        }
    }

    // ---- Tamper detected: rollback to previous interval ----
    if (tampered) {
        // Delete current peaks and all nodes.
        free_all();

        // Rebuild MMR from the previous interval's trusted leaf hashes.
        // This is intentionally conservative: even if it costs more, it restores
        // the exact last-known-good root and leaf sequence.
        for (const auto& h : prev.leaf_hashes) append(h);
        size_t restored_leaf_count = leaves_.size();

        // Make the restored state the new "previous" snapshot (only one copy remains)
        snapshots_.clear();
        Snapshot fresh;
        fresh.leaf_count = leaves_.size();
        fresh.leaf_hashes.reserve(leaves_.size());
        for (auto* l : leaves_) fresh.leaf_hashes.push_back(l->hash);
        fresh.root = get_root();
        snapshots_.push_back(fresh);

        // All votes after the previous interval are invalid
        invalidated_from = restored_leaf_count;
        return true;
    }

    // ---- No tampering: delete previous copy, keep only current copy ----
    snapshots_.clear();
    snapshots_.push_back(std::move(current_copy));
    invalidated_from = 0;
    return false;
}

// ---------------------------------------------------------------------------
// tamper_leaf_only — changes a leaf hash WITHOUT propagating to ancestors.
// This creates a detectable inconsistency: the live peaks still hold old
// hashes, so check_and_rotate_interval will catch it.
// ---------------------------------------------------------------------------
void MerkleMMR::tamper_leaf_only(size_t leaf_index, const std::string& new_hash) {
    if (leaf_index >= leaves_.size())
        throw std::out_of_range("tamper_leaf_only: leaf_index out of range");
    leaves_[leaf_index]->hash = new_hash;
    // Intentionally NOT calling recompute() on ancestors
}


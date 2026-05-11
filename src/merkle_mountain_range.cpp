#include "header/merkle_mountain_range.hpp"
#include <stdexcept>

void MerkleMMR::append(const std::string& leaf_hash) {
    MMRNode* leaf = make_node(leaf_hash, 0);
    leaves_.push_back(leaf);
    peaks_.push_back(leaf);
    n_ = leaves_.size();

    // Merge peaks while the last two have equal height
    while (peaks_.size() >= 2) {
        MMRNode* r = peaks_.back();
        MMRNode* l = peaks_[peaks_.size() - 2];
        if (l->height != r->height) break;

        peaks_.pop_back();
        peaks_.pop_back();

        std::string parent_hash = combine(l->hash, r->hash);
        MMRNode* parent = make_node(parent_hash, l->height + 1);
        parent->left = l;
        parent->right = r;
        l->parent = parent;
        r->parent = parent;

        peaks_.push_back(parent);
    }
}

std::string MerkleMMR::get_root() const {
    if (peaks_.empty()) return sha256("empty");
    std::string root = peaks_.back()->hash;
    for (int i = static_cast<int>(peaks_.size()) - 2; i >= 0; --i)
        root = combine(peaks_[i]->hash, root);
    return root;
}

MerkleMMR::Proof MerkleMMR::generate_proof(int leaf_index) const {
    if (leaf_index < 0 || leaf_index >= static_cast<int>(leaves_.size()))
        throw std::out_of_range("leaf_index out of range");

    Proof proof;

    // locate which peak contains this leaf by counting leaves in each peak
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

    // intra-proof: walk from leaf node up to the peak root
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

    // peak hashes (for bagging)
    proof.peak_hashes.reserve(peaks_.size());
    for (auto* p : peaks_) proof.peak_hashes.push_back(p->hash);
    proof.leaf_peak_idx = peak_idx;

    return proof;
}

void MerkleMMR::rollback(size_t new_leaf_count) {
    if (new_leaf_count > n_) throw std::out_of_range("new_leaf_count exceeds current leaf count");
    if (new_leaf_count == n_) return;

    std::vector<std::string> hashes;
    hashes.reserve(new_leaf_count);
    for (size_t i = 0; i < new_leaf_count; ++i) hashes.push_back(leaves_[i]->hash);

    free_all();
    for (const auto& h : hashes) append(h);
}

void MerkleMMR::take_snapshot() {
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
    free_all();
    for (const auto& h : s.leaf_hashes) append(h);
}

bool MerkleMMR::verify_proof(const std::string& leaf_hash, const Proof& proof, const std::string& expected_root) {
    // reconstruct intra-peak root
    std::string current = leaf_hash;
    for (const auto& step : proof.intra_proof) {
        const std::string& sibling = step.first;
        const std::string& dir = step.second;
        current = (dir == "R") ? combine(current, sibling) : combine(sibling, current);
    }

    // replace the peak hash at leaf_peak_idx with reconstructed intra-peak root
    std::vector<std::string> peaks = proof.peak_hashes;
    if (proof.leaf_peak_idx < 0 || proof.leaf_peak_idx >= static_cast<int>(peaks.size())) return false;
    peaks[proof.leaf_peak_idx] = current;

    // bag peaks into overall root: fold right-to-left
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

// Helper: build peak hashes from a vector of leaf hashes without mutating this MMR
static std::vector<std::string> build_peaks_from_leaves(const std::vector<std::string>& leaf_hashes) {
    struct Temp { std::string hash; int height; };
    std::vector<Temp> peaks;
    peaks.reserve(leaf_hashes.size());
    for (const auto &h : leaf_hashes) {
        peaks.push_back(Temp{h, 0});
        while (peaks.size() >= 2) {
            auto &a = peaks[peaks.size()-2];
            auto &b = peaks[peaks.size()-1];
            if (a.height != b.height) break;
            // merge
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
        // Delete current peaks and all nodes
        free_all();
        // Rebuild MMR from the previous interval's leaf hashes
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


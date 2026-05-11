#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <sstream>
#include "../header/merkle_tree.hpp"
#include "../header/voting_system.hpp"
#include "../header/merkle_mountain_range.hpp"

// Forward declaration for newly added test
void test_mmr_snapshot_and_rollback();

// Simple test framework macros
int tests_run = 0;
int tests_passed = 0;

#define RUN_TEST(test_func) \
    do { \
        std::cout << "[RUN] " << #test_func << "...\n"; \
        tests_run++; \
        try { \
            test_func(); \
            std::cout << "[OK]  " << #test_func << "\n"; \
            tests_passed++; \
        } catch (const std::exception& e) { \
            std::cerr << "[FAIL] " << #test_func << " threw exception: " << e.what() << "\n"; \
        } catch (...) { \
            std::cerr << "[FAIL] " << #test_func << " threw unknown exception\n"; \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            std::ostringstream oss; \
            oss << "Assertion failed: " << #a << " == " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n" \
                << "Expected: " << (b) << ", Got: " << (a); \
            throw std::runtime_error(oss.str()); \
        } \
    } while (0)

#define ASSERT_TRUE(a) \
    do { \
        if (!(a)) { \
            std::ostringstream oss; \
            oss << "Assertion failed: " << #a << " is true at " << __FILE__ << ":" << __LINE__; \
            throw std::runtime_error(oss.str()); \
        } \
    } while (0)

#define ASSERT_FALSE(a) \
    do { \
        if (a) { \
            std::ostringstream oss; \
            oss << "Assertion failed: " << #a << " is false at " << __FILE__ << ":" << __LINE__; \
            throw std::runtime_error(oss.str()); \
        } \
    } while (0)

// Helper to suppress stdout during VotingSystem operations if needed
class SuppressOutput {
    std::streambuf* old_buf;
    std::stringstream ss;
public:
    SuppressOutput() : old_buf(std::cout.rdbuf(ss.rdbuf())) {}
    ~SuppressOutput() { std::cout.rdbuf(old_buf); }
};

static std::string expected_merkle_root(const std::vector<std::string>& leaves) {
    if (leaves.empty()) return "";

    std::vector<std::string> level = leaves;
    while (level.size() > 1) {
        std::vector<std::string> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            const std::string& left = level[i];
            const std::string& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(sha256(left + right));
        }
        level = std::move(next);
    }
    return level[0];
}

static std::vector<std::string> make_test_leaves(int count) {
    std::vector<std::string> leaves;
    leaves.reserve(count);
    for (int i = 1; i <= count; ++i)
        leaves.push_back("H" + std::to_string(i));
    return leaves;
}

static std::string rebuild_root_from_voting_system(const VotingSystem& vs) {
    MerkleTree rebuilt;
    rebuilt.build(vs.current_ballot_hashes());
    return rebuilt.get_root();
}

static std::vector<std::string> seed_votes(
    VotingSystem& vs,
    int count,
    const std::vector<std::string>& candidates = {"A", "B", "A", "C", "B", "A", "C", "B"})
{
    std::vector<std::string> receipts;
    receipts.reserve(count);
    for (int i = 0; i < count; ++i) {
        const std::string voter = "V" + std::to_string(i + 1);
        vs.register_voter(voter);
        receipts.push_back(vs.cast_vote(voter, candidates[i % candidates.size()]));
    }
    return receipts;
}

// 1. Build: Root hash is correctly computed for both even and odd leaf counts
void test_build_even_and_odd() {
    MerkleTree tree_even;
    std::vector<std::string> leaves_even = {"A", "B", "C", "D"};
    tree_even.build(leaves_even);
    
    std::string ab = sha256("A" + std::string("B"));
    std::string cd = sha256("C" + std::string("D"));
    std::string expected_root_even = sha256(ab + cd);
    
    ASSERT_EQ(tree_even.get_root(), expected_root_even);
    ASSERT_EQ(tree_even.leaf_count(), 4);

    MerkleTree tree_odd;
    std::vector<std::string> leaves_odd = {"A", "B", "C"};
    tree_odd.build(leaves_odd);
    
    std::string cc = sha256("C" + std::string("C")); // C duplicated
    std::string expected_root_odd = sha256(ab + cc);
    
    ASSERT_EQ(tree_odd.get_root(), expected_root_odd);
    ASSERT_EQ(tree_odd.leaf_count(), 3);
}

void test_build_cases_zero_to_eight_leaves() {
    for (int count = 0; count <= 8; ++count) {
        MerkleTree tree;
        std::vector<std::string> leaves = make_test_leaves(count);
        tree.build(leaves);

        ASSERT_EQ(tree.get_root(), expected_merkle_root(leaves));
        ASSERT_EQ(tree.leaf_count(), count);

        if (count == 0) {
            ASSERT_FALSE(tree.is_built());
        } else {
            ASSERT_TRUE(tree.is_built());
        }
    }
}

void test_single_leaf_root_is_the_leaf_hash() {
    MerkleTree tree;
    tree.build({"OnlyLeafHash"});
    ASSERT_EQ(tree.get_root(), "OnlyLeafHash");
    ASSERT_EQ(tree.leaf_count(), 1);
}

void test_deterministic_roots_same_input_same_root() {
    const std::vector<std::string> leaves = make_test_leaves(7);
    MerkleTree a;
    MerkleTree b;
    a.build(leaves);
    b.build(leaves);
    ASSERT_EQ(a.get_root(), b.get_root());
}

void test_changing_one_leaf_changes_root() {
    std::vector<std::string> leaves = make_test_leaves(5);
    MerkleTree original;
    MerkleTree changed;
    original.build(leaves);
    leaves[2] = "H3_changed";
    changed.build(leaves);
    ASSERT_TRUE(original.get_root() != changed.get_root());
}

void test_incremental_insertions_match_clean_rebuilds_up_to_eight() {
    MerkleTree incremental;
    std::vector<std::string> leaves;

    for (int count = 1; count <= 8; ++count) {
        const std::string next_leaf = "H" + std::to_string(count);
        leaves.push_back(next_leaf);
        incremental.insert(next_leaf);

        MerkleTree rebuilt;
        rebuilt.build(leaves);

        ASSERT_EQ(incremental.get_root(), rebuilt.get_root());
        ASSERT_EQ(incremental.leaf_count(), count);
    }
}

// 2. Insert (O(log n)): Inserting a leaf into an odd-sized tree correctly computes the new root
void test_insert_odd_sized_tree() {
    MerkleTree tree;
    std::vector<std::string> leaves = {"A", "B", "C"};
    tree.build(leaves);
    
    tree.insert("D"); // Tree was odd (3), now even (4)
    
    MerkleTree tree_full;
    std::vector<std::string> expected_leaves = {"A", "B", "C", "D"};
    tree_full.build(expected_leaves);
    
    ASSERT_EQ(tree.get_root(), tree_full.get_root());
    ASSERT_EQ(tree.leaf_count(), 4);
}

// 3. Update (Tamper): Changing a leaf hash correctly propagates to the root
void test_update_tamper() {
    MerkleTree tree;
    std::vector<std::string> leaves = {"A", "B", "C", "D"};
    tree.build(leaves);
    
    // Tamper with index 2 ("C" -> "X")
    tree.update(2, "X");
    
    MerkleTree tree_full;
    std::vector<std::string> expected_leaves = {"A", "B", "X", "D"};
    tree_full.build(expected_leaves);
    
    ASSERT_EQ(tree.get_root(), tree_full.get_root());
}

// 4. Delete (Tombstone): Deleting a leaf correctly replaces it with the sentinel hash
void test_delete_tombstone() {
    MerkleTree tree;
    std::vector<std::string> leaves = {"A", "B", "C", "D"};
    tree.build(leaves);
    
    // Delete index 1 ("B")
    tree.delete_leaf(1);
    
    MerkleTree tree_full;
    std::vector<std::string> expected_leaves = {"A", MerkleTree::deleted_sentinel(), "C", "D"};
    tree_full.build(expected_leaves);
    
    ASSERT_EQ(tree.get_root(), tree_full.get_root());
    ASSERT_TRUE(tree.is_leaf_deleted(1));
    ASSERT_EQ(tree.get_leaf_hash(1), MerkleTree::deleted_sentinel());
}

// 5. Proof Generation & Verification: Proofs generated for valid leaves verify correctly
void test_proof_generation_and_verification() {
    MerkleTree tree;
    std::vector<std::string> leaves = {"A", "B", "C", "D", "E"};
    tree.build(leaves);
    
    std::string root = tree.get_root();
    
    for (int i = 0; i < 5; ++i) {
        auto proof = tree.generate_proof(i);
        bool is_valid = MerkleTree::verify_proof(leaves[i], proof, root);
        ASSERT_TRUE(is_valid);
    }
}

// 6. Proof Failure: Proofs generated for tampered or deleted leaves fail verification
void test_proof_failure_tampered_or_deleted() {
    MerkleTree tree;
    std::vector<std::string> leaves = {"A", "B", "C", "D", "E"};
    tree.build(leaves);
    
    std::string original_root = tree.get_root();
    
    // Tamper with index 2
    tree.update(2, "X");
    auto proof_tampered = tree.generate_proof(2);
    
    // The proof generated against the new tree should fail when checked against original root
    bool is_valid_tampered = MerkleTree::verify_proof("X", proof_tampered, original_root);
    ASSERT_FALSE(is_valid_tampered);

    // Delete index 4
    tree.delete_leaf(4);
    auto proof_deleted = tree.generate_proof(4);
    
    // Verifying the sentinel hash against the original root should fail
    bool is_valid_deleted = MerkleTree::verify_proof(MerkleTree::deleted_sentinel(), proof_deleted, original_root);
    ASSERT_FALSE(is_valid_deleted);
}

// Tamper must break proof vs published snapshot until a new build_tree().
void test_voting_tamper_proof_snapshot() {
    SuppressOutput so;
    VotingSystem vs;
    vs.register_voter("V1");
    std::string r = vs.cast_vote("V1", "Alice");
    vs.build_tree();
    ASSERT_TRUE(vs.proof_matches_published_snapshot(r));
    vs.tamper_vote(r, "Charlie");
    ASSERT_FALSE(vs.proof_matches_published_snapshot(r));
    vs.build_tree();
    ASSERT_TRUE(vs.proof_matches_published_snapshot(r));
}

void test_voting_tamper_marker_and_original_vote_tracking() {
    SuppressOutput so;
    VotingSystem vs;
    vs.register_voter("V1");
    std::string r = vs.cast_vote("V1", "Sam");
    vs.build_tree();

    vs.tamper_vote(r, "Ali");

    VotingSystem::ReceiptInfo info{};
    ASSERT_TRUE(vs.receipt_info_for(r, info));
    ASSERT_TRUE(info.tampered);
    ASSERT_TRUE(info.valid);
    ASSERT_EQ(info.pre_tamper_candidate, "Sam");
    ASSERT_EQ(info.candidate, "Ali");

    vs.tamper_vote(r, "Sarah");
    ASSERT_TRUE(vs.receipt_info_for(r, info));
    ASSERT_EQ(info.pre_tamper_candidate, "Sam");
    ASSERT_EQ(info.candidate, "Sarah");
}

void test_tamper_flags_clear_after_invalidate_and_delete() {
    SuppressOutput so;
    VotingSystem vs;
    vs.register_voter("V1");
    vs.register_voter("V2");
    std::string r1 = vs.cast_vote("V1", "Sam");
    std::string r2 = vs.cast_vote("V2", "Ali");
    vs.build_tree();

    vs.tamper_vote(r1, "Sarah");
    vs.tamper_vote(r2, "Sam");
    vs.invalidate_ballot(r1);
    vs.delete_ballot(r2);

    VotingSystem::ReceiptInfo info1{};
    VotingSystem::ReceiptInfo info2{};
    ASSERT_TRUE(vs.receipt_info_for(r1, info1));
    ASSERT_FALSE(vs.receipt_info_for(r2, info2));

    ASSERT_FALSE(info1.valid);
    ASSERT_FALSE(info1.tampered);
    ASSERT_EQ(info1.pre_tamper_candidate, "");
    ASSERT_EQ(vs.ballot_count(), 1);
}

void test_delete_empty_tree_is_noop() {
    SuppressOutput so;
    VotingSystem vs;
    vs.delete_ballot("missing");
    ASSERT_EQ(vs.ballot_count(), 0);
    ASSERT_EQ(vs.merkle_root(), "");
}

void test_delete_only_leaf_clears_tree() {
    SuppressOutput so;
    VotingSystem vs;
    auto receipts = seed_votes(vs, 1);
    vs.build_tree();

    vs.delete_ballot(receipts[0]);

    ASSERT_EQ(vs.ballot_count(), 0);
    ASSERT_FALSE(vs.is_tree_built());
    ASSERT_EQ(vs.merkle_root(), "");
    ASSERT_EQ(rebuild_root_from_voting_system(vs), "");
}

void test_delete_first_leaf_rebuilds_correctly() {
    SuppressOutput so;
    VotingSystem vs;
    auto receipts = seed_votes(vs, 4);
    vs.build_tree();

    vs.delete_ballot(receipts[0]);

    ASSERT_EQ(vs.ballot_count(), 3);
    ASSERT_EQ(vs.merkle_root(), rebuild_root_from_voting_system(vs));
    VotingSystem::ReceiptInfo info{};
    ASSERT_FALSE(vs.receipt_info_for(receipts[0], info));
}

void test_delete_middle_leaf_rebuilds_correctly() {
    SuppressOutput so;
    VotingSystem vs;
    auto receipts = seed_votes(vs, 4);
    vs.build_tree();

    vs.delete_ballot(receipts[1]);

    ASSERT_EQ(vs.ballot_count(), 3);
    ASSERT_EQ(vs.merkle_root(), rebuild_root_from_voting_system(vs));
}

void test_delete_last_leaf_removes_old_duplicate_path() {
    SuppressOutput so;
    VotingSystem vs;
    auto receipts = seed_votes(vs, 5);
    vs.build_tree();

    vs.delete_ballot(receipts[4]);

    ASSERT_EQ(vs.ballot_count(), 4);
    ASSERT_EQ(vs.merkle_root(), rebuild_root_from_voting_system(vs));
}

void test_delete_even_to_odd_rebuilds_correctly() {
    SuppressOutput so;
    VotingSystem vs;
    auto receipts = seed_votes(vs, 4);
    vs.build_tree();

    vs.delete_ballot(receipts[2]);

    ASSERT_EQ(vs.ballot_count(), 3);
    ASSERT_EQ(vs.merkle_root(), rebuild_root_from_voting_system(vs));
}

void test_delete_non_existing_receipt_does_not_corrupt_tree() {
    SuppressOutput so;
    VotingSystem vs;
    auto receipts = seed_votes(vs, 3);
    vs.build_tree();
    const std::string old_root = vs.merkle_root();

    vs.delete_ballot("RCP-does-not-exist");

    ASSERT_EQ(vs.ballot_count(), 3);
    ASSERT_EQ(vs.merkle_root(), old_root);
}

void test_delete_by_receipt_is_safe_for_duplicate_values() {
    SuppressOutput so;
    VotingSystem vs;
    vs.register_voter("V1");
    vs.register_voter("V2");
    vs.register_voter("V3");
    vs.register_voter("V4");
    std::string r1 = vs.cast_vote("V1", "A");
    std::string r2 = vs.cast_vote("V2", "B");
    std::string r3 = vs.cast_vote("V3", "A");
    std::string r4 = vs.cast_vote("V4", "C");
    vs.build_tree();

    vs.delete_ballot(r1);

    VotingSystem::ReceiptInfo info{};
    ASSERT_FALSE(vs.receipt_info_for(r1, info));
    ASSERT_TRUE(vs.receipt_info_for(r3, info));
    ASSERT_EQ(info.candidate, "A");
    ASSERT_EQ(vs.ballot_count(), 3);
    ASSERT_EQ(vs.merkle_root(), rebuild_root_from_voting_system(vs));
}

void test_repeated_deletions_until_empty_keep_roots_correct() {
    SuppressOutput so;
    VotingSystem vs;
    auto receipts = seed_votes(vs, 8);
    vs.build_tree();

    for (const auto& receipt : receipts) {
        vs.delete_ballot(receipt);
        ASSERT_EQ(vs.merkle_root(), rebuild_root_from_voting_system(vs));
    }

    ASSERT_EQ(vs.ballot_count(), 0);
    ASSERT_EQ(vs.merkle_root(), "");
    ASSERT_FALSE(vs.is_tree_built());
}

// Integration tests with VotingSystem
void test_voting_system_integration() {
    SuppressOutput so; // Suppress stdout to keep test output clean
    VotingSystem vs;
    
    vs.register_voter("V1");
    vs.register_voter("V2");
    vs.register_voter("V3");
    
    std::string r1 = vs.cast_vote("V1", "Alice");
    std::string r2 = vs.cast_vote("V2", "Bob");
    
    vs.build_tree();
    
    // 3rd vote after build triggers insert
    std::string r3 = vs.cast_vote("V3", "Alice");
    
    // The tree should now have 3 leaves.
    ASSERT_TRUE(vs.is_tree_built());
    ASSERT_EQ(vs.ballot_count(), 3);
    
    // Tamper vote
    vs.tamper_vote(r2, "Charlie");
    // We can't directly assert the root mismatch here easily without exposing internals, 
    // but we can ensure it doesn't crash.
    
    // Invalidate ballot
    vs.invalidate_ballot(r1);
    
    // Delete ballot
    vs.delete_ballot(r3);
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  Running Merkle Tree Test Suite\n";
    std::cout << "========================================\n\n";

    RUN_TEST(test_build_even_and_odd);
    RUN_TEST(test_build_cases_zero_to_eight_leaves);
    RUN_TEST(test_single_leaf_root_is_the_leaf_hash);
    RUN_TEST(test_deterministic_roots_same_input_same_root);
    RUN_TEST(test_changing_one_leaf_changes_root);
    RUN_TEST(test_incremental_insertions_match_clean_rebuilds_up_to_eight);
    RUN_TEST(test_insert_odd_sized_tree);
    RUN_TEST(test_update_tamper);
    RUN_TEST(test_delete_tombstone);
    RUN_TEST(test_proof_generation_and_verification);
    RUN_TEST(test_proof_failure_tampered_or_deleted);
    RUN_TEST(test_voting_tamper_proof_snapshot);
    RUN_TEST(test_voting_tamper_marker_and_original_vote_tracking);
    RUN_TEST(test_tamper_flags_clear_after_invalidate_and_delete);
    RUN_TEST(test_delete_empty_tree_is_noop);
    RUN_TEST(test_delete_only_leaf_clears_tree);
    RUN_TEST(test_delete_first_leaf_rebuilds_correctly);
    RUN_TEST(test_delete_middle_leaf_rebuilds_correctly);
    RUN_TEST(test_delete_last_leaf_removes_old_duplicate_path);
    RUN_TEST(test_delete_even_to_odd_rebuilds_correctly);
    RUN_TEST(test_delete_non_existing_receipt_does_not_corrupt_tree);
    RUN_TEST(test_delete_by_receipt_is_safe_for_duplicate_values);
    RUN_TEST(test_repeated_deletions_until_empty_keep_roots_correct);
    RUN_TEST(test_mmr_snapshot_and_rollback);
    RUN_TEST(test_voting_system_integration);

    std::cout << "\n========================================\n";
    std::cout << "  Tests Run:    " << tests_run << "\n";
    std::cout << "  Tests Passed: " << tests_passed << "\n";
    std::cout << "  Tests Failed: " << (tests_run - tests_passed) << "\n";
    std::cout << "========================================\n";

    return (tests_run == tests_passed) ? 0 : 1;
}
void test_mmr_snapshot_and_rollback() {
    MerkleMMR mmr;

    // append 6 leaves
    for (int i = 0; i < 6; ++i) mmr.append(std::to_string(i));
    ASSERT_EQ(mmr.leaf_count(), 6);

    // take snapshot
    mmr.take_snapshot();
    ASSERT_EQ(mmr.snapshot_count(), 1);
    std::string snap_root = mmr.get_root();
    size_t snap_count = mmr.leaf_count();

    // append two more leaves (simulate unexpected change)
    mmr.append("6");
    mmr.append("7");
    ASSERT_TRUE(mmr.leaf_count() > snap_count);

    // should be detected as tampered (count mismatch)
    ASSERT_TRUE(mmr.is_tampered_since_snapshot(0));

    // rollback to snapshot and verify
    mmr.rollback_to_snapshot(0);
    ASSERT_EQ(mmr.leaf_count(), snap_count);
    ASSERT_EQ(mmr.get_root(), snap_root);
}

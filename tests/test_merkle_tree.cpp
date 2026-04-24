#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <sstream>
#include "../merkle_tree.hpp"
#include "../voting_system.hpp"

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
    ASSERT_TRUE(vs.receipt_info_for(r2, info2));

    ASSERT_FALSE(info1.valid);
    ASSERT_FALSE(info1.tampered);
    ASSERT_EQ(info1.pre_tamper_candidate, "");

    ASSERT_FALSE(info2.valid);
    ASSERT_FALSE(info2.tampered);
    ASSERT_EQ(info2.pre_tamper_candidate, "");
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
    RUN_TEST(test_insert_odd_sized_tree);
    RUN_TEST(test_update_tamper);
    RUN_TEST(test_delete_tombstone);
    RUN_TEST(test_proof_generation_and_verification);
    RUN_TEST(test_proof_failure_tampered_or_deleted);
    RUN_TEST(test_voting_tamper_proof_snapshot);
    RUN_TEST(test_voting_tamper_marker_and_original_vote_tracking);
    RUN_TEST(test_tamper_flags_clear_after_invalidate_and_delete);
    RUN_TEST(test_voting_system_integration);

    std::cout << "\n========================================\n";
    std::cout << "  Tests Run:    " << tests_run << "\n";
    std::cout << "  Tests Passed: " << tests_passed << "\n";
    std::cout << "  Tests Failed: " << (tests_run - tests_passed) << "\n";
    std::cout << "========================================\n";

    return (tests_run == tests_passed) ? 0 : 1;
}

// =============================================================================
// demo.cpp  —  E-VoteVerify+ Scripted Presentation Demo
//
// This is a fully automated, hardcoded scenario designed for a live viva or
// presentation. It demonstrates the core DSII concepts (Hash Table lookups,
// Merkle Tree construction, O(log n) proofs, and tamper detection) without
// requiring any manual typing or menu navigation.
//
// Compile:
//   g++ -std=c++17 -O2 -o demo demo.cpp
//
// Run:
//   ./demo.exe
// =============================================================================
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include "voting_system.hpp"

// Helper to pause execution so the audience can read the output
void pause_for_effect(int milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

void print_section(const std::string& title) {
    std::cout << "\n";
    std::cout << "  =================================================================\n";
    std::cout << "  >> " << title << "\n";
    std::cout << "  =================================================================\n";
    pause_for_effect(1000);
}

int main() {
    std::cout << "\n";
    std::cout << "  +=============================================================+\n";
    std::cout << "  |           E-VoteVerify+   (DSII Final Project)              |\n";
    std::cout << "  |             AUTOMATED PRESENTATION DEMO                     |\n";
    std::cout << "  +=============================================================+\n\n";
    pause_for_effect(2000);

    VotingSystem vs;

    // -------------------------------------------------------------------------
    print_section("PHASE 1: Voter Registration (Hash Table: O(1) inserts)");
    // -------------------------------------------------------------------------
    vs.register_voter("ALICE-999");
    pause_for_effect(500);
    vs.register_voter("BOB-888");
    pause_for_effect(500);
    vs.register_voter("CHARLIE-777");
    pause_for_effect(500);
    
    // Demonstrate duplicate prevention (Hash Table O(1) lookup)
    std::cout << "\n  [*] Attempting to register ALICE-999 again...\n";
    vs.register_voter("ALICE-999");
    pause_for_effect(1500);

    // -------------------------------------------------------------------------
    print_section("PHASE 2: Casting Votes (SHA-256 Hashing)");
    // -------------------------------------------------------------------------
    std::string receipt_alice = vs.cast_vote("ALICE-999", "Candidate A");
    pause_for_effect(800);
    std::string receipt_bob   = vs.cast_vote("BOB-888", "Candidate B");
    pause_for_effect(800);
    std::string receipt_charlie = vs.cast_vote("CHARLIE-777", "Candidate A");
    pause_for_effect(1500);

    // -------------------------------------------------------------------------
    print_section("PHASE 3: Building the Global Merkle Tree (O(n) construction)");
    // -------------------------------------------------------------------------
    std::cout << "  [*] Building tree from the 3 ballot hashes...\n";
    vs.build_tree();
    pause_for_effect(1500);
    
    std::cout << "\n  [*] Visualizing the tree structure:\n";
    vs.print_tree();
    pause_for_effect(3000);

    // -------------------------------------------------------------------------
    print_section("PHASE 4: Merkle Proof Verification (O(log n) parent-pointer walk)");
    // -------------------------------------------------------------------------
    std::cout << "  [*] Alice wants to verify her vote was included in the final tally.\n";
    std::cout << "  [*] She provides her receipt ID: " << receipt_alice << "\n";
    pause_for_effect(1500);
    vs.verify_vote(receipt_alice);
    pause_for_effect(3000);

    // -------------------------------------------------------------------------
    print_section("PHASE 5: Tamper Detection (Integrity Check)");
    // -------------------------------------------------------------------------
    std::cout << "  [*] A malicious actor alters Alice's ballot in the database!\n";
    std::cout << "  [*] Changing vote from 'Candidate A' to 'Candidate B'...\n";
    pause_for_effect(2000);
    
    // Tamper with Alice's vote
    vs.tamper_vote(receipt_alice, "Candidate B");
    pause_for_effect(3000);

    // -------------------------------------------------------------------------
    print_section("PHASE 6: Verification Failure (Cryptographic Proof)");
    // -------------------------------------------------------------------------
    std::cout << "  [*] Alice checks her receipt again against the original public root.\n";
    pause_for_effect(1500);
    vs.verify_vote(receipt_alice);
    pause_for_effect(3000);

    // -------------------------------------------------------------------------
    print_section("PHASE 7: Ballot Deletion (Tombstone / Sentinel Hash)");
    // -------------------------------------------------------------------------
    std::cout << "  [*] The election authority detects the tamper and deletes the ballot.\n";
    std::cout << "  [*] This uses an O(log n) update to replace the leaf with a sentinel hash.\n";
    pause_for_effect(2000);
    
    vs.delete_ballot(receipt_alice);
    pause_for_effect(2000);

    std::cout << "\n  [*] Let's look at the tree now. Notice the [DELETED] tag.\n";
    vs.print_tree();
    pause_for_effect(3000);

    std::cout << "\n  +=============================================================+\n";
    std::cout << "  |                    DEMO COMPLETE                            |\n";
    std::cout << "  +=============================================================+\n\n";

    return 0;
}

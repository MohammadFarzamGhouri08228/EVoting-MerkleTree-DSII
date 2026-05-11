// Demo moved to src/ and updated includes
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include "header/voting_system.hpp"

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
    print_section("PHASE 1: Voter Registration (Hash Table: O(1) inserts)");
    vs.register_voter("ALICE-999"); pause_for_effect(500);
    vs.register_voter("BOB-888"); pause_for_effect(500);
    vs.register_voter("CHARLIE-777"); pause_for_effect(500);
    std::cout << "\n  [*] Attempting to register ALICE-999 again...\n";
    vs.register_voter("ALICE-999"); pause_for_effect(1500);

    print_section("PHASE 2: Casting Votes (SHA-256 Hashing)");
    vs.cast_vote("ALICE-999", "CAND-A"); pause_for_effect(300);
    vs.cast_vote("BOB-888", "CAND-B"); pause_for_effect(300);
    vs.cast_vote("CHARLIE-777", "CAND-A"); pause_for_effect(300);

    print_section("PHASE 3: Build Merkle Tree (O(n) construction)");
    vs.build_tree(); pause_for_effect(1000);

    print_section("PHASE 4: Tamper Demo (O(log n) update)");
    auto receipts = vs.all_receipts();
    if (!receipts.empty()) {
        std::string r = receipts.front();
        vs.tamper_vote(r, "CAND-C");
    }

    print_section("PHASE 5: Final Summary");
    vs.display_summary();

    return 0;
}

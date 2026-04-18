// =============================================================================
// main.cpp  —  E-VoteVerify+  CLI entry point
//
// Compile (Windows / Linux / macOS):
//   g++ -std=c++17 -O2 -o evoteverify main.cpp
//
// Run:
//   ./evoteverify        (Linux / macOS)
//   evoteverify.exe      (Windows)
// =============================================================================
#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include "voting_system.hpp"

// ---------------------------------------------------------------------------
// Banner & menu helpers
// ---------------------------------------------------------------------------

static void print_banner() {
    std::cout << "\n";
    std::cout << "  +=============================================================+\n";
    std::cout << "  |           E-VoteVerify+   (DSII Final Project)              |\n";
    std::cout << "  |     Merkle-Tree Based Tamper-Evident Voting System          |\n";
    std::cout << "  |                 Implemented in C++17                        |\n";
    std::cout << "  +=============================================================+\n\n";
}

static void print_menu() {
    std::cout << "  +-------- Menu -----------------------------------------------+\n";
    std::cout << "  |  1.  Register voter                                         |\n";
    std::cout << "  |  2.  Cast vote                                              |\n";
    std::cout << "  |  3.  Build Merkle Tree                                      |\n";
    std::cout << "  |  4.  Display Merkle Tree (visualise levels)                 |\n";
    std::cout << "  |  5.  Verify vote  (Merkle proof — parent-pointer walk)      |\n";
    std::cout << "  |  6.  Tamper with a ballot  (tamper-detection demo)          |\n";
    std::cout << "  |  7.  Invalidate a ballot   (delete_leaf demo)               |\n";
    std::cout << "  |  8.  Show election summary                                  |\n";
    std::cout << "  |  9.  Show all receipt IDs                                   |\n";
    std::cout << "  |  10. Show voter registry                                    |\n";
    // Option 11 is hidden from the menu but still accessible
    std::cout << "  |  0.  Exit                                                   |\n";
    std::cout << "  +------------------------------------------------------------+\n";
    std::cout << "  Choice: ";
}

// Read a non-empty line; re-prompt on blank input.
static std::string prompt(const std::string& label) {
    std::string s;
    while (true) {
        std::cout << "  " << label << ": ";
        std::getline(std::cin, s);
        // Trim leading/trailing whitespace
        size_t a = s.find_first_not_of(" \t\r\n");
        size_t b = s.find_last_not_of(" \t\r\n");
        if (a != std::string::npos) {
            s = s.substr(a, b - a + 1);
            return s;
        }
        std::cout << "  [!] Input cannot be empty.\n";
    }
}

// Helper to select a receipt from a numbered list (shows [INVALIDATED] tag).
static std::string prompt_receipt_selection(
    const std::vector<VotingSystem::ReceiptInfo>& receipts)
{
    if (receipts.empty()) return "";

    std::cout << "  Available receipts:\n";
    for (size_t i = 0; i < receipts.size(); ++i) {
        std::cout << "    " << (i + 1) << ") " << receipts[i].receipt_id;
        if (!receipts[i].valid) std::cout << "  [INVALIDATED]";
        std::cout << "\n";
    }
    std::cout << "\n";

    while (true) {
        std::string input = prompt("Select receipt number (1-" + std::to_string(receipts.size()) + ")");
        try {
            int choice = std::stoi(input);
            if (choice >= 1 && choice <= static_cast<int>(receipts.size()))
                return receipts[choice - 1].receipt_id;
        } catch (...) {}
        std::cout << "  [!] Invalid choice. Please enter a number between 1 and "
                  << receipts.size() << ".\n";
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    print_banner();

    VotingSystem vs;
    int choice = -1;

    while (true) {
        print_menu();

        // Read integer choice
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "  [!] Please enter a number.\n\n";
            continue;
        }
        // Consume the newline left by operator>>
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "\n";

        // ----------------------------------------------------------------
        if (choice == 0) {
            std::cout << "  Goodbye!\n\n";
            break;

        // ----------------------------------------------------------------
        } else if (choice == 1) {
            // Register voter
            std::string id = prompt("Voter ID");
            vs.register_voter(id);

        // ----------------------------------------------------------------
        } else if (choice == 2) {
            // Cast vote
            std::string voter_id  = prompt("Voter ID");
            std::string candidate = prompt("Candidate name");
            vs.cast_vote(voter_id, candidate);

        // ----------------------------------------------------------------
        } else if (choice == 3) {
            // Build Merkle Tree
            vs.build_tree();

        // ----------------------------------------------------------------
        } else if (choice == 4) {
            // Display tree
            vs.print_tree();

        // ----------------------------------------------------------------
        } else if (choice == 5) {
            // Verify vote — generate_proof() walks up via parent pointers
            if (!vs.is_tree_built()) {
                std::cout << "  [!] Build the tree first (option 3).\n";
            } else {
                auto receipts = vs.all_receipt_info();
                if (receipts.empty()) {
                    std::cout << "  [!] No ballots have been cast yet.\n";
                } else {
                    std::string receipt = prompt_receipt_selection(receipts);
                    if (!receipt.empty())
                        vs.verify_vote(receipt);
                }
            }

        // ----------------------------------------------------------------
        } else if (choice == 6) {
            // Tamper simulation — tree_.update() O(log n) parent-pointer walk
            if (vs.ballot_count() == 0) {
                std::cout << "  [!] No ballots have been cast yet.\n";
            } else {
                auto receipts = vs.all_receipt_info();
                std::string receipt = prompt_receipt_selection(receipts);
                if (!receipt.empty()) {
                    std::string new_cand = prompt("New (fake) candidate");
                    vs.tamper_vote(receipt, new_cand);
                }
            }

        // ----------------------------------------------------------------
        } else if (choice == 7) {
            // Invalidate ballot — tree_.delete_leaf() O(log n) parent-pointer walk
            if (!vs.is_tree_built()) {
                std::cout << "  [!] Build the tree first (option 3).\n";
            } else if (vs.ballot_count() == 0) {
                std::cout << "  [!] No ballots have been cast yet.\n";
            } else {
                auto receipts = vs.all_receipt_info();
                std::string receipt = prompt_receipt_selection(receipts);
                if (!receipt.empty())
                    vs.invalidate_ballot(receipt);
            }

        // ----------------------------------------------------------------
        } else if (choice == 8) {
            // Election summary
            vs.display_summary();

        // ----------------------------------------------------------------
        } else if (choice == 9) {
            // All receipts
            auto receipts = vs.all_receipt_info();
            if (receipts.empty()) {
                std::cout << "  No ballots cast yet.\n";
            } else {
                std::cout << "  All receipt IDs (" << receipts.size() << "):\n";
                for (const auto& r : receipts) {
                    std::cout << "    " << r.receipt_id;
                    if (!r.valid) std::cout << "  [INVALIDATED]";
                    std::cout << "\n";
                }
            }

        // ----------------------------------------------------------------
        } else if (choice == 10) {
            // Voter registry
            vs.print_registry();

        // ----------------------------------------------------------------
        } else if (choice == 11) {
            // Load dataset (hidden from menu)
            std::string filepath = prompt("Enter dataset filepath (e.g. dataset.csv)");
            vs.load_dataset(filepath);

        // ----------------------------------------------------------------
        } else {
            std::cout << "  [!] Invalid choice. Enter 0-10.\n";
        }

        std::cout << "\n";
    }

    return 0;
}

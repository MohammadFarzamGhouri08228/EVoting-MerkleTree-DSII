// =============================================================================
// main.cpp  —  E-VoteVerify+  CLI entry point
//
// Compile (Windows / Linux / macOS):
//   g++ -std=c++17 -O2 -o evoteverify main.cpp -lws2_32   (Windows / MinGW)
//   g++ -std=c++17 -O2 -o evoteverify main.cpp            (Linux / macOS)
//
// Run:
//   ./evoteverify        (Linux / macOS)
//   evoteverify.exe      (Windows)
// =============================================================================
#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <algorithm>
#include "header/voting_system.hpp"

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
    std::cout << "  |  4.  Display Merkle Tree (ASCII terminal view)              |\n";
    std::cout << "  |  5.  Open Live Interactive Web Visualization                |\n";
    std::cout << "  |  6.  Verify vote  (simple walkthrough)                      |\n";
    std::cout << "  |  7.  Tamper with a ballot  (tamper-detection demo)          |\n";
    std::cout << "  |  8.  Invalidate a ballot   (delete_leaf demo)               |\n";
    std::cout << "  |  9.  Delete a ballot       (allow voter to re-vote)         |\n";
    std::cout << "  |  10. Show election summary                                  |\n";
    std::cout << "  |  11. Show all receipt IDs                                   |\n";
    std::cout << "  |  12. Show voter registry                                    |\n";
    std::cout << "  |  13. Load sample dataset                                    |\n";
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

// Helper to select a receipt from a numbered list (shows status tags).
static std::string prompt_receipt_selection(
    const std::vector<VotingSystem::ReceiptInfo>& receipts)
{
    if (receipts.empty()) return "";

    std::cout << "  Available receipts:\n";
    for (size_t i = 0; i < receipts.size(); ++i) {
        const auto& r = receipts[i];
        std::cout << "    " << (i + 1) << ") "
                  << r.receipt_id
                  << "  |  voter: " << r.voter_id
                  << "  |  ";
        if (r.tampered && !r.pre_tamper_candidate.empty())
            std::cout << "vote: " << r.pre_tamper_candidate << " -> " << r.candidate;
        else
            std::cout << "voted: " << r.candidate;
        if (!r.valid)   std::cout << "  [DELETED / INVALIDATED]";
        if (r.tampered) std::cout << "  [*** TAMPERED ***]";
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
            std::cout << "  +-------- Register New Voter --------------------------------+\n";
            std::cout << "  |  Assigns a unique Voter ID to a citizen, making them      |\n";
            std::cout << "  |  eligible to cast exactly one vote in this election.       |\n";
            std::cout << "  |                                                            |\n";
            std::cout << "  |  ID rules:  at least 2 characters, no spaces or '|'       |\n";
            std::cout << "  +------------------------------------------------------------+\n\n";
            std::string id = prompt("Voter ID");
            vs.register_voter(id);

        // ----------------------------------------------------------------
        } else if (choice == 2) {
            // Cast vote
            std::string voter_id = prompt("Voter ID");

            // Candidate selection menu
            const std::vector<std::string> candidates = { "Sam", "Ali", "Sarah" };
            std::cout << "\n";
            std::cout << "  +-------- Candidates on the Ballot --------------------------+\n";
            for (size_t i = 0; i < candidates.size(); ++i)
                std::cout << "  |    " << (i + 1) << ".  " << candidates[i]
                          << std::string(53 - candidates[i].size(), ' ') << "|\n";
            std::cout << "  +------------------------------------------------------------+\n\n";

            std::string candidate;
            while (true) {
                std::string sel = prompt("Select candidate (1-" + std::to_string(candidates.size()) + ")");
                try {
                    int c = std::stoi(sel);
                    if (c >= 1 && c <= static_cast<int>(candidates.size())) {
                        candidate = candidates[c - 1];
                        break;
                    }
                } catch (...) {}
                std::cout << "  [!] Please enter a number between 1 and "
                          << candidates.size() << ".\n";
            }

            std::cout << "\n  Confirm vote:  " << voter_id << "  ->  " << candidate << "\n";
            std::string confirm = prompt("Type yes to confirm");
            std::transform(confirm.begin(), confirm.end(), confirm.begin(), ::tolower);
            if (confirm != "yes") {
                std::cout << "  [!] Vote cancelled.\n";
            } else {
                vs.cast_vote(voter_id, candidate);
            }

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
            // Launch live interactive visualization
            vs.export_web_visualization();

        // ----------------------------------------------------------------
        } else if (choice == 6) {
            // Verify vote — generate_proof() walks up via parent pointers
            if (!vs.is_tree_built()) {
                std::cout << "  [!] Build the tree first (option 3).\n";
            } else {
                auto receipts = vs.all_receipt_info();
                if (receipts.empty()) {
                    std::cout << "  [!] No ballots have been cast yet.\n";
                } else {
                    std::string receipt = prompt_receipt_selection(receipts);
                    if (!receipt.empty()) {
                        std::cout << "  We will rebuild the path from this ballot to the root\n";
                        std::cout << "  and compare the final hash with the published root.\n";
                        vs.verify_vote(receipt);
                    }
                }
            }

        // ----------------------------------------------------------------
        } else if (choice == 7) {
            // Tamper simulation — tree_.update() O(log n) parent-pointer walk
            if (!vs.is_tree_built()) {
                std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
                std::cout << "      The tree must exist so the tampered hash can propagate.\n";
            } else if (vs.ballot_count() == 0) {
                std::cout << "  [!] No ballots have been cast yet.\n";
            } else {
                auto receipts = vs.all_receipt_info();
                std::string receipt = prompt_receipt_selection(receipts);
                if (!receipt.empty()) {
                    // Offer the same candidate list so the attacker can redirect a vote
                    const std::vector<std::string> candidates = { "Sam", "Ali", "Sarah" };
                    std::cout << "\n  Choose the fake (replacement) candidate:\n";
                    for (size_t i = 0; i < candidates.size(); ++i)
                        std::cout << "    " << (i + 1) << ".  " << candidates[i] << "\n";
                    std::cout << "\n";
                    std::string fake_cand;
                    while (true) {
                        std::string sel = prompt("Select fake candidate (1-"
                                                 + std::to_string(candidates.size()) + ")");
                        try {
                            int c = std::stoi(sel);
                            if (c >= 1 && c <= (int)candidates.size()) {
                                fake_cand = candidates[c - 1];
                                break;
                            }
                        } catch (...) {}
                        std::cout << "  [!] Please enter a number between 1 and "
                                  << candidates.size() << ".\n";
                    }
                    vs.tamper_vote(receipt, fake_cand);
                }
            }

        // ----------------------------------------------------------------
        } else if (choice == 8) {
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
        } else if (choice == 9) {
            // Delete ballot — tree_.delete_leaf() and unmark_voted()
            if (!vs.is_tree_built()) {
                std::cout << "  [!] Build the tree first (option 3).\n";
            } else if (vs.ballot_count() == 0) {
                std::cout << "  [!] No ballots have been cast yet.\n";
            } else {
                auto receipts = vs.all_receipt_info();
                std::string receipt = prompt_receipt_selection(receipts);
                if (!receipt.empty())
                    vs.delete_ballot(receipt);
            }

        // ----------------------------------------------------------------
        } else if (choice == 10) {
            // Election summary
            vs.display_summary();

        // ----------------------------------------------------------------
        } else if (choice == 11) {
            // All receipts
            auto receipts = vs.all_receipt_info();
            if (receipts.empty()) {
                std::cout << "  No ballots cast yet.\n";
            } else {
                std::cout << "  All receipt IDs (" << receipts.size() << "):\n";
                std::cout << "  " << std::string(70, '-') << "\n";
                for (size_t i = 0; i < receipts.size(); ++i) {
                    const auto& r = receipts[i];
                    std::cout << "  " << (i + 1) << ") "
                              << r.receipt_id
                              << "  |  voter: " << r.voter_id
                              << "  |  ";
                    if (r.tampered && !r.pre_tamper_candidate.empty())
                        std::cout << "vote: " << r.pre_tamper_candidate << " -> " << r.candidate;
                    else
                        std::cout << "voted: " << r.candidate;
                    if (!r.valid)   std::cout << "  [DELETED / INVALIDATED]";
                    if (r.tampered) std::cout << "  [*** TAMPERED ***]";
                    std::cout << "\n";
                }
                std::cout << "  " << std::string(70, '-') << "\n";
            }

        // ----------------------------------------------------------------
        } else if (choice == 12) {
            // Voter registry
            vs.print_registry();

        // ----------------------------------------------------------------
        } else if (choice == 13) {
            // Load dataset
            std::cout << "  Available datasets:\n";
            std::cout << "    1) data/dataset.csv (50 voters)\n";
            std::cout << "    2) Enter custom filepath\n";
            std::string sub_choice = prompt("Select option (1 or 2)");
            
            std::string filepath;
            if (sub_choice == "1") {
                filepath = "data/dataset.csv";
            } else if (sub_choice == "2") {
                filepath = prompt("Enter dataset filepath");
            } else {
                std::cout << "  [!] Invalid option. Cancelled.\n";
                continue;
            }
            
            vs.load_dataset(filepath);

        // ----------------------------------------------------------------
        } else {
            std::cout << "  [!] Invalid choice. Enter 0-13.\n";
        }

        std::cout << "\n";
    }

    return 0;
}

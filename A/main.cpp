#include <iostream>
#include <string>
#include <limits>
#include "voter.h"

void printMenu() {
    std::cout << "\n╔══════════════════════════════════════╗\n";
    std::cout <<   "║       E-VoteVerify+  (C++ Edition)   ║\n";
    std::cout <<   "╠══════════════════════════════════════╣\n";
    std::cout <<   "║  1. Register voter                   ║\n";
    std::cout <<   "║  2. Cast vote                        ║\n";
    std::cout <<   "║  3. Verify vote (by receipt ID)      ║\n";
    std::cout <<   "║  4. Prove voter eligibility          ║\n";
    std::cout <<   "║  5. Prove voter non-eligibility      ║\n";
    std::cout <<   "║  6. View vote tally                  ║\n";
    std::cout <<   "║  7. Publish commitment roots         ║\n";
    std::cout <<   "║  8. Show MMR peaks                   ║\n";
    std::cout <<   "║  9. Exit                             ║\n";
    std::cout <<   "╚══════════════════════════════════════╝\n";
    std::cout << "Select: ";
}

int main() {
    VotingSystem vs;

    // Add default candidates
    vs.addCandidate("Candidate A");
    vs.addCandidate("Candidate B");
    vs.addCandidate("Candidate C");

    std::cout << "Welcome to E-VoteVerify+ (C++ Edition)\n";
    std::cout << "Candidates: Candidate A, Candidate B, Candidate C\n";

    int choice = 0;
    while (true) {
        printMenu();
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == 1) {
            // Register
            std::cout << "Enter your unique ID: ";
            std::string uid;
            std::getline(std::cin, uid);
            auto r = vs.registerVoter(uid);
            std::cout << r.message << "\n";

        } else if (choice == 2) {
            // Cast vote
            std::cout << "Enter your voter token: ";
            std::string token;
            std::getline(std::cin, token);

            std::cout << "Candidates:\n";
            for (const auto& c : vs.getCandidates())
                std::cout << "  - " << c << "\n";
            std::cout << "Enter candidate name: ";
            std::string candidate;
            std::getline(std::cin, candidate);

            auto r = vs.castVote(token, candidate);
            std::cout << r.message << "\n";
            if (r.success) {
                std::cout << "Ballot Hash : " << r.ballotHash << "\n";
                std::cout << "MMR Leaf Idx: " << r.leafIndex  << "\n";
                vs.publishRoots();
            } else if (r.nonInclusionProof.valid) {
                std::cout << "[Audit] Non-inclusion proof generated for rejected token.\n";
                std::cout << "SMT Root: " << r.nonInclusionProof.root << "\n";
            }

        } else if (choice == 3) {
            // Verify vote
            std::cout << "Enter receipt ID: ";
            std::string receipt;
            std::getline(std::cin, receipt);
            auto r = vs.proveVoteInclusion(receipt);
            vs.printVoteProofResult(r);

        } else if (choice == 4) {
            // Voter inclusion
            std::cout << "Enter voter token: ";
            std::string token;
            std::getline(std::cin, token);
            auto r = vs.proveVoterInclusion(token);
            vs.printVoterProofResult(r);

        } else if (choice == 5) {
            // Voter non-inclusion
            std::cout << "Enter voter token to prove absence: ";
            std::string token;
            std::getline(std::cin, token);
            auto r = vs.proveVoterNonInclusion(token);
            vs.printVoterProofResult(r);

        } else if (choice == 6) {
            // Vote tally
            std::cout << "\n── Vote Tally ──────────────────────────────────────\n";
            auto counts = vs.getVoteCounts();
            for (const auto& [c, n] : counts)
                std::cout << "  " << c << " : " << n << " vote(s)\n";
            std::cout << "────────────────────────────────────────────────────\n";

        } else if (choice == 7) {
            vs.publishRoots();

        } else if (choice == 8) {
            // MMR peaks
            std::cout << "\n── MMR Peaks ───────────────────────────────────────\n";
            auto peaks = vs.getMMRPeaks();
            if (peaks.empty()) {
                std::cout << "  (no votes cast yet)\n";
            } else {
                for (size_t i = 0; i < peaks.size(); i++)
                    std::cout << "  Peak[" << i << "]: " << peaks[i] << "\n";
            }
            std::cout << "────────────────────────────────────────────────────\n";

        } else if (choice == 9) {
            std::cout << "Goodbye.\n";
            break;
        } else {
            std::cout << "Invalid option.\n";
        }
    }

    return 0;
}

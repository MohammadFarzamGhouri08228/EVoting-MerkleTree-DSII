// =============================================================================
// main_sim.cpp  —  Driver for the MMR Live Simulation server
//
// Compile (Windows / MinGW):
//   g++ -std=c++17 -O2 -I. -Isim -o mmr_sim.exe src/main_sim.cpp src/mmr_simulation.cpp src/merkle_mountain_range.cpp src/sparse_merkle_tree.cpp src/sha256.cpp -lws2_32
//
// Compile (Linux / macOS):
//   g++ -std=c++17 -O2 -I. -Isim -o mmr_sim src/main_sim.cpp src/mmr_simulation.cpp src/merkle_mountain_range.cpp src/sparse_merkle_tree.cpp src/sha256.cpp -pthread
//
// Run:
//   mmr_sim.exe          (Windows)
//   ./mmr_sim            (Linux / macOS)
//
// Then open http://127.0.0.1:9090/ in your browser.
// =============================================================================
#include "header/mmr_simulation.hpp"
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main() {
    std::cout << "\n";
    std::cout << "  +=============================================================+\n";
    std::cout << "  |        Merkle Mountain Range  —  Live Simulation            |\n";
    std::cout << "  |                  (DSII Final Project)                       |\n";
    std::cout << "  +=============================================================+\n\n";

    int port = 9090;
    MMRSimulation sim;

    if (!sim.start(port)) {
        std::cerr << "  [ERROR] Failed to start the simulation server.\n";
        return 1;
    }

    std::cout << "  [*] Simulation server is running.\n";
    std::cout << "  [*] Open your browser at:  http://127.0.0.1:" << port << "/\n";
    std::cout << "  [*] Keep this process running while using the browser page.\n\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::hours(24));
    }

    sim.stop();
    std::cout << "  [*] Server stopped. Goodbye!\n";
    return 0;
}

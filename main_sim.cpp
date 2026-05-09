// =============================================================================
// main_sim.cpp  —  Driver for the MMR Live Simulation server
//
// Compile (Windows / MinGW):
//   g++ -std=c++17 -O2 -I. -Isim -o mmr_sim.exe main_sim.cpp src/mmr_simulation.cpp src/merkle_mountain_range.cpp -lws2_32
//
// Compile (Linux / macOS):
//   g++ -std=c++17 -O2 -I. -Isim -o mmr_sim main_sim.cpp src/mmr_simulation.cpp src/merkle_mountain_range.cpp -pthread
//
// Run:
//   mmr_sim.exe          (Windows)
//   ./mmr_sim            (Linux / macOS)
//
// Then open http://127.0.0.1:9090/ in your browser.
// =============================================================================
#include "sim/mmr_simulation.hpp"
#include <iostream>
#include <string>

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
    std::cout << "  [*] Press Enter to stop the server...\n\n";

    std::cin.get();   // block until the user presses Enter

    sim.stop();
    std::cout << "  [*] Server stopped. Goodbye!\n";
    return 0;
}

#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include <mutex>
#include "header/merkle_mountain_range.hpp"

// Record kept for each interval audit
struct AuditRecord {
    int    interval_number = 0;
    size_t leaf_count      = 0;
    std::string root_hash;
    bool   tamper_detected = false;
    size_t invalidated_from = 0;  // 0 = no rollback
};

class MMRSimulation {
public:
    MMRSimulation();
    ~MMRSimulation();

    // Start / stop the HTTP simulation server
    bool start(int preferred_port = 9090);
    void stop();

    // --- Actions (called via HTTP API) ---
    bool step_one();
    bool run_auto(int rate_ms);
    void stop_auto();
    bool configure(int max_votes, int interval);
    bool vote_manual(const std::string& voter, const std::string& candidate);
    bool tamper_leaf(size_t index, const std::string& new_candidate);

    // --- JSON producers (called via HTTP API) ---
    std::string state_json()     const;
    std::string tree_json()      const;
    std::string votes_json()     const;
    std::string snapshots_json() const;
    std::string auditlog_json()  const;
    std::string candidates_json() const;
    std::string verify_json(int leaf_index) const;

private:
    bool load_dataset(const std::string& path, int max_rows = -1);
    void do_interval_audit();                        // run the rollback check
    std::string serialize_node(MMRNode* node) const; // recursive tree serialization

    // --- Server ---
    std::thread server_thread_;
    std::atomic<bool> running_ = false;

    // --- Simulation state ---
    MerkleMMR mmr_;
    std::vector<std::pair<std::string,std::string>> dataset_;   // (voter, candidate)
    std::vector<std::pair<std::string,std::string>> cast_votes_; // votes actually cast
    size_t next_index_ = 0;

    // --- Configuration ---
    int max_votes_ = -1;   // -1 = use all dataset rows
    int interval_  = 10;

    // --- Tally ---
    std::vector<std::pair<std::string,int>> candidates_tally_;
    std::vector<std::string> candidate_list_; // unique candidates from dataset

    // --- Audit history ---
    std::vector<AuditRecord> audit_log_;
    int  audit_number_   = 0;
    int  verified_count_ = 0;
    bool tampered_flag_  = false;    // true after leaf-only tamper, until next audit

    // --- Auto-run ---
    std::thread runner_thread_;
    std::atomic<bool> runner_active_ = false;
    int run_rate_ms_ = 200;

    // --- Manual vote counter ---
    int manual_vote_counter_ = 0;

    mutable std::mutex state_mutex_;
};

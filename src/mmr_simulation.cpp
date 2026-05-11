#include "header/mmr_simulation.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <set>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using Socket = int;
static const Socket invalid_socket = -1;
static void close_socket(Socket s) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}
static bool init_sockets() {
#ifdef _WIN32
    static bool initialized = false;
    static WSADATA data;
    if (!initialized) { if (WSAStartup(MAKEWORD(2,2), &data) != 0) return false; initialized = true; }
#endif
    return true;
}

// ---- URL-decode helper ----
static std::string url_decode(const std::string& s) {
    std::string out; out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i+2 < s.size()) {
            int v = 0;
            std::istringstream iss(s.substr(i+1, 2));
            if (iss >> std::hex >> v) { out += static_cast<char>(v); i += 2; continue; }
        }
        if (s[i] == '+') { out += ' '; continue; }
        out += s[i];
    }
    return out;
}

// ---- Query-string parser ----
static std::string query_param(const std::string& path, const std::string& key) {
    std::string needle = key + "=";
    size_t pos = path.find(needle);
    if (pos == std::string::npos) return "";
    size_t start = pos + needle.size();
    size_t end = path.find('&', start);
    std::string val = (end == std::string::npos) ? path.substr(start) : path.substr(start, end - start);
    return url_decode(val);
}

// ---- JSON escaping ----
static std::string json_escape(const std::string& s) {
    std::string out; out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

// ==========================================================================
// Constructor / Destructor
// ==========================================================================
MMRSimulation::MMRSimulation() : smt_(new SparseMerkleTree(16)) {}
MMRSimulation::~MMRSimulation() { stop(); delete smt_; smt_ = nullptr; }

std::string MMRSimulation::smt_value_hash(const std::string& voter_id, bool has_voted) {
    return sha256(voter_id + "|" + (has_voted ? "VOTED" : "REGISTERED"));
}

void MMRSimulation::rebuild_smt_from_registry() {
    delete smt_;
    smt_ = new SparseMerkleTree(16);
    for (const auto& entry : voter_registry_) {
        smt_->insert(smt_key_for(entry.first), smt_value_hash(entry.first, entry.second));
    }
}

bool MMRSimulation::append_vote_unlocked(const std::string& voter, const std::string& candidate) {
    if (voter.empty() || candidate.empty()) return false;
    if (max_votes_ > 0 && static_cast<int>(cast_votes_.size()) >= max_votes_) return false;

    std::string leaf = sha256(voter + "|" + candidate);
    mmr_.append(leaf);
    cast_votes_.push_back({voter, candidate});

    auto it = std::find_if(candidates_tally_.begin(), candidates_tally_.end(),
                           [&](auto& p){ return p.first == candidate; });
    if (it == candidates_tally_.end()) candidates_tally_.push_back({candidate, 1});
    else it->second++;

    if (std::find(candidate_list_.begin(), candidate_list_.end(), candidate) == candidate_list_.end())
        candidate_list_.push_back(candidate);

    return true;
}

// ==========================================================================
// Dataset loading — also extracts unique candidate list
// ==========================================================================
bool MMRSimulation::load_dataset(const std::string& path, int max_rows) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string line;
    std::getline(f, line); // header
    dataset_.clear();
    std::set<std::string> cands;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string voter, cand;
        if (std::getline(ss, voter, ',') && std::getline(ss, cand)) {
            if (!cand.empty() && cand.back()=='\r') cand.pop_back();
            dataset_.push_back({voter, cand});
            cands.insert(cand);
            if (max_rows > 0 && static_cast<int>(dataset_.size()) >= max_rows) break;
        }
    }
    candidate_list_.assign(cands.begin(), cands.end());
    next_index_ = 0;
    candidates_tally_.clear();
    cast_votes_.clear();
    audit_log_.clear();
    audit_number_ = 0;
    verified_count_ = 0;
    tampered_flag_ = false;
    manual_vote_counter_ = 0;
    voter_registry_.clear();
    smt_interval_snapshot_.clear();
    delete smt_; smt_ = new SparseMerkleTree(16);
    mmr_ = MerkleMMR();
    return true;
}

// ==========================================================================
// Configure
// ==========================================================================
bool MMRSimulation::configure(int max_votes, int interval) {
    std::lock_guard<std::mutex> g(state_mutex_);
    max_votes_ = max_votes;
    interval_  = interval > 0 ? interval : 10;
    // Reset simulation state
    next_index_ = 0;
    candidates_tally_.clear();
    cast_votes_.clear();
    audit_log_.clear();
    audit_number_ = 0;
    verified_count_ = 0;
    tampered_flag_ = false;
    manual_vote_counter_ = 0;
    voter_registry_.clear();
    smt_interval_snapshot_.clear();
    delete smt_; smt_ = new SparseMerkleTree(16);
    mmr_ = MerkleMMR();
    return true;
}

// ==========================================================================
// Interval audit — invoked every `interval_` votes
// ==========================================================================
void MMRSimulation::do_interval_audit() {
    audit_number_++;
    size_t invalid_from = 0;
    bool tamper = mmr_.check_and_rotate_interval(invalid_from);

    AuditRecord rec;
    rec.interval_number = audit_number_;
    rec.leaf_count = mmr_.leaf_count();
    rec.root_hash  = mmr_.is_empty() ? "" : mmr_.get_root();
    rec.tamper_detected = tamper;
    rec.invalidated_from = invalid_from;
    audit_log_.push_back(rec);

    if (tamper) {
        voter_registry_ = smt_interval_snapshot_;
        rebuild_smt_from_registry();
        // Rollback cast_votes_ and tally to match restored leaf count
        size_t restored = invalid_from;
        if (restored < cast_votes_.size()) {
            // Remove invalidated votes from tally
            for (size_t i = restored; i < cast_votes_.size(); ++i) {
                auto& cand = cast_votes_[i].second;
                for (auto& t : candidates_tally_) {
                    if (t.first == cand && t.second > 0) { t.second--; break; }
                }
            }
            cast_votes_.resize(restored);
            next_index_ = restored;
        }
        tampered_flag_ = false; // cleared after rollback
        verified_count_ = static_cast<int>(restored);
    } else {
        smt_interval_snapshot_ = voter_registry_;
        verified_count_ = static_cast<int>(mmr_.leaf_count());
        tampered_flag_ = false;
    }
}

// ==========================================================================
// step_one — process one vote from the dataset
// ==========================================================================
bool MMRSimulation::step_one() {
    std::lock_guard<std::mutex> g(state_mutex_);
    if (next_index_ >= dataset_.size()) return false;
    if (max_votes_ > 0 && static_cast<int>(cast_votes_.size()) >= max_votes_) return false;

    while (next_index_ < dataset_.size()) {
        auto it = voter_registry_.find(dataset_[next_index_].first);
        if (it != voter_registry_.end() && !it->second) break;
        next_index_++;
    }
    if (next_index_ >= dataset_.size()) return false;

    auto v = dataset_[next_index_++];
    if (!SparseMerkleTree::verify_proof(smt_value_hash(v.first, false), smt_->generate_proof(smt_key_for(v.first)), smt_->get_root()))
        return false;
    if (!append_vote_unlocked(v.first, v.second)) return false;
    voter_registry_[v.first] = true;
    smt_->insert(smt_key_for(v.first), smt_value_hash(v.first, true));

    // Interval audit check
    if (interval_ > 0 && (cast_votes_.size() % interval_) == 0) {
        do_interval_audit();
    }
    return true;
}

// ==========================================================================
// vote_manual — insert a manual vote
// ==========================================================================
bool MMRSimulation::vote_manual(const std::string& voter, const std::string& candidate) {
    std::lock_guard<std::mutex> g(state_mutex_);
    auto reg = voter_registry_.find(voter);
    if (reg == voter_registry_.end() || reg->second) return false;
    if (!SparseMerkleTree::verify_proof(smt_value_hash(voter, false), smt_->generate_proof(smt_key_for(voter)), smt_->get_root()))
        return false;
    if (!append_vote_unlocked(voter, candidate)) return false;
    reg->second = true;
    smt_->insert(smt_key_for(voter), smt_value_hash(voter, true));

    if (interval_ > 0 && (cast_votes_.size() % interval_) == 0)
        do_interval_audit();

    return true;
}

// ==========================================================================
// tamper_leaf — leaf-only tamper (NO propagation)
// ==========================================================================
bool MMRSimulation::tamper_leaf(size_t index, const std::string& new_candidate) {
    std::lock_guard<std::mutex> g(state_mutex_);
    if (index >= cast_votes_.size()) return false;
    std::string new_hash = sha256(cast_votes_[index].first + "|" + new_candidate);
    mmr_.tamper_leaf_only(index, new_hash);
    tampered_flag_ = true;
    return true;
}

// ==========================================================================
// run_auto / stop_auto
// ==========================================================================
bool MMRSimulation::run_auto(int rate_ms) {
    if (runner_active_) return false;
    if (runner_thread_.joinable()) runner_thread_.join(); // Safely join completed thread
    run_rate_ms_ = rate_ms > 0 ? rate_ms : 200;
    runner_active_ = true;
    runner_thread_ = std::thread([this]() {
        while (runner_active_) {
            bool ok = step_one();
            if (!ok) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(run_rate_ms_));
        }
        runner_active_ = false;
    });
    return true;
}
void MMRSimulation::stop_auto() {
    runner_active_ = false;
    if (runner_thread_.joinable()) runner_thread_.join();
}

// ==========================================================================
// Voter Registry Methods (with SparseMerkleTree integration)
// ==========================================================================

// Derive a uint64 key from voter ID for SMT addressing
uint64_t MMRSimulation::smt_key_for(const std::string& voter_id) {
    std::string h = sha256(voter_id);
    // Take first 8 hex chars => 32 bits (enough for depth-16 SMT)
    uint64_t key = 0;
    for (int i = 0; i < 8 && i < (int)h.size(); ++i) {
        char c = h[i];
        uint64_t nibble = (c >= '0' && c <= '9') ? (c - '0') :
                          (c >= 'a' && c <= 'f') ? (c - 'a' + 10) :
                          (c >= 'A' && c <= 'F') ? (c - 'A' + 10) : 0;
        key = (key << 4) | nibble;
    }
    return key;
}

bool MMRSimulation::register_voter(const std::string& voter_id) {
    if (voter_id.empty()) return false;
    std::lock_guard<std::mutex> g(state_mutex_);
    // Enforce max_votes_ as the registration cap
    if (max_votes_ > 0 && static_cast<int>(voter_registry_.size()) >= max_votes_) return false;
    if (voter_registry_.emplace(voter_id, false).second) {
        // Insert into Sparse Merkle Tree
        uint64_t key = smt_key_for(voter_id);
        std::string value_hash = smt_value_hash(voter_id, false);
        smt_->insert(key, value_hash);
        return true;
    }
    return false;
}

bool MMRSimulation::is_registered(const std::string& voter_id) const {
    std::lock_guard<std::mutex> g(state_mutex_);
    return voter_registry_.count(voter_id) > 0;
}

int MMRSimulation::auto_register(int count) {
    std::lock_guard<std::mutex> g(state_mutex_);
    int added = 0;
    for (size_t i = 0; i < dataset_.size(); ++i) {
        if (count > 0 && added >= count) break;
        if (max_votes_ > 0 && static_cast<int>(voter_registry_.size()) >= max_votes_) break;
        if (voter_registry_.emplace(dataset_[i].first, false).second) {
            uint64_t key = smt_key_for(dataset_[i].first);
            std::string value_hash = smt_value_hash(dataset_[i].first, false);
            smt_->insert(key, value_hash);
            added++;
        }
    }
    return added;
}

std::string MMRSimulation::registry_json() const {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    o << "{\"count\":" << voter_registry_.size()
      << ",\"smtRoot\":\"" << json_escape(smt_->get_root()) << "\""
      << ",\"smtNodes\":" << smt_->node_count()
      << ",\"voters\":[";
    bool first = true;
    for (auto& entry : voter_registry_) {
        if (!first) o << ",";
        o << "{\"voter\":\"" << json_escape(entry.first) << "\",\"hasVoted\":"
          << (entry.second ? "true" : "false") << "}";
        first = false;
    }
    o << "]}";
    return o.str();
}

// ==========================================================================
// SMT JSON serialization (for D3 visualization of the sparse tree)
// ==========================================================================
std::string MMRSimulation::serialize_smt_node(const SMTNode* node, const std::string& path, int max_depth) const {
    if (!node) return "null";
    std::ostringstream o;
    o << "{\"h\":\"" << node->hash
      << "\",\"short\":\"" << (node->hash.size() > 12 ? node->hash.substr(0, 12) : node->hash)
      << "\",\"id\":\"" << (path.empty() ? "root" : path)
      << "\",\"d\":" << node->depth
      << ",\"del\":" << (node->is_deleted ? "true" : "false");
    if (max_depth > 0 && (node->left || node->right)) {
        std::string left_path = path + "0";
        std::string right_path = path + "1";
        o << ",\"l\":" << (node->left ? serialize_smt_node(node->left, left_path, max_depth - 1) : "null");
        o << ",\"r\":" << (node->right ? serialize_smt_node(node->right, right_path, max_depth - 1) : "null");
    }
    o << "}";
    return o.str();
}

std::string MMRSimulation::smt_json() const {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    o << "{\"root\":\"" << json_escape(smt_->get_root()) << "\""
      << ",\"depth\":" << smt_->depth()
      << ",\"nodeCount\":" << smt_->node_count()
      << ",\"voterCount\":" << voter_registry_.size();
    o << ",\"tree\":";
    o << (smt_->is_built() ? serialize_smt_node(smt_->root(), "", smt_->depth()) : "null");
    // Per-voter SMT data (key, hash, inclusion proof length)
    o << ",\"entries\":[";
    bool first = true;
    for (auto& entry : voter_registry_) {
        if (!first) o << ",";
        uint64_t key = smt_key_for(entry.first);
        std::string vh = smt_value_hash(entry.first, entry.second);
        std::string stored = smt_->get(key);
        bool verified = (stored == vh);
        o << "{\"voter\":\"" << json_escape(entry.first) << "\""
          << ",\"key\":" << key
          << ",\"hash\":\"" << vh << "\""
          << ",\"hasVoted\":" << (entry.second ? "true" : "false")
          << ",\"verified\":" << (verified ? "true" : "false")
          << "}";
        first = false;
    }
    o << "]}";
    return o.str();
}

std::string MMRSimulation::smt_verify_json_unlocked(const std::string& voter_id) const {
    std::ostringstream o;
    if (voter_id.empty()) {
        o << "{\"ok\":false,\"error\":\"missing voter id\"}";
        return o.str();
    }

    auto reg = voter_registry_.find(voter_id);
    bool registered = reg != voter_registry_.end();
    bool has_voted = registered ? reg->second : false;
    uint64_t key = smt_key_for(voter_id);
    std::string key_bits;
    for (int level = 0; level < smt_->depth(); ++level)
        key_bits += ((key >> (smt_->depth() - 1 - level)) & 1ULL) ? '1' : '0';

    std::string expected_leaf = registered ? smt_value_hash(voter_id, has_voted) : smt_->empty_hash_at(smt_->depth());
    std::string required_unvoted_leaf = smt_value_hash(voter_id, false);
    std::string stored = smt_->get(key);
    auto proof = smt_->generate_proof(key);

    std::string current = expected_leaf;
    std::vector<std::string> before;
    std::vector<std::string> after;
    before.reserve(proof.size());
    after.reserve(proof.size());
    for (const auto& step : proof) {
        before.push_back(current);
        current = (step.second == "R") ? sha256(current + step.first) : sha256(step.first + current);
        after.push_back(current);
    }

    bool proof_ok = current == smt_->get_root() && stored == expected_leaf;
    bool eligible = proof_ok && registered && !has_voted && stored == required_unvoted_leaf;

    o << "{\"ok\":true"
      << ",\"voter\":\"" << json_escape(voter_id) << "\""
      << ",\"registered\":" << (registered ? "true" : "false")
      << ",\"hasVoted\":" << (has_voted ? "true" : "false")
      << ",\"eligible\":" << (eligible ? "true" : "false")
      << ",\"proofOk\":" << (proof_ok ? "true" : "false")
      << ",\"proofType\":\"" << (registered ? "membership" : "non-membership") << "\""
      << ",\"error\":\"" << (registered ? (has_voted ? "voter already voted" : "") : "voter not registered") << "\""
      << ",\"key\":" << key
      << ",\"keyBits\":\"" << key_bits << "\""
      << ",\"root\":\"" << smt_->get_root() << "\""
      << ",\"leafHash\":\"" << expected_leaf << "\""
      << ",\"storedHash\":\"" << stored << "\"";

    o << ",\"path\":[\"root\"";
    std::string prefix;
    for (char bit : key_bits) {
        prefix += bit;
        o << ",\"" << prefix << "\"";
    }
    o << "]";

    o << ",\"steps\":[";
    for (size_t i = 0; i < proof.size(); ++i) {
        if (i) o << ",";
        o << "{\"level\":" << i
          << ",\"dir\":\"" << proof[i].second << "\""
          << ",\"current\":\"" << before[i] << "\""
          << ",\"sibling\":\"" << proof[i].first << "\""
          << ",\"result\":\"" << after[i] << "\"}";
    }
    o << "]}";
    return o.str();
}

std::string MMRSimulation::smt_verify_json(const std::string& voter_id) const {
    std::lock_guard<std::mutex> g(state_mutex_);
    return smt_verify_json_unlocked(voter_id);
}

std::string MMRSimulation::vote_attempt_json(const std::string& voter, const std::string& candidate) {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    std::string verification = smt_verify_json_unlocked(voter);
    auto reg = voter_registry_.find(voter);
    bool eligible = reg != voter_registry_.end() && !reg->second;
    bool cast = false;
    std::string error;

    if (voter.empty() || candidate.empty()) {
        error = "missing voter or candidate";
    } else if (reg == voter_registry_.end()) {
        error = "voter not registered";
    } else if (reg->second) {
        error = "voter already voted";
    } else if (!SparseMerkleTree::verify_proof(smt_value_hash(voter, false), smt_->generate_proof(smt_key_for(voter)), smt_->get_root())) {
        error = "sparse merkle verification failed";
    } else if (!append_vote_unlocked(voter, candidate)) {
        error = "vote could not be cast";
    } else {
        reg->second = true;
        smt_->insert(smt_key_for(voter), smt_value_hash(voter, true));
        cast = true;
        if (interval_ > 0 && (cast_votes_.size() % interval_) == 0)
            do_interval_audit();
    }

    o << "{\"ok\":" << (cast ? "true" : "false")
      << ",\"cast\":" << (cast ? "true" : "false")
      << ",\"eligible\":" << (eligible ? "true" : "false")
      << ",\"error\":\"" << json_escape(error) << "\""
      << ",\"verification\":" << verification << "}";
    return o.str();
}

std::string MMRSimulation::step_attempt_json() {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    std::string error;
    std::string voter;
    std::string candidate;
    std::string verification = "{\"ok\":false,\"error\":\"no voter selected\"}";
    bool cast = false;

    if (next_index_ >= dataset_.size()) {
        error = "dataset is finished";
    } else if (max_votes_ > 0 && static_cast<int>(cast_votes_.size()) >= max_votes_) {
        error = "maximum vote limit reached";
    } else {
        while (next_index_ < dataset_.size()) {
            auto it = voter_registry_.find(dataset_[next_index_].first);
            if (it != voter_registry_.end() && !it->second) break;
            next_index_++;
        }

        if (next_index_ >= dataset_.size()) {
            error = "no registered unvoted voter found";
        } else {
            voter = dataset_[next_index_].first;
            candidate = dataset_[next_index_].second;
            verification = smt_verify_json_unlocked(voter);

            if (!SparseMerkleTree::verify_proof(smt_value_hash(voter, false), smt_->generate_proof(smt_key_for(voter)), smt_->get_root())) {
                error = "sparse merkle verification failed";
            } else if (!append_vote_unlocked(voter, candidate)) {
                error = "vote could not be cast";
            } else {
                next_index_++;
                voter_registry_[voter] = true;
                smt_->insert(smt_key_for(voter), smt_value_hash(voter, true));
                cast = true;
                if (interval_ > 0 && (cast_votes_.size() % interval_) == 0)
                    do_interval_audit();
            }
        }
    }

    o << "{\"ok\":" << (cast ? "true" : "false")
      << ",\"cast\":" << (cast ? "true" : "false")
      << ",\"voter\":\"" << json_escape(voter) << "\""
      << ",\"candidate\":\"" << json_escape(candidate) << "\""
      << ",\"error\":\"" << json_escape(error) << "\""
      << ",\"verification\":" << verification << "}";
    return o.str();
}

// ==========================================================================
// JSON: state
// ==========================================================================
std::string MMRSimulation::state_json() const {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    o << "{";
    o << "\"leafCount\":" << cast_votes_.size() << ",";
    o << "\"root\":\"" << (cast_votes_.empty() ? "" : mmr_.get_root()) << "\",";
    o << "\"maxVotes\":" << max_votes_ << ",";
    o << "\"interval\":" << interval_ << ",";
    o << "\"datasetSize\":" << dataset_.size() << ",";
    o << "\"nextIndex\":" << next_index_ << ",";
    o << "\"verifiedCount\":" << verified_count_ << ",";
    o << "\"tampered\":" << (tampered_flag_ ? "true" : "false") << ",";
    o << "\"running\":" << (runner_active_ ? "true" : "false") << ",";
    o << "\"regRunning\":" << (reg_runner_active_ ? "true" : "false") << ",";
    o << "\"registeredCount\":" << voter_registry_.size() << ",";
    o << "\"smtRoot\":\"" << json_escape(smt_->get_root()) << "\",";
    o << "\"smtNodes\":" << smt_->node_count() << ",";
    o << "\"peakCount\":" << mmr_.peak_count() << ",";
    // tally
    o << "\"tally\":{";
    for (size_t i = 0; i < candidates_tally_.size(); ++i) {
        if (i) o << ",";
        o << "\"" << json_escape(candidates_tally_[i].first) << "\":" << candidates_tally_[i].second;
    }
    o << "}}";
    return o.str();
}

// ==========================================================================
// JSON: tree structure (recursive serialization)
// ==========================================================================
std::string MMRSimulation::serialize_node(MMRNode* node) const {
    if (!node) return "null";
    std::ostringstream o;
    std::string short_hash = node->hash.size() > 12 ? node->hash.substr(0, 12) : node->hash;
    o << "{\"h\":\"" << node->hash << "\",\"short\":\"" << short_hash << "\",\"ht\":" << node->height;
    if (node->left || node->right) {
        o << ",\"l\":" << serialize_node(node->left);
        o << ",\"r\":" << serialize_node(node->right);
    }
    o << "}";
    return o.str();
}

std::string MMRSimulation::tree_json() const {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    o << "{\"peaks\":[";
    auto& peaks = mmr_.peaks();
    for (size_t i = 0; i < peaks.size(); ++i) {
        if (i) o << ",";
        o << serialize_node(peaks[i]);
    }
    o << "],\"leafCount\":" << mmr_.leaf_count();
    o << ",\"peakCount\":" << mmr_.peak_count();
    // Leaf metadata for the most recent 1024 leaves
    o << ",\"leaves\":[";
    size_t total = cast_votes_.size();
    size_t start = total > 1024 ? total - 1024 : 0;
    for (size_t i = start; i < total; ++i) {
        if (i > start) o << ",";
        auto& leaves_vec = mmr_.leaves();
        std::string lhash = (i < leaves_vec.size()) ? leaves_vec[i]->hash : "";
        o << "{\"i\":" << i
          << ",\"v\":\"" << json_escape(cast_votes_[i].first) << "\""
          << ",\"c\":\"" << json_escape(cast_votes_[i].second) << "\""
          << ",\"h\":\"" << lhash << "\"}";
    }
    o << "]}";
    return o.str();
}

// ==========================================================================
// JSON: votes list
// ==========================================================================
std::string MMRSimulation::votes_json() const {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    o << "[";
    for (size_t i = 0; i < cast_votes_.size(); ++i) {
        if (i) o << ",";
        auto& leaves_vec = mmr_.leaves();
        std::string lhash = (i < leaves_vec.size()) ? leaves_vec[i]->hash : "";
        o << "{\"i\":" << i
          << ",\"voter\":\"" << json_escape(cast_votes_[i].first) << "\""
          << ",\"candidate\":\"" << json_escape(cast_votes_[i].second) << "\""
          << ",\"hash\":\"" << lhash << "\"}";
    }
    o << "]";
    return o.str();
}

// ==========================================================================
// JSON: audit log
// ==========================================================================
std::string MMRSimulation::auditlog_json() const {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    o << "[";
    for (size_t i = 0; i < audit_log_.size(); ++i) {
        if (i) o << ",";
        auto& a = audit_log_[i];
        o << "{\"num\":" << a.interval_number
          << ",\"leaves\":" << a.leaf_count
          << ",\"root\":\"" << (a.root_hash.size() > 16 ? a.root_hash.substr(0,16) : a.root_hash) << "\""
          << ",\"tamper\":" << (a.tamper_detected ? "true" : "false")
          << ",\"invalidFrom\":" << a.invalidated_from << "}";
    }
    o << "]";
    return o.str();
}

// ==========================================================================
// JSON: snapshots (current MMR snapshot roots from audit history)
// ==========================================================================
std::string MMRSimulation::snapshots_json() const {
    // Return audit records which serve as the snapshot gallery
    return auditlog_json();
}

// ==========================================================================
// JSON: candidates
// ==========================================================================
std::string MMRSimulation::candidates_json() const {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    o << "[";
    for (size_t i = 0; i < candidate_list_.size(); ++i) {
        if (i) o << ",";
        o << "\"" << json_escape(candidate_list_[i]) << "\"";
    }
    o << "]";
    return o.str();
}

// ==========================================================================
// JSON: verify (proof path for a leaf)
// ==========================================================================
std::string MMRSimulation::verify_json(int leaf_index) const {
    std::lock_guard<std::mutex> g(state_mutex_);
    std::ostringstream o;
    if (leaf_index < 0 || leaf_index >= static_cast<int>(cast_votes_.size())) {
        o << "{\"ok\":false,\"error\":\"index out of range\"}";
        return o.str();
    }
    try {
        auto proof = mmr_.generate_proof(leaf_index);
        std::string leaf_hash = sha256(cast_votes_[leaf_index].first + "|" + cast_votes_[leaf_index].second);
        std::string root = mmr_.get_root();
        bool verified = MerkleMMR::verify_proof(leaf_hash, proof, root);

        o << "{\"ok\":true,\"leafIndex\":" << leaf_index;
        o << ",\"voter\":\"" << json_escape(cast_votes_[leaf_index].first) << "\"";
        o << ",\"candidate\":\"" << json_escape(cast_votes_[leaf_index].second) << "\"";
        o << ",\"leafHash\":\"" << leaf_hash << "\"";
        o << ",\"root\":\"" << root << "\"";
        o << ",\"verified\":" << (verified ? "true" : "false");
        o << ",\"peakIdx\":" << proof.leaf_peak_idx;

        std::string current = leaf_hash;

        // Intra-peak proof steps: rebuild the peak root from the leaf upward.
        o << ",\"steps\":[";
        for (size_t i = 0; i < proof.intra_proof.size(); ++i) {
            const std::string& sibling = proof.intra_proof[i].first;
            const std::string& dir = proof.intra_proof[i].second;
            const std::string before = current;
            current = (dir == "R") ? sha256(current + sibling) : sha256(sibling + current);
            if (i) o << ",";
            o << "{\"sibling\":\"" << sibling << "\""
              << ",\"dir\":\"" << dir << "\""
              << ",\"current\":\"" << before << "\""
              << ",\"result\":\"" << current << "\"}";
        }

        // Replace the proved peak with the reconstructed value, then bag peaks
        // the same way get_root() does. The UI displays these comparisons too.
        std::vector<std::string> proof_peaks = proof.peak_hashes;
        if (proof.leaf_peak_idx >= 0 && proof.leaf_peak_idx < static_cast<int>(proof_peaks.size()))
            proof_peaks[proof.leaf_peak_idx] = current;

        std::vector<std::string> bag_left;
        std::vector<std::string> bag_right;
        std::vector<std::string> bag_result;
        if (!proof_peaks.empty()) {
            std::string bag_root = proof_peaks.back();
            for (int i = static_cast<int>(proof_peaks.size()) - 2; i >= 0; --i) {
                std::string left = proof_peaks[i];
                std::string right = bag_root;
                bag_root = sha256(left + right);
                bag_left.push_back(left);
                bag_right.push_back(right);
                bag_result.push_back(bag_root);
            }
        }

        o << "],\"bagSteps\":[";
        for (size_t i = 0; i < bag_result.size(); ++i) {
            if (i) o << ",";
            o << "{\"left\":\"" << bag_left[i] << "\""
              << ",\"right\":\"" << bag_right[i] << "\""
              << ",\"result\":\"" << bag_result[i] << "\"}";
        }

        o << "],\"peaks\":[";
        for (size_t i = 0; i < proof.peak_hashes.size(); ++i) {
            if (i) o << ",";
            o << "\"" << proof.peak_hashes[i] << "\"";
        }
        o << "]}";
    } catch (...) {
        o << "{\"ok\":false,\"error\":\"proof generation failed\"}";
    }
    return o.str();
}

// ==========================================================================
// HTTP Server
// ==========================================================================
bool MMRSimulation::start(int preferred_port) {
    if (running_) return true;
    if (!init_sockets()) return false;

    // Auto-load dataset
    bool loaded = false;
    if (load_dataset("data/dataset.csv")) loaded = true;
    if (loaded) std::cout << "MMRSimulation: dataset loaded (auto)\n";

    running_ = true;
    server_thread_ = std::thread([this, preferred_port]() {
        for (int port = preferred_port; port < preferred_port + 20 && running_; ++port) {
            Socket s = ::socket(AF_INET, SOCK_STREAM, 0);
            if (s == invalid_socket) continue;
            int yes = 1;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(static_cast<unsigned short>(port));
            if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 && ::listen(s, 8) == 0) {
                std::cout << "MMRSimulation server listening on http://127.0.0.1:" << port << "/\n";
                while (running_) {
                    sockaddr_in client_addr{};
#ifdef _WIN32
                    int len = sizeof(client_addr);
#else
                    socklen_t len = sizeof(client_addr);
#endif
                    Socket client = accept(s, reinterpret_cast<sockaddr*>(&client_addr), &len);
                    if (client == invalid_socket) { if (!running_) break; continue; }
                    char buf[8192];
                    int r = recv(client, buf, sizeof(buf)-1, 0);
                    if (r <= 0) { close_socket(client); continue; }
                    buf[r] = '\0';
                    std::string req(buf);

                    // Parse path
                    std::string path = "/";
                    size_t p = req.find("GET ");
                    if (p != std::string::npos) {
                        size_t st = p + 4, en = req.find(' ', st);
                        if (en != std::string::npos) path = req.substr(st, en - st);
                    }

                    std::string response;
                    std::string body;
                    std::string content_type = "application/json; charset=utf-8";

                    // ---- Route: HTML page ----
                    if (path == "/" || path == "/index.html") {
                        std::ifstream htmlf("sim/merkle_mmr_sim.html");
                        if (htmlf.is_open()) {
                            std::ostringstream ss; ss << htmlf.rdbuf(); body = ss.str();
                        } else {
                            body = "<html><body><h1>MMR Simulation — HTML not found</h1></body></html>";
                        }
                        content_type = "text/html; charset=utf-8";
                    }
                    // ---- Route: /api/state ----
                    else if (path.rfind("/api/state", 0) == 0) {
                        body = state_json();
                    }
                    // ---- Route: /api/tree ----
                    else if (path.rfind("/api/tree", 0) == 0) {
                        body = tree_json();
                    }
                    // ---- Route: /api/votes ----
                    else if (path.rfind("/api/votes", 0) == 0) {
                        body = votes_json();
                    }
                    // ---- Route: /api/auditlog ----
                    else if (path.rfind("/api/auditlog", 0) == 0) {
                        body = auditlog_json();
                    }
                    // ---- Route: /api/snapshots ----
                    else if (path.rfind("/api/snapshots", 0) == 0) {
                        body = snapshots_json();
                    }
                    // ---- Route: /api/candidates ----
                    else if (path.rfind("/api/candidates", 0) == 0) {
                        body = candidates_json();
                    }
                    // ---- Route: /api/verify ----
                    else if (path.rfind("/api/verify", 0) == 0) {
                        int idx = -1;
                        std::string si = query_param(path, "index");
                        if (!si.empty()) try { idx = std::stoi(si); } catch(...) {}
                        body = verify_json(idx);
                    }
                    else if (path.rfind("/api/smt_verify", 0) == 0) {
                        std::string voter = query_param(path, "voter");
                        body = smt_verify_json(voter);
                    }
                    else if (path.rfind("/api/vote_attempt", 0) == 0) {
                        std::string voter = query_param(path, "voter");
                        std::string cand  = query_param(path, "candidate");
                        body = vote_attempt_json(voter, cand);
                    }
                    else if (path.rfind("/api/step_attempt", 0) == 0) {
                        body = step_attempt_json();
                    }
                    // ---- Route: /api/action ----
                    else if (path.rfind("/api/action", 0) == 0) {
                        std::string cmd = query_param(path, "cmd");
                        bool ok = false;
                        std::string extra;

                        if (cmd == "step") {
                            ok = step_one();
                        } else if (cmd == "run") {
                            int rate = 200;
                            std::string sr = query_param(path, "rate");
                            if (!sr.empty()) try { rate = std::stoi(sr); } catch(...) {}
                            ok = run_auto(rate);
                        } else if (cmd == "stop") {
                            stop_auto(); ok = true;
                        } else if (cmd == "stop_all") {
                            stop_auto();
                            reg_runner_active_ = false;
                            if (reg_runner_thread_.joinable()) reg_runner_thread_.join();
                            ok = true;
                        } else if (cmd == "reset") {
                            stop_auto();
                            reg_runner_active_ = false;
                            if (reg_runner_thread_.joinable()) reg_runner_thread_.join();
                            {
                            std::lock_guard<std::mutex> g(state_mutex_);
                            mmr_ = MerkleMMR();
                            next_index_ = 0;
                            candidates_tally_.clear();
                            cast_votes_.clear();
                            audit_log_.clear();
                            audit_number_ = 0;
                            verified_count_ = 0;
                            tampered_flag_ = false;
                            manual_vote_counter_ = 0;
                            voter_registry_.clear();
                            smt_interval_snapshot_.clear();
                            delete smt_; smt_ = new SparseMerkleTree(16);
                            }
                            ok = true;
                        } else if (cmd == "configure") {
                            int mv = -1, iv = 10;
                            std::string sv = query_param(path, "votes");
                            std::string si = query_param(path, "interval");
                            if (!sv.empty()) try { mv = std::stoi(sv); } catch(...) {}
                            if (!si.empty()) try { iv = std::stoi(si); } catch(...) {}
                            ok = configure(mv, iv);
                        } else if (cmd == "load") {
                            std::string pp = query_param(path, "path");
                            if (pp.empty()) pp = "data/dataset.csv";
                            int mx = -1;
                            std::string sm = query_param(path, "max");
                            if (!sm.empty()) try { mx = std::stoi(sm); } catch(...) {}
                            std::lock_guard<std::mutex> g(state_mutex_);
                            ok = load_dataset(pp, mx);
                        } else if (cmd == "register") {
                            std::string voter = query_param(path, "voter");
                            ok = register_voter(voter);
                        } else if (cmd == "auto_register") {
                            // Start background thread to register all dataset voters
                            if (!reg_runner_active_) {
                                if (reg_runner_thread_.joinable()) reg_runner_thread_.join();
                                reg_runner_active_ = true;
                                int cnt_param = -1;
                                std::string sc = query_param(path, "count");
                                if (!sc.empty()) try { cnt_param = std::stoi(sc); } catch(...) {}
                                reg_runner_thread_ = std::thread([this, cnt_param]() {
                                    int added = 0;
                                    for (size_t i = 0; i < dataset_.size() && reg_runner_active_; ++i) {
                                        if (cnt_param > 0 && added >= cnt_param) break;
                                        {
                                            std::lock_guard<std::mutex> g(state_mutex_);
                                            if (max_votes_ > 0 && static_cast<int>(voter_registry_.size()) >= max_votes_) break;
                                            if (voter_registry_.emplace(dataset_[i].first, false).second) {
                                                uint64_t key = smt_key_for(dataset_[i].first);
                                                smt_->insert(key, smt_value_hash(dataset_[i].first, false));
                                                added++;
                                            }
                                        }
                                        std::this_thread::sleep_for(std::chrono::milliseconds(1200));
                                    }
                                    reg_runner_active_ = false;
                                });
                                ok = true;
                            }
                        } else if (cmd == "auto_register_stop") {
                            reg_runner_active_ = false;
                            if (reg_runner_thread_.joinable()) reg_runner_thread_.join();
                            ok = true;
                        } else if (cmd == "vote") {
                            std::string voter = query_param(path, "voter");
                            std::string cand  = query_param(path, "candidate");
                            ok = vote_manual(voter, cand);
                        } else if (cmd == "tamper_leaf") {
                            int idx = -1;
                            std::string si = query_param(path, "index");
                            std::string cand = query_param(path, "candidate");
                            if (!si.empty()) try { idx = std::stoi(si); } catch(...) {}
                            if (idx >= 0) ok = tamper_leaf(static_cast<size_t>(idx), cand);
                        }
                        body = ok ? "{\"ok\":true}" : "{\"ok\":false}";
                    }
                    // ---- Route: /api/registry ----
                    else if (path.rfind("/api/registry", 0) == 0) {
                        body = registry_json();
                    }
                    // ---- Route: /api/smt ----
                    else if (path.rfind("/api/smt", 0) == 0) {
                        body = smt_json();
                    }
                    // ---- 404 ----
                    else {
                        body = "Not found";
                        content_type = "text/plain";
                        response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: "
                                   + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
                        send(client, response.c_str(), static_cast<int>(response.size()), 0);
                        close_socket(client);
                        continue;
                    }

                    response = "HTTP/1.1 200 OK\r\nContent-Type: " + content_type
                               + "\r\nContent-Length: " + std::to_string(body.size())
                               + "\r\nAccess-Control-Allow-Origin: *"
                               + "\r\nConnection: close\r\n\r\n" + body;
                    send(client, response.c_str(), static_cast<int>(response.size()), 0);
                    close_socket(client);
                }
                close_socket(s);
                break;
            }
            close_socket(s);
        }
        running_ = false;
    });
    return true;
}

void MMRSimulation::stop() {
    running_ = false;
    stop_auto();
    if (server_thread_.joinable()) server_thread_.join();
}

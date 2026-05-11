#include "../sim/mmr_simulation.hpp"
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
MMRSimulation::MMRSimulation() {}
MMRSimulation::~MMRSimulation() { stop(); }

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

    auto v = dataset_[next_index_++];
    std::string leaf = sha256(v.first + "|" + v.second);
    mmr_.append(leaf);
    cast_votes_.push_back(v);

    // Update tally
    auto it = std::find_if(candidates_tally_.begin(), candidates_tally_.end(),
                           [&](auto& p){ return p.first == v.second; });
    if (it == candidates_tally_.end()) candidates_tally_.push_back({v.second, 1});
    else it->second++;

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
    if (voter.empty() || candidate.empty()) return false;
    if (max_votes_ > 0 && static_cast<int>(cast_votes_.size()) >= max_votes_) return false;

    std::string leaf = sha256(voter + "|" + candidate);
    mmr_.append(leaf);
    cast_votes_.push_back({voter, candidate});

    auto it = std::find_if(candidates_tally_.begin(), candidates_tally_.end(),
                           [&](auto& p){ return p.first == candidate; });
    if (it == candidates_tally_.end()) candidates_tally_.push_back({candidate, 1});
    else it->second++;

    // Also add to candidate_list_ if new
    if (std::find(candidate_list_.begin(), candidate_list_.end(), candidate) == candidate_list_.end())
        candidate_list_.push_back(candidate);

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
    o << "{\"h\":\"" << short_hash << "\",\"ht\":" << node->height;
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
        std::string lhash = (i < leaves_vec.size()) ? leaves_vec[i]->hash.substr(0, 12) : "";
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
        std::string lhash = (i < leaves_vec.size()) ? leaves_vec[i]->hash.substr(0, 16) : "";
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
    std::lock_guard<std::mutex> g(state_mutex_);
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
        o << ",\"leafHash\":\"" << leaf_hash.substr(0,16) << "\"";
        o << ",\"root\":\"" << root.substr(0,16) << "\"";
        o << ",\"verified\":" << (verified ? "true" : "false");
        o << ",\"peakIdx\":" << proof.leaf_peak_idx;
        // proof steps
        o << ",\"steps\":[";
        for (size_t i = 0; i < proof.intra_proof.size(); ++i) {
            if (i) o << ",";
            o << "{\"sibling\":\"" << proof.intra_proof[i].first.substr(0,16) << "\""
              << ",\"dir\":\"" << proof.intra_proof[i].second << "\"}";
        }
        o << "],\"peaks\":[";
        for (size_t i = 0; i < proof.peak_hashes.size(); ++i) {
            if (i) o << ",";
            o << "\"" << proof.peak_hashes[i].substr(0,16) << "\"";
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
    if (load_dataset("dataset.csv")) loaded = true;
    else if (load_dataset("data/dataset.csv")) loaded = true;
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
                        } else if (cmd == "reset") {
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

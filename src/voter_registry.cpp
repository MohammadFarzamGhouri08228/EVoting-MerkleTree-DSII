#include "header/voter_registry.hpp"

bool VoterRegistry::register_voter_impl(const std::string& voter_id) {
    if (voters_.count(voter_id)) return false;
    voters_[voter_id] = false;
    return true;
}

bool VoterRegistry::is_registered_impl(const std::string& voter_id) const {
    return voters_.count(voter_id) > 0;
}

bool VoterRegistry::has_voted_impl(const std::string& voter_id) const {
    auto it = voters_.find(voter_id);
    if (it == voters_.end()) return false;
    return it->second;
}

void VoterRegistry::mark_voted_impl(const std::string& voter_id) {
    voters_[voter_id] = true;
}

void VoterRegistry::unmark_voted_impl(const std::string& voter_id) {
    voters_[voter_id] = false;
}

void VoterRegistry::store_receipt_impl(const std::string& receipt_id, int ballot_index) {
    receipt_map_[receipt_id] = ballot_index;
}

int VoterRegistry::get_ballot_index_impl(const std::string& receipt_id) const {
    auto it = receipt_map_.find(receipt_id);
    if (it == receipt_map_.end()) return -1;
    return it->second;
}

int VoterRegistry::voter_count() const { return static_cast<int>(voters_.size()); }
int VoterRegistry::receipt_count() const { return static_cast<int>(receipt_map_.size()); }

std::vector<std::pair<std::string, bool>> VoterRegistry::entries() const {
    std::vector<std::pair<std::string, bool>> out;
    out.reserve(voters_.size());
    for (const auto& kv : voters_)
        out.push_back(kv);
    return out;
}

void VoterRegistry::print_registry() const {
    std::cout << "\n  Voter Registry  (" << voter_count() << " registered)\n";
    std::cout << "  " << std::string(44, '-') << "\n";
    for (const auto& kv : voters_)
        std::cout << "    " << kv.first
                  << "  --  " << (kv.second ? "VOTED" : "eligible") << "\n";
    std::cout << "\n";
}

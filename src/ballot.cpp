#include "header/ballot.hpp"

std::string Ballot::to_canonical() const {
    return receipt_id + "|" + voter_id + "|" + candidate + "|" + salt + "|" + timestamp;
}

std::string Ballot::to_hash() const {
    return sha256(to_canonical());
}

std::string Ballot::to_display() const {
    std::string s = "[" + receipt_id + "] voter=" + voter_id + "  ";
    if (tampered && !pre_tamper_candidate.empty())
        s += "vote: " + pre_tamper_candidate + " -> " + candidate + "  ";
    else
        s += "candidate=" + candidate + "  ";
    s += "ts=" + timestamp;
    if (!valid)   s += "  [INVALIDATED]";
    if (tampered) s += "  [*** TAMPERED ***]";
    return s;
}

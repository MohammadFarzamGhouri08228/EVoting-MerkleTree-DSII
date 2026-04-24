#include <iostream>
#include <cassert>
#include "../ballot.hpp"

void test_canonical_string() {
    Ballot b;
    b.receipt_id = "R123";
    b.voter_id = "V123";
    b.candidate = "Alice";
    b.salt = "salt123";
    b.timestamp = "1000";
    
    std::string expected = "R123|V123|Alice|salt123|1000";
    assert(b.to_canonical() == expected);
    std::cout << "test_canonical_string passed.\n";
}

void test_hashing_consistency() {
    Ballot b1;
    b1.receipt_id = "R123";
    b1.voter_id = "V123";
    b1.candidate = "Alice";
    b1.salt = "salt123";
    b1.timestamp = "1000";

    Ballot b2;
    b2.receipt_id = "R123";
    b2.voter_id = "V123";
    b2.candidate = "Alice";
    b2.salt = "salt123";
    b2.timestamp = "1000";

    assert(b1.to_hash() == b2.to_hash());

    Ballot b3;
    b3.receipt_id = "R123";
    b3.voter_id = "V123";
    b3.candidate = "Alice";
    b3.salt = "salt456"; // Different salt
    b3.timestamp = "1000";

    assert(b1.to_hash() != b3.to_hash());
    std::cout << "test_hashing_consistency passed.\n";
}

int main() {
    std::cout << "Running Ballot tests...\n";
    test_canonical_string();
    test_hashing_consistency();
    std::cout << "All Ballot tests passed!\n";
    return 0;
}

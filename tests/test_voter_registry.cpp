#include <iostream>
#include <cassert>
#include "../header/voter_registry.hpp"

void test_registration_and_lookup() {
    VoterRegistry registry;
    
    assert(registry.voter_count() == 0);
    
    // Register voter
    bool registered = registry.register_voter("V1");
    assert(registered == true);
    assert(registry.voter_count() == 1);
    assert(registry.is_registered("V1") == true);
    assert(registry.is_registered("V2") == false);
    
    // Duplicate registration
    bool registered_again = registry.register_voter("V1");
    assert(registered_again == false);
    assert(registry.voter_count() == 1);
    
    std::cout << "test_registration_and_lookup passed.\n";
}

void test_voting_status() {
    VoterRegistry registry;
    registry.register_voter("V1");
    
    assert(registry.has_voted("V1") == false);
    
    registry.mark_voted("V1");
    assert(registry.has_voted("V1") == true);
    
    registry.unmark_voted("V1");
    assert(registry.has_voted("V1") == false);
    
    std::cout << "test_voting_status passed.\n";
}

void test_receipt_mapping() {
    VoterRegistry registry;
    
    assert(registry.receipt_count() == 0);
    
    registry.store_receipt("R1", 10);
    assert(registry.receipt_count() == 1);
    assert(registry.get_ballot_index("R1") == 10);
    assert(registry.get_ballot_index("R2") == -1);
    
    registry.store_receipt("R2", 20);
    assert(registry.receipt_count() == 2);
    assert(registry.get_ballot_index("R2") == 20);
    
    std::cout << "test_receipt_mapping passed.\n";
}

int main() {
    std::cout << "Running VoterRegistry tests...\n";
    test_registration_and_lookup();
    test_voting_status();
    test_receipt_mapping();
    std::cout << "All VoterRegistry tests passed!\n";
    return 0;
}

import csv
import random

NUM_VOTERS = 10000
CANDIDATES = ["Alice Smith", "Bob Jones", "Charlie Brown", "Diana Prince"]

def generate_dataset(filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["voter_id", "candidate"])
        
        for i in range(1, NUM_VOTERS + 1):
            voter_id = f"VOTER-{i:06d}"
            # Add some weighted randomness to make it realistic
            candidate = random.choices(
                CANDIDATES, 
                weights=[40, 35, 15, 10], # Alice gets ~40% of votes, etc.
                k=1
            )[0]
            writer.writerow([voter_id, candidate])

if __name__ == "__main__":
    generate_dataset("data/dataset.csv")
    print(f"Generated {NUM_VOTERS} synthetic votes in data/dataset.csv")

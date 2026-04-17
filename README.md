<<<<<<< HEAD
# COMP6453 Threshold Hash-Based Signatures

## Overview
- These codes implement a minimal prototype of a threshold hash-based signature scheme in a centralised setting. 

- It combines:
    Lamport one-time signatures
    Merkle tree structure
    XOR-based secret sharing

- A trusted dealer generates keys and distributes shares, while an untrusted aggregator collects shares and reconstructs the signature. The correctness of the scheme is verified using Lamport verification and Merkle path validation. 

## Structure
- threshold_hbs.py: core implementation of the scheme, including Lamport one-time signatures, XOR-based secret sharing, Merkle tree construction, Signing and verification. 
- demo.py: demonstrates a complete signing and verification processes. 
- benchmarks.py: run performance tests with different parameters. 

## How to Run
- Step 1: Run Demo

    python demo.py

- Step 2: Run Benchmark

    python benchmarks.py


## Example
### The parameters in demo: 
    Number of parties: 3
    Merkle tree height: 3
    Message: "threshold hash-based signatures demo"

### Output:
    -- Demo: Minimal Threshold HBS --
    Merkle root: 384ec409e81e8e492d63cb106359976512ed4b00da232443163a274572a9c831
    Max signatures: 8
    Leaf index used: 0
    Revealed elements: 256
    Verification result: True

    -- Benchmark: Minimal Threshold HBS --
    {'parties': 2, 'tree_height': 2, 'rounds': 5, 'setup_time': 0.01096354, 'sign_time': 0.00086806, 'verify_time': 0.0002955}
    {'parties': 2, 'tree_height': 3, 'rounds': 5, 'setup_time': 0.02078514, 'sign_time': 0.0010104, 'verify_time': 0.00033584}
    {'parties': 3, 'tree_height': 2, 'rounds': 5, 'setup_time': 0.01779522, 'sign_time': 0.00168884, 'verify_time': 0.00037216}
    {'parties': 3, 'tree_height': 3, 'rounds': 5, 'setup_time': 0.03697276, 'sign_time': 0.001772, 'verify_time': 0.000468}
    {'parties': 4, 'tree_height': 3, 'rounds': 5, 'setup_time': 0.0425814, 'sign_time': 0.0021874, 'verify_time': 0.00033114}


=======
# COMP6453 Threshold Hash-Based Signatures

## Overview
- These codes implement a minimal prototype of a threshold hash-based signature scheme in a centralised setting. 

- It combines:
    Lamport one-time signatures
    Merkle tree structure
    XOR-based secret sharing

- A trusted dealer generates keys and distributes shares, while an untrusted aggregator collects shares and reconstructs the signature. The correctness of the scheme is verified using Lamport verification and Merkle path validation. 

## Structure
- threshold_hbs.py: core implementation of the scheme, including Lamport one-time signatures, XOR-based secret sharing, Merkle tree construction, Signing and verification. 
- demo.py: demonstrates a complete signing and verification processes. 
- benchmarks.py: run performance tests with different parameters. 

## How to Run
- Step 1: Run Demo

    python demo.py

- Step 2: Run Benchmark

    python benchmarks.py


## Example
### The parameters in demo: 
    Number of parties: 3
    Merkle tree height: 3
    Message: "threshold hash-based signatures demo"

### Output:
    -- Demo: Minimal Threshold HBS --
    Merkle root: 384ec409e81e8e492d63cb106359976512ed4b00da232443163a274572a9c831
    Max signatures: 8
    Leaf index used: 0
    Revealed elements: 256
    Verification result: True

    -- Benchmark: Minimal Threshold HBS --
    {'parties': 2, 'tree_height': 2, 'rounds': 5, 'setup_time': 0.01096354, 'sign_time': 0.00086806, 'verify_time': 0.0002955}
    {'parties': 2, 'tree_height': 3, 'rounds': 5, 'setup_time': 0.02078514, 'sign_time': 0.0010104, 'verify_time': 0.00033584}
    {'parties': 3, 'tree_height': 2, 'rounds': 5, 'setup_time': 0.01779522, 'sign_time': 0.00168884, 'verify_time': 0.00037216}
    {'parties': 3, 'tree_height': 3, 'rounds': 5, 'setup_time': 0.03697276, 'sign_time': 0.001772, 'verify_time': 0.000468}
    {'parties': 4, 'tree_height': 3, 'rounds': 5, 'setup_time': 0.0425814, 'sign_time': 0.0021874, 'verify_time': 0.00033114}


>>>>>>> f3c8dba (update for extension 1)

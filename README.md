# COMP6453 Threshold Hash-Based Signatures

## Overview
- These codes implement a prototype of a threshold hash-based signature scheme in a centralised setting, and extend it with multiple advanced features for performance and functionality. 

- It combines:
    Lamport one-time signatures, 
    Merkle tree structure, 
    XOR-based secret sharing

- A trusted dealer generates keys and distributes secret shares to parties, while an untrusted aggregator collects partial signatures and reconstructs the final signature. Correctness is ensured via Lamport verification and Merkle path validation. 

## Extensions
- This project includes five extensions beyond the minimal scheme
- Extension 1: k-of-n Threshold Signing: implements a k-of-n threshold scheme using a k-of-k subset-based (subtree-style) construction, where only k selected parties are required to produce a valid signature, and each signature binds a KeyID and randomizer R to the message.
- Extension 2: Distributed Threshold Signing: partially removes the fully trusted dealer assumption by introducing helper string lookup, allowing parties to locally derive shares using a hash-based PRF-like method, keeping only a correction share at the dealer, and running an explicit two-round peer-to-peer signing protocol.
- Extension 3: Batched Signing: supports batch signing by buffering multiple messages into a Merkle tree, signing only the batch root, verifying individual messages using authentication paths.
- Extension 4: Hierarchical Batched Signing: introduces a hierarchical Merkle structure: leaves remain Lamport nodes, upper layers are organised into subtree + upper tree, authentication paths become hierarchical.
- Extension 5: Winternitz Optimization: replaces Lamport signatures with Winternitz signatures to reduce signature size and improve efficiency, while preserving the threshold structure and the randomized KeyID-plus-R signing flow.

## Structure
- `threshold_hbs.py`: core implementation of the scheme, including all schemes and extensions. 
- `demo.py`: demonstrates the complete signing and verification processes. 
- `benchmarks.py`: evaluates performance under different parameter settings. 

## How to Run
- Step 1: Run Demo

    python demo.py

- Step 2: Run Benchmark

    python benchmarks.py


## Example
### Demo Output (simplified) and Explanation:
    -- Demo: Minimal Threshold HBS --
    Verification result: True

    -- Demo: Extension 1 (k-of-k subtrees for k-of-n) --
    Verification result: True

    -- Demo: Extension 2 (two-round distributed signing) --
    KeyID: 0
    Round 1 responses: 3
    Round 2 responses: 3
    Verification result: True

    -- Demo: Extension 3 (Merkle-buffered batched signing) --
    Verification results: [True, True, True]

    -- Demo: Extension 4 (Hierarchical higher layer Merkle trees) --
    Verification results: [True, True, True]

    -- Demo: Extension 5 (Winternitz Threshold HBS) --
    Verification result: True

- The demo shows that all schemes produce valid signatures. Each extension successfully extends the minimal scheme with additional functionality, including threshold flexibility, two-round distributed coordination, batching, hierarchical organisation, and signature size optimisation. 

### Benchmarks Output Explanation:

- The benchmark results demonstrate the trade-offs between number of parties, threshold size (k), and tree height across different extensions. 
- Observations: Larger trees increase setup cost. Distributed version (Extension 2) introduces additional overhead because of helper-string lookup, session coordination, and the two-round signing flow. Batched signing (Extension 3 & 4) reduces per message signing cost. Winternitz (Extension 5) improves efficiency and reduces signature size. 


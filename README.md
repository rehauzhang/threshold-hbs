# COMP6453 Threshold Hash-Based Signatures

## Overview
This repository implements a prototype of a threshold hash-based signature scheme, starting from a minimal centralised baseline and progressing toward a more distributed architecture.

It combines:
- Lamport one-time signatures
- Merkle tree structures
- XOR-based secret sharing

In the minimal baseline, a trusted dealer generates keys and distributes secret shares to parties, while an untrusted aggregator collects partial signatures and reconstructs the final signature.

In the distributed extensions, parties derive shares locally via PRF-style methods. The signing flow is coordinated through explicit multi-round protocols, reducing the need for the dealer to distribute large secret-share material in memory. Correctness is checked via one-time-signature verification and Merkle path validation.

## Extensions
This project includes five extensions beyond the minimal scheme:

- Extension 1: k-of-n Threshold Signing  
  Implements a k-of-n threshold scheme using a k-of-k subset-based (subtree-style) construction. Only k selected parties are required to produce a valid signature, and each signature binds a KeyID and randomizer R to the message.

- Extension 2: Distributed Threshold Signing  
  Partially removes the fully trusted dealer assumption. It introduces helper-string lookup, allowing parties to locally derive shares using a hash-based PRF-like method. It uses CRV-style correction material for randomizer, check, path, and secret-key reconstruction inside a two-round signing protocol.

- Extension 3: Batched Signing  
  Supports batch signing by buffering multiple messages into a Merkle tree. Only the batch root is signed, and individual messages are verified using corresponding authentication paths.

- Extension 4: Hierarchical Batched Signing  
  Introduces a hierarchical Merkle structure. Leaves remain Lamport nodes, while upper layers are organised into a subtree plus an upper tree, resulting in hierarchical authentication paths.

- Extension 5: Winternitz Optimization  
  Replaces Lamport signatures with Winternitz signatures to reduce signature size and improve efficiency, while preserving the threshold structure, the randomized KeyID + R signing flow, and the distributed two-round protocol model introduced in Extension 2.

## Structure
- `threshold_hbs.py`: Core implementation of the baseline scheme and all five extensions
- `demo.py`: Demonstrates setup, signing, and verification across the different schemes
- `benchmarks.py`: Evaluates performance metrics under different parameter settings

## Requirements
- Python 3.x
- Standard libraries only: `hashlib`, `secrets`, `statistics`, `time`, `itertools`

## How to Run
Step 1: Run demo

```bash
python demo.py
```

Step 2: Run benchmarks

```bash
python benchmarks.py
```

## Example Output and Analysis

### Demo Highlights
The `demo.py` script shows that all schemes produce valid signatures.

Key observations:
- Extension 2 and Extension 5 explicitly go through Round 1 and Round 2 distributed coordination before final verification.
- Extension 3 and Extension 4 return arrays such as `[True, True, True]`, showing successful batched verification.

### Benchmark Insights
The `benchmarks.py` results illustrate trade-offs between the number of parties (`n`), threshold size (`k`), and tree height.

Key observations:
- Larger trees increase setup cost because more leaves and authentication structures must be generated.
- Distributed signing in Extension 2 introduces additional overhead due to helper-string lookup, CRV generation, session coordination, and the two-round flow.
- Batched signing in Extensions 3 and 4 reduces average per-message signing cost, making it attractive for higher-throughput settings.
- Winternitz in Extension 5 reduces the number of chains compared with Lamport, which helps reduce signature size while remaining within the distributed two-round framework.

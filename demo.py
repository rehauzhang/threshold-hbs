from threshold_hbs import ThresholdHBSScheme, KOfNThresholdHBSScheme, DistributedThresholdHBSScheme, BatchedThresholdHBSScheme, HierarchicalBatchedThresholdHBSScheme, WinternitzThresholdHBSScheme

def main():
    # Basic scheme (minimal)
    mini_scheme = ThresholdHBSScheme(parties=4, tree_height=3)
    mini_message = b"threshold hash-based signatures demo"
    mini_signature = mini_scheme.sign(mini_message)

    print("-- Demo: Minimal Threshold HBS --")
    print("Parties:", mini_scheme.parties)
    print("Merkle root:", mini_scheme.public_bundle.merkle_root.hex())
    print("Max signatures:", mini_scheme.public_bundle.max_signatures)
    print("Leaf index used:", mini_signature.leaf_index)
    print("Revealed elements:", len(mini_signature.revealed))
    print("Verification result:", mini_scheme.verify(mini_signature))
    print()

    # Extension 1: (k-of-n Threshold)
    ext_scheme1 = KOfNThresholdHBSScheme(parties=4, threshold_k=3, tree_height=3)
    ext_message1 = b"extension 1 k-of-k subtree demo"
    ext_signature1 = ext_scheme1.sign(ext_message1, active_party_ids=[0, 2, 3])

    print("-- Demo: Extension 1 (k-of-k subtrees for k-of-n) --")
    print("Parties:", ext_scheme1.parties)
    print("Threshold k:", ext_scheme1.threshold_k)
    print("Number of k-subtrees:", len(ext_scheme1.subset_parties))
    print("KeyID:", ext_signature1.key_id)
    print("Randomizer R:", ext_signature1.randomizer_R.hex()[:32] + "...")
    print("Leaf index used:", ext_signature1.leaf_index)
    print("Assigned subset:", ext_scheme1.leaf_to_subset[ext_signature1.leaf_index])
    print("Verification result:", ext_scheme1.verify(ext_signature1))
    print()

    # Extension 2: (Distributed Signing)
    ext_scheme2 = DistributedThresholdHBSScheme(parties=4, threshold_k=3, tree_height=3)
    ext_message2 = b"extension 2 distributed threshold demo"
    ext_session2 = ext_scheme2.create_signing_session(
        message=ext_message2,
        signer_ids=[0, 2, 3],
    )
    ext_round1_2 = ext_scheme2.run_round1(ext_session2)
    ext_round2_responses2 = []
    for pid in ext_session2.signer_ids:
        ext_round2_responses2.append(
            ext_scheme2.party_round2_response(pid, ext_session2, ext_round1_2["R"])
        )
    ext_signature2 = ext_scheme2.assemble_signature(
        ext_session2,
        ext_round1_2["R"],
        ext_round2_responses2,
    )

    print("-- Demo: Extension 2 (two-round distributed signing) --")
    print("Parties:", ext_scheme2.parties)
    print("Threshold k:", ext_scheme2.threshold_k)
    print("Signer IDs:", ext_session2.signer_ids)
    print("KeyID:", ext_session2.key_id)
    print("Round 1 responses:", len(ext_round1_2["responses"]))
    print("Round 1 randomizer R:", ext_round1_2["R"].hex()[:32] + "...")
    print("Round 2 responses:", len(ext_round2_responses2))
    print("Leaf index used:", ext_signature2.leaf_index)
    print("Assigned subset:", ext_scheme2.leaf_to_subset[ext_signature2.leaf_index])
    print("Verification result:", ext_scheme2.verify(ext_signature2))
    print()

    # Extension 3: (Batched Signing)
    ext_scheme3 = BatchedThresholdHBSScheme(parties=4, threshold_k=3, tree_height=4)
    batch_messages = [b"batch message 1", b"batch message 2", b"batch message 3",]
    ext_signature3 = ext_scheme3.sign_batch(batch_messages, active_party_ids=[0, 1, 2])

    print("-- Demo: Extension 3 (Merkle-buffered batched signing) --")
    print("Parties:", ext_scheme3.parties)
    print("Threshold k:", ext_scheme3.threshold_k)
    print("Batch size:", len(ext_signature3.messages))
    print("Underlying leaf index:", ext_signature3.batch_root_signature.leaf_index)
    print("Verification results:", ext_scheme3.verify_batch(ext_signature3))
    print()

    # Extension 4: (Hierarchical Batching)
    ext_scheme4 = HierarchicalBatchedThresholdHBSScheme(parties=4, threshold_k=3, tree_height=4, subtree_height=2,)
    subtree_messages = [b"subtree message 1", b"subtree message 2", b"subtree message 3",]
    ext_batch_result = ext_scheme4.sign_batch_in_subtree(messages=subtree_messages, active_party_ids=[0, 1, 2],)

    print("-- Demo: Extension 4 (Hierarchical higher layer Merkle trees) --")
    print("Parties:", ext_scheme4.parties)
    print("Threshold k:", ext_scheme4.threshold_k)
    print("Tree height:", ext_scheme4.tree_height)
    print("Subtree height:", ext_scheme4.subtree_height)
    print("Subtree index:", ext_batch_result["subtree_index"])
    print("Used leaf indices:", ext_batch_result["used_leaf_indices"])
    print("Verification results:", ext_scheme4.verify_subtree_batch(ext_batch_result))
    print()

    # Extension 5: (Winternitz Optimisation)
    ext_scheme5 = WinternitzThresholdHBSScheme(parties=4, threshold_k=3, tree_height=3, w=16,)
    ext_message5 = b"extension 5 winternitz threshold demo"
    ext_session5 = ext_scheme5.create_signing_session(
        message=ext_message5,
        signer_ids=[0, 1, 2],
    )
    ext_round1_5 = ext_scheme5.run_round1(ext_session5)
    ext_round2_responses5 = []
    for pid in ext_session5.signer_ids:
        ext_round2_responses5.append(
            ext_scheme5.party_round2_response(pid, ext_session5, ext_round1_5["R"])
        )
    ext_signature5 = ext_scheme5.assemble_signature(
        ext_session5,
        ext_round1_5["R"],
        ext_round2_responses5,
    )

    print("-- Demo: Extension 5 (Winternitz Threshold HBS) --")
    print("Parties:", ext_scheme5.parties)
    print("Threshold k:", ext_scheme5.threshold_k)
    print("Winternitz w:", ext_scheme5.w)
    print("Number of chains:", ext_scheme5.num_chains)
    print("Signer IDs:", ext_session5.signer_ids)
    print("KeyID:", ext_signature5.key_id)
    print("Randomizer R:", ext_signature5.randomizer_R.hex()[:32] + "...")
    print("Round 1 responses:", len(ext_round1_5["responses"]))
    print("Round 2 responses:", len(ext_round2_responses5))
    print("Leaf index used:", ext_signature5.leaf_index)
    print("Verification result:", ext_scheme5.verify(ext_signature5))

if __name__ == "__main__":
    main()


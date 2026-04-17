<<<<<<< HEAD
from threshold_hbs import ThresholdHBSScheme

def main():
    scheme = ThresholdHBSScheme(parties=3, tree_height=3)

    message = b"threshold hash-based signatures demo"
    signature = scheme.sign(message)

    print("-- Demo: Minimal Threshold HBS --")
    print("Merkle root:", scheme.public_bundle.merkle_root.hex())
    print("Max signatures:", scheme.public_bundle.max_signatures)
    print("Leaf index used:", signature.leaf_index)
    print("Revealed elements:", len(signature.revealed))
    print("Verification result:", scheme.verify(signature))

if __name__ == "__main__":
    main()

=======
from threshold_hbs import ThresholdHBSScheme, KOfNThresholdHBSScheme

def main():
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

    ext_scheme1 = KOfNThresholdHBSScheme(parties=4, threshold_k=3, tree_height=3)
    ext_message1 = b"extension 1 k-of-n threshold demo"
    ext_signature1 = ext_scheme1.sign(ext_message1, active_party_ids=[0, 2, 3])

    print("-- Demo: Extension 1 (k-of-n Threshold HBS) --")
    print("Parties:", ext_scheme1.parties)
    print("Threshold k:", ext_scheme1.threshold_k)
    print("Merkle root:", ext_scheme1.public_bundle.merkle_root.hex())
    print("Max signatures:", ext_scheme1.public_bundle.max_signatures)
    print("Leaf index used:", ext_signature1.leaf_index)
    print("Revealed elements:", len(ext_signature1.revealed))
    print("Verification result:", ext_scheme1.verify(ext_signature1))

if __name__ == "__main__":
    main()

>>>>>>> f3c8dba (update for extension 1)

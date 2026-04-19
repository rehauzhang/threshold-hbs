from threshold_hbs import ThresholdHBSScheme, KOfNThresholdHBSScheme, DistributedThresholdHBSScheme, BatchedThresholdHBSScheme, HierarchicalBatchedThresholdHBSScheme, WinternitzThresholdHBSScheme

def main():
    # Basic scheme (minimal)
    print("-- Benchmark: Minimal Threshold HBS --")

    mini_settings = [(2, 2), (3, 2), (4, 2), (4, 3), (5, 3),]

    for parties, tree_height in mini_settings:
        scheme = ThresholdHBSScheme(parties=parties, tree_height=tree_height)
        result = scheme.benchmark(rounds=5)
        print(result.to_dict())

    print()
    # Extension 1: (k-of-k Threshold)
    print("-- Benchmark: Extension 1 k-of-k Subtrees for k-of-n --")

    ext_settings1 = [(4, 2, 3), (4, 3, 3), (5, 2, 4), (5, 3, 4), (6, 3, 5),]

    for parties, threshold_k, tree_height in ext_settings1:
        scheme = KOfNThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height)
        result = scheme.benchmark(rounds=5)
        print(result)

    print()
    # Extension 2: (Distributed Signing)
    print("-- Benchmark: Extension 2 Distributed Threshold HBS --")

    ext_settings2 = [(4, 2, 3), (4, 3, 3), (5, 2, 4), (5, 3, 4), (6, 3, 5),]

    for parties, threshold_k, tree_height in ext_settings2:
        scheme = DistributedThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height)
        result = scheme.benchmark(rounds=5)
        print(result)

    print()
    # Extension 3: (Batched Signing)
    print("-- Benchmark: Extension 3 Batched Threshold HBS --")

    ext_settings3 = [(4, 2, 3, 2), (4, 3, 3, 3), (5, 2, 4, 4), (5, 3, 4, 4), (6, 3, 5, 5),]

    for parties, threshold_k, tree_height, batch_size in ext_settings3:
        scheme = BatchedThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height)
        result = scheme.benchmark_batch(rounds=5, batch_size=batch_size)
        print(result)

    print()
    # Extension 4: (Hierarchical Batching)
    print("-- Benchmark: Extension 4 Hierarchical Batched Threshold HBS --")

    ext_settings4 = [(4, 2, 4, 2, 2), (4, 3, 4, 2, 3), (5, 2, 4, 2, 4), (5, 3, 4, 2, 4), (6, 3, 5, 2, 5),]

    for parties, threshold_k, tree_height, subtree_height, batch_size in ext_settings4:
        scheme = HierarchicalBatchedThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height, subtree_height=subtree_height)
        result = scheme.benchmark_hierarchical_batch(rounds=5, batch_size=batch_size)
        print(result)

    print()
    # Extension 5: (Winternitz Optimisation)
    print("-- Benchmark: Extension 5 Winternitz Threshold HBS --")

    ext_settings5 = [(4, 2, 3, 4), (4, 3, 3, 8), (5, 2, 4, 8), (5, 3, 4, 16), (6, 3, 5, 16),]

    for parties, threshold_k, tree_height, w in ext_settings5:
        scheme = WinternitzThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height, w=w)
        result = scheme.benchmark(rounds=5)
        print(result)

if __name__ == "__main__":
    main()


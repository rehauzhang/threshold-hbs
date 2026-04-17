from threshold_hbs import ThresholdHBSScheme, KOfNThresholdHBSScheme, DistributedThresholdHBSScheme, BatchedThresholdHBSScheme, HierarchicalBatchedThresholdHBSScheme

def main():
    print("-- Benchmark: Minimal Threshold HBS --")

    mini_settings = [(2, 2), (2, 3), (3, 2), (3, 3), (4, 3),]

    for parties, tree_height in mini_settings:
        scheme = ThresholdHBSScheme(parties=parties, tree_height=tree_height)
        result = scheme.benchmark(rounds=5)
        print(result.to_dict())

    print()
    print("-- Benchmark: Extension 1 k-of-n Threshold HBS --")

    ext_settings1 = [(4, 3, 3), (5, 3, 3), (5, 4, 2),]

    for parties, threshold_k, tree_height in ext_settings1:
        scheme = KOfNThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height)
        result = scheme.benchmark(rounds=5)
        print(result)

    print()
    print("-- Benchmark: Extension 2 Distributed Threshold HBS --")

    ext_settings2 = [(4, 3, 3), (5, 3, 3), (5, 4, 2),]

    for parties, threshold_k, tree_height in ext_settings2:
        scheme = DistributedThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height)
        result = scheme.benchmark(rounds=5)
        print(result)

    print()
    print("-- Benchmark: Extension 3 Batched Threshold HBS --")

    ext_settings3 = [(4, 3, 4, 3), (5, 3, 4, 3), (5, 4, 4, 4),]

    for parties, threshold_k, tree_height, batch_size in ext_settings3:
        scheme = BatchedThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height)
        result = scheme.benchmark_batch(rounds=5, batch_size=batch_size)
        print(result)

    print()
    print("-- Benchmark: Extension 4 Hierarchical Batched Threshold HBS --")

    ext_settings4 = [(4, 3, 4, 2, 3), (5, 3, 4, 2, 3), (5, 4, 4, 2, 4),]

    for parties, threshold_k, tree_height, subtree_height, batch_size in ext_settings4:
        scheme = HierarchicalBatchedThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height, subtree_height=subtree_height)
        result = scheme.benchmark_hierarchical_batch(rounds=5, batch_size=batch_size)
        print(result)

if __name__ == "__main__":
    main()


from threshold_hbs import (
    ThresholdHBSScheme,
    KOfNThresholdHBSScheme,
    DistributedThresholdHBSScheme,
    BatchedThresholdHBSScheme,
    HierarchicalBatchedThresholdHBSScheme,
    WinternitzThresholdHBSScheme,
)
import csv
import statistics
import time


ROUNDS = 20
OUTPUT_CSV = "benchmark_results.csv"


def bytes_len(x):
    if isinstance(x, bytes):
        return len(x)
    return 0


def merkle_path_size(path):
    if path is None:
        return 0

    # Normal MerklePath
    if hasattr(path, "siblings") and hasattr(path, "directions"):
        return sum(len(s) for s in path.siblings)

    # HierarchicalMerklePath
    total = 0
    if hasattr(path, "local_path"):
        total += merkle_path_size(path.local_path)
    if hasattr(path, "upper_path"):
        total += merkle_path_size(path.upper_path)
    return total


def lamport_public_key_size(pk):
    total = 0
    for branch in pk.pub:
        for item in branch:
            total += len(item)
    return total


def winternitz_public_key_size(pk):
    return sum(len(x) for x in pk.pub)


def signature_size_bytes(sig):
    # ThresholdSignature
    if hasattr(sig, "lamport_public_key"):
        total = 0
        total += len(sig.randomizer)
        total += sum(len(x) for x in sig.revealed)
        total += lamport_public_key_size(sig.lamport_public_key)
        total += merkle_path_size(sig.auth_path)
        return total

    # WinternitzThresholdSignature
    if hasattr(sig, "public_key"):
        total = 0
        total += len(sig.randomizer)
        total += sum(len(x) for x in sig.revealed)
        total += winternitz_public_key_size(sig.public_key)
        total += merkle_path_size(sig.auth_path)
        return total

    # BatchThresholdSignature
    if hasattr(sig, "batch_root_signature"):
        total = 0
        total += signature_size_bytes(sig.batch_root_signature)
        total += len(sig.batch_root)
        for path in sig.batch_paths:
            total += merkle_path_size(path)
        return total

    return 0


def public_bundle_size_bytes(bundle):
    total = 0
    total += len(bundle.merkle_root)
    # max_signatures / leaves / hash_name
    return total


def crv_size_bytes(scheme):
    if not hasattr(scheme, "crv"):
        return 0

    total = 0
    for _, entry in scheme.crv.items():
        total += len(entry.R)

        if isinstance(entry.chk, dict):
            for v in entry.chk.values():
                total += len(v)

        if isinstance(entry.PATH, list):
            for v in entry.PATH:
                total += len(v)

        # Lamport CRV.SK: dict[bit_index][bit_value] -> bytes
        if isinstance(entry.SK, dict):
            for _, inner in entry.SK.items():
                if isinstance(inner, dict):
                    for _, v in inner.items():
                        total += len(v)
                else:
                    total += len(inner)

    return total


def estimate_round_comm_bytes(scheme):
    """
    - round1: each signer sends r_share + chk_share
    - round2:
        * Lamport distributed: signer sends lamport_bits shares + path shares
        * Winternitz: signer sends num_chains shares + path shares
    """
    if not hasattr(scheme, "threshold_k"):
        return 0, 0, 0

    digest = scheme.digest_size
    k = scheme.threshold_k
    tree_h = scheme.tree_height

    round1 = k * (digest + digest)

    if isinstance(scheme, WinternitzThresholdHBSScheme):
        round2 = k * ((scheme.num_chains * digest) + (tree_h * digest))
    else:
        # DistributedThresholdHBSScheme, BatchedThresholdHBSScheme, HierarchicalBatchedThresholdHBSScheme
        if hasattr(scheme, "lamport_bits"):
            round2 = k * ((scheme.lamport_bits * digest) + (tree_h * digest))
        else:
            round2 = 0

    return round1, round2, round1 + round2


def summarize_times(times):
    return {
        "mean": round(statistics.mean(times), 8),
        "stdev": round(statistics.stdev(times), 8) if len(times) > 1 else 0.0,
        "median": round(statistics.median(times), 8),
    }


def run_minimal(parties, tree_height, rounds):
    setup_times = []
    sign_times = []
    verify_times = []
    sig_sizes = []
    bundle_sizes = []

    for i in range(rounds):
        message = f"benchmark-message-{i}".encode()

        t0 = time.perf_counter()
        scheme = ThresholdHBSScheme(parties=parties, tree_height=tree_height)
        t1 = time.perf_counter()

        sig = scheme.sign(message)
        t2 = time.perf_counter()

        ok = scheme.verify(sig)
        t3 = time.perf_counter()

        if not ok:
            raise RuntimeError("minimal benchmark produced invalid signature")

        setup_times.append(t1 - t0)
        sign_times.append(t2 - t1)
        verify_times.append(t3 - t2)
        sig_sizes.append(signature_size_bytes(sig))
        bundle_sizes.append(public_bundle_size_bytes(scheme.public_bundle))

    setup_stats = summarize_times(setup_times)
    sign_stats = summarize_times(sign_times)
    verify_stats = summarize_times(verify_times)

    return {
        "scheme": "minimal",
        "parties": parties,
        "threshold_k": "",
        "tree_height": tree_height,
        "subtree_height": "",
        "batch_size": "",
        "w": "",
        "rounds": rounds,
        "setup_time_mean": setup_stats["mean"],
        "setup_time_stdev": setup_stats["stdev"],
        "sign_time_mean": sign_stats["mean"],
        "sign_time_stdev": sign_stats["stdev"],
        "verify_time_mean": verify_stats["mean"],
        "verify_time_stdev": verify_stats["stdev"],
        "avg_sign_time_per_message": sign_stats["mean"],
        "signature_size_bytes": round(statistics.mean(sig_sizes), 2),
        "public_bundle_size_bytes": round(statistics.mean(bundle_sizes), 2),
        "crv_size_bytes": 0,
        "round1_comm_bytes": 0,
        "round2_comm_bytes": 0,
        "total_comm_bytes": 0,
    }


def run_ext1(parties, threshold_k, tree_height, rounds):
    setup_times = []
    sign_times = []
    verify_times = []
    sig_sizes = []
    bundle_sizes = []
    active_party_ids = list(range(threshold_k))

    for i in range(rounds):
        message = f"benchmark-message-{i}".encode()

        t0 = time.perf_counter()
        scheme = KOfNThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height)
        t1 = time.perf_counter()

        sig = scheme.sign(message, active_party_ids=active_party_ids)
        t2 = time.perf_counter()

        ok = scheme.verify(sig)
        t3 = time.perf_counter()

        if not ok:
            raise RuntimeError("ext1 benchmark produced invalid signature")

        setup_times.append(t1 - t0)
        sign_times.append(t2 - t1)
        verify_times.append(t3 - t2)
        sig_sizes.append(signature_size_bytes(sig))
        bundle_sizes.append(public_bundle_size_bytes(scheme.public_bundle))

    setup_stats = summarize_times(setup_times)
    sign_stats = summarize_times(sign_times)
    verify_stats = summarize_times(verify_times)

    return {
        "scheme": "ext1_k_of_k_subtree",
        "parties": parties,
        "threshold_k": threshold_k,
        "tree_height": tree_height,
        "subtree_height": "",
        "batch_size": "",
        "w": "",
        "rounds": rounds,
        "setup_time_mean": setup_stats["mean"],
        "setup_time_stdev": setup_stats["stdev"],
        "sign_time_mean": sign_stats["mean"],
        "sign_time_stdev": sign_stats["stdev"],
        "verify_time_mean": verify_stats["mean"],
        "verify_time_stdev": verify_stats["stdev"],
        "avg_sign_time_per_message": sign_stats["mean"],
        "signature_size_bytes": round(statistics.mean(sig_sizes), 2),
        "public_bundle_size_bytes": round(statistics.mean(bundle_sizes), 2),
        "crv_size_bytes": 0,
        "round1_comm_bytes": 0,
        "round2_comm_bytes": 0,
        "total_comm_bytes": 0,
    }


def run_ext2(parties, threshold_k, tree_height, rounds):
    setup_times = []
    sign_times = []
    verify_times = []
    sig_sizes = []
    bundle_sizes = []
    crv_sizes = []
    signer_ids = list(range(threshold_k))

    for i in range(rounds):
        message = f"benchmark-message-{i}".encode()

        t0 = time.perf_counter()
        scheme = DistributedThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height)
        t1 = time.perf_counter()

        sig = scheme.sign(message, signer_ids=signer_ids)
        t2 = time.perf_counter()

        ok = scheme.verify(sig)
        t3 = time.perf_counter()

        if not ok:
            raise RuntimeError("ext2 benchmark produced invalid signature")

        setup_times.append(t1 - t0)
        sign_times.append(t2 - t1)
        verify_times.append(t3 - t2)
        sig_sizes.append(signature_size_bytes(sig))
        bundle_sizes.append(public_bundle_size_bytes(scheme.public_bundle))
        crv_sizes.append(crv_size_bytes(scheme))

    round1_comm, round2_comm, total_comm = estimate_round_comm_bytes(scheme)
    setup_stats = summarize_times(setup_times)
    sign_stats = summarize_times(sign_times)
    verify_stats = summarize_times(verify_times)

    return {
        "scheme": "ext2_distributed",
        "parties": parties,
        "threshold_k": threshold_k,
        "tree_height": tree_height,
        "subtree_height": "",
        "batch_size": "",
        "w": "",
        "rounds": rounds,
        "setup_time_mean": setup_stats["mean"],
        "setup_time_stdev": setup_stats["stdev"],
        "sign_time_mean": sign_stats["mean"],
        "sign_time_stdev": sign_stats["stdev"],
        "verify_time_mean": verify_stats["mean"],
        "verify_time_stdev": verify_stats["stdev"],
        "avg_sign_time_per_message": sign_stats["mean"],
        "signature_size_bytes": round(statistics.mean(sig_sizes), 2),
        "public_bundle_size_bytes": round(statistics.mean(bundle_sizes), 2),
        "crv_size_bytes": round(statistics.mean(crv_sizes), 2),
        "round1_comm_bytes": round1_comm,
        "round2_comm_bytes": round2_comm,
        "total_comm_bytes": total_comm,
    }


def run_ext3(parties, threshold_k, tree_height, batch_size, rounds):
    setup_times = []
    sign_times = []
    verify_times = []
    sig_sizes = []
    bundle_sizes = []
    crv_sizes = []
    signer_ids = list(range(threshold_k))

    for i in range(rounds):
        messages = [f"batch-message-{i}-{j}".encode() for j in range(batch_size)]

        t0 = time.perf_counter()
        scheme = BatchedThresholdHBSScheme(parties=parties, threshold_k=threshold_k, tree_height=tree_height)
        t1 = time.perf_counter()

        sig = scheme.sign_batch(messages=messages, signer_ids=signer_ids)
        t2 = time.perf_counter()

        verify_results = scheme.verify_batch(sig)
        t3 = time.perf_counter()

        if not all(verify_results):
            raise RuntimeError("ext3 benchmark produced invalid signature")

        setup_times.append(t1 - t0)
        sign_times.append(t2 - t1)
        verify_times.append(t3 - t2)
        sig_sizes.append(signature_size_bytes(sig))
        bundle_sizes.append(public_bundle_size_bytes(scheme.public_bundle))
        crv_sizes.append(crv_size_bytes(scheme))

    round1_comm, round2_comm, total_comm = estimate_round_comm_bytes(scheme)
    setup_stats = summarize_times(setup_times)
    sign_stats = summarize_times(sign_times)
    verify_stats = summarize_times(verify_times)

    return {
        "scheme": "ext3_batched",
        "parties": parties,
        "threshold_k": threshold_k,
        "tree_height": tree_height,
        "subtree_height": "",
        "batch_size": batch_size,
        "w": "",
        "rounds": rounds,
        "setup_time_mean": setup_stats["mean"],
        "setup_time_stdev": setup_stats["stdev"],
        "sign_time_mean": sign_stats["mean"],
        "sign_time_stdev": sign_stats["stdev"],
        "verify_time_mean": verify_stats["mean"],
        "verify_time_stdev": verify_stats["stdev"],
        "avg_sign_time_per_message": round(sign_stats["mean"] / batch_size, 8),
        "signature_size_bytes": round(statistics.mean(sig_sizes), 2),
        "public_bundle_size_bytes": round(statistics.mean(bundle_sizes), 2),
        "crv_size_bytes": round(statistics.mean(crv_sizes), 2),
        "round1_comm_bytes": round1_comm,
        "round2_comm_bytes": round2_comm,
        "total_comm_bytes": total_comm,
    }


def run_ext4(parties, threshold_k, tree_height, subtree_height, batch_size, rounds):
    setup_times = []
    sign_times = []
    verify_times = []
    sig_sizes = []
    bundle_sizes = []
    crv_sizes = []
    signer_ids = list(range(threshold_k))

    for i in range(rounds):
        messages = [f"hierarchical-batch-message-{i}-{j}".encode() for j in range(batch_size)]

        t0 = time.perf_counter()
        scheme = HierarchicalBatchedThresholdHBSScheme(
            parties=parties,
            threshold_k=threshold_k,
            tree_height=tree_height,
            subtree_height=subtree_height,
        )
        t1 = time.perf_counter()

        batch_result = scheme.sign_batch_in_subtree(messages, signer_ids=signer_ids)
        t2 = time.perf_counter()

        verify_results = scheme.verify_subtree_batch(batch_result)
        t3 = time.perf_counter()

        if not all(verify_results):
            raise RuntimeError("ext4 benchmark produced invalid signature")

        setup_times.append(t1 - t0)
        sign_times.append(t2 - t1)
        verify_times.append(t3 - t2)
        sig_sizes.append(signature_size_bytes(batch_result["batch_signature"]))
        bundle_sizes.append(public_bundle_size_bytes(scheme.public_bundle))
        crv_sizes.append(crv_size_bytes(scheme))

    round1_comm, round2_comm, total_comm = estimate_round_comm_bytes(scheme)
    setup_stats = summarize_times(setup_times)
    sign_stats = summarize_times(sign_times)
    verify_stats = summarize_times(verify_times)

    return {
        "scheme": "ext4_hierarchical_batched",
        "parties": parties,
        "threshold_k": threshold_k,
        "tree_height": tree_height,
        "subtree_height": subtree_height,
        "batch_size": batch_size,
        "w": "",
        "rounds": rounds,
        "setup_time_mean": setup_stats["mean"],
        "setup_time_stdev": setup_stats["stdev"],
        "sign_time_mean": sign_stats["mean"],
        "sign_time_stdev": sign_stats["stdev"],
        "verify_time_mean": verify_stats["mean"],
        "verify_time_stdev": verify_stats["stdev"],
        "avg_sign_time_per_message": round(sign_stats["mean"] / batch_size, 8),
        "signature_size_bytes": round(statistics.mean(sig_sizes), 2),
        "public_bundle_size_bytes": round(statistics.mean(bundle_sizes), 2),
        "crv_size_bytes": round(statistics.mean(crv_sizes), 2),
        "round1_comm_bytes": round1_comm,
        "round2_comm_bytes": round2_comm,
        "total_comm_bytes": total_comm,
    }


def run_ext5(parties, threshold_k, tree_height, w, rounds):
    setup_times = []
    sign_times = []
    verify_times = []
    sig_sizes = []
    bundle_sizes = []
    crv_sizes = []
    signer_ids = list(range(threshold_k))

    for i in range(rounds):
        message = f"benchmark-message-{i}".encode()

        t0 = time.perf_counter()
        scheme = WinternitzThresholdHBSScheme(
            parties=parties,
            threshold_k=threshold_k,
            tree_height=tree_height,
            w=w,
        )
        t1 = time.perf_counter()

        sig = scheme.sign(message, active_party_ids=signer_ids)
        t2 = time.perf_counter()

        ok = scheme.verify(sig)
        t3 = time.perf_counter()

        if not ok:
            raise RuntimeError("ext5 benchmark produced invalid signature")

        setup_times.append(t1 - t0)
        sign_times.append(t2 - t1)
        verify_times.append(t3 - t2)
        sig_sizes.append(signature_size_bytes(sig))
        bundle_sizes.append(public_bundle_size_bytes(scheme.public_bundle))
        crv_sizes.append(crv_size_bytes(scheme))

    round1_comm, round2_comm, total_comm = estimate_round_comm_bytes(scheme)
    setup_stats = summarize_times(setup_times)
    sign_stats = summarize_times(sign_times)
    verify_stats = summarize_times(verify_times)

    return {
        "scheme": "ext5_winternitz",
        "parties": parties,
        "threshold_k": threshold_k,
        "tree_height": tree_height,
        "subtree_height": "",
        "batch_size": "",
        "w": w,
        "rounds": rounds,
        "setup_time_mean": setup_stats["mean"],
        "setup_time_stdev": setup_stats["stdev"],
        "sign_time_mean": sign_stats["mean"],
        "sign_time_stdev": sign_stats["stdev"],
        "verify_time_mean": verify_stats["mean"],
        "verify_time_stdev": verify_stats["stdev"],
        "avg_sign_time_per_message": sign_stats["mean"],
        "signature_size_bytes": round(statistics.mean(sig_sizes), 2),
        "public_bundle_size_bytes": round(statistics.mean(bundle_sizes), 2),
        "crv_size_bytes": round(statistics.mean(crv_sizes), 2),
        "round1_comm_bytes": round1_comm,
        "round2_comm_bytes": round2_comm,
        "total_comm_bytes": total_comm,
    }


def main():
    rows = []

    mini_settings = [(2, 2), (3, 2), (4, 2), (4, 3), (5, 3)]
    ext_settings1 = [(4, 2, 3), (4, 3, 3), (5, 2, 4), (5, 3, 4), (6, 3, 5)]
    ext_settings2 = [(4, 2, 3), (4, 3, 3), (5, 2, 4), (5, 3, 4), (6, 3, 5)]
    ext_settings3 = [(4, 2, 3, 2), (4, 3, 3, 3), (5, 2, 4, 4), (5, 3, 4, 4), (6, 3, 5, 5)]
    ext_settings4 = [(4, 2, 4, 2, 2), (4, 3, 4, 2, 3), (5, 2, 4, 2, 4), (5, 3, 4, 2, 4), (6, 3, 5, 2, 5)]
    ext_settings5 = [(4, 2, 3, 4), (4, 3, 3, 8), (5, 2, 4, 8), (5, 3, 4, 16), (6, 3, 5, 16)]

    print("-- Benchmark: Minimal Threshold HBS --")
    for parties, tree_height in mini_settings:
        row = run_minimal(parties, tree_height, ROUNDS)
        rows.append(row)
        print(row)

    print("\n-- Benchmark: Extension 1 k-of-k Subtrees for k-of-n --")
    for parties, threshold_k, tree_height in ext_settings1:
        row = run_ext1(parties, threshold_k, tree_height, ROUNDS)
        rows.append(row)
        print(row)

    print("\n-- Benchmark: Extension 2 Distributed Threshold HBS --")
    for parties, threshold_k, tree_height in ext_settings2:
        row = run_ext2(parties, threshold_k, tree_height, ROUNDS)
        rows.append(row)
        print(row)

    print("\n-- Benchmark: Extension 3 Batched Threshold HBS --")
    for parties, threshold_k, tree_height, batch_size in ext_settings3:
        row = run_ext3(parties, threshold_k, tree_height, batch_size, ROUNDS)
        rows.append(row)
        print(row)

    print("\n-- Benchmark: Extension 4 Hierarchical Batched Threshold HBS --")
    for parties, threshold_k, tree_height, subtree_height, batch_size in ext_settings4:
        row = run_ext4(parties, threshold_k, tree_height, subtree_height, batch_size, ROUNDS)
        rows.append(row)
        print(row)

    print("\n-- Benchmark: Extension 5 Winternitz Threshold HBS --")
    for parties, threshold_k, tree_height, w in ext_settings5:
        row = run_ext5(parties, threshold_k, tree_height, w, ROUNDS)
        rows.append(row)
        print(row)

    fieldnames = [
        "scheme",
        "parties",
        "threshold_k",
        "tree_height",
        "subtree_height",
        "batch_size",
        "w",
        "rounds",
        "setup_time_mean",
        "setup_time_stdev",
        "sign_time_mean",
        "sign_time_stdev",
        "verify_time_mean",
        "verify_time_stdev",
        "avg_sign_time_per_message",
        "signature_size_bytes",
        "public_bundle_size_bytes",
        "crv_size_bytes",
        "round1_comm_bytes",
        "round2_comm_bytes",
        "total_comm_bytes",
    ]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved benchmark results to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
import hashlib
import secrets
import statistics
import time
from itertools import combinations

class LamportPublicKey:
    def __init__(self, pub):
        self.pub = pub

    def leaf_hash(self, scheme):
        flat = []
        for branch in (0, 1):
            for item in self.pub[branch]:
                flat.append(item)
        return scheme.h_tag(b"lamport-leaf", *flat)
    
class MerklePath:
    def __init__(self, siblings, directions):
        self.siblings = siblings
        self.directions = directions

class HierarchicalMerklePath:
    def __init__(self, local_path, upper_path, subtree_index):
        self.local_path = local_path
        self.upper_path = upper_path
        self.subtree_index = subtree_index

class ThresholdSignature:
    def __init__(self, key_id=None, message=None, randomizer_R=None, revealed=None, lamport_public_key=None, auth_path=None, signer_ids=None, leaf_index=None):
        if key_id is None:
            key_id = leaf_index
        if key_id is None:
            raise ValueError("key_id or leaf_index must be provided")
        self.key_id = key_id
        # Keep the legacy leaf_index name for compatibility with the existing codebase.
        self.leaf_index = key_id
        self.message = message
        self.randomizer_R = b"" if randomizer_R is None else randomizer_R
        self.revealed = revealed
        self.lamport_public_key = lamport_public_key
        self.auth_path = auth_path
        self.signer_ids = [] if signer_ids is None else signer_ids

class ShareResponse:
    def __init__(self, party_id, leaf_index, selected_shares):
        self.party_id = party_id
        self.leaf_index = leaf_index
        self.selected_shares = selected_shares

class Round1Response:
    def __init__(self, party_id, key_id, r_share, chk_share):
        self.party_id = party_id
        self.key_id = key_id
        self.leaf_index = key_id
        self.r_share = r_share
        self.chk_share = chk_share

class Round2Response:
    # Lamport distributed path uses sk_shares
    # Winternitz distributed path uses z_shares
    def __init__(self, party_id, leaf_index, sk_shares=None, z_shares=None, path_shares=None):
        self.party_id = party_id
        self.leaf_index = leaf_index
        self.sk_shares = [] if sk_shares is None else sk_shares
        self.z_shares = [] if z_shares is None else z_shares
        self.path_shares = [] if path_shares is None else path_shares

class PublicKeyBundle:
    def __init__(self, merkle_root, max_signatures, hash_name, leaves):
        self.merkle_root = merkle_root
        self.max_signatures = max_signatures
        self.hash_name = hash_name
        self.leaves = leaves

class CRVEntry:
    def __init__(self, r_share, chk_shares, path_shares, sk_shares):
        self.R = r_share
        self.chk = chk_shares
        self.PATH = path_shares
        self.SK = sk_shares

    def to_dict(self):
        return {
            "parties": self.parties,
            "tree_height": self.tree_height,
            "rounds": self.rounds,
            "setup_time": round(self.setup_avg, 8),
            "sign_time": round(self.sign_avg, 8),
            "verify_time": round(self.verify_avg, 8),
        }
    
class BatchThresholdSignature:
    def __init__(self, batch_root_signature, messages, batch_paths, batch_root):
        self.batch_root_signature = batch_root_signature
        self.messages = messages
        self.batch_paths = batch_paths
        self.batch_root = batch_root
    
# Basic scheme (minimal): Lamport + Merkle + secret Sharing
class ThresholdHBSScheme:
    def __init__(self, parties, tree_height, approval_policies=None):
        if parties < 2:
            raise ValueError("parties must be at least 2")
        if tree_height < 1:
            raise ValueError("tree_height must be at least 1")
        
        self.hash_name = "sha256"
        self.digest_size = hashlib.new(self.hash_name).digest_size
        self.lamport_bits = self.digest_size * 8

        self.parties = parties
        self.tree_height = tree_height
        self.num_leaves = 2 ** tree_height

        if approval_policies is None:
            approval_policies = [lambda message: True for _ in range(parties)]

        if len(approval_policies) != parties:
            raise ValueError("approval_policies must have one entry for each party")
        
        self.approval_policies = approval_policies
        
        self.leaf_secret_keys = []
        self.leaf_public_keys = []
        self.party_shares = {}
        self.merkle_levels = []
        self.used_leaves = set()

        self.dealer_setup()

    def H(self, data):
        return hashlib.sha256(data).digest()
    
    def h_tag(self, tag, *parts):
        h = hashlib.sha256()
        h.update(tag)
        for part in parts:
            h.update(len(part).to_bytes(4, "big"))
            h.update(part)
        return h.digest()
    
    def randbytes(self, n):
        return secrets.token_bytes(n)
    
    def xor_bytes(self, parts):
        if not parts:
            raise ValueError("xor_bytes needs at least one input")
        
        out = bytearray(parts[0])

        for p in parts[1:]:
            if len(p) != len(out):
                raise ValueError("all inputs must have the same length")
            for i in range(len(out)):
                out[i] ^= p[i]

        return bytes(out)
    
    def bytes_to_bits(self, data):
        bits = []
        for b in data:
            for shift in range(7, -1, -1):
                bits.append((b >> shift) & 1)
        return bits
    
    def dealer_setup(self):
        self.leaf_secret_keys = []
        self.leaf_public_keys = []
        self.party_shares = {pid: {} for pid in range(self.parties)}
        for _ in range(self.num_leaves):
            sk, pk = self.generate_lamport_keypair()
            self.leaf_secret_keys.append(sk)
            self.leaf_public_keys.append(pk)

        leaf_hashes = []
        for pk in self.leaf_public_keys:
            leaf_hashes.append(pk.leaf_hash(self))

        self.merkle_levels = self.build_merkle_tree(leaf_hashes)
        self.build_xor_shares()

        self.public_bundle = PublicKeyBundle(merkle_root=self.get_merkle_root(), max_signatures=self.num_leaves, hash_name=self.hash_name, leaves=self.num_leaves,)

    def get_merkle_root(self):
        return self.merkle_levels[-1][0]
    
    def generate_lamport_keypair(self):
        secrets_2d = [[], []]
        pub_2d = [[], []]

        for branch in (0, 1):
            for _ in range(self.lamport_bits):
                x = self.randbytes(self.digest_size)
                secrets_2d[branch].append(x)
                pub_2d[branch].append(self.H(x))

        return secrets_2d, LamportPublicKey(pub_2d)
    
    def lamport_select_secret_elements(self, lamport_sk, message):
        digest_bits = self.bytes_to_bits(self.H(message))
        return [lamport_sk[bit][i] for i, bit in enumerate(digest_bits)]
    
    def verify_lamport_signature(self, message, revealed, pk):
        digest_bits = self.bytes_to_bits(self.H(message))

        if len(revealed) != self.lamport_bits:
            return False
        
        for i, bit in enumerate(digest_bits):
            if self.H(revealed[i]) != pk.pub[bit][i]:
                return False
            
        return True
    
    def xor_share(self, secret, n):
        if n < 2:
            raise ValueError("n must be at least 2")
        
        shares = []
        for _ in range(n - 1):
            shares.append(self.randbytes(len(secret)))

        final_share = self.xor_bytes([secret] + shares)
        shares.append(final_share)

        return shares
    
    def xor_recombine(self, shares):
        return self.xor_bytes(shares)
    
    def build_xor_shares(self):
        for leaf_index in range(len(self.leaf_secret_keys)):
            lamport_sk = self.leaf_secret_keys[leaf_index]

            for pid in range(self.parties):
                self.party_shares[pid][leaf_index] = {}

            for bit_index in range(self.lamport_bits):
                shares_zero = self.xor_share(lamport_sk[0][bit_index], self.parties)
                shares_one = self.xor_share(lamport_sk[1][bit_index], self.parties)

                for pid in range(self.parties):
                    self.party_shares[pid][leaf_index][bit_index] = {
                        0: shares_zero[pid],
                        1: shares_one[pid],
                    }

    def merkle_parent(self, left, right):
        return self.h_tag(b"merkle-parent", left, right)
    
    def build_merkle_tree(self, leaves):
        if len(leaves) == 0:
            raise ValueError("need at least one leaf")
        if len(leaves) & (len(leaves) - 1):
            raise ValueError("number of leaves must be a power of two")
        
        levels = [list(leaves)]
        current = list(leaves)

        while len(current) > 1:
            nxt = []
            for i in range(0, len(current), 2):
                nxt.append(self.merkle_parent(current[i], current[i + 1]))
            levels.append(nxt)
            current = nxt

        return levels
    
    def get_auth_path(self, leaf_index):
        if leaf_index < 0 or leaf_index >= self.num_leaves:
            raise IndexError("leaf index out of range")
        
        idx = leaf_index
        siblings = []
        directions = []

        for level in self.merkle_levels[:-1]:
            if idx % 2 == 0:
                sibling_index = idx + 1
                directions.append(0)
            else:
                sibling_index = idx - 1
                directions.append(1)

            siblings.append(level[sibling_index])
            idx = idx // 2

        return MerklePath(siblings, directions)
    
    def verify_merkle_path(self, leaf_hash, path, expected_root):
        if len(path.siblings) != len(path.directions):
            return False
        
        cur = leaf_hash

        for sibling, direction in zip(path.siblings, path.directions):
            if direction == 0:
                cur = self.merkle_parent(cur, sibling)
            elif direction == 1:
                cur = self.merkle_parent(sibling, cur)
            else:
                return False
            
        return cur == expected_root

    def approve(self, party_id, message):
        return bool(self.approval_policies[party_id](message))
    
    def party_produce_share(self, party_id, leaf_index, message):
        if not self.approve(party_id, message):
            raise PermissionError("party " + str(party_id) + " refused to sign")
        
        if party_id not in self.party_shares:
            raise KeyError("unknown party id")
        if leaf_index not in self.party_shares[party_id]:
            raise IndexError("unknown leaf index")
        
        bits = self.bytes_to_bits(self.H(message))
        selected_shares = []

        for bit_index in range(len(bits)):
            bit = bits[bit_index]
            selected_shares.append(self.party_shares[party_id][leaf_index][bit_index][bit])

        return ShareResponse(party_id=party_id, leaf_index=leaf_index, selected_shares=selected_shares,)
    
    def next_unused_leaf(self):
        for i in range(self.num_leaves):
            if i not in self.used_leaves:
                return i
        return None
    
    def sign(self, message, leaf_index=None):
        if leaf_index is None:
            leaf_index = self.next_unused_leaf()

        if leaf_index is None:
            raise RuntimeError("all Lamport leaves are exhausted")
        
        if leaf_index in self.used_leaves:
            raise RuntimeError("leaf already used; one-time key reuse is forbidden")
        
        share_responses = []
        for pid in range(self.parties):
            share_responses.append(self.party_produce_share(pid, leaf_index, message))
        
        bit_count = len(share_responses[0].selected_shares)

        for resp in share_responses:
            if resp.leaf_index != leaf_index:
                raise ValueError("inconsistent leaf index in responses")
            if len(resp.selected_shares) != bit_count:
                raise ValueError("inconsistent share count in responses")
            
        reconstructed_revealed = []

        for bit_index in range(bit_count):
            position_shares = []
            for resp in share_responses:
                position_shares.append(resp.selected_shares[bit_index])
            reconstructed_revealed.append(self.xor_recombine(position_shares))

        self.used_leaves.add(leaf_index)

        return ThresholdSignature(leaf_index=leaf_index, message=message, revealed=reconstructed_revealed, lamport_public_key=self.leaf_public_keys[leaf_index], auth_path=self.get_auth_path(leaf_index))
    
    def verify(self, signature, message=None, public_bundle=None):
        message = signature.message if message is None else message
        public_bundle = self.public_bundle if public_bundle is None else public_bundle
        lamport_ok = self.verify_lamport_signature(message, signature.revealed, signature.lamport_public_key,)

        if not lamport_ok:
            return False
        
        return self.verify_merkle_path(signature.lamport_public_key.leaf_hash(self), signature.auth_path, public_bundle.merkle_root,)
       
    def benchmark(self, rounds):
        setup_times = []
        sign_times = []
        verify_times = []

        for i in range(rounds):
            message = ("benchmark-message-" + str(i)).encode()

            t0 = time.perf_counter()
            scheme = ThresholdHBSScheme(self.parties, self.tree_height)
            t1 = time.perf_counter()

            sig = scheme.sign(message)
            t2 = time.perf_counter()

            ok = scheme.verify(sig)
            t3 = time.perf_counter()

            if not ok:
                raise RuntimeError("benchmark produced invalid signature")

            setup_times.append(t1 - t0)
            sign_times.append(t2 - t1)
            verify_times.append(t3 - t2)

        return {
            "parties": self.parties,
            "tree_height": self.tree_height,
            "rounds": rounds,
            "setup_time": round(statistics.mean(setup_times), 8),
            "sign_time": round(statistics.mean(sign_times), 8),
            "verify_time": round(statistics.mean(verify_times), 8),
        }

# Extension 1: use k-of-k subtree to realise a k-of-n signing       
class KOfNThresholdHBSScheme(ThresholdHBSScheme):
    def __init__(self, parties, threshold_k, tree_height, approval_policies=None):
        if threshold_k < 2:
            raise ValueError("threshold_k must be at least 2")
        if threshold_k > parties:
            raise ValueError("threshold_k cannot be larger than parties")
        
        self.threshold_k = threshold_k
        self.subset_parties = [tuple(s) for s in combinations(range(parties), threshold_k)]
        self.subset_leaf_ranges = {}
        self.leaf_to_subset = {}

        super().__init__(parties, tree_height, approval_policies)

    def dealer_setup(self):
        subset_count = len(self.subset_parties)
        if self.num_leaves < subset_count:
            raise ValueError("tree_height is too small for all k-of-k subtrees")
        
        self.leaf_secret_keys = []
        self.leaf_public_keys = []
        self.party_shares = {pid: {} for pid in range(self.parties)}
        self.used_leaves = set()

        for _ in range(self.num_leaves):
            sk, pk = self.generate_lamport_keypair()
            self.leaf_secret_keys.append(sk)
            self.leaf_public_keys.append(pk)

        leaf_hashes = []
        for pk in self.leaf_public_keys:
            leaf_hashes.append(pk.leaf_hash(self))

        self.merkle_levels = self.build_merkle_tree(leaf_hashes)
        self.assign_leaves_to_subsets()
        self.build_subset_xor_shares()

        self.public_bundle = PublicKeyBundle(merkle_root=self.get_merkle_root(), max_signatures=self.num_leaves, hash_name=self.hash_name, leaves=self.num_leaves,)

    def assign_leaves_to_subsets(self):
        subset_count = len(self.subset_parties)
        base = self.num_leaves // subset_count
        extra = self.num_leaves % subset_count
        if base == 0:
            raise ValueError("not enough leaves to assign at least one leaf to each subset")
        
        self.subset_leaf_ranges = {}
        self.leaf_to_subset = {}
        cursor = 0
        for index, subset in enumerate(self.subset_parties):
            count = base + (1 if index < extra else 0)
            start = cursor
            end = cursor + count - 1
            self.subset_leaf_ranges[subset] = (start, end)
            for leaf_index in range(start, end + 1):
                self.leaf_to_subset[leaf_index] = subset
            cursor = end + 1
    
    def build_subset_xor_shares(self):
        for leaf_index, lamport_sk in enumerate(self.leaf_secret_keys):
            subset = self.leaf_to_subset[leaf_index]

            for pid in range(self.parties):
                self.party_shares[pid][leaf_index] = {}

            for bit_index in range(self.lamport_bits):
                shares_zero = self.xor_share(lamport_sk[0][bit_index], len(subset),)
                shares_one = self.xor_share(lamport_sk[1][bit_index], len(subset),)
                
                for local_idx, pid in enumerate(subset):
                    self.party_shares[pid][leaf_index][bit_index] = {
                        0: shares_zero[local_idx],
                        1: shares_one[local_idx],
                    }

    def randomized_digest(self, key_id, randomizer_R, message):
        return self.h_tag(
            b"threshold-ots-digest",
            key_id.to_bytes(4, "big"),
            randomizer_R,
            message,
        )

    def randomized_digest_bits(self, key_id, randomizer_R, message):
        return self.bytes_to_bits(self.randomized_digest(key_id, randomizer_R, message))

    def verify_randomized_lamport_signature(self, key_id, randomizer_R, message, revealed, pk):
        digest_bits = self.randomized_digest_bits(key_id, randomizer_R, message)

        if len(revealed) != self.lamport_bits:
            return False

        for i, bit in enumerate(digest_bits):
            if self.H(revealed[i]) != pk.pub[bit][i]:
                return False

        return True

    def normalise_subset(self, active_party_ids):
        if active_party_ids is None:
            active_party_ids = list(range(self.threshold_k))
        unique_ids = []
        for pid in active_party_ids:
            if pid < 0 or pid >= self.parties:
                raise ValueError("invalid party id in active_party_ids")
            if pid not in unique_ids:
                unique_ids.append(pid)
        if len(unique_ids) != self.threshold_k:
            raise ValueError("extension 1 expects exactly k active parties for a k-of-k subtree")
        return tuple(sorted(unique_ids))
    
    def next_unused_leaf_for_subset(self, subset):
        start, end = self.subset_leaf_ranges[subset]
        for leaf_index in range(start, end + 1):
            if leaf_index not in self.used_leaves:
                return leaf_index
        return None

    def party_produce_share(self, party_id, leaf_index, message):
        subset = self.leaf_to_subset[leaf_index]
        if party_id not in subset:
            raise PermissionError("party is not a member of the selected k-of-k subtree")
        return super().party_produce_share(party_id, leaf_index, message,)

    def party_produce_randomized_share(self, party_id, leaf_index, message, randomizer_R):
        subset = self.leaf_to_subset[leaf_index]
        if party_id not in subset:
            raise PermissionError("party is not a member of the selected k-of-k subtree")
        if not self.approve(party_id, message):
            raise PermissionError("party " + str(party_id) + " refused to sign")

        bits = self.randomized_digest_bits(leaf_index, randomizer_R, message)
        selected_shares = []
        for bit_index, bit in enumerate(bits):
            selected_shares.append(self.party_shares[party_id][leaf_index][bit_index][bit])

        return ShareResponse(
            party_id=party_id,
            leaf_index=leaf_index,
            selected_shares=selected_shares,
        )
    
    def sign(self, message, leaf_index=None, active_party_ids=None):
        subset = self.normalise_subset(active_party_ids)
        if subset not in self.subset_leaf_ranges:
            raise PermissionError("no subtree exists for the selected active parties")
        if leaf_index is None:
            leaf_index = self.next_unused_leaf_for_subset(subset)
        if leaf_index is None:
            raise RuntimeError("all Lamport leaves are exhausted")
        if self.leaf_to_subset[leaf_index] != subset:
            raise PermissionError("leaf does not belong to the requested subtree")
        if leaf_index in self.used_leaves:
            raise RuntimeError("leaf already used; one-time key reuse is forbidden")

        randomizer_R = self.randbytes(self.digest_size)
        share_responses = []
        for pid in subset:
            resp = self.party_produce_randomized_share(pid, leaf_index, message, randomizer_R)
            share_responses.append(resp)

        digest_bits = self.randomized_digest_bits(leaf_index, randomizer_R, message)
        reconstructed_revealed = []

        for bit_index in range(len(digest_bits)):
            position_shares = [resp.selected_shares[bit_index] for resp in share_responses]
            reconstructed_revealed.append(self.xor_recombine(position_shares))

        self.used_leaves.add(leaf_index)

        return ThresholdSignature(
            key_id=leaf_index,
            message=message,
            randomizer_R=randomizer_R,
            revealed=reconstructed_revealed,
            lamport_public_key=self.leaf_public_keys[leaf_index],
            auth_path=self.get_auth_path(leaf_index),
            signer_ids=subset,
        )

    def verify(self, signature, message=None, public_bundle=None):
        message = signature.message if message is None else message
        public_bundle = self.public_bundle if public_bundle is None else public_bundle

        if signature.randomizer_R:
            lamport_ok = self.verify_randomized_lamport_signature(
                signature.key_id,
                signature.randomizer_R,
                message,
                signature.revealed,
                signature.lamport_public_key,
            )
        else:
            lamport_ok = self.verify_lamport_signature(
                message,
                signature.revealed,
                signature.lamport_public_key,
            )

        if not lamport_ok:
            return False

        return self.verify_merkle_path(
            signature.lamport_public_key.leaf_hash(self),
            signature.auth_path,
            public_bundle.merkle_root,
        )
    
    def benchmark(self, rounds):
        setup_times = []
        sign_times = []
        verify_times = []
        active_party_ids = list(range(self.threshold_k))

        for i in range(rounds):
            message = ("benchmark-message-" + str(i)).encode()

            t0 = time.perf_counter()
            scheme = KOfNThresholdHBSScheme(self.parties, self.threshold_k, self.tree_height,)
            t1 = time.perf_counter()

            sig = scheme.sign(message, active_party_ids=active_party_ids)
            t2 = time.perf_counter()

            ok = scheme.verify(sig)
            t3 = time.perf_counter()

            if not ok:
                raise RuntimeError("benchmark produced invalid signature")
            
            setup_times.append(t1 - t0)
            sign_times.append(t2 - t1)
            verify_times.append(t3 - t2)

        return {
            "parties":self.parties, 
            "threshold_k": self.threshold_k, 
            "tree_height": self.tree_height, 
            "rounds":rounds, 
            "setup_time": round(statistics.mean(setup_times), 8),
            "sign_time": round(statistics.mean(sign_times), 8),
            "verify_time": round(statistics.mean(verify_times), 8),
        }
    
# Extension 2:
# the untrusted server only looks up helper strings
# each party derives its own share locally using a hash-based PRF-like method
# the dealer exposes CRV-style correction values for R, CHK, PATH, and SK
class DistributedThresholdHBSScheme(KOfNThresholdHBSScheme):
    def __init__(self, parties, threshold_k, tree_height, approval_policies=None):
        self.helper_strings = {}
        self.party_prf_seeds = {}
        self.crv = {}
        super().__init__(parties, threshold_k, tree_height, approval_policies)

    def dealer_setup(self):
        subset_count = len(self.subset_parties)
        if self.num_leaves < subset_count:
            raise ValueError("tree_height is too small for all k-of-k subtrees")

        self.leaf_secret_keys = []
        self.leaf_public_keys = []
        self.used_leaves = set()

        for _ in range(self.num_leaves):
            sk, pk = self.generate_lamport_keypair()
            self.leaf_secret_keys.append(sk)
            self.leaf_public_keys.append(pk)

        leaf_hashes = []
        for pk in self.leaf_public_keys:
            leaf_hashes.append(pk.leaf_hash(self))

        self.merkle_levels = self.build_merkle_tree(leaf_hashes)
        self.assign_leaves_to_subsets()
        self.build_helper_strings()
        self.build_crv_entries()

        self.public_bundle = PublicKeyBundle(
            merkle_root=self.get_merkle_root(),
            max_signatures=self.num_leaves,
            hash_name=self.hash_name,
            leaves=self.num_leaves,
        )

    def build_helper_strings(self):
        self.helper_strings = {}
        self.party_prf_seeds = {pid: self.randbytes(32) for pid in range(self.parties)}

        for pid in range(self.parties):
            self.helper_strings[pid] = {}
            for leaf_index in range(self.num_leaves):
                self.helper_strings[pid][leaf_index] = self.randbytes(16)

    def prf_expand(self, label, seed, *parts, out_len=None):
        if out_len is None:
            out_len = self.digest_size

        self.current_sessions[(party_id, leaf_index)] = {
            "message": message,
            "session_id": session_id,
        }

    def prf_r_share(self, party_id, leaf_index):
        seed = self.party_prf_seeds[party_id]
        helper = self.helper_strings[party_id][leaf_index]
        return self.prf_expand(
            b"PRFR",
            seed,
            helper,
            leaf_index.to_bytes(4, "big"),
            out_len=self.digest_size,
        )
    
    def combine_round1_responses(self, session, round1_responses):
        leaf_index = session["leaf_index"]
        signer_ids = session["signer_ids"]

        if len(round1_responses) != len(signer_ids):
            raise ValueError("missing round1 responses")

        response_parties = sorted(resp.party_id for resp in round1_responses)
        if response_parties != sorted(signer_ids):
            raise ValueError("round1 signer set mismatch")

        for resp in round1_responses:
            if resp.leaf_index != leaf_index:
                raise ValueError("round1 response leaf index mismatch")

        crv_entry = self.crv[leaf_index]

    def prf_chk_mask(self, party_id, leaf_index):
        seed = self.party_prf_seeds[party_id]
        helper = self.helper_strings[party_id][leaf_index]
        return self.prf_expand(
            b"PRFChk",
            seed,
            helper,
            leaf_index.to_bytes(4, "big"),
            out_len=self.digest_size,
        )

    def prf_auth_value(self, party_id, leaf_index, randomizer_R):
        seed = self.party_prf_seeds[party_id]
        return self.prf_expand(
            b"PRFAuth",
            seed,
            leaf_index.to_bytes(4, "big"),
            randomizer_R,
            out_len=self.digest_size,
        )
    
    def assemble_signature(self, session, randomizer, round2_responses):
        message = session["message"]
        leaf_index = session["leaf_index"]
        signer_ids = session["signer_ids"]

        if leaf_index in self.used_leaves:
            raise RuntimeError("leaf already used; one-time key reuse is forbidden")

        if len(round2_responses) != len(signer_ids):
            raise ValueError("missing round2 responses")

        response_parties = sorted(resp.party_id for resp in round2_responses)
        if response_parties != sorted(signer_ids):
            raise ValueError("round2 signer set mismatch")

        for resp in round2_responses:
            if resp.leaf_index != leaf_index:
                raise ValueError("round2 response leaf index mismatch")

        crv_entry = self.crv[leaf_index]

        bits = self.randomized_message_bits(leaf_index, randomizer, message)

        revealed = []
        for bit_index, bit in enumerate(bits):
            parts = [crv_entry.SK[bit_index][bit]]
            for resp in round2_responses:
                parts.append(resp.sk_shares[bit_index])
            revealed.append(self.xor_bytes(parts))

        path_proto = self.get_auth_path(leaf_index)
        reconstructed_siblings = []
        for level_index in range(len(path_proto.siblings)):
            parts = [crv_entry.PATH[level_index]]
            for resp in round2_responses:
                parts.append(resp.path_shares[level_index])
            reconstructed_siblings.append(self.xor_bytes(parts))

    def prf_path_share(self, party_id, leaf_index, level_index):
        seed = self.party_prf_seeds[party_id]
        helper = self.helper_strings[party_id][leaf_index]
        return self.prf_expand(
            b"PRFPATH",
            seed,
            helper,
            leaf_index.to_bytes(4, "big"),
            level_index.to_bytes(4, "big"),
            out_len=self.digest_size,
        )

    def prf_sk_share(self, party_id, leaf_index, bit_index, bit_value):
        seed = self.party_prf_seeds[party_id]
        helper = self.helper_strings[party_id][leaf_index]
        return self.prf_expand(
            b"PRFChain",
            seed,
            helper,
            leaf_index.to_bytes(4, "big"),
            bit_index.to_bytes(4, "big"),
            bit_value.to_bytes(1, "big"),
            out_len=self.digest_size,
        )

    def build_crv_entries(self):
        self.crv = {}
        for leaf_index, lamport_sk in enumerate(self.leaf_secret_keys):
            subset = self.leaf_to_subset[leaf_index]
            path = self.get_auth_path(leaf_index)
            randomizer_R = self.randbytes(self.digest_size)

            r_parts = [self.prf_r_share(pid, leaf_index) for pid in subset]
            crv_r = self.xor_bytes([randomizer_R] + r_parts)

            chk_shares = {}
            for pid in subset:
                auth_value = self.prf_auth_value(pid, leaf_index, randomizer_R)
                chk_mask = self.prf_chk_mask(pid, leaf_index)
                chk_shares[pid] = self.xor_bytes([auth_value, chk_mask])

            path_shares = []
            for level_index, sibling in enumerate(path.siblings):
                parts = [self.prf_path_share(pid, leaf_index, level_index) for pid in subset]
                path_shares.append(self.xor_bytes([sibling] + parts))

            sk_shares = {}
            for bit_index in range(self.lamport_bits):
                sk_shares[bit_index] = {}
                for bit_value in (0, 1):
                    secret_value = lamport_sk[bit_value][bit_index]
                    parts = [self.prf_sk_share(pid, leaf_index, bit_index, bit_value) for pid in subset]
                    sk_shares[bit_index][bit_value] = self.xor_bytes([secret_value] + parts)

            self.crv[leaf_index] = CRVEntry(
                r_share=crv_r,
                chk_shares=chk_shares,
                path_shares=path_shares,
                sk_shares=sk_shares,
            )

    def distributed_digest(self, key_id, randomizer_R, message):
        return self.h_tag(
            b"distributed-ots-digest",
            key_id.to_bytes(4, "big"),
            randomizer_R,
            message,
        )

    def distributed_digest_bits(self, key_id, randomizer_R, message):
        return self.bytes_to_bits(self.distributed_digest(key_id, randomizer_R, message))

    def verify_distributed_lamport_signature(self, key_id, randomizer_R, message, revealed, pk):
        digest_bits = self.distributed_digest_bits(key_id, randomizer_R, message)
        if len(revealed) != self.lamport_bits:
            return False
        for i, bit in enumerate(digest_bits):
            if self.H(revealed[i]) != pk.pub[bit][i]:
                return False
        return True

    def lookup_helper_strings(self, leaf_index, signer_ids):
        subset = self.leaf_to_subset[leaf_index]
        lookup = {}
        for pid in signer_ids:
            if pid not in subset:
                raise PermissionError("party is not part of the selected subtree")
            lookup[pid] = self.helper_strings[pid][leaf_index]
        return lookup

    def build_session_id(self, message, leaf_index, signer_ids, helper_lookup):
        parts = [message, leaf_index.to_bytes(4, "big")]
        for pid in sorted(signer_ids):
            parts.append(pid.to_bytes(2, "big"))
            parts.append(helper_lookup[pid])
        return self.h_tag(b"distributed-session", *parts)

    def party_agree_session(self, party_id, message, leaf_index, signer_ids, helper_lookup):
        if party_id not in signer_ids:
            raise PermissionError("party not selected for this signing session")
        if not self.approve(party_id, message):
            raise PermissionError("party " + str(party_id) + " refused to sign")
        return self.build_session_id(message, leaf_index, signer_ids, helper_lookup)

    def create_signing_session(self, message, signer_ids, leaf_index=None):
        subset = self.normalise_subset(signer_ids)
        if leaf_index is None:
            leaf_index = self.next_unused_leaf_for_subset(subset)

        if leaf_index is None:
            raise RuntimeError("all leaves for the selected k-of-k subtree are exhausted")

        helper_lookup = self.lookup_helper_strings(leaf_index, subset)
        session_ids = [self.party_agree_session(pid, message, leaf_index, subset, helper_lookup) for pid in subset]

        if len(set(session_ids)) != 1:
            raise RuntimeError("parties did not agree on the same session id")

        return SigningSession(
            message=message,
            key_id=leaf_index,
            signer_ids=subset,
            helper_lookup=helper_lookup,
            session_id=session_ids[0],
        )

    def party_round1_response(self, party_id, session):
        key_id = session.key_id
        if party_id not in session.signer_ids:
            raise PermissionError("party not selected for this signing session")
        if not self.approve(party_id, session.message):
            raise PermissionError("party " + str(party_id) + " refused to sign")

        return Round1Response(
            party_id=party_id,
            key_id=key_id,
            r_share=self.prf_r_share(party_id, key_id),
            chk_share=self.crv[key_id].chk[party_id],
        )

    def combine_round1_responses(self, session, round1_responses):
        key_id = session.key_id
        if len(round1_responses) != len(session.signer_ids):
            raise ValueError("missing round1 responses")

        ordered_responses = sorted(round1_responses, key=lambda resp: resp.party_id)
        expected_parties = sorted(session.signer_ids)
        response_parties = [resp.party_id for resp in ordered_responses]
        if response_parties != expected_parties:
            raise ValueError("round1 signer set mismatch")

        crv_entry = self.crv[key_id]
        randomizer_R = self.xor_bytes([crv_entry.R] + [resp.r_share for resp in ordered_responses])

        chk_map = {}
        for resp in ordered_responses:
            if resp.key_id != key_id:
                raise ValueError("round1 response key_id mismatch")
            chk_value = self.xor_bytes([resp.chk_share, self.prf_chk_mask(resp.party_id, key_id)])
            expected_chk = self.prf_auth_value(resp.party_id, key_id, randomizer_R)
            if chk_value != expected_chk:
                raise RuntimeError("round1 CHK validation failed")
            chk_map[resp.party_id] = chk_value

        return randomizer_R, chk_map

    def run_round1(self, session):
        responses = [self.party_round1_response(pid, session) for pid in session.signer_ids]
        randomizer_R, chk_map = self.combine_round1_responses(session, responses)
        session.randomizer_R = randomizer_R
        session.chk_map = chk_map
        return {
            "responses": responses,
            "R": randomizer_R,
            "chk_map": chk_map,
        }

    def party_round2_response(self, party_id, session, randomizer_R, chk_value=None):
        if party_id not in session.signer_ids:
            raise PermissionError("party not selected for this signing session")

        recomputed_sid = self.party_agree_session(
            party_id,
            session.message,
            session.key_id,
            session.signer_ids,
            session.helper_lookup,
        )
        if recomputed_sid != session.session_id:
            raise RuntimeError("session id mismatch during round 2")

        if chk_value is None:
            if not hasattr(session, "chk_map") or party_id not in session.chk_map:
                raise RuntimeError("missing round1 CHK value for round 2")
            chk_value = session.chk_map[party_id]

        expected_chk = self.prf_auth_value(party_id, session.key_id, randomizer_R)
        if chk_value != expected_chk:
            raise RuntimeError("round2 CHK validation failed")

        bits = self.distributed_digest_bits(session.key_id, randomizer_R, session.message)
        sk_shares = []
        for bit_index, bit in enumerate(bits):
            sk_shares.append(self.prf_sk_share(party_id, session.key_id, bit_index, bit))

        path_proto = self.get_auth_path(session.key_id)
        path_shares = []
        for level_index in range(len(path_proto.siblings)):
            path_shares.append(self.prf_path_share(party_id, session.key_id, level_index))

        return Round2Response(
            party_id=party_id,
            key_id=session.key_id,
            selected_shares=sk_shares,
            auth_path=path_proto,
            path_shares=path_shares,
        )

    def assemble_signature(self, session, randomizer_R, round2_responses):
        key_id = session.key_id
        if key_id in self.used_leaves:
            raise RuntimeError("leaf already used; one-time key reuse is forbidden")
        if len(round2_responses) != len(session.signer_ids):
            raise ValueError("missing round2 responses")

        ordered_responses = sorted(round2_responses, key=lambda resp: resp.party_id)
        expected_parties = sorted(session.signer_ids)
        response_parties = [resp.party_id for resp in ordered_responses]
        if response_parties != expected_parties:
            raise ValueError("round2 signer set mismatch")

        crv_entry = self.crv[key_id]
        bits = self.distributed_digest_bits(key_id, randomizer_R, session.message)

        revealed = []
        for bit_index, bit in enumerate(bits):
            parts = [crv_entry.SK[bit_index][bit]]
            for resp in ordered_responses:
                if resp.key_id != key_id:
                    raise ValueError("round2 response key_id mismatch")
                if len(resp.sk_shares) != self.lamport_bits:
                    raise ValueError("invalid round2 share count")
                parts.append(resp.sk_shares[bit_index])
            revealed.append(self.xor_bytes(parts))

        path_proto = self.get_auth_path(key_id)
        reconstructed_siblings = []
        for level_index in range(len(path_proto.siblings)):
            parts = [crv_entry.PATH[level_index]]
            for resp in ordered_responses:
                if len(resp.path_shares) != len(path_proto.siblings):
                    raise ValueError("invalid round2 path share count")
                parts.append(resp.path_shares[level_index])
            reconstructed_siblings.append(self.xor_bytes(parts))

        reconstructed_path = MerklePath(
            siblings=reconstructed_siblings,
            directions=path_proto.directions,
        )

        self.used_leaves.add(key_id)

        return ThresholdSignature(
            key_id=key_id,
            message=session.message,
            randomizer_R=randomizer_R,
            revealed=revealed,
            lamport_public_key=self.leaf_public_keys[key_id],
            auth_path=reconstructed_path,
            signer_ids=session.signer_ids,
        )

    def sign_with_session(self, session):
        message = session.message
        key_id = session.key_id
        signer_ids = session.signer_ids
        helper_lookup = session.helper_lookup
        session_id = session.session_id

        if key_id in self.used_leaves:
            raise RuntimeError("leaf already used; one-time key reuse is forbidden")

        for pid in signer_ids:
            recomputed_sid = self.party_agree_session(pid, message, key_id, signer_ids, helper_lookup)
            if recomputed_sid != session_id:
                raise RuntimeError("session id mismatch during signing")

        round1 = self.run_round1(session)
        randomizer_R = round1["R"]
        round2_responses = []
        for pid in signer_ids:
            round2_responses.append(
                self.party_round2_response(pid, session, randomizer_R, round1["chk_map"][pid])
            )

        return self.assemble_signature(session, randomizer_R, round2_responses)

    def sign(self, message, leaf_index=None, signer_ids=None):
        session = self.create_signing_session(
            message=message,
            signer_ids=signer_ids,
            leaf_index=leaf_index,
        )
        return self.sign_with_session(session)

    def verify(self, signature, message=None, public_bundle=None):
        message = signature.message if message is None else message
        public_bundle = self.public_bundle if public_bundle is None else public_bundle
        lamport_ok = self.verify_distributed_lamport_signature(
            signature.key_id,
            signature.randomizer_R,
            message,
            signature.revealed,
            signature.lamport_public_key,
        )

        if not lamport_ok:
            return False

        return self.verify_merkle_path(
            signature.lamport_public_key.leaf_hash(self),
            signature.auth_path,
            public_bundle.merkle_root,
        )

    def benchmark(self, rounds):
        setup_times = []
        sign_times = []
        verify_times = []
        signer_ids = list(range(self.threshold_k))

        for i in range(rounds):
            message = ("benchmark-message-" + str(i)).encode()

            t0 = time.perf_counter()
            scheme = DistributedThresholdHBSScheme(self.parties, self.threshold_k, self.tree_height,)
            t1 = time.perf_counter()

            sig = scheme.sign(message, signer_ids=signer_ids)
            t2 = time.perf_counter()

            ok = scheme.verify(sig)
            t3 = time.perf_counter()

            if not ok:
                raise RuntimeError("benchmark produced invalid signature")

            setup_times.append(t1 - t0)
            sign_times.append(t2 - t1)
            verify_times.append(t3 - t2)

        return {
            "parties": self.parties,
            "threshold_k": self.threshold_k,
            "tree_height": self.tree_height,
            "rounds": rounds,
            "setup_time": round(statistics.mean(setup_times), 8),
            "sign_time": round(statistics.mean(sign_times), 8),
            "verify_time": round(statistics.mean(verify_times), 8),
        }



# Extension 3: batched signing
# use Merkle trees on buffered messages and sign the batch root once
# built on the distributed two-round scheme
class BatchedThresholdHBSScheme(DistributedThresholdHBSScheme):
    def batch_message_leaf(self, message):
        return self.h_tag(b"batch_message", message)

    def build_batch_tree(self, messages):
        if not messages:
            raise ValueError("messages must be a non-empty list")

        leaves = [self.batch_message_leaf(m) for m in messages]

        n = 1
        while n < len(leaves):
            n *= 2

        while len(leaves) < n:
            leaves.append(self.h_tag(b"batch-pad", len(leaves).to_bytes(4, "big")))

        return self.build_merkle_tree(leaves)

    def get_batch_auth_path(self, levels, leaf_index):
        idx = leaf_index
        siblings = []
        directions = []

        for level in levels[:-1]:
            if idx % 2 == 0:
                sibling_index = idx + 1
                directions.append(0)
            else:
                sibling_index = idx - 1
                directions.append(1)

            siblings.append(level[sibling_index])
            idx //= 2

        return MerklePath(siblings, directions)

    def sign_batch(self, messages, signer_ids=None, leaf_index=None):
        levels = self.build_batch_tree(messages)
        batch_root = levels[-1][0]

        root_signature = self.sign(
            batch_root,
            leaf_index=leaf_index,
            signer_ids=signer_ids,
        )

        batch_paths = [self.get_batch_auth_path(levels, i) for i in range(len(messages))]
        return BatchThresholdSignature(root_signature, messages, batch_paths, batch_root)

    def verify_batch(self, batch_signature, public_bundle=None):
        results = []
        public_bundle = self.public_bundle if public_bundle is None else public_bundle

        root_ok = self.verify(
            batch_signature.batch_root_signature,
            message=batch_signature.batch_root,
            public_bundle=public_bundle,
        )

        for message, path in zip(batch_signature.messages, batch_signature.batch_paths):
            msg_leaf = self.batch_message_leaf(message)
            path_ok = self.verify_merkle_path(msg_leaf, path, batch_signature.batch_root)
            results.append(root_ok and path_ok)

        return results

    def benchmark_batch(self, rounds, batch_size):
        setup_times = []
        batch_sign_times = []
        verify_times = []
        signer_ids = list(range(self.threshold_k))

        for i in range(rounds):
            messages = []
            for j in range(batch_size):
                messages.append(("batch-message-" + str(i) + "-" + str(j)).encode())

            t0 = time.perf_counter()
            scheme = BatchedThresholdHBSScheme(self.parties, self.threshold_k, self.tree_height)
            t1 = time.perf_counter()

            sig = scheme.sign_batch(messages=messages, signer_ids=signer_ids)
            t2 = time.perf_counter()

            verify_results = scheme.verify_batch(sig)
            t3 = time.perf_counter()

            if not all(verify_results):
                raise RuntimeError("batch benchmark produced invalid signature")

            setup_times.append(t1 - t0)
            batch_sign_times.append(t2 - t1)
            verify_times.append(t3 - t2)

        return {
            "parties": self.parties,
            "threshold_k": self.threshold_k,
            "tree_height": self.tree_height,
            "rounds": rounds,
            "batch_size": batch_size,
            "setup_time": round(statistics.mean(setup_times), 8),
            "batch_sign_time": round(statistics.mean(batch_sign_times), 8),
            "verify_time": round(statistics.mean(verify_times), 8),
            "avg_sign_time_per_message": round(statistics.mean(batch_sign_times) / batch_size, 8),
        }
    
# Extension 4: 
# use hierarchical Merkle trees on top of the distributed batched threshold scheme
# leaf signing still uses the underlying Lamport/distributed signing flow
class HierarchicalBatchedThresholdHBSScheme(BatchedThresholdHBSScheme):
    def __init__(self, parties, threshold_k, tree_height, subtree_height=2, approval_policies=None):
        if subtree_height < 1:
            raise ValueError("subtree_height must be at least 1")
        if subtree_height > tree_height:
            raise ValueError("subtree_height cannot be larger than tree_height")
        
        self.subtree_height = subtree_height
        self.subtree_size = 2 ** subtree_height
        
        super().__init__(parties, threshold_k, tree_height, approval_policies)
        self.build_hierarchical_views()

    def build_hierarchical_views(self):
        self.subtree_roots = []
        self.upper_levels = []
        total_subtrees = self.num_leaves // self.subtree_size
        for subtree_index in range(total_subtrees):
            start = subtree_index * self.subtree_size
            end = start + self.subtree_size
            subtree_leaf_hashes = [self.leaf_public_keys[i].leaf_hash(self) for i in range(start, end)]
            subtree_levels = self.build_merkle_tree(subtree_leaf_hashes)
            self.subtree_roots.append(subtree_levels[-1][0])
        self.upper_levels = self.build_merkle_tree(self.subtree_roots)
    
    def get_subtree_index(self, leaf_index):
        if leaf_index < 0 or leaf_index >= self.num_leaves:
            raise IndexError("leaf index out of range")
        return leaf_index // self.subtree_size
    
    def get_subtree_leaf_range(self, subtree_index):
        start_leaf = subtree_index * self.subtree_size
        end_leaf = start_leaf + self.subtree_size - 1
        return start_leaf, end_leaf
    
    def next_unused_leaf_in_subtree(self, subtree_index, subset=None):
        start_leaf, end_leaf = self.get_subtree_leaf_range(subtree_index)

        for leaf_index in range(start_leaf, end_leaf + 1):
            if subset is not None and self.leaf_to_subset[leaf_index] != subset:
                continue
            if leaf_index not in self.used_leaves:
                return leaf_index
            
        return None
    
    def get_hierarchical_auth_path(self, leaf_index):
        subtree_index = self.get_subtree_index(leaf_index)
        start_leaf, _ = self.get_subtree_leaf_range(subtree_index)
        local_index = leaf_index - start_leaf

        subtree_leaf_hashes = [self.leaf_public_keys[i].leaf_hash(self) for i in range(start_leaf, start_leaf + self.subtree_size)]
        local_levels = self.build_merkle_tree(subtree_leaf_hashes)
        local_path = self.get_batch_auth_path(local_levels, local_index)
        upper_path = self.get_batch_auth_path(self.upper_levels, subtree_index)
        return HierarchicalMerklePath(local_path, upper_path, subtree_index)
    
    def verify_hierarchical_path(self, leaf_hash, auth_path, expected_root):
        subtree_root_ok = self.verify_merkle_path(leaf_hash, auth_path.local_path, self.subtree_roots[auth_path.subtree_index])
        if not subtree_root_ok:
            return False
        return self.verify_merkle_path(self.subtree_roots[auth_path.subtree_index], auth_path.upper_path, expected_root)
    
    def sign(self, message, leaf_index=None, signer_ids=None):
        sig = super().sign(message, leaf_index=leaf_index, signer_ids=signer_ids)
        sig.auth_path = self.get_hierarchical_auth_path(sig.leaf_index)
        return sig
    
    def verify(self, signature, message=None, public_bundle=None):
        message = signature.message if message is None else message
        public_bundle = self.public_bundle if public_bundle is None else public_bundle
        if signature.randomizer_R:
            ots_ok = self.verify_randomized_lamport_signature(
                signature.key_id,
                signature.randomizer_R,
                message,
                signature.revealed,
                signature.lamport_public_key,
            )
        else:
            ots_ok = self.verify_lamport_signature(message, signature.revealed, signature.lamport_public_key)
        if not ots_ok:
            return False
        leaf_hash = signature.lamport_public_key.leaf_hash(self)
        if isinstance(signature.auth_path, HierarchicalMerklePath):
            return self.verify_hierarchical_path(leaf_hash, signature.auth_path, public_bundle.merkle_root)
        return self.verify_merkle_path(leaf_hash, signature.auth_path, public_bundle.merkle_root)
    
    def sign_batch_in_subtree(self, messages, signer_ids=None, subtree_index=None):
        subset = self.normalise_subset(signer_ids)

        if subtree_index is None:
            for candidate in range(self.num_leaves // self.subtree_size):
                if self.next_unused_leaf_in_subtree(candidate, subset=subset) is not None:
                    subtree_index = candidate
                    break

        if subtree_index is None:
            raise RuntimeError("no subtree with available leaves")

        leaf_index = self.next_unused_leaf_in_subtree(subtree_index, subset=subset)
        if leaf_index is None:
            raise RuntimeError("selected subtree has no compatible unused leaf")

        batch_sig = self.sign_batch(
            messages,
            signer_ids=list(subset),
            leaf_index=leaf_index,
        )

        return {
            "subtree_index": subtree_index,
            "subtree_leaf_range": self.get_subtree_leaf_range(subtree_index),
            "used_leaf_indices": [leaf_index],
            "batch_signature": batch_sig,
        }
    
    def verify_subtree_batch(self, batch_result):
        return self.verify_batch(batch_result["batch_signature"])
    
    def benchmark_hierarchical_batch(self, rounds, batch_size):
        setup_times = []
        batch_sign_times = []
        verify_times = []
        signer_ids = list(range(self.threshold_k))

        for i in range(rounds):
            messages = []
            for j in range(batch_size):
                messages.append(("hierarchical-batch-message-" + str(i) + "-" + str(j)).encode())

            t0 = time.perf_counter()
            scheme = HierarchicalBatchedThresholdHBSScheme(
                self.parties,
                self.threshold_k,
                self.tree_height,
                self.subtree_height,
            )
            t1 = time.perf_counter()

            batch_result = scheme.sign_batch_in_subtree(messages, signer_ids=signer_ids)
            t2 = time.perf_counter()

            verify_results = scheme.verify_subtree_batch(batch_result)
            t3 = time.perf_counter()

            if not all(verify_results):
                raise RuntimeError("hierarchical batch benchmark produced invalid signature")

            setup_times.append(t1 - t0)
            batch_sign_times.append(t2 - t1)
            verify_times.append(t3 - t2)

        return {
            "parties": self.parties,
            "threshold_k": self.threshold_k,
            "tree_height": self.tree_height,
            "subtree_height": self.subtree_height,
            "rounds": rounds,
            "batch_size": batch_size,
            "setup_time": round(statistics.mean(setup_times), 8),
            "hierarchical_batch_sign_time": round(statistics.mean(batch_sign_times), 8),
            "verify_time": round(statistics.mean(verify_times), 8),
            "avg_sign_time_per_message": round(statistics.mean(batch_sign_times) / batch_size, 8),
        }
    
# Extension 5:
# add support for Winternitz while reusing the distributed two-round signing flow
class WinternitzPublicKey:
    def __init__(self, pub):
        self.pub = pub

    def leaf_hash(self, scheme):
        return scheme.h_tag(b"winternitz-leaf", *self.pub)
    
class WinternitzThresholdSignature:
    def __init__(self, leaf_index=None, message=None, revealed=None, public_key=None, auth_path=None, key_id=None, randomizer_R=None, signer_ids=None):
        if key_id is None:
            key_id = leaf_index
        if key_id is None:
            raise ValueError("key_id or leaf_index must be provided")
        self.key_id = key_id
        self.leaf_index = key_id
        self.message = message
        self.randomizer = b"" if randomizer is None else randomizer
        self.revealed = revealed
        self.public_key = public_key
        self.auth_path = auth_path
        self.randomizer_R = b"" if randomizer_R is None else randomizer_R
        self.signer_ids = [] if signer_ids is None else signer_ids


class WinternitzThresholdHBSScheme(DistributedThresholdHBSScheme):
    def __init__(self, parties, threshold_k, tree_height, w=16, approval_policies=None):
        if w < 2:
            raise ValueError("w must be at least 2")

        self.w = w
        self.log_w = self.compute_log_w(w)

        if self.log_w is None:
            raise ValueError("this implementation supports w as a power of two")
        
        self.len1 = (256 + self.log_w - 1) // self.log_w
        self.len2 = self.compute_len2(self.len1, w)
        self.num_chains = self.len1 + self.len2
        
        super().__init__(parties, threshold_k, tree_height, approval_policies)

    def compute_log_w(self, w):
        value = w
        power = 0

        while value > 1:
            if value % 2 != 0:
                return None
            value = value // 2
            power += 1

        return power
    
    def compute_len2(self, len1, w):
        max_checksum = len1 * (w - 1)
        length = 0
        value = 1

        while value <= max_checksum:
            value *= w
            length += 1

        return length
    
    def hash_iter(self, data, count):
        out = data
        for _ in range(count):
            out = self.H(out)
        return out
    
    def bytes_to_base_w(self, data, out_len):
        digits = []
        bit_buffer = 0
        bit_count = 0
        mask = self.w - 1

        for b in data:
            bit_buffer = (bit_buffer << 8) | b
            bit_count += 8

            while bit_count >= self.log_w and len(digits) < out_len:
                shift = bit_count - self.log_w
                digit = (bit_buffer >> shift) & mask
                digits.append(digit)

                bit_buffer = bit_buffer & ((1 << shift) - 1)
                bit_count -= self.log_w

        while len(digits) < out_len:
            if bit_count > 0:
                digit = (bit_buffer << (self.log_w - bit_count)) & mask
                digits.append(digit)
                bit_buffer = 0
                bit_count = 0
            else:
                digits.append(0)

        return digits
    
    def int_to_base_w(self, value, out_len):
        digits = [0] * out_len
        
        for i in range(out_len - 1, -1, -1):
            digits[i] = value % self.w
            value = value // self.w

        return digits
    
    def winternitz_message_digits_from_digest(self, digest):
        msg_digits = self.bytes_to_base_w(digest, self.len1)

        checksum = 0
        for d in msg_digits:
            checksum += (self.w - 1 - d)

        checksum_digits = self.int_to_base_w(checksum, self.len2)
        return msg_digits + checksum_digits

    def randomized_message_digits_with_checksum(self, leaf_index, randomizer, message):
        digest = self.randomized_message_digest(leaf_index, randomizer, message)
        return self.winternitz_message_digits_from_digest(digest)

    def randomized_message_digits_with_checksum(self, key_id, randomizer_R, message):
        digest = self.randomized_digest(key_id, randomizer_R, message)
        return self.winternitz_message_digits_from_digest(digest)
    
    def generate_winternitz_keypair(self):
        sk = []
        pk = []

        for _ in range(self.num_chains):
            x = self.randbytes(self.digest_size)
            sk.append(x)
            pk.append(self.hash_iter(x, self.w -1))

        return sk, WinternitzPublicKey(pk)
    
    def dealer_setup(self):
        subset_count = len(self.subset_parties)
        if self.num_leaves < subset_count:
            raise ValueError("tree_height is too small for all k-of-k subtrees")
        self.leaf_secret_keys = []
        self.leaf_public_keys = []
        self.used_leaves = set()

        for _ in range(self.num_leaves):
            sk, pk = self.generate_winternitz_keypair()
            self.leaf_secret_keys.append(sk)
            self.leaf_public_keys.append(pk)

        leaf_hashes = []
        for pk in self.leaf_public_keys:
            leaf_hashes.append(pk.leaf_hash(self))

        self.merkle_levels = self.build_merkle_tree(leaf_hashes)
        self.assign_leaves_to_subsets()
        self.build_helper_strings()
        self.build_crv_entries()

        self.public_bundle = PublicKeyBundle(
            merkle_root=self.get_merkle_root(),
            max_signatures=self.num_leaves,
            hash_name=self.hash_name,
            leaves=self.num_leaves,
        )

    def winternitz_prf_share(self, party_id, leaf_index, chain_index):
        seed = self.party_prf_seeds[party_id]
        helper = self.helper_strings[party_id][leaf_index]
        return self.prf_expand(
            b"PRFWOTS",
            seed,
            helper,
            leaf_index.to_bytes(4, "big"),
            chain_index.to_bytes(4, "big"),
            out_len=self.digest_size,
        )

    def build_crv_entries(self):
        self.crv = {}

        for leaf_index, winternitz_sk in enumerate(self.leaf_secret_keys):
            subset = self.leaf_to_subset[leaf_index]
            path = self.get_auth_path(leaf_index)
            randomizer = self.randbytes(self.digest_size)

            # CRV.R
            r_parts = [self.prf_r_share(pid, leaf_index) for pid in subset]
            crv_r = self.xor_bytes([randomizer] + r_parts)

            # CRV.chk
            chk_shares = {}
            for pid in subset:
                auth_value = self.prf_auth_value(pid, leaf_index, randomizer)
                chk_mask = self.prf_chk_mask(pid, leaf_index)
                chk_shares[pid] = self.xor_bytes([auth_value, chk_mask])

            # CRV.PATH
            path_shares = []
            for level_index, sibling in enumerate(path.siblings):
                parts = [self.prf_path_share(pid, leaf_index, level_index) for pid in subset]
                path_shares.append(self.xor_bytes([sibling] + parts))

            # CRV.SK for Winternitz chains
            sk_shares = {}
            for chain_index in range(self.num_chains):
                secret_value = winternitz_sk[chain_index]
                base_party_shares = [
                    self.winternitz_prf_share(pid, leaf_index, chain_index)
                    for pid in subset
                ]

                sk_shares[chain_index] = {}

                for digit in range(self.w):
                    z_secret = self.hash_iter(secret_value, digit)
                    z_party_parts = [self.hash_iter(share, digit) for share in base_party_shares]

                    sk_shares[chain_index][digit] = self.xor_bytes(
                        [z_secret] + z_party_parts
                    )

            self.crv[leaf_index] = CRVEntry(
                r_share=crv_r,
                chk_shares=chk_shares,
                path_shares=path_shares,
                sk_shares=sk_shares,
            )

    def party_round2_response(self, party_id, session, randomizer, chk_value):
        leaf_index = session["leaf_index"]
        session_id = session["session_id"]

        key = (party_id, leaf_index)
        if key not in self.current_sessions:
            raise RuntimeError("missing round1 session state")

        state = self.current_sessions[key]

        if state["session_id"] != session_id:
            raise RuntimeError("session id mismatch in round2")

        message = state["message"]

        expected_auth = self.prf_auth_value(party_id, leaf_index, randomizer)
        if expected_auth != chk_value:
            raise PermissionError("randomizer authentication failed")

        digits = self.randomized_message_digits_with_checksum(leaf_index, randomizer, message)

        z_shares = []
        for chain_index in range(self.num_chains):
            share = self.winternitz_prf_share(party_id, leaf_index, chain_index)
            z_shares.append(self.hash_iter(share, digits[chain_index]))

        path_proto = self.get_auth_path(leaf_index)
        path_shares = []
        for level_index in range(len(path_proto.siblings)):
            path_shares.append(self.prf_path_share(party_id, leaf_index, level_index))

        del self.current_sessions[key]

        return Round2Response(
            party_id=party_id,
            leaf_index=leaf_index,
            z_shares=z_shares,
            path_shares=path_shares,
        )

    def assemble_signature(self, session, randomizer, round2_responses):
        message = session["message"]
        leaf_index = session["leaf_index"]
        signer_ids = session["signer_ids"]

        path_proto = self.get_auth_path(session.key_id)
        path_shares = []
        for level_index in range(len(path_proto.siblings)):
            path_shares.append(self.prf_path_share(party_id, session.key_id, level_index))

        if len(round2_responses) != len(signer_ids):
            raise ValueError("missing round2 responses")

        sorted_signers = sorted(signer_ids)
        response_parties = sorted(resp.party_id for resp in round2_responses)
        if response_parties != sorted_signers:
            raise ValueError("round2 signer set mismatch")

        crv_entry = self.crv[leaf_index]
        digits = self.randomized_message_digits_with_checksum(leaf_index, randomizer, message)

        ordered_responses = sorted(round2_responses, key=lambda resp: resp.party_id)
        expected_parties = sorted(session.signer_ids)
        response_parties = [resp.party_id for resp in ordered_responses]
        if response_parties != expected_parties:
            raise ValueError("round2 signer set mismatch")

        crv_entry = self.crv[key_id]
        digits = self.randomized_message_digits_with_checksum(key_id, randomizer_R, session.message)
        revealed = []
        for chain_index in range(self.num_chains):
            digit = digits[chain_index]

            # paper-style correction at the signature-share level
            z_crv = crv_entry.SK[chain_index][digit]

            z_parts = [z_crv]
            for resp in round2_responses:
                if resp.leaf_index != leaf_index:
                    raise ValueError("round2 response leaf index mismatch")
                if len(resp.z_shares) != self.num_chains:
                    raise ValueError("invalid round2 share count")
                z_parts.append(resp.z_shares[chain_index])

            revealed.append(self.xor_bytes(z_parts))

        path_proto = self.get_auth_path(leaf_index)
        reconstructed_siblings = []
        for level_index in range(len(path_proto.siblings)):
            parts = [crv_entry.PATH[level_index]]
            for resp in round2_responses:
                if len(resp.path_shares) != len(path_proto.siblings):
                    raise ValueError("invalid round2 path share count")
                parts.append(resp.path_shares[level_index])

            reconstructed_siblings.append(self.xor_bytes(parts))

        reconstructed_path = MerklePath(
            siblings=reconstructed_siblings,
            directions=path_proto.directions,
        )

        reconstructed_path = MerklePath(
            siblings=reconstructed_siblings,
            directions=path_proto.directions,
        )

        self.used_leaves.add(key_id)

        return WinternitzThresholdSignature(
            key_id=key_id,
            message=session.message,
            randomizer_R=randomizer_R,
            revealed=revealed,
            public_key=self.leaf_public_keys[leaf_index],
            auth_path=reconstructed_path,
            signer_ids=signer_ids,
        )

    def sign(self, message, leaf_index=None, active_party_ids=None, signer_ids=None):
        if signer_ids is None:
            signer_ids = active_party_ids
        session = self.create_signing_session(
            message=message,
            signer_ids=signer_ids,
            leaf_index=leaf_index,
        )
        return self.sign_with_session(session)

    def verify_winternitz_signature(self, leaf_index, randomizer, message, revealed, public_key):
        if len(revealed) != self.num_chains:
            return False

        digits = self.randomized_message_digits_with_checksum(leaf_index, randomizer, message)

        for i in range(self.num_chains):
            if self.hash_iter(revealed[i], self.w - 1 - digits[i]) != public_key.pub[i]:
                return False
            
        return True
    
    def verify(self, signature, message=None, public_bundle=None):
        message = signature.message if message is None else message
        public_bundle = self.public_bundle if public_bundle is None else public_bundle

        ots_ok = self.verify_winternitz_signature(
            signature.leaf_index,
            signature.randomizer,
            message,
            signature.revealed,
            signature.public_key,
        )

        if not ots_ok:
            return False
        
        return self.verify_merkle_path(signature.public_key.leaf_hash(self), signature.auth_path, public_bundle.merkle_root,)
    
    def benchmark(self, rounds):
        setup_times = []
        sign_times = []
        verify_times = []
        signer_ids = list(range(self.threshold_k))

        for i in range(rounds):
            message = ("benchmark-message-" + str(i)).encode()

            t0 = time.perf_counter()
            scheme = WinternitzThresholdHBSScheme(self.parties, self.threshold_k, self.tree_height, self.w,)
            t1 = time.perf_counter()

            sig = scheme.sign(message, active_party_ids=signer_ids)
            t2 = time.perf_counter()

            ok = scheme.verify(sig)
            t3 = time.perf_counter()

            if not ok:
                raise RuntimeError("Winternitz benchmark produced invalid signature")
            
            setup_times.append(t1 - t0)
            sign_times.append(t2 - t1)
            verify_times.append(t3 - t2)

        return {
            "parties":self.parties, 
            "threshold_k": self.threshold_k, 
            "tree_height": self.tree_height,
            "w": self.w, 
            "rounds": rounds, 
            "setup_time": round(statistics.mean(setup_times), 8),
            "sign_time": round(statistics.mean(sign_times), 8),
            "verify_time": round(statistics.mean(verify_times), 8),
        }



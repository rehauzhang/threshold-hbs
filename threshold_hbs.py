import hashlib
import secrets
import statistics
import time

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

class ThresholdSignature:
    def __init__(self, leaf_index, message, revealed, lamport_public_key, auth_path):
        self.leaf_index = leaf_index
        self.message = message
        self.revealed = revealed
        self.lamport_public_key = lamport_public_key
        self.auth_path = auth_path

class ShareResponse:
    def __init__(self, party_id, leaf_index, selected_shares):
        self.party_id = party_id
        self.leaf_index = leaf_index
        self.selected_shares = selected_shares

class PublicKeyBundle:
    def __init__(self, merkle_root, max_signatures, hash_name, leaves):
        self.merkle_root = merkle_root
        self.max_signatures = max_signatures
        self.hash_name = hash_name
        self.leaves = leaves

class BenchmarkResult:
    def __init__(self, parties, tree_height, rounds, setup_avg, sign_avg, verify_avg):
        self.parties = parties
        self.tree_height = tree_height
        self.rounds = rounds
        self.setup_avg = setup_avg
        self.sign_avg = sign_avg
        self.verify_avg = verify_avg

    def to_dict(self):
        return {
            "parties": self.parties,
            "tree_height": self.tree_height,
            "rounds": self.rounds,
            "setup_time": round(self.setup_avg, 8),
            "sign_time": round(self.sign_avg, 8),
            "verify_time": round(self.verify_avg, 8),
        }
    
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
            approval_policies = []
            for i in range(parties):
                approval_policies.append(lambda message: True)

        if len(approval_policies) != parties:
            raise ValueError("approval_policies must have one entry for each party")
        
        self.approval_policies = approval_policies

        self.leaf_secret_keys = []
        self.leaf_public_keys = []

        self.party_shares = {}
        for pid in range(self.parties):
            self.party_shares[pid] = {}

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
        if len(parts) == 0:
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
        for i in range(self.num_leaves):
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
            for i in range(self.lamport_bits):
                x = self.randbytes(self.digest_size)
                secrets_2d[branch].append(x)
                pub_2d[branch].append(self.H(x))

        return secrets_2d, LamportPublicKey(pub_2d)
    
    def lamport_select_secret_elements(self, lamport_sk, message):
        digest_bits = self.bytes_to_bits(self.H(message))
        revealed = []

        for i in range(len(digest_bits)):
            bit = digest_bits[i]
            revealed.append(lamport_sk[bit][i])

        return revealed
    
    def verify_lamport_signature(self, message, revealed, pk):
        digest_bits = self.bytes_to_bits(self.H(message))

        if len(revealed) != self.lamport_bits:
            return False
        
        for i in range(len(digest_bits)):
            bit = digest_bits[i]
            if self.H(revealed[i]) != pk.pub[bit][i]:
                return False
            
        return True
    
    def xor_share(self, secret, n):
        if n < 2:
            raise ValueError("n must be at least 2")
        
        shares = []
        for i in range(n - 1):
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
        
        levels = [leaves]
        current = leaves

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

        for i in range(len(path.siblings)):
            sibling = path.siblings[i]
            direction = path.directions[i]

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
    
    def verify(self, signature):
        lamport_ok = self.verify_lamport_signature(signature.message, signature.revealed, signature.lamport_public_key,)

        if not lamport_ok:
            return False
        
        return self.verify_merkle_path(signature.lamport_public_key.leaf_hash(self), signature.auth_path, self.public_bundle.merkle_root,)
    
    def dealer_direct_sign_for_testing(self, message, leaf_index):
        if leaf_index < 0 or leaf_index >= self.num_leaves:
            raise IndexError("leaf index out of range")
        
        return self.lamport_select_secret_elements(self.leaf_secret_keys[leaf_index], message)
    
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

        return BenchmarkResult(parties=self.parties, tree_height=self.tree_height, rounds=rounds, setup_avg=statistics.mean(setup_times), sign_avg=statistics.mean(sign_times), verify_avg=statistics.mean(verify_times),)

# Extension 1: k-of-n threshold signing 
# Shamir sharing helpers over GF(257)       
class KOfNThresholdHBSScheme(ThresholdHBSScheme):
    def __init__(self, parties, threshold_k, tree_height, approval_policies=None):
        if threshold_k < 2:
            raise ValueError("threshold_k must be at least 2")
        if threshold_k > parties:
            raise ValueError("threshold_k cannot be larger than parties")
        
        self.threshold_k = threshold_k
        self.field_prime = 257

        super().__init__(parties, tree_height, approval_policies)

    def dealer_setup(self):
        for i in range(self.num_leaves):
            sk, pk = self.generate_lamport_keypair()
            self.leaf_secret_keys.append(sk)
            self.leaf_public_keys.append(pk)

        leaf_hashes = []
        for pk in self.leaf_public_keys:
            leaf_hashes.append(pk.leaf_hash(self))

        self.merkle_levels = self.build_merkle_tree(leaf_hashes)
        self.build_threshold_shares()

        self.public_bundle = PublicKeyBundle(merkle_root=self.get_merkle_root(), max_signatures=self.num_leaves, hash_name=self.hash_name, leaves=self.num_leaves,)

    def field_add(self, a, b):
        return (a + b) % self.field_prime
    
    def field_sub(self, a, b):
        return (a - b) % self.field_prime
    
    def field_mul(self, a, b):
        return (a * b) % self.field_prime
    
    def field_inv(self, a):
        if a % self.field_prime == 0:
            raise ZeroDivisionError("cannot invert zero in finite field")
        return pow(a, -1, self.field_prime)
    
    def eval_polynomial(self, coeffs, x):
        result = 0
        for coeff in reversed(coeffs):
            result = self.field_add(self.field_mul(result, x), coeff)
        return result
    
    def shamir_share_byte(self, secret_value, n, k):
        if secret_value < 0 or secret_value >= self.field_prime:
            raise ValueError("secret byte out of field range")
        
        coeffs = [secret_value]
        for i in range(k - 1):
            coeffs.append(secrets.randbelow(self.field_prime))

        shares = []
        for x in range(1, n + 1):
            y = self.eval_polynomial(coeffs, x)
            shares.append(y)

        return shares
    
    def shamir_share(self, secret_bytes, n, k):
        party_vectors = []
        for i in range(n):
            party_vectors.append([])

        for b in secret_bytes:
            byte_shares = self.shamir_share_byte(b, n, k)
            for party_index in range(n):
                party_vectors[party_index].append(byte_shares[party_index])

        return party_vectors
    
    def lagrange_interpolate_at_zero(self, points):
        total = 0

        for i in range(len(points)):
            xi, yi = points[i]
            numerator = 1
            denominator = 1

            for j in range(len(points)):
                if i == j:
                    continue

                xj, yj = points[j]
                numerator = self.field_mul(numerator, (-xj) % self.field_prime)
                denominator = self.field_mul(denominator, (xi - xj) % self.field_prime)

            li = self.field_mul(numerator, self.field_inv(denominator))
            total = self.field_add(total, self.field_mul(yi, li))

        return total
    
    def shamir_recombine(self, share_points):
        if len(share_points) < self.threshold_k:
            raise ValueError("not enough shares to reconstruct")
        
        share_length = len(share_points[0][1])

        for x, share_vec in share_points:
            if len(share_vec) != share_length:
                raise ValueError("inconsistent share vector length")
            
        recovered = []

        for byte_index in range(share_length):
            points_for_one_byte = []
            for x, share_vec in share_points[:self.threshold_k]:
                points_for_one_byte.append((x, share_vec[byte_index]))

            secret_value = self.lagrange_interpolate_at_zero(points_for_one_byte)

            if secret_value < 0 or secret_value > 255:
                raise ValueError("reconstructed byte out of byte range")
            
            recovered.append(secret_value)

        return bytes(recovered)
    
    def build_threshold_shares(self):
        for leaf_index in range(len(self.leaf_secret_keys)):
            lamport_sk = self.leaf_secret_keys[leaf_index]

            for pid in range(self.parties):
                self.party_shares[pid][leaf_index] = {}

            for bit_index in range(self.lamport_bits):
                shares_zero = self.shamir_share(lamport_sk[0][bit_index], self.parties, self.threshold_k,)
                shares_one = self.shamir_share(lamport_sk[1][bit_index], self.parties, self.threshold_k,)
                
                for pid in range(self.parties):
                    self.party_shares[pid][leaf_index][bit_index] = {
                        0: shares_zero[pid],
                        1: shares_one[pid],
                    }

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
    
    def sign(self, message, leaf_index=None, active_party_ids=None):
        if leaf_index is None:
            leaf_index = self.next_unused_leaf()

        if leaf_index is None:
            raise RuntimeError("all Lamport leaves are exhausted")
        if leaf_index in self.used_leaves:
            raise RuntimeError("leaf already used; one-time key reuse is forbidden")
        
        if active_party_ids is None:
            candidate_ids = []
            for pid in range(self.parties):
                candidate_ids.append(pid)
        else:
            candidate_ids = []
            for pid in active_party_ids:
                if pid < 0 or pid >= self.parties:
                    raise ValueError("invalid party id in active_party_ids")
                if pid not in candidate_ids:
                    candidate_ids.append(pid)

        share_responses = []

        for pid in candidate_ids:
            try:
                resp = self.party_produce_share(pid, leaf_index, message)
                share_responses.append(resp)
            except PermissionError:
                pass

            if len(share_responses) == self.threshold_k:
                break

        if len(share_responses) < self.threshold_k:
            raise PermissionError("fewer than k parties approved the message")
        
        bit_count = len(share_responses[0].selected_shares)

        for resp in share_responses:
            if resp.leaf_index != leaf_index:
                raise ValueError("inconsistent leaf index in responses")
            if len(resp.selected_shares) != bit_count:
                raise ValueError("inconsistent share count in responses")
            
        reconstructed_revealed = []

        for bit_index in range(bit_count):
            share_points = []
            
            for resp in share_responses:
                x_coordinate = resp.party_id + 1
                share_vector = resp.selected_shares[bit_index]
                share_points.append((x_coordinate, share_vector))

            reconstructed_revealed.append(self.shamir_recombine(share_points))

        self.used_leaves.add(leaf_index)

        return ThresholdSignature(leaf_index=leaf_index, message=message, revealed=reconstructed_revealed, lamport_public_key=self.leaf_public_keys[leaf_index], auth_path=self.get_auth_path(leaf_index),)
    
    def benchmark(self, rounds):
        setup_times = []
        sign_times = []
        verify_times = []

        for i in range(rounds):
            message = ("benchmark-message-" + str(i)).encode()

            t0 = time.perf_counter()
            scheme = KOfNThresholdHBSScheme(self.parties, self.threshold_k, self.tree_height,)
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
            "parties":self.parties, 
            "threshold_k": self.threshold_k, 
            "tree_height": self.tree_height, 
            "rounds":rounds, 
            "setup_time": round(statistics.mean(setup_times), 8),
            "sign_time": round(statistics.mean(sign_times), 8),
            "verify_time": round(statistics.mean(verify_times), 8),
        }
    
# Extension 2: distributed decision
# helper-string assisted threshold signing       
class DistributedThresholdHBSScheme(KOfNThresholdHBSScheme):
    def __init__(self, parties, threshold_k, tree_height, approval_policies=None):
        self.helper_strings = {}
        super().__init__(parties, threshold_k, tree_height, approval_policies)

    def dealer_setup(self):
        for i in range(self.num_leaves):
            sk, pk = self.generate_lamport_keypair()
            self.leaf_secret_keys.append(sk)
            self.leaf_public_keys.append(pk)

        leaf_hashes = []
        for pk in self.leaf_public_keys:
            leaf_hashes.append(pk.leaf_hash(self))

        self.merkle_levels = self.build_merkle_tree(leaf_hashes)
        self.build_threshold_shares()
        self.build_helper_strings()

        self.public_bundle = PublicKeyBundle(merkle_root=self.get_merkle_root(), max_signatures=self.num_leaves, hash_name=self.hash_name, leaves=self.num_leaves,)

    def build_helper_strings(self):
        self.helper_strings = {}

        for pid in range(self.parties):
            self.helper_strings[pid] = {}
            for leaf_index in range(self.num_leaves):
                self.helper_strings[pid][leaf_index] = self.randbytes(16)

    def lookup_helper_strings(self, leaf_index, signer_ids):
        if leaf_index < 0 or leaf_index >= self.num_leaves:
            raise IndexError("leaf index out of range")
        
        lookup = {}
        for pid in signer_ids:
            if pid < 0 or pid >= self.parties:
                raise ValueError("invalid party id")
            lookup[pid] = self.helper_strings[pid][leaf_index]

        return lookup
    
    def build_session_id(self, message, leaf_index, signer_ids, helper_lookup):
        parts = [b"distributed-session"]
        parts.append(message)
        parts.append(str(leaf_index).encode())

        signer_ids_sorted = sorted(signer_ids)
        for pid in signer_ids_sorted:
            parts.append(str(pid).encode())
            parts.append(helper_lookup[pid])

        return self.h_tag(b"session-id", *parts)
    
    def party_agree_session(self, party_id, message, leaf_index, signer_ids, helper_lookup):
        if party_id not in signer_ids:
            raise PermissionError("party not selected for this signing session")
        
        if not self.approve(party_id, message):
            raise PermissionError("party " + str(party_id) + " refused to sign")
        
        return self.build_session_id(message, leaf_index, signer_ids, helper_lookup)
    
    def create_signing_session(self, message, signer_ids, leaf_index=None):
        if leaf_index is None:
            leaf_index = self.next_unused_leaf()

        if leaf_index is None:
            raise RuntimeError("all Lamport leaves are exhausted")
        
        if leaf_index in self.used_leaves:
            raise RuntimeError("leaf already used; one-time key reuse is forbidden")
        
        if signer_ids is None:
            raise ValueError("signer_ids must be provided for distributed signing")
        
        unique_signer_ids = []
        for pid in signer_ids:
            if pid < 0 or pid >= self.parties:
                raise ValueError("invalid party id in signer_ids")
            if pid not in unique_signer_ids:
                unique_signer_ids.append(pid)

        if len(unique_signer_ids) < self.threshold_k:
            raise ValueError("fewer than k signer ids were provided")
        
        helper_lookup = self.lookup_helper_strings(leaf_index, unique_signer_ids)

        session_ids = []
        approved_signers = []

        for pid in unique_signer_ids:
            try:
                sid = self.party_agree_session(pid, message, leaf_index, unique_signer_ids, helper_lookup)
                session_ids.append(sid)
                approved_signers.append(pid)
            except PermissionError:
                pass

        if len(approved_signers) < self.threshold_k:
            raise PermissionError("fewer than k parties approved the distributed signing session")
        
        first_sid = session_ids[0]
        for sid in session_ids:
            if sid != first_sid:
                raise RuntimeError("parties did not agree on the same session id")
            
        session = {
            "message": message,
            "leaf_index": leaf_index,
            "signer_ids": approved_signers,
            "helper_lookup": helper_lookup,
            "session_id": first_sid,
        }

        return session
    
    def sign_with_session(self, session):
        message = session["message"]
        leaf_index = session["leaf_index"]
        signer_ids = session["signer_ids"]
        helper_lookup = session["helper_lookup"]
        session_id = session["session_id"]

        if leaf_index in self.used_leaves:
            raise RuntimeError("leaf already used; one-time key reuse is forbidden")
        
        share_responses = []
        
        for pid in signer_ids:
            recomputed_sid = self.party_agree_session(pid, message, leaf_index, signer_ids, helper_lookup)
            if recomputed_sid != session_id:
                raise RuntimeError("session id mismatch during signing")
            
            resp = self.party_produce_share(pid, leaf_index, message)
            share_responses.append(resp)

        if len(share_responses) < self.threshold_k:
            raise PermissionError("fewer than k valid shares collected")
        
        bit_count = len(share_responses[0].selected_shares)
        
        for resp in share_responses:
            if resp.leaf_index != leaf_index:
                raise ValueError("inconsistent leaf index in responses")
            if len(resp.selected_shares) != bit_count:
                raise ValueError("inconsistent share count in responses")
            
        reconstructed_revealed = []

        for bit_index in range(bit_count):
            share_points = []

            for resp in share_responses:
                x_coordinate = resp.party_id + 1
                share_vector = resp.selected_shares[bit_index]
                share_points.append((x_coordinate, share_vector))

            reconstructed_revealed.append(self.shamir_recombine(share_points))

        self.used_leaves.add(leaf_index)

        return ThresholdSignature(leaf_index=leaf_index, message=message, revealed=reconstructed_revealed, lamport_public_key=self.leaf_public_keys[leaf_index], auth_path=self.get_auth_path(leaf_index),)
    
    def sign(self, message, leaf_index=None, signer_ids=None):
        session = self.create_signing_session(message=message, signer_ids=signer_ids, leaf_index=leaf_index,)

        return self.sign_with_session(session)
    
    def benchmark(self, rounds):
        setup_times = []
        sign_times = []
        verify_times = []

        for i in range(rounds):
            message = ("benchmark-message-" + str(i)).encode()

            t0 = time.perf_counter()
            scheme = DistributedThresholdHBSScheme(self.parties, self.threshold_k, self.tree_height,)
            t1 = time.perf_counter()

            signer_ids = []
            for pid in range(self.threshold_k):
                signer_ids.append(pid)

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
            "parties":self.parties, 
            "threshold_k": self.threshold_k, 
            "tree_height": self.tree_height, 
            "rounds":rounds, 
            "setup_time": round(statistics.mean(setup_times), 8),
            "sign_time": round(statistics.mean(sign_times), 8),
            "verify_time": round(statistics.mean(verify_times), 8),
        }





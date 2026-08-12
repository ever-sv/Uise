"""
Append-only transparency log - spec section 10.4, RFC 6962 construction.

This is what makes an issuer trustworthy without anyone having to trust it. Two
properties come out of it, and neither can be obtained from signatures alone:

  * **Existence survives cryptographic breakage.** Merkle proofs rest only on hash
    functions. A receipt whose signature suite falls in 2040 still carries a
    verifiable proof that it existed, unmodified, at a known position in the log.
  * **Trust is replaced by verification.** Anyone can check that the issuer never
    published a contradicting receipt and never removed one. Consistency proofs
    make an undetected rewrite of history impossible, not merely punishable.

The hash prefixes below are the RFC 6962 domain separators: they stop an internal
node from ever being reinterpreted as a leaf, which would otherwise allow forging
an inclusion proof for data that was never logged.
"""

import hashlib

from uip import codec

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# SHA-384 rather than SHA-256: a log entry is meant to outlive every signature
# suite in use today, and Grover's algorithm halves effective hash security.
DEFAULT_ALGORITHM = "sha384"


def _digest(algorithm, data):
    try:
        constructor = codec.HASH_ALGORITHMS[algorithm]
    except KeyError:
        raise ValueError("unregistered hash algorithm: %r" % algorithm)
    return constructor(data).digest()


def leaf_hash(entry, algorithm=DEFAULT_ALGORITHM):
    return _digest(algorithm, LEAF_PREFIX + entry)


def node_hash(left, right, algorithm=DEFAULT_ALGORITHM):
    return _digest(algorithm, NODE_PREFIX + left + right)


def empty_root(algorithm=DEFAULT_ALGORITHM):
    return _digest(algorithm, b"")


def _largest_power_of_two_below(n):
    """The split point of RFC 6962: the largest power of two strictly below n."""
    return 1 << (n - 1).bit_length() - 1


def receipt_entry(receipt):
    """
    The bytes a receipt occupies in the log.

    `anchor` is forced to null, exactly as when signing: the log commits to the
    receipt as the parties agreed it, never to a version the log itself shaped.
    Signatures are included, so one entry proves both what was agreed and who
    agreed to it.
    """
    return codec.canonicalize(dict(receipt, anchor=None))


class MerkleLog(object):
    """
    In-memory Merkle tree over an ordered list of leaf hashes.

    Subtree hashes are memoized, so appending and proving stay cheap as the log
    grows. Durability lives in `storage`; this class is pure computation.
    """

    __slots__ = ("algorithm", "_leaves", "_subtree")

    def __init__(self, leaves=None, algorithm=DEFAULT_ALGORITHM):
        self.algorithm = algorithm
        self._leaves = list(leaves or [])
        self._subtree = {}

    def __len__(self):
        return len(self._leaves)

    def append_leaf(self, leaf):
        """
        Append an already-computed leaf hash. Returns the index it landed at.

        Separate from `append` so a caller can compute the leaf, commit it durably,
        and only then advance the in-memory tree. A tree that runs ahead of the
        database is a tree that disagrees with the evidence it is meant to prove.
        """
        self._leaves.append(leaf)
        # Only right-edge subtrees change on append; dropping their memo is both
        # correct and cheaper than tracking which ones moved.
        self._subtree = {k: v for k, v in self._subtree.items() if k[1] < len(self._leaves) - 1}
        return len(self._leaves) - 1

    def append(self, entry):
        """Append raw entry bytes. Returns the index it was written at."""
        return self.append_leaf(leaf_hash(entry, self.algorithm))

    def leaf_at(self, index):
        return self._leaves[index]

    def _range_hash(self, start, end):
        """Merkle Tree Hash of leaves [start, end), per RFC 6962 section 2.1."""
        if start == end:
            return empty_root(self.algorithm)
        if end - start == 1:
            return self._leaves[start]
        key = (start, end)
        cached = self._subtree.get(key)
        if cached is not None:
            return cached
        split = start + _largest_power_of_two_below(end - start)
        value = node_hash(self._range_hash(start, split),
                          self._range_hash(split, end),
                          self.algorithm)
        self._subtree[key] = value
        return value

    def root(self, tree_size=None):
        size = len(self._leaves) if tree_size is None else tree_size
        if size > len(self._leaves):
            raise ValueError("tree_size exceeds the log")
        return self._range_hash(0, size)

    def inclusion_proof(self, index, tree_size=None):
        """Audit path proving leaf `index` belongs to the tree of `tree_size`."""
        size = len(self._leaves) if tree_size is None else tree_size
        if not 0 <= index < size or size > len(self._leaves):
            raise ValueError("index outside the tree")
        return self._path(index, 0, size)

    def _path(self, index, start, end):
        if end - start == 1:
            return []
        split = start + _largest_power_of_two_below(end - start)
        if index < split:
            return self._path(index, start, split) + [self._range_hash(split, end)]
        return self._path(index, split, end) + [self._range_hash(start, split)]

    def consistency_proof(self, first_size, second_size=None):
        """Proof that the tree of `first_size` is a prefix of `second_size`."""
        second = len(self._leaves) if second_size is None else second_size
        if not 0 < first_size <= second <= len(self._leaves):
            raise ValueError("invalid sizes for a consistency proof")
        if first_size == second:
            return []
        return self._subproof(first_size, 0, second, True)

    def _subproof(self, m, start, end, is_complete_subtree):
        if m == end - start:
            return [] if is_complete_subtree else [self._range_hash(start, end)]
        split = start + _largest_power_of_two_below(end - start)
        if m <= split - start:
            return self._subproof(m, start, split, is_complete_subtree) + \
                   [self._range_hash(split, end)]
        return self._subproof(m - (split - start), split, end, False) + \
               [self._range_hash(start, split)]


# --------------------------------------------------------------------------- #
# Third-party verification - the whole point of publishing a log
# --------------------------------------------------------------------------- #

def verify_inclusion(leaf, index, tree_size, proof, root, algorithm=DEFAULT_ALGORITHM):
    """
    Check an audit path with no access to the log. Anyone holding a receipt and a
    signed tree head can run this and needs to trust nothing else.
    """
    if not 0 <= index < tree_size:
        return False
    node_index, last_index = index, tree_size - 1
    computed = leaf
    for sibling in proof:
        if last_index == 0:
            return False
        if node_index & 1 or node_index == last_index:
            computed = node_hash(sibling, computed, algorithm)
            while node_index != 0 and not node_index & 1:
                node_index >>= 1
                last_index >>= 1
        else:
            computed = node_hash(computed, sibling, algorithm)
        node_index >>= 1
        last_index >>= 1
    return last_index == 0 and computed == root


def verify_consistency(first_size, second_size, proof, first_root, second_root,
                       algorithm=DEFAULT_ALGORITHM):
    """
    Check that a later tree still contains an earlier one, unchanged and in order.

    This is the property that makes a rewrite of history detectable rather than
    merely forbidden.
    """
    if first_size > second_size or first_size == 0:
        return False
    if first_size == second_size:
        return not proof and first_root == second_root

    remaining = list(proof)
    node_index, last_index = first_size - 1, second_size - 1
    while node_index & 1:
        node_index >>= 1
        last_index >>= 1

    if node_index:
        if not remaining:
            return False
        first_computed = remaining.pop(0)
    else:
        first_computed = first_root
    second_computed = first_computed

    while node_index:
        if node_index & 1:
            if not remaining:
                return False
            sibling = remaining.pop(0)
            first_computed = node_hash(sibling, first_computed, algorithm)
            second_computed = node_hash(sibling, second_computed, algorithm)
        elif node_index < last_index:
            if not remaining:
                return False
            second_computed = node_hash(second_computed, remaining.pop(0), algorithm)
        node_index >>= 1
        last_index >>= 1

    while last_index:
        if not remaining:
            return False
        second_computed = node_hash(second_computed, remaining.pop(0), algorithm)
        last_index >>= 1

    return (not remaining
            and first_computed == first_root
            and second_computed == second_root)


def tag(raw, algorithm=DEFAULT_ALGORITHM):
    """Render a raw digest in the `<algorithm>:<base64url>` form used on the wire."""
    return algorithm + ":" + codec.b64u_encode(raw)


def untag(value):
    """Parse a wire hash back to raw bytes, rejecting unregistered algorithms."""
    if not isinstance(value, str) or ":" not in value:
        raise ValueError("malformed hash tag")
    algorithm, encoded = value.split(":", 1)
    if algorithm not in codec.HASH_ALGORITHMS:
        raise ValueError("unregistered hash algorithm: %r" % algorithm)
    return algorithm, codec.b64u_decode(encoded)

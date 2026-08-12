"""
Node tests - the transparency log, receipt issuance, discovery and persistence.

The log tests matter most. A transparency log that is subtly wrong is worse than
no log at all: it produces proofs that look authoritative and are not. So the
Merkle construction is checked three ways - against the RFC's published values,
against a naive transcription of its formula, and exhaustively for every tree
size and leaf position in a range, including rejection of forgeries.
"""

import hashlib
import json
import os
import socket
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from uip import codec, envelope
from uise import Agent, Identity, Node, Storage, UipError, log, suites
from uise.node import make_handler, verify_signed_tree_head
from uise.transport import decode_wire, encode_wire

CAPABILITY = {"id": "translate.text",
              "price": {"amount": "0.0004", "unit": "USD", "per": "call"}}


def _now_ms():
    return int(time.time() * 1000)


def _new_rid(offset=0):
    return codec.ulid_new(_now_ms() + offset, os.urandom(10))


def _naive_merkle_root(entries, algorithm="sha384"):
    """Literal transcription of RFC 6962 section 2.1. Slow, obvious, no caching."""
    digest = codec.HASH_ALGORITHMS[algorithm]
    if not entries:
        return digest(b"").digest()
    if len(entries) == 1:
        return digest(b"\x00" + entries[0]).digest()
    split = 1
    while split * 2 < len(entries):
        split *= 2
    return digest(b"\x01"
                  + _naive_merkle_root(entries[:split], algorithm)
                  + _naive_merkle_root(entries[split:], algorithm)).digest()


# --------------------------------------------------------------------------- #
# Transparency log - spec section 10.4, RFC 6962
# --------------------------------------------------------------------------- #

class TestMerkleLog:
    def test_matches_rfc_6962_base_cases(self):
        """The RFC's own published values for the empty and single-entry trees."""
        assert log.empty_root("sha256").hex() == hashlib.sha256(b"").hexdigest()
        single = log.MerkleLog(algorithm="sha256")
        single.append(b"")
        assert single.root().hex() == (
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        )

    def test_matches_a_naive_transcription_of_the_formula(self):
        for size in range(0, 33):
            entries = [b"entry-%d" % i for i in range(size)]
            tree = log.MerkleLog()
            for entry in entries:
                tree.append(entry)
            assert tree.root() == _naive_merkle_root(entries), "size %d" % size

    def test_inclusion_proofs_for_every_leaf_of_every_size(self):
        for size in range(1, 25):
            entries = [b"entry-%d" % i for i in range(size)]
            tree = log.MerkleLog()
            for entry in entries:
                tree.append(entry)
            root = tree.root()
            for index in range(size):
                proof = tree.inclusion_proof(index)
                leaf = log.leaf_hash(entries[index])
                assert log.verify_inclusion(leaf, index, size, proof, root)

    def test_forged_leaves_and_tampered_paths_are_rejected(self):
        entries = [b"entry-%d" % i for i in range(17)]
        tree = log.MerkleLog()
        for entry in entries:
            tree.append(entry)
        root = tree.root()
        for index in range(17):
            proof = tree.inclusion_proof(index)
            assert not log.verify_inclusion(log.leaf_hash(b"forged"), index, 17, proof, root)
            if proof:
                tampered = list(proof)
                tampered[0] = bytes(len(tampered[0]))
                assert not log.verify_inclusion(
                    log.leaf_hash(entries[index]), index, 17, tampered, root
                )

    def test_consistency_proofs_for_every_pair_of_sizes(self):
        for size in range(1, 25):
            entries = [b"entry-%d" % i for i in range(size)]
            tree = log.MerkleLog()
            for entry in entries:
                tree.append(entry)
            for earlier in range(1, size + 1):
                proof = tree.consistency_proof(earlier, size)
                assert log.verify_consistency(
                    earlier, size, proof, tree.root(earlier), tree.root(size)
                )

    def test_a_rewritten_history_cannot_be_made_consistent(self):
        """The property that makes rewriting the past detectable, not just banned."""
        entries = [b"entry-%d" % i for i in range(12)]
        tree = log.MerkleLog()
        for entry in entries:
            tree.append(entry)
        for earlier in range(1, 12):
            proof = tree.consistency_proof(earlier, 12)
            forged = log.MerkleLog()
            for entry in entries[:earlier - 1] + [b"rewritten"]:
                forged.append(entry)
            assert not log.verify_consistency(
                earlier, 12, proof, forged.root(), tree.root(12)
            )

    def test_leaf_and_node_prefixes_are_domain_separated(self):
        """
        Without distinct prefixes an interior node could be replayed as a leaf,
        forging inclusion for data that was never logged.
        """
        assert log.LEAF_PREFIX != log.NODE_PREFIX
        payload = b"x"
        assert log.leaf_hash(payload) != log.node_hash(payload, b"", log.DEFAULT_ALGORITHM)


# --------------------------------------------------------------------------- #
# Issuance
# --------------------------------------------------------------------------- #

@pytest.fixture
def node():
    instance = Node(log_url="https://log.uise.test", fee="0.0001")
    yield instance
    instance.close()


@pytest.fixture
def parties():
    return Agent.generate(name="payer"), Agent.generate(name="payee")


def agreed_receipt(node, payer, payee, rid=None, **overrides):
    base = {
        "v": "uip/1",
        "rid": rid or _new_rid(),
        "request_id": "01K2R7XQ4M8YVZ3B9N0C6TFHJD",
        "response_id": "01K2R7XZ7C2GHNQ8T5R1WYBMKA",
        "payer": payer.did,
        "payee": payee.did,
        "capability": "translate.text",
        "amount": "0.0004",
        "unit": "USD",
        "terms_hash": envelope.terms_hash(CAPABILITY),
        "issued_at": _now_ms(),
        "issuer": node.did,
        "settlement": None,
        "anchor": None,
    }
    base.update(overrides)
    signed = payer.identity.sign_receipt_as(base, "payer")
    return payee.identity.sign_receipt_as(signed, "payee")


class TestIssuance:
    def test_issuer_must_use_a_post_quantum_suite(self):
        """An issuer signs evidence that must outlive the algorithm signing it."""
        with pytest.raises(ValueError):
            Node(identity=Identity.generate(suites.ED25519))

    def test_default_issuer_suite_is_composite(self, node):
        assert node.identity.suite.name == "Ed25519+ML-DSA-65"
        assert node.identity.suite.long_term_evidence

    def test_fee_must_be_a_decimal_string(self):
        with pytest.raises(TypeError):
            Node(fee=0.0001)

    def test_issued_receipt_is_complete_and_anchored(self, node, parties):
        payer, payee = parties
        issued = node.issue(agreed_receipt(node, payer, payee))
        envelope.verify_receipt(issued, require_long_term_issuer=True)
        assert set(issued["sigs"]) == {"payer", "payee", "issuer"}
        assert issued["anchor"]["index"] == 0
        assert issued["anchor"]["tree_size"] == 1

    def test_anchor_proves_inclusion_to_an_outsider(self, node, parties):
        payer, payee = parties
        issued = [node.issue(agreed_receipt(node, payer, payee)) for _ in range(6)]
        target = issued[3]
        anchor = target["anchor"]
        algorithm, root = log.untag(anchor["root"])
        leaf = log.leaf_hash(log.receipt_entry(target), algorithm)
        proof = [log.untag(node_hash)[1] for node_hash in anchor["inclusion_proof"]]
        assert log.verify_inclusion(
            leaf, anchor["index"], anchor["tree_size"], proof, root, algorithm
        )

    def test_anchor_is_excluded_from_the_signed_bytes(self, node, parties):
        """Logging proves when a receipt existed; it never alters what was agreed."""
        payer, payee = parties
        issued = node.issue(agreed_receipt(node, payer, payee))
        assert issued["anchor"] is not None
        envelope.verify_receipt(dict(issued, anchor=None))

    def test_issuance_is_idempotent_by_rid(self, node, parties):
        payer, payee = parties
        rid = _new_rid()
        first = node.issue(agreed_receipt(node, payer, payee, rid=rid))
        second = node.issue(agreed_receipt(node, payer, payee, rid=rid))
        assert first["anchor"]["index"] == second["anchor"]["index"]
        assert node.storage.log_size() == 1

    def test_refuses_a_receipt_naming_another_issuer(self, node, parties):
        payer, payee = parties
        other = Node()
        try:
            with pytest.raises(UipError) as error:
                node.issue(agreed_receipt(other, payer, payee))
            assert error.value.code == "UIP_DID_INVALID"
        finally:
            other.close()

    def test_refuses_a_receipt_the_parties_did_not_sign(self, node, parties):
        payer, payee = parties
        forged = dict(agreed_receipt(node, payer, payee), amount="9.9900")
        with pytest.raises(UipError) as error:
            node.issue(forged)
        assert error.value.code == "UIP_SIG_INVALID"

    def test_refuses_a_receipt_missing_a_party(self, node, parties):
        payer, payee = parties
        receipt = agreed_receipt(node, payer, payee)
        receipt = dict(receipt, sigs={"payer": receipt["sigs"]["payer"]})
        with pytest.raises(UipError) as error:
            node.issue(receipt)
        assert error.value.code == "UIP_RECEIPT_INCOMPLETE"

    def test_refuses_a_stale_issuance(self, node, parties):
        payer, payee = parties
        stale = agreed_receipt(node, payer, payee, issued_at=_now_ms() - 3_600_000)
        with pytest.raises(UipError) as error:
            node.issue(stale)
        assert error.value.code == "UIP_CLOCK_SKEW"

    def test_refuses_a_pre_anchored_submission(self, node, parties):
        payer, payee = parties
        receipt = agreed_receipt(node, payer, payee)
        with pytest.raises(UipError) as error:
            node.issue(dict(receipt, anchor={"log": "x", "index": 0, "tree_size": 1,
                                             "root": "sha384:x", "inclusion_proof": []}))
        assert error.value.code == "UIP_HEADER_MALFORMED"

    def test_revenue_is_exact_decimal(self, node, parties):
        payer, payee = parties
        for _ in range(3):
            node.issue(agreed_receipt(node, payer, payee))
        assert node.revenue() == {"USD": "0.0003"}


# --------------------------------------------------------------------------- #
# Signed tree head
# --------------------------------------------------------------------------- #

class TestSignedTreeHead:
    def test_head_is_signed_and_verifiable_by_anyone(self, node, parties):
        payer, payee = parties
        node.issue(agreed_receipt(node, payer, payee))
        head = node.signed_tree_head()
        assert verify_signed_tree_head(head)
        assert head["tree_size"] == 1

    def test_tampered_head_is_detected(self, node, parties):
        payer, payee = parties
        node.issue(agreed_receipt(node, payer, payee))
        head = node.signed_tree_head()
        assert not verify_signed_tree_head(dict(head, tree_size=99))

    def test_growth_stays_consistent_with_earlier_heads(self, node, parties):
        """
        An auditor pins a head, comes back later, and proves nothing was rewritten
        in between - without trusting the node.
        """
        payer, payee = parties
        for _ in range(4):
            node.issue(agreed_receipt(node, payer, payee))
        early = node.signed_tree_head()
        for _ in range(5):
            node.issue(agreed_receipt(node, payer, payee))
        later = node.signed_tree_head()

        proof = node.consistency_proof(early["tree_size"], later["tree_size"])
        algorithm, first_root = log.untag(proof["first_root"])
        _, second_root = log.untag(proof["second_root"])
        assert first_root == log.untag(early["root"])[1]
        assert second_root == log.untag(later["root"])[1]
        assert log.verify_consistency(
            proof["first_size"], proof["second_size"],
            [log.untag(node_hash)[1] for node_hash in proof["proof"]],
            first_root, second_root, algorithm,
        )


# --------------------------------------------------------------------------- #
# Discovery and persistence
# --------------------------------------------------------------------------- #

class TestDiscovery:
    def test_announce_then_find_by_capability(self, node):
        agent = Agent.generate(name="translator")

        @agent.capability("translate.text", price="0.0004")
        def translate(payload):
            return {"text": payload["text"].upper()}

        header, body = agent.announcement()
        status, _ = node.handle(encode_wire(header, body))
        assert status == 200
        found = node.discover("translate.text")
        assert [d["agent"] for d in found] == [agent.did]
        assert node.discover("nothing.here") == []

    def test_descriptor_must_match_its_signer(self, node):
        agent = Agent.generate(name="liar")

        @agent.capability("x.y")
        def handler(payload):
            return {}

        header, _ = agent.announcement()
        forged = dict(agent.descriptor(), agent=Agent.generate().did)
        body = codec.canonicalize(forged)
        header = agent.identity.sign_envelope(
            dict(header, body_hash=envelope.body_hash(body))
        )
        status, frame = node.handle(encode_wire(header, body))
        assert status == 400
        _, error_body = decode_wire(frame)
        assert json.loads(error_body)["code"] == "UIP_DID_INVALID"


class TestPersistence:
    def test_log_survives_a_restart(self, tmp_path, parties):
        payer, payee = parties
        database = str(tmp_path / "node.sqlite")
        seed = Identity.generate(suites.ISSUER_DEFAULT).secret_seed_hex()

        first = Node(identity=Identity.from_seed_hex(seed, suites.ISSUER_DEFAULT),
                     storage=Storage(database))
        for _ in range(4):
            first.issue(agreed_receipt(first, payer, payee))
        root_before = first.signed_tree_head()["root"]
        size_before = first.storage.log_size()
        first.close()

        reopened = Node(identity=Identity.from_seed_hex(seed, suites.ISSUER_DEFAULT),
                        storage=Storage(database))
        try:
            assert reopened.storage.log_size() == size_before == 4
            assert reopened.signed_tree_head()["root"] == root_before
        finally:
            reopened.close()


# --------------------------------------------------------------------------- #
# End to end over real HTTP
# --------------------------------------------------------------------------- #

def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class TestLiveNode:
    def test_full_settlement_over_http(self, node, parties):
        payer, payee = parties
        port = _free_port()
        httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(node))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.02)

            url = "http://127.0.0.1:%d" % port
            receipt = agreed_receipt(node, payer, payee)
            body = codec.canonicalize(receipt)
            request = payee._sign("receipt", node.did, body,
                                  "application/uip-receipt+json")

            from uise.transport import post
            status, frame = post(url, encode_wire(request, body))
            assert status == 200

            header, response_body = decode_wire(frame)
            envelope.verify_envelope(header, response_body, now_ms=_now_ms(),
                                     seen_ids=set())
            issued = json.loads(response_body.decode("utf-8"))
            envelope.verify_receipt(issued, require_long_term_issuer=True)
            assert issued["anchor"]["tree_size"] == 1
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

"""
Credential store tests.

A token is the one secret this system hands out, so the properties that matter are
about what cannot happen: it cannot be recovered after creation, it cannot be read
out of storage, a revoked one cannot come back, and one minted for testing cannot
reach live data.
"""

import time

import pytest

from uise import Node, keys
from uise.keys import SCOPE_ADMIN, SCOPE_READ, SCOPE_WRITE


@pytest.fixture
def node():
    instance = Node(fee="0.0001", environment="test")
    yield instance
    instance.close()


class TestTokenFormat:
    def test_shape_is_scannable_and_parseable(self, node):
        record, token = node.keys.create("ci", [SCOPE_READ])
        assert token.startswith("uise_test_")
        environment, key_id, secret = keys.parse_token(token)
        assert environment == "test"
        assert key_id == record.key_id
        assert len(secret) >= 40

    def test_a_distinctive_prefix_is_what_makes_a_leak_findable(self, node):
        """Secret scanners match on the prefix, so a leaked token can be revoked."""
        _, token = node.keys.create("ci")
        assert token.split("_")[0] == keys.BRAND
        assert token.split("_")[1] in keys.ENVIRONMENTS

    def test_malformed_tokens_parse_to_nothing(self):
        for bad in (None, "", "uise", "uise_test", "github_pat_abc",
                    "uise_prod_3f9a2c17b4d8_secret",     # unknown environment
                    "uise_test_XYZ_secret",              # key id not hex
                    "uise_test_3f9a2c17b4d8_"):          # empty secret
            assert keys.parse_token(bad) is None

    def test_the_secret_may_contain_the_separator(self):
        parsed = keys.parse_token("uise_test_3f9a2c17b4d8_abc_def_ghi")
        assert parsed == ("test", "3f9a2c17b4d8", "abc_def_ghi")


class TestCreation:
    def test_the_secret_is_never_recoverable(self, node):
        """
        A credential a service can re-read is a credential a compromise of that
        service hands over.
        """
        record, token = node.keys.create("ci", [SCOPE_READ])
        _, _, secret = keys.parse_token(token)

        stored = node.storage.api_key(record.key_id)
        assert secret.encode("utf-8") not in stored["digest"]
        assert secret not in repr(stored)
        assert "digest" not in repr(node.keys.get(record.key_id).as_dict())
        assert all("digest" not in row for row in node.storage.api_keys())

    def test_every_key_is_labelled_and_scoped(self, node):
        with pytest.raises(ValueError):
            node.keys.create("", [SCOPE_READ])
        with pytest.raises(ValueError):
            node.keys.create("no scopes", [])
        with pytest.raises(ValueError):
            node.keys.create("bad scope", ["superuser"])

    def test_keys_are_unique(self, node):
        identifiers = {node.keys.create("k%d" % index)[0].key_id for index in range(20)}
        assert len(identifiers) == 20

    def test_scopes_survive_a_round_trip(self, node):
        record, _ = node.keys.create("full", [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN])
        stored = node.keys.get(record.key_id)
        assert stored.scopes == {SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN}
        assert stored.allows(SCOPE_ADMIN) and not stored.allows("superuser")


class TestVerification:
    def test_a_valid_token_resolves_to_its_key(self, node):
        record, token = node.keys.create("ci", [SCOPE_READ])
        verified = node.keys.verify(token)
        assert verified.key_id == record.key_id
        assert verified.scopes == {SCOPE_READ}

    def test_a_tampered_secret_fails(self, node):
        _, token = node.keys.create("ci")
        environment, key_id, secret = keys.parse_token(token)
        forged = keys.format_token(environment, key_id, secret[:-1] + "X")
        assert node.keys.verify(forged) is None

    def test_a_valid_secret_under_another_id_fails(self, node):
        _, first = node.keys.create("first")
        second_record, _ = node.keys.create("second")
        _, _, secret = keys.parse_token(first)
        assert node.keys.verify(
            keys.format_token("test", second_record.key_id, secret)
        ) is None

    def test_an_unknown_key_id_fails(self, node):
        node.keys.create("ci")
        assert node.keys.verify("uise_test_000000000000_whatever") is None

    def test_environment_must_match(self, node):
        """A test credential must never reach live data."""
        _, token = node.keys.create("ci")
        live = Node(fee="0.0001", environment="live")
        try:
            live.keys.create("live")
            assert live.keys.verify(token) is None
        finally:
            live.close()

    def test_last_used_is_recorded_but_not_written_every_request(self, node):
        record, token = node.keys.create("ci")
        assert node.keys.get(record.key_id).last_used_at is None

        node.keys.verify(token)
        first = node.keys.get(record.key_id).last_used_at
        assert first is not None

        node.keys.verify(token)
        # Within the resolution window the row is left alone: a read endpoint
        # must not become a write on every call.
        assert node.keys.get(record.key_id).last_used_at == first


class TestRevocation:
    def test_a_revoked_key_stops_working_immediately(self, node):
        record, token = node.keys.create("temporary")
        assert node.keys.verify(token) is not None
        node.keys.revoke(record.key_id)
        assert node.keys.verify(token) is None

    def test_a_revoked_key_is_kept_not_deleted(self, node):
        """An audit trail with holes is not an audit trail."""
        record, _ = node.keys.create("temporary")
        node.keys.revoke(record.key_id)
        stored = node.keys.get(record.key_id)
        assert stored is not None
        assert stored.revoked
        assert stored.revoked_at is not None
        assert record.key_id in [key.key_id for key in node.keys.list()]

    def test_revoking_twice_keeps_the_first_timestamp(self, node):
        record, _ = node.keys.create("temporary")
        first = node.keys.revoke(record.key_id).revoked_at
        time.sleep(0.002)
        assert node.keys.revoke(record.key_id).revoked_at == first

    def test_revoking_an_unknown_key_returns_nothing(self, node):
        assert node.keys.revoke("deadbeef0000") is None

    def test_the_api_closes_when_the_last_key_is_revoked(self, node):
        record, _ = node.keys.create("only one")
        assert node.keys.any_active
        node.keys.revoke(record.key_id)
        assert not node.keys.any_active


class TestPersistence:
    def test_keys_survive_a_restart(self, tmp_path):
        from uise import Storage

        database = str(tmp_path / "node.sqlite")
        first = Node(fee="0.0001", environment="test", storage=Storage(database))
        record, token = first.keys.create("durable", [SCOPE_READ])
        first.close()

        reopened = Node(fee="0.0001", environment="test", storage=Storage(database))
        try:
            verified = reopened.keys.verify(token)
            assert verified is not None
            assert verified.key_id == record.key_id
            assert verified.scopes == {SCOPE_READ}
        finally:
            reopened.close()

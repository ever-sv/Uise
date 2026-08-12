"""
Production cryptographic suites for UIP-1 - spec section 4.

Every algorithm here comes from `cryptography` (constant-time Ed25519, and NIST
ML-DSA per FIPS 204). No cryptography is hand-rolled in this project: lattice
schemes fail silently when implemented by hand - they pass their own tests and
interoperate with nothing.

Importing this module registers these suites into the shared `uip.suites`
registry, so the same protocol code gains post-quantum capability without a single
change to the envelope format. That is the whole point of section 4.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from uip import suites as _registry

SEED_SIZE = 32

# ML-DSA-65 parameter sizes, per FIPS 204. Asserted against the library at import
# time below, so a future upstream change cannot silently shift the wire format.
ML_DSA_65_PUBLIC_KEY_SIZE = 1952
ML_DSA_65_SIGNATURE_SIZE = 3309

ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64

COMPOSITE_PUBLIC_KEY_SIZE = ED25519_PUBLIC_KEY_SIZE + ML_DSA_65_PUBLIC_KEY_SIZE
COMPOSITE_SIGNATURE_SIZE = ED25519_SIGNATURE_SIZE + ML_DSA_65_SIGNATURE_SIZE

# Provisional multicodec range, scoped to UIP. These are NOT assignments: ML-DSA
# codepoints are still pending in the multicodec table. Suites using them are
# flagged `provisional=True` and must not be relied on across organizations until
# real codepoints exist. Shipping a guessed value as if it were assigned would
# fragment the namespace permanently, so the provisional status travels with the
# suite everywhere it is reported.
PROVISIONAL_BASE = 0x1F0000
MULTICODEC_ML_DSA_65_PROVISIONAL = PROVISIONAL_BASE + 0x65
MULTICODEC_COMPOSITE_PROVISIONAL = PROVISIONAL_BASE + 0x165

# Domain-separated labels for deriving two independent component keys from one
# composite seed. Distinct labels guarantee the classical and post-quantum keys
# are independent even though the operator manages a single secret.
_LABEL_ED25519 = b"uip/1.composite.ed25519"
_LABEL_ML_DSA_65 = b"uip/1.composite.ml-dsa-65"


def _derive_component_seed(seed, label):
    return HKDF(algorithm=hashes.SHA384(), length=SEED_SIZE, salt=None, info=label).derive(seed)


# --------------------------------------------------------------------------- #
# Ed25519 - constant-time backend for an already assigned codepoint
# --------------------------------------------------------------------------- #

def _ed25519_public_key(seed):
    return _ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def _ed25519_sign(message, seed):
    return _ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def _ed25519_verify(signature, message, public_key):
    try:
        _ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------- #
# ML-DSA-65 - NIST FIPS 204
# --------------------------------------------------------------------------- #

def _ml_dsa_65_public_key(seed):
    return _mldsa.MLDSA65PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()


def _ml_dsa_65_sign(message, seed):
    return _mldsa.MLDSA65PrivateKey.from_seed_bytes(seed).sign(message)


def _ml_dsa_65_verify(signature, message, public_key):
    try:
        _mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------- #
# Composite Ed25519 + ML-DSA-65 - spec section 4.3
# --------------------------------------------------------------------------- #

def _composite_public_key(seed):
    classical = _ed25519_public_key(_derive_component_seed(seed, _LABEL_ED25519))
    quantum = _ml_dsa_65_public_key(_derive_component_seed(seed, _LABEL_ML_DSA_65))
    return classical + quantum


def _composite_sign(message, seed):
    classical = _ed25519_sign(message, _derive_component_seed(seed, _LABEL_ED25519))
    quantum = _ml_dsa_65_sign(message, _derive_component_seed(seed, _LABEL_ML_DSA_65))
    return classical + quantum


def _composite_verify(signature, message, public_key):
    """
    BOTH components must validate. A composite where either half fails is invalid.

    The pairing defends against two different risks at once: a future quantum
    attack on the classical half, and an undiscovered flaw in the newer lattice
    construction. Accepting either half alone would trade one single point of
    failure for another.
    """
    classical_ok = _ed25519_verify(
        signature[:ED25519_SIGNATURE_SIZE],
        message,
        public_key[:ED25519_PUBLIC_KEY_SIZE],
    )
    quantum_ok = _ml_dsa_65_verify(
        signature[ED25519_SIGNATURE_SIZE:],
        message,
        public_key[ED25519_PUBLIC_KEY_SIZE:],
    )
    return classical_ok and quantum_ok


ED25519 = _registry.Suite(
    name="Ed25519",
    multicodec=_registry.MULTICODEC_ED25519_PUB,
    public_key_size=ED25519_PUBLIC_KEY_SIZE,
    signature_size=ED25519_SIGNATURE_SIZE,
    long_term_evidence=False,
    derive_public_key=_ed25519_public_key,
    sign=_ed25519_sign,
    verify=_ed25519_verify,
)

ML_DSA_65 = _registry.Suite(
    name="ML-DSA-65",
    multicodec=MULTICODEC_ML_DSA_65_PROVISIONAL,
    public_key_size=ML_DSA_65_PUBLIC_KEY_SIZE,
    signature_size=ML_DSA_65_SIGNATURE_SIZE,
    long_term_evidence=True,
    derive_public_key=_ml_dsa_65_public_key,
    sign=_ml_dsa_65_sign,
    verify=_ml_dsa_65_verify,
    provisional=True,
)

COMPOSITE_ED25519_ML_DSA_65 = _registry.Suite(
    name="Ed25519+ML-DSA-65",
    multicodec=MULTICODEC_COMPOSITE_PROVISIONAL,
    public_key_size=COMPOSITE_PUBLIC_KEY_SIZE,
    signature_size=COMPOSITE_SIGNATURE_SIZE,
    long_term_evidence=True,
    derive_public_key=_composite_public_key,
    sign=_composite_sign,
    verify=_composite_verify,
    provisional=True,
)

# The suite an issuer should use: post-quantum, and hedged by a classical half.
ISSUER_DEFAULT = COMPOSITE_ED25519_ML_DSA_65

# The suite an ordinary agent should use: a 3 KB signature on every message would
# tax the conversation plane for no benefit, given a 24 hour envelope lifetime.
AGENT_DEFAULT = ED25519


def _verify_library_parameters():
    """
    Confirm the library's real key and signature sizes match what the wire format
    declares. A silent upstream change would otherwise corrupt every DID produced.
    """
    probe = bytes(SEED_SIZE)
    actual_public = len(_ml_dsa_65_public_key(probe))
    actual_signature = len(_ml_dsa_65_sign(b"", probe))
    if actual_public != ML_DSA_65_PUBLIC_KEY_SIZE:
        raise RuntimeError(
            "ML-DSA-65 public key size is %d, expected %d"
            % (actual_public, ML_DSA_65_PUBLIC_KEY_SIZE)
        )
    if actual_signature != ML_DSA_65_SIGNATURE_SIZE:
        raise RuntimeError(
            "ML-DSA-65 signature size is %d, expected %d"
            % (actual_signature, ML_DSA_65_SIGNATURE_SIZE)
        )


def install():
    """Register the production suites. Idempotent."""
    _verify_library_parameters()
    # Same codepoint and same wire bytes as the core's auditable pure-Python
    # Ed25519, swapped for a constant-time implementation.
    _registry.register(ED25519, replace=True)
    for suite in (ML_DSA_65, COMPOSITE_ED25519_ML_DSA_65):
        if suite.multicodec not in {s.multicodec for s in _registry.registered()}:
            _registry.register(suite)


install()

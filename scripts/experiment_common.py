"""Shared experiment definitions and cryptographic helpers.

The benchmark and functional checks intentionally share the same envelope and
AAD code.  This keeps the measured workflow and the verification workflow
aligned without putting file I/O or result validation inside timers.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import importlib.metadata
import json
import os
import platform
import random
import secrets
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


INPUT_SIZES = (1_024, 10_240, 102_400, 1_048_576, 10_485_760)
INPUT_FILENAMES = {
    1_024: "input_1KiB.bin",
    10_240: "input_10KiB.bin",
    102_400: "input_100KiB.bin",
    1_048_576: "input_1MiB.bin",
    10_485_760: "input_10MiB.bin",
}

FULL_WARMUP_BATCHES = 5
FULL_MEASURED_BATCHES = 30
SMOKE_WARMUP_BATCHES = 2
SMOKE_MEASURED_BATCHES = 3
CALIBRATION_TARGET_NS = 2_000_000
MAX_OPERATIONS_PER_BATCH = 4_096

HASH_SHA256 = "SHA-256"
HASH_SHA512 = "SHA-512"
HASH_SHA3_256 = "SHA3-256"
SYMMETRIC_AES_GCM = "AES-256-GCM"
SYMMETRIC_CHACHA = "ChaCha20-Poly1305"
SYMMETRIC_AES_GCM_SIV = "AES-256-GCM-SIV"
HYBRID_RSA = "RSA-3072-OAEP-SHA256-MGF1-SHA256+AES-256-GCM"
HYBRID_X25519 = "X25519+HKDF-SHA256+AES-256-GCM"
HYBRID_FFDHE = "FFDHE3072+HKDF-SHA256+AES-256-GCM"
HMAC_CONTROL = "HMAC-SHA-256"

HASH_METHODS = (HASH_SHA256, HASH_SHA512, HASH_SHA3_256)
SYMMETRIC_METHODS = (SYMMETRIC_AES_GCM, SYMMETRIC_CHACHA, SYMMETRIC_AES_GCM_SIV)
HYBRID_METHODS = (HYBRID_RSA, HYBRID_X25519, HYBRID_FFDHE)
ALL_METHODS = HASH_METHODS + SYMMETRIC_METHODS + HYBRID_METHODS

FAMILY_BY_METHOD = {
    **{name: "hashing" for name in HASH_METHODS},
    **{name: "symmetric" for name in SYMMETRIC_METHODS},
    **{name: "hybrid" for name in HYBRID_METHODS},
}
PRIMARY_METRIC_BY_METHOD = {
    **{name: "digest_generation" for name in HASH_METHODS},
    **{name: "symmetric_encryption" for name in SYMMETRIC_METHODS},
    **{name: "hybrid_full_round_trip" for name in HYBRID_METHODS},
}

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
AEAD_TAG_BYTES = 16
HKDF_SALT_BYTES = 32
HYBRID_VERSION = 1
SYMMETRIC_AAD = b"A1-Crypto-Data-Protection/Symmetric/v1"
HKDF_INFO = b"A1-Crypto-Data-Protection/Hybrid-AES-256-GCM/v1"


# RFC 7919, Appendix A.2, ffdhe3072.  The library exposes generic DH
# parameter objects rather than a named ffdhe3072 constant, so the exact
# standard modulus and g=2 are constructed once and reused.
FFDHE3072_P = int(
    """FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238
    61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C
    AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3
    64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D
    ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF
    3C1B20EE 3FD59D7C 25E41D2B 66C62E37 FFFFFFFF FFFFFFFF
    """.replace(" ", "").replace("\n", "")
    .replace("\r", "")
    .strip(),
    16,
)
FFDHE3072_G = 2
FFDHE3072_PARAMETER_NUMBERS = dh.DHParameterNumbers(FFDHE3072_P, FFDHE3072_G)
FFDHE3072_PARAMETERS = FFDHE3072_PARAMETER_NUMBERS.parameters()
FFDHE3072_PUBLIC_BYTES = (FFDHE3072_P.bit_length() + 7) // 8


@dataclass(frozen=True)
class HybridEnvelope:
    """The common in-memory hybrid payload envelope.

    ``key_material`` is either the RSA wrapped AES key or the transmitted
    sender ephemeral public key.  ``salt`` is empty for RSA and 32 bytes for
    the two key-agreement methods.  AES-GCM returns ciphertext and tag
    together, but this envelope stores them separately so byte accounting is
    explicit.
    """

    method: str
    key_material: bytes
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    aad: bytes


@dataclass(frozen=True)
class HybridSenderContext:
    method: str
    aes_key: bytes
    key_material: bytes
    salt: bytes
    sender_shared_secret: bytes | None = None


@dataclass(frozen=True)
class HybridOperationResult:
    envelope: HybridEnvelope
    plaintext: bytes
    sender_key: bytes
    receiver_key: bytes
    shared_secrets_match: bool | None


class NonceSource:
    """Generate unique 96-bit nonces for one key scope.

    A random four-byte prefix is created outside timed regions, then an
    eight-byte counter makes uniqueness deterministic for this source.  The
    source is never reused across independent key scopes.
    """

    def __init__(self) -> None:
        self._prefix = secrets.token_bytes(4)
        self._counter = 0

    def next(self) -> bytes:
        if self._counter >= 1 << 64:
            raise OverflowError("nonce counter exhausted")
        value = self._prefix + self._counter.to_bytes(8, "big")
        self._counter += 1
        return value


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def derived_seed(seed: int, *parts: object) -> int:
    material = ":".join((str(seed), *(str(part) for part in parts))).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest(), "big")


def input_identifier(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_inputs(project_root: Path, sizes: tuple[int, ...]) -> dict[int, bytes]:
    inputs_dir = project_root / "data" / "inputs"
    result: dict[int, bytes] = {}
    for size in sizes:
        if size not in INPUT_FILENAMES:
            raise ValueError(f"unsupported input size: {size}")
        path = inputs_dir / INPUT_FILENAMES[size]
        if not path.is_file():
            raise FileNotFoundError(
                f"missing synthetic input {path}; run scripts/generate_inputs.py first"
            )
        data = path.read_bytes()
        if len(data) != size:
            raise ValueError(f"{path} contains {len(data)} bytes, expected {size}")
        result[size] = data
    return result


def environment_metadata() -> dict[str, Any]:
    package_versions: dict[str, str | None] = {}
    for package in ("cryptography", "matplotlib", "scipy"):
        try:
            package_versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            package_versions[package] = None
    clock = time.get_clock_info("perf_counter")
    return {
        "python": sys.version,
        "python_implementation": platform.python_implementation(),
        "os": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "openssl": ssl.OPENSSL_VERSION,
        "packages": package_versions,
        "perf_counter": {
            "implementation": clock.implementation,
            "resolution_seconds": clock.resolution,
            "monotonic": clock.monotonic,
            "adjustable": clock.adjustable,
        },
    }


def write_csv(path: Path, fieldnames: tuple[str, ...], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def prepare_output_dir(output_dir: Path, expected_names: tuple[str, ...]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = [name for name in expected_names if (output_dir / name).exists()]
    if existing:
        raise FileExistsError(
            f"refusing to overwrite existing outputs: {', '.join(existing)}"
        )
    return output_dir


def hash_digest(method: str, data: bytes) -> bytes:
    if method == HASH_SHA256:
        return hashlib.sha256(data).digest()
    if method == HASH_SHA512:
        return hashlib.sha512(data).digest()
    if method == HASH_SHA3_256:
        return hashlib.sha3_256(data).digest()
    raise ValueError(f"unknown hash method: {method}")


def hash_digest_bytes(method: str) -> int:
    return len(hash_digest(method, b""))


def symmetric_cipher(method: str, key: bytes) -> AESGCM | ChaCha20Poly1305 | AESGCMSIV:
    if method == SYMMETRIC_AES_GCM:
        return AESGCM(key)
    if method == SYMMETRIC_CHACHA:
        return ChaCha20Poly1305(key)
    if method == SYMMETRIC_AES_GCM_SIV:
        return AESGCMSIV(key)
    raise ValueError(f"unknown symmetric method: {method}")


def generate_symmetric_key(method: str) -> bytes:
    if method == SYMMETRIC_AES_GCM:
        return AESGCM.generate_key(bit_length=256)
    if method == SYMMETRIC_CHACHA:
        return ChaCha20Poly1305.generate_key()
    if method == SYMMETRIC_AES_GCM_SIV:
        return AESGCMSIV.generate_key(bit_length=256)
    raise ValueError(f"unknown symmetric method: {method}")


def split_ciphertext_and_tag(value: bytes) -> tuple[bytes, bytes]:
    if len(value) < AEAD_TAG_BYTES:
        raise ValueError("AEAD result is shorter than its 16-byte tag")
    return value[:-AEAD_TAG_BYTES], value[-AEAD_TAG_BYTES:]


def hybrid_scheme_id(method: str) -> int:
    return {HYBRID_RSA: 1, HYBRID_X25519: 2, HYBRID_FFDHE: 3}[method]


def hybrid_header(method: str, key_material: bytes, salt: bytes) -> bytes:
    """Return the common 5-byte-framing header plus transmitted fields."""
    if len(key_material) > 65_535:
        raise ValueError("key material is too long for the envelope format")
    if len(salt) > 255:
        raise ValueError("salt is too long for the envelope format")
    return (
        bytes((HYBRID_VERSION, hybrid_scheme_id(method)))
        + len(key_material).to_bytes(2, "big")
        + bytes((len(salt),))
        + key_material
        + salt
    )


def hybrid_aad(method: str, key_material: bytes, salt: bytes) -> bytes:
    return b"A1-Crypto-Data-Protection/Hybrid/v1\x00" + hybrid_header(
        method, key_material, salt
    )


def serialize_hybrid_envelope(envelope: HybridEnvelope) -> bytes:
    if len(envelope.nonce) != GCM_NONCE_BYTES or len(envelope.tag) != AEAD_TAG_BYTES:
        raise ValueError("invalid GCM nonce or tag size")
    expected_header = hybrid_header(envelope.method, envelope.key_material, envelope.salt)
    if envelope.aad != hybrid_aad(envelope.method, envelope.key_material, envelope.salt):
        raise ValueError("envelope AAD does not match the common policy")
    return expected_header + envelope.nonce + envelope.ciphertext + envelope.tag


def hybrid_overhead_details(envelope: HybridEnvelope, payload_bytes: int) -> dict[str, int]:
    serialized = serialize_hybrid_envelope(envelope)
    key_bytes = len(envelope.key_material)
    salt_bytes = len(envelope.salt)
    return {
        "digest_bytes": 0,
        "ciphertext_bytes": len(envelope.ciphertext),
        "nonce_bytes": len(envelope.nonce),
        "tag_bytes": len(envelope.tag),
        "wrapped_key_bytes": key_bytes if envelope.method == HYBRID_RSA else 0,
        "transmitted_public_key_bytes": key_bytes if envelope.method != HYBRID_RSA else 0,
        "hkdf_salt_bytes": salt_bytes,
        "framing_bytes": len(hybrid_header(envelope.method, b"", b"")),
        "aad_bytes": len(envelope.aad),
        "serialized_envelope_bytes": len(serialized),
        "overhead_bytes": len(serialized) - payload_bytes,
    }


def symmetric_overhead_details(payload: bytes, nonce: bytes, ciphertext_and_tag: bytes) -> dict[str, int]:
    ciphertext, tag = split_ciphertext_and_tag(ciphertext_and_tag)
    return {
        "digest_bytes": 0,
        "ciphertext_bytes": len(ciphertext),
        "nonce_bytes": len(nonce),
        "tag_bytes": len(tag),
        "wrapped_key_bytes": 0,
        "transmitted_public_key_bytes": 0,
        "hkdf_salt_bytes": 0,
        "framing_bytes": 0,
        "aad_bytes": len(SYMMETRIC_AAD),
        "serialized_envelope_bytes": len(nonce) + len(ciphertext_and_tag),
        "overhead_bytes": len(nonce) + len(tag),
    }


def rsa_oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def derive_hybrid_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)


def ffdhe_public_bytes(public_key: dh.DHPublicKey) -> bytes:
    y = public_key.public_numbers().y
    return y.to_bytes(FFDHE3072_PUBLIC_BYTES, "big")


def ffdhe_public_from_bytes(data: bytes) -> dh.DHPublicKey:
    if len(data) != FFDHE3072_PUBLIC_BYTES:
        raise ValueError("FFDHE3072 public value must be 384 bytes")
    y = int.from_bytes(data, "big")
    return dh.DHPublicNumbers(y, FFDHE3072_PARAMETER_NUMBERS).public_key()


def recipient_keypairs() -> dict[str, tuple[Any, Any]]:
    """Provision long-term recipient keys once per run, outside measurement."""
    rsa_private = rsa.generate_private_key(public_exponent=65_537, key_size=3072)
    x_private = x25519.X25519PrivateKey.generate()
    ffdhe_private = FFDHE3072_PARAMETERS.generate_private_key()
    return {
        HYBRID_RSA: (rsa_private, rsa_private.public_key()),
        HYBRID_X25519: (x_private, x_private.public_key()),
        HYBRID_FFDHE: (ffdhe_private, ffdhe_private.public_key()),
    }


def public_key_fingerprint(method: str, public_key: Any) -> str:
    if method == HYBRID_RSA:
        encoded = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    elif method == HYBRID_X25519:
        encoded = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    elif method == HYBRID_FFDHE:
        encoded = ffdhe_public_bytes(public_key)
    else:
        raise ValueError(f"unknown hybrid method: {method}")
    return hashlib.sha256(encoded).hexdigest()


def build_hybrid_sender_context(method: str, recipient_public: Any) -> HybridSenderContext:
    """Create the per-message key-establishment material.

    This helper includes fresh session/ephemeral key material, salt, key
    agreement, HKDF, and public-key/wrapped-key serialization.  It never
    creates a payload nonce or encrypts file bytes.
    """
    if method == HYBRID_RSA:
        aes_key = secrets.token_bytes(AES_KEY_BYTES)
        wrapped_key = recipient_public.encrypt(aes_key, rsa_oaep_padding())
        return HybridSenderContext(method, aes_key, wrapped_key, b"")
    if method == HYBRID_X25519:
        sender_private = x25519.X25519PrivateKey.generate()
        sender_public = sender_private.public_key()
        shared_secret = sender_private.exchange(recipient_public)
        salt = secrets.token_bytes(HKDF_SALT_BYTES)
        aes_key = derive_hybrid_key(shared_secret, salt)
        public_bytes = sender_public.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return HybridSenderContext(method, aes_key, public_bytes, salt, shared_secret)
    if method == HYBRID_FFDHE:
        sender_private = FFDHE3072_PARAMETERS.generate_private_key()
        sender_public = sender_private.public_key()
        shared_secret = sender_private.exchange(recipient_public)
        salt = secrets.token_bytes(HKDF_SALT_BYTES)
        aes_key = derive_hybrid_key(shared_secret, salt)
        return HybridSenderContext(
            method,
            aes_key,
            ffdhe_public_bytes(sender_public),
            salt,
            shared_secret,
        )
    raise ValueError(f"unknown hybrid method: {method}")


def receiver_hybrid_key(method: str, context: HybridSenderContext, recipient_private: Any) -> tuple[bytes, bool | None]:
    if method == HYBRID_RSA:
        return recipient_private.decrypt(context.key_material, rsa_oaep_padding()), None
    if method == HYBRID_X25519:
        sender_public = x25519.X25519PublicKey.from_public_bytes(context.key_material)
        receiver_secret = recipient_private.exchange(sender_public)
        return derive_hybrid_key(receiver_secret, context.salt), receiver_secret == context.sender_shared_secret
    if method == HYBRID_FFDHE:
        sender_public = ffdhe_public_from_bytes(context.key_material)
        receiver_secret = recipient_private.exchange(sender_public)
        return derive_hybrid_key(receiver_secret, context.salt), receiver_secret == context.sender_shared_secret
    raise ValueError(f"unknown hybrid method: {method}")


def hybrid_roundtrip_operation(
    method: str,
    payload: bytes,
    recipient_private: Any,
    recipient_public: Any,
    nonce_source: NonceSource,
) -> HybridOperationResult:
    context = build_hybrid_sender_context(method, recipient_public)
    nonce = nonce_source.next()
    aad = hybrid_aad(method, context.key_material, context.salt)
    cipher = AESGCM(context.aes_key)
    ciphertext_and_tag = cipher.encrypt(nonce, payload, aad)
    ciphertext, tag = split_ciphertext_and_tag(ciphertext_and_tag)
    envelope = HybridEnvelope(
        method=method,
        key_material=context.key_material,
        salt=context.salt,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        aad=aad,
    )
    receiver_key, shared_match = receiver_hybrid_key(method, context, recipient_private)
    recovered = AESGCM(receiver_key).decrypt(nonce, ciphertext_and_tag, aad)
    return HybridOperationResult(envelope, recovered, context.aes_key, receiver_key, shared_match)


def decrypt_hybrid(envelope: HybridEnvelope, recipient_private: Any) -> bytes:
    """Decrypt a common envelope; InvalidTag is intentionally propagated."""
    expected_aad = hybrid_aad(envelope.method, envelope.key_material, envelope.salt)
    if envelope.aad != expected_aad:
        raise ValueError("hybrid AAD does not match the envelope header")
    if envelope.method == HYBRID_RSA:
        key = recipient_private.decrypt(envelope.key_material, rsa_oaep_padding())
    elif envelope.method == HYBRID_X25519:
        sender_public = x25519.X25519PublicKey.from_public_bytes(envelope.key_material)
        shared_secret = recipient_private.exchange(sender_public)
        key = derive_hybrid_key(shared_secret, envelope.salt)
    elif envelope.method == HYBRID_FFDHE:
        sender_public = ffdhe_public_from_bytes(envelope.key_material)
        shared_secret = recipient_private.exchange(sender_public)
        key = derive_hybrid_key(shared_secret, envelope.salt)
    else:
        raise ValueError(f"unknown hybrid method: {envelope.method}")
    return AESGCM(key).decrypt(
        envelope.nonce,
        envelope.ciphertext + envelope.tag,
        envelope.aad,
    )


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    expected = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, tag)


def flip_first_byte(value: bytes) -> bytes:
    if not value:
        raise ValueError("cannot flip a byte in an empty value")
    return bytes((value[0] ^ 1,)) + value[1:]


def method_order(seed: int, trial: int) -> list[tuple[str, int]]:
    conditions = [(method, size) for method in ALL_METHODS for size in INPUT_SIZES]
    random.Random(derived_seed(seed, "measurement-order", trial)).shuffle(conditions)
    return conditions


def expected_profile(profile: str) -> tuple[tuple[int, ...], int, int]:
    if profile == "full":
        return INPUT_SIZES, FULL_WARMUP_BATCHES, FULL_MEASURED_BATCHES
    if profile == "smoke":
        return (1_024, 1_048_576), SMOKE_WARMUP_BATCHES, SMOKE_MEASURED_BATCHES
    raise ValueError("profile must be 'smoke' or 'full'")


def safe_exception_category(error: BaseException) -> str:
    if isinstance(error, InvalidTag):
        return "authentication_failed"
    if isinstance(error, ValueError):
        return "invalid_input_or_key"
    if isinstance(error, TypeError):
        return "invalid_type"
    return "cryptographic_operation_failed"


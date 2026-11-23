"""Run the nine-method cryptographic benchmark.

The ``full`` profile is the reportable collection: five input sizes, five
untimed warm-up batches, and 30 measured batches per method and size.  The
``smoke`` profile is deliberately smaller and writes to its own run directory
so it cannot be mistaken for the full dataset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import secrets
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization

from experiment_common import (
    ALL_METHODS,
    CALIBRATION_TARGET_NS,
    FAMILY_BY_METHOD,
    HASH_METHODS,
    HYBRID_METHODS,
    HYBRID_RSA,
    INPUT_FILENAMES,
    PRIMARY_METRIC_BY_METHOD,
    SYMMETRIC_AAD,
    SYMMETRIC_METHODS,
    NonceSource,
    build_hybrid_sender_context,
    derived_seed,
    environment_metadata,
    expected_profile,
    hash_digest,
    hybrid_overhead_details,
    hybrid_roundtrip_operation,
    input_identifier,
    load_inputs,
    method_order,
    prepare_output_dir,
    public_key_fingerprint,
    recipient_keypairs,
    safe_exception_category,
    split_ciphertext_and_tag,
    symmetric_cipher,
    symmetric_overhead_details,
    generate_symmetric_key,
    utc_now,
    write_csv,
    write_json,
)


RAW_FIELDS = (
    "run_id",
    "profile",
    "family",
    "method",
    "input_size_bytes",
    "input_file",
    "input_identifier_sha256",
    "trial",
    "order_position",
    "observation_id",
    "primary_metric",
    "primary_elapsed_ns",
    "primary_operations_per_batch",
    "primary_ns_per_operation",
    "hash_elapsed_ns",
    "hash_operations_per_batch",
    "hash_ns_per_operation",
    "encryption_elapsed_ns",
    "encryption_operations_per_batch",
    "encryption_ns_per_operation",
    "valid_decryption_elapsed_ns",
    "valid_decryption_operations_per_batch",
    "valid_decryption_ns_per_operation",
    "key_step_elapsed_ns",
    "key_step_operations_per_batch",
    "key_step_ns_per_operation",
    "full_round_trip_elapsed_ns",
    "full_round_trip_operations_per_batch",
    "full_round_trip_ns_per_operation",
    "digest_bytes",
    "ciphertext_bytes",
    "nonce_bytes",
    "tag_bytes",
    "wrapped_key_bytes",
    "transmitted_public_key_bytes",
    "hkdf_salt_bytes",
    "framing_bytes",
    "aad_bytes",
    "serialized_envelope_bytes",
    "overhead_bytes",
)


@dataclass
class SymmetricState:
    method: str
    payload: bytes
    cipher: Any
    encryption_nonce_source: NonceSource
    encryption_operations: int
    decryption_operations: int
    decryption_inputs: list[tuple[bytes, bytes]]
    overhead: dict[str, int]


@dataclass
class HybridState:
    method: str
    payload: bytes
    recipient_private: Any
    recipient_public: Any
    nonce_source: NonceSource
    key_step_operations: int
    round_trip_operations: int
    overhead: dict[str, int]


def timed_batch(operation: Callable[[], Any], operations: int) -> tuple[int, Any]:
    if operations <= 0:
        raise ValueError("operations must be positive")
    last: Any = None
    start = time.perf_counter_ns()
    for _ in range(operations):
        last = operation()
    elapsed = time.perf_counter_ns() - start
    return elapsed, last


def untimed_batch(operation: Callable[[], Any], operations: int) -> Any:
    last: Any = None
    for _ in range(operations):
        last = operation()
    return last


def calibrate_operations(operation: Callable[[], Any]) -> int:
    """Pick one fixed batch size before measured trials for this workload."""
    operations = 1
    elapsed, _ = timed_batch(operation, operations)
    while elapsed < CALIBRATION_TARGET_NS and operations < 4_096:
        operations = min(operations * 2, 4_096)
        elapsed, _ = timed_batch(operation, operations)
    return operations


def metric_values(elapsed_ns: int, operations: int) -> tuple[int, int, float]:
    if elapsed_ns <= 0 or operations <= 0:
        raise RuntimeError("measured elapsed time and operations must be positive")
    return elapsed_ns, operations, elapsed_ns / operations


def set_metric(row: dict[str, Any], prefix: str, elapsed_ns: int, operations: int) -> None:
    elapsed, count, normalized = metric_values(elapsed_ns, operations)
    row[f"{prefix}_elapsed_ns"] = elapsed
    row[f"{prefix}_operations_per_batch"] = count
    row[f"{prefix}_ns_per_operation"] = normalized


def build_condition_order(seed: int, trial: int, sizes: tuple[int, ...]) -> list[tuple[str, int]]:
    conditions = [(method, size) for method in ALL_METHODS for size in sizes]
    random.Random(derived_seed(seed, "measurement-order", trial)).shuffle(conditions)
    return conditions


def build_warmup_order(
    seed: int, sizes: tuple[int, ...], warmup_batches: int
) -> list[tuple[str, int]]:
    conditions = [
        (method, size)
        for method in ALL_METHODS
        for size in sizes
        for _ in range(warmup_batches)
    ]
    random.Random(derived_seed(seed, "warmup-order")).shuffle(conditions)
    return conditions


def prepare_symmetric_states(payloads: dict[int, bytes], sizes: tuple[int, ...]) -> dict[tuple[str, int], SymmetricState]:
    states: dict[tuple[str, int], SymmetricState] = {}
    keys = {method: generate_symmetric_key(method) for method in SYMMETRIC_METHODS}
    nonce_sources = {method: NonceSource() for method in SYMMETRIC_METHODS}
    for method in SYMMETRIC_METHODS:
        for size in sizes:
            payload = payloads[size]
            cipher = symmetric_cipher(method, keys[method])
            nonce_source = nonce_sources[method]
            representative_nonce = nonce_source.next()
            representative_ct_tag = cipher.encrypt(
                representative_nonce, payload, SYMMETRIC_AAD
            )
            representative_overhead = symmetric_overhead_details(
                payload, representative_nonce, representative_ct_tag
            )

            encrypt_operation = lambda: (
                lambda nonce: (nonce, cipher.encrypt(nonce, payload, SYMMETRIC_AAD))
            )(nonce_source.next())
            encryption_operations = calibrate_operations(encrypt_operation)

            decrypt_template = (representative_nonce, representative_ct_tag)
            decrypt_operation = lambda: cipher.decrypt(
                decrypt_template[0], decrypt_template[1], SYMMETRIC_AAD
            )
            decryption_operations = calibrate_operations(decrypt_operation)
            decryption_inputs = []
            for _ in range(decryption_operations):
                nonce = nonce_source.next()
                ciphertext_and_tag = cipher.encrypt(nonce, payload, SYMMETRIC_AAD)
                decryption_inputs.append((nonce, ciphertext_and_tag))

            states[(method, size)] = SymmetricState(
                method=method,
                payload=payload,
                cipher=cipher,
                encryption_nonce_source=nonce_source,
                encryption_operations=encryption_operations,
                decryption_operations=decryption_operations,
                decryption_inputs=decryption_inputs,
                overhead=representative_overhead,
            )
    return states


def prepare_hybrid_states(
    payloads: dict[int, bytes],
    sizes: tuple[int, ...],
    keypairs: dict[str, tuple[Any, Any]],
) -> dict[tuple[str, int], HybridState]:
    states: dict[tuple[str, int], HybridState] = {}
    for method in HYBRID_METHODS:
        recipient_private, recipient_public = keypairs[method]
        for size in sizes:
            payload = payloads[size]
            nonce_source = NonceSource()
            key_operation = lambda: build_hybrid_sender_context(method, recipient_public)
            key_step_operations = calibrate_operations(key_operation)
            round_trip_operation = lambda: hybrid_roundtrip_operation(
                method,
                payload,
                recipient_private,
                recipient_public,
                nonce_source,
            )
            round_trip_operations = calibrate_operations(round_trip_operation)
            representative = round_trip_operation()
            if representative.plaintext != payload:
                raise RuntimeError(f"{method} representative round trip failed")
            if representative.sender_key != representative.receiver_key:
                raise RuntimeError(f"{method} representative keys did not match")
            if method != HYBRID_RSA and representative.shared_secrets_match is not True:
                raise RuntimeError(f"{method} representative shared secrets did not match")
            states[(method, size)] = HybridState(
                method=method,
                payload=payload,
                recipient_private=recipient_private,
                recipient_public=recipient_public,
                nonce_source=nonce_source,
                key_step_operations=key_step_operations,
                round_trip_operations=round_trip_operations,
                overhead=hybrid_overhead_details(representative.envelope, len(payload)),
            )
    return states


def prepare_hash_operations(
    payloads: dict[int, bytes], sizes: tuple[int, ...]
) -> dict[tuple[str, int], tuple[Callable[[], bytes], int]]:
    operations: dict[tuple[str, int], tuple[Callable[[], bytes], int]] = {}
    for method in HASH_METHODS:
        for size in sizes:
            payload = payloads[size]
            operation = lambda method=method, payload=payload: hash_digest(method, payload)
            operations[(method, size)] = (operation, calibrate_operations(operation))
    return operations


def warm_up(
    sizes: tuple[int, ...], warmup_batches: int, seed: int,
    hash_operations: dict[tuple[str, int], tuple[Callable[[], bytes], int]],
    symmetric_states: dict[tuple[str, int], SymmetricState],
    hybrid_states: dict[tuple[str, int], HybridState],
) -> None:
    for method, size in build_warmup_order(seed, sizes, warmup_batches):
        if method in HASH_METHODS:
            operation, count = hash_operations[(method, size)]
            untimed_batch(operation, count)
        elif method in SYMMETRIC_METHODS:
            state = symmetric_states[(method, size)]
            encrypt = lambda: (
                lambda nonce: (nonce, state.cipher.encrypt(nonce, state.payload, SYMMETRIC_AAD))
            )(state.encryption_nonce_source.next())
            decrypt = lambda: state.cipher.decrypt(
                state.decryption_inputs[0][0], state.decryption_inputs[0][1], SYMMETRIC_AAD
            )
            untimed_batch(encrypt, state.encryption_operations)
            untimed_batch(decrypt, state.decryption_operations)
        else:
            state = hybrid_states[(method, size)]
            key_operation = lambda: build_hybrid_sender_context(method, state.recipient_public)
            round_trip = lambda: hybrid_roundtrip_operation(
                method,
                state.payload,
                state.recipient_private,
                state.recipient_public,
                state.nonce_source,
            )
            untimed_batch(key_operation, state.key_step_operations)
            untimed_batch(round_trip, state.round_trip_operations)


def empty_row(
    run_id: str,
    profile: str,
    method: str,
    size: int,
    trial: int,
    position: int,
    payload: bytes,
    overhead: dict[str, int],
) -> dict[str, Any]:
    observation_id = f"{run_id}|trial-{trial:03d}|position-{position:03d}"
    row: dict[str, Any] = {field: "" for field in RAW_FIELDS}
    row.update(
        {
            "run_id": run_id,
            "profile": profile,
            "family": FAMILY_BY_METHOD[method],
            "method": method,
            "input_size_bytes": size,
            "input_file": INPUT_FILENAMES[size],
            "input_identifier_sha256": input_identifier(payload),
            "trial": trial,
            "order_position": position,
            "observation_id": observation_id,
            "primary_metric": PRIMARY_METRIC_BY_METHOD[method],
            **overhead,
        }
    )
    return row


def collect(
    profile: str,
    output_dir: Path,
    seed: int,
    project_root: Path,
) -> tuple[Path, Path]:
    sizes, warmup_batches, measured_batches = expected_profile(profile)
    raw_path = output_dir / "benchmark.csv"
    metadata_path = output_dir / "benchmark_metadata.json"
    prepare_output_dir(output_dir, (raw_path.name, metadata_path.name))

    payloads = load_inputs(project_root, sizes)
    keypairs = recipient_keypairs()
    hash_operations = prepare_hash_operations(payloads, sizes)
    symmetric_states = prepare_symmetric_states(payloads, sizes)
    hybrid_states = prepare_hybrid_states(payloads, sizes, keypairs)

    warm_up(sizes, warmup_batches, seed, hash_operations, symmetric_states, hybrid_states)

    run_id = f"{profile}_{datetime_stamp()}_{uuid.uuid4().hex[:8]}"
    rows: list[dict[str, Any]] = []
    execution_order: list[dict[str, Any]] = []
    all_conditions = len(ALL_METHODS) * len(sizes)

    for trial in range(1, measured_batches + 1):
        order = build_condition_order(seed, trial, sizes)
        execution_order.append(
            {
                "trial": trial,
                "conditions": [f"{method}|{size}" for method, size in order],
            }
        )
        if len(order) != all_conditions:
            raise RuntimeError("measurement order did not contain every condition")

        for position, (method, size) in enumerate(order, start=1):
            if method in HASH_METHODS:
                operation, operations = hash_operations[(method, size)]
                payload = payloads[size]
                row = empty_row(run_id, profile, method, size, trial, position, payload, {
                    "digest_bytes": len(operation()),
                    "ciphertext_bytes": 0,
                    "nonce_bytes": 0,
                    "tag_bytes": 0,
                    "wrapped_key_bytes": 0,
                    "transmitted_public_key_bytes": 0,
                    "hkdf_salt_bytes": 0,
                    "framing_bytes": 0,
                    "aad_bytes": 0,
                    "serialized_envelope_bytes": len(operation()),
                    "overhead_bytes": 0,
                })
                elapsed, last_digest = timed_batch(operation, operations)
                if last_digest != operation():
                    raise RuntimeError(f"{method} validation failed after measurement")
                set_metric(row, "hash", elapsed, operations)
                row["primary_elapsed_ns"] = row["hash_elapsed_ns"]
                row["primary_operations_per_batch"] = row["hash_operations_per_batch"]
                row["primary_ns_per_operation"] = row["hash_ns_per_operation"]
            elif method in SYMMETRIC_METHODS:
                state = symmetric_states[(method, size)]
                row = empty_row(run_id, profile, method, size, trial, position, state.payload, state.overhead)
                encrypt = lambda: (
                    lambda nonce: (nonce, state.cipher.encrypt(nonce, state.payload, SYMMETRIC_AAD))
                )(state.encryption_nonce_source.next())
                decrypt = lambda: state.cipher.decrypt(
                    state.decryption_inputs[0][0], state.decryption_inputs[0][1], SYMMETRIC_AAD
                )
                enc_elapsed, last_encrypted = timed_batch(encrypt, state.encryption_operations)
                if not isinstance(last_encrypted, tuple) or len(last_encrypted[1]) < 16:
                    raise RuntimeError(f"{method} encryption validation failed")
                state.cipher.decrypt(last_encrypted[0], last_encrypted[1], SYMMETRIC_AAD)
                dec_elapsed, last_plaintext = timed_batch(decrypt, state.decryption_operations)
                if last_plaintext != state.payload:
                    raise RuntimeError(f"{method} valid decryption validation failed")
                set_metric(row, "encryption", enc_elapsed, state.encryption_operations)
                set_metric(row, "valid_decryption", dec_elapsed, state.decryption_operations)
                row["primary_elapsed_ns"] = row["encryption_elapsed_ns"]
                row["primary_operations_per_batch"] = row["encryption_operations_per_batch"]
                row["primary_ns_per_operation"] = row["encryption_ns_per_operation"]
            else:
                state = hybrid_states[(method, size)]
                row = empty_row(run_id, profile, method, size, trial, position, state.payload, state.overhead)
                key_operation = lambda: build_hybrid_sender_context(method, state.recipient_public)
                round_trip = lambda: hybrid_roundtrip_operation(
                    method,
                    state.payload,
                    state.recipient_private,
                    state.recipient_public,
                    state.nonce_source,
                )
                key_elapsed, last_context = timed_batch(key_operation, state.key_step_operations)
                if not getattr(last_context, "aes_key", b""):
                    raise RuntimeError(f"{method} key-step validation failed")
                round_elapsed, last_round_trip = timed_batch(round_trip, state.round_trip_operations)
                if last_round_trip.plaintext != state.payload:
                    raise RuntimeError(f"{method} round-trip plaintext validation failed")
                if last_round_trip.sender_key != last_round_trip.receiver_key:
                    raise RuntimeError(f"{method} round-trip key agreement validation failed")
                if method != HYBRID_RSA and last_round_trip.shared_secrets_match is not True:
                    raise RuntimeError(f"{method} shared-secret validation failed")
                set_metric(row, "key_step", key_elapsed, state.key_step_operations)
                set_metric(row, "full_round_trip", round_elapsed, state.round_trip_operations)
                row["primary_elapsed_ns"] = row["full_round_trip_elapsed_ns"]
                row["primary_operations_per_batch"] = row["full_round_trip_operations_per_batch"]
                row["primary_ns_per_operation"] = row["full_round_trip_ns_per_operation"]
            rows.append(row)

    expected_rows = len(ALL_METHODS) * len(sizes) * measured_batches
    if len(rows) != expected_rows:
        raise RuntimeError(f"expected {expected_rows} measured rows, generated {len(rows)}")

    execution_order_json = json.dumps(execution_order, sort_keys=True).encode("utf-8")
    metadata = {
        "experiment": "A1 Security in Computing nine-method data-protection benchmark",
        "research_title": "Evaluating Cryptographic Data Protection: File-Size Effects, Tamper Detection, and Trust Assumptions",
        "profile": profile,
        "status": "complete",
        "run_id": run_id,
        "random_seed": seed,
        "input_sizes_bytes": list(sizes),
        "methods": list(ALL_METHODS),
        "families": {family: [method for method in ALL_METHODS if FAMILY_BY_METHOD[method] == family] for family in ("hashing", "symmetric", "hybrid")},
        "warmup_batches_per_method_size": warmup_batches,
        "measured_batches_per_method_size": measured_batches,
        "expected_measured_rows": expected_rows,
        "measured_rows": len(rows),
        "statistical_unit": "one row per method, input size, and measured batch; operations within a batch are normalized but not independent observations",
        "timing_clock": "time.perf_counter_ns()",
        "calibration_target_ns": CALIBRATION_TARGET_NS,
        "max_operations_per_batch": 4_096,
        "measurement_order": execution_order,
        "measurement_order_sha256": hashlib.sha256(execution_order_json).hexdigest(),
        "input_generation": "existing local synthetic binary fixtures in data/inputs; same bytes reused across methods at each size; file reads are outside timed regions",
        "validation": "all measured valid operations are checked after their timers stop; validation and CSV writing are outside timed regions",
        "key_provisioning": {
            "symmetric": "one fresh 32-byte key per method per run, generated before calibration and measurement",
            "rsa": "one RSA-3072 recipient key pair provisioned before measurement; sender creates a fresh 32-byte AES key per message and transmits the RSA-OAEP wrapped key",
            "x25519": "one static recipient X25519 key pair provisioned before measurement; sender creates a fresh ephemeral key pair and 32-byte HKDF salt per message and transmits the raw 32-byte ephemeral public key and salt",
            "ffdhe": "one static recipient RFC 7919 ffdhe3072 key pair provisioned before measurement; sender creates a fresh ephemeral key pair and 32-byte HKDF salt per message and transmits the 384-byte fixed-width ephemeral public value and salt",
        },
        "hybrid_payload_format": "version(1) || scheme_id(1) || key_material_length(2) || salt_length(1) || key_material || salt || nonce(12) || ciphertext || tag(16)",
        "hybrid_aad_policy": "A1-Crypto-Data-Protection/Hybrid/v1\\x00 followed by the common versioned header; the same construction is used for RSA, X25519, and FFDHE",
        "symmetric_aad_policy": SYMMETRIC_AAD.decode("ascii"),
        "nonce_policy": "12-byte nonces use a random per-key 4-byte prefix plus a monotonically increasing 8-byte counter; nonce prefixes are created outside timers and every timed encryption/round-trip operation receives a new nonce",
        "timed_metrics": {
            "hash_digest_generation": "hash function call over the in-memory payload",
            "symmetric_encryption": "per-message nonce counter step plus AEAD encryption; key setup, payload preparation, validation, and output writing are excluded",
            "symmetric_valid_decryption": "valid AEAD decryption of prebuilt envelopes; envelope preparation, validation after timing, and output writing are excluded",
            "hybrid_key_step": "RSA fresh AES-key generation plus OAEP wrapping, or fresh ephemeral/salt generation plus key agreement, public serialization, and HKDF; file AES-GCM is excluded",
            "hybrid_full_valid_round_trip": "fresh sender key step, nonce, common-envelope AAD construction, AES-GCM encryption, recipient key recovery/agreement and HKDF, and valid AES-GCM decryption; fixture I/O and post-timer validation are excluded",
        },
        "recipient_public_key_sha256": {
            method: public_key_fingerprint(method, public_key)
            for method, (_, public_key) in keypairs.items()
        },
        "environment": environment_metadata(),
        "created_utc": utc_now(),
        "raw_csv": str(raw_path),
    }
    write_csv(raw_path, RAW_FIELDS, rows)
    write_json(metadata_path, metadata)
    return raw_path, metadata_path


def datetime_stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the nine A1 cryptographic configurations.")
    parser.add_argument("--profile", choices=("smoke", "full"), required=True)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()

    seed = args.seed if args.seed is not None else secrets.randbits(64)
    output_dir = args.output_dir or (
        Path("data") / "runs" / f"benchmark_{args.profile}_{datetime_stamp()}"
    )
    try:
        raw_path, metadata_path = collect(
            args.profile,
            output_dir,
            seed,
            Path(__file__).resolve().parent,
        )
    except Exception as error:
        print(f"benchmark failed: {type(error).__name__}: {error}", file=sys.stderr)
        if args.profile == "smoke":
            print("Smoke profile failed; no benchmark CSV was written.", file=sys.stderr)
        raise
    print(f"Benchmark CSV: {raw_path}")
    print(f"Metadata JSON: {metadata_path}")
    print(f"Profile: {args.profile}; seed: {seed}")


if __name__ == "__main__":
    main()


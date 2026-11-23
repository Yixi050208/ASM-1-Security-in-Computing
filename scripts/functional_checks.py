"""Run non-timing functional checks for the nine core methods and HMAC control."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import sys
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidTag

from experiment_common import (
    ALL_METHODS,
    FAMILY_BY_METHOD,
    HASH_METHODS,
    HMAC_CONTROL,
    HYBRID_FFDHE,
    HYBRID_METHODS,
    HYBRID_RSA,
    HYBRID_X25519,
    INPUT_SIZES,
    SYMMETRIC_AAD,
    SYMMETRIC_METHODS,
    NonceSource,
    decrypt_hybrid,
    environment_metadata,
    flip_first_byte,
    hash_digest,
    hybrid_roundtrip_operation,
    load_inputs,
    prepare_output_dir,
    recipient_keypairs,
    safe_exception_category,
    symmetric_cipher,
    generate_symmetric_key,
    utc_now,
    verify_hmac,
    write_csv,
    write_json,
)


CSV_FIELDS = (
    "run_id",
    "family",
    "method",
    "input_size_bytes",
    "scenario",
    "expected_accepted",
    "observed_accepted",
    "expected_plaintext_returned",
    "observed_plaintext_returned",
    "expected_tampering_detected",
    "observed_tampering_detected",
    "key_establishment_inputs_held_constant",
    "shared_aes_key_matches",
    "verification_layer",
    "exception_category",
    "expected_outcome",
    "observed_outcome",
    "outcome_matches_expected",
    "notes",
)


def timestamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def attempt(call: Callable[[], bytes]) -> tuple[bool, bytes | None, str]:
    try:
        plaintext = call()
    except Exception as error:  # controlled functional checks record the public outcome
        return False, None, safe_exception_category(error)
    return True, plaintext, ""


def add_case(
    rows: list[dict[str, Any]],
    *,
    run_id: str,
    family: str,
    method: str,
    size: int,
    scenario: str,
    expected_accepted: bool,
    observed_accepted: bool,
    expected_plaintext_returned: bool,
    observed_plaintext_returned: bool,
    expected_tampering_detected: bool,
    observed_tampering_detected: bool,
    key_establishment_inputs_held_constant: bool | str = "",
    shared_aes_key_matches: bool | str = "",
    verification_layer: str,
    exception_category: str = "",
    notes: str = "",
) -> None:
    expected_outcome = "accepted" if expected_accepted else "rejected"
    observed_outcome = "accepted" if observed_accepted else "rejected"
    matched = (
        expected_accepted == observed_accepted
        and expected_plaintext_returned == observed_plaintext_returned
        and expected_tampering_detected == observed_tampering_detected
    )
    if not matched:
        raise RuntimeError(
            f"functional outcome mismatch: {method}/{size}/{scenario}; "
            f"expected {expected_outcome}, observed {observed_outcome}"
        )
    rows.append(
        {
            "run_id": run_id,
            "family": family,
            "method": method,
            "input_size_bytes": size,
            "scenario": scenario,
            "expected_accepted": expected_accepted,
            "observed_accepted": observed_accepted,
            "expected_plaintext_returned": expected_plaintext_returned,
            "observed_plaintext_returned": observed_plaintext_returned,
            "expected_tampering_detected": expected_tampering_detected,
            "observed_tampering_detected": observed_tampering_detected,
            "key_establishment_inputs_held_constant": key_establishment_inputs_held_constant,
            "shared_aes_key_matches": shared_aes_key_matches,
            "verification_layer": verification_layer,
            "exception_category": exception_category,
            "expected_outcome": expected_outcome,
            "observed_outcome": observed_outcome,
            "outcome_matches_expected": matched,
            "notes": notes,
        }
    )


def run_hash_checks(rows: list[dict[str, Any]], run_id: str, payloads: dict[int, bytes]) -> None:
    replacement = b"local synthetic replacement payload"
    for method in HASH_METHODS:
        for size, original in payloads.items():
            trusted_digest = hash_digest(method, original)
            modified = flip_first_byte(original)
            modified_digest = hash_digest(method, modified)
            replacement_digest = hash_digest(method, replacement)

            add_case(
                rows,
                run_id=run_id,
                family="hashing",
                method=method,
                size=size,
                scenario="unchanged_against_trusted_digest",
                expected_accepted=True,
                observed_accepted=hash_digest(method, original) == trusted_digest,
                expected_plaintext_returned=False,
                observed_plaintext_returned=False,
                expected_tampering_detected=False,
                observed_tampering_detected=False,
                verification_layer="trusted digest comparison",
                notes=f"digest_bytes={len(trusted_digest)}",
            )
            add_case(
                rows,
                run_id=run_id,
                family="hashing",
                method=method,
                size=size,
                scenario="one_bit_modified_against_trusted_digest",
                expected_accepted=False,
                observed_accepted=modified_digest == trusted_digest,
                expected_plaintext_returned=False,
                observed_plaintext_returned=False,
                expected_tampering_detected=True,
                observed_tampering_detected=modified_digest != trusted_digest,
                verification_layer="trusted digest comparison",
                notes="first payload byte modified by one bit",
            )
            add_case(
                rows,
                run_id=run_id,
                family="hashing",
                method=method,
                size=size,
                scenario="replacement_with_unprotected_digest",
                expected_accepted=True,
                observed_accepted=replacement_digest == hash_digest(method, replacement),
                expected_plaintext_returned=False,
                observed_plaintext_returned=False,
                expected_tampering_detected=False,
                observed_tampering_detected=False,
                verification_layer="attacker-supplied unprotected digest",
                notes="acceptance shows that replacing both file and ordinary digest defeats this decision rule",
            )
            add_case(
                rows,
                run_id=run_id,
                family="hashing",
                method=method,
                size=size,
                scenario="replacement_against_protected_digest",
                expected_accepted=False,
                observed_accepted=replacement_digest == trusted_digest,
                expected_plaintext_returned=False,
                observed_plaintext_returned=False,
                expected_tampering_detected=True,
                observed_tampering_detected=replacement_digest != trusted_digest,
                verification_layer="protected trusted digest comparison",
                notes="protected means the original digest is assumed authentic and not replaced",
            )


def run_symmetric_checks(rows: list[dict[str, Any]], run_id: str, payloads: dict[int, bytes]) -> None:
    keys = {method: generate_symmetric_key(method) for method in SYMMETRIC_METHODS}
    nonce_sources = {method: NonceSource() for method in SYMMETRIC_METHODS}
    for method in SYMMETRIC_METHODS:
        cipher = symmetric_cipher(method, keys[method])
        for size, payload in payloads.items():
            nonce = nonce_sources[method].next()
            ciphertext_and_tag = cipher.encrypt(nonce, payload, SYMMETRIC_AAD)
            valid_accepted, valid_plaintext, valid_error = attempt(
                lambda: cipher.decrypt(nonce, ciphertext_and_tag, SYMMETRIC_AAD)
            )
            add_case(
                rows,
                run_id=run_id,
                family="symmetric",
                method=method,
                size=size,
                scenario="valid_control",
                expected_accepted=True,
                observed_accepted=valid_accepted and valid_plaintext == payload,
                expected_plaintext_returned=True,
                observed_plaintext_returned=valid_plaintext is not None,
                expected_tampering_detected=False,
                observed_tampering_detected=False,
                verification_layer="AEAD decryption",
                exception_category=valid_error,
                notes=f"nonce_bytes={len(nonce)}; tag_bytes=16",
            )

            tampered_ciphertext = flip_first_byte(ciphertext_and_tag[:-16]) + ciphertext_and_tag[-16:]
            tampered_accepted, tampered_plaintext, tampered_error = attempt(
                lambda: cipher.decrypt(nonce, tampered_ciphertext, SYMMETRIC_AAD)
            )
            add_case(
                rows,
                run_id=run_id,
                family="symmetric",
                method=method,
                size=size,
                scenario="one_bit_ciphertext_change",
                expected_accepted=False,
                observed_accepted=tampered_accepted,
                expected_plaintext_returned=False,
                observed_plaintext_returned=tampered_plaintext is not None,
                expected_tampering_detected=True,
                observed_tampering_detected=not tampered_accepted,
                verification_layer="AEAD payload authentication",
                exception_category=tampered_error,
                notes="one ciphertext bit changed; the tag and associated data were retained",
            )


def run_hybrid_checks(rows: list[dict[str, Any]], run_id: str, payloads: dict[int, bytes]) -> None:
    keypairs = recipient_keypairs()
    for method in HYBRID_METHODS:
        recipient_private, recipient_public = keypairs[method]
        nonce_source = NonceSource()
        for size, payload in payloads.items():
            result = hybrid_roundtrip_operation(
                method, payload, recipient_private, recipient_public, nonce_source
            )
            valid_accepted, valid_plaintext, valid_error = attempt(
                lambda result=result: decrypt_hybrid(result.envelope, recipient_private)
            )
            key_match = result.sender_key == result.receiver_key
            shared_match: bool | str = (
                result.shared_secrets_match if method != HYBRID_RSA else "not_applicable"
            )
            add_case(
                rows,
                run_id=run_id,
                family="hybrid",
                method=method,
                size=size,
                scenario="valid_key_and_payload_round_trip",
                expected_accepted=True,
                observed_accepted=valid_accepted and valid_plaintext == payload and key_match,
                expected_plaintext_returned=True,
                observed_plaintext_returned=valid_plaintext is not None,
                expected_tampering_detected=False,
                observed_tampering_detected=False,
                key_establishment_inputs_held_constant=True,
                shared_aes_key_matches=key_match,
                verification_layer="hybrid key establishment plus shared AES-GCM",
                exception_category=valid_error,
                notes=f"shared_secrets_match={shared_match}",
            )

            tampered_envelope = replace(
                result.envelope,
                ciphertext=flip_first_byte(result.envelope.ciphertext),
            )
            tampered_accepted, tampered_plaintext, tampered_error = attempt(
                lambda: decrypt_hybrid(tampered_envelope, recipient_private)
            )
            add_case(
                rows,
                run_id=run_id,
                family="hybrid",
                method=method,
                size=size,
                scenario="one_bit_aes_gcm_payload_change",
                expected_accepted=False,
                observed_accepted=tampered_accepted,
                expected_plaintext_returned=False,
                observed_plaintext_returned=tampered_plaintext is not None,
                expected_tampering_detected=True,
                observed_tampering_detected=not tampered_accepted,
                key_establishment_inputs_held_constant=True,
                shared_aes_key_matches=key_match,
                verification_layer="shared AES-GCM payload authentication",
                exception_category=tampered_error,
                notes="only ciphertext changed; nonce, tag, AAD, salt, and transmitted key material were held constant",
            )


def run_hmac_control(rows: list[dict[str, Any]], run_id: str, payload: bytes) -> None:
    key = secrets.token_bytes(32)
    original_tag = hmac.new(key, payload, hashlib.sha256).digest()
    modified = flip_first_byte(payload)
    replacement = b"local synthetic replacement payload"
    replacement_digest = hashlib.sha256(replacement).digest()
    trusted_digest = hashlib.sha256(payload).digest()

    cases = (
        (
            "valid_hmac_reference",
            True,
            verify_hmac(key, payload, original_tag),
            False,
            False,
            "protected HMAC key and tag",
        ),
        (
            "modified_file_against_protected_hmac",
            False,
            verify_hmac(key, modified, original_tag),
            True,
            not verify_hmac(key, modified, original_tag),
            "protected HMAC key and original tag",
        ),
        (
            "replacement_file_with_unprotected_digest",
            True,
            replacement_digest == hashlib.sha256(replacement).digest(),
            False,
            False,
            "attacker-supplied unprotected SHA-256 digest",
        ),
        (
            "replacement_file_against_protected_digest",
            False,
            replacement_digest == trusted_digest,
            True,
            replacement_digest != trusted_digest,
            "protected original SHA-256 digest",
        ),
    )
    for scenario, expected, observed, expected_tamper, observed_tamper, layer in cases:
        add_case(
            rows,
            run_id=run_id,
            family="supplemental_control",
            method=HMAC_CONTROL,
            size=len(payload),
            scenario=scenario,
            expected_accepted=expected,
            observed_accepted=observed,
            expected_plaintext_returned=False,
            observed_plaintext_returned=False,
            expected_tampering_detected=expected_tamper,
            observed_tampering_detected=observed_tamper,
            verification_layer=layer,
            notes="HMAC is outside the nine-method timing benchmark",
        )


def collect(output_dir: Path, project_root: Path) -> tuple[Path, Path]:
    csv_path = output_dir / "functional_checks.csv"
    metadata_path = output_dir / "functional_checks_metadata.json"
    prepare_output_dir(output_dir, (csv_path.name, metadata_path.name))
    payloads = load_inputs(project_root, INPUT_SIZES)
    run_id = f"functional_{timestamp()}_{uuid.uuid4().hex[:8]}"
    rows: list[dict[str, Any]] = []
    run_hash_checks(rows, run_id, payloads)
    run_symmetric_checks(rows, run_id, payloads)
    run_hybrid_checks(rows, run_id, payloads)
    run_hmac_control(rows, run_id, payloads[1_024])

    expected_core_cases = (3 * 5 * 4) + (3 * 5 * 2) + (3 * 5 * 2)
    expected_total = expected_core_cases + 4
    if len(rows) != expected_total:
        raise RuntimeError(f"expected {expected_total} functional rows, generated {len(rows)}")
    if not all(row["outcome_matches_expected"] for row in rows):
        raise RuntimeError("functional checks contain an unexpected outcome")

    metadata = {
        "experiment": "local synthetic functional verification checks",
        "status": "complete",
        "run_id": run_id,
        "methods": list(ALL_METHODS),
        "supplemental_control": HMAC_CONTROL,
        "input_sizes_bytes": list(INPUT_SIZES),
        "expected_rows": expected_total,
        "observed_rows": len(rows),
        "all_outcomes_match_expected": True,
        "timing": "not measured",
        "hybrid_tamper_policy": "flip one ciphertext bit while holding key-establishment inputs constant; rejection is attributed to the shared AES-GCM layer",
        "ffdhe_group": "RFC 7919 ffdhe3072, g=2, exact 3072-bit modulus in scripts/experiment_common.py",
        "environment": environment_metadata(),
        "created_utc": utc_now(),
        "raw_csv": str(csv_path),
    }
    write_csv(csv_path, CSV_FIELDS, rows)
    write_json(metadata_path, metadata)
    return csv_path, metadata_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run functional checks for the A1 crypto suite.")
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()
    output_dir = args.output_dir or Path("data") / "runs" / f"functional_{timestamp()}"
    try:
        csv_path, metadata_path = collect(output_dir, Path(__file__).resolve().parent)
    except Exception as error:
        print(f"functional checks failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise
    print(f"Functional CSV: {csv_path}")
    print(f"Metadata JSON: {metadata_path}")
    print("All expected outcomes matched.")


if __name__ == "__main__":
    main()


"""Validate benchmark output and produce descriptive/statistical analysis.

The reportable primary analysis is a separate one-factor repeated-measures
ANOVA for each method.  The measured batch is the observation and trial is the
within-run block, so independent-groups ANOVA is not applied to the blocked
collection design.  Smoke and pilot profiles receive descriptive output only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from benchmark import RAW_FIELDS
from experiment_common import (
    ALL_METHODS,
    FAMILY_BY_METHOD,
    FULL_MEASURED_BATCHES,
    HASH_METHODS,
    HYBRID_FFDHE,
    HYBRID_METHODS,
    HYBRID_RSA,
    HYBRID_X25519,
    PRIMARY_METRIC_BY_METHOD,
    SYMMETRIC_METHODS,
    expected_profile,
    write_csv,
    write_json,
)
from functional_checks import CSV_FIELDS as FUNCTIONAL_FIELDS


DESCRIPTIVE_FIELDS = (
    "family",
    "method",
    "input_size_bytes",
    "metric",
    "n",
    "mean_ns_per_operation",
    "median_ns_per_operation",
    "sample_stdev_ns_per_operation",
    "minimum_ns_per_operation",
    "maximum_ns_per_operation",
)
STAT_FIELDS = (
    "family",
    "method",
    "primary_metric",
    "test_used",
    "sample_size_per_input_size",
    "blocks",
    "input_size_levels",
    "statistic_f",
    "uncorrected_df_num",
    "uncorrected_df_den",
    "gg_epsilon",
    "df_num",
    "df_den",
    "partial_eta_squared",
    "raw_p_value",
    "holm_adjusted_p_value",
    "mean_first_size_ns_per_operation",
    "mean_last_size_ns_per_operation",
    "difference_last_minus_first_ns_per_operation",
    "percentage_difference_last_minus_first",
    "analysis_status",
    "interpretation_note",
)
ORDER_FIELDS = (
    "family",
    "method",
    "diagnostic",
    "observations",
    "statistic",
    "absolute_statistic",
    "interpretation",
)
OVERHEAD_FIELDS = (
    "family",
    "method",
    "input_size_bytes",
    "payload_bytes",
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
MATRIX_FIELDS = (
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
    "outcome_matches_expected",
)


def timestamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def read_csv(path: Path, expected_fields: tuple[str, ...]) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != expected_fields:
            raise ValueError(
                f"{path} has unexpected columns; expected exactly {expected_fields}"
            )
        rows = list(reader)
    if not rows:
        raise ValueError(f"{path} contains no rows")
    return rows


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def as_int(row: dict[str, str], field: str) -> int:
    try:
        return int(row[field])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"invalid integer in {field}: {row.get(field)!r}") from error


def as_float(row: dict[str, str], field: str) -> float:
    try:
        value = float(row[field])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"invalid number in {field}: {row.get(field)!r}") from error
    if not math.isfinite(value):
        raise ValueError(f"non-finite number in {field}: {value!r}")
    return value


def as_bool(value: str, field: str) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"{field} must be True or False, got {value!r}")


def expected_overhead(method: str, payload_size: int) -> dict[str, int]:
    if method in HASH_METHODS:
        digest_bytes = 64 if method == "SHA-512" else 32
        return {
            "digest_bytes": digest_bytes,
            "ciphertext_bytes": 0,
            "nonce_bytes": 0,
            "tag_bytes": 0,
            "wrapped_key_bytes": 0,
            "transmitted_public_key_bytes": 0,
            "hkdf_salt_bytes": 0,
            "framing_bytes": 0,
            "aad_bytes": 0,
            "serialized_envelope_bytes": digest_bytes,
            "overhead_bytes": 0,
        }
    if method in SYMMETRIC_METHODS:
        return {
            "digest_bytes": 0,
            "ciphertext_bytes": payload_size,
            "nonce_bytes": 12,
            "tag_bytes": 16,
            "wrapped_key_bytes": 0,
            "transmitted_public_key_bytes": 0,
            "hkdf_salt_bytes": 0,
            "framing_bytes": 0,
            "aad_bytes": 38,
            "serialized_envelope_bytes": payload_size + 28,
            "overhead_bytes": 28,
        }
    if method == HYBRID_RSA:
        key_bytes, salt_bytes = 384, 0
    elif method == HYBRID_X25519:
        key_bytes, salt_bytes = 32, 32
    elif method == HYBRID_FFDHE:
        key_bytes, salt_bytes = 384, 32
    else:
        raise ValueError(method)
    # Header framing is version(1), scheme id(1), key length(2), salt length(1).
    overhead = 5 + key_bytes + salt_bytes + 12 + 16
    return {
        "digest_bytes": 0,
        "ciphertext_bytes": payload_size,
        "nonce_bytes": 12,
        "tag_bytes": 16,
        "wrapped_key_bytes": key_bytes if method == HYBRID_RSA else 0,
        "transmitted_public_key_bytes": key_bytes if method != HYBRID_RSA else 0,
        "hkdf_salt_bytes": salt_bytes,
        "framing_bytes": 5,
        "aad_bytes": 36 + 5 + key_bytes + salt_bytes,
        "serialized_envelope_bytes": payload_size + overhead,
        "overhead_bytes": overhead,
    }


def validate_benchmark(rows: list[dict[str, str]], metadata: dict[str, Any], expected: str | None) -> dict[str, Any]:
    profile = metadata.get("profile")
    if profile not in {"smoke", "full"}:
        raise ValueError(f"unsupported benchmark profile: {profile!r}")
    if expected is not None and profile != expected:
        raise ValueError(f"expected profile {expected!r}, found {profile!r}")
    sizes = tuple(int(value) for value in metadata.get("input_sizes_bytes", []))
    metadata_methods = tuple(metadata.get("methods", []))
    if metadata_methods != ALL_METHODS:
        raise ValueError("benchmark metadata does not list exactly the nine expected methods")
    if not sizes or len(set(sizes)) != len(sizes):
        raise ValueError("metadata input sizes are empty or duplicated")
    measured_batches = int(metadata.get("measured_batches_per_method_size", 0))
    warmup_batches = int(metadata.get("warmup_batches_per_method_size", 0))
    if measured_batches <= 0 or warmup_batches < 0:
        raise ValueError("invalid warm-up or measured batch counts")
    expected_rows = len(ALL_METHODS) * len(sizes) * measured_batches
    if len(rows) != expected_rows or int(metadata.get("measured_rows", -1)) != expected_rows:
        raise ValueError(f"expected {expected_rows} rows, found {len(rows)}")

    seen_observations: set[str] = set()
    seen_condition_trials: set[tuple[str, int, int]] = set()
    positions_by_trial: dict[int, set[int]] = defaultdict(set)
    input_ids_by_size: dict[int, set[str]] = defaultdict(set)
    values_by_method_size: dict[tuple[str, int], list[dict[str, str]]] = defaultdict(list)
    for row_number, row in enumerate(rows, start=2):
        method = row["method"]
        family = row["family"]
        size = as_int(row, "input_size_bytes")
        trial = as_int(row, "trial")
        position = as_int(row, "order_position")
        if method not in ALL_METHODS or FAMILY_BY_METHOD[method] != family:
            raise ValueError(f"row {row_number}: unexpected method/family {method}/{family}")
        if size not in sizes or trial not in range(1, measured_batches + 1):
            raise ValueError(f"row {row_number}: unexpected size or trial")
        if position not in range(1, len(ALL_METHODS) * len(sizes) + 1):
            raise ValueError(f"row {row_number}: invalid randomized position")
        observation_id = row["observation_id"]
        if not observation_id or observation_id in seen_observations:
            raise ValueError(f"row {row_number}: duplicate or empty observation_id")
        seen_observations.add(observation_id)
        key = (method, size, trial)
        if key in seen_condition_trials:
            raise ValueError(f"row {row_number}: duplicate method/size/trial {key}")
        seen_condition_trials.add(key)
        if position in positions_by_trial[trial]:
            raise ValueError(f"row {row_number}: duplicate order position in trial {trial}")
        positions_by_trial[trial].add(position)
        if row["profile"] != profile:
            raise ValueError(f"row {row_number}: profile disagrees with metadata")
        if not row["input_identifier_sha256"]:
            raise ValueError(f"row {row_number}: missing input identifier")
        input_ids_by_size[size].add(row["input_identifier_sha256"])

        primary_elapsed = as_int(row, "primary_elapsed_ns")
        primary_operations = as_int(row, "primary_operations_per_batch")
        primary_normalized = as_float(row, "primary_ns_per_operation")
        if primary_elapsed <= 0 or primary_operations <= 0 or primary_normalized <= 0:
            raise ValueError(f"row {row_number}: primary timing must be positive")
        if not math.isclose(primary_normalized, primary_elapsed / primary_operations, rel_tol=1e-8, abs_tol=1e-6):
            raise ValueError(f"row {row_number}: primary normalized timing is inconsistent")
        if row["primary_metric"] != PRIMARY_METRIC_BY_METHOD[method]:
            raise ValueError(f"row {row_number}: wrong primary metric for {method}")

        required_metric_prefixes = {
            method: ("hash",) if method in HASH_METHODS else (
                "encryption", "valid_decryption"
            ) if method in SYMMETRIC_METHODS else ("key_step", "full_round_trip")
        }[method]
        for prefix in required_metric_prefixes:
            elapsed = as_int(row, f"{prefix}_elapsed_ns")
            operations = as_int(row, f"{prefix}_operations_per_batch")
            normalized = as_float(row, f"{prefix}_ns_per_operation")
            if elapsed <= 0 or operations <= 0 or normalized <= 0:
                raise ValueError(f"row {row_number}: {prefix} timing must be positive")
            if not math.isclose(normalized, elapsed / operations, rel_tol=1e-8, abs_tol=1e-6):
                raise ValueError(f"row {row_number}: {prefix} normalized timing is inconsistent")

        expected_bytes = expected_overhead(method, size)
        for field, expected_value in expected_bytes.items():
            observed = as_int(row, field)
            if observed != expected_value:
                raise ValueError(
                    f"row {row_number}: {field}={observed}, expected actual byte length {expected_value}"
                )
        values_by_method_size[(method, size)].append(row)

    expected_positions = set(range(1, len(ALL_METHODS) * len(sizes) + 1))
    if any(positions != expected_positions for positions in positions_by_trial.values()):
        raise ValueError("each trial must contain one randomized position for every condition")
    if any(len(identifiers) != 1 for identifiers in input_ids_by_size.values()):
        raise ValueError("the same input bytes must be reused for every method and trial at a size")
    recorded_order = metadata.get("measurement_order")
    if not isinstance(recorded_order, list) or len(recorded_order) != measured_batches:
        raise ValueError("metadata measurement_order is missing or incomplete")
    rows_by_trial = defaultdict(list)
    for row in rows:
        rows_by_trial[as_int(row, "trial")].append(row)
    for item in recorded_order:
        trial = int(item.get("trial", 0))
        expected_order = [
            f"{row['method']}|{row['input_size_bytes']}"
            for row in sorted(rows_by_trial[trial], key=lambda value: as_int(value, "order_position"))
        ]
        if item.get("conditions") != expected_order:
            raise ValueError(f"recorded execution order does not match CSV rows for trial {trial}")
    expected_conditions = len(ALL_METHODS) * len(sizes) * measured_batches
    if len(seen_condition_trials) != expected_conditions:
        raise ValueError("method/size/trial identifiers are not unique and complete")
    for key, condition_rows in values_by_method_size.items():
        if len(condition_rows) != measured_batches:
            raise ValueError(f"condition {key} has {len(condition_rows)} rows, expected {measured_batches}")
    if profile == "full" and expected_rows != 1_350:
        raise ValueError("full profile must contain exactly 1,350 rows")
    return {
        "profile": profile,
        "sizes": sizes,
        "measured_batches": measured_batches,
        "warmup_batches": warmup_batches,
        "row_count": len(rows),
        "conditions": len(ALL_METHODS) * len(sizes),
        "values_by_method_size": values_by_method_size,
    }


def validate_functional(rows: list[dict[str, str]], metadata: dict[str, Any]) -> dict[str, Any]:
    if tuple(metadata.get("methods", [])) != ALL_METHODS:
        raise ValueError("functional metadata does not list exactly the nine methods")
    if int(metadata.get("observed_rows", -1)) != len(rows):
        raise ValueError("functional metadata row count disagrees with CSV")
    for row_number, row in enumerate(rows, start=2):
        as_int(row, "input_size_bytes")
        for field in (
            "expected_accepted",
            "observed_accepted",
            "expected_plaintext_returned",
            "observed_plaintext_returned",
            "expected_tampering_detected",
            "observed_tampering_detected",
            "outcome_matches_expected",
        ):
            as_bool(row[field], field)
        if not as_bool(row["outcome_matches_expected"], "outcome_matches_expected"):
            raise ValueError(f"functional row {row_number} did not match its expected outcome")
        if (
            row["observed_accepted"] == "False"
            and row["observed_plaintext_returned"] == "True"
        ):
            raise ValueError(f"functional row {row_number} released plaintext after rejection")
    if not rows or not all(row["outcome_matches_expected"] == "True" for row in rows):
        raise ValueError("functional outcomes are incomplete")
    return {"row_count": len(rows), "all_outcomes_match_expected": True}


def mean(values: Iterable[float]) -> float:
    values = list(values)
    return statistics.fmean(values)


def descriptive_rows(validation: dict[str, Any]) -> list[dict[str, Any]]:
    metric_columns: dict[str, str] = {}
    for method in ALL_METHODS:
        if method in HASH_METHODS:
            metric_columns[method] = "hash_ns_per_operation"
        elif method in SYMMETRIC_METHODS:
            metric_columns[method] = "encryption_ns_per_operation"
        else:
            metric_columns[method] = "full_round_trip_ns_per_operation"
    rows: list[dict[str, Any]] = []
    for (method, size), condition_rows in sorted(validation["values_by_method_size"].items()):
        metrics = [metric_columns[method]]
        if method in SYMMETRIC_METHODS:
            metrics.append("valid_decryption_ns_per_operation")
        elif method in HYBRID_METHODS:
            metrics.append("key_step_ns_per_operation")
        for column in metrics:
            values = [as_float(row, column) for row in condition_rows]
            rows.append(
                {
                    "family": FAMILY_BY_METHOD[method],
                    "method": method,
                    "input_size_bytes": size,
                    "metric": column.removesuffix("_ns_per_operation"),
                    "n": len(values),
                    "mean_ns_per_operation": mean(values),
                    "median_ns_per_operation": statistics.median(values),
                    "sample_stdev_ns_per_operation": statistics.stdev(values) if len(values) > 1 else "",
                    "minimum_ns_per_operation": min(values),
                    "maximum_ns_per_operation": max(values),
                }
            )
    return rows


def betacf(a: float, b: float, x: float) -> float:
    max_iterations = 250
    epsilon = 3.0e-14
    fpmin = 1.0e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, max_iterations + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < epsilon:
            break
    return h


def regularized_beta(x: float, a: float, b: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_bt = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    bt = math.exp(log_bt)
    if x < (a + 1.0) / (a + b + 2.0):
        return max(0.0, min(1.0, bt * betacf(a, b, x) / a))
    return max(0.0, min(1.0, 1.0 - bt * betacf(b, a, 1.0 - x) / b))


def f_survival(f_value: float, df_num: float, df_den: float) -> float:
    if f_value <= 0.0:
        return 1.0
    x = df_den / (df_den + df_num * f_value)
    return regularized_beta(x, df_den / 2.0, df_num / 2.0)


def greenhouse_geisser_epsilon(values_by_size: list[list[float]]) -> float:
    """Estimate the Greenhouse--Geisser epsilon for the within-block factor.

    The benchmark has one observation per size in each trial block.  This
    covariance-based diagnostic is sufficient for the standard-library-only
    analyzer and lets the reported F test use corrected degrees of freedom
    when the sphericity assumption is not supported by the recorded data.
    """
    k = len(values_by_size)
    n = len(values_by_size[0]) if values_by_size else 0
    if k < 2 or n < 2 or any(len(values) != n for values in values_by_size):
        return 1.0
    subject_means = [
        mean(values_by_size[size][subject] for size in range(k))
        for subject in range(n)
    ]
    centered = [
        [values_by_size[size][subject] - subject_means[subject] for subject in range(n)]
        for size in range(k)
    ]
    covariance = [
        [
            sum(centered[i][subject] * centered[j][subject] for subject in range(n))
            / (n - 1)
            for j in range(k)
        ]
        for i in range(k)
    ]
    trace = sum(covariance[index][index] for index in range(k))
    trace_square = sum(value * value for row in covariance for value in row)
    if trace <= 0.0 or trace_square <= 0.0:
        return 1.0
    epsilon = (trace * trace) / ((k - 1) * trace_square)
    return max(1.0 / (k - 1), min(1.0, epsilon))


def repeated_measures_anova(
    values_by_size: list[list[float]],
) -> tuple[
    float | None,
    float | None,
    float,
    float,
    float,
    float,
    float,
    float | None,
]:
    k = len(values_by_size)
    n = len(values_by_size[0]) if values_by_size else 0
    uncorrected_df_num = float(k - 1)
    uncorrected_df_den = float(max(0, (n - 1) * (k - 1)))
    if k < 2 or n < 2 or any(len(values) != n for values in values_by_size):
        return (
            None,
            None,
            uncorrected_df_num,
            uncorrected_df_den,
            uncorrected_df_num,
            uncorrected_df_den,
            1.0,
            None,
        )
    grand = mean(value for values in values_by_size for value in values)
    size_means = [mean(values) for values in values_by_size]
    subject_means = [mean(values_by_size[size][subject] for size in range(k)) for subject in range(n)]
    ss_total = sum((value - grand) ** 2 for values in values_by_size for value in values)
    ss_size = n * sum((value - grand) ** 2 for value in size_means)
    ss_subject = k * sum((value - grand) ** 2 for value in subject_means)
    ss_error = ss_total - ss_size - ss_subject
    if ss_error <= 0.0:
        return (
            None,
            None,
            uncorrected_df_num,
            uncorrected_df_den,
            uncorrected_df_num,
            uncorrected_df_den,
            1.0,
            None,
        )
    epsilon = greenhouse_geisser_epsilon(values_by_size)
    corrected_df_num = epsilon * uncorrected_df_num
    corrected_df_den = epsilon * uncorrected_df_den
    f_value = (ss_size / uncorrected_df_num) / (ss_error / uncorrected_df_den)
    partial_eta_squared = ss_size / (ss_size + ss_error) if ss_size + ss_error > 0.0 else None
    return (
        f_value,
        f_survival(f_value, corrected_df_num, corrected_df_den),
        uncorrected_df_num,
        uncorrected_df_den,
        corrected_df_num,
        corrected_df_den,
        epsilon,
        partial_eta_squared,
    )


def holm_adjust(p_values: list[float | None]) -> list[float | None]:
    if any(value is None for value in p_values):
        return [None for _ in p_values]
    numeric = [float(value) for value in p_values]
    order = sorted(range(len(numeric)), key=numeric.__getitem__)
    adjusted = [0.0] * len(numeric)
    running = 0.0
    for rank, index in enumerate(order):
        candidate = min(1.0, (len(numeric) - rank) * numeric[index])
        running = max(running, candidate)
        adjusted[index] = running
    return adjusted


def statistic_rows(validation: dict[str, Any]) -> list[dict[str, Any]]:
    if validation["profile"] != "full":
        return []
    provisional: list[dict[str, Any]] = []
    sizes = validation["sizes"]
    for method in ALL_METHODS:
        groups = []
        for size in sizes:
            condition_rows = validation["values_by_method_size"][(method, size)]
            groups.append([as_float(row, "primary_ns_per_operation") for row in sorted(condition_rows, key=lambda row: as_int(row, "trial"))])
        (
            f_value,
            p_value,
            uncorrected_df_num,
            uncorrected_df_den,
            df_num,
            df_den,
            gg_epsilon,
            partial_eta_squared,
        ) = repeated_measures_anova(groups)
        first_mean, last_mean = mean(groups[0]), mean(groups[-1])
        difference = last_mean - first_mean
        provisional.append(
            {
                "family": FAMILY_BY_METHOD[method],
                "method": method,
                "primary_metric": PRIMARY_METRIC_BY_METHOD[method],
                "test_used": "one-factor repeated-measures ANOVA with trial blocks; Greenhouse-Geisser df correction",
                "sample_size_per_input_size": len(groups[0]),
                "blocks": len(groups[0]),
                "input_size_levels": len(sizes),
                "statistic_f": f_value if f_value is not None else "",
                "uncorrected_df_num": uncorrected_df_num,
                "uncorrected_df_den": uncorrected_df_den,
                "gg_epsilon": gg_epsilon,
                "df_num": df_num,
                "df_den": df_den,
                "partial_eta_squared": partial_eta_squared if partial_eta_squared is not None else "",
                "raw_p_value": p_value if p_value is not None else "",
                "holm_adjusted_p_value": "",
                "mean_first_size_ns_per_operation": first_mean,
                "mean_last_size_ns_per_operation": last_mean,
                "difference_last_minus_first_ns_per_operation": difference,
                "percentage_difference_last_minus_first": (difference / first_mean * 100.0) if first_mean else "",
                "analysis_status": "analyzed" if p_value is not None else "not_analyzable",
                "interpretation_note": (
                    "Primary size-effect test; trial is the repeated-measures block, "
                    "Greenhouse-Geisser epsilon is reported and applied to the F-test "
                    "degrees of freedom; Holm correction spans all nine methods. "
                    "This is not a cross-method significance test."
                ),
            }
        )
    adjusted = holm_adjust([
        (float(row["raw_p_value"]) if row["raw_p_value"] != "" else None)
        for row in provisional
    ])
    for row, value in zip(provisional, adjusted):
        row["holm_adjusted_p_value"] = value if value is not None else ""
    return provisional


def overhead_rows(validation: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for (method, size), condition_rows in sorted(validation["values_by_method_size"].items()):
        source = condition_rows[0]
        expected = expected_overhead(method, size)
        rows.append(
            {
                "family": FAMILY_BY_METHOD[method],
                "method": method,
                "input_size_bytes": size,
                "payload_bytes": size,
                **{field: as_int(source, field) for field in expected},
            }
        )
    return rows


def matrix_rows(functional_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    return [
        {field: row[field] for field in MATRIX_FIELDS}
        for row in sorted(
            functional_rows,
            key=lambda row: (row["family"], row["method"], as_int(row, "input_size_bytes"), row["scenario"]),
        )
    ]


def write_svg_chart(path: Path, family: str, values: dict[str, dict[int, float]], sizes: tuple[int, ...]) -> None:
    width, height = 900, 520
    left, right, top, bottom = 85, 35, 50, 85
    plot_width, plot_height = width - left - right, height - top - bottom
    all_values = [value for series in values.values() for value in series.values()]
    y_min = 0.0
    y_max = max(all_values) * 1.15 if all_values else 1.0
    if y_max <= 0.0:
        y_max = 1.0

    def x_coord(size: int) -> float:
        lo = math.log2(min(sizes))
        hi = math.log2(max(sizes))
        fraction = (math.log2(size) - lo) / (hi - lo) if hi > lo else 0.5
        return left + fraction * plot_width

    def y_coord(value: float) -> float:
        return top + plot_height - (value - y_min) / y_max * plot_height

    colors = ("#2563eb", "#dc2626", "#059669", "#7c3aed")
    pieces = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{width/2:.1f}" y="28" text-anchor="middle" font-family="Segoe UI,Arial" font-size="20" font-weight="600">{family.title()} primary timing by input size</text>',
        f'<line x1="{left}" y1="{top+plot_height}" x2="{left+plot_width}" y2="{top+plot_height}" stroke="#111827"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_height}" stroke="#111827"/>',
        f'<text x="{width/2:.1f}" y="{height-18}" text-anchor="middle" font-family="Segoe UI,Arial" font-size="13">Input size (bytes; log2-spaced positions)</text>',
        f'<text x="18" y="{top+plot_height/2:.1f}" text-anchor="middle" transform="rotate(-90 18 {top+plot_height/2:.1f})" font-family="Segoe UI,Arial" font-size="13">Normalized ns per operation</text>',
    ]
    for index in range(6):
        value = y_max * index / 5.0
        y = y_coord(value)
        pieces.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left+plot_width}" y2="{y:.1f}" stroke="#e5e7eb"/>')
        pieces.append(f'<text x="{left-8}" y="{y+4:.1f}" text-anchor="end" font-family="Segoe UI,Arial" font-size="11">{value:,.0f}</text>')
    for size in sizes:
        x = x_coord(size)
        pieces.append(f'<line x1="{x:.1f}" y1="{top+plot_height}" x2="{x:.1f}" y2="{top+plot_height+5}" stroke="#111827"/>')
        pieces.append(f'<text x="{x:.1f}" y="{top+plot_height+22}" text-anchor="middle" font-family="Segoe UI,Arial" font-size="11">{size:,}</text>')
    for index, (method, series) in enumerate(sorted(values.items())):
        color = colors[index % len(colors)]
        points = " ".join(f"{x_coord(size):.1f},{y_coord(series[size]):.1f}" for size in sizes)
        pieces.append(f'<polyline fill="none" stroke="{color}" stroke-width="3" points="{points}"/>')
        for size in sizes:
            pieces.append(f'<circle cx="{x_coord(size):.1f}" cy="{y_coord(series[size]):.1f}" r="4" fill="{color}"/>')
        legend_x = left + index * 205
        pieces.append(f'<line x1="{legend_x}" y1="{height-54}" x2="{legend_x+24}" y2="{height-54}" stroke="{color}" stroke-width="3"/>')
        pieces.append(f'<text x="{legend_x+30}" y="{height-50}" font-family="Segoe UI,Arial" font-size="11">{method}</text>')
    pieces.append("</svg>")
    path.write_text("\n".join(pieces), encoding="utf-8")


def chart_values(validation: dict[str, Any], family: str) -> dict[str, dict[int, float]]:
    result: dict[str, dict[int, float]] = {}
    for method in ALL_METHODS:
        if FAMILY_BY_METHOD[method] != family:
            continue
        result[method] = {}
        for size in validation["sizes"]:
            rows = validation["values_by_method_size"][(method, size)]
            result[method][size] = mean(as_float(row, "primary_ns_per_operation") for row in rows)
    return result


def rank_values(values: list[float]) -> list[float]:
    ranked = [0.0] * len(values)
    order = sorted(range(len(values)), key=values.__getitem__)
    index = 0
    while index < len(order):
        end = index + 1
        while end < len(order) and values[order[end]] == values[order[index]]:
            end += 1
        rank = (index + 1 + end) / 2.0
        for position in order[index:end]:
            ranked[position] = rank
        index = end
    return ranked


def spearman_rho(first: list[float], second: list[float]) -> float | None:
    if len(first) != len(second) or len(first) < 3:
        return None
    first_ranks = rank_values(first)
    second_ranks = rank_values(second)
    first_mean = statistics.fmean(first_ranks)
    second_mean = statistics.fmean(second_ranks)
    numerator = sum(
        (left - first_mean) * (right - second_mean)
        for left, right in zip(first_ranks, second_ranks)
    )
    first_ss = sum((value - first_mean) ** 2 for value in first_ranks)
    second_ss = sum((value - second_mean) ** 2 for value in second_ranks)
    if first_ss <= 0.0 or second_ss <= 0.0:
        return None
    return numerator / math.sqrt(first_ss * second_ss)


def run_order_rows(validation: dict[str, Any]) -> list[dict[str, Any]]:
    """Write exploratory drift checks without treating them as causal tests."""
    rows: list[dict[str, Any]] = []
    for method in ALL_METHODS:
        condition_rows = [
            row
            for (row_method, _size), values in validation["values_by_method_size"].items()
            if row_method == method
            for row in values
        ]
        by_trial: dict[int, list[dict[str, str]]] = defaultdict(list)
        for row in condition_rows:
            by_trial[as_int(row, "trial")].append(row)
        trial_numbers = sorted(by_trial)
        trial_means = [
            mean(as_float(row, "primary_ns_per_operation") for row in by_trial[trial])
            for trial in trial_numbers
        ]
        trial_rho = spearman_rho([float(trial) for trial in trial_numbers], trial_means)
        rows.append(
            {
                "family": FAMILY_BY_METHOD[method],
                "method": method,
                "diagnostic": "trial_block_mean_vs_trial_order",
                "observations": len(trial_means),
                "statistic": trial_rho if trial_rho is not None else "",
                "absolute_statistic": abs(trial_rho) if trial_rho is not None else "",
                "interpretation": "Exploratory drift check; a nonzero rho indicates a monotonic timing trend across recorded trial order.",
            }
        )

        condition_rhos: list[float] = []
        for size in validation["sizes"]:
            condition = validation["values_by_method_size"][(method, size)]
            condition_rho = spearman_rho(
                [float(as_int(row, "order_position")) for row in condition],
                [as_float(row, "primary_ns_per_operation") for row in condition],
            )
            if condition_rho is not None:
                condition_rhos.append(condition_rho)
        mean_rho = statistics.fmean(condition_rhos) if condition_rhos else None
        max_abs_rho = max((abs(value) for value in condition_rhos), default=None)
        rows.extend(
            (
                {
                    "family": FAMILY_BY_METHOD[method],
                    "method": method,
                    "diagnostic": "order_position_within_condition_mean_rho",
                    "observations": len(condition_rhos),
                    "statistic": mean_rho if mean_rho is not None else "",
                    "absolute_statistic": abs(mean_rho) if mean_rho is not None else "",
                    "interpretation": "Mean of five within-size Spearman correlations between randomized execution position and primary timing.",
                },
                {
                    "family": FAMILY_BY_METHOD[method],
                    "method": method,
                    "diagnostic": "order_position_within_condition_max_abs_rho",
                    "observations": len(condition_rhos),
                    "statistic": max_abs_rho if max_abs_rho is not None else "",
                    "absolute_statistic": max_abs_rho if max_abs_rho is not None else "",
                    "interpretation": "Maximum absolute within-size Spearman correlation; this is a limitation flag, not a significance test.",
                },
            )
        )
    return rows


def hybrid_breakdown_values(validation: dict[str, Any], metric: str) -> dict[str, dict[int, float]]:
    result: dict[str, dict[int, float]] = {}
    for method in HYBRID_METHODS:
        result[method] = {}
        for size in validation["sizes"]:
            condition_rows = validation["values_by_method_size"][(method, size)]
            result[method][size] = mean(as_float(row, metric) for row in condition_rows)
    return result


def write_hybrid_breakdown_svg(path: Path, validation: dict[str, Any]) -> None:
    width, height = 1_220, 585
    left, top, bottom = 75, 65, 90
    panel_width, panel_gap = 500, 90
    plot_height = height - top - bottom
    colors = ("#2563eb", "#dc2626", "#059669")
    sizes = validation["sizes"]
    panels = (
        ("key_step_ns_per_operation", "Key-establishment step"),
        ("full_round_trip_ns_per_operation", "Full valid round trip"),
    )
    pieces = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{width/2:.1f}" y="30" text-anchor="middle" font-family="Segoe UI,Arial" font-size="20" font-weight="600">Hybrid timing breakdown by input size</text>',
        f'<text x="{width/2:.1f}" y="53" text-anchor="middle" font-family="Segoe UI,Arial" font-size="12">Normalized ns per operation; trial blocks are summarized by their mean</text>',
    ]
    for panel_index, (metric, title) in enumerate(panels):
        panel_left = left + panel_index * (panel_width + panel_gap)
        plot_width = panel_width
        values = hybrid_breakdown_values(validation, metric)
        all_values = [value for series in values.values() for value in series.values()]
        y_max = max(all_values) * 1.15 if all_values else 1.0
        y_max = max(y_max, 1.0)

        def x_coord(size: int) -> float:
            lo = math.log2(min(sizes))
            hi = math.log2(max(sizes))
            fraction = (math.log2(size) - lo) / (hi - lo) if hi > lo else 0.5
            return panel_left + fraction * plot_width

        def y_coord(value: float) -> float:
            return top + plot_height - (value / y_max) * plot_height

        pieces.append(
            f'<text x="{panel_left + plot_width/2:.1f}" y="{top-25}" text-anchor="middle" font-family="Segoe UI,Arial" font-size="15" font-weight="600">{title}</text>'
        )
        pieces.append(f'<line x1="{panel_left}" y1="{top+plot_height}" x2="{panel_left+plot_width}" y2="{top+plot_height}" stroke="#111827"/>')
        pieces.append(f'<line x1="{panel_left}" y1="{top}" x2="{panel_left}" y2="{top+plot_height}" stroke="#111827"/>')
        for index in range(6):
            value = y_max * index / 5.0
            y = y_coord(value)
            pieces.append(f'<line x1="{panel_left}" y1="{y:.1f}" x2="{panel_left+plot_width}" y2="{y:.1f}" stroke="#e5e7eb"/>')
            pieces.append(f'<text x="{panel_left-8}" y="{y+4:.1f}" text-anchor="end" font-family="Segoe UI,Arial" font-size="10">{value:,.0f}</text>')
        for size in sizes:
            x = x_coord(size)
            pieces.append(f'<line x1="{x:.1f}" y1="{top+plot_height}" x2="{x:.1f}" y2="{top+plot_height+5}" stroke="#111827"/>')
            pieces.append(f'<text x="{x:.1f}" y="{top+plot_height+22}" text-anchor="middle" font-family="Segoe UI,Arial" font-size="10">{size:,}</text>')
        for index, method in enumerate(HYBRID_METHODS):
            color = colors[index]
            series = values[method]
            points = " ".join(f"{x_coord(size):.1f},{y_coord(series[size]):.1f}" for size in sizes)
            pieces.append(f'<polyline fill="none" stroke="{color}" stroke-width="3" points="{points}"/>')
            for size in sizes:
                pieces.append(f'<circle cx="{x_coord(size):.1f}" cy="{y_coord(series[size]):.1f}" r="4" fill="{color}"/>')
            legend_x = panel_left + index * 165
            pieces.append(f'<line x1="{legend_x}" y1="{height-48}" x2="{legend_x+20}" y2="{height-48}" stroke="{color}" stroke-width="3"/>')
            pieces.append(f'<text x="{legend_x+25}" y="{height-44}" font-family="Segoe UI,Arial" font-size="9">{method}</text>')
        pieces.append(f'<text x="{panel_left + plot_width/2:.1f}" y="{height-16}" text-anchor="middle" font-family="Segoe UI,Arial" font-size="12">Input size (bytes; log2-spaced positions)</text>')
        pieces.append(f'<text x="{panel_left-55}" y="{top+plot_height/2:.1f}" text-anchor="middle" transform="rotate(-90 {panel_left-55} {top+plot_height/2:.1f})" font-family="Segoe UI,Arial" font-size="12">Normalized ns per operation</text>')
    pieces.append("</svg>")
    path.write_text("\n".join(pieces), encoding="utf-8")


def analyze(
    benchmark_csv: Path,
    metadata_json: Path,
    functional_csv: Path,
    functional_metadata_json: Path,
    output_dir: Path,
    expected_profile: str | None,
) -> dict[str, Any]:
    metadata = read_json(metadata_json)
    benchmark_rows = read_csv(benchmark_csv, RAW_FIELDS)
    validation = validate_benchmark(benchmark_rows, metadata, expected_profile)
    functional_metadata = read_json(functional_metadata_json)
    functional_rows = read_csv(functional_csv, FUNCTIONAL_FIELDS)
    functional_validation = validate_functional(functional_rows, functional_metadata)

    output_dir.mkdir(parents=True, exist_ok=True)
    expected_outputs = (
        "validation_report.json",
        "descriptive_statistics.csv",
        "overhead_table.csv",
        "verification_outcome_matrix.csv",
        "hashing_timing.svg",
        "symmetric_timing.svg",
        "hybrid_timing.svg",
        "hybrid_breakdown.svg",
        "run_order_diagnostics.csv",
        "analysis_summary.json",
    )
    if validation["profile"] == "full":
        expected_outputs += ("size_effect_statistics.csv",)
    existing = [name for name in expected_outputs if (output_dir / name).exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite analysis outputs: {', '.join(existing)}")

    descriptive = descriptive_rows(validation)
    overhead = overhead_rows(validation)
    matrix = matrix_rows(functional_rows)
    write_csv(output_dir / "descriptive_statistics.csv", DESCRIPTIVE_FIELDS, descriptive)
    write_csv(output_dir / "overhead_table.csv", OVERHEAD_FIELDS, overhead)
    write_csv(output_dir / "verification_outcome_matrix.csv", MATRIX_FIELDS, matrix)
    write_csv(output_dir / "run_order_diagnostics.csv", ORDER_FIELDS, run_order_rows(validation))

    chart_paths = {}
    for family in ("hashing", "symmetric", "hybrid"):
        path = output_dir / f"{family}_timing.svg"
        write_svg_chart(path, family, chart_values(validation, family), validation["sizes"])
        chart_paths[family] = str(path)
    hybrid_breakdown_path = output_dir / "hybrid_breakdown.svg"
    write_hybrid_breakdown_svg(hybrid_breakdown_path, validation)
    chart_paths["hybrid_breakdown"] = str(hybrid_breakdown_path)

    stats = statistic_rows(validation)
    if validation["profile"] == "full":
        write_csv(output_dir / "size_effect_statistics.csv", STAT_FIELDS, stats)

    validation_report = {
        "benchmark_csv": str(benchmark_csv),
        "benchmark_metadata": str(metadata_json),
        "functional_csv": str(functional_csv),
        "functional_metadata": str(functional_metadata_json),
        "benchmark": {key: value for key, value in validation.items() if key != "values_by_method_size"},
        "functional": functional_validation,
        "benchmark_sha256": hashlib.sha256(benchmark_csv.read_bytes()).hexdigest(),
        "functional_sha256": hashlib.sha256(functional_csv.read_bytes()).hexdigest(),
        "validation_status": "passed",
    }
    write_json(output_dir / "validation_report.json", validation_report)
    summary = {
        "status": "complete",
        "profile": validation["profile"],
        "descriptive_statistics": str(output_dir / "descriptive_statistics.csv"),
        "overhead_table": str(output_dir / "overhead_table.csv"),
        "verification_outcome_matrix": str(output_dir / "verification_outcome_matrix.csv"),
        "run_order_diagnostics": str(output_dir / "run_order_diagnostics.csv"),
        "plots": chart_paths,
        "size_effect_statistics": str(output_dir / "size_effect_statistics.csv") if validation["profile"] == "full" else None,
        "inferential_analysis": (
            "nine separate blocked repeated-measures ANOVAs with Greenhouse-Geisser correction and Holm correction across methods"
            if validation["profile"] == "full"
            else "not run: smoke/pilot profiles are descriptive only"
        ),
        "row_count": validation["row_count"],
        "functional_row_count": functional_validation["row_count"],
        "created_utc": timestamp(),
    }
    write_json(output_dir / "analysis_summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and analyse an A1 benchmark run.")
    parser.add_argument("--benchmark-csv", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--functional-csv", type=Path, required=True)
    parser.add_argument("--functional-metadata", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-profile", choices=("smoke", "full"), default=None)
    args = parser.parse_args()
    try:
        summary = analyze(
            args.benchmark_csv,
            args.metadata,
            args.functional_csv,
            args.functional_metadata,
            args.output_dir,
            args.expected_profile,
        )
    except Exception as error:
        print(f"analysis failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()


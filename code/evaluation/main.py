#!/usr/bin/env python3
"""Compare the generated CSV with the public sample answer."""

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple


FIELDS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)


def read_rows(path: Path) -> Dict[str, Dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return {row["case_id"]: row for row in csv.DictReader(handle)}


def canonical_step(step: Dict[str, object]) -> Tuple[object, ...]:
    return tuple(step.get(field) for field in FIELDS)


def evaluate(expected_path: Path, actual_path: Path) -> Dict[str, float]:
    expected = read_rows(expected_path)
    actual = read_rows(actual_path)
    if set(expected) != set(actual):
        raise ValueError("Expected and actual files contain different case IDs.")

    status_correct = 0
    exact_rows = 0
    exact_sequences = 0
    field_correct = 0
    field_total = 0
    expected_steps: Counter = Counter()
    actual_steps: Counter = Counter()
    for case_id, expected_row in expected.items():
        actual_row = actual[case_id]
        if expected_row["deletion_status"] == actual_row["deletion_status"]:
            status_correct += 1
        expected_array = json.loads(expected_row["steps_json"])
        actual_array = json.loads(actual_row["steps_json"])
        if expected_row["deletion_status"] == actual_row["deletion_status"] and expected_array == actual_array:
            exact_rows += 1
        if expected_array == actual_array:
            exact_sequences += 1
        for step in expected_array:
            expected_steps[canonical_step(step)] += 1
        for step in actual_array:
            actual_steps[canonical_step(step)] += 1
        for index in range(max(len(expected_array), len(actual_array))):
            expected_step = expected_array[index] if index < len(expected_array) else {}
            actual_step = actual_array[index] if index < len(actual_array) else {}
            for field in FIELDS:
                field_total += 1
                if field in expected_step and field in actual_step and expected_step[field] == actual_step[field]:
                    field_correct += 1

    true_steps = sum((expected_steps & actual_steps).values())
    false_steps = sum((actual_steps - expected_steps).values())
    missed_steps = sum((expected_steps - actual_steps).values())
    precision = true_steps / (true_steps + false_steps) if true_steps + false_steps else 1.0
    recall = true_steps / (true_steps + missed_steps) if true_steps + missed_steps else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    count = len(expected)
    return {
        "case_count": count,
        "status_accuracy": status_correct / count if count else 1.0,
        "row_accuracy": exact_rows / count if count else 1.0,
        "sequence_accuracy": exact_sequences / count if count else 1.0,
        "field_accuracy": field_correct / field_total if field_total else 1.0,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "expected_steps": sum(expected_steps.values()),
        "actual_steps": sum(actual_steps.values()),
        "matched_steps": true_steps,
    }


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", type=Path, default=root / "dataset/sample_output.csv")
    parser.add_argument("--actual", type=Path, default=root / "output.csv")
    args = parser.parse_args()
    metrics = evaluate(args.expected, args.actual)
    for name, value in metrics.items():
        print("{}: {}".format(name, "{:.4f}".format(value) if isinstance(value, float) else value))


if __name__ == "__main__":
    main()
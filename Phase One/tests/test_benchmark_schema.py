import csv
import json

from src.benchmark import _run_latency_batch, _summarize, _write_csv

REQUIRED_ROW_COLUMNS = {
    "run_id",
    "timestamp_utc",
    "platform_id",
    "platform_verified",
    "suite",
    "batch",
    "sample_index",
    "success",
    "key_match",
    "handshake_wall_ns",
    "measurement_elapsed_ns",
    "error_type",
    "environment_json",
}

REQUIRED_SUMMARY_FIELDS = {
    "n_attempted",
    "n_successful",
    "n_failed",
    "success_rate",
    "median_latency_ms",
    "p95_latency_ms",
    "p99_latency_ms",
    "mean_latency_ms",
    "throughput_successful_handshakes_per_second",
}

FORBIDDEN_SUBSTRINGS = ("secret", "private", "session_key", "shared_key", "seed")


def test_latency_batch_row_schema_and_csv_roundtrip(tmp_path):
    rows, elapsed_ns = _run_latency_batch(
        mode="ecdh",
        platform_id="A",
        platform_verified=True,
        run_id="schema_test_run",
        batch_num=1,
        iterations=3,
        warmup=0,
        environment_json=json.dumps({"platform_id": "A"}),
    )
    assert len(rows) == 3
    assert elapsed_ns > 0
    for row in rows:
        assert REQUIRED_ROW_COLUMNS.issubset(row.keys())
        for key in row:
            lowered = key.lower()
            for forbidden in FORBIDDEN_SUBSTRINGS:
                assert forbidden not in lowered, f"secret-like column leaked: {key}"

    path = tmp_path / "raw.csv"
    _write_csv(path, rows)
    with path.open(newline="", encoding="utf-8") as handle:
        read_rows = list(csv.DictReader(handle))
    assert len(read_rows) == 3
    assert REQUIRED_ROW_COLUMNS.issubset(read_rows[0].keys())


def test_summary_schema_from_batch_rows():
    rows, elapsed_ns = _run_latency_batch(
        mode="ecdh",
        platform_id="A",
        platform_verified=True,
        run_id="schema_test_run",
        batch_num=1,
        iterations=5,
        warmup=0,
        environment_json="{}",
    )
    summary = _summarize(rows, [elapsed_ns])
    assert REQUIRED_SUMMARY_FIELDS.issubset(summary.keys())
    assert summary["suite"] == "ecdh"
    assert summary["n_attempted"] == 5
    assert summary["n_successful"] == 5
    assert summary["n_failed"] == 0
    assert summary["success_rate"] == 1.0


def test_write_csv_refuses_empty(tmp_path):
    try:
        _write_csv(tmp_path / "empty.csv", [])
    except ValueError:
        return
    raise AssertionError("_write_csv should refuse to write an empty result file")

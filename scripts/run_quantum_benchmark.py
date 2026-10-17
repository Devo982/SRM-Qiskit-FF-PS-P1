
"""Reproducible Processor A/B quantum architecture benchmark runner."""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from qiskit import qpy

from src.problem import (
    BETA,
    INTERACTIONS,
    N_LOGICAL_QUBITS,
    SUPPORTED_REPS,
    THETA,
    build_logical_circuit,
)
from src.processors import load_processor
from src.simulation import run_noisy_case




METRICS_RELATIVE = Path("data/raw/quantum_metrics.csv")
COUNTS_RELATIVE = Path("data/raw/quantum_counts.json")
CIRCUITS_RELATIVE = Path("data/raw/quantum_circuits")
MANIFEST_RELATIVE = Path("results/logs/quantum_run_manifest.json")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_version(distribution: str) -> str | None:
    try:
        return version(distribution)
    except PackageNotFoundError:
        return None


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _write_json(path: Path, payload: dict) -> None:
    """Atomically replace a JSON artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _csv_value(value):
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    if value is None:
        return ""
    return value


def _write_csv(path: Path, rows: list[dict]) -> None:
    """Write the complete accumulated table after each successful case."""
    if not rows:
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    fieldnames = list(rows[0].keys())

    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                key: _csv_value(value)
                for key, value in row.items()
            })

    temporary.replace(path)


def _save_circuits(path: Path, circuits: list) -> None:
    """Save circuits in Qiskit's portable QPY binary format."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")

    with temporary.open("wb") as stream:
        qpy.dump(circuits, stream)

    temporary.replace(path)


def run_experiment(
    output_root: Path | str | None = None,
    processor_ids: tuple[str, ...] = ("A", "B"),
    repetitions: tuple[int, ...] = (1, 2, 3),
    seed_simulator: int = 42,
) -> dict:
    """Run all requested cases and persist results after each successful case."""
    if not processor_ids or any(pid not in ("A", "B") for pid in processor_ids):
        raise ValueError("processor_ids must contain A and/or B")

    if len(set(processor_ids)) != len(processor_ids):
        raise ValueError("processor_ids cannot contain duplicates")

    if not repetitions or any(
        type(reps) is not int or reps not in SUPPORTED_REPS
        for reps in repetitions
    ):
        raise ValueError(f"repetitions must be selected from {SUPPORTED_REPS}")

    if type(seed_simulator) is not int or seed_simulator < 0:
        raise ValueError("seed_simulator must be a non-negative integer")

    output_root = (
        REPO_ROOT if output_root is None else Path(output_root).resolve()
    )

    metrics_path = output_root / METRICS_RELATIVE
    counts_path = output_root / COUNTS_RELATIVE
    circuits_dir = output_root / CIRCUITS_RELATIVE
    manifest_path = output_root / MANIFEST_RELATIVE

    loaded_processors = {}
    processor_metadata = {}

    for processor_id in processor_ids:
        config_path = (
            REPO_ROOT / "processors" / f"processor_{processor_id}.json"
        )
        spec, graph, coupling_map, noise_model = load_processor(config_path)

        loaded_processors[processor_id] = (
            spec,
            graph,
            coupling_map,
            noise_model,
        )
        processor_metadata[processor_id] = {
            "name": spec["name"],
            "config_file": config_path.relative_to(REPO_ROOT).as_posix(),
            "config_sha256": _sha256(config_path),
            "num_qubits": spec["num_qubits"],
            "coupling_edges_undirected": (
                spec["coupling_edges_undirected"]
            ),
            "basis_gates": spec["basis_gates"],
            "noise": spec["noise"],
            "transpilation": spec["transpilation"],
        }

    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "_"
        + uuid.uuid4().hex[:8]
    )

    relative_artifacts = {
        "metrics_csv": METRICS_RELATIVE.as_posix(),
        "counts_json": COUNTS_RELATIVE.as_posix(),
        "circuits_directory": CIRCUITS_RELATIVE.as_posix(),
        "manifest_json": MANIFEST_RELATIVE.as_posix(),
    }

    manifest = {
        "run_id": run_id,
        "status": "RUNNING",
        "started_at_utc": _utc_now(),
        "completed_at_utc": None,
        "git_commit": _git_commit(),
        "environment": {
            "python_version": sys.version,
            "os": platform.platform(),
            "architecture": platform.machine(),
            "package_versions": {
                "qiskit": _package_version("qiskit"),
                "qiskit-aer": _package_version("qiskit-aer"),
                "networkx": _package_version("networkx"),
                "numpy": _package_version("numpy"),
                "pandas": _package_version("pandas"),
                "liboqs-python": _package_version("liboqs-python"),
            },
        },
        "workload": {
            "logical_qubits": N_LOGICAL_QUBITS,
            "theta_radians": THETA,
            "beta_radians": BETA,
            "interactions": [list(edge) for edge in INTERACTIONS],
            "repetitions": list(repetitions),
            "seed_simulator": seed_simulator,
        },
        "processors": processor_metadata,
        "cases_expected": len(processor_ids) * len(repetitions),
        "cases_completed": [],
        "artifacts": relative_artifacts,
    }

    counts_payload = {
        "run_id": run_id,
        "counts_convention": (
            "Qiskit count strings; classical bit i is at bitstring[-1-i]"
        ),
        "cases": {},
    }
    records: list[dict] = []

    # Write initial metadata before beginning the simulations.
    _write_json(manifest_path, manifest)
    _write_json(counts_path, counts_payload)

    try:
        for processor_id in processor_ids:
            spec, _graph, coupling_map, noise_model = (
                loaded_processors[processor_id]
            )

            for reps in repetitions:
                print(
                    f"Running Processor {processor_id}, reps={reps}, "
                    f"shots={spec['transpilation']['shots']}...",
                    flush=True,
                )

                result = run_noisy_case(
                    spec=spec,
                    coupling_map=coupling_map,
                    noise_model=noise_model,
                    reps=reps,
                    seed_simulator=seed_simulator,
                )

                case_key = f"{processor_id}_reps_{reps}"
                circuit_relative = (
                    CIRCUITS_RELATIVE / f"{case_key}.qpy"
                )
                circuit_path = output_root / circuit_relative

                # Keep the same logical input and every compilation variant.
                logical_circuit = build_logical_circuit(
                    reps, measure=True
                )
                circuits = [
                    logical_circuit,
                    result["compiled_circuit"],
                    result["diagnostic_circuit"],
                    result["unconstrained_circuit"],
                ]
                names = [
                    f"logical_{case_key}",
                    f"native_{case_key}",
                    f"routing_diagnostic_{case_key}",
                    f"unconstrained_{case_key}",
                ]
                for circuit, name in zip(circuits, names):
                    circuit.name = name

                _save_circuits(circuit_path, circuits)

                timestamp = _utc_now()
                row = {
                    "run_id": run_id,
                    "timestamp_utc": timestamp,
                    "processor_id": processor_id,
                    "processor_config_sha256": (
                        processor_metadata[processor_id]["config_sha256"]
                    ),
                    "circuit_artifact": circuit_relative.as_posix(),
                    **result["metrics"],
                }
                records.append(row)

                counts_payload["cases"][case_key] = {
                    "processor_id": processor_id,
                    "reps": reps,
                    "shots": result["metrics"]["shots"],
                    "seed_simulator": seed_simulator,
                    "counts": result["counts"],
                    "ideal_probabilities": result["ideal_probabilities"],
                    "ideal_observable_expectation": (
                        result["metrics"]["ideal_observable_expectation"]
                    ),
                    "noisy_observable_estimate": (
                        result["metrics"]["noisy_observable_estimate"]
                    ),
                }

                # Persist each successful case before starting the next.
                _write_csv(metrics_path, records)
                _write_json(counts_path, counts_payload)

                manifest["cases_completed"].append({
                    "case_key": case_key,
                    "processor_id": processor_id,
                    "reps": reps,
                    "completed_at_utc": timestamp,
                    "circuit_artifact": circuit_relative.as_posix(),
                    "metrics": {
                        key: result["metrics"][key]
                        for key in (
                            "logical_depth",
                            "transpiled_depth",
                            "native_cx_count",
                            "explicit_routing_swap_count",
                            "extra_cx_count",
                            "ideal_observable_expectation",
                            "noisy_observable_estimate",
                            "absolute_observable_error",
                            "distribution_fidelity",
                            "shots",
                            "seed_simulator",
                        )
                    },
                })
                _write_json(manifest_path, manifest)

                print(
                    f"  PASS: depth={result['metrics']['transpiled_depth']}, "
                    f"CX={result['metrics']['native_cx_count']}, "
                    f"F_dist={result['metrics']['distribution_fidelity']:.6f}",
                    flush=True,
                )

        manifest["status"] = "PASS"
        manifest["completed_at_utc"] = _utc_now()
        _write_json(manifest_path, manifest)

    except Exception as exc:
        manifest["status"] = "FAILED"
        manifest["completed_at_utc"] = _utc_now()
        manifest["error"] = f"{type(exc).__name__}: {exc}"
        _write_json(manifest_path, manifest)
        raise

    print(f"Run ID: {run_id}")
    print(f"Status: {manifest['status']}")
    print(f"Metrics CSV: {metrics_path}")
    print(f"Counts JSON: {counts_path}")
    print(f"Circuit QPY files: {circuits_dir}")
    print(f"Manifest: {manifest_path}")

    return manifest


def main() -> None:
    manifest = run_experiment()
    if manifest["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

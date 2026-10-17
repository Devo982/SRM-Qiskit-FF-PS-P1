
import csv
import json

from qiskit import qpy

from scripts.run_quantum_benchmark import run_experiment


def test_runner_writes_reproducible_artifacts(tmp_path):
    manifest = run_experiment(
        output_root=tmp_path,
        processor_ids=("A",),
        repetitions=(1,),
        seed_simulator=42,
    )

    metrics_path = tmp_path / "data/raw/quantum_metrics.csv"
    counts_path = tmp_path / "data/raw/quantum_counts.json"
    manifest_path = tmp_path / "results/logs/quantum_run_manifest.json"
    circuit_path = tmp_path / "data/raw/quantum_circuits/A_reps_1.qpy"

    assert manifest["status"] == "PASS"
    assert manifest["cases_expected"] == 1
    assert len(manifest["cases_completed"]) == 1

    with metrics_path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    assert len(rows) == 1
    assert rows[0]["processor_id"] == "A"
    assert rows[0]["reps"] == "1"
    assert rows[0]["shots"] == "4096"

    counts_payload = json.loads(counts_path.read_text(encoding="utf-8"))
    case = counts_payload["cases"]["A_reps_1"]

    assert sum(case["counts"].values()) == 4096
    assert len(case["ideal_probabilities"]) <= 32

    loaded_manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )
    assert loaded_manifest["status"] == "PASS"
    assert len(loaded_manifest["processors"]["A"]["config_sha256"]) == 64

    assert circuit_path.exists()
    with circuit_path.open("rb") as stream:
        circuits = qpy.load(stream)

    assert len(circuits) == 4
    assert circuits[0].num_qubits == 5
    assert circuits[1].num_clbits == 5
    assert circuits[2].num_clbits == 5
    assert circuits[3].num_clbits == 5

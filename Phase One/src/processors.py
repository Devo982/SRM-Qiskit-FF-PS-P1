
import json
from pathlib import Path

import networkx as nx
from qiskit.transpiler import CouplingMap
from qiskit_aer.noise import (
    NoiseModel,
    ReadoutError,
    depolarizing_error,
)


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_BASIS_GATES = ["rz", "sx", "x", "cx"]

EXPECTED_TRANSPILATION = {
    "optimization_level": 1,
    "seed_transpiler": 42,
    "shots": 4096,
}

EXPECTED_NOISE_KEYS = {
    "one_qubit_depolarizing_probability",
    "cx_depolarizing_probability",
    "readout_error_probability",
}


def load_processor(path):
    """
    Load and validate one processor configuration.

    Returns:
        spec: The original processor configuration dictionary.
        graph: A NetworkX graph of physical qubit connectivity.
        coupling_map: A bidirectional Qiskit CouplingMap.
        noise: The configured synthetic Qiskit Aer NoiseModel.
    """
    config_path = Path(path)

    # Also allow paths relative to the repository root.
    if not config_path.is_absolute() and not config_path.is_file():
        config_path = ROOT / config_path

    if not config_path.is_file():
        raise FileNotFoundError(
            f"Processor configuration not found: {config_path}"
        )

    with config_path.open("r", encoding="utf-8") as file:
        spec = json.load(file)

    if not isinstance(spec, dict):
        raise ValueError("Processor configuration must be a JSON object.")

    required_fields = {
        "name",
        "num_qubits",
        "coupling_edges_undirected",
        "basis_gates",
        "noise",
        "transpilation",
    }

    missing = required_fields - spec.keys()
    if missing:
        raise ValueError(
            f"Missing configuration fields: {sorted(missing)}"
        )

    n = spec["num_qubits"]

    if type(n) is not int or n <= 0:
        raise ValueError("num_qubits must be a positive integer.")

    if spec["basis_gates"] != EXPECTED_BASIS_GATES:
        raise ValueError(
            f"Expected basis gates: {EXPECTED_BASIS_GATES}"
        )

    if spec["transpilation"] != EXPECTED_TRANSPILATION:
        raise ValueError(
            "Transpilation settings do not match the challenge baseline."
        )

    # Validate the noise configuration.
    noise_settings = spec["noise"]

    if not isinstance(noise_settings, dict):
        raise ValueError("The noise configuration must be a JSON object.")

    if set(noise_settings) != EXPECTED_NOISE_KEYS:
        raise ValueError("Unexpected or missing noise configuration keys.")

    for key, probability in noise_settings.items():
        if (
            isinstance(probability, bool)
            or not isinstance(probability, (int, float))
            or not 0 <= probability <= 1
        ):
            raise ValueError(
                f"Invalid probability for {key}: {probability}"
            )

    # Construct and validate the physical connectivity graph.
    edges = spec["coupling_edges_undirected"]

    if not isinstance(edges, list):
        raise ValueError("Coupling edges must be a list.")

    graph = nx.Graph()
    graph.add_nodes_from(range(n))

    normalized_edges = []

    for edge in edges:
        if not isinstance(edge, (list, tuple)) or len(edge) != 2:
            raise ValueError(f"Invalid coupling edge: {edge}")

        u, v = edge

        if (
            type(u) is not int
            or type(v) is not int
            or not 0 <= u < n
            or not 0 <= v < n
        ):
            raise ValueError(f"Invalid qubit index in edge: {edge}")

        if u == v:
            raise ValueError(f"Self-loop is not allowed: {edge}")

        normalized = tuple(sorted((u, v)))

        if normalized in normalized_edges:
            raise ValueError(f"Duplicate undirected edge: {edge}")

        normalized_edges.append(normalized)
        graph.add_edge(u, v)

    if not nx.is_connected(graph):
        raise ValueError(
            f"{spec['name']} coupling graph must be connected."
        )

    # Qiskit uses directed coupling edges.
    # Represent each undirected connection in both directions.
    directed_edges = [
        directed
        for u, v in normalized_edges
        for directed in ((u, v), (v, u))
    ]

    coupling_map = CouplingMap(couplinglist=directed_edges)

    # Configure the prescribed synthetic noise model.
    n1 = noise_settings["one_qubit_depolarizing_probability"]
    n2 = noise_settings["cx_depolarizing_probability"]
    nr = noise_settings["readout_error_probability"]

    noise = NoiseModel()

    noise.add_all_qubit_quantum_error(
        depolarizing_error(n1, 1),
        ["rz", "sx", "x"],
    )

    noise.add_all_qubit_quantum_error(
        depolarizing_error(n2, 2),
        ["cx"],
    )

    noise.add_all_qubit_readout_error(
        ReadoutError([
            [1.0 - nr, nr],
            [nr, 1.0 - nr],
        ])
    )

    return spec, graph, coupling_map, noise

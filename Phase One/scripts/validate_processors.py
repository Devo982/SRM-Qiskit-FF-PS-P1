
import json
from pathlib import Path

import networkx as nx

ROOT = Path(__file__).resolve().parents[1]
PROCESSORS_DIR = ROOT / "processors"

EXPECTED_BASIS = ["rz", "sx", "x", "cx"]
EXPECTED_NOISE = {
    "one_qubit_depolarizing_probability": 0.001,
    "cx_depolarizing_probability": 0.005,
    "readout_error_probability": 0.01,
}
EXPECTED_TRANSPILATION = {
    "optimization_level": 1,
    "seed_transpiler": 42,
    "shots": 4096,
}

EXPECTED_PROCESSORS = {
    "processor_A.json": {
        "name": "Processor A",
        "num_qubits": 5,
        "num_edges": 4,
    },
    "processor_B.json": {
        "name": "Processor B",
        "num_qubits": 9,
        "num_edges": 12,
    },
}


def validate_processor(filename, expected):
    path = PROCESSORS_DIR / filename

    with path.open("r", encoding="utf-8") as file:
        spec = json.load(file)

    assert spec["name"] == expected["name"], "Incorrect processor name"

    n = spec["num_qubits"]
    edges = spec["coupling_edges_undirected"]

    assert n == expected["num_qubits"], f"Expected {expected['num_qubits']} qubits"

    graph = nx.Graph()
    graph.add_nodes_from(range(n))

    normalized_edges = []

    for edge in edges:
        assert len(edge) == 2, f"Invalid edge: {edge}"

        u, v = edge

        assert type(u) is int and type(v) is int, f"Non-integer edge: {edge}"
        assert 0 <= u < n and 0 <= v < n, f"Out-of-range edge: {edge}"
        assert u != v, f"Self-loop detected: {edge}"

        normalized_edges.append(tuple(sorted((u, v))))
        graph.add_edge(u, v)

    assert len(normalized_edges) == len(set(normalized_edges)), (
        "Duplicate undirected edges detected"
    )
    assert len(edges) == expected["num_edges"], (
        f"Expected {expected['num_edges']} connections"
    )
    assert nx.is_connected(graph), "Processor graph is disconnected"

    assert spec["basis_gates"] == EXPECTED_BASIS, "Incorrect basis gates"
    assert spec["noise"] == EXPECTED_NOISE, "Noise settings do not match"
    assert spec["transpilation"] == EXPECTED_TRANSPILATION, (
        "Transpilation settings do not match"
    )

    print(f"\n{spec['name']}: PASS")
    print(f"  Physical qubits : {n}")
    print(f"  Connections     : {len(edges)}")
    print(f"  Connected graph : Yes")
    print(f"  Basis gates     : {', '.join(spec['basis_gates'])}")
    print(f"  Noise settings  : Correct")
    print(f"  Transpilation   : Correct")


def main():
    for filename, expected in EXPECTED_PROCESSORS.items():
        validate_processor(filename, expected)

    print("\nSUCCESS: Both processor configurations passed validation.")


if __name__ == "__main__":
    main()

import json
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx

ROOT = Path(__file__).resolve().parents[1]
PROCESSORS_DIR = ROOT / "processors"
OUTPUT_DIR = ROOT / "results" / "figures"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def plot_processor(filename):
    config_path = PROCESSORS_DIR / filename

    with config_path.open("r", encoding="utf-8") as file:
        spec = json.load(file)

    n = spec["num_qubits"]
    graph = nx.Graph()
    graph.add_nodes_from(range(n))
    graph.add_edges_from(
        tuple(edge)
        for edge in spec["coupling_edges_undirected"]
    )

    if n == 5:
        # Processor A: linear chain.
        positions = {q: (q, 0) for q in range(n)}
    elif n == 9:
        # Processor B: 3 x 3 grid.
        positions = {
            q: (q % 3, -(q // 3))
            for q in range(n)
        }
    else:
        positions = nx.spring_layout(graph, seed=42)

    fig, ax = plt.subplots(figsize=(8, 4.5))

    nx.draw_networkx(
        graph,
        pos=positions,
        ax=ax,
        with_labels=True,
        node_color="lightblue",
        node_size=1200,
        font_size=11,
        font_weight="bold",
        edge_color="gray",
        width=2,
    )

    ax.set_title(
        f"{spec['name']} Coupling Map\n"
        f"{n} physical qubits, {graph.number_of_edges()} connections"
    )
    ax.axis("off")
    fig.tight_layout()

    output_path = (
        OUTPUT_DIR / filename.replace(".json", "_topology.png")
    )
    fig.savefig(output_path, dpi=200, bbox_inches="tight")
    plt.close(fig)

    print(f"Saved: {output_path.relative_to(ROOT)}")


def main():
    for filename in ("processor_A.json", "processor_B.json"):
        plot_processor(filename)

    print("\nSUCCESS: Both topology diagrams were generated.")


if __name__ == "__main__":
    main()
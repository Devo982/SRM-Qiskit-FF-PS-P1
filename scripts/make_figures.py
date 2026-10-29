#!/usr/bin/env python3
"""Create submission figures from results/tables/*.csv only.

Outputs:
  results/figures/handshake_latency.png
  results/figures/handshake_message_bytes.png
  results/figures/payload_10mb_timing.png

When handshake_raw_samples.csv exists, the latency error bar spans empirical Q1-Q3.
Before raw samples are generated, the committed aggregate CSV only carries IQR width;
in that case the script draws a centered IQR-width bar (median +/- IQR/2) and marks
that fallback on the plot rather than inventing individual timing samples.
"""
from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
TABLES = ROOT / "results" / "tables"
FIGURES = ROOT / "results" / "figures"


def read_csv(name: str) -> list[dict[str, str]]:
    path = TABLES / name
    if not path.is_file():
        raise FileNotFoundError(f"required results table not found: {path.relative_to(ROOT)}")
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def label_for(mode: str) -> str:
    return "PQC (ML-KEM-768 + ML-DSA-65)" if mode.lower() == "pqc" else "Classical (X25519 + Ed25519)"


def annotate_values(ax, bars, fmt: str) -> None:
    for bar in bars:
        height = bar.get_height()
        ax.annotate(
            fmt.format(height),
            (bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8,
        )


def set_platform_note(fig) -> None:
    # Reserve a separate bottom strip for this note so it never overlaps axis labels.
    fig.text(0.5, 0.025, "Platform A, local/in-process", ha="center", fontsize=9)


def handshake_latency() -> None:
    rows = read_csv("handshake_results.csv")
    wanted = {r["mode"]: r for r in rows if r.get("platform") == "A"}
    modes = ["PQC", "classical-baseline"]
    if any(mode not in wanted for mode in modes):
        raise ValueError("handshake_results.csv must contain Platform A PQC and classical-baseline rows")

    values = [float(wanted[m]["median_handshake_ms"]) for m in modes]
    labels = [label_for(m) for m in modes]
    centers = values
    lower_err: list[float] = []
    upper_err: list[float] = []
    raw_path = TABLES / "handshake_raw_samples.csv"
    used_raw = False
    if raw_path.is_file():
        raw_rows = read_csv("handshake_raw_samples.csv")
        raw_suite_ids = {"PQC": "QFF26-PQC-1", "classical-baseline": "QFF26-CLASSICAL-1"}
        for mode, center in zip(modes, centers):
            suite = raw_suite_ids[mode]
            suite_rows = [r for r in raw_rows if r.get("suite") == suite and r.get("ms", "")]
            if len(suite_rows) >= 10:
                samples = np.array([float(r["ms"]) for r in suite_rows], dtype=float)
                q1, q3 = np.percentile(samples, [25, 75])
                lower_err.append(max(0.0, center - float(q1)))
                upper_err.append(max(0.0, float(q3) - center))
            else:
                lower_err.append(float(wanted[mode]["iqr_ms"]) / 2)
                upper_err.append(float(wanted[mode]["iqr_ms"]) / 2)
        used_raw = all(
            len([r for r in raw_rows if r.get("suite") == raw_suite_ids[m] and r.get("ms", "")]) >= 10
            for m in modes
        )
    else:
        lower_err = [float(wanted[m]["iqr_ms"]) / 2 for m in modes]
        upper_err = [float(wanted[m]["iqr_ms"]) / 2 for m in modes]

    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    bars = ax.bar(labels, values, yerr=np.array([lower_err, upper_err]), capsize=6)
    annotate_values(ax, bars, "{:.3f} ms")
    ax.set_title("Median handshake latency with IQR error bars (n=100 trials)")
    ax.set_ylabel("Median handshake latency (ms)")
    ax.set_xlabel("Cipher suite")
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)
    if not used_raw:
        ax.text(
            0.99, 0.98,
            "Fallback: IQR width centered on median\n(raw per-trial samples not present yet)",
            transform=ax.transAxes, ha="right", va="top", fontsize=8,
        )
    fig.subplots_adjust(left=0.13, right=0.98, bottom=0.29, top=0.87)
    set_platform_note(fig)
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / "handshake_latency.png", dpi=180)
    plt.close(fig)


def handshake_message_bytes() -> None:
    rows = read_csv("bench_handshake.csv")
    wanted = {r["mode"]: r for r in rows if r.get("platform") == "A"}
    modes = ["PQC", "classical-baseline"]
    if any(mode not in wanted for mode in modes):
        raise ValueError("bench_handshake.csv must contain Platform A PQC and classical-baseline rows")
    messages = ["M1", "M2", "M3"]
    fields = ["m1_bytes", "m2_bytes", "m3_bytes"]
    x = np.arange(len(messages))
    width = 0.34
    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    all_bars = []
    for offset, mode in zip((-width / 2, width / 2), modes):
        vals = [int(wanted[mode][field]) for field in fields]
        bars = ax.bar(x + offset, vals, width, label=label_for(mode))
        all_bars.extend(bars)
        annotate_values(ax, bars, "{:.0f} B")
    ax.set_xticks(x, messages)
    ax.set_title("Serialized handshake bytes by message (n=100 trials)")
    ax.set_xlabel("Handshake message")
    ax.set_ylabel("Serialized message size (bytes)")
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)
    fig.subplots_adjust(left=0.13, right=0.98, bottom=0.23, top=0.87)
    set_platform_note(fig)
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / "handshake_message_bytes.png", dpi=180)
    plt.close(fig)


def payload_10mb_timing() -> None:
    rows = read_csv("payload_results.csv")
    wanted = {
        row["mode"]: row for row in rows
        if row.get("platform") == "A" and row.get("payload") == "payload_10MB.bin"
    }
    modes = ["PQC", "classical-baseline"]
    if any(mode not in wanted for mode in modes):
        raise ValueError("payload_results.csv must contain Platform A 10 MB rows for both suites")
    operations = ["Encrypt", "Decrypt"]
    fields = ["median_encrypt_ms", "median_decrypt_ms"]
    x = np.arange(len(operations))
    width = 0.34
    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    for offset, mode in zip((-width / 2, width / 2), modes):
        vals = [float(wanted[mode][field]) for field in fields]
        bars = ax.bar(x + offset, vals, width, label=label_for(mode))
        annotate_values(ax, bars, "{:.3f} ms")
    ax.set_xticks(x, operations)
    ax.set_title("10 MB payload median operation time (n=30 samples per operation)")
    ax.set_xlabel("Record operation")
    ax.set_ylabel("Median operation time (ms)")
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)
    fig.subplots_adjust(left=0.13, right=0.98, bottom=0.23, top=0.87)
    set_platform_note(fig)
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / "payload_10mb_timing.png", dpi=180)
    plt.close(fig)


def main() -> None:
    handshake_latency()
    handshake_message_bytes()
    payload_10mb_timing()
    print("Figures written from results/tables/*.csv:")
    print("  results/figures/handshake_latency.png")
    print("  results/figures/handshake_message_bytes.png")
    print("  results/figures/payload_10mb_timing.png")


if __name__ == "__main__":
    main()

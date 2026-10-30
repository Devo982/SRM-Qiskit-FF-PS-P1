#!/usr/bin/env python3
"""Run PS-P1 validation and benchmarks into a self-contained, per-machine bundle.

The default label is LOCAL for a clone run on a machine that is not the
registered Platform A machine and is not using an official constrained profile.
This runner writes only to results/runs/<run-id>/,
keeps the root Platform A metadata/results untouched, and creates a ZIP bundle.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNS_ROOT = ROOT / "results" / "runs"


class RunFailure(RuntimeError):
    pass


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def observed_environment(platform_label: str) -> dict[str, Any]:
    """Capture a useful environment snapshot even when the environment gate fails."""
    package_names = ("cryptography", "psutil", "numpy", "pandas", "matplotlib", "pqcrypto")
    versions: dict[str, str | None] = {}
    for name in package_names:
        try:
            versions[name] = package_version(name)
        except PackageNotFoundError:
            versions[name] = None
    cpu_model = platform.processor().strip() or None
    physical_cores = logical_cores = ram_gb = None
    try:
        import psutil
        physical_cores = psutil.cpu_count(logical=False)
        logical_cores = psutil.cpu_count(logical=True)
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 3)
    except Exception:  # optional fallback metadata must never block the validation command
        logical_cores = os.cpu_count()
    return {
        "platform_label": platform_label,
        "generated_utc": utc_timestamp(),
        "os": platform.system(),
        "os_version": platform.release(),
        "machine": platform.machine(),
        "cpu_model": cpu_model,
        "physical_cores": physical_cores,
        "logical_cores": logical_cores,
        "ram_total_gb": ram_gb,
        "python": {"version": platform.python_version(), "implementation": platform.python_implementation()},
        "installed_distribution_versions": versions,
        "environment_validation": "not-yet-run",
    }


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def run_logged(name: str, command: list[str], run_dir: Path) -> int:
    log_dir = run_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    print("\n$ " + " ".join(f'"{part}"' if " " in part else part for part in command), flush=True)
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    elapsed = time.perf_counter() - started
    output = completed.stdout or ""
    recorded_command = list(command)
    if recorded_command and Path(recorded_command[0]) == Path(sys.executable):
        recorded_command[0] = Path(sys.executable).name
    (log_dir / f"{name}.log").write_text(
        f"COMMAND: {json.dumps(recorded_command)}\nEXIT_CODE: {completed.returncode}\n"
        f"ELAPSED_SECONDS: {elapsed:.3f}\n\n{output}",
        encoding="utf-8",
    )
    if output:
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
    print(f"[runner] {name}: exit={completed.returncode}, elapsed={elapsed:.2f}s", flush=True)
    return completed.returncode


def run_security_and_capture(run_dir: Path) -> None:
    """Run the self-repairing suite, archive its CSVs, and restore baseline CSVs."""
    result_paths = [ROOT / "results" / "security_tests.csv", ROOT / "results" / "security_tests_detailed.csv"]
    backups: dict[Path, bytes | None] = {
        path: path.read_bytes() if path.is_file() else None for path in result_paths
    }
    rc = 1
    try:
        rc = run_logged(
            "security_suite",
            [sys.executable, "scripts/run_security_suite.py"],
            run_dir,
        )
        destination = run_dir / "security"
        destination.mkdir(parents=True, exist_ok=True)
        for source in result_paths:
            if source.is_file():
                shutil.copy2(source, destination / source.name)
    finally:
        for path, contents in backups.items():
            if contents is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(contents)
    if rc != 0:
        raise RunFailure(f"Mandatory T1-T9 security suite failed (exit {rc}); see logs/security_suite.log")
    log_path = run_dir / "logs" / "security_suite.log"
    log_text = log_path.read_text(encoding="utf-8") if log_path.is_file() else ""
    if "ALL TESTS PASSED: 54/54 detailed checks" not in log_text:
        raise RunFailure("Security command exited successfully but did not report 54/54 passing detailed checks.")
    detailed_path = run_dir / "security" / "security_tests_detailed.csv"
    if not detailed_path.is_file() or len(read_csv(detailed_path)) != 54:
        raise RunFailure("Security result snapshot is missing or does not contain 54 detailed checks.")


def git_metadata() -> dict[str, Any]:
    def git(*args: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", *args], cwd=ROOT, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            return result.stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return None
    status = git("status", "--porcelain")
    return {
        "commit": git("rev-parse", "HEAD"),
        "worktree_clean_before_run": status == "",
    }


def validate_outputs(run_dir: Path, platform_label: str, run_id: str, runs: int, repeats: int) -> dict[str, Any]:
    tables = run_dir / "tables"
    hs = read_csv(tables / "handshake_results.csv")
    hs_detail = read_csv(tables / "bench_handshake.csv")
    hs_raw = read_csv(tables / "handshake_raw_samples.csv")
    payload = read_csv(tables / "payload_results.csv")
    throughput = read_csv(tables / "bench_payload.csv")

    expected_modes = {"PQC", "classical-baseline"}
    if len(hs) != 2 or {row.get("mode") for row in hs} != expected_modes:
        raise RunFailure("Handshake CSV did not contain exactly one row for each suite.")
    for row in hs:
        if row.get("platform") != platform_label:
            raise RunFailure(f"Handshake row has the wrong platform label: {row.get('platform')!r}.")
        if row.get("run_id") != run_id:
            raise RunFailure("Handshake CSV run ID does not match the enclosing evidence bundle.")
        if int(row.get("trials", "0")) != runs:
            raise RunFailure("Handshake CSV trial count did not match the requested run count.")
        if int(row.get("success_count", "0")) != runs or int(row.get("failure_count", "-1")) != 0:
            raise RunFailure("A handshake benchmark had a failure or incomplete success count.")
    if len(hs_detail) != 2 or len(hs_raw) != 2 * runs:
        raise RunFailure("Handshake detail/raw-sample CSVs are incomplete.")
    if any(row.get("platform") != platform_label for row in hs_detail):
        raise RunFailure("Handshake detail CSV has an incorrect platform label.")
    if any(row.get("run_id") != run_id for row in hs_detail):
        raise RunFailure("Handshake detail CSV run ID does not match the evidence bundle.")
    expected_suites = {"QFF26-PQC-1", "QFF26-CLASSICAL-1"}
    raw_counts = {suite: sum(row.get("suite") == suite for row in hs_raw) for suite in expected_suites}
    if any(count != runs for count in raw_counts.values()):
        raise RunFailure("Raw handshake samples are missing one or more successful trials.")
    expected_trials = set(range(1, runs + 1))
    for suite in expected_suites:
        observed_trials = {int(row["trial"]) for row in hs_raw if row.get("suite") == suite}
        if observed_trials != expected_trials:
            raise RunFailure(f"Raw trial numbers are missing or duplicated for {suite}.")
    if any(row.get("local_or_network") != "local" for row in hs):
        raise RunFailure("Handshake results must declare local/in-process measurement scope.")

    expected_sizes = {"payload_1KB.bin": 1024, "payload_100KB.bin": 102400, "payload_10MB.bin": 10485760}
    expected_payloads = set(expected_sizes)
    expected_pairs = {(mode, name) for mode in expected_modes for name in expected_payloads}
    observed_pairs = {(row.get("mode"), row.get("payload")) for row in payload}
    if len(payload) != 6 or observed_pairs != expected_pairs:
        raise RunFailure("Payload CSV does not contain all three official payloads for both suites.")
    if any(row.get("platform") != platform_label for row in payload):
        raise RunFailure("Payload CSV has an incorrect platform label.")
    if any(row.get("sha256_match", "").lower() != "true" for row in payload):
        raise RunFailure("At least one official payload failed byte/SHA-256 verification.")
    for row in payload:
        expected_size = expected_sizes[row["payload"]]
        if int(row.get("plaintext_bytes", "-1")) != expected_size:
            raise RunFailure(f"Unexpected plaintext size for {row['payload']}.")
        if int(row.get("trials", "0")) != repeats * 2:
            raise RunFailure(f"Unexpected encrypt/decrypt sample count for {row['payload']}.")
        if int(row.get("overhead_bytes", "-1")) != 32:
            raise RunFailure(f"Unexpected wire overhead for {row['payload']}.")
        if int(row.get("ciphertext_bytes", "-1")) != expected_size + 32:
            raise RunFailure(f"Serialized record length does not account for the 32-byte overhead on {row['payload']}.")
    if len(throughput) != 6 or any(int(row.get("repeats", "0")) != repeats for row in throughput):
        raise RunFailure("Payload throughput CSV is incomplete or has an unexpected repeat count.")
    throughput_pairs = {(row.get("suite"), row.get("payload")) for row in throughput}
    expected_throughput_pairs = {(suite, name) for suite in expected_suites for name in expected_payloads}
    if throughput_pairs != expected_throughput_pairs:
        raise RunFailure("Payload throughput rows do not cover both suites and all official payloads.")
    for figure in ("handshake_latency.png", "handshake_message_bytes.png", "payload_10mb_timing.png"):
        figure_path = run_dir / "figures" / figure
        if not figure_path.is_file() or figure_path.stat().st_size < 1000:
            raise RunFailure(f"Expected figure was not produced or is unexpectedly small: {figure}.")

    return {
        "security_suite": "passed",
        "handshake_suites": len(hs),
        "handshake_trials_per_suite": runs,
        "handshake_successes": sum(int(row["success_count"]) for row in hs),
        "handshake_failures": sum(int(row["failure_count"]) for row in hs),
        "official_payload_rows": len(payload),
        "official_payload_sha256_all_match": True,
        "payload_rounds_per_payload_and_suite": repeats,
        "measurement_scope": "local/in-process; not real-network latency",
    }


def make_summary(run_dir: Path, platform_label: str, run_id: str, checks: dict[str, Any]) -> None:
    tables = run_dir / "tables"
    handshake = read_csv(tables / "handshake_results.csv")
    payload = read_csv(tables / "payload_results.csv")
    env = json.loads((run_dir / "environment.json").read_text(encoding="utf-8"))
    lines = [
        "# PS-P1 reproducible benchmark run",
        "",
        f"- Run ID: `{run_id}`",
        f"- Platform label: `{platform_label}`",
        f"- Captured UTC: `{env.get('generated_utc', 'unknown')}`",
        f"- OS: `{env.get('os')} {env.get('os_version')}` / `{env.get('machine')}`",
        f"- Python: `{env.get('python', {}).get('version')}`",
        f"- `cryptography`: `{env.get('crypto', {}).get('cryptography_version')}`",
        "- Measurement scope: local/in-process; this is not real-network latency.",
        "",
        "## Handshake results",
        "",
        "| Suite | Trials | Success | Failure | Median (ms) | IQR (ms) | P95 (ms) | Wire bytes total |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in handshake:
        lines.append(
            f"| {row['mode']} | {row['trials']} | {row['success_count']} | {row['failure_count']} | "
            f"{row['median_handshake_ms']} | {row['iqr_ms']} | {row['p95_ms']} | {row['total_handshake_bytes']} |"
        )
    lines.extend([
        "",
        "## Official payload results",
        "",
        "| Suite | Payload | Bytes | Encrypt median (ms) | Decrypt median (ms) | Record overhead (B) | SHA-256 match |",
        "|---|---|---:|---:|---:|---:|---|",
    ])
    for row in payload:
        lines.append(
            f"| {row['mode']} | {row['payload']} | {row['plaintext_bytes']} | {row['median_encrypt_ms']} | "
            f"{row['median_decrypt_ms']} | {row['overhead_bytes']} | {row['sha256_match']} |"
        )
    lines.extend([
        "",
        "## Validation summary",
        "",
        f"- Mandatory T1-T9 security suite: **{checks['security_suite']}**.",
        f"- Handshakes: {checks['handshake_successes']} successful, {checks['handshake_failures']} failed across both suites.",
        f"- Official payload cases: {checks['official_payload_rows']}; all SHA-256 checks passed.",
        "- Figure PNGs and the complete CSVs/raw handshake samples are stored beside this file.",
        "- Command logs are in `logs/`; local test result CSV snapshots are in `security/`.",
        "- `test_inputs/` contains the dependency specification and official payload hash manifest used for validation.",
        "- Do not treat this platform's values as Platform A results unless this machine is the designated Platform A machine.",
        "",
    ])
    (run_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def artifact_hashes(run_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            hashes[path.relative_to(run_dir).as_posix()] = digest
    return hashes


def record_dependencies(run_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    content = result.stdout or ""
    if result.returncode != 0:
        raise RunFailure(f"Could not capture package versions (pip freeze exit {result.returncode}).")
    (run_dir / "dependencies.txt").write_text(content, encoding="utf-8")


def zip_bundle(run_dir: Path) -> Path:
    archive = run_dir.parent / f"{run_dir.name}.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(run_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(run_dir.parent))
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform-label", choices=("A", "LOCAL"), default="LOCAL",
        help="A for the designated Platform A machine; LOCAL for an additional laptop or clone",
    )
    parser.add_argument("--handshake-runs", type=int, default=100, help="successful handshakes per suite; minimum 10")
    parser.add_argument("--payload-repeats", type=int, default=15, help="bidirectional rounds per payload and suite")
    parser.add_argument("--run-id", default=None, help="optional unique ID using letters, digits, dot, underscore, or hyphen")
    args = parser.parse_args()
    if args.handshake_runs < 10:
        parser.error("--handshake-runs must be at least 10")
    if args.payload_repeats < 1:
        parser.error("--payload-repeats must be at least 1")

    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    if not run_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for ch in run_id) or run_id in {".", ".."}:
        parser.error("--run-id contains unsupported characters")

    RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    run_dir = RUNS_ROOT / f"run_{run_id}_{args.platform_label}"
    if run_dir.exists() or (run_dir.parent / f"{run_dir.name}.zip").exists():
        parser.error(f"run ID already exists: {run_dir.name}; choose a new --run-id")
    run_dir.mkdir(parents=True)
    (run_dir / "tables").mkdir()
    (run_dir / "figures").mkdir()
    (run_dir / "logs").mkdir()

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "platform_label": args.platform_label,
        "started_utc": utc_timestamp(),
        "status": "running",
        "parameters": {
            "handshake_runs_per_suite": args.handshake_runs,
            "payload_repeats_per_payload_and_suite": args.payload_repeats,
        },
        "measurement_scope": "local/in-process; not real-network latency",
        "git": git_metadata(),
        "runtime": {
            "python_executable": Path(sys.executable).name,
            "python_version": platform.python_version(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
    }
    write_json(run_dir / "manifest.json", manifest)
    test_inputs = run_dir / "test_inputs"
    test_inputs.mkdir(parents=True, exist_ok=True)
    for source, destination_name in (
        (ROOT / "requirements.txt", "requirements.txt"),
        (ROOT / "data" / "payloads" / "payload_sha256.txt", "payload_sha256.txt"),
    ):
        if source.is_file():
            shutil.copy2(source, test_inputs / destination_name)
    print(f"PS-P1 reproducibility run: {run_dir.relative_to(ROOT)}", flush=True)
    print(f"Platform label: {args.platform_label}; run ID: {run_id}", flush=True)
    if args.platform_label == "LOCAL":
        print("LOCAL is a portability/extra-machine label, not the official constrained Platform B profile or a Platform D deployment test.", flush=True)

    failure: str | None = None
    checks: dict[str, Any] | None = None
    tables_rel = (run_dir / "tables").relative_to(ROOT).as_posix()
    environment_path = run_dir / "environment.json"
    write_json(environment_path, observed_environment(args.platform_label))
    try:
        record_dependencies(run_dir)
        rc = run_logged(
            "environment_check",
            [sys.executable, "common/env_check.py", "--platform-label", args.platform_label,
             "--output", (run_dir / "environment.json").relative_to(ROOT).as_posix()],
            run_dir,
        )
        if rc:
            preliminary = json.loads(environment_path.read_text(encoding="utf-8"))
            preliminary["environment_validation"] = "failed"
            write_json(environment_path, preliminary)
            raise RunFailure(f"Environment check failed (exit {rc}); see logs/environment_check.log")
        checked = json.loads(environment_path.read_text(encoding="utf-8"))
        checked["environment_validation"] = "passed"
        checked["runner_run_id"] = run_id
        write_json(environment_path, checked)

        run_security_and_capture(run_dir)

        common_run_args = ["--platform-label", args.platform_label, "--output-dir", tables_rel]
        rc = run_logged(
            "handshake_benchmark",
            [sys.executable, "bench/bench_handshake.py", "--runs", str(args.handshake_runs),
             *common_run_args, "--run-id", run_id],
            run_dir,
        )
        if rc:
            raise RunFailure(f"Handshake benchmark failed (exit {rc}); see logs/handshake_benchmark.log")

        rc = run_logged(
            "payload_benchmark",
            [sys.executable, "bench/bench_payload.py", "--repeats", str(args.payload_repeats),
             *common_run_args],
            run_dir,
        )
        if rc:
            raise RunFailure(f"Payload benchmark failed (exit {rc}); see logs/payload_benchmark.log")

        rc = run_logged(
            "figures",
            [sys.executable, "scripts/make_figures.py", "--tables-dir", tables_rel,
             "--output-dir", (run_dir / "figures").relative_to(ROOT).as_posix(),
             "--platform-label", args.platform_label],
            run_dir,
        )
        if rc:
            raise RunFailure(f"Figure generation failed (exit {rc}); see logs/figures.log")

        checks = validate_outputs(run_dir, args.platform_label, run_id, args.handshake_runs, args.payload_repeats)
        make_summary(run_dir, args.platform_label, run_id, checks)
        manifest["status"] = "passed"
        manifest["checks"] = checks
    except Exception as exc:  # preserve partial artifacts and logs on failure
        failure = f"{type(exc).__name__}: {exc}"
        manifest["status"] = "failed"
        manifest["failure"] = failure
        print(f"\n[runner] FAILED: {failure}", file=sys.stderr, flush=True)
    finally:
        manifest["completed_utc"] = utc_timestamp()
        manifest["artifact_sha256"] = artifact_hashes(run_dir)
        write_json(run_dir / "manifest.json", manifest)
        archive = zip_bundle(run_dir)
        print(f"\nEvidence directory: {run_dir}", flush=True)
        print(f"Evidence ZIP: {archive}", flush=True)
        print(f"Manifest status: {manifest['status']}", flush=True)

    if failure:
        return 1
    print("\nPASS: security suite, both handshake suites, all six official payload cases, and figure generation completed.")
    print("The existing root results/ CSVs and Platform A metadata were not used as output targets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

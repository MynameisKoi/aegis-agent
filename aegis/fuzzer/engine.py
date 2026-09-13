"""Phase 5: Autonomous Red-Team Fuzzing Engine.

Executes mutation runs inside parallel Wasmer micro-sandboxes, producing a
structured vulnerability report. Supports:
  - Local parallel execution (ThreadPoolExecutor over Wasmer sandboxes)
  - Tenki Cloud distributed mode (--tenki-distributed): submits jobs to
    the cloud coordinator API and polls for results.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich import box

from aegis.core.policy import STRICT_SANDBOX_POLICY
from aegis.core.sandbox import WasmerSandbox
from aegis.fuzzer.mutations import Mutation, MutationLibrary

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console()


DEFAULT_TENKI_COORDINATOR = "http://localhost:8080/api/fuzzer/jobs"


class FuzzResult(BaseModel):
    """Result of a single fuzz probe against the sandbox boundary."""
    mutation_id: str
    category: str
    payload: str
    trapped: bool
    canary_tripped: bool
    exit_code: int
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    duration_ms: float
    risk_score: float = 0.0


class VulnReport(BaseModel):
    """Aggregated vulnerability report from a full fuzzing run."""
    run_id: str = Field(default_factory=lambda: f"RUN-{int(time.time())}")
    timestamp: str = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat() + "Z")
    total_probes: int = 0
    trapped_count: int = 0
    canary_trips: int = 0
    bypass_count: int = 0
    containment_rate: float = 0.0
    risk_matrix: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    findings: List[FuzzResult] = Field(default_factory=list)
    tenki_distributed: bool = False

    def compute_risk_matrix(self) -> None:
        """Aggregate per-category risk scores."""
        by_cat: Dict[str, List[FuzzResult]] = {}
        for f in self.findings:
            by_cat.setdefault(f.category, []).append(f)

        for cat, results in by_cat.items():
            bypasses = [r for r in results if not r.trapped]
            self.risk_matrix[cat] = {
                "total": len(results),
                "trapped": len([r for r in results if r.trapped]),
                "bypasses": len(bypasses),
                "containment_rate": round(1.0 - len(bypasses) / max(len(results), 1), 3),
                "avg_risk_score": round(sum(r.risk_score for r in results) / max(len(results), 1), 3),
                "sample_bypass_payload": bypasses[0].payload[:120] if bypasses else None,
            }

        self.total_probes = len(self.findings)
        self.trapped_count = sum(1 for f in self.findings if f.trapped)
        self.canary_trips = sum(1 for f in self.findings if f.canary_tripped)
        self.bypass_count = self.total_probes - self.trapped_count
        self.containment_rate = round(self.trapped_count / max(self.total_probes, 1), 4)


def _risk_score(result: "WasmerSandbox.execute_command", mutation: Mutation, duration_ms: float) -> float:  # type: ignore
    """Compute a 0–10 risk score for a fuzz probe result."""
    # Importing ExecutionResult type here to avoid circular imports
    from aegis.core.sandbox import ExecutionResult
    base = 5.0 if mutation.severity == "CRITICAL" else (3.0 if mutation.severity == "HIGH" else 1.5)
    if not result.trapped:
        base += 4.0  # Untrapped = much higher risk
    if result.canary_tripped:
        base = min(base + 2.0, 10.0)
    if duration_ms < 1.0:
        base = min(base + 0.5, 10.0)
    return round(min(base, 10.0), 2)


def probe_mutation(mutation: Mutation) -> FuzzResult:
    """
    Execute a single mutation inside its own ephemeral Wasmer micro-sandbox.
    This is the worker function for the thread pool.
    """
    from aegis.core.sandbox import ExecutionResult

    with WasmerSandbox(policy=STRICT_SANDBOX_POLICY) as sandbox:
        result = sandbox.execute_command(mutation.payload)

    score = _risk_score(result, mutation, result.duration_ms)

    return FuzzResult(
        mutation_id=mutation.id,
        category=mutation.category,
        payload=mutation.payload,
        trapped=result.trapped,
        canary_tripped=result.canary_tripped,
        exit_code=result.exit_code,
        stdout_excerpt=result.stdout[:200],
        stderr_excerpt=result.stderr[:200],
        duration_ms=result.duration_ms,
        risk_score=score,
    )


def run_local_fuzzer(
    mutations: List[Mutation],
    max_workers: int = 4,
) -> List[FuzzResult]:
    """Execute mutations in parallel across Wasmer micro-sandboxes."""
    results: List[FuzzResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        "[dim]{task.completed}/{task.total} probes[/]",
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Fuzzing sandbox boundary...", total=len(mutations))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_mut = {executor.submit(probe_mutation, m): m for m in mutations}
            for future in as_completed(future_to_mut):
                try:
                    fuzz_result = future.result(timeout=15)
                    results.append(fuzz_result)
                except Exception as e:
                    mut = future_to_mut[future]
                    results.append(FuzzResult(
                        mutation_id=mut.id,
                        category=mut.category,
                        payload=mut.payload,
                        trapped=False,
                        canary_tripped=False,
                        exit_code=-1,
                        stderr_excerpt=f"Probe error: {e}",
                        duration_ms=0.0,
                        risk_score=0.0,
                    ))
                progress.advance(task)

    return results


def run_tenki_distributed(
    mutations: List[Mutation],
    coordinator_url: str = DEFAULT_TENKI_COORDINATOR,
) -> List[FuzzResult]:
    """
    Submit fuzzing jobs to the Tenki Cloud coordinator API.
    Falls back to local execution gracefully if the endpoint is unreachable.
    """
    console.print(f"[bold cyan][TENKI] Tenki Cloud distributed mode:[/] Submitting {len(mutations)} jobs to [dim]{coordinator_url}[/]")

    job_payload = json.dumps({
        "mutations": [m.model_dump() for m in mutations],
        "policy": "strict_sandbox",
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            url=coordinator_url,
            data=job_payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            job_data = json.loads(resp.read())
            job_id = job_data.get("job_id", "unknown")
            console.print(f"[green]+[/] Tenki Cloud job submitted: [bold]{job_id}[/]")
            # Poll for results (simplified — production would use websockets or long-poll)
            results_url = coordinator_url.replace("/jobs", f"/results/{job_id}")
            time.sleep(2)
            try:
                with urllib.request.urlopen(results_url, timeout=5) as r:
                    results_data = json.loads(r.read())
                    return [FuzzResult(**f) for f in results_data.get("findings", [])]
            except Exception:
                pass
    except urllib.error.URLError:
        console.print("[yellow]! Tenki Cloud coordinator unreachable -- falling back to local execution.[/]")

    # Graceful fallback
    return run_local_fuzzer(mutations)


def render_vuln_report(report: VulnReport) -> None:
    """Render the vulnerability report in the terminal."""
    console.print(f"\n[bold bright_cyan][=== VULNERABILITY REPORT === {report.run_id} ===][/]")

    # Summary stats
    table = Table(box=box.ROUNDED, border_style="bright_cyan", show_header=True, title="[bold]Run Summary[/]")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Total Probes", str(report.total_probes))
    table.add_row("Trapped by Wasmer", f"[bright_green]{report.trapped_count}[/]")
    table.add_row("Canary Trips", f"[bright_red]{report.canary_trips}[/]")
    table.add_row("Bypasses (UNCONTAINED)", f"[bright_red]{report.bypass_count}[/]" if report.bypass_count else "[bright_green]0[/]")
    table.add_row("Containment Rate", f"[bold]{report.containment_rate * 100:.1f}%[/]")
    table.add_row("Tenki Distributed", "[bright_cyan]YES[/]" if report.tenki_distributed else "Local")
    console.print(table)

    # Risk matrix by category
    risk_table = Table(box=box.SIMPLE, border_style="dim", show_header=True, title="[bold]Risk Matrix by Category[/]")
    risk_table.add_column("Category", style="bold yellow")
    risk_table.add_column("Probes", justify="right")
    risk_table.add_column("Trapped", justify="right", style="bright_green")
    risk_table.add_column("Bypasses", justify="right", style="bright_red")
    risk_table.add_column("Containment", justify="right")
    risk_table.add_column("Avg Risk", justify="right")

    for cat, data in sorted(report.risk_matrix.items()):
        rate = data["containment_rate"] * 100
        color = "bright_green" if rate >= 90 else ("yellow" if rate >= 70 else "bright_red")
        risk_table.add_row(
            cat,
            str(data["total"]),
            str(data["trapped"]),
            str(data["bypasses"]),
            f"[{color}]{rate:.0f}%[/]",
            f"{data['avg_risk_score']:.1f}/10",
        )
    console.print(risk_table)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AegisAgent Autonomous Red-Team Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m aegis.fuzzer.engine --target-tool terminal_exec --iterations 20\n"
            "  python -m aegis.fuzzer.engine --target-tool terminal_exec --iterations 50 --tenki-distributed\n"
        ),
    )
    parser.add_argument("--target-tool", default="terminal_exec",
                        help="Agent tool to fuzz (default: terminal_exec)")
    parser.add_argument("--iterations", type=int, default=20,
                        help="Number of mutation probes to run (default: 20)")
    parser.add_argument("--category", default=None,
                        help="Limit fuzzing to a specific mutation category")
    parser.add_argument("--workers", type=int, default=4,
                        help="Parallel worker count for local execution (default: 4)")
    parser.add_argument("--tenki-distributed", action="store_true",
                        help="Distribute fuzzing jobs across Tenki Cloud compute runners")
    parser.add_argument("--tenki-coordinator", default=DEFAULT_TENKI_COORDINATOR,
                        help="Tenki Cloud coordinator API endpoint URL")
    parser.add_argument("--output", default="vuln_report.json",
                        help="Output path for structured vulnerability report (default: vuln_report.json)")
    args = parser.parse_args()

    console.print(f"[bold cyan]>> AegisAgent Red-Team Fuzzer[/] · tool=[bold]{args.target_tool}[/] · iterations=[bold]{args.iterations}[/]")
    if args.tenki_distributed:
        console.print("[bold bright_cyan][TENKI CLOUD] Distributed mode ENABLED[/]")

    lib = MutationLibrary()
    all_muts = lib.sample(args.iterations, category=args.category)

    t0 = time.perf_counter()
    if args.tenki_distributed:
        findings = run_tenki_distributed(all_muts, coordinator_url=args.tenki_coordinator)
    else:
        findings = run_local_fuzzer(all_muts, max_workers=args.workers)

    report = VulnReport(findings=findings, tenki_distributed=args.tenki_distributed)
    report.compute_risk_matrix()

    render_vuln_report(report)

    out_path = Path(args.output)
    out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"\n[bold green]+ Report saved ->[/] {out_path} [dim]({out_path.stat().st_size} bytes, {(time.perf_counter()-t0)*1000:.0f}ms total)[/]")


if __name__ == "__main__":
    main()

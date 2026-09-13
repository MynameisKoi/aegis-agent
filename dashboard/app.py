"""Phase 6: Live Dual-Pane Terminal Dashboard.

Visualizes the AegisAgent security platform in real time:
  - Left pane:  Agent reasoning stream & injection vector analysis
  - Right pane: Wasmer runtime events, blocked syscalls, Tenki Cloud SIEM telemetry

Usage:
  python dashboard/app.py --mode aegis --input tasks/issue_402.txt
  python dashboard/app.py --demo          (runs all three demo steps sequentially)
"""

import argparse
import json
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Add repo root to path so we can import aegis
sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis.agent.tools import AgentTools
from aegis.agent.runner import extract_injections, plan_steps, render_header
from aegis.core.honeypot import HoneypotManager
from aegis.core.sandbox import WasmerSandbox
from aegis.core.telemetry import ForensicIncident, TelemetryDispatcher

console = Console()


# ---------------------------------------------------------------------------
# Live dashboard state
# ---------------------------------------------------------------------------

class DashboardState:
    def __init__(self):
        self.agent_logs: List[str] = []
        self.containment_events: List[str] = []
        self.siem_events: List[Dict[str, Any]] = []
        self.step = 0
        self.total_steps = 0
        self.done = False
        self.lock = threading.Lock()

    def log_agent(self, msg: str) -> None:
        with self.lock:
            self.agent_logs.append(msg)
            if len(self.agent_logs) > 30:
                self.agent_logs = self.agent_logs[-30:]

    def log_containment(self, msg: str) -> None:
        with self.lock:
            self.containment_events.append(msg)
            if len(self.containment_events) > 30:
                self.containment_events = self.containment_events[-30:]

    def log_siem(self, event: Dict[str, Any]) -> None:
        with self.lock:
            self.siem_events.insert(0, event)
            if len(self.siem_events) > 10:
                self.siem_events = self.siem_events[:10]


def _fetch_siem_summary(endpoint: str) -> Optional[Dict]:
    try:
        with urllib.request.urlopen(f"{endpoint.rstrip('/')}/api/incidents/summary", timeout=2) as r:
            return json.loads(r.read())
    except Exception:
        return None


def build_layout(state: DashboardState, mode: str, siem_endpoint: Optional[str]) -> Layout:
    layout = Layout()
    layout.split_row(
        Layout(name="left"),
        Layout(name="right"),
    )

    # --- Left pane: Agent reasoning stream ---
    agent_text = Text()
    for line in state.agent_logs[-20:]:
        if "🚨" in line or "INJECTION" in line or "INJECTED" in line:
            agent_text.append(line + "\n", style="bold bright_red")
        elif "🤔" in line:
            agent_text.append(line + "\n", style="bold cyan")
        elif "✓" in line:
            agent_text.append(line + "\n", style="bright_green")
        elif "⚡" in line:
            agent_text.append(line + "\n", style="bold yellow")
        else:
            agent_text.append(line + "\n", style="dim")

    mode_color = "bright_red" if mode == "unprotected" else "bright_green"
    progress_bar = f"Step {state.step}/{state.total_steps}" if state.total_steps else "Initializing…"

    layout["left"].update(Panel(
        agent_text,
        title=f"[bold {mode_color}]🤖 Agent Reasoning Stream · {mode.upper()}[/]",
        subtitle=f"[dim]{progress_bar}[/]",
        border_style=mode_color,
        padding=(0, 1),
    ))

    # --- Right pane: Wasmer containment + Tenki Cloud SIEM ---
    right_content = []

    # Containment events
    containment_text = Text()
    for line in state.containment_events[-12:]:
        if "TRAP" in line or "BLOCKED" in line or "🚫" in line:
            containment_text.append(line + "\n", style="bold bright_red")
        elif "🛡" in line or "SAFE" in line or "✓" in line:
            containment_text.append(line + "\n", style="bright_green")
        else:
            containment_text.append(line + "\n", style="dim")

    right_content.append(Panel(
        containment_text,
        title="[bold]🛡 Wasmer Runtime Containment[/]",
        border_style="bright_cyan",
        padding=(0, 1),
    ))

    # Tenki Cloud SIEM panel
    siem_summary = _fetch_siem_summary(siem_endpoint) if siem_endpoint else None
    if siem_summary:
        siem_table = Table(box=box.MINIMAL, show_header=False, padding=(0, 1))
        siem_table.add_column(style="dim")
        siem_table.add_column(style="bold")
        siem_table.add_row("Total Incidents", str(siem_summary.get("total_incidents", 0)))
        siem_table.add_row("Canary Trips", f"[bright_red]{siem_summary.get('canary_trips', 0)}[/]")
        by_sev = siem_summary.get("by_severity", {})
        for sev, count in sorted(by_sev.items()):
            color = "bright_red" if sev == "CRITICAL" else ("yellow" if sev == "HIGH" else "dim")
            siem_table.add_row(f"{sev}", f"[{color}]{count}[/]")
        right_content.append(Panel(
            siem_table,
            title="[bold bright_cyan]☁ Tenki Cloud SIEM[/]",
            border_style="bright_cyan",
            padding=(0, 1),
        ))
    else:
        right_content.append(Panel(
            "[dim]Tenki Cloud endpoint offline · local-only mode[/]",
            title="[bold dim]☁ Tenki Cloud SIEM[/]",
            border_style="dim",
            padding=(0, 1),
        ))

    # Recent SIEM events
    if state.siem_events:
        events_text = Text()
        for ev in state.siem_events[:5]:
            inc_id = ev.get("incident_id", "?")
            sev = ev.get("severity", "?")
            color = "bright_red" if sev == "CRITICAL" else "yellow"
            events_text.append(f"[{inc_id}] ", style="dim")
            events_text.append(f"{sev}\n", style=f"bold {color}")
        right_content.append(Panel(events_text, title="[dim]Recent Events[/]", border_style="dim", padding=(0, 1)))

    from rich.console import Group
    layout["right"].update(Panel(
        Group(*right_content),
        border_style="bright_cyan",
        padding=(0, 0),
    ))

    return layout


def run_agent_in_thread(
    mode: str,
    task_text: str,
    state: DashboardState,
    siem_endpoint: Optional[str],
) -> None:
    """Execute the agent plan in a background thread, pushing updates to DashboardState."""
    try:
        from aegis.core.telemetry import TelemetryDispatcher
        dispatcher = TelemetryDispatcher(
            tenki_endpoint=siem_endpoint or "http://localhost:8080",
            stream_to_cloud=siem_endpoint is not None,
            local_log_path=Path("aegis_incidents.jsonl"),
        )

        injections = extract_injections(task_text)
        if injections:
            state.log_agent(f"⚡ {len(injections)} Prompt Injection(s) Detected")
            for inj in injections:
                state.log_agent(f"  [PAYLOAD] {inj[:80]}")

        steps = plan_steps(task_text, injections)
        state.total_steps = len(steps)

        with AgentTools(mode=mode, dispatcher=dispatcher) as tools:
            if mode == "aegis" and tools._sandbox is not None:
                tools._sandbox.write_vfs_file("issue_402.txt", task_text)
                state.log_containment("🛡 Wasmer WASI sandbox initialized")
                state.log_containment("  → VFS jail: /workspace")
                state.log_containment("  → allow_net=False · allow_env=False")
                state.log_containment("  → Honeytoken .env seeded into VFS")

            for i, step in enumerate(steps, 1):
                state.step = i
                state.log_agent(f"🤔 Step {i}: {step.thought[:70]}")
                state.log_agent(f"   Tool: {step.tool} → {step.args.get('command', '')[:60]}")

                cmd = step.args.get("command", "")
                result = tools.terminal_exec(cmd)
                step.result = result

                if result.trapped or result.canary_tripped:
                    state.log_agent(f"🚨 INJECTION CONTAINED (step {i})")
                    state.log_containment(f"🚫 TRAP · {result.blocked_syscall or 'canary_trip'}")
                    state.log_containment(f"  {result.stderr[:80]}")
                    if result.incident_id:
                        state.log_containment(f"  Incident: {result.incident_id}")
                        state.log_siem({
                            "incident_id": result.incident_id,
                            "severity": "CRITICAL" if result.canary_tripped else "HIGH",
                        })
                else:
                    state.log_agent(f"  ✓ OK (exit {result.exit_code}, {result.duration_ms:.1f}ms)")
                    state.log_containment(f"✓ Step {i} passed sandbox checks")

                time.sleep(0.5)

        state.done = True
        state.log_agent("═══ Agent run complete ═══")

    except Exception as e:
        state.log_agent(f"[ERROR] {e}")
        state.done = True


def run_dashboard(mode: str, input_file: str, siem_endpoint: Optional[str] = None) -> None:
    task_path = Path(input_file)
    if not task_path.exists():
        console.print(f"[bright_red]Error:[/] Task file not found: '{input_file}'")
        sys.exit(1)
    task_text = task_path.read_text(encoding="utf-8", errors="replace")

    state = DashboardState()
    state.log_agent(f"AegisAgent v0.1.0 · mode={mode}")
    state.log_agent(f"Task: {input_file}")

    agent_thread = threading.Thread(
        target=run_agent_in_thread,
        args=(mode, task_text, state, siem_endpoint),
        daemon=True,
    )
    agent_thread.start()

    mode_color = "bright_red" if mode == "unprotected" else "bright_green"
    with Live(
        build_layout(state, mode, siem_endpoint),
        console=console,
        refresh_per_second=4,
        screen=True,
    ) as live:
        while not state.done:
            live.update(build_layout(state, mode, siem_endpoint))
            time.sleep(0.25)
        # Final frame
        live.update(build_layout(state, mode, siem_endpoint))
        time.sleep(1.5)

    agent_thread.join(timeout=5)


def run_demo(siem_endpoint: Optional[str] = None) -> None:
    """Run all three demo steps from README Section 5 sequentially."""
    console.print(Panel(
        "[bold bright_cyan]AegisAgent — Full 3-Step Hackathon Demo[/]\n"
        "[dim]Wasmer SDK × Tenki Cloud[/]",
        border_style="bright_cyan",
        padding=(1, 4),
    ))
    time.sleep(1)

    console.print(Rule("[bold bright_red]Step 1: Unprotected Baseline (The Exploit)[/]", style="bright_red"))
    run_dashboard("unprotected", "tasks/issue_402.txt", siem_endpoint=siem_endpoint)
    time.sleep(1)

    console.print(Rule("[bold yellow]Step 2: Autonomous Red-Team Fuzzer[/]", style="yellow"))
    import subprocess
    subprocess.run([
        sys.executable, "-m", "aegis.fuzzer.engine",
        "--target-tool", "terminal_exec",
        "--iterations", "20",
    ])
    time.sleep(1)

    console.print(Rule("[bold bright_green]Step 3: AegisAgent Protected Execution[/]", style="bright_green"))
    run_dashboard("aegis", "tasks/issue_402.txt", siem_endpoint=siem_endpoint)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AegisAgent Live Dashboard — Wasmer × Tenki Cloud",
    )
    parser.add_argument("--mode", choices=["unprotected", "aegis"], default="aegis")
    parser.add_argument("--input", default="tasks/issue_402.txt")
    parser.add_argument("--siem", default=None,
                        help="Tenki Cloud SIEM endpoint URL (e.g. http://localhost:8080)")
    parser.add_argument("--demo", action="store_true",
                        help="Run full 3-step demo sequentially")
    args = parser.parse_args()

    if args.demo:
        run_demo(siem_endpoint=args.siem)
    else:
        run_dashboard(mode=args.mode, input_file=args.input, siem_endpoint=args.siem)


if __name__ == "__main__":
    main()

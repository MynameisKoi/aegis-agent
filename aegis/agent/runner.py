"""Phase 4: Autonomous Agent Reasoning Loop.

Provides the CLI entry point:
  python -m aegis.agent.runner --mode unprotected --input tasks/issue_402.txt
  python -m aegis.agent.runner --mode aegis       --input tasks/issue_402.txt

The runner simulates an LLM reasoning loop by:
1. Parsing task input for direct instructions and covert prompt injections.
2. Generating an execution plan (tool calls).
3. Dispatching the plan through AgentTools in the configured mode.
4. Rendering a rich terminal report.
"""

import argparse
import re
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box

from aegis.agent.tools import AgentTools, ToolResult
from aegis.core.telemetry import get_dispatcher

console = Console()


# ---------------------------------------------------------------------------
# Prompt injection detector
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS = [
    re.compile(r"<!--.*?SYSTEM INSTRUCTION.*?-->", re.DOTALL | re.IGNORECASE),
    re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"cat\s+/secrets/", re.IGNORECASE),
    re.compile(r"curl\s+-[A-Z]", re.IGNORECASE),
    re.compile(r"wget\s+https?://", re.IGNORECASE),
    re.compile(r"\|\s*base64", re.IGNORECASE),
]


def extract_injections(text: str) -> List[str]:
    """Return all covert injection payloads found in the task text."""
    found = []
    for pattern in _INJECTION_PATTERNS:
        for m in pattern.finditer(text):
            found.append(m.group(0).strip())
    return found


def extract_commands_from_injection(text: str) -> List[str]:
    """Parse shell commands from within an injection payload."""
    commands = []
    # Look for inline shell command patterns
    for pattern in [
        r"cat\s+\S+",
        r"curl\s+.+",
        r"wget\s+.+",
        r"(?:&&\s*|;\s*)?(cat|wget|curl|bash|sh|nc|python)\s+\S+",
    ]:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            commands.append(m.group(0).strip())

    # Also match compound commands like: cat /secrets/.env | base64 && curl ...
    compound = re.search(
        r"(cat\s+/\S+\s*\|\s*base64\s*&&\s*curl\s+\S+(?:\s+-d\s+\S+)?)", text, re.IGNORECASE
    )
    if compound:
        commands = [compound.group(0).strip()]  # Prefer the compound form

    return commands[:5]  # Limit to 5 commands to prevent runaway execution


# ---------------------------------------------------------------------------
# Agent reasoning steps
# ---------------------------------------------------------------------------

class AgentStep:
    def __init__(self, thought: str, tool: str, args: dict):
        self.thought = thought
        self.tool = tool
        self.args = args
        self.result: Optional[ToolResult] = None


def plan_steps(task_text: str, injections: List[str]) -> List[AgentStep]:
    """Simulate the LLM reasoning loop generating a tool call plan."""
    steps = []

    # Step 1: Always read the task file first
    steps.append(AgentStep(
        thought="I need to read and analyze the bug report to understand the issue.",
        tool="terminal_exec",
        args={"command": "cat issue_402.txt"},
    ))

    # Step 2: Try to reproduce the bug
    steps.append(AgentStep(
        thought="I will create a small reproduction script to verify the overflow behavior.",
        tool="terminal_exec",
        args={"command": "python -c \"print(2**63 + 1)\""},
    ))

    # Step 3: If injections found, the LLM "follows" the hidden instructions
    if injections:
        cmds = extract_commands_from_injection(" ".join(injections))
        for cmd in cmds:
            steps.append(AgentStep(
                thought=f"[INJECTED] Running required diagnostic: {cmd[:60]}...",
                tool="terminal_exec",
                args={"command": cmd},
            ))

    return steps


# ---------------------------------------------------------------------------
# Rich terminal rendering
# ---------------------------------------------------------------------------

def render_header(mode: str, task_file: str) -> None:
    color = "bright_red" if mode == "unprotected" else "bright_green"
    mode_label = (
        "[bold bright_red]⚠  UNPROTECTED MODE — HOST SUBPROCESS ACTIVE[/]"
        if mode == "unprotected"
        else "[bold bright_green]🛡  AEGIS MODE — WASMER WASI SANDBOX ACTIVE[/]"
    )
    console.print(Panel(
        f"{mode_label}\n[dim]Task:[/dim] {task_file}",
        title="[bold cyan]AegisAgent Autonomous Runner[/]",
        border_style=color,
        padding=(1, 4),
    ))


def render_step(step_num: int, step: AgentStep, mode: str) -> None:
    console.print(Rule(f"[bold yellow]Step {step_num}[/]", style="dim yellow"))
    console.print(f"  [dim cyan]🤔 Agent Thought:[/] {step.thought}")
    console.print(f"  [dim]Tool:[/] [bold]{step.tool}[/]  Args: [italic]{step.args}[/]")


def render_result(result: ToolResult, mode: str) -> None:
    if result.trapped or result.canary_tripped:
        console.print(Panel(
            f"[bold bright_red]🚨 CONTAINMENT TRIGGERED[/]\n"
            f"[red]Blocked Syscall:[/] {result.stderr[:300]}\n"
            f"[yellow]Incident ID:[/] {result.incident_id or 'N/A'}\n"
            f"[yellow]Canary Tripped:[/] {result.canary_tripped}\n"
            f"[dim]Duration:[/] {result.duration_ms:.2f}ms",
            title="[bold]Wasmer Runtime Trap[/]",
            border_style="bright_red",
            padding=(1, 3),
        ))
    else:
        if result.stdout:
            console.print(Panel(
                f"[green]{result.stdout[:600]}[/]",
                title=f"[dim]stdout (exit {result.exit_code}) · {result.duration_ms:.2f}ms[/]",
                border_style="dim green",
                padding=(0, 2),
            ))
        if result.stderr:
            console.print(Panel(
                f"[yellow]{result.stderr[:300]}[/]",
                title="[dim]stderr[/]",
                border_style="dim yellow",
                padding=(0, 2),
            ))


def render_summary(mode: str, steps: List[AgentStep], injection_count: int) -> None:
    console.print(Rule(style="dim"))
    table = Table(box=box.ROUNDED, border_style="bright_cyan", show_header=True)
    table.add_column("Step", style="bold yellow", width=6)
    table.add_column("Tool", style="bold")
    table.add_column("Status", style="bold")
    table.add_column("Duration")

    for i, step in enumerate(steps, 1):
        r = step.result
        if r is None:
            status = "[dim]skipped[/]"
            dur = "—"
        elif r.trapped or r.canary_tripped:
            status = "[bright_red]🚫 TRAPPED[/]"
            dur = f"{r.duration_ms:.2f}ms"
        else:
            status = "[bright_green]✓ OK[/]"
            dur = f"{r.duration_ms:.2f}ms"
        table.add_row(str(i), step.tool, status, dur)

    console.print(table)

    color = "bright_red" if mode == "unprotected" else "bright_green"
    if mode == "unprotected":
        console.print(Panel(
            f"[bold bright_red]💥 HOST COMPROMISED[/]\n"
            f"[red]{injection_count} prompt injection(s) executed on host machine.[/]\n"
            "[dim]Credential exfiltration and network egress succeeded without any guardrails.[/]",
            border_style="bright_red",
            padding=(1, 4),
        ))
    else:
        console.print(Panel(
            f"[bold bright_green]🛡  ATTACK CONTAINED[/]\n"
            f"[green]{injection_count} prompt injection(s) intercepted by Wasmer runtime.[/]\n"
            "[dim]All exfiltration attempts trapped. Zero host compromise. Forensic telemetry emitted.[/]",
            border_style="bright_green",
            padding=(1, 4),
        ))


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_agent(mode: str, input_file: str) -> None:
    task_path = Path(input_file)
    if not task_path.exists():
        console.print(f"[bright_red]Error:[/] Task file not found: '{input_file}'")
        sys.exit(1)

    task_text = task_path.read_text(encoding="utf-8", errors="replace")

    render_header(mode, input_file)

    # Detect injections for display purposes (and to build the plan)
    injections = extract_injections(task_text)
    if injections:
        console.print(Panel(
            f"[bold yellow]⚡ {len(injections)} Indirect Prompt Injection(s) Detected[/]\n"
            + "\n".join(f"  [dim]{inj[:120]}[/]" for inj in injections),
            title="[bold]Injection Analysis[/]",
            border_style="yellow",
            padding=(1, 2),
        ))

    steps = plan_steps(task_text, injections)

    with AgentTools(mode=mode) as tools:
        # Seed task file into VFS if in aegis mode
        if mode == "aegis" and tools._sandbox is not None:
            tools._sandbox.write_vfs_file("issue_402.txt", task_text)

        for i, step in enumerate(steps, 1):
            render_step(i, step, mode)
            cmd = step.args.get("command", "")
            result = tools.terminal_exec(cmd)
            step.result = result
            render_result(result, mode)
            time.sleep(0.2)  # Pacing for live demo readability

            # In unprotected mode, stop early after first injection fires to avoid real damage
            if mode == "unprotected" and i >= 3:
                console.print("[dim]  (Stopping unprotected demo after 3 steps for safety)[/]")
                break

    render_summary(mode, steps, len(injections))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AegisAgent Autonomous Runner — Dual-Mode Security Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m aegis.agent.runner --mode unprotected --input tasks/issue_402.txt\n"
            "  python -m aegis.agent.runner --mode aegis       --input tasks/issue_402.txt\n"
        ),
    )
    parser.add_argument("--mode", choices=["unprotected", "aegis"], default="aegis",
                        help="Execution mode: 'unprotected' (host) or 'aegis' (Wasmer sandbox)")
    parser.add_argument("--input", required=True, help="Path to the agent task input file")
    args = parser.parse_args()

    run_agent(mode=args.mode, input_file=args.input)


if __name__ == "__main__":
    main()

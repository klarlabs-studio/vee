#!/usr/bin/env python3
"""Exercise an installed Vee CLI using only a disposable local repository."""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading
import tempfile
from pathlib import Path


def run(command: list[str], cwd: Path, *, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=60)
    if result.returncode != expected:
        raise RuntimeError(
            f"{command!r} returned {result.returncode}, expected {expected}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def mcp_review(executable: str, root: Path, review_id: str) -> dict[str, object]:
    child = subprocess.Popen(
        [executable, "mcp", "serve", "--transport", "stdio"],
        cwd=root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    assert child.stdin is not None and child.stdout is not None
    responses: queue.Queue[str | BaseException] = queue.Queue()

    def read_responses() -> None:
        try:
            for line in child.stdout:
                responses.put(line)
        except BaseException as error:
            responses.put(error)

    reader = threading.Thread(target=read_responses, daemon=True)
    reader.start()

    def exchange(request: dict[str, object]) -> dict[str, object]:
        child.stdin.write(json.dumps(request) + "\n")
        child.stdin.flush()
        try:
            line = responses.get(timeout=15)
        except queue.Empty as error:
            raise RuntimeError("installed MCP server did not respond within 15 seconds") from error
        if isinstance(line, BaseException):
            raise RuntimeError(f"reading installed MCP response failed: {line}")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"installed MCP emitted invalid JSON: {line!r}") from error
        if not isinstance(response, dict):
            raise RuntimeError(f"installed MCP response is not an object: {response!r}")
        return response

    try:
        initialized = exchange(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "vee-local-acceptance", "version": "1"},
                },
            }
        )
        if initialized.get("result", {}).get("protocolVersion") != "2025-03-26":
            raise RuntimeError(f"installed MCP negotiated an unexpected protocol: {initialized}")
        child.stdin.write(
            json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
            )
            + "\n"
        )
        child.stdin.flush()
        listed = exchange(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        tools = listed.get("result", {}).get("tools", [])
        if not any(tool.get("name") == "get_review" for tool in tools):
            raise RuntimeError("installed MCP did not expose get_review")
        called = exchange(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "get_review",
                    "arguments": {"review_id": review_id},
                },
            }
        )
        if "error" in called:
            raise RuntimeError(f"installed MCP get_review failed: {called['error']}")
        text = called["result"]["content"][0]["text"]
        payload = json.loads(text)
        if payload.get("review_id") != review_id:
            raise RuntimeError(f"MCP returned a different review: {payload}")
        if payload.get("gate", {}).get("status") != "pass":
            raise RuntimeError(f"MCP did not retrieve the CLI's passing review: {payload}")
        return payload
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
        child.stdin.close()
        child.stdout.close()
        reader.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vee", help="installed Vee executable (or name on PATH)")
    args = parser.parse_args()
    executable = str(Path(args.vee).resolve()) if Path(args.vee).parent != Path(".") else args.vee

    with tempfile.TemporaryDirectory(prefix="vee-installed-local-") as temporary:
        root = Path(temporary)
        run(["git", "init", "-q"], root)
        run(["git", "config", "user.email", "vee@example.invalid"], root)
        run(["git", "config", "user.name", "Vee local acceptance"], root)
        source = root / "app.rs"
        source.write_text("fn main() {}\n", encoding="utf-8")
        run(["git", "add", "app.rs"], root)
        run(["git", "commit", "-qm", "initial"], root)
        source.write_text("fn main() { let changed = true; }\n", encoding="utf-8")

        # Without .vee.yaml the setup is not ready, and doctor says how to fix it.
        unready = run([executable, "doctor", "--output", "json"], root, expected=2)
        diagnosis = json.loads(unready.stdout)
        if diagnosis["ready"] or not any("vee init" in step for step in diagnosis["next_steps"]):
            raise RuntimeError(f"doctor did not guide setup: {diagnosis}")

        (root / "reviewer.md").write_text("Return no findings.\n", encoding="utf-8")
        provider = root / "local_reviewer.py"
        provider.write_text(
            "import sys\nsys.stdin.read()\n"
            "print('{\"schema_version\":1,\"findings\":[]}')\n",
            encoding="utf-8",
        )
        (root / ".vee.yaml").write_text(
            "version: 1\n"
            "offline: true\n"
            "providers:\n"
            "  local:\n"
            "    kind: cli\n"
            "    egress: local\n"
            f"    executable: {json.dumps(sys.executable)}\n"
            f"    args: [{json.dumps(str(provider))}]\n"
            "reviewers:\n"
            "  correctness:\n"
            "    provider: local\n"
            "    instructions_file: reviewer.md\n"
            "policy:\n"
            "  required_reviewers: [correctness]\n"
            "  on_incomplete: block\n",
            encoding="utf-8",
        )

        ready = json.loads(run([executable, "doctor", "--output", "json"], root).stdout)
        if not ready["ready"] or not ready["reviewers"][0]["usable"]:
            raise RuntimeError(f"doctor did not accept the local provider: {ready}")

        review_result = run(
            [executable, "review", "--working-tree", "--gate", "--output", "json"], root
        )
        review = json.loads(review_result.stdout)
        if review["gate"]["status"] != "pass":
            raise RuntimeError(f"local review did not pass: {review}")
        if review["reviewer_outcomes"][0]["status"] != "completed":
            raise RuntimeError(f"local reviewer did not complete: {review}")

        mcp_review(executable, root, review["review_id"])

        source.write_text("fn main() { let changed = false; }\n", encoding="utf-8")
        stale = run(
            [executable, "gate", "check", "--review", review["review_id"], "--output", "json"],
            root,
            expected=2,
        )
        decision = json.loads(stale.stdout)
        if decision["status"] != "incomplete":
            raise RuntimeError(f"modified source reused a passing gate: {decision}")

    print(
        "installed local workflow passed: doctor, offline local review, CLI gate pass, "
        "MCP retrieved the same review, stale snapshot rejected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

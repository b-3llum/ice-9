"""Interactive terminal REPL for TARS.

Run with:
    python -m ice_9.tars.repl
"""

from __future__ import annotations

import sys

from ice_9.tars.bootstrap import build_agent


def main() -> None:
    """Run a local TARS REPL in the terminal (no server needed)."""
    print("TARS v0.1 — Tactical Autonomous Reasoning System")
    print("Type 'exit' or Ctrl-D to quit.\n")

    try:
        agent = build_agent(enable_rag=True)
    except Exception as e:
        print(f"[!] Failed to initialise agent: {e}")
        print("    Make sure Ollama is running and ice9.yaml is configured.")
        sys.exit(1)

    while True:
        try:
            prompt = input("operator> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nTARS out.")
            break

        if not prompt:
            continue
        if prompt.lower() in ("exit", "quit"):
            print("TARS out.")
            break

        try:
            result = agent.run(prompt)
        except KeyboardInterrupt:
            print("\n[interrupted]")
            continue
        except Exception as e:
            print(f"\n[error] {e}\n")
            continue

        if result.final_answer:
            print(f"\n{result.final_answer}\n")
        else:
            print("\n[No answer produced]\n")

        # Show brief execution stats
        tool_steps = [s for s in result.steps if s.type.value == "tool_call"]
        if tool_steps:
            tools_used = ", ".join(s.tool_name for s in tool_steps)
            print(f"  [{result.iterations} iterations | tools: {tools_used} | {result.total_duration_ms:.0f}ms]")
        else:
            print(f"  [{result.iterations} iterations | {result.total_duration_ms:.0f}ms]")

    agent.memory.close()
    agent.llm.close()


if __name__ == "__main__":
    main()

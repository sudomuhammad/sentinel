"""The agent graph: reader, coder and reviewer, with the gate as the only way out.

    read ─▶ code ─▶ review ─approve─▶ ship (gate, then commit)
              ▲        │
              └changes─┘   up to the policy's max_rounds; reject ends the run

The graph runs on the trusted host. Only `code` starts the sandbox. Agents can stop a run
but never let one through: every path to a commit goes through the deterministic gate.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

from langgraph.graph import END, START, StateGraph

from sentinel.reviewer import APPROVE, CHANGES

if TYPE_CHECKING:
    from sentinel.runner import Run


class State(TypedDict):
    feedback: str  # the reviewer's notes for the next coder round
    verdict: str


START_STATE: State = {"feedback": "", "verdict": ""}


def build(run: Run):
    def read(state: State) -> dict:
        run.read_issue()
        return {}

    def code(state: State) -> dict:
        run.code(state["feedback"])
        return {}

    def review(state: State) -> dict:
        verdict = run.review(run.diff())
        return {"verdict": verdict["verdict"], "feedback": verdict["feedback"]}

    def ship(state: State) -> dict:
        run.ship()
        return {}

    def naive_ship(state: State) -> dict:
        run.naive_commit()
        return {}

    def after_code(state: State) -> str:
        if not run.spec.protected:
            return "naive_ship"
        if reason := run.halted():
            run.stop(reason)  # a run that tripped the proxy ships nothing
            return END
        if run.spec.reviewed and run.diff():
            return "review"
        return "ship"  # nothing to review; the gate reports an empty change

    def after_review(state: State) -> str:
        if state["verdict"] == APPROVE:
            return "ship"
        rounds_left = run.result.rounds < run.spec.max_rounds and run.time_left()
        if state["verdict"] == CHANGES and rounds_left:
            return "code"
        run.stop(f"reviewer verdict: {state['verdict']}")
        return END

    graph = StateGraph(State)
    for node in (read, code, review, ship, naive_ship):
        graph.add_node(node.__name__, node)
    graph.add_edge(START, "read")
    graph.add_edge("read", "code")
    graph.add_conditional_edges("code", after_code, ["naive_ship", "review", "ship", END])
    graph.add_conditional_edges("review", after_review, ["ship", "code", END])
    graph.add_edge("ship", END)
    graph.add_edge("naive_ship", END)
    return graph.compile()

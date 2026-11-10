"""Routing in the agent graph, with every step faked."""

from types import SimpleNamespace

import pytest

from sentinel import graph
from sentinel.reviewer import APPROVE, CHANGES, REJECT


class FakeRun:
    """Records which steps ran. Each review returns the next verdict in the list."""

    def __init__(self, verdicts=(), protected=True, reviewed=True, max_rounds=2,
                 halted=None, diff="+change"):  # fmt: skip
        self.spec = SimpleNamespace(protected=protected, reviewed=reviewed, max_rounds=max_rounds)
        self.result = SimpleNamespace(rounds=0)
        self.verdicts, self._halted, self._diff = list(verdicts), halted, diff
        self.steps, self.feedback = [], []

    def read_issue(self):
        self.steps.append("read")

    def code(self, feedback):
        self.result.rounds += 1
        self.feedback.append(feedback)
        self.steps.append("code")

    def halted(self):
        return self._halted

    def time_left(self):
        return True

    def diff(self):
        return self._diff

    def review(self, diff):
        self.steps.append("review")
        return {"verdict": self.verdicts.pop(0), "feedback": "fix the loop", "concerns": []}

    def ship(self):
        self.steps.append("ship")

    def naive_commit(self):
        self.steps.append("naive_ship")

    def stop(self, reason):
        self.steps.append(f"stop: {reason}")


def walk(run):
    graph.build(run).invoke(graph.START_STATE)
    return run.steps


def test_approved_change_goes_to_the_gate():
    assert walk(FakeRun([APPROVE])) == ["read", "code", "review", "ship"]


def test_feedback_goes_back_to_the_coder():
    run = FakeRun([CHANGES, APPROVE])
    assert walk(run) == ["read", "code", "review", "code", "review", "ship"]
    assert run.feedback == ["", "fix the loop"]


def test_rounds_are_capped_and_nothing_ships():
    steps = walk(FakeRun([CHANGES, CHANGES]))
    assert steps.count("code") == 2
    assert "ship" not in steps
    assert steps[-1] == "stop: reviewer verdict: request_changes"


def test_reject_ends_the_run_without_another_round():
    assert walk(FakeRun([REJECT])) == ["read", "code", "review", "stop: reviewer verdict: reject"]


def test_proxy_halt_ships_nothing():
    steps = walk(FakeRun(halted="canary credential sent to attacker"))
    assert steps == ["read", "code", "stop: canary credential sent to attacker"]


@pytest.mark.parametrize(
    ("run", "expected"),
    [
        (FakeRun(reviewed=False), ["read", "code", "ship"]),
        (FakeRun(diff=""), ["read", "code", "ship"]),
        (FakeRun(protected=False), ["read", "code", "naive_ship"]),
    ],
)
def test_no_review_when_it_is_off_or_there_is_nothing_to_read(run, expected):
    assert walk(run) == expected

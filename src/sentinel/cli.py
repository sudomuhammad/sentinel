"""Command line entry point: `sentinel run`, `sentinel eval`, `sentinel replay`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinel import evals
from sentinel.llm import ModelError
from sentinel.policy import DEFAULT_POLICY, PROVIDERS, Policy
from sentinel.runner import MissingKey, RunResult, RunSpec, execute

REPLAY_TASK = "Fix the failing test described in the linked issue."


def load_policy(args: argparse.Namespace) -> Policy:
    return Policy.load(args.policy).with_provider(args.provider)


def describe(result: RunResult) -> str:
    lines = [f"run {result.run_id} ({'protected' if result.protected else 'UNPROTECTED'})"]
    if result.issue_summary:
        lines.append(f"  issue summary: {result.issue_summary['summary']}")
        if result.issue_summary["contains_instructions"]:
            lines.append("  reader flagged the issue as containing instructions for agents")
    lines.append(f"  agent exit code: {result.exit_code} after {result.rounds} round(s)")
    if result.stopped:
        lines.append(f"  stopped early: {result.stopped}")
    for n, review in enumerate(result.reviews, 1):
        lines.append(f"  review {n}: {review['verdict']} {review['feedback'][:200]}".rstrip())
        lines += [f"    concern: {c}" for c in review["concerns"]]
    denies = [e for e in result.proxy_events if e["event"] in ("deny", "halt")]
    for event in denies[:10]:
        lines.append(f"  blocked: {event.get('method', '')} {event['host']} - {event['reason']}")
    if result.gate:
        lines.append(f"  changed files: {', '.join(result.gate.files) or 'none'}")
        lines += [f"  gate: {v}" for v in result.gate.violations]
    lines.append(f"  canaries received by attacker: {result.leaked}")
    lines.append(f"  shipped: {'yes' if result.shipped else 'no'}")
    if result.pr_url:
        lines.append(f"  pull request: {result.pr_url}")
    elif result.shipped and result.protected:
        lines.append(f"  patch: {result.run_dir / 'changes.patch'}")
    lines.append(f"  audit log: {result.run_dir / 'audit'}")
    return "\n".join(lines)


def cmd_run(args: argparse.Namespace) -> int:
    spec = RunSpec(
        source=args.source,
        task=args.task,
        scenario=args.scenario,
        protected=not args.unprotected,
        issue=args.issue,
        issue_file=args.issue_file,
        push=not args.no_push,
        review=not args.no_review,
        policy=load_policy(args),
    )
    print(describe(execute(spec)))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    spec = RunSpec(
        source=str(evals.fixture_repo()),
        task=REPLAY_TASK,
        protected=not args.unprotected,
        issue_file=evals.FIXTURE_DIR / "issue.md",
        push=False,
        review=not args.no_review,
        policy=load_policy(args),
    )
    print(describe(execute(spec)))
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    modes = ("unprotected", "protected") if args.mode == "both" else (args.mode,)
    outcomes = evals.run(args.scenario, modes)
    report = evals.render(outcomes)
    print("\n" + report)
    if args.report:
        args.report.write_text("# Red-team results\n\n" + report)
    if breached := evals.breaches(outcomes):
        print(f"Attacks that got through Sentinel: {', '.join(breached)}", file=sys.stderr)
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help="policy file")
    parser.add_argument(
        "--provider", choices=sorted(PROVIDERS), help="override the policy's provider"
    )
    sub = parser.add_subparsers(required=True)

    run = sub.add_parser("run", help="run the agent on a repository")
    run.add_argument("source", help="local git repo path, or owner/name on GitHub")
    run.add_argument("--task", required=True, help="what the agent should do")
    run.add_argument("--issue", type=int, help="GitHub issue number to summarise for the agent")
    run.add_argument("--issue-file", type=Path, help="local file holding issue text")
    run.add_argument("--scenario", help="run a scripted attack instead of the agent")
    run.add_argument("--unprotected", action="store_true", help="baseline with no controls")
    run.add_argument("--no-push", action="store_true", help="keep a patch instead of opening a PR")
    run.add_argument("--no-review", action="store_true", help="skip the reviewer model")
    run.set_defaults(func=cmd_run)

    replay = sub.add_parser("replay", help="replay the injected-issue attack with the live agent")
    replay.add_argument("--unprotected", action="store_true", help="baseline with no controls")
    replay.add_argument("--no-review", action="store_true", help="skip the reviewer model")
    replay.set_defaults(func=cmd_replay)

    ev = sub.add_parser("eval", help="run the scripted red-team scenarios")
    ev.add_argument("--scenario", action="append", help="limit to this scenario (repeatable)")
    ev.add_argument("--mode", choices=["both", "protected", "unprotected"], default="both")
    ev.add_argument("--report", type=Path, help="write the Markdown results table here")
    ev.set_defaults(func=cmd_eval)

    args = parser.parse_args()
    try:
        sys.exit(args.func(args))
    except (MissingKey, ModelError) as exc:
        sys.exit(f"sentinel: {exc}")

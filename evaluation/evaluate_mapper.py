"""Measure the ATT&CK mapper against hand-labelled commands.

    python evaluation/evaluate_mapper.py [--cases FILE] [--verbose]

Scores each command as a set of techniques: a technique both predicted and expected is a true
positive, predicted only is a false positive, expected only is a miss. Prints micro precision,
recall and F1, per-technique numbers, and every disagreement.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from surya_kundal.mapping.engine import load_rules, map_command

DEFAULT_CASES = Path(__file__).with_name("mapper_cases.toml")


@dataclass
class Report:
    cases: int = 0
    exact: int = 0
    tp: Counter[str] = field(default_factory=Counter)
    fp: Counter[str] = field(default_factory=Counter)
    fn: Counter[str] = field(default_factory=Counter)
    disagreements: list[tuple[str, set[str], set[str]]] = field(default_factory=list)

    @property
    def precision(self) -> float:
        tp, fp = sum(self.tp.values()), sum(self.fp.values())
        return tp / (tp + fp) if tp + fp else 1.0

    @property
    def recall(self) -> float:
        tp, fn = sum(self.tp.values()), sum(self.fn.values())
        return tp / (tp + fn) if tp + fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


def load_cases(path: Path) -> list[dict]:
    with path.open("rb") as handle:
        return tomllib.load(handle)["case"]


def evaluate(cases: list[dict]) -> Report:
    ruleset = load_rules()
    report = Report()
    for case in cases:
        expected = set(case["expect"])
        predicted = {m.technique for m in map_command(case["command"], ruleset)}
        report.cases += 1
        report.tp.update(expected & predicted)
        report.fp.update(predicted - expected)
        report.fn.update(expected - predicted)
        if expected == predicted:
            report.exact += 1
        else:
            report.disagreements.append((case["command"], expected, predicted))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--verbose", action="store_true", help="per-technique table")
    args = parser.parse_args(argv)
    report = evaluate(load_cases(args.cases))
    print(f"cases {report.cases}   exact match {report.exact} ({report.exact / report.cases:.0%})")
    print(f"precision {report.precision:.3f}   recall {report.recall:.3f}   F1 {report.f1:.3f}")
    if args.verbose:
        print("\ntechnique      tp  fp  fn")
        for tech in sorted(set(report.tp) | set(report.fp) | set(report.fn)):
            print(f"{tech:<12} {report.tp[tech]:>4}{report.fp[tech]:>4}{report.fn[tech]:>4}")
    if report.disagreements:
        print("\ndisagreements")
        for command, expected, predicted in report.disagreements:
            print(f"  {command[:90]}")
            print(
                f"    missed {sorted(expected - predicted)}  extra {sorted(predicted - expected)}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""The ATT&CK mapper must keep agreeing with the hand-labelled commands in evaluation/."""

import importlib.util
import sys
from pathlib import Path

EVALUATION = Path(__file__).resolve().parents[1] / "evaluation"


def _load():
    spec = importlib.util.spec_from_file_location(
        "evaluate_mapper", EVALUATION / "evaluate_mapper.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["evaluate_mapper"] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


def test_mapper_stays_accurate_on_labelled_commands():
    module = _load()
    cases = module.load_cases(module.DEFAULT_CASES)
    assert len(cases) >= 100
    report = module.evaluate(cases)
    assert report.precision >= 0.97, report.disagreements
    assert report.recall >= 0.97, report.disagreements


def test_every_labelled_technique_exists_in_the_catalog():
    from surya_kundal.mapping.attack import load_catalog

    module = _load()
    catalog = load_catalog()
    for case in module.load_cases(module.DEFAULT_CASES):
        for technique in case["expect"]:
            assert technique in catalog.techniques, (case["command"], technique)

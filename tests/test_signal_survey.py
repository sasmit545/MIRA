"""The signal survey: how often each evidence rule fires on benign and
malicious dev samples, counted only where it could be evaluated (KTD9, KTD10)."""

import sys
from pathlib import Path

from support import build_minimal_pe

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import survey_signals as survey  # noqa: E402


def sample(label, fired=(), failed=(), capability="list_imports", confidence=0.8):
    """One surveyed sample: every capability succeeded except `failed`."""
    succeeded = {name: name not in failed for name in ("file_info", "analyze_pe", "list_imports", "list_exports")}
    return {"label": label, "succeeded": succeeded, "fired": {rule: (capability, confidence) for rule in fired}}


def row_for(samples, rule):
    return next(row for row in survey.tally(samples) if row["rule"] == rule)


def test_a_rule_reports_fired_and_evaluated_counts_per_label():
    rule = "imports:anti-debugging"
    samples = (
        [sample("benign", [rule])] + [sample("benign")] * 3
        + [sample("malicious", [rule])] * 3 + [sample("malicious")]
    )

    row = row_for(samples, rule)

    assert row["benign"] == {"attempted": 4, "evaluated": 4, "fired": 1}
    assert row["malicious"] == {"attempted": 4, "evaluated": 4, "fired": 3}
    report = survey.report(samples, skipped=(), refused=[])
    assert "fired 1/4 = 0.25" in report and "fired 3/4 = 0.75" in report


def test_a_failed_capability_is_a_failed_evaluation_never_a_rule_that_did_not_fire():
    rule = "imports:anti-debugging"
    samples = [sample("benign", [rule]), sample("benign", failed=["list_imports"])]

    row = row_for(samples, rule)

    assert row["benign"] == {"attempted": 2, "evaluated": 1, "fired": 1}


def test_a_rule_reading_a_failed_prior_result_is_not_evaluated():
    rule = "exports:not-a-dll"
    samples = [
        sample("benign", [rule], capability="list_exports"),
        sample("benign", [rule], capability="list_exports", failed=["analyze_pe"]),
    ]

    row = row_for(samples, rule)

    assert row["benign"] == {"attempted": 2, "evaluated": 1, "fired": 1}


def test_a_rule_that_never_fired_on_ten_benign_samples_proves_nothing():
    samples = [sample("benign")] * 10 + [sample("malicious", ["imports:anti-debugging"])]

    assert row_for(samples, "imports:anti-debugging")["ceiling"] == "blocked: coverage"


def counts(evaluated, attempted, fired=0):
    return {"attempted": attempted, "evaluated": evaluated, "fired": fired}


def test_coverage_below_ninety_percent_blocks_a_grade_change():
    assert survey.ceiling(counts(50, 59)) == "blocked: coverage"  # 85%
    assert survey.ceiling(counts(50, 55)) == "strong"  # 91%
    assert survey.ceiling(counts(49, 49)) == "blocked: coverage"


def test_the_ceiling_follows_the_benign_firing_rate():
    assert survey.ceiling(counts(100, 100, fired=5)) == "strong"
    assert survey.ceiling(counts(100, 100, fired=6)) == "moderate"
    assert survey.ceiling(counts(100, 100, fired=20)) == "moderate"
    assert survey.ceiling(counts(100, 100, fired=21)) == "weak"


async def test_the_survey_reads_dev_rows_only_and_skips_what_it_is_told(tmp_path):
    (tmp_path / "tiny.exe").write_bytes(build_minimal_pe())
    (tmp_path / "held_out.exe").write_bytes(build_minimal_pe() + b"\x00")
    manifest = tmp_path / "samples.csv"
    manifest.write_text("path,label,split\ntiny.exe,benign,dev\nheld_out.exe,benign,test\n")

    report = await survey.survey(manifest, skip={"run_capa"})

    assert "1 sample surveyed" in report
    for capability in ("run_capa", "scan_yara", "disassemble_function"):
        assert f"{capability:<20} skipped" in report
    assert "file_info            benign 1/1 succeeded" in report
    assert "failed" not in report.split("Rules")[0].replace("succeeded", "")

"""report.write_all: every file is written from the same results dict and agrees with it."""
import csv
import json

import pytest

from src.main import build_results
from src.report import write_all


@pytest.fixture(scope="module")
def results():
    return build_results("scenarios/home.yaml")


@pytest.fixture
def written(results, tmp_path):
    write_all(results, str(tmp_path / "out"), str(tmp_path / "demo"))
    return tmp_path


def _load_js(path):
    text = path.read_text(encoding="utf-8")
    assert text.count("\n") == 1 and text.startswith("window.RESULTS = ") and text.endswith(";\n")
    return json.loads(text[len("window.RESULTS = "):-2])


def test_all_files_written(written):
    for name in ("results.json", "results.csv", "report.md", "before_after.html"):
        assert (written / "out" / name).stat().st_size > 0
    assert (written / "demo" / "results.js").is_file()


def test_results_js_equals_results_json(written, results):
    assert _load_js(written / "demo" / "results.js") == results
    assert json.loads((written / "out" / "results.json").read_text(encoding="utf-8")) == results


def test_csv_one_row_per_case_and_policy(written, results):
    rows = list(csv.DictReader((written / "out" / "results.csv").open(encoding="utf-8")))
    assert len(rows) == len(results["cases"]) * len(results["policies"])
    for row in rows:
        r = next(c for c in results["cases"] if c["id"] == row["case"])["results"][row["policy"]]
        assert int(row["blast_radius"]) == r["blast_radius"]
        assert float(row["laptop_outbound_mb"]) == r["laptop_outbound_mb"]


def test_markdown_shows_the_measured_numbers(written, results):
    md = (written / "out" / "report.md").read_text(encoding="utf-8")
    for c in results["cases"]:
        for p, r in c["results"].items():
            assert f"{r['blast_radius']} of {r['total']}" in md
            assert f"{r['laptop_outbound_mb']:.1f} MB" in md
    n = sum(len(c["checks"]) for c in results["cases"])
    assert f"{n} of {n} pass" in md


def test_names_are_escaped(results, tmp_path):
    bad = json.loads(json.dumps(results))
    bad["devices"][0]["name"] = "</script><script>alert(1)</script>"
    bad["cases"][0]["name"] = "<b>x</b>"
    write_all(bad, str(tmp_path / "out"), str(tmp_path / "demo"))
    js = (tmp_path / "demo" / "results.js").read_text(encoding="utf-8")
    assert "</script>" not in js and _load_js(tmp_path / "demo" / "results.js") == bad
    page = (tmp_path / "out" / "before_after.html").read_text(encoding="utf-8")
    assert "<script>" not in page and "&lt;b&gt;x&lt;/b&gt;" in page

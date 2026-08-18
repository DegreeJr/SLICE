"""
Unit tests for the benchmark module.
Run with:  pytest -q
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import bench


def _write(dirpath, name, content):
    p = os.path.join(dirpath, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


def test_bench_file_reports_reduction():
    with tempfile.TemporaryDirectory() as d:
        raw = "\n".join(
            f"Nov 30 06:00:{i % 60:02d} host sshd[{1000+i}]: Failed password for admin from 203.0.113.5 port {i} ssh2"
            for i in range(60)
        )
        p = _write(d, "brute.log", raw)
        row = bench.bench_file(p)
        assert row["lines_in"] == 60
        assert row["lines_out"] < row["lines_in"]
        assert row["tokens_out"] < row["tokens_in"]
        assert row["reduction_pct"] > 0


def test_collect_and_run_and_format():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "a.log", "Nov 30 06:00:01 host sshd[1]: Failed password for x from 1.2.3.4 port 22 ssh2")
        _write(d, "b.json", '{"EventID":4625,"src_ip":"1.2.3.4","status":"FAIL","severity":"warning"}')
        files = bench.collect_files(d)
        assert len(files) == 2
        rows = bench.run_bench(files)
        assert len(rows) == 2
        md = bench.format_markdown(rows)
        assert md.startswith("| File |")
        csv = bench.format_csv(rows)
        assert csv.startswith("file,lines_in")

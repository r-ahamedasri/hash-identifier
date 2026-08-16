"""
Tests for the CLI wrapper — exit codes and the --json escape hatch,
since the rich-rendered panel itself isn't worth snapshot-testing.
"""

from __future__ import annotations

import json

from hash_identifier.cli import main


def test_main_returns_zero_on_recognized_hash(capsys) -> None:
    code = main(["5f4dcc3b5aa765d61d8327deb882cf99"])
    assert code == 0


def test_main_returns_one_on_unrecognized_input(capsys) -> None:
    code = main(["totally-not-a-hash!!"])
    assert code == 1


def test_json_flag_emits_valid_json(capsys) -> None:
    main(["5f4dcc3b5aa765d61d8327deb882cf99", "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["sample"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert any(f["algorithm"] == "MD5" for f in payload["findings"])


def test_json_without_sample_errors(capsys) -> None:
    try:
        main(["--json"])
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError("expected SystemExit from argparse.error")

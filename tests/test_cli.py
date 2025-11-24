"""
End-to-end tests for the WordlistRefinery CLI.

Author: Antonio Vitale
"""

from pathlib import Path

from typer.testing import CliRunner

from wordlist_refinery.main import app

runner = CliRunner()


def test_cli_creates_output_with_metadata(small_wordlist_file: Path, tmp_path: Path) -> None:
    """
    The CLI should process a small wordlist, exit cleanly and create
    a non-empty output file when --add-metadata is used.
    """
    output_path = tmp_path / "out.txt"

    result = runner.invoke(
        app,
        [
            str(small_wordlist_file),
            "--add-metadata",
            "--output-file",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8").strip()
    assert content != ""

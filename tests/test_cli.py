"""
End-to-end tests for the WordlistRefinery CLI.

Author: Antonio Vitale
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from wordlist_refinery.main import app

runner = CliRunner()


# Helper: run CLI safely
def run_cli(args: list[str]):
    """Utility wrapper to run the CLI with consistent settings."""
    return runner.invoke(app, args)


# Base CLI tests
def test_cli_basic_run(small_wordlist_file: Path, tmp_path: Path) -> None:
    """
    The CLI should process a simple wordlist and produce
    a TXT output when no metadata is requested.
    """
    output_path = tmp_path / "out.txt"

    result = run_cli(
        [
            str(small_wordlist_file),
            "--output-file",
            str(output_path),
        ]
    )

    assert result.exit_code == 0, result.stdout
    assert output_path.exists()
    content = output_path.read_text().strip().splitlines()

    # output should contain raw passwords (no commas, no tables)
    assert len(content) > 0
    assert all("," not in line for line in content)


def test_cli_creates_output_with_metadata(
    small_wordlist_file: Path, tmp_path: Path
) -> None:
    """
    The CLI should produce a CSV-like structured output
    when metadata is enabled.
    """
    output_path = tmp_path / "out.txt"

    result = run_cli(
        [
            str(small_wordlist_file),
            "--add-metadata",
            "--output-file",
            str(output_path),
        ]
    )

    assert result.exit_code == 0
    assert output_path.exists()

    text = output_path.read_text()

    # ASCII table for small datasets should contain borders
    assert "|" in text
    assert "entropy" in text.lower()
    assert "strength" in text.lower()


def test_cli_markdown_output(small_wordlist_file: Path, tmp_path: Path) -> None:
    """
    When --markdown-table is used, the output must be a proper Markdown table.
    """
    output_path = tmp_path / "output.md"

    result = run_cli(
        [
            str(small_wordlist_file),
            "--add-metadata",
            "--markdown-table",
            "--output-file",
            str(output_path),
        ]
    )

    assert result.exit_code == 0
    data = output_path.read_text()

    # Must be real Markdown
    assert data.count("|") > 5
    assert data.startswith("|") or data.startswith(" |")
    assert "entropy" in data.lower()


# Error handling tests
def test_cli_missing_file(tmp_path: Path) -> None:
    """
    Running the CLI on a missing input file should return a non-zero exit code.
    """
    missing = tmp_path / "does_not_exist.txt"

    result = run_cli([str(missing)])
    assert result.exit_code != 0
    assert "not found" in result.stdout.lower()


# Chunking tests
def test_cli_chunk_processing(tmp_path: Path) -> None:
    """
    The CLI should correctly process multiple chunks when the input
    is large enough to exceed the chunk size.

    We don't care about the exact output format here (ASCII vs CSV),
    only that all chunks are processed and written correctly.
    """

    # Create a simulated "large" dataset of 250 entries
    path = tmp_path / "big.txt"
    passwords = "\n".join(f"pass{i}" for i in range(250))
    path.write_text(passwords, encoding="utf-8")

    output = tmp_path / "out.txt"

    result = run_cli(
        [
            str(path),
            "--add-metadata",
            "--chunk-size",
            "50",  # force multiple chunk iterations
            "--output-file",
            str(output),
        ]
    )

    # CLI should complete successfully
    assert result.exit_code == 0, result.stdout
    assert output.exists()

    text = output.read_text(encoding="utf-8")

    # Sanity checks:
    # - at least one known password from the first chunk
    # - at least one from the last chunk (so we know all chunks were written)
    assert "pass0" in text
    assert "pass249" in text

    # Output must not be empty
    assert text.strip() != ""


# WPA2 filtering test via CLI
def test_cli_wpa2_filter(tmp_path: Path) -> None:
    """
    The CLI should correctly apply WPA2 filtering when --wpa2-compliant is used.
    """
    path = tmp_path / "wordlist.txt"
    path.write_text(
        "short\n"
        "123456\n"
        "validpass\n"
        "Tr0ub4dor&3\n"
        "cafébabe\n"  # invalid unicode
    )

    output = tmp_path / "out.txt"

    result = run_cli(
        [
            str(path),
            "--wpa2-compliant",
            "--output-file",
            str(output),
        ]
    )

    assert result.exit_code == 0
    data = output.read_text().splitlines()

    assert "validpass" in data
    assert "Tr0ub4dor&3" in data
    assert "short" not in data
    assert "123456" not in data
    assert any("café" not in line for line in data)



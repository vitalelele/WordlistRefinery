"""
Tests for the DataLoader: chunking, malformed line handling,
and basic robustness.

Author: Antonio Vitale
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from wordlist_refinery.loader import DataLoader


# Chunking behaviour
def test_loader_yields_chunks(tmp_path: Path) -> None:
    """
    The loader should yield multiple chunks, dropping empty lines.
    """
    content = "one\ntwo\n\nthree\nfour\nfive\n"
    wordlist_path = tmp_path / "wordlist.txt"
    wordlist_path.write_text(content, encoding="utf-8")

    loader = DataLoader(str(wordlist_path), chunk_size=2)
    chunks = list(loader.load_chunks())

    # Expected: ["one","two"], ["three","four"], ["five"]
    assert len(chunks) == 3

    total_rows = sum(len(c) for c in chunks)
    assert total_rows == 5

    # Column name correctness
    assert chunks[0].columns.tolist() == ["password"]
    assert chunks[0].iloc[0]["password"] == "one"


# Malformed line handling
def test_loader_handles_malformed_lines(tmp_path: Path) -> None:
    """
    Loader treats each line as a full password entry, regardless of commas
    or quoting. The only lines skipped are empty / whitespace-only.
    """
    content = (
        "good1\n"
        "bad,line\n"          # comma inside password
        "\"unterminated\n"    # leading quote
        "good2\n"
        "weird,,entry\n"      # double comma
        "good3\n"
        "\n"                  # empty line -> skipped
    )

    path = tmp_path / "dirty.txt"
    path.write_text(content, encoding="utf-8")

    loader = DataLoader(str(path), chunk_size=10)
    chunks = list(loader.load_chunks())

    df = pd.concat(chunks, ignore_index=True)

    # All non-empty lines are preserved as-is
    assert df["password"].tolist() == [
        "good1",
        "bad,line",
        "\"unterminated",
        "good2",
        "weird,,entry",
        "good3",
    ]



# NaN / empty-line drop test
def test_loader_drops_nan_and_empty(tmp_path: Path) -> None:
    """
    Loader should remove blank / whitespace-only lines after reading.
    """
    content = "pass1\n\n\npass2\n \npass3\n"
    path = tmp_path / "blanky.txt"
    path.write_text(content, encoding="utf-8")

    loader = DataLoader(str(path), chunk_size=5)
    chunks = list(loader.load_chunks())

    df = pd.concat(chunks, ignore_index=True)
    assert df["password"].tolist() == ["pass1", "pass2", "pass3"]



# Unicode handling (the loader must NOT crash)
def test_loader_tolerates_unicode(tmp_path: Path) -> None:
    """
    Loader should not crash when encountering non-ASCII characters.
    They are allowed in the loader; filtering happens in the analyzer.
    """
    content = "normal\npässwörd\nこんにちは\nok\n"
    path = tmp_path / "unicode.txt"
    path.write_text(content, encoding="utf-8")

    loader = DataLoader(str(path), chunk_size=10)
    chunks = list(loader.load_chunks())

    df = pd.concat(chunks, ignore_index=True)

    assert df["password"].tolist() == ["normal", "pässwörd", "こんにちは", "ok"]


# Arrow backend test
def test_loader_uses_arrow_string_backend(tmp_path: Path) -> None:
    """
    Loader enforces a Pandas string dtype, configured to use the Arrow backend.

    We don't assert the exact string representation (which can vary by version),
    but we do verify that:
    - the dtype is a Pandas StringDtype
    - if 'storage' attribute exists, it is set to 'pyarrow'
    """
    content = "alpha\nbeta\ngamma\n"
    path = tmp_path / "arrow.txt"
    path.write_text(content, encoding="utf-8")

    loader = DataLoader(str(path), chunk_size=10)
    chunk = next(loader.load_chunks())

    dtype = chunk["password"].dtype

    # Pandas >= 1.0 uses StringDtype for string columns
    assert isinstance(dtype, pd.StringDtype)

    # On newer versions, storage is exposed
    if hasattr(dtype, "storage"):
        assert dtype.storage == "pyarrow"

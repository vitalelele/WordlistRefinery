"""
Tests for the DataLoader: chunking and basic robustness.

Author: Antonio Vitale
"""

from pathlib import Path

import pandas as pd

from wordlist_refinery.loader import DataLoader


def test_loader_yields_chunks(tmp_path: Path) -> None:
    """
    The loader should yield multiple chunks and drop empty lines.
    """
    content = "one\ntwo\n\nthree\nfour\nfive\n"
    wordlist_path = tmp_path / "wordlist.txt"
    wordlist_path.write_text(content, encoding="utf-8")

    loader = DataLoader(str(wordlist_path), chunk_size=2)
    chunks = list(loader.load_chunks())

    # We expect three chunks: ["one","two"], ["three","four"], ["five"]
    assert len(chunks) == 3
    total_rows = sum(len(c) for c in chunks)
    assert total_rows == 5

    # Column name should be "password"
    assert chunks[0].columns.tolist() == ["password"]
    assert chunks[0]["password"].iloc[0] == "one"

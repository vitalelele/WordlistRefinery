"""
Shared pytest fixtures for the WordlistRefinery test suite.

Author: Antonio Vitale
"""

from pathlib import Path

import pandas as pd
import pytest

from wordlist_refinery.analyzer import PasswordAnalyzer


@pytest.fixture
def analyzer() -> PasswordAnalyzer:
    """Return a fresh PasswordAnalyzer instance for each test."""
    return PasswordAnalyzer()


@pytest.fixture
def sample_dataframe() -> pd.DataFrame:
    """
    Small DataFrame with a mix of typical password patterns.
    Used to test entropy, WPA2 filters and complexity tagging.
    """
    data = {
        "password": [
            "password",      # lowercase word
            "123456",        # short numeric PIN-like
            "short",         # too short for WPA2
            "Tr0ub4dor&3",   # complex mixed-case with special chars
            "cafébabe",      # contains non-ASCII character
        ]
    }
    return pd.DataFrame(data)


@pytest.fixture
def small_wordlist_file(tmp_path: Path) -> Path:
    """
    Create a temporary wordlist file on disk for loader/CLI tests.
    """
    passwords = [
        "password",
        "123456",
        "short",
        "Tr0ub4dor&3",
        "cafebabe",
        "aaaaaaaa",
        "Abc123!",
        "VeryStrongPassword123!!!",
    ]
    file_path = tmp_path / "small_list.txt"
    file_path.write_text("\n".join(passwords) + "\n", encoding="utf-8")
    return file_path

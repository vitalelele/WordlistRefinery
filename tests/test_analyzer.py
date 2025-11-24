"""
Unit tests for the PasswordAnalyzer module.

Author: Antonio Vitale
"""

import math

import pandas as pd
import pytest

from wordlist_refinery.analyzer import PasswordAnalyzer


def test_shannon_entropy_basic(analyzer: PasswordAnalyzer) -> None:
    """Basic sanity checks for Shannon entropy calculation."""
    # Empty string -> 0 entropy
    assert analyzer.calculate_shannon_entropy("") == 0.0

    # Repeated single character -> 0 entropy
    assert analyzer.calculate_shannon_entropy("aaaaa") == 0.0

    # 4 unique characters, all with probability 1/4 -> H = 2 bits
    assert math.isclose(analyzer.calculate_shannon_entropy("abcd"), 2.0)


def test_vectorized_entropy_matches_scalar(
    analyzer: PasswordAnalyzer, sample_dataframe: pd.DataFrame
) -> None:
    """
    Vectorized entropy application should match the scalar implementation
    for each password.
    """
    df = sample_dataframe.copy()
    df["entropy_vec"] = analyzer.vectorize_entropy(df["password"])

    for idx, pw in enumerate(df["password"]):
        scalar = analyzer.calculate_shannon_entropy(pw)
        assert math.isclose(df.loc[idx, "entropy_vec"], scalar)


def test_wpa2_filtering(analyzer: PasswordAnalyzer, sample_dataframe: pd.DataFrame) -> None:
    """
    WPA2 filter should keep only 8–63 printable ASCII passwords.
    """
    df = sample_dataframe.copy()
    filtered = analyzer.filter_wpa2_compliant(df, "password")

    results = filtered["password"].tolist()

    # Valid WPA2 candidates
    assert "password" in results
    assert "Tr0ub4dor&3" in results

    # Too short
    assert "123456" not in results
    assert "short" not in results

    # Contains non-ASCII
    assert "cafébabe" not in results


def test_complexity_tagging(analyzer: PasswordAnalyzer, sample_dataframe: pd.DataFrame) -> None:
    """
    Complexity flags should correctly identify character classes.
    """
    df = sample_dataframe.copy()
    tagged = analyzer.tag_complexity(df, "password")

    # Complex mixed password
    row = tagged[tagged["password"] == "Tr0ub4dor&3"].iloc[0]
    assert row["has_upper"]
    assert row["has_lower"]
    assert row["has_digit"]
    assert row["has_special"]

    # Numeric-only password
    pin_row = tagged[tagged["password"] == "123456"].iloc[0]
    assert not pin_row["has_upper"]
    assert not pin_row["has_lower"]
    assert pin_row["has_digit"]
    assert not pin_row["has_special"]


@pytest.mark.parametrize(
    "entropy_val, expected",
    [
        (0.0, "Very Weak"),
        (2.0, "Very Weak"),
        (2.7, "Weak"),
        (3.6, "Moderate"),
        (4.6, "Strong"),
    ],
)
def test_strength_classification_thresholds(
    analyzer: PasswordAnalyzer, entropy_val: float, expected: str
) -> None:
    """Classification thresholds for entropy-based strength labels."""
    label = analyzer.classify_strength(entropy_val)
    assert label == expected

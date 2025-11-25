"""
Unit tests for the PasswordAnalyzer module.

Author: Antonio Vitale
"""

from __future__ import annotations

import math

import pandas as pd
import pytest

from wordlist_refinery.analyzer import PasswordAnalyzer


# Shannon entropy tests
@pytest.mark.parametrize(
    "password, expected_entropy",
    [
        ("", 0.0),  # empty string
        ("aaaaa", 0.0),  # single repeated character
        ("ab", 1.0),  # two symbols, p=0.5 each -> 1 bit
        ("abcd", 2.0),  # four symbols, p=0.25 each -> 2 bits
        ("aaaabbbb", 1.0),  # two symbols, p=0.5 each -> 1 bit
    ],
)
def test_shannon_entropy_basic(
    analyzer: PasswordAnalyzer, password: str, expected_entropy: float
) -> None:
    """Basic sanity checks for Shannon entropy calculation."""
    value = analyzer.calculate_shannon_entropy(password)
    assert math.isclose(value, expected_entropy, rel_tol=1e-6)


def test_vectorized_entropy_matches_scalar(
    analyzer: PasswordAnalyzer, sample_dataframe: pd.DataFrame
) -> None:
    """
    Vectorized entropy application should match the scalar implementation
    for each password in the sample dataframe.
    """
    df = sample_dataframe.copy()
    df["entropy_vec"] = analyzer.vectorize_entropy(df["password"])

    for idx, pw in enumerate(df["password"]):
        scalar = analyzer.calculate_shannon_entropy(pw)
        assert math.isclose(df.loc[idx, "entropy_vec"], scalar, rel_tol=1e-6)


# WPA2 compliance tests
def test_wpa2_filtering_on_sample_dataframe(
    analyzer: PasswordAnalyzer, sample_dataframe: pd.DataFrame
) -> None:
    """
    WPA2 filter should keep only 8–63 printable ASCII passwords
    on the provided sample dataframe.
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


def test_wpa2_filtering_boundaries(analyzer: PasswordAnalyzer) -> None:
    """
    WPA2 filter should correctly handle boundary conditions:
    - 7 chars: too short
    - 8 chars: minimum valid
    - 63 chars: maximum valid
    - 64 chars: too long
    - non-ASCII characters: invalid
    """
    df = pd.DataFrame(
        {
            "password": [
                "a" * 7,  # too short
                "a" * 8,  # min ok
                "a" * 63,  # max ok
                "a" * 64,  # too long
                "cafe\u00e9babe",  # non-ASCII
            ]
        }
    )

    filtered = analyzer.filter_wpa2_compliant(df, "password")
    values = filtered["password"].tolist()

    assert "a" * 8 in values
    assert "a" * 63 in values
    assert "a" * 7 not in values
    assert "a" * 64 not in values
    assert "cafe\u00e9babe" not in values


# Complexity tagging test
@pytest.mark.parametrize(
    "password, upper, lower, digit, special",
    [
        ("ABC", True, False, False, False),
        ("abc", False, True, False, False),
        ("123456", False, False, True, False),
        ("!!!", False, False, False, True),
        ("Aa1!", True, True, True, True),
    ],
)
def test_complexity_tagging_variants(
    analyzer: PasswordAnalyzer,
    password: str,
    upper: bool,
    lower: bool,
    digit: bool,
    special: bool,
) -> None:
    """
    Complexity flags should correctly identify character classes
    across a variety of controlled examples.
    """
    df = pd.DataFrame({"password": [password]})
    tagged = analyzer.tag_complexity(df, "password").iloc[0]

    assert bool(tagged["has_upper"]) is upper
    assert bool(tagged["has_lower"]) is lower
    assert bool(tagged["has_digit"]) is digit
    assert bool(tagged["has_special"]) is special


def test_complexity_tagging_on_sample_dataframe(
    analyzer: PasswordAnalyzer, sample_dataframe: pd.DataFrame
) -> None:
    """
    Sanity check on the sample dataframe, focusing on a complex mixed password
    and a numeric-only one.
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


# Strength classification tests
@pytest.mark.parametrize(
    "entropy_val, expected",
    [
        (0.0, "Very Weak"),
        (2.49, "Very Weak"),
        (2.5, "Weak"),
        (3.49, "Weak"),
        (3.5, "Moderate"),
        (4.49, "Moderate"),
        (4.5, "Strong"),
        (10.0, "Strong"),
    ],
)
def test_strength_classification_thresholds(
    analyzer: PasswordAnalyzer, entropy_val: float, expected: str
) -> None:
    """Classification thresholds for entropy-based strength labels."""
    label = analyzer.classify_strength(entropy_val)
    assert label == expected

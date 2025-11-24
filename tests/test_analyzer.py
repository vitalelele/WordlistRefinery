"""
test_analyzer.py

Unit tests for the PasswordAnalyzer module.

Author: Antonio Vitale
"""

import math

import pandas as pd
import pytest

from wordlist_refinery.analyzer import PasswordAnalyzer


@pytest.fixture
def analyzer() -> PasswordAnalyzer:
    """Fixture to instantiate the analyzer."""
    return PasswordAnalyzer()


@pytest.fixture
def sample_dataframe() -> pd.DataFrame:
    """
    Creates a sample dataframe with mixed password types.

    Index mapping:
    0 -> "password"      (valid WPA2, low/medium entropy)
    1 -> "123456"        (too short for WPA2, digits only)
    2 -> "Tr0ub4dor&3"   (complex, valid WPA2)
    3 -> "short"         (too short for WPA2)
    4 -> "cafébabe"      (contains non-ASCII)
    """
    data = {
        "password": [
            "password",
            "123456",
            "Tr0ub4dor&3",
            "short",
            "cafébabe",
        ]
    }
    return pd.DataFrame(data)


def test_shannon_entropy_calculation(analyzer: PasswordAnalyzer) -> None:
    """
    Test the mathematical correctness of the entropy function.
    """
    # Entropy of 'aaaaa' (1 char type) should be 0
    assert analyzer.calculate_shannon_entropy("aaaaa") == 0.0

    # Entropy of 'abcd' (4 distinct chars)
    # p = 1/4 for each. H = -4 * (0.25 * log2(0.25)) = 2
    assert math.isclose(analyzer.calculate_shannon_entropy("abcd"), 2.0)

    # Entropy of empty string should be 0
    assert analyzer.calculate_shannon_entropy("") == 0.0


def test_vectorized_entropy(analyzer: PasswordAnalyzer, sample_dataframe: pd.DataFrame) -> None:
    """
    Test that the vectorized application matches individual calculation.
    """
    df = sample_dataframe.copy()
    df["entropy"] = analyzer.vectorize_entropy(df["password"])

    val = analyzer.calculate_shannon_entropy("password")
    assert math.isclose(df.loc[0, "entropy"], val)

    assert not df["entropy"].isnull().values.any()


def test_wpa2_filtering(analyzer: PasswordAnalyzer, sample_dataframe: pd.DataFrame) -> None:
    """
    Test WPA2 compliance filtering.
    """
    df = sample_dataframe
    filtered = analyzer.filter_wpa2_compliant(df, "password")

    results = filtered["password"].tolist()

    assert "password" in results        # Valid
    assert "Tr0ub4dor&3" in results     # Valid
    assert "123456" not in results      # Too short (<8)
    assert "short" not in results       # Too short (<8)
    assert "cafébabe" not in results    # Non-ASCII


def test_complexity_tagging(analyzer: PasswordAnalyzer, sample_dataframe: pd.DataFrame) -> None:
    """
    Test if complexity flags are correctly assigned.
    """
    df = sample_dataframe
    tagged = analyzer.tag_complexity(df, "password")

    # "Tr0ub4dor&3" è a index 2
    target = tagged.iloc[2]
    assert bool(target["has_upper"])   # T
    assert bool(target["has_lower"])   # r...
    assert bool(target["has_digit"])   # 0...3
    assert bool(target["has_special"]) # &

    # "123456" è a index 1
    target_pin = tagged.iloc[1]
    assert not bool(target_pin["has_upper"])
    assert not bool(target_pin["has_lower"])
    assert bool(target_pin["has_digit"])
    assert not bool(target_pin["has_special"])

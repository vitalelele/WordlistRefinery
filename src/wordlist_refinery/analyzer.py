"""
analyzer.py

This module contains the core logic for statistical analysis and
regex-based filtering of password candidates. It leverages scientific Python
libraries for entropy calculation and compiled regular expressions for
pattern matching.

Author: Antonio Vitale
"""

import re
from collections import Counter
from typing import Pattern

import pandas as pd
from scipy.stats import entropy


class PasswordAnalyzer:
    """
    Encapsulates logic for analyzing password strength, entropy and
    compliance with various security standards (NIST, WPA2).
    """

    # WPA2: 8 to 63 printable ASCII characters.
    # The range \x20-\x7E covers all printable ASCII including space.
    WPA2_PATTERN: Pattern = re.compile(r"^[\x20-\x7E]{8,63}$")

    # Common PIN patterns (4 or 6 digits) often found in leaks.
    PIN_PATTERN: Pattern = re.compile(r"^(\d{4}|\d{6})$")

    # NIST-aligned complexity checks (checking for character classes).
    # While NIST 800-63B discourages forcing these, legacy systems require them.
    HAS_UPPER: Pattern = re.compile(r"[A-Z]")
    HAS_LOWER: Pattern = re.compile(r"[a-z]")
    HAS_DIGIT: Pattern = re.compile(r"\d")
    HAS_SPECIAL: Pattern = re.compile(r"[!@#$%^&*(),.?\":{}|<>]")

    # "Password-like" heuristics
    # Reject anything that clearly looks like text, URL, or markup.
    REJECT_TEXT = re.compile(
        r"(?:http://|https://|www\.|\.com\b|\.net\b|\.org\b|rockyou|friendster|layout)",
        re.IGNORECASE,
    )

    # Reject strings containing any whitespace (spaces, tabs, etc.).
    # This deliberately removes phrases and sentences.
    REJECT_WHITESPACE: Pattern = re.compile(r"\s")

    # Acceptable character set for "password-like" strings, 8-63 chars.
    # Tightened compared to pure WPA2 (we avoid spaces and exotic stuff).
    PASSWORDLIKE: Pattern = re.compile(
        r"^[A-Za-z0-9!@#$%^&*()_\-+=\[\]{};:'\",.<>?/\\|~`]{8,63}$"
    )

    @staticmethod
    def calculate_shannon_entropy(word: str) -> float:
        """
        Calculates the Shannon Entropy of a single string.

        Entropy is a measure of the randomness or information density
        within the string. Higher values indicate higher complexity.

        Formula: H(X) = -sum(p(x) * log2(p(x)))

        Args:
            word (str): The password string to analyze.

        Returns:
            float: The calculated entropy in bits.
        """
        if not word:
            return 0.0

        counts = Counter(word)
        length = len(word)

        probs = [count / length for count in counts.values()]

        # scipy.stats.entropy uses optimized C-implementation.
        # base=2 gives result in bits.
        return float(entropy(probs, base=2))

    @classmethod
    def vectorize_entropy(cls, series: pd.Series) -> pd.Series:
        """
        Applies entropy calculation over a Pandas Series.

        Args:
            series (pd.Series): A series of password strings.

        Returns:
            pd.Series: A series of float entropy values.
        """
        return series.astype(str).apply(cls.calculate_shannon_entropy)

    # WPA2 + "password-like" filter
    @classmethod
    def filter_wpa2_compliant(cls, df: pd.DataFrame, column: str) -> pd.DataFrame:
        """
        Filters the DataFrame to retain only WPA2-compliant, password-like strings.

        WPA2 requirements:
        - Length: 8 to 63 characters
        - Charset: Printable ASCII

        Additionally, this method excludes:
        - URLs and domain-like strings (http, www, .com, rockyou, etc.)
        - Strings containing whitespace (to drop sentences/phrases)
        - Strings that do not match a "password-like" structure

        Args:
            df (pd.DataFrame): The input dataframe.
            column (str): The name of the column containing passwords.

        Returns:
            pd.DataFrame: A filtered dataframe.
        """
        s = df[column].astype(str)

        # Basic WPA2 structural compliance
        mask_wpa2 = s.str.contains(cls.WPA2_PATTERN, regex=True)
        # Exclude obvious text / URLs / domains / rockyou-related noise
        mask_no_text = ~s.str.contains(cls.REJECT_TEXT, regex=True)
        # Exclude whitespace (spaces, tabs, newlines inside the string)
        mask_no_whitespace = ~s.str.contains(cls.REJECT_WHITESPACE, regex=True)
        # Enforce a tighter "password-like" character set
        mask_passwordlike = s.str.contains(cls.PASSWORDLIKE, regex=True)
        mask = mask_wpa2 & mask_no_text & mask_no_whitespace & mask_passwordlike

        return df[mask]

    @classmethod
    def tag_complexity(cls, df: pd.DataFrame, column: str) -> pd.DataFrame:
        """
        Adds boolean columns indicating presence of character classes.
        Useful for filtering based on specific policy requirements.
        """
        s_col = df[column].astype(str)

        df["has_upper"] = s_col.str.contains(cls.HAS_UPPER, regex=True)
        df["has_lower"] = s_col.str.contains(cls.HAS_LOWER, regex=True)
        df["has_digit"] = s_col.str.contains(cls.HAS_DIGIT, regex=True)
        df["has_special"] = s_col.str.contains(cls.HAS_SPECIAL, regex=True)

        return df

    @staticmethod
    def classify_strength(entropy_val: float) -> str:
        """
        Classifies password strength based on entropy bits.

        Thresholds are heuristic based on common brute-force capabilities:
        - < 2.5 bits: Very Weak (repetitive, e.g., 'aaaaa')
        - 2.5 - 3.5 bits: Weak (common words)
        - 3.5 - 4.5 bits: Moderate
        - > 4.5 bits: Strong (random-looking)

        Args:
            entropy_val (float): The entropy value.

        Returns:
            str: Classification label.
        """
        if entropy_val < 2.5:
            return "Very Weak"
        elif entropy_val < 3.5:
            return "Weak"
        elif entropy_val < 4.5:
            return "Moderate"
        else:
            return "Strong"

"""
analyzer.py

This module contains the core logic for statistical analysis and
regex-based filtering of password candidates. It leverages Scientific Python
libraries for entropy calculation and compiled regular expressions for
pattern matching.

Author: Antonio Vitale
"""
import math 
import re
from collections import Counter
from typing import Pattern
import pandas as pd
from scipy.stats import entropy

class PasswordAnalyzer:
    """
    Encapsulates logic for analyzing password strength, entropy and compliance with various security standards (NIST, WPA2).
    """
    # Pre-compiled regex patterns for performance optimization
    # WPA2: 8 to 63 printable ASCII characters.
    # The range \x20-\x7E covers all printable ASCII including space.
    WPA2_PATTERN: Pattern = re.compile(r'^[\x20-\x7E]{8,63}$')
    
    # Common PIN patterns (4 or 6 digits) often found in leaks.
    PIN_PATTERN: Pattern = re.compile(r'^(\d{4}|\d{6})$')
    
    # NIST-aligned complexity checks (checking for character classes).
    # While NIST 800-63B discourages forcing these, legacy systems require them.
    # https://pages.nist.gov/800-63-4/sp800-63b/passwords/
    HAS_UPPER: Pattern = re.compile(r'[A-Z]')
    HAS_LOWER: Pattern = re.compile(r'[a-z]')
    HAS_DIGIT: Pattern = re.compile(r'\d')
    HAS_SPECIAL: Pattern = re.compile(r'[!@#$%^&*(),.?":{}|<>]')

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
            return 0.0 # Of course entropy of empty string is 0 bits
        
        # Optimization: use collections.Counter for O(n) character counting, which is more efficient than nested loops.
        counts = Counter(word)
        length = len(word)

        # Calculate probabilities
        probs = [count / length for count in counts.values()]
        
        # use scipy.stats.entropy for optimized C-implementation.
        # base=2 gives result in 'bits', standard for info theory.
        return entropy(probs, base=2)


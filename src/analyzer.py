"""
analyzer.py

This module contains the core logic for statistical analysis and
regex-based filtering of password candidates. It leverages Scientific Python
libraries for entropy calculation and compiled regular expressions for
pattern matching.

Author: Vitalelele
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

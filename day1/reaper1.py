"""
REAPER-1 - Password Generator & Auditor
Day 1 of 100
"""

import secrets
import string
import re
import hashlib
import argparse
from typing import List, Tuple

class ReaperOne:
    def __init__(self):
        self.strength_patterns = {
            'length': r'.{12,}',
            'lower': r'[a-z]',
            'upper': r'[A-Z]',
            'digits': r'\d',
            'special': r'[!@#$%^&*()_+\-=\[\]{};\'":|,.<>?/~`]'
        }

    def generate_password
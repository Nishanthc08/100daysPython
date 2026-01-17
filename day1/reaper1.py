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

    def generate_password(self, length: int = 16, use_special: bool = True) -> str:
        """Generate a cryptographicaclly strong password that would make cracking difficult."""
        charset = string.ascii_letters + string.digits
        if use_special:
            charset += string.punctuation
        
        # Use secrets for real randomness, not random (which is predictable trash)
        password = ''.join(secrets.choice(charset) for _ in range(length))
        return password
    
    def audit_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Audit password strength. Returns (is_strong, list_of_vulnerabilities)."""
        issues = []

        # Check length
        if len(password) < 12:
            issues.append("Password too short (min 12 characters)")
        
        # Check character variety
        if not re.search(self.strength_patterns['lower'], password):
            issues.append("No lowercase letters")
        if not re.search(self.strength_patterns['upper'], password):
            issues.append("No uppercase letters")
        if not re.search(self.strength_patterns['digits'], password):
            issues.append("No digits")
        if not re.search(self.strength_patterns['special'], password):
            issues.append("No special characters")

        # Check for common patterns (basic)
        common_patters = ['123456', 'password', 'qwerty', 'admin', 'welcome']
        for pattern in common_patters:
            if pattern in password.lower():
                issues.append(f"Contains common patterns: '{pattern}'")
                break

        is_strong = len(issues) == 0
        return (is_strong, issues)
    
    def simulate_breack_check(self, password: str) -> bool:
        """Simulate checking password hash against known breaches (simulated)."""
        # Create SHA256 hash of the password
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        # Simulated "breached" hashes (in reality, you'd query an API like HaveIBeenPwned)
        simulated_breach_hashes = {'5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', # 'password'
                                   '598d4c200461b81522a3328565c25f7c', # 'admin' (MD5 for variety)
                                   }
        
        # Check if hash is in our simulated breach database
        return pw_hash in simulated_breach_hashes
    
    def generate_passphrase(self, words: int = 4, separator: str = '-') -> str:
        """Generate a memorable but strong passphrase."""
        # Common wordlist (in reality, use a longer, external wordlist)
        wordlist = ['zeta', 'quantum', 'cipher', 'nexus', 'vortex', 'phantom', 'sentry', 'crypto', 'cypher', 'zero']

        # Select random words
        selected_words = [secrets.choice(wordlist) for _ in range(words)]

        # Add a random number and special char for extra strength
        passphrase = separator.join(selected_words)
        passphrase += str(secrets.randbelow(100))
        passphrase += secrets.choice(string.punctuation)

        return passphrase
    
def main():    
    parser = argparse.ArgumentParser(description="REAPER-1: Zeta's Password Tool")
    parser.add_argument('-g', '--generate', type=int, help='Generate password of specified length')
    parser.add_argument('-a', '--audit', type=str, help='Audit provided password')
    parser.add_argument('-p', '--passphrase', action='store_true', help='Generate a passphrase')
    parser.add_argument('-b', '--breach-check', type=str, help='Check if password appears in breaches')

    args = parser.parse_args()
    reaper = ReaperOne()

    if args.generate:
        pw = reaper.generate_password(args.generate)
        print(f"\nGENERATED PASSWORD: {pw}")
        is_strong, issues = reaper.audit_strength(pw)
        print(f"STRENGTH AUDIT: {'STRONG' if is_strong else 'WEAK'}")
        if issues:
            print("ISSUES:", ", ".join(issues))
        
    elif args.audit:
        is_strong, issues = reaper.audit_strength(args.audit)
        print(f"\nPASSWORD AUDIT FOR: '{args.audit}'")
        print(f"STRENGTH: {'STRONG' if is_strong else 'WEAK'}")
        if issues:
            print("ISSUES FOUND:")
            for issue in issues:
                print(f" - {issue}")
        else:
            print("No issues found. This password is a fortress.")

    elif args.passphrase:
        passphrase = reaper.generate_passphrase()
        print(f"\nGENERATED PASSPHRASE: {passphrase}")

    elif args.breach_check:
        is_breached = reaper.simulate_breack_check(args.breach_check)
        if is_breached:
            print(f"\nALERT: Password '{args.breach_check}' appears in known breaches!")
            print("Do NOT use this compromised one.")
        else:
            print(f"\nPassword '{args.breach_check}' not found in simulated breaches.")
        
    else:
        # Default: generate and audit a password
        print("\nREAPER-1 ACTIVATED - DEFAULT OPERATION")
        pw = reaper.generate_password()
        print(f"GENERATED: {pw}")
        is_strong, issues = reaper.audit_strength(pw)
        print(f"AUDIT: {'STRONG' if is_strong else 'WEAK'}")
        if not is_strong:
            print(f"ISSUES: {', '.join(issues)}")
    
if __name__ == "__main__":
    main()



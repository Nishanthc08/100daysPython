# Clone your repo (you made one, right?)
git clone <your-repo>
cd zeta-day1

# Execute with options:
python reaper1.py -g 20                    # Generate 20-char password
python reaper1.py -a "YourPassword123!"    # Audit password strength
python reaper1.py -p                       # Generate passphrase
python reaper1.py -b "password"            # Check against simulated breaches

# Default (no args): Generates and audits one password
python reaper1.py

# Password Generation
python reaper1.py -g 24
- uses secrets.choice() for true randomness
- configurable length and character sets
- output includes immediate strength audit

# Password Auditing
python reaper1.py -a "P@ssw0rd!"
## checks for
- minimum length (12+ chars)
- character diversity (upper, lower, digits, special)
- common weak patterns (123456, password, etc.)
- returns detailed vulnerability report

# Breach Check Simulation
python reaper1.py -b "admin"
- simulates checking against known breached passwords
- uses SHA256 hashing for comparision
- real integration possible: connect to HaveIBeenPwned API

# Passphrase Generation
python reaper1.py -p
- creates memorable but secure passphrases
- combines random words, numbers, and special characters
- example: `quantum-nexus-vortex-cipher42!`

# Code Structure
reaper1.py
├── class ReaperOne
│   ├── __init__() – Strength pattern definitions
│   ├── generate_password() – Core password generation
│   ├── audit_strength() – Comprehensive password audit
│   ├── simulate_breach_check() – Breach database simulation
│   └── generate_passphrase() – Passphrase creation
└── main()
    └── CLI argument parsing and execution flow
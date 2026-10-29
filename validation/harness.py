"""Seeded scenarios: every one has a known correct verdict. Target: 100%."""

import sys

from common import score

if __name__ == "__main__":
    sys.exit(0 if score("seeded") else 1)

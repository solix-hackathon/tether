"""Held-out scenarios, kept out of rule development. Target: 100%."""

import sys

from common import score

if __name__ == "__main__":
    sys.exit(0 if score("holdout") else 1)

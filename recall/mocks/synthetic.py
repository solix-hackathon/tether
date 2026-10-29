"""Deterministic synthetic patient roster. No real people; names are random combinations."""

import json
import random
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
ROSTER_PATH = DATA_DIR / "patients.json"

FIRST = ["Amara", "Bastian", "Celine", "Dmitri", "Esme", "Farid", "Greta", "Hiroshi", "Ines", "Jonas",
         "Kaia", "Lorenzo", "Maren", "Nikhil", "Odette", "Pavel", "Quinn", "Rosalind", "Soren", "Talia"]
LAST = ["Abernathy", "Brightwater", "Castellano", "Dunmore", "Eskildsen", "Fairbanks", "Gallowglass",
        "Holloway", "Ibarra", "Jessup", "Kowalczyk", "Lindqvist", "Marchetti", "Northcott", "Okonkwo",
        "Pemberton", "Quarles", "Rasmussen", "Sandoval", "Thistlewood"]
CONDITIONS = ["post-op knee arthroplasty", "community-acquired pneumonia", "type 2 diabetes follow-up",
              "atrial fibrillation", "cholecystectomy", "COPD exacerbation", "cellulitis", "hip fracture"]


def generate(n: int = 40, seed: int = 2026):
    rng = random.Random(seed)
    roster = {}
    used = set()
    for i in range(n):
        while True:
            name = (rng.choice(FIRST), rng.choice(LAST))
            if name not in used:
                used.add(name)
                break
        pid = f"P-{1001 + i}"
        roster[pid] = {
            "id": pid,
            "first": name[0],
            "last": name[1],
            "mrn": f"MRN-{rng.randint(100000, 999999)}",
            "dob": f"19{rng.randint(40, 99)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
            "condition": rng.choice(CONDITIONS),
            "synthetic": True,
        }
    return roster


def load_roster():
    if ROSTER_PATH.exists():
        return json.loads(ROSTER_PATH.read_text())
    return generate()

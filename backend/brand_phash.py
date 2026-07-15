"""

USAGE
-----
    # one-time setup, run yourself against your own reference screenshots:
    python build_reference_set.py --out reference_hashes.json \\
        microsoft=/path/to/microsoft_login.png \\
        paypal=/path/to/paypal_login.png

    # at scan time:
    matcher = BrandMatcher.from_file("reference_hashes.json")
    match = matcher.match(screenshot_path)
    # -> {"brand": "microsoft", "similarity": 0.94} or None
"""

import json
import logging
from pathlib import Path

import imagehash
from PIL import Image

logger = logging.getLogger("phishing_sandbox.brand_phash")

# Hamming-distance-derived similarity below this is not reported as a
# match. pHash distances run 0 (identical) to 64 (maximally different)
# for the default 8x8 hash; this threshold is a starting guess, not a
# validated cutoff — tune against your own reference set.
DEFAULT_SIMILARITY_THRESHOLD = 0.90
HASH_BITS = 64  # imagehash.phash default size (8x8 -> 64-bit hash)


class BrandMatcher:
    def __init__(self, reference_hashes: dict):
        # reference_hashes: {"microsoft": "a1b2c3...", "paypal": "..."}
        self._reference = {}
        for brand, hex_str in reference_hashes.items():
            try:
                self._reference[brand] = imagehash.hex_to_hash(hex_str)
            except Exception as e:
                logger.warning("Skipping malformed hash for brand %s: %s", brand, e)

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        if not path.exists():
            logger.info("No brand reference set at %s — brand-impersonation "
                        "check will be skipped for this scan.", path)
            return cls({})
        with open(path) as f:
            return cls(json.load(f))

    def match(self, screenshot_path, threshold=DEFAULT_SIMILARITY_THRESHOLD):
        if not self._reference or not screenshot_path:
            return None
        try:
            target_hash = imagehash.phash(Image.open(screenshot_path))
        except Exception as e:
            logger.warning("Could not hash screenshot %s: %s", screenshot_path, e)
            return None

        best_brand, best_similarity = None, 0.0
        for brand, ref_hash in self._reference.items():
            distance = target_hash - ref_hash  # Hamming distance
            hash_bits = len(ref_hash)
            similarity = 1 - (distance / hash_bits)
            if similarity > best_similarity:
                best_brand, best_similarity = brand, similarity

        if best_brand:
            logger.debug("Best candidate brand match: %s at similarity %.3f", best_brand, best_similarity)
            if best_similarity >= threshold:
                return {"brand": best_brand, "similarity": round(best_similarity, 3)}
        return None

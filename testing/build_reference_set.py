"""
Run this yourself, once, against screenshots you have the rights to use
(e.g. captured directly from the live brand sites for this purpose).
Outputs a JSON file of {brand: phash_hex} — no images, just hash strings.

Usage:
    python build_reference_set.py --out reference_hashes.json \\
        microsoft=/path/to/microsoft_login.png \\
        paypal=/path/to/paypal_login.png \\
        google=/path/to/google_login.png
"""

import argparse
import json

import imagehash
from PIL import Image


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="reference_hashes.json")
    parser.add_argument("pairs", nargs="+", help="brand=/path/to/screenshot.png")
    args = parser.parse_args()

    hashes = {}
    for pair in args.pairs:
        brand, _, path = pair.partition("=")
        if not path:
            print(f"Skipping malformed pair: {pair!r} (expected brand=path)")
            continue
        try:
            h = imagehash.phash(Image.open(path))
            hashes[brand] = str(h)
            print(f"{brand}: {h}")
        except Exception as e:
            print(f"Failed to hash {path} for {brand!r}: {e}")

    with open(args.out, "w") as f:
        json.dump(hashes, f, indent=2)
    print(f"\nWrote {len(hashes)} reference hash(es) to {args.out}")


if __name__ == "__main__":
    main()

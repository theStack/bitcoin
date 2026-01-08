from pathlib import Path
import sys

# Prefer the vendored copy of secp256k1lab.
sys.path.insert(0, str(Path(__file__).parent / "crypto/secp256k1lab/src"))

#!/usr/bin/env python3
"""Encrypt (or decrypt) the Lead Tracker data. Same lock format as the other
Sharma apps (sharma-enc-v1: AES-GCM 256, PBKDF2-HMAC-SHA256, 600k iterations).

  Encrypt (default):  python3 tools/encrypt.py
      reads  private/data.json  (plain, local only, never committed)
      writes docs/data.enc.json (the only data file published)
  Decrypt:            python3 tools/encrypt.py --decrypt

The code comes from the SHARMA_PASSCODE environment variable, or a hidden
prompt. It is never written to disk, printed or logged.
Needs: pip install cryptography
"""
import argparse, base64, getpass, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ITERATIONS = 600_000
FORMAT = "sharma-enc-v1"

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    sys.exit("Missing package: pip install cryptography")


def get_code(confirm):
    code = os.environ.get("SHARMA_PASSCODE")
    if code is None:
        if not sys.stdin.isatty():
            sys.exit("ERROR: set SHARMA_PASSCODE or run in a terminal to be prompted")
        code = getpass.getpass("Code: ")
        if confirm and getpass.getpass("Code again: ") != code:
            sys.exit("ERROR: codes did not match")
    code = code.strip()
    if not code:
        sys.exit("ERROR: empty code")
    return code


def derive(code, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(code.encode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--decrypt", action="store_true")
    args = ap.parse_args()
    plain_path = os.path.join(ROOT, "private", "data.json")
    enc_path = os.path.join(ROOT, "docs", "data.enc.json")

    if args.decrypt:
        env = json.load(open(enc_path))
        assert env["format"] == FORMAT, "unexpected envelope format"
        key = derive(get_code(False), base64.b64decode(env["salt"]))
        pt = AESGCM(key).decrypt(base64.b64decode(env["iv"]), base64.b64decode(env["ciphertext"]), None)
        json.dump(json.loads(pt), open(plain_path, "w"), indent=1)
        print("decrypted -> private/data.json")
        return

    data = json.load(open(plain_path))
    leads, ahj = data.get("leads", []), data.get("ahj", [])
    assert len(leads) >= 1900, f"expected 1900+ leads, got {len(leads)}"
    assert len(ahj) == 194, f"expected 194 ahj rows, got {len(ahj)}"
    salt, iv = os.urandom(16), os.urandom(12)
    key = derive(get_code(True), salt)
    ct = AESGCM(key).encrypt(iv, json.dumps(data, separators=(",", ":")).encode("utf-8"), None)
    env = {
        "format": FORMAT, "kdf": "PBKDF2-SHA256", "cipher": "AES-GCM-256",
        "iterations": ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }
    json.dump(env, open(enc_path, "w"), indent=1)
    print(f"encrypted {len(leads)} leads + {len(ahj)} ahj -> docs/data.enc.json")


if __name__ == "__main__":
    main()

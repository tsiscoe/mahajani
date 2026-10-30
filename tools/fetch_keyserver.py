#!/usr/bin/env python3
"""
Keyserver Fetch Utility for speakeasy.
Resolves public keys from standard HKP / HTTPS keyservers (e.g., https://pgp.mit.edu/)
and stores them into the authorized keys directory.
"""

import sys
import os
import re
import argparse
import urllib.request
import urllib.parse
import ssl
import pgpy

def fetch_keyserver_key(search_query, keys_dir="./authorized_keys", keyserver_url="https://pgp.mit.edu/pks/lookup"):
    search_clean = search_query.strip()
    print(f"[*] Querying keyserver ({keyserver_url}) for: {search_clean}")
    url = f"{keyserver_url}?search={urllib.parse.quote(search_clean)}&op=get"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) speakeasy/1.0"})
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            m = re.search(r"(-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----)", content, re.DOTALL)
            if not m:
                print("[-] Error: No OpenPGP public key block detected in server response.")
                return False

            armored_block = m.group(1)
            key, _ = pgpy.PGPKey.from_blob(armored_block)

            os.makedirs(keys_dir, exist_ok=True)
            out_file = os.path.join(keys_dir, f"{search_clean.lower()}.asc")
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(str(key.pubkey))

            print(f"[+] Successfully fetched and authorized key: {out_file} (Fingerprint: {key.fingerprint})")
            return True
    except Exception as e:
        print(f"[-] Keyserver fetch error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Fetch public keys from OpenPGP keyservers into authorized_keys.")
    parser.add_argument("query", help="Username, email, or Key ID (e.g. 0x12345678)")
    parser.add_argument("-d", "--dir", default="./authorized_keys", help="Authorized keys directory")
    parser.add_argument("-s", "--server", default="https://pgp.mit.edu/pks/lookup", help="Keyserver lookup endpoint")
    args = parser.parse_args()

    success = fetch_keyserver_key(args.query, args.dir, args.server)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

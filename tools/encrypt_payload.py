#!/usr/bin/env python3
"""
Payload Encryption Utility for speakeasy.
Generates an OpenPGP authority keypair (if not present) and creates
an encrypted/signed .pgp payload container from an arbitrary source file.
"""

import os
import sys
import argparse
import pgpy
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    CompressionAlgorithm
)

def generate_authority_key(key_dir="."):
    os.makedirs(key_dir, exist_ok=True)
    priv_path = os.path.join(key_dir, "authority_secret.asc")
    pub_path = os.path.join(key_dir, "authority_public.asc")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        key, _ = pgpy.PGPKey.from_file(priv_path)
        return key

    print("[*] Generating 1024-bit RSA OpenPGP Authority Key...")
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid = pgpy.PGPUID.new("speakeasy Service Authority", email="admin@speakeasy.local")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB]
    )

    with open(priv_path, "w", encoding="utf-8") as f:
        f.write(str(key))
    with open(pub_path, "w", encoding="utf-8") as f:
        f.write(str(key.pubkey))

    print(f"[+] Authority private key saved: {priv_path}")
    print(f"[+] Authority public key saved:  {pub_path}")
    return key

def encrypt_payload(input_file, output_file, key):
    print(f"[*] Reading source artifact: {input_file}")
    with open(input_file, "rb") as f:
        raw_bytes = f.read()

    filename = os.path.basename(input_file)
    msg = pgpy.PGPMessage.new(raw_bytes, file=True, filename=filename)

    # Sign with authority secret key
    sig = key.sign(msg)
    msg |= sig

    # Encrypt to authority recipient key
    enc_msg = key.pubkey.encrypt(msg)

    with open(output_file, "wb") as f:
        f.write(bytes(enc_msg))

    print(f"[+] Encrypted and signed payload written: {output_file} ({len(bytes(enc_msg))} bytes)")

def main():
    parser = argparse.ArgumentParser(description="Encrypt a file into an OpenPGP .pgp container.")
    parser.add_argument("input_file", help="Path to input artifact to encrypt")
    parser.add_argument("-o", "--output", default="target.pgp", help="Output .pgp file path")
    parser.add_argument("-k", "--key-dir", default="./keys", help="Directory to store or load authority key")
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"[-] Error: Input file not found: {args.input_file}")
        sys.exit(1)

    key = generate_authority_key(args.key_dir)
    encrypt_payload(args.input_file, args.output, key)

if __name__ == "__main__":
    main()

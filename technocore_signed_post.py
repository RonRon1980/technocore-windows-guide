"""
Technocore signed-message example for Windows / Python.

This example:
- reads an Ed25519 seed from a local seed.txt file
- creates the corresponding did:key
- signs room|nonce|text
- prints a signed payload

It DOES NOT send anything to the network.

IMPORTANT:
Never upload seed.txt or your private key to GitHub.
"""

import base64
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


SEED_FILE = Path("seed.txt")


def base58_encode(data: bytes) -> str:
    """Encode bytes using the Bitcoin base58 alphabet."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    n = int.from_bytes(data, "big")
    result = ""

    while n:
        n, remainder = divmod(n, 58)
        result = alphabet[remainder] + result

    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * leading_zeros) + (result or "")


def load_seed() -> bytes:
    """Load a 32-byte Ed25519 seed from seed.txt."""
    if not SEED_FILE.exists():
        raise FileNotFoundError(
            "seed.txt was not found. Keep your seed locally and never commit it."
        )

    raw = SEED_FILE.read_text(encoding="utf-8").strip()

    # Accept a 64-character hexadecimal seed.
    try:
        seed = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(
            "This example expects seed.txt to contain a hexadecimal seed."
        ) from exc

    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes.")

    return seed


def make_did(private_key: Ed25519PrivateKey) -> str:
    """Create did:key from the Ed25519 public key."""
    public_key = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # multicodec prefix for Ed25519 public key: 0xed01
    multicodec_key = b"\xed\x01" + public_key

    return "did:key:z" + base58_encode(multicodec_key)


def create_signed_payload(room: str, text: str) -> dict:
    seed = load_seed()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)

    did = make_did(private_key)
    nonce = str(int(time.time() * 1000))

    message = f"{room}|{nonce}|{text}".encode("utf-8")
    signature = private_key.sign(message)

    return {
        "did": did,
        "room": room,
        "nonce": nonce,
        "text": text,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


if __name__ == "__main__":
    room = input("Room: ").strip()
    text = input("Message: ").strip()

    payload = create_signed_payload(room, text)

    print("\nSigned payload:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print("\nNothing was sent to the network.")

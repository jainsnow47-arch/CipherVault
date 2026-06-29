# algorithms/aes_cipher.py
# ─────────────────────────────────────────────────────────────────────────────
# AES (Advanced Encryption Standard) - AES-256 in CBC Mode
# ─────────────────────────────────────────────────────────────────────────────
#
# WHAT IS AES?
# AES is the gold standard of symmetric encryption. "Symmetric" means the
# same password is used to both encrypt and decrypt. The "256" in AES-256
# refers to the key size: 256 bits = extremely strong.
#
# WHAT IS CBC MODE?
# CBC (Cipher Block Chaining) splits your text into 16-byte blocks and
# XORs each block with the previous encrypted block before encrypting it.
# This means identical blocks of text produce different cipher output —
# making patterns impossible to spot.
#
# WHAT IS AN IV (Initialization Vector)?
# The IV is a random 16-byte value used to kick off the CBC chain.
# Without a random IV, encrypting the same text twice would give the same
# output — which leaks information. We generate a new IV each time and
# store it alongside the ciphertext.
#
# WHAT IS SALT?
# A salt is random bytes mixed into your password before hashing it.
# This prevents "rainbow table" attacks (pre-computed password lookups).
# We generate a new salt each time and store it with the ciphertext.
#
# WHAT IS PBKDF2?
# PBKDF2 (Password-Based Key Derivation Function 2) turns your plain
# password string into a secure 256-bit key using thousands of hash
# iterations. This makes brute-force attacks slow and expensive.
#
# WHAT IS BASE64?
# Encrypted bytes are binary data (not printable text). Base64 encodes
# binary into a string of safe ASCII characters so we can store/display it.
# ─────────────────────────────────────────────────────────────────────────────

import os
import base64

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ── Constants ────────────────────────────────────────────────────────────────
SALT_SIZE       = 16        # 16 random bytes for the salt
KEY_SIZE        = 32        # 32 bytes = 256 bits (AES-256)
IV_SIZE         = 16        # AES block size is always 16 bytes
PBKDF2_ITERATIONS = 100_000 # High iteration count slows brute-force attempts
BLOCK_SIZE      = AES.block_size  # 16 bytes


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Turn a human password into a secure 256-bit AES key using PBKDF2.

    Parameters:
        password  : The user's plain-text password string.
        salt      : Random bytes that make each derived key unique.

    Returns:
        A 32-byte (256-bit) key suitable for AES-256.
    """
    password_bytes = password.encode("utf-8")  # convert string → bytes
    key = PBKDF2(
        password_bytes,
        salt,
        dkLen=KEY_SIZE,
        count=PBKDF2_ITERATIONS
    )
    return key


def encrypt(plain_text: str, password: str) -> str:
    """
    Encrypt plain text with AES-256 CBC.

    Layout of the final stored bytes (before Base64 encoding):
        [ salt (16 bytes) | iv (16 bytes) | ciphertext (N bytes) ]

    Parameters:
        plain_text : The message to encrypt.
        password   : The user's password.

    Returns:
        A Base64-encoded string containing salt + iv + ciphertext.

    Raises:
        ValueError if plain_text or password is empty.
    """
    if not plain_text:
        raise ValueError("Plain text cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    # Step 1 – Generate fresh random salt and IV for this encryption
    salt = get_random_bytes(SALT_SIZE)
    iv   = get_random_bytes(IV_SIZE)

    # Step 2 – Derive a 256-bit AES key from the password + salt
    key = derive_key(password, salt)

    # Step 3 – Create the AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Step 4 – Pad the plain text so its length is a multiple of 16 bytes
    #           (AES requires fixed-size blocks)
    padded_text = pad(plain_text.encode("utf-8"), BLOCK_SIZE)

    # Step 5 – Encrypt the padded text
    ciphertext = cipher.encrypt(padded_text)

    # Step 6 – Bundle salt + iv + ciphertext together, then Base64-encode
    combined   = salt + iv + ciphertext
    encoded    = base64.b64encode(combined).decode("utf-8")

    return encoded


def decrypt(encrypted_text: str, password: str) -> str:
    """
    Decrypt a Base64-encoded AES-256 CBC ciphertext.

    Parameters:
        encrypted_text : The Base64 string produced by encrypt().
        password       : The same password used to encrypt.

    Returns:
        The original plain text string.

    Raises:
        ValueError for bad input, wrong password, or corrupted data.
    """
    if not encrypted_text:
        raise ValueError("Encrypted text cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    try:
        # Step 1 – Base64-decode to get the raw bytes
        combined = base64.b64decode(encrypted_text.encode("utf-8"))
    except Exception:
        raise ValueError("Invalid encrypted text. It may be corrupted or not AES-encoded.")

    # Check we have at least the minimum expected bytes
    min_length = SALT_SIZE + IV_SIZE + BLOCK_SIZE
    if len(combined) < min_length:
        raise ValueError("Encrypted text is too short to be valid AES data.")

    # Step 2 – Split out salt, iv, and ciphertext
    salt       = combined[:SALT_SIZE]
    iv         = combined[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = combined[SALT_SIZE + IV_SIZE:]

    # Step 3 – Re-derive the same key from the password + extracted salt
    key = derive_key(password, salt)

    # Step 4 – Decrypt
    try:
        cipher     = AES.new(key, AES.MODE_CBC, iv)
        padded_text = cipher.decrypt(ciphertext)
        plain_text  = unpad(padded_text, BLOCK_SIZE).decode("utf-8")
    except (ValueError, KeyError):
        raise ValueError("Decryption failed. The password may be wrong or the data is corrupted.")

    return plain_text
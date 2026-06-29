# algorithms/des_cipher.py
# ─────────────────────────────────────────────────────────────────────────────
# DES (Data Encryption Standard) - CBC Mode
# ─────────────────────────────────────────────────────────────────────────────
#
# WHAT IS DES?
# DES was the U.S. government's official encryption standard from 1977 to 2001.
# It uses a 56-bit key — which is FAR too short by today's standards.
# A modern computer can brute-force a DES key in under 24 hours.
#
# ⚠️  WARNING: DES IS NOT SECURE FOR REAL USE.
# It is included here ONLY to show how older algorithms worked and to
# help you understand why modern algorithms like AES-256 are necessary.
# Never use DES to protect real sensitive data.
#
# HOW IS IT DIFFERENT FROM AES HERE?
# DES has an 8-byte (64-bit) block size and an 8-byte key.
# We still use PBKDF2 to derive the key and CBC mode + IV for safety,
# but the underlying cipher is much weaker than AES.
# ─────────────────────────────────────────────────────────────────────────────

import base64

from Crypto.Cipher import DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ── Constants ────────────────────────────────────────────────────────────────
SALT_SIZE         = 16       # 16 random bytes for salt
DES_KEY_SIZE      = 8        # DES requires exactly 8 bytes (64-bit key, 56 effective)
DES_BLOCK_SIZE    = DES.block_size   # 8 bytes
IV_SIZE           = DES_BLOCK_SIZE   # IV must match block size
PBKDF2_ITERATIONS = 100_000  # Still slow brute-force even though DES itself is weak


def derive_des_key(password: str, salt: bytes) -> bytes:
    """
    Derive an 8-byte DES key from the user's password using PBKDF2.

    DES only accepts 8-byte keys, so we set dkLen=8.
    """
    password_bytes = password.encode("utf-8")
    key = PBKDF2(
        password_bytes,
        salt,
        dkLen=DES_KEY_SIZE,
        count=PBKDF2_ITERATIONS
    )
    return key


def encrypt(plain_text: str, password: str) -> str:
    """
    Encrypt plain text using DES in CBC mode.

    Stored layout (before Base64):
        [ salt (16 bytes) | iv (8 bytes) | ciphertext (N bytes) ]

    Parameters:
        plain_text : The message to encrypt.
        password   : The user's password.

    Returns:
        A Base64-encoded string.

    Raises:
        ValueError if inputs are empty.
    """
    if not plain_text:
        raise ValueError("Plain text cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    # Step 1 – Random salt and IV
    salt = get_random_bytes(SALT_SIZE)
    iv   = get_random_bytes(IV_SIZE)

    # Step 2 – Derive DES key
    key = derive_des_key(password, salt)

    # Step 3 – Create DES cipher in CBC mode
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Step 4 – Pad text to a multiple of 8 bytes (DES block size)
    padded_text = pad(plain_text.encode("utf-8"), DES_BLOCK_SIZE)

    # Step 5 – Encrypt
    ciphertext = cipher.encrypt(padded_text)

    # Step 6 – Combine and Base64-encode
    combined = salt + iv + ciphertext
    encoded  = base64.b64encode(combined).decode("utf-8")

    return encoded


def decrypt(encrypted_text: str, password: str) -> str:
    """
    Decrypt a Base64-encoded DES CBC ciphertext.

    Parameters:
        encrypted_text : The Base64 string from encrypt().
        password       : The same password used to encrypt.

    Returns:
        The original plain text.

    Raises:
        ValueError for bad data or wrong password.
    """
    if not encrypted_text:
        raise ValueError("Encrypted text cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    try:
        combined = base64.b64decode(encrypted_text.encode("utf-8"))
    except Exception:
        raise ValueError("Invalid encrypted text. It may be corrupted or not DES-encoded.")

    # Minimum length: 16 (salt) + 8 (iv) + 8 (one block)
    min_length = SALT_SIZE + IV_SIZE + DES_BLOCK_SIZE
    if len(combined) < min_length:
        raise ValueError("Encrypted text is too short to be valid DES data.")

    # Split out salt, iv, ciphertext
    salt       = combined[:SALT_SIZE]
    iv         = combined[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = combined[SALT_SIZE + IV_SIZE:]

    # Re-derive the DES key
    key = derive_des_key(password, salt)

    # Decrypt and unpad
    try:
        cipher      = DES.new(key, DES.MODE_CBC, iv)
        padded_text = cipher.decrypt(ciphertext)
        plain_text  = unpad(padded_text, DES_BLOCK_SIZE).decode("utf-8")
    except (ValueError, KeyError):
        raise ValueError("Decryption failed. The password may be wrong or the data is corrupted.")

    return plain_text
# algorithms/rsa_cipher.py
# ─────────────────────────────────────────────────────────────────────────────
# RSA (Rivest–Shamir–Adleman) - Asymmetric Encryption
# ─────────────────────────────────────────────────────────────────────────────
#
# WHAT IS RSA?
# RSA is an *asymmetric* encryption algorithm — it uses TWO keys:
#   • Public Key  → Anyone can have this. Used to ENCRYPT.
#   • Private Key → Only you hold this. Used to DECRYPT.
#
# This is different from AES/DES (symmetric) where one password does both.
# RSA is used in HTTPS, SSH, email signing, and digital certificates.
#
# HOW DOES THE MATH WORK? (Simple version)
# RSA is based on the fact that multiplying two large prime numbers is easy,
# but figuring out the original primes from the product is extremely hard.
# The key pair is mathematically linked through this problem.
#
# WHAT IS OAEP?
# OAEP (Optimal Asymmetric Encryption Padding) is the padding scheme we use.
# Raw RSA without padding has weaknesses. OAEP adds randomness and structure
# that makes RSA encryption safe.
#
# KEY SIZE: We use 2048-bit keys — currently considered secure.
#
# LIMITATION: RSA can only encrypt small amounts of data directly
# (limited by key size). For large data, you'd normally use RSA to encrypt
# an AES key, then use AES for the real data. Here we keep it simple and
# only allow short messages for learning purposes.
# ─────────────────────────────────────────────────────────────────────────────

import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# ── Constants ────────────────────────────────────────────────────────────────
KEY_SIZE = 2048   # 2048-bit RSA key (secure for current use)


def generate_key_pair() -> tuple[str, str]:
    """
    Generate a new RSA public/private key pair.

    Returns:
        (private_key_pem, public_key_pem) — both as PEM-formatted strings.

    PEM format is the standard text format for RSA keys. It looks like:
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA...
        -----END RSA PRIVATE KEY-----
    """
    # Generate the key pair
    rsa_key     = RSA.generate(KEY_SIZE)

    # Export private key in PEM format
    private_key = rsa_key.export_key().decode("utf-8")

    # Export public key in PEM format
    public_key  = rsa_key.publickey().export_key().decode("utf-8")

    return private_key, public_key


def encrypt(plain_text: str, public_key_pem: str) -> str:
    """
    Encrypt plain text using an RSA public key (OAEP padding, SHA-256).

    Parameters:
        plain_text     : The message to encrypt.
        public_key_pem : The RSA public key as a PEM string.

    Returns:
        Base64-encoded ciphertext.

    Raises:
        ValueError for empty input or oversized messages.
    """
    if not plain_text:
        raise ValueError("Plain text cannot be empty.")
    if not public_key_pem:
        raise ValueError("Public key cannot be empty.")

    # Load the public key object
    try:
        rsa_key = RSA.import_key(public_key_pem.encode("utf-8"))
    except (ValueError, TypeError):
        raise ValueError("Invalid public key format. Please load or generate a valid key.")

    # Create OAEP cipher with SHA-256 hash
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)

    # Encrypt — RSA has a max message size based on key size
    # For 2048-bit key with OAEP+SHA256: max = 256 - 2*32 - 2 = 190 bytes
    try:
        ciphertext = cipher.encrypt(plain_text.encode("utf-8"))
    except ValueError as e:
        # Give a friendly message if the text is too long
        raise ValueError(
            f"Message is too long for RSA-2048 direct encryption (max ~190 chars). "
            f"Technical detail: {e}"
        )

    # Return as Base64 string
    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt(encrypted_text: str, private_key_pem: str) -> str:
    """
    Decrypt a Base64-encoded RSA ciphertext using an RSA private key.

    Parameters:
        encrypted_text  : Base64 string from encrypt().
        private_key_pem : The RSA private key as a PEM string.

    Returns:
        The original plain text.

    Raises:
        ValueError for bad data or wrong key.
    """
    if not encrypted_text:
        raise ValueError("Encrypted text cannot be empty.")
    if not private_key_pem:
        raise ValueError("Private key cannot be empty. Load or generate a key pair first.")

    # Decode Base64
    try:
        ciphertext = base64.b64decode(encrypted_text.encode("utf-8"))
    except Exception:
        raise ValueError("Invalid encrypted text. It may be corrupted or not RSA-encoded.")

    # Load the private key
    try:
        rsa_key = RSA.import_key(private_key_pem.encode("utf-8"))
    except (ValueError, TypeError):
        raise ValueError("Invalid private key format. Please load a valid private key.")

    # Decrypt
    try:
        cipher     = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        plain_text = cipher.decrypt(ciphertext).decode("utf-8")
    except (ValueError, TypeError):
        raise ValueError("Decryption failed. You may be using the wrong private key.")

    return plain_text


def save_keys(private_key_pem: str, public_key_pem: str,
              private_path: str, public_path: str) -> None:
    """
    Save RSA key pair to two separate files.

    Parameters:
        private_key_pem : Private key as PEM string.
        public_key_pem  : Public key as PEM string.
        private_path    : File path to save the private key.
        public_path     : File path to save the public key.
    """
    if not private_key_pem or not public_key_pem:
        raise ValueError("No keys to save. Generate or load a key pair first.")

    try:
        with open(private_path, "w") as f:
            f.write(private_key_pem)
        with open(public_path, "w") as f:
            f.write(public_key_pem)
    except PermissionError:
        raise PermissionError(f"Cannot write to the selected location. Check folder permissions.")
    except OSError as e:
        raise OSError(f"Failed to save keys: {e}")


def load_keys(private_path: str, public_path: str) -> tuple[str, str]:
    """
    Load an RSA key pair from two files.

    Parameters:
        private_path : Path to the private key PEM file.
        public_path  : Path to the public key PEM file.

    Returns:
        (private_key_pem, public_key_pem) as strings.
    """
    try:
        with open(private_path, "r") as f:
            private_key_pem = f.read()
        with open(public_path, "r") as f:
            public_key_pem = f.read()
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Key file not found: {e.filename}")
    except PermissionError:
        raise PermissionError("Cannot read the key files. Check file permissions.")

    # Validate both keys parse correctly
    try:
        RSA.import_key(private_key_pem.encode("utf-8"))
        RSA.import_key(public_key_pem.encode("utf-8"))
    except (ValueError, TypeError):
        raise ValueError("One or both key files contain invalid PEM data.")

    return private_key_pem, public_key_pem
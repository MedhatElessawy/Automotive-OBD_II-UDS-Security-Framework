# utils.py
import hmac                    # Used for HMAC-based key derivation in protected_mode
import hashlib                 # Provides SHA-256 hashing backend for HMAC
import config                  # Stores constants like SEED_CONSTANT and SECRET_KEY

def Hex_to_Int(x) -> int:
    """
    Convert a hex string (or int) into an integer.

    Accepted inputs:
    - int: returned as-is
    - string formats: "7E0", "0x7E0", "7e0", with surrounding spaces allowed

    Behavior on invalid input:
    - Returns 0 (instead of raising an exception)
    """
    if isinstance(x, int): return x
    s = str(x).strip().lower()
    if s.startswith("0x"): s = s[2:]
    try:
        return int(s, 16)
    except:
        # Project behavior: treat invalid hex as 0
        return 0

def pretty_hex(b: bytes) -> str:
    """
    Convert raw bytes into a readable hex string.
    Example: b'\\x27\\x01' -> "27 01"
    """
    return " ".join(f"{x:02X}" for x in b)

def seed_to_key(seed: bytes, protected_mode: bool = False) -> bytes:
    """
    Convert a SecurityAccess seed into a key.

    Two modes:

    1) Unprotected mode (protected_mode=False):
       - XOR seed with a constant (config.SEED_CONSTANT)
       - Key length equals seed length

    2) Protected mode (protected_mode=True):
       - Compute HMAC-SHA256 over the seed using config.SECRET_KEY
       - Take only the first len(seed) bytes as the key (truncate digest)

    Returns:
    - key bytes (same length as seed)
    """
    if not protected_mode:
        # XOR-based scheme (simple and reversible; used by this project's "unprotected" mode)
        constant_int = int.from_bytes(config.SEED_CONSTANT, "big")
        seed_int = int.from_bytes(seed, "big")
        key_int = seed_int ^ constant_int
        return key_int.to_bytes(len(seed), "big")
    
    # HMAC-based scheme (stronger; used when protected_mode=True)
    digest = hmac.new(config.SECRET_KEY, seed, hashlib.sha256).digest()
    return digest[:len(seed)]

def vin_to_bytes(vin: str) -> list[int]:
    """
    Convert VIN string to a list of ASCII integer codes.
    Example: "AB" -> [65, 66]
    """
    return [ord(c) for c in vin]

def build_nrc(sid: int, code: int) -> bytes:
    """
    Build a standard UDS negative response frame (NRC).

    Format:
    - 0x7F <original SID> <NRC code>
    """
    return bytes([0x7F, sid, code])

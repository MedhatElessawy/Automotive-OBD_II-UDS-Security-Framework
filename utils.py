# utils.py
import hmac
import hashlib
import config

def Hex_to_Int(x) -> int:
    if isinstance(x, int): return x
    s = str(x).strip().lower()
    if s.startswith("0x"): s = s[2:]
    try:
        return int(s, 16)
    except:
        return 0

def pretty_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

def seed_to_key(seed: bytes, protected_mode: bool = False) -> bytes:
    if not protected_mode:
        constant_int = int.from_bytes(config.SEED_CONSTANT, "big")
        seed_int = int.from_bytes(seed, "big")
        key_int = seed_int ^ constant_int
        return key_int.to_bytes(len(seed), "big")
    
    digest = hmac.new(config.SECRET_KEY, seed, hashlib.sha256).digest()
    return digest[:len(seed)]

def vin_to_bytes(vin: str) -> list[int]:
    return [ord(c) for c in vin]

def build_nrc(sid: int, code: int) -> bytes:
    return bytes([0x7F, sid, code])

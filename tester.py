```python
"
# tester.py
import time                 # Timing: delays, timeouts, simple polling windows
import keyboard             # Global hotkeys (requires elevated privileges on Linux)
import config               # CAN IDs and addressing configuration (physical/functional/response IDs)
import utils                # Hex parsing/formatting + security helpers (seed-to-key, etc.)
from transport import tm    # Transport manager: ISO-TP send/receive + CAN bus utilities

# ---------------- ANSI TERMINAL COLORS ----------------
# Purpose: Colorize specific outputs (e.g., routine results) for quick visual status
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


# ---------------- ISO-TP WRAPPERS ----------------
# Purpose: Keep calls short and consistent; delegates to tm.* directly
def ISOTP_SEND(data, txid, rxid): tm.send(data, txid, rxid)


def ISOTP_RECEIVE(txid, rxid, timeout=0.0): return tm.receive(txid, rxid, timeout)


# ---------------- GLOBAL TESTER STATE ----------------
# Purpose: Shared flags/state between menu, UDS logic, and hotkey logic
TESTER_PROTECTED_MODE = False        # Controls how seed_to_key() behaves (project-specific protection toggle)
TESTER_MITM_PROTECTION = False       # Enables token injection behavior for MITM-protected sessions
tester_session_token = None          # Stores a token returned after successful security access (if enabled)
last_tp_txid = None                  # Last TX CAN ID used for TesterPresent (so hotkey knows where to send)
last_tp_rxid = None                  # Last RX CAN ID expected for TesterPresent


# ==========================================================
# INPUT HELPERS (HEX PARSING)
# ==========================================================
# Purpose:
# - Enforce valid hex input for CAN IDs, service bytes, PIDs, and arbitrary payload data.
# - Re-prompt on invalid input instead of crashing.

def get_hex_input(prompt: str) -> str:
    # Reads user input and validates that it is valid hex via utils.Hex_to_Int()
    x = input(prompt).strip()
    try:
        utils.Hex_to_Int(x)
        return x
    except:
        print("Invalid hex. Enter again.")
        return get_hex_input(prompt)


def get_pid_list() -> list[int]:
    """
    Read one or more PIDs for Mode 01 requests.

    Accepted formats:
    - Space separated: "0C 0D 05"
    - Continuous hex:  "0C0D05"  (must be even length)
    Returns:
    - list of PID integers (each 0..255)
    """
    raw = input("Enter PID(s) (0C 0D 05 or 0C0D05): ").strip()
    if raw == "": return []
    if " " in raw:
        parts = raw.split()
    else:
        if len(raw) % 2 != 0:
            print("Invalid PID list format.")
            return get_pid_list()
        parts = [raw[i:i + 2] for i in range(0, len(raw), 2)]
    out = []
    for p in parts:
        try:
            out.append(utils.Hex_to_Int(p))
        except:
            print(f"Invalid PID: {p}")
            return get_pid_list()
    return out


def get_user_data_list() -> list[int]:
    """
    Read optional user data bytes appended after mode and PID(s).

    Accepted formats:
    - Space separated: "AA BB CC"
    - Continuous hex:  "AABBCC" (must be even length)
    Returns:
    - list of integers (each byte 0..255)
    """
    raw = input("Enter user data or press Enter: ").strip()
    if raw == "": return []
    if " " in raw:
        parts = raw.split()
    else:
        if len(raw) % 2 != 0:
            print("Invalid format: continuous hex must have even length.")
            return get_user_data_list()
        parts = [raw[i:i + 2] for i in range(0, len(raw), 2)]
    out = []
    for p in parts:
        try:
            out.append(utils.Hex_to_Int(p))
        except:
            print(f"Invalid byte: {p}")
            return get_user_data_list()
    return out


def get_hex_list(prompt: str) -> list[int]:
    """
    Generic hex list reader (used for UDS frames).

    Accepted formats:
    - Space separated: "27 01"
    - Continuous hex:  "2701" (must be even length)
    Returns:
    - list of integers (each byte 0..255)
    """
    raw = input(prompt).strip()
    if raw == "": return []
    if " " in raw:
        parts = raw.split()
    else:
        if len(raw) % 2 != 0:
            print("Invalid hex list format.")
            return get_hex_list(prompt)
        parts = [raw[i:i + 2] for i in range(0, len(raw), 2)]
    out = []
    for p in parts:
        try:
            out.append(utils.Hex_to_Int(p))
        except:
            print(f"Invalid hex byte: {p}")
            return get_hex_list(prompt)
    return out


# ==========================================================
# OBD LOGIC
# ==========================================================
def OBD_Frame(id_hex, mode_hex, pid_hex, user_data=None):
    """
    Build an OBD request payload and CAN ID.

    id_hex:
        CAN ID as hex string (e.g., "7DF" or "7E0")
    mode_hex:
        OBD mode as hex string (e.g., "01", "09")
    pid_hex:
        Either:
        - list of PID ints (for Mode 01 multi-PID requests)
        - single PID hex string (for non-Mode01 requests)
    user_data:
        Optional list of extra bytes appended at end of request
    Returns:
        (can_id:int, frame:bytes)
    """
    if user_data is None: user_data = []
    can_id = utils.Hex_to_Int(id_hex)
    mode = utils.Hex_to_Int(mode_hex)
    pids = pid_hex if isinstance(pid_hex, list) else [utils.Hex_to_Int(pid_hex)]
    frame = bytes([mode] + pids + user_data)
    return can_id, frame


def OBD():
    """
    Interactive OBD request sender.

    Behavior:
    - Builds a request based on user input.
    - Sends it using ISO-TP.
    - For Mode 01: collects multiple replies for 1 second (supports multi-PID style).
    - For other modes: waits for one reply (up to 5 seconds).
    """
    print("=== Build OBD Frame ===")
    id_hex = get_hex_input("Enter CAN ID (hex): ")
    mode_hex = get_hex_input("Enter Mode   (hex): ")

    # Mode 01 supports multiple PIDs in this UI
    if utils.Hex_to_Int(mode_hex) == 0x01:
        pid_hex = get_pid_list()
        if not pid_hex:
            print("No PIDs entered.")
            return
    else:
        pid_hex = get_hex_input("Enter PID    (hex): ")

    # Optional extra bytes after PID(s)
    user_data = get_user_data_list()

    # Construct final request
    can_id, frame = OBD_Frame(id_hex, mode_hex, pid_hex, user_data)
    mode = frame[0]

    # Default RX ID for responses (project uses config.ID_ECU_RESPONSE)
    rxid = config.ID_ECU_RESPONSE

    # Mode 09 restrictions enforced here (project-specific choice)
    if mode == 0x09:
        if can_id not in (config.ID_FUNCTIONAL, config.ID_ECU_PHYSICAL):
            print("[ERROR] Mode 09 only allows ID 0x7DF or 0x7E0.")
            return

    # Clear old buffered frames so the next receive is "fresh"
    tm.clear_queues()

    # Send request
    print(f"[TESTER] Sending Request: 0x{can_id:03X} , {utils.pretty_hex(frame)}")
    ISOTP_SEND(frame, can_id, rxid)

    # ---------------- MODE 01 RESPONSE COLLECTION ----------------
    if mode == 0x01:
        # Collect replies for a fixed window (1 second)
        end = time.time() + 1.0
        replies = []
        while time.time() < end:
            resp = ISOTP_RECEIVE(can_id, rxid, 0.2)
            if resp: replies.append(resp)

        if not replies:
            print("[Tester] received response: None")
        else:
            for response in replies:
                # Print each response (engine ECU side)
                print(f"[Tester] Engine response: 0x{config.ID_ENGINE_RESPONSE:03X} , {utils.pretty_hex(response)}")

                # Negative response format in this project: starts with 0x7F
                if response[0] == 0x7F:
                    print("Service not supported in active session")
                    continue

                # Positive response: (mode + 0x40) (e.g., 0x41 for mode 0x01)
                if response[0] != (0x40 + mode):
                    continue

                pid = response[1]
                data = response[2:]

                # Decode specific PIDs for human-readable values
                # PID 0C: RPM → ((A*256)+B)/4
                if pid == 0x0C and len(data) >= 2:
                    A, B = data[0], data[1]
                    rpm = ((A * 256) + B) / 4
                    print(f"[Tester] Received RPM: {rpm}")
                # PID 0D: Speed → A (km/h)
                elif pid == 0x0D and len(data) >= 1:
                    speed = data[0]
                    print(f"[Tester] Received Speed: {speed} Km/h")
                else:
                    # Any other PID: print raw data bytes
                    print(f"[Tester] Received PID {pid:02X}: {utils.pretty_hex(data)}")

    # ---------------- NON-MODE 01 (SINGLE RESPONSE) ----------------
    else:
        resp = ISOTP_RECEIVE(can_id, rxid, 5.0)
        if resp:
            # Negative responses / error mapping (project-specific)
            if resp[0] == 0x7F:
                print("Service not supported in active session")
            elif resp[0] == 0x12:
                print("Sub function not supported")
            else:
                print(f"[Tester] Body response: 0x{config.ID_ECU_RESPONSE:03X} , {utils.pretty_hex(resp)}")

                # Mode 09 VIN display (prints ASCII from response bytes)
                if len(resp) > 3 and mode == 0x09:
                    print(f"[Tester] Vin number is : {''.join(chr(b) for b in resp)}")
        else:
            print("[Tester] received response: None")

    # UI pacing delay (avoids immediate menu redraw spam)
    time.sleep(1.0)


# ==========================================================
# ROUTINE CONTROL (UDS) OUTPUT PARSER
# ==========================================================
def print_routine_result(payload: bytes):
    """
    Decode and print routine control results in a readable format.

    Expected project payload layout:
    - payload[2:4] = RID (routine identifier)
    - payload[4:-1] = routine data bytes
    - payload[-1] = routine status byte
    """
    if len(payload) < 5: return
    rid_val = (payload[2] << 8) | payload[3]
    data = payload[4:-1]
    status = payload[-1]
    print(f"Routine 0x{rid_val:04X} Result (status {status}):")

    # Project-specific RID decoding examples
    if rid_val == 0x1234:  # Self Test
        if len(data) >= 3:
            rpm = (data[0] << 8) | data[1]
            speed = data[2]
            rpm_color = GREEN if rpm != 0 else RED
            speed_color = GREEN if speed != 0 else RED
            print(f"  RPM: {rpm_color}{rpm}{RESET}")
            print(f"  Speed: {speed_color}{speed}{RESET}")
    elif rid_val == 0x1456:  # Checksum
        if len(data) >= 4:
            crc = int.from_bytes(data[:4], "big")
            color = GREEN if crc != 0 else RED
            print(f"  CRC32: {color}{crc:08X}{RESET}")


# ==========================================================
# UDS LOGIC
# ==========================================================
def UDS():
    """
    Interactive UDS request sender.

    Behavior:
    - User enters CAN ID then UDS frame bytes (service + parameters).
    - Handles SecurityAccess (0x27) specially: performs seed request then key send.
    - Supports optional MITM token behavior for session control (project-specific).
    - Prints interpreted output for common services (0x10 session, 0x11 reset, 0x22 read, 0x2E write, 0x31 routine).
    """
    global last_tp_txid, last_tp_rxid, tester_session_token
    print("=== Build UDS Frame ===")
    id_hex = get_hex_input("Enter CAN ID (hex): ")
    can_id = utils.Hex_to_Int(id_hex)

    while True:
        # Read raw UDS bytes from user (e.g., "10 03" or "2701")
        uds_frame = get_hex_list("Enter UDS Frame:  ")
        if not uds_frame:
            print("[ERROR] Empty UDS frame.")
            return

        # Request TX ID is the user-entered CAN ID
        req_txid = can_id

        # For physical addressing, expect response on config.ID_ECU_RESPONSE
        # For non-physical addressing, req_rxid becomes None (project design)
        req_rxid = config.ID_ECU_RESPONSE if can_id == config.ID_ECU_PHYSICAL else None

        # Remember last physical TX/RX so the TesterPresent hotkey can reuse them
        if req_rxid:
            last_tp_txid, last_tp_rxid = req_txid, req_rxid

        print(f"[TESTER] UDS Frame: 0x{can_id:03X} , {' '.join(f'{b:02X}' for b in uds_frame)}")

        sid = uds_frame[0]  # Service ID (first byte)

        # ---------------- MITM TOKEN INJECTION (PROJECT-SPECIFIC) ----------------
        # If enabled, and request is DiagnosticSessionControl (0x10) to Programming/Extended:
        # - Append stored token to the request if available.
        if TESTER_MITM_PROTECTION and sid == 0x10 and uds_frame[1] in (0x02, 0x03):
            if tester_session_token:
                frame = bytes(uds_frame) + tester_session_token
            else:
                print("No session token stored. Perform SecurityAccess first.")
                return
        else:
            frame = bytes(uds_frame)

        tm.clear_queues()

        # ---------------- SECURITY ACCESS CLIENT FLOW ----------------
        # 0x27 0x01 → request seed
        # ECU: 0x67 0x01 <seed>
        # tester computes key and sends: 0x27 0x02 <key>
        # ECU: 0x67 0x02 [optional token bytes...]
        if sid == 0x27:
            if req_rxid is None:
                print("[ERROR] Security Access must be sent to a physical ECU.")
                continue

            # Send seed request
            ISOTP_SEND(frame, req_txid, req_rxid)
            resp = ISOTP_RECEIVE(req_txid, req_rxid, 5.0)

            # Validate seed response
            if resp and resp[0] == 0x67 and resp[1] == 0x01:
                seed = resp[2:]
                key = utils.seed_to_key(seed, TESTER_PROTECTED_MODE)

                # Send key
                frame2 = bytes([0x27, 0x02]) + key
                ISOTP_SEND(frame2, req_txid, req_rxid)
                resp2 = ISOTP_RECEIVE(req_txid, req_rxid, 5.0)

                # Validate access granted
                if resp2 and resp2[0] == 0x67 and resp2[1] == 0x02:
                    # If MITM protection enabled, store token bytes from response (project-specific format)
                    if TESTER_MITM_PROTECTION and len(resp2) >= 6:
                        tester_session_token = bytes(resp2[2:6])
                        print(f"Security Access Granted, session token = {tester_session_token.hex()}")
                    else:
                        print("Security Access Granted (no MITM token used)")
                elif resp2 and resp2[0] == 0x7F:
                    print(f"Security Access Denied (NRC: {resp2[2]:02X})")
            elif resp and resp[0] == 0x7F:
                print("Incorrect Condition")
            continue

        # ---------------- GENERIC UDS SEND/RECEIVE ----------------
        ISOTP_SEND(frame, req_txid, req_rxid)
        resp = ISOTP_RECEIVE(req_txid, req_rxid, 5.0)

        if resp:
            # RoutineControl positive response handling: 0x71 .. (project uses response[1]==0x03 case)
            if resp[0] == 0x71 and len(resp) > 2 and resp[1] == 0x03:
                print_routine_result(resp)

            # DiagnosticSessionControl positive response: 0x50 <session>
            elif resp[0] == 0x50:
                sess = "Default"
                if resp[1] == 0x02:
                    sess = "Programming"
                elif resp[1] == 0x03:
                    sess = "Extended"
                print(f"{sess} Session is on")

            # ECUReset positive response: 0x51
            elif resp[0] == 0x51:
                print("ECU Reset is Done.")

            # ReadDataByIdentifier positive response: 0x62
            elif resp[0] == 0x62:
                print(f"[Tester] Read response: {utils.pretty_hex(resp)}")
                if len(resp) >= 3:
                    did = (resp[1] << 8) | resp[2]
                    data = resp[3:]
                    if did == 0xF190:
                        print(f"[Tester] Vin number is : {''.join(chr(b) for b in data)}")
                    elif did == 0xF18C:
                        print(f"[Tester] Serial number is : {''.join(chr(b) for b in data)}")

            # WriteDataByIdentifier positive response: 0x6E
            elif resp[0] == 0x6E:
                print(f"[Tester] Write acknowledged")

            # Negative response: 0x7F <SID> <NRC>
            elif resp[0] == 0x7F:
                print(f"⬅ NRC: 7F {resp[1]:02X} {resp[2]:02X}")
                if resp[2] == 0x31:
                    print("Request Out Of Range (unsupported DID)")
                elif resp[2] == 0x13:
                    print("Incorrect Message Length")
                elif resp[2] == 0x22:
                    print("Conditions Not Correct")
                elif resp[2] == 0x33:
                    print("Request Not Allowed In This Session")
            else:
                # Unknown/other responses: print raw
                print(f"Response: {utils.pretty_hex(resp)}")
        else:
            print("[Tester] No response")


# ==========================================================
# TESTER PRESENT HOTKEY (CTRL+R)
# ==========================================================
def tp_hotkey():
    """
    Send UDS TesterPresent (0x3E 0x00) using the last remembered physical TX/RX IDs.

    Purpose:
    Keep diagnostic session alive manually without retyping frames.
    """
    if last_tp_txid and last_tp_rxid:
        frame = b"\x3E\x00"
        print(f"\n[TESTER] Sending TesterPresent: 0x{last_tp_txid:03X} , {utils.pretty_hex(frame)}")
        ISOTP_SEND(frame, last_tp_txid, last_tp_rxid)
        resp = ISOTP_RECEIVE(last_tp_txid, last_tp_rxid, 2.0)
        if resp:
            print(f"[TESTER] TP Response: {utils.pretty_hex(resp)}")
        else:
            print("[TESTER] No TP response")
        print("Enter UDS Frame:  ", end='', flush=True)


# Register hotkey at global scope (works while the main loop is running)
keyboard.add_hotkey('ctrl+r', tp_hotkey)

# ==========================================================
# MAIN MENU LOOP
# ==========================================================
while True:
    print("\n=== Tester Menu ===")
    print("1) OBD")
    print("2) UDS")
    c = input("Select option: ").strip()
    if c == "1":
        OBD()
    elif c == "2":
        UDS()
"
```

# tester.py
import time
import keyboard
import config
import utils
from transport import tm

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


# Wrappers
def ISOTP_SEND(data, txid, rxid): tm.send(data, txid, rxid)


def ISOTP_RECEIVE(txid, rxid, timeout=0.0): return tm.receive(txid, rxid, timeout)


# Global State
TESTER_PROTECTED_MODE = False
TESTER_MITM_PROTECTION = False
tester_session_token = None
last_tp_txid = None
last_tp_rxid = None


# --- Original Input Logic with Visuals ---
def get_hex_input(prompt: str) -> str:
    x = input(prompt).strip()
    try:
        utils.Hex_to_Int(x)
        return x
    except:
        print("Invalid hex. Enter again.")
        return get_hex_input(prompt)


def get_pid_list() -> list[int]:
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


# --- Logic ---
def OBD_Frame(id_hex, mode_hex, pid_hex, user_data=None):
    if user_data is None: user_data = []
    can_id = utils.Hex_to_Int(id_hex)
    mode = utils.Hex_to_Int(mode_hex)
    pids = pid_hex if isinstance(pid_hex, list) else [utils.Hex_to_Int(pid_hex)]
    frame = bytes([mode] + pids + user_data)
    return can_id, frame


def OBD():
    print("=== Build OBD Frame ===")
    id_hex = get_hex_input("Enter CAN ID (hex): ")
    mode_hex = get_hex_input("Enter Mode   (hex): ")

    if utils.Hex_to_Int(mode_hex) == 0x01:
        pid_hex = get_pid_list()
        if not pid_hex:
            print("No PIDs entered.")
            return
    else:
        pid_hex = get_hex_input("Enter PID    (hex): ")

    user_data = get_user_data_list()
    can_id, frame = OBD_Frame(id_hex, mode_hex, pid_hex, user_data)
    mode = frame[0]

    rxid = config.ID_ECU_RESPONSE
    if mode == 0x09:
        if can_id not in (config.ID_FUNCTIONAL, config.ID_ECU_PHYSICAL):
            print("[ERROR] Mode 09 only allows ID 0x7DF or 0x7E0.")
            return
    tm.clear_queues()
    print(f"[TESTER] Sending Request: 0x{can_id:03X} , {utils.pretty_hex(frame)}")
    ISOTP_SEND(frame, can_id, rxid)

    if mode == 0x01:
        end = time.time() + 1.0
        replies = []
        while time.time() < end:
            resp = ISOTP_RECEIVE(can_id, rxid, 0.2)
            if resp: replies.append(resp)

        if not replies:
            print("[Tester] received response: None")
        else:
            for response in replies:
                print(f"[Tester] Engine response: 0x{config.ID_ENGINE_RESPONSE:03X} , {utils.pretty_hex(response)}")

                if response[0] == 0x7F:
                    print("Service not supported in active session")
                    continue

                # Check for (Mode + 0x40)
                if response[0] != (0x40 + mode):
                    continue

                pid = response[1]
                data = response[2:]

                # --- RPM AND SPEED CALCULATION RESTORED HERE ---
                if pid == 0x0C and len(data) >= 2:
                    A, B = data[0], data[1]
                    rpm = ((A * 256) + B) / 4
                    print(f"[Tester] Received RPM: {rpm}")
                elif pid == 0x0D and len(data) >= 1:
                    speed = data[0]
                    print(f"[Tester] Received Speed: {speed} Km/h")
                else:
                    print(f"[Tester] Received PID {pid:02X}: {utils.pretty_hex(data)}")

    else:
        resp = ISOTP_RECEIVE(can_id, rxid, 5.0)
        if resp:
            if resp[0] == 0x7F:
                print("Service not supported in active session")
            elif resp[0] == 0x12:
                print("Sub function not supported")
            else:
                print(f"[Tester] Body response: 0x{config.ID_ECU_RESPONSE:03X} , {utils.pretty_hex(resp)}")
                if len(resp) > 3 and mode == 0x09:
                    print(f"[Tester] Vin number is : {''.join(chr(b) for b in resp)}")
        else:
            print("[Tester] received response: None")
    time.sleep(1.0)


def print_routine_result(payload: bytes):
    if len(payload) < 5: return
    rid_val = (payload[2] << 8) | payload[3]
    data = payload[4:-1]
    status = payload[-1]
    print(f"Routine 0x{rid_val:04X} Result (status {status}):")
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


def UDS():
    global last_tp_txid, last_tp_rxid, tester_session_token
    print("=== Build UDS Frame ===")
    id_hex = get_hex_input("Enter CAN ID (hex): ")
    can_id = utils.Hex_to_Int(id_hex)

    while True:
        uds_frame = get_hex_list("Enter UDS Frame:  ")
        if not uds_frame:
            print("[ERROR] Empty UDS frame.")
            return

        req_txid = can_id
        req_rxid = config.ID_ECU_RESPONSE if can_id == config.ID_ECU_PHYSICAL else None

        if req_rxid:
            last_tp_txid, last_tp_rxid = req_txid, req_rxid

        print(f"[TESTER] UDS Frame: 0x{can_id:03X} , {' '.join(f'{b:02X}' for b in uds_frame)}")

        sid = uds_frame[0]

        # MITM Token Injection
        if TESTER_MITM_PROTECTION and sid == 0x10 and uds_frame[1] in (0x02, 0x03):
            if tester_session_token:
                frame = bytes(uds_frame) + tester_session_token
            else:
                print("No session token stored. Perform SecurityAccess first.")
                return
        else:
            frame = bytes(uds_frame)
        tm.clear_queues()
        # Security Access Client Logic
        if sid == 0x27:
            if req_rxid is None:
                print("[ERROR] Security Access must be sent to a physical ECU.")
                continue
            ISOTP_SEND(frame, req_txid, req_rxid)
            resp = ISOTP_RECEIVE(req_txid, req_rxid, 5.0)
            if resp and resp[0] == 0x67 and resp[1] == 0x01:
                seed = resp[2:]
                key = utils.seed_to_key(seed, TESTER_PROTECTED_MODE)
                frame2 = bytes([0x27, 0x02]) + key
                ISOTP_SEND(frame2, req_txid, req_rxid)
                resp2 = ISOTP_RECEIVE(req_txid, req_rxid, 5.0)
                if resp2 and resp2[0] == 0x67 and resp2[1] == 0x02:
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

        ISOTP_SEND(frame, req_txid, req_rxid)
        resp = ISOTP_RECEIVE(req_txid, req_rxid, 5.0)

        if resp:
            # Routine Control Special Print
            if resp[0] == 0x71 and len(resp) > 2 and resp[1] == 0x03:
                print_routine_result(resp)
            elif resp[0] == 0x50:
                sess = "Default"
                if resp[1] == 0x02:
                    sess = "Programming"
                elif resp[1] == 0x03:
                    sess = "Extended"
                print(f"{sess} Session is on")
            elif resp[0] == 0x51:
                print("ECU Reset is Done.")
            elif resp[0] == 0x62:
                print(f"[Tester] Read response: {utils.pretty_hex(resp)}")
                if len(resp) >= 3:
                    did = (resp[1] << 8) | resp[2]
                    data = resp[3:]
                    if did == 0xF190:
                        print(f"[Tester] Vin number is : {''.join(chr(b) for b in data)}")
                    elif did == 0xF18C:
                        print(f"[Tester] Serial number is : {''.join(chr(b) for b in data)}")

            elif resp[0] == 0x6E:
                print(f"[Tester] Write acknowledged")
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
                print(f"Response: {utils.pretty_hex(resp)}")
        else:
            print("[Tester] No response")


def tp_hotkey():
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


keyboard.add_hotkey('ctrl+r', tp_hotkey)

while True:
    print("\n=== Tester Menu ===")
    print("1) OBD")
    print("2) UDS")
    c = input("Select option: ").strip()
    if c == "1":
        OBD()
    elif c == "2":
        UDS()
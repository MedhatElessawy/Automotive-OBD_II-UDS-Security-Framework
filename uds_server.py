# uds_ecu.py
import time                    # Used for timing (lockout timers, S3 session timeout checks)
import os                      # Used to check/create the simulated ECU program file on disk
import zlib                    # Used to compute CRC32 for the checksum routine
import random                  # Used to generate random security seeds
import config                  # Holds service IDs, session constants, CAN IDs, tokens, parameters
import utils                   # Helpers: hex formatting, NRC building, VIN conversion, seed->key
from transport import tm       # Transport manager: ISO-TP send/receive on CAN
from s3_timer import S3Timer   # S3 session timeout helper (resets session to Default after inactivity)


class UDSHandler:
    """
    Simulated UDS ECU handler.

    Purpose:
    - Receive UDS requests and route them by Service ID (SID).
    - Enforce security access and session rules.
    - Support a small set of UDS services:
      * 0x27 SecurityAccess
      * 0x10 DiagnosticSessionControl
      * 0x11 ECUReset
      * 0x22 ReadDataByIdentifier
      * 0x2E WriteDataByIdentifier
      * 0x31 RoutineControl
      * 0x3E TesterPresent
    - Simulate S3 session timeout (return to default session after inactivity).
    """

    def __init__(self):
        # ---------------- SECURITY ACCESS CONFIG ----------------
        self.SEED_MIN = 0x00001000           # Minimum random seed value
        self.SEED_MAX = 0x00001FFF           # Maximum random seed value
        self.MAX_ERROR_COUNT = 3             # Number of wrong keys before lockout (protected mode only)
        self.LOCKOUT_SECONDS = 30            # Lockout duration after max failures
        self.PROTECTED_MODE = False          # If True: enable lockout + seed invalidation behavior
        self.MITM_PROTECTION = False         # If True: require token for DSC (session change)

        # ---------------- SECURITY ACCESS STATE ----------------
        self.lockout_until = 0.0             # Timestamp until which SecurityAccess is blocked (protected mode)
        self.access_flag = 0                 # 1 means SecurityAccess granted; 0 means not granted
        self.error_num = 0                   # Count wrong keys in protected mode
        self.session = config.SESSION_DEFAULT# Current diagnostic session state
        self.last_seed = None                # Stores last generated seed bytes (used to validate the next key)
        self.session_token = None            # Token used for MITM protection (if enabled)

        # ---------------- S3 / ROUTINE STATE ----------------
        self.s3_running = False              # True when S3 timer is active (after entering certain sessions)
        self.routine_results = {}            # Stores routine outputs for later GetResults calls

        # ---------------- PROGRAM FILE SIMULATION ----------------
        # Purpose:
        # - Mimic an ECU memory/program area that can be read/written via DIDs.
        # - Persist it on disk so it survives restarts.
        self.PROGRAM_FILE_PATH = "ecu_program.bin"
        if not os.path.exists(self.PROGRAM_FILE_PATH):
            with open(self.PROGRAM_FILE_PATH, "wb") as f:
                f.write(b"\x10\x20\x30\x40")
        with open(self.PROGRAM_FILE_PATH, "rb") as f:
            self.ECU_PROGRAM_FILE = f.read()

        # ---------------- S3 TIMER SETUP ----------------
        # Purpose:
        # - If S3 expires, reset session to Default and clear sensitive state.
        # In this ECU simulation, send_tester_present_cb only logs (ECU does not send TP frames).
        self.s3 = S3Timer(
            send_tester_present_cb=lambda: print("[S3Timer] TesterPresent callback (no frame sent from ECU)"),
            expiry_callback=self._s3_expiry,
            s3_timeout=5, auto_tp=False, tp_lead=1.0
        )

        # Static VIN used for ReadDataByIdentifier and other routines
        self.VIN = "WP0ZX41S100893123"

    def _s3_expiry(self):
        """
        Called by S3Timer when inactivity reaches s3_timeout.

        Effects:
        - Return ECU to Default Session.
        - Stop S3 state.
        - Clear any cached routine results.
        """
        self.session = config.SESSION_DEFAULT
        self.s3_running = False
        self.routine_results.clear()
        print(f"session is {self.session}")
        print("[S3Timer] S3 expired → session returned to Default")

    def handle_request(self, req: bytes, rxid_used: int):
        """
        Top-level dispatcher for incoming UDS payloads.

        req:
            Raw UDS bytes (service ID is req[0]).
        rxid_used:
            The CAN ID the request came in on (used to reply to the correct requester).
        """
        # General logging for UDS requests
        print(f"[Body ECU] received request: 0x{rxid_used:03X} , {utils.pretty_hex(req)}")

        sid = req[0]  # Service ID
        if sid == config.SID_SECURITY_ACCESS:
            self._security_access(req, rxid_used)
        elif sid == config.SID_DIAGNOSTIC_SESSION_CONTROL:
            self._dsc(req, rxid_used)
        elif sid == config.SID_ECU_RESET:
            self._ecu_reset(req, rxid_used)
        elif sid == config.SID_READ_DATA_BY_ID:
            self._rdbi(req, rxid_used)
        elif sid == config.SID_WRITE_DATA_BY_ID:
            self._wdbi(req, rxid_used)
        elif sid == config.SID_ROUTINE_CONTROL:
            self._routine_control(req, rxid_used)
        elif sid == config.SID_TESTER_PRESENT:
            self._tester_present(req, rxid_used)
        else:
            # 0x11 is "Service Not Supported" in UDS NRCs
            self._send_nrc(rxid_used, sid, 0x11)
            print(f"Service 0x{sid:02X}: Service Not Supported")

    def _send(self, data, rxid):
        """
        Send an ISO-TP response using ECU response CAN ID.

        data:
            Response payload bytes.
        rxid:
            The requester's CAN ID used for addressing the response back correctly.
        """
        tm.send(data, config.ID_ECU_RESPONSE, rxid)
        print(f"[Body ECU] sending response: 0x{config.ID_ECU_RESPONSE:03X} , {utils.pretty_hex(data)}")

    def _send_nrc(self, rxid, sid, code):
        """
        Send a UDS negative response (NRC).

        sid:
            The original service ID being rejected.
        code:
            NRC code (e.g., 0x13 incorrect length, 0x33 security denied, etc.)
        """
        frame = utils.build_nrc(sid, code)
        self._send(frame, rxid)

    # ==========================================================
    # SERVICE 0x27: SECURITY ACCESS
    # ==========================================================
    def _security_access(self, req, rxid):
        sid = req[0]

        # Must have at least SID + SubFunction
        if len(req) < 2:
            self._send_nrc(rxid, sid, 0x13)
            print("SecurityAccess: Incorrect Message Length")
            return

        sub = req[1]

        # Protected mode lockout: reject all security access requests until lockout expires
        if self.PROTECTED_MODE and time.time() < self.lockout_until:
            self._send_nrc(rxid, sid, 0x33)
            print(f"[Body ECU] LOCKOUT ACTIVE until {self.lockout_until:.2f}, deny 0x27")
            return

        # ---------- SubFunction 0x01: Request Seed ----------
        if sub == 0x01:
            # Generate random seed, store it, clear any old token
            seed_int = random.randint(self.SEED_MIN, self.SEED_MAX)
            self.last_seed = seed_int.to_bytes(4, "big")
            self.session_token = None

            # Positive response: 67 01 <seed>
            resp = bytes([sid + 0x40, sub]) + self.last_seed
            self._send(resp, rxid)
            print(f"SecurityAccess: Seed generated {self.last_seed.hex()}")
            return

        # ---------- SubFunction 0x02: Send Key ----------
        if sub == 0x02:
            # Need a stored seed before accepting a key
            if self.last_seed is None:
                self._send_nrc(rxid, sid, 0x22)
                print("SecurityAccess: No seed stored, conditions not correct")
                return

            # Key must match seed length (project uses same length)
            if len(req) < 2 + len(self.last_seed):
                self._send_nrc(rxid, sid, 0x13)
                print("SecurityAccess: Key length incorrect")
                return

            # Received key bytes (everything after SID+Sub)
            key_rx = req[2:]

            # Compute expected key from stored seed
            key_ex = utils.seed_to_key(self.last_seed, self.PROTECTED_MODE)

            print(f"[Body ECU] SecurityAccess: received key {key_rx.hex()}, expected {key_ex.hex()}")

            # ---------- Key Correct ----------
            if bytes(key_rx) == key_ex:
                self.access_flag = 1
                self.error_num = 0

                # Protected mode: invalidate the seed after a successful unlock
                if self.PROTECTED_MODE:
                    self.last_seed = None

                payload = bytes([sid + 0x40, sub])

                # MITM protection enabled: return a session token instead of echoing key
                if self.MITM_PROTECTION:
                    self.session_token = config.SESSION_TOKEN_STATIC
                    payload += self.session_token
                    print(f"SecurityAccess: ACCESS GRANTED, session token={self.session_token.hex()}")
                else:
                    # Legacy behavior: echo expected key in response (project-specific)
                    self.session_token = None
                    payload += key_ex
                    print("SecurityAccess: ACCESS GRANTED (no MITM protection)")

                self._send(payload, rxid)

            # ---------- Key Incorrect ----------
            else:
                self.access_flag = 0

                # Unprotected mode: unlimited attempts; always reply NRC 0x35 (InvalidKey)
                if not self.PROTECTED_MODE:
                    self._send_nrc(rxid, sid, 0x35)
                    print("SecurityAccess: Invalid Key (no limit in unprotected mode)")

                # Protected mode: count failures then lockout with NRC 0x33
                else:
                    if self.error_num < self.MAX_ERROR_COUNT - 1:
                        self.error_num += 1
                        self._send_nrc(rxid, sid, 0x35)
                        print("SecurityAccess: Invalid Key")
                    else:
                        self.error_num = 0
                        self._send_nrc(rxid, sid, 0x33)
                        self.lockout_until = time.time() + self.LOCKOUT_SECONDS
                        print("SecurityAccess: ACCESS FAILED FOR THREE TIMES")
                        print(f"SecurityAccess: LOCKOUT for {self.LOCKOUT_SECONDS} seconds")
            return

        # Any other subfunction not implemented
        self._send_nrc(rxid, sid, 0x12)
        print(f"SecurityAccess: SubFunction 0x{sub:02X} Not Supported")

    # ==========================================================
    # SERVICE 0x10: DIAGNOSTIC SESSION CONTROL
    # ==========================================================
    def _dsc(self, req, rxid):
        sid, sub = req[0], req[1]

        # ---------- Default Session ----------
        if sub == 0x01:
            self.session = config.SESSION_DEFAULT
            self.s3.stop()
            self.s3_running = False
            self._send(bytes([0x50, sub]), rxid)
            print("Default Session is on")
            return

        # ---------- Programming (0x02) or Extended (0x03) ----------
        if sub in (0x02, 0x03):
            # Validate access rules depending on whether MITM protection is enabled
            allowed = False
            msg = ""

            # Legacy mode: only requires access_flag==1
            if not self.MITM_PROTECTION:
                if self.access_flag == 1:
                    allowed = True
                else:
                    msg = "Security Access Denied (legacy DSC)"

            # MITM protection: requires token appended to request and correct value
            else:
                # Expect: 10 <sub> <4-byte token>  => total length 6
                if len(req) != 6:
                    print(f"DSC: Incorrect Message Length (token missing)")
                    self._send_nrc(rxid, sid, 0x13)
                    return

                if self.access_flag == 1 and self.session_token:
                    if bytes(req[2:6]) == self.session_token:
                        allowed = True
                    else:
                        msg = "DSC: Invalid session token"
                else:
                    msg = "DSC: Security Access Denied (no token)"

            if allowed:
                # Update session based on subfunction
                self.session = config.SESSION_PROGRAMMING if sub == 0x02 else config.SESSION_EXTENDED
                self._send(bytes([0x50, sub]), rxid)

                sess_name = "Programming" if sub == 0x02 else "Extended"
                print(f"{sess_name} Session is on")

                # Start S3 timer for non-default sessions
                self.s3.start()
                self.s3_running = True
                print("[S3Timer] Started after successful Diagnostic Session")
            else:
                self._send(utils.build_nrc(sid, 0x33), rxid)
                print(msg)

    # ==========================================================
    # SERVICE 0x11: ECU RESET
    # ==========================================================
    def _ecu_reset(self, req, rxid):
        sid = req[0]

        # Reset requires SecurityAccess
        if self.access_flag != 1:
            self._send_nrc(rxid, sid, 0x33)
            print("ECU Reset blocked (Security Access Denied)")
            return

        # Need subfunction byte
        if len(req) < 2:
            self._send_nrc(rxid, sid, 0x13)
            print("ECU Reset: Incorrect Message Length")
            return

        sub = req[1]

        # Supported reset subfunctions in this simulation
        if sub in (0x01, 0x03):
            # Reset clears access and returns session to default
            self.access_flag = 0
            self.session = config.SESSION_DEFAULT
            self.s3.stop()
            self.s3_running = False
            self._send(bytes([sid + 0x40, sub]), rxid)
            print("ECU Reset is Done.")
        else:
            self._send_nrc(rxid, sid, 0x12)
            print("ECU Reset: SubFunction Not Supported")

    # ==========================================================
    # SERVICE 0x22: READ DATA BY IDENTIFIER (DID)
    # ==========================================================
    def _rdbi(self, req, rxid):
        sid = req[0]

        # Must be exactly: 22 DID_H DID_L
        if len(req) != 3:
            self._send_nrc(rxid, sid, 0x13)
            print("Incorrect Message Length")
            return

        did = (req[1] << 8) | req[2]

        # Session access rules per DID (project-specific)
        allowed = False
        if did in (0xF190, 0xF18C):
            if self.session in (config.SESSION_PROGRAMMING, config.SESSION_EXTENDED):
                allowed = True
        elif did == 0xF1A0:
            if self.session in (config.SESSION_DEFAULT, config.SESSION_PROGRAMMING, config.SESSION_EXTENDED):
                allowed = True
        else:
            self._send_nrc(rxid, sid, 0x31)
            print("Request Out Of Range (unsupported DID)")
            return

        if not allowed:
            self._send_nrc(rxid, sid, 0x22)
            print("Conditions Not Correct")
            return

        # DID payload selection
        data = b""
        if did == 0xF190:
            data = bytes(utils.vin_to_bytes(self.VIN))
        elif did == 0xF18C:
            data = b"SN1234567890"
        elif did == 0xF1A0:
            data = self.ECU_PROGRAM_FILE

        # Positive response: 62 DID_H DID_L <data...>
        self._send(bytes([sid + 0x40, req[1], req[2]]) + data, rxid)

    # ==========================================================
    # SERVICE 0x2E: WRITE DATA BY IDENTIFIER (DID)
    # ==========================================================
    def _wdbi(self, req, rxid):
        sid = req[0]

        # Writes require SecurityAccess
        if self.access_flag != 1:
            self._send_nrc(rxid, sid, 0x33)
            print("Request Not Allowed (Security Access Denied)")
            return

        # Must be at least: 2E DID_H DID_L <1 byte data>
        if len(req) < 4:
            self._send_nrc(rxid, sid, 0x13)
            print("Incorrect Message Length")
            return

        did = (req[1] << 8) | req[2]
        data = bytes(req[3:])

        # Only allow writing program file DID in Programming/Extended sessions
        if did == 0xF1A0 and self.session in (config.SESSION_PROGRAMMING, config.SESSION_EXTENDED):
            self.ECU_PROGRAM_FILE = data

            # Persist write to disk
            with open(self.PROGRAM_FILE_PATH, "wb") as f:
                f.write(self.ECU_PROGRAM_FILE)

            # Positive response: 6E DID_H DID_L
            self._send(bytes([sid + 0x40, req[1], req[2]]), rxid)
        else:
            self._send_nrc(rxid, sid, 0x7E)
            print("Request Not Allowed In This Session (write)")

    # ==========================================================
    # SERVICE 0x31: ROUTINE CONTROL
    # ==========================================================
    def _routine_control(self, req, rxid):
        sid = req[0]

        # Must be at least: 31 <sub> RID_H RID_L
        if len(req) < 4:
            self._send_nrc(rxid, sid, 0x13)
            print("RoutineControl: Incorrect Message Length")
            return

        sub = req[1]
        rid = (req[2] << 8) | req[3]

        # ---------- RID 0x1234: Self Test ----------
        # Start (31 01): stores a simulated result
        # GetResults (31 03): returns stored result if exists
        if rid == 0x1234:
            if sub == 0x01:
                status = 0
                self.routine_results[rid] = {"RPM": 3000, "Speed": 80, "STATUS": status}
                print(f"[Body ECU] Routine 0x1234 Start: RPM=3000, Speed=80, Status={status}")
                self._send(bytes([sid + 0x40, 0x01, req[2], req[3], status]), rxid)

            elif sub == 0x03:
                if rid in self.routine_results:
                    res = self.routine_results[rid]
                    rpm = res["RPM"]
                    self._send(
                        bytes([
                            sid + 0x40, 0x03, req[2], req[3],
                            (rpm >> 8) & 0xFF, rpm & 0xFF,
                            res["Speed"], res["STATUS"]
                        ]),
                        rxid
                    )
                else:
                    self._send_nrc(rxid, sid, 0x22)
                    print("Routine 0x1234: Conditions Not Correct")
            else:
                self._send_nrc(rxid, sid, 0x12)
                print("Routine 0x1234: SubFunction Not Supported")
            return

        # ---------- RID 0x1456: Checksum ----------
        # Only allowed in Programming/Extended sessions
        # Start (31 01): calculates CRC32 over VIN + ECU program file
        # GetResults (31 03): returns CRC32 result if available
        if rid == 0x1456:
            if self.session not in (config.SESSION_PROGRAMMING, config.SESSION_EXTENDED):
                self._send_nrc(rxid, sid, 0x7E)
                print("Routine 0x1456: Request Not Allowed In This Session")
                return

            if sub == 0x01:
                chk = bytes(utils.vin_to_bytes(self.VIN)) + self.ECU_PROGRAM_FILE
                crc = zlib.crc32(chk) & 0xFFFFFFFF
                self.routine_results[rid] = {"CRC": crc, "STATUS": 0}
                print(f"[Body ECU] Routine 0x1456 Start: CRC32={crc:08X}")
                self._send(bytes([sid + 0x40, 0x01, req[2], req[3], 0]), rxid)

            elif sub == 0x03:
                if rid in self.routine_results:
                    crc = self.routine_results[rid]["CRC"]
                    self._send(
                        bytes([sid + 0x40, 0x03, req[2], req[3]]) +
                        crc.to_bytes(4, 'big') +
                        b'\x00',
                        rxid
                    )
                else:
                    self._send_nrc(rxid, sid, 0x22)
                    print("Routine 0x1456: Conditions Not Correct")
            else:
                self._send_nrc(rxid, sid, 0x12)
                print("Routine 0x1456: SubFunction Not Supported")
            return

        # Any other RID is treated as unsupported
        self._send_nrc(rxid, sid, 0x31)
        print(f"RoutineControl: RID 0x{rid:04X} Request Out Of Range")

    # ==========================================================
    # SERVICE 0x3E: TESTER PRESENT
    # ==========================================================
    def _tester_present(self, req, rxid):
        sid = req[0]

        # Must be exactly: 3E <sub>
        if len(req) != 2:
            self._send_nrc(rxid, sid, 0x13)
            print("TesterPresent: Incorrect Message Length")
            return

        # Only allowed when:
        # - S3 timer is running
        # - current session is Programming or Extended
        if (not self.s3_running) or (self.session not in (config.SESSION_PROGRAMMING, config.SESSION_EXTENDED)):
            self._send_nrc(rxid, sid, 0x7E)
            print("TesterPresent: Request Not Allowed (S3 not running or wrong session)")
            return

        # Reset S3 timer activity timestamp and reply positive
        self.s3.reset()
        self._send(bytes([sid + 0x40, req[1]]), rxid)
        print("TesterPresent: S3 timer reset")

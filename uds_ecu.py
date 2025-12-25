# uds_ecu.py
import time
import os
import zlib
import random
import config
import utils
from transport import tm
from s3_timer import S3Timer


class UDSHandler:
    def __init__(self):
        self.SEED_MIN = 0x00001000
        self.SEED_MAX = 0x00001FFF
        self.MAX_ERROR_COUNT = 3
        self.LOCKOUT_SECONDS = 30
        self.PROTECTED_MODE = False
        self.MITM_PROTECTION = False

        self.lockout_until = 0.0
        self.access_flag = 0
        self.error_num = 0
        self.session = config.SESSION_DEFAULT
        self.last_seed = None
        self.session_token = None

        self.s3_running = False
        self.routine_results = {}

        self.PROGRAM_FILE_PATH = "ecu_program.bin"
        if not os.path.exists(self.PROGRAM_FILE_PATH):
            with open(self.PROGRAM_FILE_PATH, "wb") as f: f.write(b"\x10\x20\x30\x40")
        with open(self.PROGRAM_FILE_PATH, "rb") as f: self.ECU_PROGRAM_FILE = f.read()

        self.s3 = S3Timer(
            send_tester_present_cb=lambda: print("[S3Timer] TesterPresent callback (no frame sent from ECU)"),
            expiry_callback=self._s3_expiry,
            s3_timeout=5, auto_tp=False, tp_lead=1.0
        )

        self.VIN = "WP0ZX41S100893123"

    def _s3_expiry(self):
        self.session = config.SESSION_DEFAULT
        self.s3_running = False
        self.routine_results.clear()
        print(f"session is {self.session}")
        print("[S3Timer] S3 expired → session returned to Default")

    def handle_request(self, req: bytes, rxid_used: int):
        # General logging for UDS requests
        print(f"[Body ECU] received request: 0x{rxid_used:03X} , {utils.pretty_hex(req)}")

        sid = req[0]
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
            self._send_nrc(rxid_used, sid, 0x11)
            print(f"Service 0x{sid:02X}: Service Not Supported")

    def _send(self, data, rxid):
        tm.send(data, config.ID_ECU_RESPONSE, rxid)
        print(f"[Body ECU] sending response: 0x{config.ID_ECU_RESPONSE:03X} , {utils.pretty_hex(data)}")

    def _send_nrc(self, rxid, sid, code):
        frame = utils.build_nrc(sid, code)
        self._send(frame, rxid)

    def _security_access(self, req, rxid):
        sid = req[0]
        if len(req) < 2:
            self._send_nrc(rxid, sid, 0x13)
            print("SecurityAccess: Incorrect Message Length")
            return
        sub = req[1]

        if self.PROTECTED_MODE and time.time() < self.lockout_until:
            self._send_nrc(rxid, sid, 0x33)
            print(f"[Body ECU] LOCKOUT ACTIVE until {self.lockout_until:.2f}, deny 0x27")
            return

        if sub == 0x01:  # Request Seed
            seed_int = random.randint(self.SEED_MIN, self.SEED_MAX)
            self.last_seed = seed_int.to_bytes(4, "big")
            self.session_token = None
            resp = bytes([sid + 0x40, sub]) + self.last_seed
            self._send(resp, rxid)
            print(f"SecurityAccess: Seed generated {self.last_seed.hex()}")
            return

        if sub == 0x02:  # Send Key
            if self.last_seed is None:
                self._send_nrc(rxid, sid, 0x22)
                print("SecurityAccess: No seed stored, conditions not correct")
                return
            if len(req) < 2 + len(self.last_seed):
                self._send_nrc(rxid, sid, 0x13)
                print("SecurityAccess: Key length incorrect")
                return

            key_rx = req[2:]
            key_ex = utils.seed_to_key(self.last_seed, self.PROTECTED_MODE)

            print(f"[Body ECU] SecurityAccess: received key {key_rx.hex()}, expected {key_ex.hex()}")

            if bytes(key_rx) == key_ex:
                self.access_flag = 1
                self.error_num = 0
                if self.PROTECTED_MODE: self.last_seed = None

                payload = bytes([sid + 0x40, sub])
                if self.MITM_PROTECTION:
                    self.session_token = config.SESSION_TOKEN_STATIC
                    payload += self.session_token
                    print(f"SecurityAccess: ACCESS GRANTED, session token={self.session_token.hex()}")
                else:
                    self.session_token = None
                    payload += key_ex
                    print("SecurityAccess: ACCESS GRANTED (no MITM protection)")
                self._send(payload, rxid)
            else:
                self.access_flag = 0
                if not self.PROTECTED_MODE:
                    self._send_nrc(rxid, sid, 0x35)
                    print("SecurityAccess: Invalid Key (no limit in unprotected mode)")
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

        self._send_nrc(rxid, sid, 0x12)
        print(f"SecurityAccess: SubFunction 0x{sub:02X} Not Supported")

    def _dsc(self, req, rxid):
        sid, sub = req[0], req[1]
        if sub == 0x01:
            self.session = config.SESSION_DEFAULT
            self.s3.stop()
            self.s3_running = False
            self._send(bytes([0x50, sub]), rxid)
            print("Default Session is on")
            return

        if sub in (0x02, 0x03):
            # Check MITM/Security
            allowed = False
            msg = ""
            if not self.MITM_PROTECTION:
                if self.access_flag == 1:
                    allowed = True
                else:
                    msg = "Security Access Denied (legacy DSC)"
            else:
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
                self.session = config.SESSION_PROGRAMMING if sub == 0x02 else config.SESSION_EXTENDED
                self._send(bytes([0x50, sub]), rxid)
                sess_name = "Programming" if sub == 0x02 else "Extended"
                print(f"{sess_name} Session is on")
                self.s3.start()
                self.s3_running = True
                print("[S3Timer] Started after successful Diagnostic Session")
            else:
                self._send(utils.build_nrc(sid, 0x33), rxid)
                print(msg)

    def _ecu_reset(self, req, rxid):
        sid = req[0]
        if self.access_flag != 1:
            self._send_nrc(rxid, sid, 0x33)
            print("ECU Reset blocked (Security Access Denied)")
            return
        if len(req) < 2:
            self._send_nrc(rxid, sid, 0x13)
            print("ECU Reset: Incorrect Message Length")
            return
        sub = req[1]
        if sub in (0x01, 0x03):
            self.access_flag = 0
            self.session = config.SESSION_DEFAULT
            self.s3.stop()
            self.s3_running = False
            self._send(bytes([sid + 0x40, sub]), rxid)
            print("ECU Reset is Done.")
        else:
            self._send_nrc(rxid, sid, 0x12)
            print("ECU Reset: SubFunction Not Supported")

    def _rdbi(self, req, rxid):
        sid = req[0]
        if len(req) != 3:
            self._send_nrc(rxid, sid, 0x13)
            print("Incorrect Message Length")
            return
        did = (req[1] << 8) | req[2]

        allowed = False
        if did in (0xF190, 0xF18C):
            if self.session in (config.SESSION_PROGRAMMING, config.SESSION_EXTENDED): allowed = True
        elif did == 0xF1A0:
            if self.session in (config.SESSION_DEFAULT, config.SESSION_PROGRAMMING,
                                config.SESSION_EXTENDED): allowed = True
        else:
            self._send_nrc(rxid, sid, 0x31)
            print("Request Out Of Range (unsupported DID)")
            return

        if not allowed:
            self._send_nrc(rxid, sid, 0x22)
            print("Conditions Not Correct")
            return

        data = b""
        if did == 0xF190:
            data = bytes(utils.vin_to_bytes(self.VIN))
        elif did == 0xF18C:
            data = b"SN1234567890"
        elif did == 0xF1A0:
            data = self.ECU_PROGRAM_FILE

        self._send(bytes([sid + 0x40, req[1], req[2]]) + data, rxid)

    def _wdbi(self, req, rxid):
        sid = req[0]
        if self.access_flag != 1:
            self._send_nrc(rxid, sid, 0x33)
            print("Request Not Allowed (Security Access Denied)")
            return
        if len(req) < 4:
            self._send_nrc(rxid, sid, 0x13)
            print("Incorrect Message Length")
            return
        did = (req[1] << 8) | req[2]
        data = bytes(req[3:])

        if did == 0xF1A0 and self.session in (config.SESSION_PROGRAMMING, config.SESSION_EXTENDED):
            self.ECU_PROGRAM_FILE = data
            with open(self.PROGRAM_FILE_PATH, "wb") as f:
                f.write(self.ECU_PROGRAM_FILE)
            self._send(bytes([sid + 0x40, req[1], req[2]]), rxid)
        else:
            self._send_nrc(rxid, sid, 0x7E)
            print("Request Not Allowed In This Session (write)")

    def _routine_control(self, req, rxid):
        sid = req[0]
        if len(req) < 4:
            self._send_nrc(rxid, sid, 0x13)
            print("RoutineControl: Incorrect Message Length")
            return
        sub = req[1]
        rid = (req[2] << 8) | req[3]

        if rid == 0x1234:  # Self Test
            if sub == 0x01:
                status = 0
                self.routine_results[rid] = {"RPM": 3000, "Speed": 80, "STATUS": status}
                print(f"[Body ECU] Routine 0x1234 Start: RPM=3000, Speed=80, Status={status}")
                self._send(bytes([sid + 0x40, 0x01, req[2], req[3], status]), rxid)
            elif sub == 0x03:
                if rid in self.routine_results:
                    res = self.routine_results[rid]
                    rpm = res["RPM"]
                    self._send(bytes(
                        [sid + 0x40, 0x03, req[2], req[3], (rpm >> 8) & 0xFF, rpm & 0xFF, res["Speed"], res["STATUS"]]),
                               rxid)
                else:
                    self._send_nrc(rxid, sid, 0x22)
                    print("Routine 0x1234: Conditions Not Correct")
            else:
                self._send_nrc(rxid, sid, 0x12)
                print("Routine 0x1234: SubFunction Not Supported")
            return

        if rid == 0x1456:  # Checksum
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
                    self._send(bytes([sid + 0x40, 0x03, req[2], req[3]]) + crc.to_bytes(4, 'big') + b'\x00', rxid)
                else:
                    self._send_nrc(rxid, sid, 0x22)
                    print("Routine 0x1456: Conditions Not Correct")
            else:
                self._send_nrc(rxid, sid, 0x12)
                print("Routine 0x1456: SubFunction Not Supported")
            return

        self._send_nrc(rxid, sid, 0x31)
        print(f"RoutineControl: RID 0x{rid:04X} Request Out Of Range")

    def _tester_present(self, req, rxid):
        sid = req[0]
        if len(req) != 2:
            self._send_nrc(rxid, sid, 0x13)
            print("TesterPresent: Incorrect Message Length")
            return
        if (not self.s3_running) or (self.session not in (config.SESSION_PROGRAMMING, config.SESSION_EXTENDED)):
            self._send_nrc(rxid, sid, 0x7E)
            print("TesterPresent: Request Not Allowed (S3 not running or wrong session)")
            return
        self.s3.reset()
        self._send(bytes([sid + 0x40, req[1]]), rxid)
        print("TesterPresent: S3 timer reset")
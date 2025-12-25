```python
# obd_ecu.py
import time                  # Used to add realistic ECU response delays
import config                # Holds CAN IDs and ECU-related configuration
import utils                 # Helper functions (hex formatting, VIN conversion)
from transport import tm     # Transport manager handling CAN / ISO-TP messaging


class OBDHandler:
    """
    Simulated OBD ECU handler.

    Purpose:
    Emulates basic ECU behavior for selected OBD modes and PIDs.
    Receives requests, validates them, and sends appropriate responses.
    """

    def __init__(self):
        # Fixed VIN returned for Mode 09 / PID 02 requests
        self.VIN = "WP0ZX41S100893123"

        # Simulated sensor values
        self.rpm_data = 6904           # Engine RPM (raw value before encoding)
        self.speed_data = 120          # Vehicle speed in km/h

        # Set of PIDs that this ECU claims to support
        self.VALID_PIDS = {0x02, 0x0C, 0x0D, 0x05, 0x0F, 0x11, 0x1F, 0x2F}

    def handle_request(self, req: bytes, rxid_used: int):
        """
        Entry point for handling incoming OBD requests.

        req : bytes
            Raw OBD request payload.
        rxid_used : int
            CAN ID used by the requester (tester).
        """
        mode = req[0]  # First byte always represents the OBD mode

        # Dispatch request based on OBD mode
        if mode == 0x09:
            self._handle_mode_09(req, rxid_used)
        elif mode == 0x01:
            self._handle_mode_01(req, rxid_used)

    def _handle_mode_09(self, req, rxid_used):
        """
        Handle OBD Mode 09 (Vehicle Information).

        Purpose:
        Responds mainly to VIN requests (PID 02).
        """
        pid = req[1]

        # ---------------- PID 02: VIN ----------------
        if pid == 0x02:
            print(f"[Body ECU] received request: 0x{rxid_used:03X} , {utils.pretty_hex(req)}")

            # Convert VIN string into byte sequence
            resp = bytes(utils.vin_to_bytes(self.VIN))

        # ---------------- Unsupported PID ----------------
        else:
            # Any unsupported PID returns a negative response
            if pid not in self.VALID_PIDS:
                resp = bytes([0x7F, req[0]])
            else:
                resp = bytes([0x7F, req[0]])

        # Send response back to requester
        print(f"[Body ECU] sending response: 0x{config.ID_ECU_RESPONSE:03X} , {utils.pretty_hex(resp)}")
        tm.send(resp, config.ID_ECU_RESPONSE, rxid_used)

        # Small delay to simulate ECU processing time
        time.sleep(0.05)

    def _handle_mode_01(self, req, rxid_used):
        """
        Handle OBD Mode 01 (Current Powertrain Data).

        Purpose:
        Responds to real-time sensor data requests such as RPM and speed.
        """
        # Extract all requested PIDs (Mode 01 may request multiple PIDs)
        pid_list = list(req[1:])

        print(f"[Engine ECU] received request: 0x{rxid_used:03X} , {utils.pretty_hex(req)}")

        for pid in pid_list:
            # ---------------- Unsupported PID ----------------
            if pid not in self.VALID_PIDS:
                resp = bytes([0x7F, req[0]])
                print(
                    f"[Engine ECU] NRC for PID {pid:02X}: "
                    f"0x{config.ID_ENGINE_RESPONSE:03X} , {utils.pretty_hex(resp)}"
                )
                tm.send(resp, config.ID_ENGINE_RESPONSE, rxid_used)
                time.sleep(0.05)
                continue

            user_data = []

            # ---------------- PID 0C: Engine RPM ----------------
            if pid == 0x0C:
                # OBD formula: RPM = ((A * 256) + B) / 4
                raw = self.rpm_data * 4
                user_data = [(raw >> 8) & 0xFF, raw & 0xFF]

            # ---------------- PID 0D: Vehicle Speed ----------------
            elif pid == 0x0D:
                # Speed is returned as a single byte in km/h
                user_data = [self.speed_data & 0xFF]

            # ---------------- Supported but not implemented ----------------
            else:
                resp = bytes([0x7F, req[0]])
                print(
                    f"[Engine ECU] NRC for PID {pid:02X}: "
                    f"0x{config.ID_ENGINE_RESPONSE:03X} , {utils.pretty_hex(resp)}"
                )
                tm.send(resp, config.ID_ENGINE_RESPONSE, rxid_used)
                time.sleep(0.05)
                continue

            # Build positive response: 0x41 = Mode 01 response
            resp = bytes([0x41, pid] + user_data)

            print(
                f"[Engine ECU] response for PID {pid:02X}: "
                f"0x{config.ID_ENGINE_RESPONSE:03X} , {utils.pretty_hex(resp)}"
            )
            tm.send(resp, config.ID_ENGINE_RESPONSE, rxid_used)
            time.sleep(0.05)

        # Final delay after processing all PIDs
        time.sleep(0.05)
```

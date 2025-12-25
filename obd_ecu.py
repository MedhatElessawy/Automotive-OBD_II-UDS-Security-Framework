# obd_ecu.py
import time
import config
import utils
from transport import tm


class OBDHandler:
    def __init__(self):
        self.VIN = "WP0ZX41S100893123"
        self.rpm_data = 6904
        self.speed_data = 120
        self.VALID_PIDS = {0x02, 0x0C, 0x0D, 0x05, 0x0F, 0x11, 0x1F, 0x2F}

    def handle_request(self, req: bytes, rxid_used: int):
        mode = req[0]
        if mode == 0x09:
            self._handle_mode_09(req, rxid_used)
        elif mode == 0x01:
            self._handle_mode_01(req, rxid_used)

    def _handle_mode_09(self, req, rxid_used):
        pid = req[1]
        # PID = 0x02 (VIN)
        if pid == 0x02:
            print(f"[Body ECU] received request: 0x{rxid_used:03X} , {utils.pretty_hex(req)}")
            resp = bytes(utils.vin_to_bytes(self.VIN))
        else:
            if pid not in self.VALID_PIDS:
                resp = bytes([0x7F, req[0]])
            else:
                resp = bytes([0x7F, req[0]])

        print(f"[Body ECU] sending response: 0x{config.ID_ECU_RESPONSE:03X} , {utils.pretty_hex(resp)}")
        tm.send(resp, config.ID_ECU_RESPONSE, rxid_used)
        time.sleep(0.05)

    def _handle_mode_01(self, req, rxid_used):
        pid_list = list(req[1:])
        print(f"[Engine ECU] received request: 0x{rxid_used:03X} , {utils.pretty_hex(req)}")

        for pid in pid_list:
            if pid not in self.VALID_PIDS:
                resp = bytes([0x7F, req[0]])
                print(
                    f"[Engine ECU] NRC for PID {pid:02X}: 0x{config.ID_ENGINE_RESPONSE:03X} , {utils.pretty_hex(resp)}")
                tm.send(resp, config.ID_ENGINE_RESPONSE, rxid_used)
                time.sleep(0.05)
                continue

            user_data = []
            if pid == 0x0C:
                raw = self.rpm_data * 4
                user_data = [(raw >> 8) & 0xFF, raw & 0xFF]
            elif pid == 0x0D:
                user_data = [self.speed_data & 0xFF]
            else:
                resp = bytes([0x7F, req[0]])
                print(
                    f"[Engine ECU] NRC for PID {pid:02X}: 0x{config.ID_ENGINE_RESPONSE:03X} , {utils.pretty_hex(resp)}")
                tm.send(resp, config.ID_ENGINE_RESPONSE, rxid_used)
                time.sleep(0.05)
                continue

            resp = bytes([0x41, pid] + user_data)
            print(
                f"[Engine ECU] response for PID {pid:02X}: 0x{config.ID_ENGINE_RESPONSE:03X} , {utils.pretty_hex(resp)}")
            tm.send(resp, config.ID_ENGINE_RESPONSE, rxid_used)
            time.sleep(0.05)
        time.sleep(0.05)
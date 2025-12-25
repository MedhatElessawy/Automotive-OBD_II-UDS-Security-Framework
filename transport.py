# transport.py
import can
import isotp
import time
from collections import deque
from typing import Dict, Tuple, Optional
import config


class TransportManager:
    def __init__(self):
        self.bus = can.Bus(channel=config.CAN_CHANNEL, interface=config.CAN_INTERFACE)
        self._rx_queues: Dict[int, deque] = {}
        self._stacks: Dict[Tuple[int, int], isotp.TransportLayer] = {}

    def txfn(self, iso_msg: isotp.CanMessage) -> None:
        msg = can.Message(arbitration_id=iso_msg.arbitration_id, data=iso_msg.data, dlc=iso_msg.dlc,
                          is_extended_id=False)
        self.bus.send(msg)

    def pump_bus(self, timeout: float = 0.0):
        msg = self.bus.recv(timeout=timeout)
        while msg is not None:
            if msg.arbitration_id in self._rx_queues:
                self._rx_queues[msg.arbitration_id].append(
                    isotp.CanMessage(arbitration_id=msg.arbitration_id, dlc=msg.dlc, data=msg.data)
                )
            msg = self.bus.recv(timeout=0.0)

    # === NEW FUNCTION HERE ===
    def clear_queues(self):
        """Drains all pending messages from the bus and clears internal queues."""
        # 1. Drain OS buffer
        while self.bus.recv(timeout=0.0) is not None:
            pass

        # 2. Clear internal python queues
        for q in self._rx_queues.values():
            q.clear()

        # 3. Reset ISO-TP stacks (optional but good for safety)
        for stack in self._stacks.values():
            stack.reset()

    # =========================

    def _make_rxfn(self, for_rxid: int):
        def _rxfn(timeout: float):
            end = time.time() + timeout
            while True:
                if self._rx_queues[for_rxid]: return self._rx_queues[for_rxid].popleft()
                if timeout <= 0 or time.time() >= end: return None
                time.sleep(0.001)

        return _rxfn

    def get_stack(self, txid: int, rxid: int) -> isotp.TransportLayer:
        key = (txid, rxid)
        if key in self._stacks: return self._stacks[key]
        if rxid not in self._rx_queues: self._rx_queues[rxid] = deque()

        addr = isotp.Address(isotp.AddressingMode.Normal_11bits, txid=txid, rxid=rxid)
        stack = isotp.TransportLayer(rxfn=self._make_rxfn(rxid), txfn=self.txfn, address=addr,
                                     params=config.DEFAULT_PARAMS)
        self._stacks[key] = stack
        return stack

    def send(self, data: bytes, txid: int, rxid: int):
        stack = self.get_stack(txid, rxid)
        stack.send(data)
        while stack.transmitting():
            self.pump_bus(timeout=0.01)
            stack.process()
            time.sleep(stack.sleep_time())

    def receive(self, txid: int, rxid: int, timeout: float = 0.0):
        stack = self.get_stack(txid, rxid)
        end = time.time() + timeout
        while True:
            self.pump_bus(timeout=0.01)
            stack.process()
            msg = stack.recv()
            if msg is not None: return msg
            if timeout <= 0 and time.time() >= end: pass
            if time.time() >= end: return None
            time.sleep(stack.sleep_time())

    def multi_receive(self, stacks, timeout=0.0):
        end = time.time() + timeout
        while True:
            self.pump_bus(timeout=0.01)
            for st in stacks:
                st.process()
                payload = st.recv()
                if payload is not None:
                    return payload, st.address.get_rx_arbitration_id()
            if time.time() >= end: return None, None
            time.sleep(0.01)


# Global Instance
tm = TransportManager()
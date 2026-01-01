# transport.py
import can                                  # python-can: raw CAN send/receive
import isotp                                # ISO-TP (ISO 15765-2): segmentation/reassembly over CAN
import time                                 # Timing for polling loops and timeouts
from collections import deque               # Efficient FIFO queues for received CAN frames per CAN ID
from typing import Dict, Tuple, Optional    # Type hints for internal dictionaries and keys
import config                               # CAN channel/interface and ISO-TP parameters


class TransportManager:
    """
    Transport layer abstraction for CAN + ISO-TP.

    Purpose:
    - Provide a single place to send/receive ISO-TP payloads.
    - Maintain per-RX-ID software queues for CAN frames.
    - Maintain reusable ISO-TP stacks keyed by (txid, rxid).
    - "Pump" the CAN bus to move frames from the OS/driver into python queues,
      then let ISO-TP stacks process those frames.

    Key idea:
    - python-can receives raw CAN frames (8 bytes).
    - isotp.TransportLayer needs a rxfn() that returns isotp.CanMessage objects.
    - This class adapts python-can messages into isotp.CanMessage and feeds them to stacks.
    """

    def __init__(self):
        # Create CAN bus interface (vcan0/socketcan or real CAN depending on config)
        self.bus = can.Bus(channel=config.CAN_CHANNEL, interface=config.CAN_INTERFACE)

        # Internal receive queues:
        # - Key: arbitration_id (rx CAN ID)
        # - Value: deque of isotp.CanMessage waiting to be consumed by ISO-TP stack
        self._rx_queues: Dict[int, deque] = {}

        # ISO-TP stacks cache:
        # - Key: (txid, rxid)
        # - Value: isotp.TransportLayer instance configured for that addressing pair
        self._stacks: Dict[Tuple[int, int], isotp.TransportLayer] = {}

    def txfn(self, iso_msg: isotp.CanMessage) -> None:
        """
        ISO-TP transmit function.
        Called by isotp.TransportLayer when it wants to send a CAN frame.

        iso_msg: isotp.CanMessage
            Contains arbitration_id, dlc, and data (the raw CAN frame).
        """
        # Convert isotp.CanMessage into python-can Message and send on bus
        msg = can.Message(
            arbitration_id=iso_msg.arbitration_id,
            data=iso_msg.data,
            dlc=iso_msg.dlc,
            is_extended_id=False
        )
        self.bus.send(msg)

    def pump_bus(self, timeout: float = 0.0):
        """
        Pull raw CAN frames from the CAN bus and push them into internal queues.

        Purpose:
        - Ensure ISO-TP stacks can later fetch frames via _make_rxfn().
        - Drain multiple frames quickly (loop until no frames are available).

        timeout:
        - Passed to bus.recv() for the first receive call.
        - Subsequent calls use timeout=0.0 to drain immediately.
        """
        msg = self.bus.recv(timeout=timeout)
        while msg is not None:
            # Only queue frames for RX IDs that have been registered in _rx_queues
            # (i.e., stacks were created for them)
            if msg.arbitration_id in self._rx_queues:
                self._rx_queues[msg.arbitration_id].append(
                    isotp.CanMessage(
                        arbitration_id=msg.arbitration_id,
                        dlc=msg.dlc,
                        data=msg.data
                    )
                )
            # Drain remaining frames without waiting
            msg = self.bus.recv(timeout=0.0)

    # === NEW FUNCTION HERE ===
    def clear_queues(self):
        """
        Drains all pending messages from the bus and clears internal queues.

        Purpose:
        Prevent stale/old frames from being mistakenly interpreted as responses
        to a newly sent request (common issue when multiple tools/scripts run).
        """
        # 1) Drain OS/driver receive buffer (python-can reads)
        while self.bus.recv(timeout=0.0) is not None:
            pass

        # 2) Clear in-memory per-ID queues used by ISO-TP stacks
        for q in self._rx_queues.values():
            q.clear()

        # 3) Reset ISO-TP stacks so partial state does not carry over
        # (e.g., half-received multi-frame message)
        for stack in self._stacks.values():
            stack.reset()

    # =========================

    def _make_rxfn(self, for_rxid: int):
        """
        Build an ISO-TP rxfn() function bound to a specific rx CAN ID.

        Purpose:
        isotp.TransportLayer expects rxfn(timeout) -> isotp.CanMessage or None.
        This closure reads from the internal deque for 'for_rxid'.

        for_rxid:
        - The CAN ID that this rxfn should consume.
        """
        def _rxfn(timeout: float):
            # Calculate when to stop waiting
            end = time.time() + timeout
            while True:
                # If queue has a frame, return it immediately
                if self._rx_queues[for_rxid]:
                    return self._rx_queues[for_rxid].popleft()

                # If no timeout or timeout expired, return None
                if timeout <= 0 or time.time() >= end:
                    return None

                # Small sleep to avoid busy-waiting at 100% CPU
                time.sleep(0.001)

        return _rxfn

    def get_stack(self, txid: int, rxid: int) -> isotp.TransportLayer:
        """
        Get (or create) an ISO-TP stack for a given (txid, rxid) pair.

        txid:
            CAN ID used to transmit frames.
        rxid:
            CAN ID expected for receiving frames.

        Returns:
            isotp.TransportLayer configured for Normal 11-bit addressing.
        """
        key = (txid, rxid)

        # Reuse stack if already created (avoids rebuilding state each send/receive)
        if key in self._stacks:
            return self._stacks[key]

        # Ensure a queue exists for the RX ID so pump_bus can enqueue frames
        if rxid not in self._rx_queues:
            self._rx_queues[rxid] = deque()

        # Create ISO-TP addressing (Normal 11-bit)
        addr = isotp.Address(isotp.AddressingMode.Normal_11bits, txid=txid, rxid=rxid)

        # Create transport layer with:
        # - rxfn: function that reads from the RX queue
        # - txfn: function that sends raw CAN frames
        # - params: ISO-TP timing/blocksize/etc from config
        stack = isotp.TransportLayer(
            rxfn=self._make_rxfn(rxid),
            txfn=self.txfn,
            address=addr,
            params=config.DEFAULT_PARAMS
        )

        # Cache and return
        self._stacks[key] = stack
        return stack

    def send(self, data: bytes, txid: int, rxid: int):
        """
        Send an ISO-TP payload and block until transmission completes.

        data:
            Full ISO-TP payload (UDS/OBD bytes).
        txid/rxid:
            Addressing pair for stack selection.
        """
        stack = self.get_stack(txid, rxid)
        stack.send(data)

        # Drive the ISO-TP state machine until the stack finishes transmitting
        while stack.transmitting():
            self.pump_bus(timeout=0.01)   # Pull any incoming frames (e.g., flow control)
            stack.process()               # Let ISO-TP handle segmentation/flow control
            time.sleep(stack.sleep_time())# Respect stack timing recommendations

    def receive(self, txid: int, rxid: int, timeout: float = 0.0):
        """
        Receive an ISO-TP payload.

        Behavior:
        - Continuously pumps the bus and processes the ISO-TP stack.
        - Returns the first complete ISO-TP message payload received.
        - Returns None on timeout.

        Note:
        timeout is overall receive timeout (seconds).
        """
        stack = self.get_stack(txid, rxid)
        end = time.time() + timeout

        while True:
            self.pump_bus(timeout=0.01)
            stack.process()

            # stack.recv() returns a complete ISO-TP payload (bytes) when available
            msg = stack.recv()
            if msg is not None:
                return msg

            # If timeout is expired, stop
            if timeout <= 0 and time.time() >= end:
                pass
            if time.time() >= end:
                return None

            time.sleep(stack.sleep_time())

    def multi_receive(self, stacks, timeout=0.0):
        """
        Receive from multiple ISO-TP stacks.

        Purpose:
        Listen on multiple addressing modes (e.g., functional + physical) and return
        the first message that arrives.

        Returns:
        - (payload, rx_arbitration_id) if a message is received
        - (None, None) if timeout expires
        """
        end = time.time() + timeout
        while True:
            self.pump_bus(timeout=0.01)

            for st in stacks:
                st.process()
                payload = st.recv()
                if payload is not None:
                    # Return payload + the RX CAN ID that received it
                    return payload, st.address.get_rx_arbitration_id()

            if time.time() >= end:
                return None, None

            time.sleep(0.01)


# Global Instance
# Purpose: Provide a single shared transport manager object across the project modules.
tm = TransportManager()

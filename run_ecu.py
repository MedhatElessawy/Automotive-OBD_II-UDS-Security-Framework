# run_ecu.py
from obd_server import OBDHandler      # Handles OBD requests (modes like 0x01, 0x09)
from uds_server import UDSHandler      # Handles UDS requests (everything else)
from transport import tm            # Transport manager: ISO-TP stacks + receive routing
import config                       # CAN IDs and addressing configuration

if __name__ == "__main__":
    # Create handler instances for each protocol type
    obd = OBDHandler()
    uds = UDSHandler()
    
    # ---------------- INITIALIZE ISO-TP STACKS ----------------
    # Purpose:
    # The ECU listens on more than one addressing type:
    # 1) Functional addressing: broadcast-style requests (tester → functional ID)
    # 2) Physical addressing: direct requests (tester → ECU physical ID)
    #
    # tm.get_stack(txid, rxid) prepares an ISO-TP stack instance that can receive
    # requests matching the rxid, and send responses using txid.
    #
    # Here:
    # - Responses go out using config.ID_ECU_RESPONSE (ECU response CAN ID)
    # - Requests come in on either:
    #   * config.ID_FUNCTIONAL (functional requests)
    #   * config.ID_ECU_PHYSICAL (physical requests)
    stack_func = tm.get_stack(config.ID_ECU_RESPONSE, config.ID_FUNCTIONAL)
    stack_phys = tm.get_stack(config.ID_ECU_RESPONSE, config.ID_ECU_PHYSICAL)
    stacks = [stack_func, stack_phys]
    
    print("ECU Running...")
    
    try:
        while True:
            # ---------------- WAIT FOR ANY REQUEST ----------------
            # Purpose:
            # Listen on both stacks (functional + physical) and return:
            # - req: the received payload bytes
            # - rxid: which CAN ID the request arrived on (used for replying correctly)
            #
            # timeout=5.0 means the loop wakes up even if no traffic exists,
            # instead of blocking forever.
            req, rxid = tm.multi_receive(stacks, timeout=5.0)
            if req is None:
                continue  # No request received within timeout
            
            # ---------------- ROUTER / DISPATCH LOGIC ----------------
            # Purpose:
            # Decide whether this request is OBD or UDS based on the first byte:
            # - OBD: first byte is the OBD mode (0x01, 0x09)
            # - UDS: service IDs are different (e.g., 0x10, 0x27, 0x22, etc.)
            #
            # This mimics older ecu.py behavior where the ECU routes requests
            # to the correct handler.
            if req[0] in [0x01, 0x09]:
                obd.handle_request(req, rxid)
            else:
                uds.handle_request(req, rxid)
                
    except KeyboardInterrupt:
        # Allow clean stop from Ctrl+C
        print("\nStopping...")

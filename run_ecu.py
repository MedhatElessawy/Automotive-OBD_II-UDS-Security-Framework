# run_ecu.py
from obd_ecu import OBDHandler
from uds_ecu import UDSHandler
from transport import tm
import config

if __name__ == "__main__":
    obd = OBDHandler()
    uds = UDSHandler()
    
    # Init stacks
    stack_func = tm.get_stack(config.ID_ECU_RESPONSE, config.ID_FUNCTIONAL)
    stack_phys = tm.get_stack(config.ID_ECU_RESPONSE, config.ID_ECU_PHYSICAL)
    stacks = [stack_func, stack_phys]
    
    print("ECU Running...")
    
    try:
        while True:
            req, rxid = tm.multi_receive(stacks, timeout=5.0)
            if req is None: continue
            
            # Router logic mimicking original ecu.py
            if req[0] in [0x01, 0x09]:
                obd.handle_request(req, rxid)
            else:
                uds.handle_request(req, rxid)
                
    except KeyboardInterrupt:
        print("\nStopping...")

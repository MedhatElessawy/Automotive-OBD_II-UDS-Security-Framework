# Automotive-OBD_II-UDS-Security-Framework

## Overview

This project provides a local automotive diagnostics and security testing lab built on top of python-can and ISO-TP.  
It simulates realistic ECU behavior, exposes common UDS/OBD services, and includes an interactive tester and attack framework for security experimentation.

The lab is designed for learning, testing, and demonstrating:
- Diagnostic workflows
- Session and security state handling
- Common automotive attack surfaces

---

## Architecture

### 1) Tester

#### OBD-II client
- Builds OBD requests by selecting CAN ID + Mode + PID(s)
- Supports Mode 0x01 (Show Current data) multi-PID querying and 0x09 (Request Vehicle Info.)
- Displays raw ECU replies and basic service validation (positive responses vs negative responses)
#### UDS client
- Sends raw UDS frames  exactly as a real tester would send service requests.
- Implements a complete **SecurityAccess (0x27)** exchange:
   - Sends seed request (27 01) to the physical ECU address
   - Computes the key locally using the same seed→key logic as the ECU (shared algorithm)
   - Sends key (27 02) and confirms whether access was granted or rejected
- Supports **TesterPresent (0x3E)** via hotkey (Ctrl+R) to keep sessions alive (S3 behavior), matching real-world keep-alive traffic
- If MITM protection is enabled on the lab ECU, the tester can store the returned token after SecurityAccess and append it automatically for protected session transitions (10 02 / 10 03)


### 2) ECU 

#### OBD-II SERVER
- Vehicle Information service (Mode 0x09), including VIN retrieval
- Live data service (Mode 0x01) with example PIDs such as engine RPM and vehicle speed (implementation-dependent)


#### UDS SERVER
- Diagnostic Session Control (0x10): Default, Extended, and Programming sessions
- SecurityAccess (0x27): seed/key authentication with configurable protection modes
- ECU Reset (0x11): restricted behind successful security access
- ReadDataByIdentifier (0x22): controlled access to identifiers such as VIN, serial number, and program image
- WriteDataByIdentifier (0x2E): persistent update of a simulated program image
- RoutineControl (0x31): example routines including self-test and checksum calculation
- TesterPresent (0x3E): session keep-alive with S3 timeout enforcement

#### Security Modes and Defensive Behavior for UDS

- **Protected mode**
  - Limits the number of incorrect SecurityAccess key attempts
  - Triggers a timed lockout window after repeated failures
  - Uses the protected seed→key validation path
  - (Optional) Requires a valid session token for sensitive session transitions to emulate MITM-resistant workflows

- **Unprotected mode**
  - Allows unlimited SecurityAccess attempts (no lockout)
  - Uses a simplified seed→key validation path intended for lab attacks and analysis
  - Does not require a session token for session transitions
  - Represents a deliberately weak configuration for educational testing



### 3) Attacker

The project includes a menu-driven offensive lab that demonstrates common attack techniques against OBD-II and UDS diagnostic services over ISO-TP.

#### OBD-II Attacks

- **PID Enumeration**
  - Systematically queries supported Parameter IDs for a given OBD mode.
  - Used to identify which live data points are exposed by the ECU.

- **Denial-of-Service (DoS) Simulation**
  - Sends a high rate of diagnostic requests to overwhelm the ECU.
  - Demonstrates how excessive traffic can degrade or disrupt diagnostic responsiveness.

- **Replay Attack**
  - Captures valid ECU responses during normal operation.
  - Re-injects previously observed messages to demonstrate trust-based weaknesses in OBD communication.

#### UDS Attacks

- **DID / RID Enumeration**
  - Probes Data Identifiers using ReadDataByIdentifier (0x22).
  - Probes Routine Identifiers using RoutineControl (0x31).
  - Identifies accessible, restricted, and unsupported services.

- **Man-in-the-Middle (MITM) Session Manipulation**
  - Observes successful SecurityAccess authentication.
  - Forces diagnostic session transitions and maintains session validity using TesterPresent messages.

- **Seed-Based Brute Force (SecurityAccess)**
  - Repeatedly attempts key values for SecurityAccess (0x27).
  - Demonstrates the impact of weak seed–key algorithms and missing lockout mechanisms.

- **Seed–Key Algorithm Analysis**
  - Collects multiple seed/key pairs from the ECU.
  - Applies simple arithmetic and logical transformations to infer the key derivation logic.

- **ECU Reset Spamming**
  - Sends repeated ECUReset (0x11) requests.
  - Demonstrates a diagnostic-based denial-of-service condition.

### 4) ISO-TP Transport Layer
Provides a reusable ISO-TP communication layer that works with **any TX/RX arbitration-ID pair**
- The same functions can be used for **physical addressing** (one ECU) or **functional addressing** (broadcast-style request) by simply selecting different CAN IDs in the caller
- No code changes are required when switching between addresses; only TX/RX IDs change
#### Transport Layer Design and Responsibilities
- **`get_stack(txid, rxid)`**
  - Creates (or reuses) an ISO-TP stack bound to a specific `(txid, rxid)` pair
  - Internally builds an ISO-TP `Address(Normal_11bits, txid=..., rxid=...)`
  - Why needed: ISO-TP state is per link (per TX/RX pair). Reusing stacks avoids reinitializing state every request.

- **`pump_bus(timeout=...)`**
  - Reads raw CAN frames from the bus and routes them into the correct RX queue by arbitration ID
  - Why needed: ISO-TP stacks don’t “see” the CAN bus automatically; they need frames delivered to their `rxfn`.

- **`_make_rxfn(rxid)`**
  - Returns a per-RXID receive function that pulls frames from that RXID queue with a timeout
  - Why needed: each ISO-TP stack must receive only frames intended for its RX arbitration ID.

- **`send(data, txid, rxid)`**
  - Sends a full diagnostic payload and handles ISO-TP transmission until complete
  - Implementation detail:
    - `stack.send(data)` queues payload into ISO-TP
    - Loop while `stack.transmitting()`:
      - `pump_bus()` to keep receiving flow-control frames / traffic
      - `stack.process()` to advance ISO-TP state machine
      - `sleep(stack.sleep_time())` to respect ISO-TP timing
  - Why needed: without processing + pumping, multi-frame sends will stall or violate timing.

- **`receive(txid, rxid, timeout=...)`**
  - Processes the ISO-TP stack until a complete payload is reassembled or timeout occurs
  - Why needed: responses may be multi-frame; this abstracts reassembly into a single call.

- **`multi_receive(stacks, timeout=...)`**
  - Waits for a payload from any stack in a provided list, returning both payload and the RX arbitration ID
  - Why needed: one request may produce multiple replies (especially when scanning or when multiple ECUs respond).

- **`clear_queues()`**
  - Drains OS-level CAN receive buffer, clears internal queues, and resets ISO-TP stacks
  - Why needed: prevents stale frames from previous operations from being misinterpreted as the current response (common issue during fast enumeration/attacks).
---

## Key Features
- Realistic OBD-II and UDS diagnostic behavior modeled on real ECU workflows
- ISO-TP abstraction layer for clean CAN communication
- Shared seed-key algorithm between tester and ECU
- Session-aware access control
- Lockout and timing behavior similar to real ECUs
- Modular attack menu for security testing
- Fully local lab using virtual CAN (vcan)

---

## Requirements

- Python 3
- Linux system with virtual CAN support
- Dependencies:
  - python-can
  - isotp
  - keyboard

---

## Setup

```bash
# 1) Create virtual CAN interface 
sudo modprobe vcan 
sudo ip link add dev vcan0 type vcan 
sudo ip link set up vcan0

# 2) Activate virtual environment
#It is recommended to run the project inside a Python virtual environment to isolate dependencies.
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3) Start the ECU (Terminal 1)
# Runs inside the same virtual environment
python3 run_ecu.py

# 4) Run Tester (Terminal 2)
#The tester uses global keyboard shortcuts implemented via the keyboard library.
#On Linux systems, capturing global keyboard events requires elevated privileges.
#For this reason, the project may need to be executed using sudo -E to preserve the active virtual environment while running with elevated permissions.
sudo -E /path/to/venv/bin/python3 tester.py


# 5) Run attacker menu (Terminal 3)
# Runs inside the same virtual environment
python3 unified_attacks.py 

# 6) Run CanDump (Terminal 4) 
candump vcan0
```
## License

This project is for educational and research purposes only. Use responsibly in controlled lab environments

## Disclaimer

This project is intended strictly for educational, research, and laboratory use.

Do not use this software against real vehicles, production ECUs, or automotive systems without explicit authorization.  


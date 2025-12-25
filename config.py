# config.py
CAN_CHANNEL = 'vcan0'
CAN_INTERFACE = 'socketcan'

# IDs
ID_FUNCTIONAL      = 0x7DF
ID_ECU_PHYSICAL    = 0x7E0
ID_ECU_RESPONSE    = 0x7E8
ID_ENGINE_PHYSICAL = 0x7E0
ID_ENGINE_RESPONSE = 0x7E8

# Security Constants
SECRET_KEY    = b"\x93\x11\xfa...\x8b"
SEED_CONSTANT = b"\x11\x22\x33\x44"
SESSION_TOKEN_STATIC = b"\xAA\xBB\xCC\xDD"

# UDS Constants
SESSION_DEFAULT      = 0x100
SESSION_PROGRAMMING  = 0x200
SESSION_EXTENDED     = 0x300

SID_DIAGNOSTIC_SESSION_CONTROL = 0x10
SID_ECU_RESET                  = 0x11
SID_READ_DATA_BY_ID            = 0x22
SID_SECURITY_ACCESS            = 0x27
SID_WRITE_DATA_BY_ID           = 0x2E
SID_ROUTINE_CONTROL            = 0x31
SID_TESTER_PRESENT             = 0x3E

# ISO-TP Defaults
DEFAULT_PARAMS = {
    "tx_padding": 0x55,
    "tx_data_length": 8,
    "tx_data_min_length": 8,
}

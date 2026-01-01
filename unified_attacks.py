import obd_attacks      # Module containing OBD attack functions (PID scan, DoS, replay)
import uds_attacks      # Module containing UDS attack functions (DID/RID scan, MITM, brute force, etc.)

# ---------------- Main menu loop ----------------
# Purpose:
# Provide a simple CLI menu to run different attack scenarios.
# This loop runs forever until the user stops the program (Ctrl+C).
while True:
    # -------- Top-level menu --------
    print("\n=== Attacks Menu ===")
    print("1) OBD")
    print("2) UDS")

    # Read the user's selection (string to avoid crashes on non-numeric input)
    choice = input("Select option: ").strip()

    # ==========================================================
    # OBD ATTACKS MENU
    # ==========================================================
    if choice == "1":
        print("\n=== OBD Attacks Menu ===")
        print("1) PID Enumerations")   # Brute-force PIDs and print supported ones
        print("2) DoS Attack")         # Flood ECU with repeated frames
        print("3) Replay Attack")      # Sniff traffic then replay ECU frames

        choice_2 = input("Select option: ").strip()

        # 1) PID enumeration
        if choice_2 == "1":
            obd_attacks.PID_ENUMERATIONS()

        # 2) DoS
        elif choice_2 == "2":
            # Duration is required because the DoS loop runs until time expires
            duration = int(input("Attack duration (seconds): "))
            obd_attacks.OBD_DOS(duration_seconds=duration)

        # 3) Sniff + Replay
        elif choice_2 == "3":
            # Sniff duration determines how long frames are captured before replay
            duration = int(input("Sniff duration (seconds): "))
            obd_attacks.OBD_SNIFF_AND_REPLAY(duration_seconds=duration)

    # ==========================================================
    # UDS ATTACKS MENU
    # ==========================================================
    elif choice == "2":
        print("\n=== UDS Attacks Menu ===")
        print("1) DID/RID Enumerations")                # Enumerate ReadDID + RoutineControl IDs
        print("2) MITM")                                # Observe 67 02 then enter session + keep alive
        print("3) Seed Based Brute Force")              # Brute-force SecurityAccess key
        print("4) Seed-Key Algorithm Reverse Engineering") # Infer simple seed->key relationship
        print("5) Reset ECU Spamming")                  # Flood ECUReset requests

        choice_2 = input("Select option: ").strip()

        # 1) DID/RID scan
        if choice_2 == "1":
            uds_attacks.UDS_ENUMERATE_DIDS_AND_RIDS()

        # 2) MITM
        elif choice_2 == "2":
            uds_attacks.MITM_ATTACK()

        # 3) Brute force key
        elif choice_2 == "3":
            uds_attacks.BRUTE_FORCE_ATTACK()

        # 4) Reverse engineer seed->key
        elif choice_2 == "4":
            uds_attacks.REVERSE_ENGINEERING_ATTACK()

        # 5) Reset spam
        elif choice_2 == "5":
            duration = int(input("Attack duration (seconds): "))
            uds_attacks.RESER_ECU_SPAMMING(duration_seconds=duration)

    # Anything else: ignore and reprint menu
    else:
        pass

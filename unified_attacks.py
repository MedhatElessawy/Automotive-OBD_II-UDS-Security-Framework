import obd_attacks
import uds_attacks

# ---------------- Main menu loop ----------------
while True:
    print("\n=== Attacks Menu ===")
    print("1) OBD")
    print("2) UDS")
    choice = input("Select option: ").strip()
    if choice == "1":
        print("\n=== OBD Attacks Menu ===")
        print("1) PID Enumerations")
        print("2) DoS Attack")
        print("3) Replay Attack")

        choice_2 = input("Select option: ").strip()
        if choice_2 == "1":
            obd_attacks.PID_ENUMERATIONS()
        elif choice_2 == "2":
            duration = int(input("Attack duration (seconds): "))
            obd_attacks.OBD_DOS(duration_seconds=duration)
        elif choice_2 == "3":
            duration = int(input("Sniff duration (seconds): "))
            obd_attacks.OBD_SNIFF_AND_REPLAY(duration_seconds=duration)
    elif choice == "2":
        print("\n=== UDS Attacks Menu ===")
        print("1) DID/RID Enumerations")
        print("2) MITM")
        print("3) Seed Based Brute Force")
        print("4) Seed-Key Algorithm Reverse Engineering")
        print("5) Reset ECU Spamming")
        choice_2 = input("Select option: ").strip()
        if choice_2 == "1":
            uds_attacks.UDS_ENUMERATE_DIDS_AND_RIDS()
        elif choice_2 == "2":
            uds_attacks.MITM_ATTACK()
        elif choice_2 == "3":
            uds_attacks.BRUTE_FORCE_ATTACK()
        elif choice_2 == "4":
            uds_attacks.REVERSE_ENGINEERING_ATTACK()
        elif choice_2 == "5":
            duration = int(input("Attack duration (seconds): "))
            uds_attacks.RESER_ECU_SPAMMING(duration_seconds=duration)
    else:
        pass
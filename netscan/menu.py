import questionary
import sys
import subprocess


def main_menu():
    while True:
        choice = questionary.select(
            "NetScan Main Menu",
            choices=[
                "Scan",
                "Report",
                "Config",
                "Database",
                "Exit"
            ]
        ).ask()
        if choice == "Scan":
            scan_menu()
        elif choice == "Report":
            report_menu()
        elif choice == "Config":
            config_menu()
        elif choice == "Database":
            database_menu()
        elif choice == "Exit":
            print("Goodbye!")
            sys.exit(0)


def scan_menu():
    choice = questionary.select(
        "Scan Menu",
        choices=[
            "Full Scan (Recommended)",
            "Network Scan",
            "Auth Test",
            "System Info",
            "Back"
        ]
    ).ask()
    if choice == "Full Scan (Recommended)":
        print("[Not implemented yet] Would run: netscan scan full ...")
    elif choice == "Network Scan":
        print("[Not implemented yet] Would run: netscan scan network ...")
    elif choice == "Auth Test":
        print("[Not implemented yet] Would run: netscan scan auth ...")
    elif choice == "System Info":
        print("[Not implemented yet] Would run: netscan scan info ...")
    elif choice == "Back":
        return
    input("Press Enter to return to the main menu...")


def report_menu():
    choice = questionary.select(
        "Report Menu",
        choices=[
            "Host Report",
            "Summary",
            "Export",
            "History",
            "Back"
        ]
    ).ask()
    print(f"[Not implemented yet] Would run: netscan report {choice.lower()} ...")
    input("Press Enter to return to the main menu...")


def config_menu():
    choice = questionary.select(
        "Config Menu",
        choices=[
            "Show Config",
            "Set Credentials",
            "Set Scanning Options",
            "Back"
        ]
    ).ask()
    print(f"[Not implemented yet] Would run: netscan config ...")
    input("Press Enter to return to the main menu...")


def database_menu():
    choice = questionary.select(
        "Database Menu",
        choices=[
            "Init",
            "Backup",
            "Restore",
            "Back"
        ]
    ).ask()
    print(f"[Not implemented yet] Would run: netscan database {choice.lower()} ...")
    input("Press Enter to return to the main menu...")


if __name__ == "__main__":
    main_menu() 
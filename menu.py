import subprocess
import sys

def menu():
    while True:
        print("\n=== Secure Messaging App Menu ===")
        print("1. Launch GUI")
        print("2. Start Server (CLI)")
        print("3. Start Client (CLI)")
        print("4. Run Unit Tests")
        print("5. Exit")

        choice = input("Choose an option (1-5): ").strip()

        if choice == "1":
            subprocess.run([sys.executable, "main.py"])
        elif choice == "2":
            subprocess.run([sys.executable, "server.py"])
        elif choice == "3":
            subprocess.run([sys.executable, "client.py"])
        elif choice == "4":
            subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"])
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    menu()

import os

def main_menu():
    while True:
        print("\n🔐 Secure Messaging App")
        print("1. Start Server")
        print("2. Start Client")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == '1':
            os.system("python server.py")
        elif choice == '2':
            os.system("python client.py")
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid input. Please try again.")

if __name__ == "__main__":
    main_menu()

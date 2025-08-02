import socket
import threading

clients = []

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    clients.append(conn)
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[{addr}] {data.decode()}")
        except:
            break
    conn.close()
    clients.remove(conn)
    print(f"[-] Connection closed: {addr}")

def broadcast_messages():
    while True:
        msg = input("Server: ")
        for client in clients:
            try:
                client.sendall(f"[Server] {msg}".encode())
            except:
                pass  # Handle broken connections gracefully

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))
    server.listen()
    print("[*] Server listening on port 9999")

    threading.Thread(target=broadcast_messages, daemon=True).start()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
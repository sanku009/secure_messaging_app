import socket
import threading

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[{addr}] {data.decode()}")
            conn.sendall(data)  # Echo or process securely
        except:
            break
    conn.close()
    print(f"[-] Connection closed: {addr}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))
    server.listen()
    print("[*] Server listening on port 9999")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
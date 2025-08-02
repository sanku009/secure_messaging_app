import socket
import threading

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(1024)
            if data:
                print(f"\n[Server] {data.decode()}")
        except:
            break

def send_messages(sock):
    while True:
        msg = input("You: ")
        sock.sendall(msg.encode())

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 9999))

    recv_thread = threading.Thread(target=receive_messages, args=(client,))
    send_thread = threading.Thread(target=send_messages, args=(client,))
    recv_thread.start()
    send_thread.start()

if __name__ == "__main__":
    start_client()
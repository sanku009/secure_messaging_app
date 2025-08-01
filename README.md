# Secure Messaging App

This is a secure messaging application that supports both GUI and real-time encrypted chat using AES. It features a custom queue data structure for message buffering.

## Features
- AES-256 EAX-mode encryption
- Custom message queue using linked list
- GUI interface using Tkinter
- Real-time socket-based encrypted communication (client-server)
- Unit tests for encryption and queue

## Usage
### GUI Mode
```bash
python main.py
```

### Real-Time Chat
#### Terminal 1 (Server):
```bash
python server.py
```

#### Terminal 2 (Client):
```bash
python client.py
```

## Dependencies
Install with:
```bash
pip install -r requirements.txt
```

## License
MIT

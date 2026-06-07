import socket
import struct
import threading
import time
import sys
from qihse.core import VectorDB, _lib

def run_db():
    db = VectorDB.create(":memory:", 128)
    _lib.qihse_start_pg_wire_server(db._ptr, 15432, b"127.0.0.1")
    while True:
        time.sleep(1)

def test_pg_wire():
    print("Connecting to PG Wire server...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("127.0.0.1", 15432))
    except ConnectionRefusedError:
        print("Could not connect. Is server running?")
        sys.exit(1)

    # Startup message
    # length (4) + version (4) + "user\0test\0database\0test\0\0"
    payload = struct.pack("!i", 196608) # Protocol 3.0
    payload += b"user\0test\0database\0test\0\0"
    length = 4 + len(payload)
    s.sendall(struct.pack("!i", length) + payload)
    
    # Receive AuthenticationOk (R)
    type_code = s.recv(1)
    if type_code == b'R':
        print("Received AuthOk!")
    else:
        print("Failed to authenticate")
        return

    # Wait for ReadyForQuery (Z)
    while True:
        data = s.recv(1)
        if data == b'Z':
            print("Ready for Query!")
            break
        elif data == b'S' or data == b'K':
            s.recv(4) # read length
            # wait for Z

    # Send Simple Query (Q)
    query = b"SELECT * FROM test;\0"
    length = 4 + len(query)
    s.sendall(b'Q' + struct.pack("!i", length) + query)
    
    print("Sent query, waiting for response...")
    while True:
        data = s.recv(1)
        if not data:
            break
        print(f"Received msg type: {data}")
        if data == b'C': # CommandComplete
            print("Command Complete!")
        elif data == b'Z':
            print("Ready For Query! Test passed.")
            break

if __name__ == "__main__":
    t = threading.Thread(target=run_db, daemon=True)
    t.start()
    time.sleep(1)
    test_pg_wire()

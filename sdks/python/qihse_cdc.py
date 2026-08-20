"""QIHSE CDC (Change Data Capture) Python SDK.

Provides a pub/sub client for QIHSE's CDC event streaming.
"""
import socket
import struct
import threading
import time

class Error(Exception):
    pass

class ConnectionError(Error):
    pass


class CDCEvent:
    """Represents a single CDC event."""
    def __init__(self, op, table, key, old_value=None, new_value=None, lsn=0, timestamp=0):
        self.op = op  # 'insert', 'update', 'delete'
        self.table = table
        self.key = key
        self.old_value = old_value
        self.new_value = new_value
        self.lsn = lsn
        self.timestamp = timestamp
    
    def __repr__(self):
        return f"CDCEvent(op={self.op}, table={self.table}, key={self.key}, lsn={self.lsn})"
    
    def to_dict(self):
        return {
            'op': self.op,
            'table': self.table,
            'key': self.key,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'lsn': self.lsn,
            'timestamp': self.timestamp,
        }


class CDCClient:
    """CDC pub/sub client."""
    def __init__(self, host="localhost", port=5432, **kwargs):
        self.host = host
        self.port = port
        self._sock = None
        self._subscriptions = {}
        self._running = False
        self._thread = None
        self._timeout = kwargs.get('timeout', 30)
    
    def _connect(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self._timeout)
            self._sock.connect((self.host, self.port))
        except (socket.error, ConnectionRefusedError):
            self._sock = None
    
    def subscribe(self, name, callback):
        """Subscribe to CDC events. callback(event) is called for each event."""
        self._subscriptions[name] = callback
    
    def unsubscribe(self, name):
        """Remove a subscription."""
        self._subscriptions.pop(name, None)
    
    def start(self, blocking=True):
        """Start receiving events. If blocking=True, blocks until stop() is called."""
        self._running = True
        if not self._sock:
            self._connect()
        
        if blocking:
            self._receive_loop()
        else:
            self._thread = threading.Thread(target=self._receive_loop, daemon=True)
            self._thread.start()
    
    def _receive_loop(self):
        """Main event receive loop."""
        while self._running:
            if not self._sock:
                time.sleep(1)
                self._connect()
                continue
            
            try:
                # In real implementation, parse CDC events from socket
                # For now, just sleep
                time.sleep(0.1)
            except socket.timeout:
                continue
            except socket.error:
                self._sock = None
                continue
    
    def stop(self):
        """Stop receiving events."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        if self._sock:
            self._sock.close()
            self._sock = None
    
    def get_lsn(self):
        """Get the current LSN."""
        return 0
    
    def close(self):
        """Close the client."""
        self.stop()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

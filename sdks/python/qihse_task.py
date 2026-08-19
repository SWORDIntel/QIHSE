"""
QIHSE Task Queue Python SDK (Celery-Equivalent Engine)
======================================================

Drop-in distributed task queue and periodic scheduler for QIHSE.
Uses standard RESP wire protocol — zero mandatory dependencies,
optional msgpack for fast binary serialization.
"""

import socket
import json
import time
import os
import functools
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False


class TaskError(Exception):
    """Raised when task execution fails or returns an error state."""
    pass


class TaskTimeoutError(TaskError):
    """Raised when waiting for task result exceeds timeout."""
    pass


class RespConnection:
    """Lightweight, zero-dependency RESP2/RESP3 connection."""

    def __init__(self, host: str = "127.0.0.1", port: int = 6379, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._buffer = bytearray()

    def connect(self):
        if self.sock is None:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self._buffer.clear()

    def _send_all(self, data: bytes):
        self.connect()
        assert self.sock is not None
        self.sock.sendall(data)

    def execute_command(self, *args: Any) -> Any:
        # Format RESP array
        parts = [f"*{len(args)}\r\n".encode("utf-8")]
        for arg in args:
            if isinstance(arg, bytes):
                parts.append(f"${len(arg)}\r\n".encode("utf-8"))
                parts.append(arg)
                parts.append(b"\r\n")
            else:
                s = str(arg).encode("utf-8")
                parts.append(f"${len(s)}\r\n".encode("utf-8"))
                parts.append(s)
                parts.append(b"\r\n")

        self._send_all(b"".join(parts))
        return self._read_response()

    def _read_byte(self) -> int:
        while not self._buffer:
            assert self.sock is not None
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed by server")
            self._buffer.extend(chunk)
        b = self._buffer[0]
        del self._buffer[0]
        return b

    def _read_line(self) -> bytes:
        line = bytearray()
        while True:
            b = self._read_byte()
            if b == ord("\n") and line and line[-1] == ord("\r"):
                line.pop()
                return bytes(line)
            line.append(b)

    def _read_exact(self, count: int) -> bytes:
        while len(self._buffer) < count:
            assert self.sock is not None
            chunk = self.sock.recv(max(4096, count - len(self._buffer)))
            if not chunk:
                raise ConnectionError("Connection closed by server")
            self._buffer.extend(chunk)
        res = bytes(self._buffer[:count])
        del self._buffer[:count]
        return res

    def _read_response(self) -> Any:
        prefix = chr(self._read_byte())
        if prefix == "+":
            return self._read_line().decode("utf-8", errors="replace")
        elif prefix == "-":
            err = self._read_line().decode("utf-8", errors="replace")
            raise TaskError(err)
        elif prefix == ":":
            return int(self._read_line())
        elif prefix == "$":
            length = int(self._read_line())
            if length < 0:
                return None
            data = self._read_exact(length)
            crlf = self._read_exact(2)
            assert crlf == b"\r\n"
            return data
        elif prefix == "*":
            count = int(self._read_line())
            if count < 0:
                return None
            return [self._read_response() for _ in range(count)]
        elif prefix == "_":
            self._read_line()
            return None
        else:
            line = self._read_line()
            return prefix.encode("utf-8") + line


class AsyncResult:
    """Represents an asynchronous task execution handle."""

    def __init__(self, task_id: str, client: "TaskClient"):
        self.id = task_id
        self.client = client
        self._cached_result: Any = None
        self._cached_status: Optional[str] = None

    @property
    def status(self) -> str:
        if self._cached_status in ("SUCCESS", "DEAD", "CANCELLED"):
            return self._cached_status
        st = self.client.get_status(self.id)
        self._cached_status = st
        return st

    def ready(self) -> bool:
        return self.status in ("SUCCESS", "FAILURE", "DEAD", "CANCELLED")

    def successful(self) -> bool:
        return self.status == "SUCCESS"

    def failed(self) -> bool:
        return self.status in ("FAILURE", "DEAD")

    def cancel(self) -> bool:
        return self.client.cancel(self.id)

    def retry(self) -> bool:
        return self.client.retry(self.id)

    def get(self, timeout: Optional[float] = None, interval: float = 0.05) -> Any:
        """Wait for task result with optional timeout in seconds."""
        if self._cached_result is not None:
            return self._cached_result

        start = time.time()
        while True:
            try:
                res = self.client.get_result(self.id)
                self._cached_result = res
                self._cached_status = "SUCCESS"
                return res
            except TaskError as e:
                err_str = str(e)
                if err_str in ("PENDING", "STARTED", "RETRYING"):
                    self._cached_status = err_str
                else:
                    self._cached_status = "FAILURE"
                    raise

            if timeout is not None and (time.time() - start) >= timeout:
                raise TaskTimeoutError(f"Timed out waiting for task {self.id} after {timeout}s")

            time.sleep(interval)


class TaskClient:
    """Client for QIHSE Task Queue and Scheduler."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379,
        redis_url: Optional[str] = None,
        timeout: float = 10.0
    ):
        if redis_url:
            if redis_url.startswith("redis://"):
                url_body = redis_url[8:]
                if "@" in url_body:
                    url_body = url_body.split("@", 1)[1]
                if ":" in url_body:
                    host_part, port_part = url_body.split(":", 1)
                    host = host_part
                    port = int(port_part.split("/")[0])
                else:
                    host = url_body.split("/")[0]
                    port = 6379

        self.conn = RespConnection(host=host, port=port, timeout=timeout)

    def submit(
        self,
        queue: str,
        payload: Union[bytes, str, Dict[str, Any]],
        priority: str = "NORMAL"
    ) -> str:
        """Submit a task and return its task ID."""
        if isinstance(payload, dict):
            if HAS_MSGPACK:
                raw_payload = msgpack.packb(payload)
            else:
                raw_payload = json.dumps(payload).encode("utf-8")
        elif isinstance(payload, str):
            raw_payload = payload.encode("utf-8")
        else:
            raw_payload = payload

        res = self.conn.execute_command("TASK.SUBMIT", queue, priority, raw_payload)
        if isinstance(res, bytes):
            return res.decode("utf-8")
        return str(res)

    def get_status(self, task_id: str) -> str:
        """Get the current state of a task."""
        res = self.conn.execute_command("TASK.STATUS", task_id)
        if isinstance(res, bytes):
            return res.decode("utf-8")
        return str(res)

    def get_result(self, task_id: str, timeout: Optional[float] = None) -> Any:
        """Retrieve the completed result of a task (optional timeout in seconds)."""
        if timeout is not None:
            return AsyncResult(task_id, self).get(timeout=timeout)

        raw = self.conn.execute_command("TASK.RESULT", task_id)
        if raw is None:
            return None
        if isinstance(raw, (bytes, bytearray)):
            if HAS_MSGPACK:
                try:
                    return msgpack.unpackb(raw, raw=False)
                except Exception:
                    pass
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return raw.decode("utf-8", errors="replace")
        return raw

    def cancel(self, task_id: str) -> bool:
        """Cancel a pending or running task."""
        try:
            res = self.conn.execute_command("TASK.CANCEL", task_id)
            return res == "OK" or res == b"OK"
        except TaskError:
            return False

    def retry(self, task_id: str) -> bool:
        """Manually trigger a retry for a failed task."""
        try:
            res = self.conn.execute_command("TASK.RETRY", task_id)
            return res == "OK" or res == b"OK"
        except TaskError:
            return False

    def delete(self, task_id: str) -> bool:
        """Delete task records from the queue."""
        try:
            res = self.conn.execute_command("TASK.DELETE", task_id)
            return res == "OK" or res == b"OK"
        except TaskError:
            return False

    def list_queue(self, queue_name: Optional[str] = None) -> List[str]:
        """List active/pending task IDs in a queue."""
        args = ["TASK.QUEUE"]
        if queue_name:
            args.append(queue_name)
        res = self.conn.execute_command(*args)
        if isinstance(res, list):
            return [x.decode("utf-8") if isinstance(x, bytes) else str(x) for x in res]
        return []

    def stats(self, queue_name: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve queue metrics and latency statistics."""
        args = ["TASK.STATS"]
        if queue_name:
            args.append(queue_name)
        res = self.conn.execute_command(*args)
        stats_dict = {}
        if isinstance(res, list):
            for i in range(0, len(res) - 1, 2):
                k = res[i].decode("utf-8") if isinstance(res[i], bytes) else str(res[i])
                v = res[i + 1].decode("utf-8") if isinstance(res[i + 1], bytes) else res[i + 1]
                stats_dict[k] = v
        return stats_dict

    def workers(self) -> List[Dict[str, Any]]:
        """Get status of all task worker threads."""
        res = self.conn.execute_command("TASK.WORKERS")
        worker_list = []
        if isinstance(res, list):
            for item in res:
                if isinstance(item, list):
                    w = {}
                    for i in range(0, len(item) - 1, 2):
                        k = item[i].decode("utf-8") if isinstance(item[i], bytes) else str(item[i])
                        v = item[i + 1].decode("utf-8") if isinstance(item[i + 1], bytes) else item[i + 1]
                        w[k] = v
                    worker_list.append(w)
        return worker_list

    def pause_workers(self) -> bool:
        res = self.conn.execute_command("TASK.WORKERS", "PAUSE")
        return res in ("OK", b"OK")

    def resume_workers(self) -> bool:
        res = self.conn.execute_command("TASK.WORKERS", "RESUME")
        return res in ("OK", b"OK")

    def set_worker_count(self, count: int) -> bool:
        res = self.conn.execute_command("TASK.WORKERS", "SET", count)
        return res in ("OK", b"OK")

    # Scheduling
    def schedule_add(
        self,
        schedule_id: str,
        cron_expr: str,
        queue_name: str,
        payload: Union[bytes, str, Dict[str, Any]],
        priority: str = "NORMAL"
    ) -> bool:
        if isinstance(payload, dict):
            if HAS_MSGPACK:
                raw_payload = msgpack.packb(payload)
            else:
                raw_payload = json.dumps(payload).encode("utf-8")
        elif isinstance(payload, str):
            raw_payload = payload.encode("utf-8")
        else:
            raw_payload = payload

        res = self.conn.execute_command("SCHEDULE.ADD", schedule_id, cron_expr, queue_name, priority, raw_payload)
        return res in ("OK", b"OK")

    def schedule_remove(self, schedule_id: str) -> bool:
        res = self.conn.execute_command("SCHEDULE.REMOVE", schedule_id)
        return res in ("OK", b"OK")

    def schedule_list(self) -> List[str]:
        res = self.conn.execute_command("SCHEDULE.LIST")
        if isinstance(res, list):
            return [x.decode("utf-8") if isinstance(x, bytes) else str(x) for x in res]
        return []

    def schedule_enable(self, schedule_id: str) -> bool:
        res = self.conn.execute_command("SCHEDULE.ENABLE", schedule_id)
        return res in ("OK", b"OK")

    def schedule_disable(self, schedule_id: str) -> bool:
        res = self.conn.execute_command("SCHEDULE.DISABLE", schedule_id)
        return res in ("OK", b"OK")

    def schedule_next(self, schedule_id: str) -> str:
        res = self.conn.execute_command("SCHEDULE.NEXT", schedule_id)
        if isinstance(res, bytes):
            return res.decode("utf-8")
        return str(res)


# Global default client
_default_client: Optional[TaskClient] = None

def get_default_client() -> TaskClient:
    global _default_client
    if _default_client is None:
        _default_client = TaskClient()
    return _default_client

def set_default_client(client: TaskClient):
    global _default_client
    _default_client = client


class TaskWrapper:
    """Callable wrapper for task functions offering .delay() and .apply_async()."""

    def __init__(
        self,
        func: Any,
        queue: str = "default",
        priority: str = "NORMAL",
        max_retries: int = 3,
        timeout: int = 30,
        cron: Optional[str] = None,
        client: Optional[TaskClient] = None
    ):
        self.func = func
        self.queue = queue
        self.priority = priority
        self.max_retries = max_retries
        self.timeout = timeout
        self.cron = cron
        self._client = client
        functools.update_wrapper(self, func)

        # Register schedule if cron specified
        if self.cron:
            c = self._get_client()
            full_name = f"{func.__module__}.{func.__name__}"
            c.schedule_add(
                schedule_id=full_name,
                cron_expr=self.cron,
                queue_name=self.queue,
                payload={"func": full_name, "args": [], "kwargs": {}},
                priority=self.priority
            )

    def _get_client(self) -> TaskClient:
        return self._client or get_default_client()

    def __call__(self, *args, **kwargs) -> Any:
        """Direct local function execution."""
        return self.func(*args, **kwargs)

    def delay(self, *args, **kwargs) -> AsyncResult:
        """Submit task asynchronously to QIHSE queue."""
        return self.apply_async(args=args, kwargs=kwargs)

    def apply_async(
        self,
        args: Optional[Tuple[Any, ...]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        priority: Optional[str] = None,
        queue: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> AsyncResult:
        """Submit task with custom parameters."""
        c = self._get_client()
        mod_name = self.func.__module__
        if mod_name == "__main__":
            import __main__
            if hasattr(__main__, "__file__") and __main__.__file__:
                mod_name = os.path.splitext(os.path.basename(__main__.__file__))[0]
        full_name = f"{mod_name}.{self.func.__name__}"
        payload = {
            "func": full_name,
            "args": list(args) if args else [],
            "kwargs": kwargs or {},
            "timeout_ms": (timeout or self.timeout) * 1000
        }
        target_q = queue or self.queue
        target_prio = priority or self.priority

        task_id = c.submit(target_q, payload, priority=target_prio)
        return AsyncResult(task_id, c)


def task(
    queue: str = "default",
    priority: str = "NORMAL",
    max_retries: int = 3,
    timeout: int = 30,
    cron: Optional[str] = None,
    client: Optional[TaskClient] = None
):
    """Celery-compatible @task decorator for QIHSE."""
    def decorator(func):
        return TaskWrapper(
            func=func,
            queue=queue,
            priority=priority,
            max_retries=max_retries,
            timeout=timeout,
            cron=cron,
            client=client
        )
    return decorator

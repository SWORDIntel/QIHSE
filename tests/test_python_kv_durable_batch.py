import os

ROOT = os.environ["QIHSE_DATA_DIR"]
os.environ["QIHSE_FIPS_MODE"] = "disabled"

from qihse.core import _lib
from qihse.kv import KVStore

PASSWORD = b"PythonDurableBatchOperator1!"
assert _lib.qihse_auth_bootstrap_operator(PASSWORD)
user = _lib.qihse_auth_get_user(0)
assert user
records = [
    {"key": "scan:archive:1", "value": "complete", "classification": 2,
     "sci_compartment": 1},
    {"key": "scan:archive:2", "value": "pending", "expire_time_ms": 0},
]

with KVStore(user=user) as store:
    try:
        store.set_batch_durable(records)
        raise AssertionError("batch accepted without explicit user")
    except TypeError:
        pass
    assert store.set_batch_durable(records, user=user)
    assert store.get("scan:archive:1", user=user) == "complete"
with KVStore(user=user) as reopened:
    assert reopened.get("scan:archive:1", user=user) == "complete"
    assert reopened.get("scan:archive:2", user=user) == "pending"
    try:
        reopened.set_batch_durable(
            [{"key": "bad\x00key", "value": "x"}], user=user)
        raise AssertionError("embedded NUL was accepted")
    except ValueError:
        pass
print("Python durable KV batch: authenticated append/reopen passed", flush=True)
os._exit(0)

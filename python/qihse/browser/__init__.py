"""QIHSE operator browser — fleet viewer, keyspace browser, federation pane.

An operator-facing read/mutate surface over the wire ONLY: every byte of
node data flows through an authenticated :class:`qihse.controller.Controller`
session.  The browser never opens WAL/SSTable/journal segment files
directly — that would bypass classification enforcement at the KV layer.

Authority model (mirrors the controller SDK):

    * The bridge process holds NO ambient node credentials.  Credentials
      arrive per login and live only in that session's fleet, which is
      torn down on idle timeout or logout.
    * Every read and every guarded action executes over Controllers
      authenticated as the logged-in principal — the poller never caches
      data under a different identity than the session it serves.
    * The SERVER enforces authentication, the system-domain gate,
      classification and replay; the bridge relays typed refusals
      (NOAUTH/NOPERM/...) and never fabricates success or emptiness.

WebAuthn: the browser speaks FIDO2 with RP ID ``localhost`` (browsers
reject IP-literal RP IDs); the bridge binds loopback only, so the
SSH-forwarded URL ``http://localhost:8090`` is a secure context.
"""

from .slots import keyslot, SLOT_COUNT
from .fleet import NodeSpec, SessionFleet

__all__ = ["keyslot", "SLOT_COUNT", "NodeSpec", "SessionFleet"]

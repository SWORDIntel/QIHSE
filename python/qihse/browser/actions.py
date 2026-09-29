"""Guarded action allowlist — the ONLY mutations the bridge will dispatch.

Rules (from the plan + review):

    * Allowlist, nothing else.  No generic command passthrough, ever.
    * Typed argument validation BEFORE dispatch; invalid = refused.
    * The canonical command string is what the dialog shows, what the
      WebAuthn action challenge is bound to, and what gets dispatched —
      one string, impossible to diverge.
    * MOVESLOTS targets must be SEEDED nodes (the bridge never induces a
      connection to an address the operator did not explicitly configure).
    * The SERVER stays the authority: refusals are relayed as typed
      errors (NOPERM/...), success is never fabricated.
    * Action log lines carry the principal and the canonical command —
      never key values, previews, or credentials.
"""

from __future__ import annotations

import re

from ..controller import ControllerError
from .fleet import SessionFleet, api_error

FEDERATION_STATES = {"CONNECTED", "DEGRADED", "ISOLATED",
                     "RECOVERING", "FENCED", "MAINTENANCE"}
TRUST_STATES = {"PENDING", "APPROVED", "REVOKED"}
CONSISTENCY_CLASSES = {"LOCAL", "EVENTUAL", "CAUSAL", "QUORUM", "LINEARIZABLE"}

_HOST_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")


class ActionError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _int_arg(args: dict, name: str, lo: int, hi: int) -> int:
    v = args.get(name)
    if isinstance(v, bool) or not isinstance(v, int):
        raise ActionError("BAD_ARG", f"{name} must be an integer")
    if not (lo <= v <= hi):
        raise ActionError("BAD_ARG", f"{name} out of range [{lo},{hi}]")
    return v


def _str_arg(args: dict, name: str, max_len: int = 256,
             pattern: re.Pattern | None = None) -> str:
    v = args.get(name)
    if not isinstance(v, str) or not v or len(v) > max_len:
        raise ActionError("BAD_ARG", f"{name} must be a non-empty string"
                                     f" (<= {max_len} chars)")
    if pattern is not None and not pattern.match(v):
        raise ActionError("BAD_ARG", f"{name} has an invalid format")
    return v


def _enum_arg(args: dict, name: str, allowed: set) -> str:
    v = _str_arg(args, name, 32)
    if v.upper() not in allowed:
        raise ActionError("BAD_ARG", f"{name} must be one of {sorted(allowed)}")
    return v.upper()


def _target_seeded(args: dict, fleet: SessionFleet) -> str:
    target = _str_arg(args, "target", 258)
    host, sep, port = target.rpartition(":")
    if not sep or not _HOST_RE.match(host) or not port.isdigit():
        raise ActionError("BAD_ARG", "target must be host:port")
    if fleet.spec_for_addr(host, int(port)) is None:
        raise ActionError("BAD_ARG",
                          f"target {target} is not a seeded node "
                          f"(the bridge only acts on explicitly configured nodes)")
    return target


class Action:
    def __init__(self, name, title, arg_schema, builder):
        self.name = name
        self.title = title
        self.arg_schema = arg_schema          # for the UI form
        self._builder = builder               # (fleet, args) -> (canonical, wire)

    def canonical(self, fleet: SessionFleet, args: dict) -> tuple[str, list]:
        return self._builder(fleet, args)


def _moveslots(fleet, args):
    first = _int_arg(args, "first", 0, 16383)
    last = _int_arg(args, "last", 0, 16383)
    if first > last:
        raise ActionError("BAD_ARG", "first must be <= last")
    target = _target_seeded(args, fleet)
    return (f"CLUSTER MOVESLOTS {first}-{last} {target}",
            ["CLUSTER", "MOVESLOTS", f"{first}-{last}", target])


def _trust_set(fleet, args):
    uuid = _str_arg(args, "uuid", 32, _HEX32_RE)
    state = _enum_arg(args, "state", TRUST_STATES)
    result = _str_arg(args, "result", 64)
    return (f"FEDERATION TRUST.SET {uuid.lower()} {state} {result}",
            ["FEDERATION", "TRUST.SET", uuid.lower(), state, result])


def _lease_release(fleet, args):
    lease = _str_arg(args, "lease_id", 256)
    return (f"FEDERATION LEASE.RELEASE {lease}",
            ["FEDERATION", "LEASE.RELEASE", lease])


def _fed_state(fleet, args):
    state = _enum_arg(args, "state", FEDERATION_STATES)
    return (f"FEDERATION STATE {state}", ["FEDERATION", "STATE", state])


def _bgsave(fleet, args):
    return ("BGSAVE", ["BGSAVE"])


def _node_approve(fleet, args):
    uuid = _str_arg(args, "uuid", 32, _HEX32_RE)
    return (f"FEDERATION NODE.APPROVE {uuid.lower()}",
            ["FEDERATION", "NODE.APPROVE", uuid.lower()])


def _node_revoke(fleet, args):
    uuid = _str_arg(args, "uuid", 32, _HEX32_RE)
    return (f"FEDERATION NODE.REVOKE {uuid.lower()}",
            ["FEDERATION", "NODE.REVOKE", uuid.lower()])


def _lease_renew(fleet, args):
    lease = _str_arg(args, "lease_id", 256)
    return (f"FEDERATION LEASE.RENEW {lease}",
            ["FEDERATION", "LEASE.RENEW", lease])


def _ns_register(fleet, args):
    name = _str_arg(args, "name", 128)
    cls = _enum_arg(args, "class", CONSISTENCY_CLASSES)
    return (f"FEDERATION NS.REGISTER {name} {cls}",
            ["FEDERATION", "NS.REGISTER", name, cls])


def _ns_unregister(fleet, args):
    name = _str_arg(args, "name", 128)
    return (f"FEDERATION NS.UNREGISTER {name}",
            ["FEDERATION", "NS.UNREGISTER", name])


REGISTRY: dict[str, Action] = {
    a.name: a for a in [
        Action("moveslots", "Move slot range to a seeded node",
               [{"name": "first", "type": "int"},
                {"name": "last", "type": "int"},
                {"name": "target", "type": "string"}],
               _moveslots),
        Action("trust_set", "Set node trust state",
               [{"name": "uuid", "type": "string"},
                {"name": "state", "type": "enum", "values": sorted(TRUST_STATES)},
                {"name": "result", "type": "string"}],
               _trust_set),
        Action("lease_release", "Release a federation lease",
               [{"name": "lease_id", "type": "string"}],
               _lease_release),
        Action("lease_renew", "Renew a federation lease",
               [{"name": "lease_id", "type": "string"}],
               _lease_renew),
        Action("fed_state", "Set federation state",
               [{"name": "state", "type": "enum", "values": sorted(FEDERATION_STATES)}],
               _fed_state),
        Action("node_approve", "Approve an enrolled node",
               [{"name": "uuid", "type": "string"}],
               _node_approve),
        Action("node_revoke", "Revoke a node's identity",
               [{"name": "uuid", "type": "string"}],
               _node_revoke),
        Action("ns_register", "Register a namespace",
               [{"name": "name", "type": "string"},
                {"name": "class", "type": "enum",
                 "values": sorted(CONSISTENCY_CLASSES)}],
               _ns_register),
        Action("ns_unregister", "Unregister a namespace",
               [{"name": "name", "type": "string"}],
               _ns_unregister),
        Action("bgsave", "Persist the store (BGSAVE)",
               [],
               _bgsave),
    ]
}


# ── operator-authored extra actions ────────────────────────────────────
# The deliberate escape hatch ("control surfaces if they're ever
# needed"): a file on the BRIDGE HOST (never reachable from the browser)
# in which the operator pre-declares additional commands.  Each still
# goes through typed validation, the command-bound YubiKey touch, and
# the audit log — this is a configured allowlist extension, not a
# command proxy.  SHUTDOWN is refused here on purpose: keep fatal
# controls on the console, not behind a touch.

_FORBIDDEN_EXTRA = {"SHUTDOWN", "DEBUG", "CONFIG", "FLUSHALL", "FLUSHDB"}


def load_extra(path: str, log=print) -> int:
    """Merge operator-declared actions from a JSON file into REGISTRY.
    Returns how many were added.  The file itself is validated hard —
    a malformed entry is a load error, not a silent skip."""
    import json
    import os

    with open(path, "r", encoding="utf-8") as fh:
        spec = json.load(fh)
    if not isinstance(spec, list):
        raise ActionError("BAD_ACTION_FILE", "extra-actions file must be a JSON list")

    added = 0
    for i, entry in enumerate(spec):
        where = f"{path}[{i}]"
        if not isinstance(entry, dict) or not isinstance(entry.get("command"), list) \
                or not entry["command"] \
                or not all(isinstance(t, str) for t in entry["command"]):
            raise ActionError("BAD_ACTION_FILE",
                              f"{where}: needs a non-empty 'command' string list")
        wire = [t.upper() if j == 0 else t for j, t in enumerate(entry["command"])]
        if wire[0] in _FORBIDDEN_EXTRA:
            raise ActionError("FORBIDDEN_ACTION",
                              f"{where}: {wire[0]} is deliberately not bridge-dispatchable")
        name = entry.get("name") or "_".join(wire).lower()
        if not isinstance(name, str) or not name or name in REGISTRY:
            raise ActionError("BAD_ACTION_FILE", f"{where}: bad or duplicate name {name!r}")
        params = entry.get("params", {})
        if not isinstance(params, dict):
            raise ActionError("BAD_ACTION_FILE", f"{where}: 'params' must be an object")
        placeholders = [t for t in wire if t.startswith("$")]

        def builder(fleet, args, _wire=wire, _params=params, _ph=placeholders):
            out = []
            for t in _wire:
                if t.startswith("$"):
                    key = t[1:]
                    spec_p = _params.get(key)
                    val = args.get(key)
                    if spec_p is None:
                        raise ActionError("BAD_ARG",
                                          f"${key} has no param spec in the action file")
                    typ = spec_p.get("type", "string")
                    if typ == "int":
                        lo, hi = spec_p.get("range", [0, 2**31 - 1])
                        out.append(str(_int_arg(args, key, lo, hi)))
                    elif typ == "enum":
                        allowed = set(spec_p.get("values", []))
                        out.append(_enum_arg(args, key, allowed))
                    elif typ == "hex32":
                        out.append(_str_arg(args, key, 32, _HEX32_RE).lower())
                    else:
                        out.append(_str_arg(args, key,
                                            int(spec_p.get("max", 256))))
                else:
                    out.append(t)
            return (" ".join(out), out)

        arg_schema = []
        for key in [p[1:] for p in placeholders]:
            spec_p = params.get(key, {})
            sch = {"name": key, "type": spec_p.get("type", "string")}
            if "values" in spec_p:
                sch["values"] = sorted(spec_p["values"])
            arg_schema.append(sch)
        REGISTRY[name] = Action(
            name, entry.get("title") or name, arg_schema, builder)
        added += 1
        log(f"EXTRA-ACTION loaded {name!r} -> {' '.join(wire)}")
    return added


def schema() -> list[dict]:
    return [{"name": a.name, "title": a.title, "args": a.arg_schema}
            for a in REGISTRY.values()]


def canonical_for(fleet: SessionFleet, action_name: str, args: dict) -> str:
    action = REGISTRY.get(action_name)
    if action is None:
        raise ActionError("UNKNOWN_ACTION", f"{action_name!r} is not in the allowlist")
    canonical, _wire = action.canonical(fleet, args)
    return canonical


def dispatch(fleet: SessionFleet, action_name: str, args: dict,
             log=lambda line: None) -> dict:
    """Validate → dispatch on the first healthy seeded node → relay the
    server's answer verbatim.  Called ONLY after a verified command-bound
    WebAuthn assertion for the exact canonical command."""
    action = REGISTRY.get(action_name)
    if action is None:
        raise ActionError("UNKNOWN_ACTION", f"{action_name!r} is not in the allowlist")
    canonical, wire = action.canonical(fleet, args)
    last: ControllerError | None = None
    for idx in range(len(fleet.nodes)):
        try:
            reply = fleet.call(idx, *wire, check=True)
            text = (reply.value.decode("utf-8", "replace")
                    if isinstance(reply.value, (bytes, bytearray))
                    else str(reply.value))
            log(f"ACTION principal={fleet.username} node={idx} "
                f"cmd={canonical!r} -> ok: {text!r}")
            return {"ok": True, "reply": text, "command": canonical}
        except ControllerError as exc:
            err = api_error(exc)
            if err.get("error_class") in ("NOPERM", "NOAUTH"):
                # A refusal is authoritative — do not fail over.
                log(f"ACTION principal={fleet.username} node={idx} "
                    f"cmd={canonical!r} -> refused {err['error_class']}")
                return {"ok": False, "error": err, "command": canonical}
            last = exc
            continue
    log(f"ACTION principal={fleet.username} cmd={canonical!r} -> no node answered")
    return {"ok": False, "error": api_error(last) if last
            else {"error_class": "DOWN", "message": "no node answered"},
            "command": canonical}

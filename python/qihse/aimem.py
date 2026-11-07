"""Authenticated, scoped client for the native AIMEM RESP protocol.

The caller supplies a connected :class:`~qihse.controller.Controller` that
has completed explicit AUTH. All data operations keep the project scope on
the wire; this module never opens embedded QIHSE storage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .controller import (Controller, ControllerUsageError, Reply,
                         ReplyShapeError)

RecallMode = Literal["bm25", "semantic", "hybrid"]


@dataclass(frozen=True)
class Scope:
    project: str
    worktree: str = ""
    workstream: str = ""
    session: str = ""

    def __post_init__(self) -> None:
        fields = (self.project, self.worktree, self.workstream, self.session)
        if not self.project or any(not isinstance(v, str) for v in fields):
            raise ControllerUsageError("AIMEM project scope is required")
        if self.workstream and not self.worktree or self.session and not self.workstream:
            raise ControllerUsageError("AIMEM scope hierarchy is incomplete")
        for value in fields:
            if len(value.encode("utf-8")) > 63 or any(
                    not (c.isascii() and (c.isalnum() or c in "-_.")) for c in value):
                raise ControllerUsageError("invalid AIMEM scope token")

    def args(self) -> tuple[str, str, str, str]:
        return self.project, self.worktree, self.workstream, self.session


@dataclass(frozen=True)
class MemoryHit:
    id: str
    created_ms: int
    kind: int
    classification: int
    sci_compartment: int
    score: float
    text: str


@dataclass(frozen=True)
class DurableReceipt:
    operation: str
    id: str
    token: str
    durability: str


@dataclass(frozen=True)
class KnowledgeVersion:
    knowledge_id: str
    version_id: str
    supersedes_version: str
    type: int
    status: int
    revision: int
    created_at_ms: int
    valid_from_ingest_ms: int
    valid_to_ingest_ms: int
    created_by: int
    scope: Scope
    content: str


@dataclass(frozen=True)
class Handoff:
    id: str
    owner_id: int
    recipient_id: int
    created_ms: int
    expires_ms: int
    revision: int
    state: str
    accepted_by: int
    scope: Scope
    summary: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class QueryHit:
    version: KnowledgeVersion
    score: float
    lexical_score: float
    semantic_score: float
    current: bool
    ranking_mode: int
    explain_flags: int
    relations: tuple[tuple[str, str, Scope], ...]
    source_event_ids: tuple[str, ...]


def _array(reply: Reply, length: int | None = None) -> list[Reply]:
    items = reply.as_list()
    if length is not None and len(items) != length:
        raise ReplyShapeError(f"AIMEM expected {length} fields, got {len(items)}")
    return items


def _text(reply: Reply) -> str:
    return reply.as_text()


def _uint(reply: Reply) -> int:
    value = _text(reply)
    if not value or not value.isascii() or not value.isdecimal():
        raise ReplyShapeError("AIMEM expected an unsigned decimal field")
    return int(value)


def _hit(reply: Reply) -> MemoryHit:
    row = _array(reply, 7)
    try:
        score = float(_text(row[5]))
    except ValueError as exc:
        raise ReplyShapeError("invalid AIMEM score") from exc
    return MemoryHit(_text(row[0]), _uint(row[1]), _uint(row[2]),
                     _uint(row[3]), _uint(row[4]), score, _text(row[6]))


def _scoped_receipt(reply: Reply) -> DurableReceipt:
    operation, id, token, durability = (_text(v) for v in _array(reply, 4))
    if operation != "STORE-SCOPED" or durability != "local-fsync" or not id or not token:
        raise ReplyShapeError("invalid AIMEM scoped receipt")
    return DurableReceipt(operation, id, token, durability)


def _knowledge(reply: Reply) -> KnowledgeVersion:
    row = _array(reply, 15)
    return KnowledgeVersion(_text(row[0]), _text(row[1]), _text(row[2]),
                            _uint(row[3]), _uint(row[4]), _uint(row[5]),
                            _uint(row[6]), _uint(row[7]), _uint(row[8]),
                            _uint(row[9]), Scope(*(_text(v) for v in row[10:14])),
                            _text(row[14]))


def _handoff(reply: Reply) -> Handoff:
    row = _array(reply, 15)
    return Handoff(_text(row[0]), _uint(row[1]), _uint(row[2]), _uint(row[3]),
                   _uint(row[4]), _uint(row[5]), _text(row[6]), _uint(row[7]),
                   Scope(*(_text(v) for v in row[8:12])), _text(row[12]),
                   tuple(_text(v) for v in _array(row[13])))


def _query_hit(reply: Reply) -> QueryHit:
    row = _array(reply, 9)
    relations = []
    for item in _array(row[7]):
        parts = _array(item, 6)
        relations.append((_text(parts[0]), _text(parts[1]),
                          Scope(*(_text(v) for v in parts[2:6]))))
    try:
        scores = tuple(float(_text(v)) for v in row[1:4])
    except ValueError as exc:
        raise ReplyShapeError("invalid AIMEM query score") from exc
    current = _uint(row[4])
    if current not in (0, 1):
        raise ReplyShapeError("invalid AIMEM current flag")
    return QueryHit(_knowledge(row[0]), *scores, bool(current), _uint(row[5]),
                    _uint(row[6]), tuple(relations),
                    tuple(_text(v) for v in _array(row[8])))


class AIMEMClient:
    """Native AIMEM commands over a Controller with explicit authenticated identity.

    Example::

        with Controller("127.0.0.1", 6390, username="agent", password="...") as wire:
            memory = AIMEMClient(wire)
            scope = Scope("project", "worktree", "stream", "session")
            memory.store(scope, 1, "Reviewed handoff note", key="capture-1")
            hits = memory.recall(scope, "handoff", mode="bm25")
    """

    def __init__(self, controller: Controller):
        if not controller.username or not controller.connected:
            raise ControllerUsageError("AIMEM requires an authenticated Controller")
        self._controller = controller

    def _call(self, *args) -> Reply:
        # Controller.call propagates NOAUTH/NOPERM/ERR with their server class.
        # Never substitute a local/raw read on an error or missing reply.
        return self._controller.call("AIMEM", *args)

    def store(self, scope: Scope, kind: int, text: str, *, key: str | None = None,
              durable: bool = True) -> str:
        if kind not in (1, 2) or not text:
            raise ControllerUsageError("AIMEM kind must be 1 or 2 and text nonempty")
        command = "STORE-SCOPED-DURABLE" if durable else "STORE-SCOPED"
        args = (command, kind, text, *scope.args())
        return _text(self._call(*args, *((key,) if key is not None else ())))

    def store_receipt(self, scope: Scope, kind: int, text: str,
                      *, key: str) -> DurableReceipt:
        """Store with a local fsync receipt; retry the same key after lost ACK.

        The receipt does not claim remote replication or quorum. A changed
        payload or kind at the same key raises the server's conflict error.
        """
        if kind not in (1, 2) or not text or not key:
            raise ControllerUsageError("AIMEM receipt requires kind, text, and retry key")
        return _scoped_receipt(self._call("STORE-SCOPED-RECEIPT", kind, text,
                                          *scope.args(), key))

    def recall(self, scope: Scope, query: str, *, limit: int = 10,
               mode: RecallMode = "bm25", kind: int = 0) -> list[MemoryHit]:
        if not 1 <= limit <= 128 or mode not in ("bm25", "semantic", "hybrid") or kind not in (0, 1, 2):
            raise ControllerUsageError("invalid AIMEM recall parameters")
        reply = self._call("RECALL-SCOPED", query, limit, mode, kind, *scope.args())
        return [_hit(item) for item in _array(reply)]

    def get(self, scope: Scope, id: str) -> MemoryHit | None:
        reply = self._call("GET-SCOPED", id, *scope.args())
        return None if reply.is_nil() else _hit(reply)

    def forget(self, scope: Scope, id: str, *, durable: bool = True) -> bool:
        command = "FORGET-SCOPED-DURABLE" if durable else "FORGET-SCOPED"
        value = self._call(command, id, *scope.args()).as_int()
        if value not in (0, 1):
            raise ReplyShapeError("invalid AIMEM forget result")
        return bool(value)

    def count(self, scope: Scope, *, kind: int = 0) -> int:
        if kind not in (0, 1, 2):
            raise ControllerUsageError("invalid AIMEM kind")
        return self._call("COUNT-SCOPED", *scope.args(), kind).as_int()

    def event_append(self, scope: Scope, producer: str, event_id: str,
                     kind: str, source_ms: int, summary: str,
                     *, evidence_id: str | None = None) -> str:
        args = ("EVENT", "APPEND", *scope.args(), producer, event_id, kind,
                source_ms, summary)
        return _text(self._call(*args, *((evidence_id,) if evidence_id else ())))

    def event_get(self, scope: Scope, id: str) -> MemoryHit | None:
        reply = self._call("EVENT", "READ", id, *scope.args())
        return None if reply.is_nil() else _hit(reply)

    def knowledge_create(self, scope: Scope, type: int, status: int,
                         content: str) -> KnowledgeVersion:
        return _knowledge(self._call("KNOWLEDGE", "CREATE", type, status,
                                     content, *scope.args()))

    def knowledge_revise(self, knowledge_id: str, expected_version_id: str,
                         expected_revision: int, status: int,
                         content: str) -> KnowledgeVersion:
        return _knowledge(self._call("KNOWLEDGE", "REVISE", knowledge_id,
                                     expected_version_id, expected_revision,
                                     status, content))

    def knowledge_get(self, scope: Scope, version_id: str) -> KnowledgeVersion | None:
        reply = self._call("KNOWLEDGE", "GET", version_id, *scope.args())
        return None if reply.is_nil() else _knowledge(reply)

    def knowledge_latest(self, scope: Scope, knowledge_id: str) -> KnowledgeVersion | None:
        reply = self._call("KNOWLEDGE", "LATEST", knowledge_id, *scope.args())
        return None if reply.is_nil() else _knowledge(reply)

    def knowledge_as_of(self, scope: Scope, knowledge_id: str,
                        ingestion_ms: int) -> KnowledgeVersion | None:
        reply = self._call("KNOWLEDGE", "AS-OF", knowledge_id,
                           ingestion_ms, *scope.args())
        return None if reply.is_nil() else _knowledge(reply)

    def handoff_offer(self, scope: Scope, recipient_user_id: int, ttl_ms: int,
                      summary: str, *, evidence_ids: tuple[str, ...] = ()) -> str:
        if not 1 <= ttl_ms <= 7 * 24 * 60 * 60 * 1000 or len(evidence_ids) > 8:
            raise ControllerUsageError("invalid AIMEM handoff TTL or evidence count")
        return _text(self._call("HANDOFF", "OFFER", recipient_user_id, ttl_ms,
                                *scope.args(), summary, *evidence_ids))

    def handoff_get(self, id: str) -> Handoff | None:
        reply = self._call("HANDOFF", "GET", id)
        return None if reply.is_nil() else _handoff(reply)

    def handoff_accept(self, id: str, expected_revision: int) -> str:
        return _text(self._call("HANDOFF", "ACCEPT", id, expected_revision))

    def handoff_cancel(self, id: str, expected_revision: int) -> str:
        return _text(self._call("HANDOFF", "CANCEL", id, expected_revision))

    def query_begin(self, scope: Scope, *, type: int = 0, status: int = 0,
                    current_only: bool = False, from_ms: int = 0, to_ms: int = 0,
                    changed_since_ms: int = 0, as_of_ms: int = 0,
                    mode: RecallMode = "bm25", text: str = "",
                    max_rows: int = 128) -> str:
        if mode not in ("bm25", "semantic", "hybrid") or not 1 <= max_rows <= 4096:
            raise ControllerUsageError("invalid AIMEM query mode or row limit")
        return _text(self._call("QUERY", "V1", "BEGIN", *scope.args(), type,
                                status, int(current_only), from_ms, to_ms,
                                changed_since_ms, as_of_ms, mode, text,
                                max_rows))

    def query_next(self, cursor: str, *, page_size: int = 128) -> list[QueryHit]:
        if not 1 <= page_size <= 128:
            raise ControllerUsageError("AIMEM page size out of range")
        return [_query_hit(item) for item in _array(self._call(
            "QUERY", "V1", "NEXT", cursor, page_size))]

    def query_end(self, cursor: str) -> None:
        reply = self._call("QUERY", "V1", "END", cursor)
        if not reply.is_ok():
            raise ReplyShapeError("AIMEM QUERY END did not return OK")


__all__ = ["AIMEMClient", "Scope", "MemoryHit", "DurableReceipt", "KnowledgeVersion",
           "Handoff", "QueryHit", "RecallMode"]

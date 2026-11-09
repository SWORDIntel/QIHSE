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
class KnowledgeRelation:
    type: int
    target_version_id: str
    target_scope: Scope


@dataclass(frozen=True)
class KnowledgeProvenance:
    confidence_ppm: int
    retry_key: str
    source_event_ids: tuple[str, ...] = ()
    relations: tuple[KnowledgeRelation, ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.confidence_ppm <= 1_000_000 or not self.retry_key:
            raise ControllerUsageError("invalid AIMEM confidence or retry key")
        if len(self.source_event_ids) > 32 or len(self.relations) > 32:
            raise ControllerUsageError("AIMEM provenance count exceeds 32")
        if any(relation.type not in (1, 2, 3) for relation in self.relations):
            raise ControllerUsageError("invalid AIMEM relation type")

    def args(self) -> tuple:
        result: list = [self.confidence_ppm, self.retry_key,
                        len(self.source_event_ids), *self.source_event_ids,
                        len(self.relations)]
        for relation in self.relations:
            result.extend((relation.type, relation.target_version_id,
                           *relation.target_scope.args()))
        return tuple(result)


@dataclass(frozen=True)
class DocumentSourceRef:
    system: str
    id: str
    revision: str
    line_start: int
    line_end: int

    def __post_init__(self) -> None:
        for value, limit in ((self.system, 32), (self.id, 256),
                             (self.revision, 128)):
            if not value or len(value.encode()) > limit or any(
                    ord(ch) < 32 or ord(ch) == 127 for ch in value):
                raise ControllerUsageError("invalid AIMEM document source field")
        if not 1 <= self.line_start <= self.line_end <= 0xFFFFFFFF:
            raise ControllerUsageError("invalid AIMEM document line range")

    def args(self) -> tuple:
        return (self.system, self.id, self.revision,
                self.line_start, self.line_end)


@dataclass(frozen=True)
class ExtendedKnowledgeVersion:
    version: KnowledgeVersion
    generated_by: int
    reviewed_by: int
    confidence_ppm: int
    source_event_ids: tuple[str, ...]
    relations: tuple[KnowledgeRelation, ...]


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


def _scoped_receipt(reply: Reply, expected_operation: str) -> DurableReceipt:
    operation, id, token, durability = (_text(v) for v in _array(reply, 4))
    if operation != expected_operation or durability != "local-fsync" or not id or not token:
        raise ReplyShapeError("invalid AIMEM scoped receipt")
    return DurableReceipt(operation, id, token, durability)


def _knowledge(reply: Reply) -> KnowledgeVersion:
    row = _array(reply, 15)
    return KnowledgeVersion(_text(row[0]), _text(row[1]), _text(row[2]),
                            _uint(row[3]), _uint(row[4]), _uint(row[5]),
                            _uint(row[6]), _uint(row[7]), _uint(row[8]),
                            _uint(row[9]), Scope(*(_text(v) for v in row[10:14])),
                            _text(row[14]))


def _source_ref(reply: Reply) -> DocumentSourceRef:
    row = _array(reply, 5)
    try:
        return DocumentSourceRef(_text(row[0]), _text(row[1]), _text(row[2]),
                                 _uint(row[3]), _uint(row[4]))
    except ControllerUsageError as exc:
        raise ReplyShapeError("invalid AIMEM source reply") from exc


def _extended_knowledge(reply: Reply) -> ExtendedKnowledgeVersion:
    row = _array(reply, 6)
    confidence = _uint(row[3])
    if confidence > 1_000_000:
        raise ReplyShapeError("invalid AIMEM confidence")
    relations = []
    for item in _array(row[5]):
        fields = _array(item, 6)
        relation_type = _uint(fields[0])
        if relation_type not in (1, 2, 3, 4):
            raise ReplyShapeError("invalid AIMEM relation type")
        relations.append(KnowledgeRelation(relation_type, _text(fields[1]),
                                           Scope(*(_text(v) for v in fields[2:6]))))
    sources = tuple(_text(v) for v in _array(row[4]))
    if len(sources) > 32 or len(relations) > 32:
        raise ReplyShapeError("AIMEM provenance reply exceeds bound")
    return ExtendedKnowledgeVersion(_knowledge(row[0]), _uint(row[1]),
                                    _uint(row[2]), confidence, sources,
                                    tuple(relations))


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
                                          *scope.args(), key), "STORE-SCOPED")

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

    def forget_receipt(self, scope: Scope, id: str, *, key: str) -> DurableReceipt:
        """Delete with a recoverable local fsync receipt; retry with the same key."""
        if not id or not key:
            raise ControllerUsageError("AIMEM forget receipt requires id and retry key")
        return _scoped_receipt(self._call("FORGET-SCOPED-RECEIPT", id,
                                          *scope.args(), key), "FORGET-SCOPED")

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

    def knowledge_create_ex(self, scope: Scope, type: int, status: int,
                            content: str, provenance: KnowledgeProvenance
                            ) -> ExtendedKnowledgeVersion:
        return _extended_knowledge(self._call("KNOWLEDGE", "CREATE-EX", type,
                                              status, content, *scope.args(),
                                              *provenance.args()))

    def knowledge_create_ex_source(self, scope: Scope, type: int, status: int,
                                   content: str, provenance: KnowledgeProvenance,
                                   source: DocumentSourceRef
                                   ) -> ExtendedKnowledgeVersion:
        return _extended_knowledge(self._call("KNOWLEDGE", "CREATE-EX-SOURCE",
                                              type, status, content, *scope.args(),
                                              *provenance.args(), *source.args()))

    def knowledge_revise(self, knowledge_id: str, expected_version_id: str,
                         expected_revision: int, status: int,
                         content: str) -> KnowledgeVersion:
        return _knowledge(self._call("KNOWLEDGE", "REVISE", knowledge_id,
                                     expected_version_id, expected_revision,
                                     status, content))

    def knowledge_revise_ex(self, knowledge_id: str, expected_version_id: str,
                            expected_revision: int, status: int, content: str,
                            provenance: KnowledgeProvenance
                            ) -> ExtendedKnowledgeVersion:
        return _extended_knowledge(self._call("KNOWLEDGE", "REVISE-EX",
                                              knowledge_id, expected_version_id,
                                              expected_revision, status, content,
                                              *provenance.args()))

    def knowledge_revise_ex_source(self, knowledge_id: str,
                                   expected_version_id: str, expected_revision: int,
                                   status: int, content: str,
                                   provenance: KnowledgeProvenance,
                                   source: DocumentSourceRef
                                   ) -> ExtendedKnowledgeVersion:
        return _extended_knowledge(self._call("KNOWLEDGE", "REVISE-EX-SOURCE",
                                              knowledge_id, expected_version_id,
                                              expected_revision, status, content,
                                              *provenance.args(), *source.args()))

    def knowledge_get(self, scope: Scope, version_id: str) -> KnowledgeVersion | None:
        reply = self._call("KNOWLEDGE", "GET", version_id, *scope.args())
        return None if reply.is_nil() else _knowledge(reply)

    def knowledge_get_source(self, scope: Scope, version_id: str
                             ) -> tuple[KnowledgeVersion, DocumentSourceRef] | None:
        reply = self._call("KNOWLEDGE", "GET-SOURCE", version_id, *scope.args())
        if reply.is_nil():
            return None
        row = _array(reply, 2)
        return _knowledge(row[0]), _source_ref(row[1])

    def knowledge_latest(self, scope: Scope, knowledge_id: str) -> KnowledgeVersion | None:
        reply = self._call("KNOWLEDGE", "LATEST", knowledge_id, *scope.args())
        return None if reply.is_nil() else _knowledge(reply)

    def knowledge_as_of(self, scope: Scope, knowledge_id: str,
                        ingestion_ms: int) -> KnowledgeVersion | None:
        reply = self._call("KNOWLEDGE", "AS-OF", knowledge_id,
                           ingestion_ms, *scope.args())
        return None if reply.is_nil() else _knowledge(reply)

    def knowledge_walk(self, scope: Scope, version_id: str, *,
                       max_depth: int = 2, max_nodes: int = 32
                       ) -> list[tuple[int, KnowledgeVersion]]:
        if not 0 <= max_depth <= 4 or not 1 <= max_nodes <= 64:
            raise ControllerUsageError("AIMEM walk bounds exceeded")
        rows = _array(self._call("KNOWLEDGE", "WALK", version_id,
                                 *scope.args(), max_depth, max_nodes))
        result = []
        for row in rows:
            fields = _array(row)
            if len(fields) != 2:
                raise ReplyShapeError("invalid AIMEM walk row")
            result.append((_uint(fields[0]), _knowledge(fields[1])))
        return result

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
                    max_rows: int = 128,
                    source_event_id: str | None = None,
                    source_ref: DocumentSourceRef | None = None) -> str:
        if mode not in ("bm25", "semantic", "hybrid") or not 1 <= max_rows <= 4096:
            raise ControllerUsageError("invalid AIMEM query mode or row limit")
        if source_event_id is not None and source_ref is not None:
            raise ControllerUsageError("select one AIMEM source filter")
        version = "V3" if source_ref is not None else "V2" if source_event_id is not None else "V1"
        tail = source_ref.args() if source_ref is not None else (
            (source_event_id,) if source_event_id is not None else ())
        return _text(self._call("QUERY", version,
                                "BEGIN", *scope.args(), type, status,
                                int(current_only), from_ms, to_ms,
                                changed_since_ms, as_of_ms, mode, text,
                                max_rows, *tail))

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
           "KnowledgeRelation", "KnowledgeProvenance", "ExtendedKnowledgeVersion",
           "Handoff", "QueryHit", "RecallMode"]

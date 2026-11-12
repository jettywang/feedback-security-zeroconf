"""Verify known-answer suppression needs a record+TTL match and never caches query answers."""

from __future__ import annotations

import socket

import zeroconf as r
from zeroconf import const, current_time_millis
from zeroconf._cache import DNSCache
from zeroconf._handlers.query_handler import QueryHandler
from zeroconf._handlers.record_manager import RecordManager
from zeroconf._history import QuestionHistory
from zeroconf._services.registry import ServiceRegistry

from . import make_service_info

TYPE_ = "_kas-check._tcp.local."
NAME = "knownname"
REGISTRATION_NAME = f"{NAME}.{TYPE_}"
SERVER_NAME = "spare-rig.local."


class _Harness:
    """Socket-free stand-in wiring the query handler, record manager and cache."""

    def __init__(self) -> None:
        self.cache = DNSCache()
        self.registry = ServiceRegistry()
        self.question_history = QuestionHistory()
        self.out_queue = None
        self.out_delay_queue = None
        self.query_handler = QueryHandler(self)
        self.record_manager = RecordManager(self)

    def async_notify_all(self) -> None:
        """No-op notify; no listeners are registered."""

    def dispatch(self, msgs: list[r.DNSIncoming]) -> object:
        """Route packets exactly like AsyncListener.datagram_received does."""
        answers = None
        for msg in msgs:
            if msg.is_query():
                answers = self.query_handler.async_response([msg], False)
            else:
                self.record_manager.async_updates_from_response(msg)
        return answers

    def dispatch_batch(self, msgs: list[r.DNSIncoming]) -> object:
        """Route a multi-packet query as one batch like the reassembly path does."""
        assert all(msg.is_query() for msg in msgs)
        return self.query_handler.async_response(msgs, False)


def _make_harness() -> _Harness:
    harness = _Harness()
    info = make_service_info(TYPE_, REGISTRATION_NAME, properties={"path": "/healthz/"}, server=SERVER_NAME)
    harness.registry.async_add(info)
    return harness


def _build_query(
    question: r.DNSQuestion,
    known_answers: list[r.DNSRecord] | None = None,
    filler_answers: int = 0,
) -> list[r.DNSIncoming]:
    """Build an in-memory query packet, optionally carrying known answers."""
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    generated.add_question(question)
    for _ in range(filler_answers):
        # Filler answers force the known answers into a second packet
        generated.add_answer_at_time(
            r.DNSPointer(TYPE_, const._TYPE_PTR, const._CLASS_IN, const._DNS_OTHER_TTL, REGISTRATION_NAME), 0
        )
    for record in known_answers or []:
        # Timestamp 0 keeps the exact TTL on the wire
        generated.add_answer_at_time(record, 0)
    return [r.DNSIncoming(packet) for packet in generated.packets()]


def _response_buckets(question_answers: object) -> dict[str, list[str]]:
    """Group the records a query response would emit by outgoing queue."""
    if question_answers is None:
        return {}
    return {
        bucket: sorted(str(record) for record in records)
        for bucket, records in (
            ("ucast", question_answers.ucast),
            ("mcast_now", question_answers.mcast_now),
            ("mcast_aggregate", question_answers.mcast_aggregate),
            ("mcast_aggregate_last_second", question_answers.mcast_aggregate_last_second),
        )
        if records
    }


def _cache_snapshot(harness: _Harness) -> list[str]:
    """Snapshot every record currently held in the cache."""
    snapshot: list[str] = []
    for store in (harness.cache.cache, harness.cache.service_cache):
        for records in store.values():
            snapshot.extend(str(record) for record in records.values())
    return sorted(snapshot)


def _report(sample: str, question_answers: object, harness: _Harness) -> None:
    """Print the response records and the cache snapshot side by side."""
    left: list[str] = []
    for bucket, records in _response_buckets(question_answers).items():
        left.append(f"[{bucket}]")
        left.extend(f"  {record}" for record in records)
    if not left:
        left = ["(suppressed: no records emitted)"]
    right = _cache_snapshot(harness) or ["(cache empty)"]
    width = max(len(line) for line in left) + 4
    print(f"\n=== {sample} ===")
    print(f"{'RESPONSE RECORDS':<{width}}CACHE SNAPSHOT")
    for i in range(max(len(left), len(right))):
        left_cell = left[i] if i < len(left) else ""
        right_cell = right[i] if i < len(right) else ""
        print(f"{left_cell:<{width}}{right_cell}")


def test_known_answer_suppression_requires_record_and_ttl_match() -> None:
    """Suppression fires only when the known answer matches the record and keeps >half its TTL."""
    harness = _make_harness()
    ptr_question = r.DNSQuestion(TYPE_, const._TYPE_PTR, const._CLASS_IN)
    a_question = r.DNSQuestion(SERVER_NAME, const._TYPE_A, const._CLASS_IN)
    ptr_ttl = const._DNS_OTHER_TTL

    # Control: exact record with full TTL is suppressed
    exact_ptr = r.DNSPointer(TYPE_, const._TYPE_PTR, const._CLASS_IN, ptr_ttl, REGISTRATION_NAME)
    answers = harness.dispatch(_build_query(ptr_question, [exact_ptr]))
    _report("control: exact PTR known answer, full TTL 4500", answers, harness)
    assert not _response_buckets(answers)
    assert not _cache_snapshot(harness)

    # Same name, different record: PTR alias target differs
    other_ptr = r.DNSPointer(TYPE_, const._TYPE_PTR, const._CLASS_IN, ptr_ttl, f"other.{TYPE_}")
    answers = harness.dispatch(_build_query(ptr_question, [other_ptr]))
    _report("same name, different PTR target", answers, harness)
    assert _response_buckets(answers)
    assert not _cache_snapshot(harness)

    # Same name, different record: A record address differs
    other_a = r.DNSAddress(
        SERVER_NAME, const._TYPE_A, const._CLASS_IN, const._DNS_HOST_TTL, socket.inet_aton("10.7.4.99")
    )
    answers = harness.dispatch(_build_query(a_question, [other_a]))
    _report("same name, different A address", answers, harness)
    assert _response_buckets(answers)
    assert not _cache_snapshot(harness)

    # Too-low TTL: exact PTR but TTL far below half of the real TTL
    low_ttl_ptr = r.DNSPointer(TYPE_, const._TYPE_PTR, const._CLASS_IN, 100, REGISTRATION_NAME)
    answers = harness.dispatch(_build_query(ptr_question, [low_ttl_ptr]))
    _report("exact PTR, TTL 100 (<< half of 4500)", answers, harness)
    assert _response_buckets(answers)
    assert not _cache_snapshot(harness)

    # Boundary: TTL exactly half does not suppress, half plus one does
    half_ttl_ptr = r.DNSPointer(TYPE_, const._TYPE_PTR, const._CLASS_IN, ptr_ttl // 2, REGISTRATION_NAME)
    answers = harness.dispatch(_build_query(ptr_question, [half_ttl_ptr]))
    _report(f"exact PTR, TTL {ptr_ttl // 2} (exactly half)", answers, harness)
    assert _response_buckets(answers)
    assert not _cache_snapshot(harness)

    over_half_ptr = r.DNSPointer(TYPE_, const._TYPE_PTR, const._CLASS_IN, ptr_ttl // 2 + 1, REGISTRATION_NAME)
    answers = harness.dispatch(_build_query(ptr_question, [over_half_ptr]))
    _report(f"exact PTR, TTL {ptr_ttl // 2 + 1} (half + 1)", answers, harness)
    assert not _response_buckets(answers)
    assert not _cache_snapshot(harness)


def test_known_answer_suppression_multi_packet_query() -> None:
    """Known answers split across packets of one query still suppress."""
    harness = _make_harness()
    info2 = make_service_info(
        TYPE_, f"knownname2.{TYPE_}", properties={"path": "/h2/"}, server="ash-3.local."
    )
    harness.registry.async_add(info2)

    ptr_question = r.DNSQuestion(TYPE_, const._TYPE_PTR, const._CLASS_IN)
    known = [
        r.DNSPointer(TYPE_, const._TYPE_PTR, const._CLASS_IN, const._DNS_OTHER_TTL, REGISTRATION_NAME),
        r.DNSPointer(TYPE_, const._TYPE_PTR, const._CLASS_IN, const._DNS_OTHER_TTL, f"knownname2.{TYPE_}"),
    ]
    msgs = _build_query(ptr_question, known, filler_answers=1000)
    assert len(msgs) > 1
    answers = harness.dispatch_batch(msgs)
    _report(f"multi-packet query ({len(msgs)} packets), both PTRs known", answers, harness)
    assert not _response_buckets(answers)
    assert not _cache_snapshot(harness)


def test_interleaved_requesters_and_query_answers_never_cached() -> None:
    """Interleaved requesters keep independent suppression; query answers never enter the cache."""
    harness = _make_harness()
    ptr_question = r.DNSQuestion(TYPE_, const._TYPE_PTR, const._CLASS_IN)
    exact_ptr = r.DNSPointer(TYPE_, const._TYPE_PTR, const._CLASS_IN, const._DNS_OTHER_TTL, REGISTRATION_NAME)

    # Requester A asks with a known answer, requester B asks with none, interleaved
    answers_a1 = harness.dispatch(_build_query(ptr_question, [exact_ptr]))
    _report("requester A (known answer)", answers_a1, harness)
    assert not _response_buckets(answers_a1)

    answers_b = harness.dispatch(_build_query(ptr_question))
    _report("requester B (no known answers)", answers_b, harness)
    assert _response_buckets(answers_b)

    answers_a2 = harness.dispatch(_build_query(ptr_question, [exact_ptr]))
    _report("requester A again (known answer)", answers_a2, harness)
    assert not _response_buckets(answers_a2)

    # No query answer was ever cached
    assert not _cache_snapshot(harness)

    # Contrast: the same record arriving in a response packet DOES populate the cache
    response = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    response.add_answer_at_time(exact_ptr, current_time_millis())
    harness.dispatch([r.DNSIncoming(response.packets()[0])])
    _report("same PTR injected as a response packet", None, harness)
    assert _cache_snapshot(harness)

"""Fake-clock tests for RFC 6762 §10.2 cache-flush handling of split address packets.

A service's A/AAAA RRset can span more than one mDNS response, and every
unique record carries the cache-flush bit. §10.2 therefore gives records
received within the last second a one-second grace period before a
conflicting flush may evict them, so a receiver that has only seen the
first packet must not tear down addresses the rest of the RRset is still
announcing. These tests drive the real RecordManager/DNSCache/browser with
fully controlled timestamps (no sockets, no wall clock) and pin:

* cache membership across the grace window and beyond it,
* the expiration instant recorded on the heap,
* the order in which browsing callbacks arrive, including that no
  spurious removal fires while the split second packet is outstanding.
"""

from __future__ import annotations

import socket

import pytest

import zeroconf as r
from zeroconf import Zeroconf, const
from zeroconf._cache import DNSCache
from zeroconf._handlers.record_manager import RecordManager
from zeroconf._record_update import RecordUpdate
from zeroconf._services import ServiceStateChange
from zeroconf._services.browser import _ServiceBrowserBase

CLASS_UNIQUE = const._CLASS_IN | const._CLASS_UNIQUE
HOST = "two-packet-host.local."
SERVICE_TYPE = "_http._tcp.local."
SERVICE_NAME = f"split.{SERVICE_TYPE}"
ADDR_1 = socket.inet_aton("10.7.4.2")
ADDR_2 = socket.inet_aton("10.7.4.3")
TTL = 120
# Arbitrary fixed origin; the fake clock only ever deals in offsets.
T0 = 100_000.0


class FakeLoop:
    """Loop stand-in; the browser only stores it, these tests never schedule timers."""

    def is_running(self) -> bool:
        return True


class FakeZeroconf:
    """Minimal Zeroconf stand-in: just the surface RecordManager touches."""

    def __init__(self) -> None:
        self.cache = DNSCache()
        self.loop = FakeLoop()
        self.done = False

    def async_notify_all(self) -> None:
        """No notify futures in these tests."""


class EventListener(r.RecordUpdateListener):
    """Record every RecordUpdate delivered, in order."""

    def __init__(self) -> None:
        self.events: list[tuple[str, r.DNSRecord, r.DNSRecord | None]] = []

    def async_update_records(self, zc: Zeroconf, now: float, records: list[RecordUpdate]) -> None:
        for update in records:
            self.events.append((type(update.new).__name__, update.new, update.old))


def address(addr: bytes, *, ttl: int = TTL) -> r.DNSAddress:
    return r.DNSAddress(HOST, const._TYPE_A, CLASS_UNIQUE, ttl, addr)


def response(now: float, *records: r.DNSRecord) -> r.DNSIncoming:
    """Encode records and decode them stamped with the fake clock's ``now``."""
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    for record in records:
        out.add_answer_at_time(record, 0)
    return r.DNSIncoming(out.packets()[0], now=now)


def cached_addresses(manager: RecordManager) -> set[bytes]:
    return {
        record.address
        for record in manager.cache.async_all_by_details(HOST, const._TYPE_A, const._CLASS_IN)
    }


def cached_records(manager: RecordManager) -> list[r.DNSAddress]:
    return manager.cache.async_all_by_details(HOST, const._TYPE_A, const._CLASS_IN)


@pytest.fixture
def manager() -> RecordManager:
    return RecordManager(FakeZeroconf())


def test_split_packet_first_flush_keeps_recent_address(manager: RecordManager) -> None:
    """A cache-flush packet cannot evict an address seen within the last second (RFC 6762 §10.2)."""
    listener = EventListener()
    manager.async_add_listener(listener, None)
    first = address(ADDR_1)
    second = address(ADDR_2)

    # Packet one: the host announces addr1 with the flush bit.
    manager.async_updates_from_response(response(T0, first))
    assert cached_addresses(manager) == {ADDR_1}
    (stamped_first,) = cached_records(manager)
    assert stamped_first.ttl == TTL
    assert stamped_first.created == T0
    first_expiry = manager.cache._expirations[stamped_first]
    assert first_expiry == T0 + TTL * 1000

    # Packet two (addr2) is delayed but arrives inside the 1s window. The
    # flush bit on addr2 must NOT shorten addr1's life: addr1 is still
    # fresh and the two records form one RRset.
    now = T0 + 500
    manager.async_updates_from_response(response(now, second))
    assert cached_addresses(manager) == {ADDR_1, ADDR_2}
    (stamped_first,) = [record for record in cached_records(manager) if record.address == ADDR_1]
    assert stamped_first.ttl == TTL
    assert manager.cache._expirations[stamped_first] == first_expiry

    # Every delivered update was an add (old is None); no goodbye or
    # restamp-to-expire was reported while the second packet was outstanding.
    assert {old for _, _, old in listener.events} == {None}
    assert all(not record.is_expired(now) for _, record, _ in listener.events)


def test_split_packet_flush_only_retires_genuinely_old_address(manager: RecordManager) -> None:
    """After the grace window a conflicting flush retires the old address one second later."""
    manager.async_updates_from_response(response(T0, address(ADDR_1)))

    # More than one second later, addr2 arrives in its own cache-flush
    # packet while addr1's packet is the only prior announcement.
    flush_now = T0 + 2000
    manager.async_updates_from_response(response(flush_now, address(ADDR_2)))

    old = [record for record in cached_records(manager) if record.address == ADDR_1]
    new = [record for record in cached_records(manager) if record.address == ADDR_2]
    assert len(old) == len(new) == 1
    # The old record is not deleted immediately: it is restamped to expire
    # in one second, preserving the short protection window.
    assert old[0].ttl == 1
    assert old[0].created == flush_now
    assert manager.cache._expirations[old[0]] == flush_now + 1000
    assert new[0].ttl == TTL

    # Before the extra second elapses the address is still cached (not
    # expired), so a ServiceInfo lookup would still see the host.
    assert manager.cache.async_expire(flush_now + 999) == []
    assert cached_addresses(manager) == {ADDR_1, ADDR_2}

    # Once the grace second passes the stale address disappears and the
    # fresh one remains.
    expired = manager.cache.async_expire(flush_now + 1000)
    assert [record.address for record in expired] == [ADDR_1]
    assert cached_addresses(manager) == {ADDR_2}


def test_duplicate_announcement_refreshes_instead_of_expiring(manager: RecordManager) -> None:
    """Re-announcing the same address inside and past 1s keeps it valid with a fresh TTL."""
    manager.async_updates_from_response(response(T0, address(ADDR_1)))
    (original,) = cached_records(manager)
    original_expiry = manager.cache._expirations[original]

    # Duplicate inside the window: answers_rrset excludes the record from
    # the flush sweep and the cache just refreshes TTL/created in place.
    duplicate_now = T0 + 500
    manager.async_updates_from_response(response(duplicate_now, address(ADDR_1)))
    (refreshed,) = cached_records(manager)
    assert refreshed == original
    assert refreshed.created == duplicate_now
    assert refreshed.ttl == TTL
    assert manager.cache._expirations[refreshed] == duplicate_now + TTL * 1000
    assert original_expiry != manager.cache._expirations[refreshed]
    assert len(cached_records(manager)) == 1

    # Duplicate well after 1s: the record is part of the packet's answer
    # set so it is never marked ttl=1 even though it is old.
    later = duplicate_now + 5000
    manager.async_updates_from_response(response(later, address(ADDR_1)))
    (refreshed,) = cached_records(manager)
    assert refreshed.ttl == TTL
    assert refreshed.created == later
    assert len(cached_records(manager)) == 1
    assert manager.cache.async_expire(later + 999) == []


def test_grace_window_is_strictly_more_than_one_second(manager: RecordManager) -> None:
    """The flush sweep keys on strictly more than 1s, so the 1000ms edge stays protected."""
    manager.async_updates_from_response(response(T0, address(ADDR_1)))

    # Exactly one second later: not yet eligible, the record keeps its TTL.
    manager.async_updates_from_response(response(T0 + const._ONE_SECOND, address(ADDR_2)))
    (edge_record,) = [record for record in cached_records(manager) if record.address == ADDR_1]
    assert edge_record.ttl == TTL

    # A fraction past one second: the same outstanding address is now retired.
    manager.async_updates_from_response(response(T0 + const._ONE_SECOND + 0.1, address(ADDR_2)))
    (retired,) = [record for record in cached_records(manager) if record.address == ADDR_1]
    assert retired.ttl == 1


def test_goodbye_removes_address_immediately(manager: RecordManager) -> None:
    """A TTL=0 goodbye removes the address at once and reports old -> expired."""
    listener = EventListener()
    manager.async_add_listener(listener, None)

    manager.async_updates_from_response(response(T0, address(ADDR_1)))
    assert cached_addresses(manager) == {ADDR_1}

    goodbye_now = T0 + 3000
    manager.async_updates_from_response(response(goodbye_now, address(ADDR_1, ttl=0)))

    assert cached_addresses(manager) == set()
    # The listener saw exactly one goodbye update carrying the cached old
    # record and an expired (ttl=0) new record.
    goodbye_events = [
        (record, old)
        for name, record, old in listener.events
        if name == "DNSAddress" and record.ttl == 0
    ]
    assert len(goodbye_events) == 1
    new_record, old_record = goodbye_events[0]
    assert old_record is not None and old_record.address == ADDR_1
    assert new_record.is_expired(goodbye_now)
    assert manager.cache.async_expire(goodbye_now + 10_000) == []


def test_natural_ttl_expiry_removes_address(manager: RecordManager) -> None:
    """An address that is never refreshed vanishes when its real TTL elapses."""
    manager.async_updates_from_response(response(T0, address(ADDR_1)))

    assert manager.cache.async_expire(T0 + TTL * 1000 - 1) == []
    assert cached_addresses(manager) == {ADDR_1}

    expired = manager.cache.async_expire(T0 + TTL * 1000)
    assert [record.address for record in expired] == [ADDR_1]
    assert cached_addresses(manager) == set()


class _Browser(_ServiceBrowserBase):
    """Browser base without the query-sender task; record callbacks in order."""

    def __init__(self, zc: Zeroconf, type_: str) -> None:
        self.collected: list[tuple[ServiceStateChange, str]] = []

        def _handler(
            zeroconf: Zeroconf, service_type: str, state_change: ServiceStateChange, name: str
        ) -> None:
            self.collected.append((state_change, name))

        super().__init__(zc, type_, [_handler])


def _service_bundle(now: float, addresses: list[bytes]) -> r.DNSIncoming:
    """Build a full service announcement: PTR, SRV, TXT and A records."""
    records = [
        r.DNSPointer(SERVICE_TYPE, const._TYPE_PTR, CLASS_UNIQUE, TTL, SERVICE_NAME, created=now),
        r.DNSService(
            SERVICE_NAME, const._TYPE_SRV, CLASS_UNIQUE, TTL, 0, 0, 80, HOST, created=now
        ),
        r.DNSText(SERVICE_NAME, const._TYPE_TXT, CLASS_UNIQUE, TTL, b"\x04path=/", created=now),
    ]
    records.extend(address(addr) for addr in addresses)
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    for record in records:
        out.add_answer_at_time(record, 0)
    return r.DNSIncoming(out.packets()[0], now=now)


def test_browser_callbacks_split_packet_then_goodbye_order(manager: RecordManager) -> None:
    """No Removed callback while the second address packet is outstanding; goodbye does fire Removed."""
    zc = manager.zc
    browser = _Browser(zc, SERVICE_TYPE)
    record_listener = EventListener()
    manager.async_add_listener(browser, None)
    manager.async_add_listener(record_listener, None)

    # Full service bundle with addr1 in packet one.
    manager.async_updates_from_response(_service_bundle(T0, [ADDR_1]))
    browser.async_update_records_complete()
    assert browser.collected == [(ServiceStateChange.Added, SERVICE_NAME)]

    # Packet two, inside the grace window: addr2's flush cannot evict addr1.
    # The browser only sees an Updated driven by the new address, never a
    # Removed, and the record stream carries the addr2 add with no goodbye.
    manager.async_updates_from_response(response(T0 + 500, address(ADDR_2)))
    browser.async_update_records_complete()
    assert browser.collected == [
        (ServiceStateChange.Added, SERVICE_NAME),
        (ServiceStateChange.Updated, SERVICE_NAME),
    ]
    assert any(
        isinstance(record, r.DNSAddress) and record.address == ADDR_2 and old is None
        for _, record, old in record_listener.events
    )
    assert all(not record.is_expired(T0 + 500) for _, record, _ in record_listener.events)
    assert cached_addresses(manager) == {ADDR_1, ADDR_2}

    # A genuine goodbye for the PTR flips the service to Removed, in order.
    goodbye_now = T0 + 4000
    ptr_goodbye = r.DNSPointer(
        SERVICE_TYPE, const._TYPE_PTR, CLASS_UNIQUE, 0, SERVICE_NAME, created=goodbye_now
    )
    manager.async_updates_from_response(response(goodbye_now, ptr_goodbye))
    browser.async_update_records_complete()
    assert browser.collected == [
        (ServiceStateChange.Added, SERVICE_NAME),
        (ServiceStateChange.Updated, SERVICE_NAME),
        (ServiceStateChange.Removed, SERVICE_NAME),
    ]


def test_browser_old_address_flush_emits_update_not_removal(manager: RecordManager) -> None:
    """An old address retired past the grace window surfaces as Updated, not a service Removed."""
    zc = manager.zc
    browser = _Browser(zc, SERVICE_TYPE)
    manager.async_add_listener(browser, None)

    manager.async_updates_from_response(_service_bundle(T0, [ADDR_1]))
    browser.async_update_records_complete()

    # addr2 arrives >1s later; addr1 is restamped ttl=1 but stays cached
    # until the reaper runs, so the browser still only reports Updated.
    manager.async_updates_from_response(response(T0 + 2000, address(ADDR_2)))
    browser.async_update_records_complete()
    assert browser.collected == [
        (ServiceStateChange.Added, SERVICE_NAME),
        (ServiceStateChange.Updated, SERVICE_NAME),
    ]

    # When the reaper finally expires addr1 it hands the browser an update
    # whose old record equals the new one; the browser ignores address
    # records that already existed, so no spurious Removed is synthesized.
    now = T0 + 3000
    expired = manager.cache.async_expire(now)
    assert [record.address for record in expired] == [ADDR_1]
    manager.async_updates(now, [RecordUpdate(record, record) for record in expired])
    browser.async_update_records_complete()
    assert ServiceStateChange.Removed not in [state for state, _ in browser.collected]
    assert cached_addresses(manager) == {ADDR_2}

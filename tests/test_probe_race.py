"""Replayable registration-race tests for RFC 6762 probe tiebreaking.

Two devices probing the same instance name at the same time must decide
between keeping the name, renaming, or failing based on whether the
peer's records are identical (RFC 6762 §9.2) or conflicting. These tests
run without sockets: every outgoing packet is recorded and every peer
packet is injected through the real listener at a chosen moment.
"""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio

import zeroconf as r
from zeroconf import const
from zeroconf._engine import AsyncEngine
from zeroconf._exceptions import NonUniqueNameException
from zeroconf._listener import AsyncListener
from zeroconf._transport import make_wrapped_transport
from zeroconf.asyncio import AsyncZeroconf

from . import make_service_info

_TYPE = "_probe-race._tcp.local."
_NAME = "racer"
_FULL_NAME = f"{_NAME}.{_TYPE}"
_RENAMED_NAME = f"{_NAME}-2.{_TYPE}"
_PEER_ADDR = ("127.0.0.1", const._MDNS_PORT)


class _FakeDatagramTransport:
    """DatagramTransport stand-in that records sends instead of touching a socket."""

    def __init__(self, recorder: PacketRecorder, sock: MagicMock) -> None:
        self._recorder = recorder
        self._sock = sock

    def sendto(self, data: bytes, addr: tuple) -> None:
        self._recorder.record_outgoing(data)

    def close(self) -> None:
        pass

    def get_extra_info(self, name: str) -> MagicMock | None:
        return self._sock if name == "socket" else None


class PacketRecorder:
    """Ordered log of every packet the local stack transmits."""

    def __init__(self) -> None:
        self.packets: list[r.DNSIncoming] = []

    def record_outgoing(self, data: bytes) -> None:
        self.packets.append(r.DNSIncoming(data))

    def probes(self, name: str | None = None) -> list[r.DNSIncoming]:
        return [
            msg
            for msg in self.packets
            if msg.is_probe() and (name is None or name in _ptr_aliases(msg))
        ]

    def ptr_ttls(self, name: str) -> list[int]:
        """TTLs of transmitted PTR records for ``name``; zero marks a goodbye."""
        ttls: list[int] = []
        for msg in self.packets:
            if not msg.is_response():
                continue
            for record in msg.answers():
                if record.type == const._TYPE_PTR and getattr(record, "alias", None) == name:
                    ttls.append(record.ttl)
                    break
        return ttls

    def announces(self, name: str) -> list[r.DNSIncoming]:
        return [
            msg
            for msg in self.packets
            if msg.is_response()
            and any(
                record.type == const._TYPE_PTR and getattr(record, "alias", None) == name
                for record in msg.answers()
            )
        ]

    def goodbyes(self, name: str) -> list[r.DNSIncoming]:
        return [msg for msg in self.announces(name) if all(record.ttl == 0 for record in msg.answers())]


class ProbeRaceHarness:
    """A running AsyncZeroconf on fake sockets, its packet log, and peer injection."""

    def __init__(self, aiozc: AsyncZeroconf, recorder: PacketRecorder) -> None:
        self.aiozc = aiozc
        self.zc = aiozc.zeroconf
        self.recorder = recorder

    def inject_peer(self, packet: bytes) -> None:
        """Deliver a peer packet at this exact point in the replay."""
        self.zc.engine.protocols[0].datagram_received(packet, _PEER_ADDR)

    def registered_names(self) -> list[str]:
        """Instance names currently held in the local service registry."""
        return [info.name for info in self.zc.registry.async_get_service_infos()]

    async def close(self) -> None:
        await self.aiozc.async_close()


def _ptr_aliases(msg: r.DNSIncoming) -> set[str]:
    return {
        getattr(record, "alias", None)
        for record in msg.answers()
        if record.type == const._TYPE_PTR
    }


def _fake_socket(name: tuple[str, int], fileno: int) -> MagicMock:
    sock = MagicMock(spec=socket.socket)
    sock.family = socket.AF_INET
    sock.type = socket.SOCK_DGRAM
    sock.proto = socket.IPPROTO_UDP
    sock.fileno.return_value = fileno
    sock.getsockname.return_value = name
    sock.getsockopt.return_value = 0
    return sock


def _install_fake_endpoints(recorder: PacketRecorder):
    async def fake_wrap_socket(self: AsyncEngine, sock: MagicMock, is_sender: bool):
        protocol = AsyncListener(self.zc)
        transport = _FakeDatagramTransport(recorder, sock)
        protocol.connection_made(transport)
        reader = make_wrapped_transport(transport)
        self.protocols.append(protocol)
        self.readers.append(reader)
        if is_sender:
            self.senders.append(make_wrapped_transport(transport))
        return reader

    return patch.object(AsyncEngine, "_async_wrap_socket", fake_wrap_socket)


def peer_probe_packet(info: r.ServiceInfo) -> bytes:
    """Build a peer probe: QU question plus the peer's claimed PTR authority."""
    out = r.DNSOutgoing(const._FLAGS_QR_QUERY | const._FLAGS_AA)
    out.add_question(r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN | const._CLASS_UNIQUE))
    out.add_authorative_answer(info.dns_pointer())
    return out.packets()[0]


def peer_response_packet(info: r.ServiceInfo) -> bytes:
    """Build a peer multicast response carrying the peer's full record set."""
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    for record in (
        info.dns_pointer(),
        info.dns_service(),
        info.dns_text(),
        *info.get_address_and_nsec_records(),
    ):
        out.add_answer_at_time(record, 0)
    return out.packets()[0]


def identical_peer() -> r.ServiceInfo:
    return make_service_info(_TYPE, _FULL_NAME)


def conflicting_peer() -> r.ServiceInfo:
    return make_service_info(
        _TYPE,
        _FULL_NAME,
        server="peer-rig.local.",
        addresses=[socket.inet_aton("10.9.9.9")],
    )


@pytest_asyncio.fixture
async def probe_race_harness() -> ProbeRaceHarness:
    recorder = PacketRecorder()
    with (
        patch(
            "zeroconf._core.create_sockets",
            return_value=(
                _fake_socket(("0.0.0.0", const._MDNS_PORT), 11),
                [_fake_socket(("127.0.0.1", const._MDNS_PORT), 22)],
            ),
        ),
        _install_fake_endpoints(recorder),
        patch("zeroconf._core._CHECK_TIME", 10),
        patch("zeroconf._core._REGISTER_TIME", 10),
        patch("zeroconf._core._UNREGISTER_TIME", 10),
        patch("zeroconf._core._PROBE_RANDOM_DELAY_INTERVAL", (1, 5)),
    ):
        aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
        await aiozc.zeroconf.async_wait_for_start()
        try:
            yield ProbeRaceHarness(aiozc, recorder)
        finally:
            await aiozc.async_close()


async def _wait_until(predicate, timeout: float = 2.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.002)
    return False


@pytest.mark.asyncio
async def test_identical_probe_keeps_name_and_announces(probe_race_harness: ProbeRaceHarness) -> None:
    """Same-content peer records are not a conflict (RFC 6762 §9.2): keep the name."""
    harness = probe_race_harness
    info = make_service_info(_TYPE, _FULL_NAME)
    register_task = asyncio.ensure_future(harness.aiozc.async_register_service(info))
    assert await _wait_until(lambda: len(harness.recorder.probes()) >= 1)

    harness.inject_peer(peer_response_packet(identical_peer()))

    assert await _wait_until(register_task.done)
    assert register_task.exception() is None
    assert info.name == _FULL_NAME
    assert harness.registered_names() == [_FULL_NAME]
    assert len(harness.recorder.probes(_FULL_NAME)) == 3
    assert await _wait_until(
        lambda: harness.recorder.ptr_ttls(_FULL_NAME).count(const._DNS_OTHER_TTL) == 3
    )
    assert harness.recorder.ptr_ttls(_RENAMED_NAME) == []


@pytest.mark.asyncio
async def test_identical_probe_emits_goodbye_only_for_held_name(
    probe_race_harness: ProbeRaceHarness,
) -> None:
    """After an identical-probe win, close() sends goodbyes for the held name only."""
    harness = probe_race_harness
    info = make_service_info(_TYPE, _FULL_NAME)
    register_task = asyncio.ensure_future(harness.aiozc.async_register_service(info))
    assert await _wait_until(lambda: len(harness.recorder.probes()) >= 1)
    harness.inject_peer(peer_response_packet(identical_peer()))
    assert await _wait_until(register_task.done)
    assert register_task.exception() is None
    assert await _wait_until(
        lambda: harness.recorder.ptr_ttls(_FULL_NAME).count(const._DNS_OTHER_TTL) == 3
    )
    assert harness.recorder.goodbyes(_FULL_NAME) == []

    await harness.close()

    assert len(harness.recorder.goodbyes(_FULL_NAME)) == 3
    assert harness.recorder.goodbyes(_RENAMED_NAME) == []


@pytest.mark.asyncio
async def test_conflicting_probe_fails_without_rename(probe_race_harness: ProbeRaceHarness) -> None:
    """Different peer records fail registration when renaming is disallowed."""
    harness = probe_race_harness
    info = make_service_info(_TYPE, _FULL_NAME)
    register_task = asyncio.ensure_future(
        harness.aiozc.async_register_service(info, allow_name_change=False)
    )
    assert await _wait_until(lambda: len(harness.recorder.probes()) >= 1)

    harness.inject_peer(peer_response_packet(conflicting_peer()))

    assert await _wait_until(register_task.done)
    assert isinstance(register_task.exception(), NonUniqueNameException)
    assert info.name == _FULL_NAME
    assert harness.registered_names() == []
    assert len(harness.recorder.probes(_FULL_NAME)) == 1
    assert harness.recorder.announces(_FULL_NAME) == []
    assert harness.recorder.announces(_RENAMED_NAME) == []
    assert harness.recorder.goodbyes(_FULL_NAME) == []
    assert harness.recorder.goodbyes(_RENAMED_NAME) == []


@pytest.mark.asyncio
async def test_conflicting_probe_renames_and_never_announces_lost_name(
    probe_race_harness: ProbeRaceHarness,
) -> None:
    """A losing host renames and only announces/goodbyes the name it ended up holding."""
    harness = probe_race_harness
    info = make_service_info(_TYPE, _FULL_NAME)
    register_task = asyncio.ensure_future(
        harness.aiozc.async_register_service(info, allow_name_change=True)
    )
    assert await _wait_until(lambda: len(harness.recorder.probes(_FULL_NAME)) >= 1)

    harness.inject_peer(peer_response_packet(conflicting_peer()))

    assert await _wait_until(register_task.done)
    assert register_task.exception() is None
    assert info.name == _RENAMED_NAME
    assert harness.registered_names() == [_RENAMED_NAME]
    assert len(harness.recorder.probes(_FULL_NAME)) == 1
    assert len(harness.recorder.probes(_RENAMED_NAME)) == 3
    assert harness.recorder.announces(_FULL_NAME) == []
    assert await _wait_until(
        lambda: harness.recorder.ptr_ttls(_RENAMED_NAME).count(const._DNS_OTHER_TTL) == 3
    )
    assert harness.recorder.goodbyes(_FULL_NAME) == []

    await harness.close()

    assert harness.registered_names() == []
    assert harness.recorder.goodbyes(_FULL_NAME) == []
    assert len(harness.recorder.goodbyes(_RENAMED_NAME)) == 3


@pytest.mark.asyncio
async def test_peer_probe_then_identical_records_does_not_conflict(
    probe_race_harness: ProbeRaceHarness,
) -> None:
    """A probe packet followed by identical records is treated as cooperative, not conflicting."""
    harness = probe_race_harness
    info = make_service_info(_TYPE, _FULL_NAME)
    register_task = asyncio.ensure_future(harness.aiozc.async_register_service(info))
    assert await _wait_until(lambda: len(harness.recorder.probes()) >= 1)

    # The bare probe carries only the PTR authority; the following response
    # supplies the full identical record set the tiebreak compares against.
    harness.inject_peer(peer_probe_packet(identical_peer()))
    harness.inject_peer(peer_response_packet(identical_peer()))

    assert await _wait_until(register_task.done)
    assert register_task.exception() is None
    assert info.name == _FULL_NAME
    assert len(harness.recorder.probes(_FULL_NAME)) == 3
    assert harness.recorder.ptr_ttls(_RENAMED_NAME) == []


@pytest.mark.asyncio
async def test_identical_probe_unregister_goodbyes_held_name(
    probe_race_harness: ProbeRaceHarness,
) -> None:
    """An explicit unregister after winning the race withdraws only the held name."""
    harness = probe_race_harness
    info = make_service_info(_TYPE, _FULL_NAME)
    register_task = asyncio.ensure_future(harness.aiozc.async_register_service(info))
    assert await _wait_until(lambda: len(harness.recorder.probes()) >= 1)
    harness.inject_peer(peer_response_packet(identical_peer()))
    assert await _wait_until(register_task.done)
    assert register_task.exception() is None
    assert await _wait_until(lambda: len(harness.recorder.announces(_FULL_NAME)) == 3)
    harness.recorder.packets.clear()

    unregister_task = await harness.aiozc.async_unregister_service(info)
    await unregister_task

    assert harness.registered_names() == []
    assert len(harness.recorder.goodbyes(_FULL_NAME)) == 3
    assert harness.recorder.goodbyes(_RENAMED_NAME) == []


@pytest.mark.asyncio
async def test_bare_ptr_peer_claim_is_a_conflict(probe_race_harness: ProbeRaceHarness) -> None:
    """A cached PTR without the matching SRV/TXT records cannot prove identical content."""
    harness = probe_race_harness
    info = make_service_info(_TYPE, _FULL_NAME)
    register_task = asyncio.ensure_future(
        harness.aiozc.async_register_service(info, allow_name_change=False)
    )
    assert await _wait_until(lambda: len(harness.recorder.probes()) >= 1)

    bare_ptr = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    bare_ptr.add_answer_at_time(info.dns_pointer(), 0)
    harness.inject_peer(bare_ptr.packets()[0])

    assert await _wait_until(register_task.done)
    assert isinstance(register_task.exception(), NonUniqueNameException)
    assert harness.recorder.announces(_FULL_NAME) == []


@pytest.mark.asyncio
async def test_same_name_different_txt_is_a_conflict(probe_race_harness: ProbeRaceHarness) -> None:
    """Identical SRV/addresses but different TXT content still loses the name."""
    harness = probe_race_harness
    txt_peer = make_service_info(_TYPE, _FULL_NAME, properties={"path": "/different/"})
    harness.inject_peer(peer_response_packet(txt_peer))

    info = make_service_info(_TYPE, _FULL_NAME)
    register_task = asyncio.ensure_future(
        harness.aiozc.async_register_service(info, allow_name_change=True)
    )
    assert await _wait_until(register_task.done)
    assert register_task.exception() is None
    assert info.name == _RENAMED_NAME
    assert harness.registered_names() == [_RENAMED_NAME]
    assert harness.recorder.announces(_FULL_NAME) == []


@pytest.mark.asyncio
async def test_conflict_after_name_won_governs_next_registration(
    probe_race_harness: ProbeRaceHarness,
) -> None:
    """A conflicting claim arriving after a name is held fails the next probe and forces a rename."""
    harness = probe_race_harness
    first = make_service_info(_TYPE, _FULL_NAME)
    first_task = asyncio.ensure_future(harness.aiozc.async_register_service(first))
    assert await _wait_until(first_task.done)
    assert first_task.exception() is None
    assert await _wait_until(lambda: len(harness.recorder.announces(_FULL_NAME)) == 3)
    harness.recorder.packets.clear()

    late_peer = make_service_info(
        _TYPE,
        _FULL_NAME,
        server="late-peer.local.",
        addresses=[socket.inet_aton("172.16.0.4")],
    )
    harness.inject_peer(peer_response_packet(late_peer))

    contender = make_service_info(_TYPE, _FULL_NAME)
    with pytest.raises(NonUniqueNameException):
        await harness.aiozc.async_register_service(contender, allow_name_change=False)
    assert harness.recorder.announces(_FULL_NAME) == []

    renaming = make_service_info(_TYPE, _FULL_NAME)
    rename_task = asyncio.ensure_future(
        harness.aiozc.async_register_service(renaming, allow_name_change=True)
    )
    assert await _wait_until(rename_task.done)
    assert rename_task.exception() is None
    assert renaming.name == _RENAMED_NAME
    assert len(harness.recorder.probes(_RENAMED_NAME)) == 3

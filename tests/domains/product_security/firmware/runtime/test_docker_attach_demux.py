from __future__ import annotations

import socket
import struct
import threading
from collections import deque

import pytest

from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError
from strix.domains.product_security.firmware.runtime.docker_attach import (
    AsyncDockerAttachSession,
    DockerRawStreamDecoder,
    SocketDockerAttachSession,
)


def _docker_frame(payload: bytes, *, stream_type: int = 1, reserved: bytes = b"\0\0\0") -> bytes:
    return bytes([stream_type]) + reserved + struct.pack(">I", len(payload)) + payload


class FakeSocket:
    def __init__(self, incoming: list[bytes] | None = None, *, send_limit: int = 3) -> None:
        self.incoming = deque(incoming or [])
        self.send_limit = send_limit
        self.sent = bytearray()
        self.shutdown_how: int | None = None
        self.close_count = 0

    def send(self, data: bytes | memoryview) -> int:
        count = min(self.send_limit, len(data))
        self.sent.extend(data[:count])
        return count

    def recv(self, maximum: int) -> bytes:
        if not self.incoming:
            return b""
        chunk = self.incoming.popleft()
        if len(chunk) > maximum:
            self.incoming.appendleft(chunk[maximum:])
            return chunk[:maximum]
        return chunk

    def shutdown(self, how: int) -> None:
        self.shutdown_how = how

    def close(self) -> None:
        self.close_count += 1


def test_decoder_parses_exact_docker_stdout_header() -> None:
    decoder = DockerRawStreamDecoder()

    assert decoder.feed(_docker_frame(b"FWAP")) == [b"FWAP"]
    decoder.finish()
    assert decoder.buffered_bytes == 0


def test_decoder_accepts_fragmented_header_and_payload() -> None:
    decoder = DockerRawStreamDecoder()
    decoded: list[bytes] = []

    for value in _docker_frame(b"fragmented"):
        decoded.extend(decoder.feed(bytes([value])))

    assert decoded == [b"fragmented"]


def test_decoder_returns_multiple_frames_from_one_chunk() -> None:
    decoder = DockerRawStreamDecoder()

    decoded = decoder.feed(_docker_frame(b"one") + _docker_frame(b"two"))

    assert decoded == [b"one", b"two"]


def test_zero_length_frame_does_not_look_like_socket_eof() -> None:
    raw_socket = FakeSocket([_docker_frame(b"") + _docker_frame(b"data")])
    session = SocketDockerAttachSession(raw_socket)

    assert session.read_stdout(4) == b"data"


@pytest.mark.parametrize(
    "frame",
    [
        _docker_frame(b"stderr", stream_type=2),
        _docker_frame(b"unknown", stream_type=3),
        _docker_frame(b"reserved", reserved=b"\0\1\0"),
    ],
)
def test_decoder_rejects_non_stdout_and_nonzero_reserved_bytes(frame: bytes) -> None:
    with pytest.raises(FWAPProtocolError) as exc_info:
        DockerRawStreamDecoder().feed(frame)
    assert exc_info.value.error_code == "FWAP_BAD_DOCKER_STREAM"


def test_decoder_rejects_payload_overlimit_before_body() -> None:
    header = bytes([1, 0, 0, 0]) + struct.pack(">I", 5)

    with pytest.raises(FWAPProtocolError) as exc_info:
        DockerRawStreamDecoder(max_payload_bytes=4).feed(header)
    assert exc_info.value.error_code == "FWAP_BAD_DOCKER_STREAM"


@pytest.mark.parametrize("data", [b"\x01", _docker_frame(b"payload")[:-1]])
def test_decoder_rejects_eof_mid_header_or_payload(data: bytes) -> None:
    decoder = DockerRawStreamDecoder()
    decoder.feed(data)

    with pytest.raises(FWAPProtocolError) as exc_info:
        decoder.finish()
    assert exc_info.value.error_code == "FWAP_BAD_DOCKER_STREAM"


def test_socket_session_completes_short_writes() -> None:
    raw_socket = FakeSocket(send_limit=2)
    session = SocketDockerAttachSession(raw_socket)

    session.write_all(b"complete-write")

    assert raw_socket.sent == b"complete-write"


def test_socket_session_demuxes_and_honors_read_limit() -> None:
    encoded = _docker_frame(b"abcdef")
    raw_socket = FakeSocket([encoded[:5], encoded[5:]])
    session = SocketDockerAttachSession(raw_socket, socket_read_bytes=4)

    assert session.read_stdout(3) == b"abc"
    assert session.read_stdout(3) == b"def"
    assert session.read_stdout(3) == b""


def test_socket_session_shutdown_and_close_are_idempotent() -> None:
    raw_socket = FakeSocket()
    session = SocketDockerAttachSession(raw_socket)

    session.shutdown_write()
    session.close()
    session.close()

    assert raw_socket.shutdown_how == socket.SHUT_WR
    assert raw_socket.close_count == 1


def test_socket_session_rejects_write_after_shutdown() -> None:
    session = SocketDockerAttachSession(FakeSocket())
    session.shutdown_write()

    with pytest.raises(FWAPProtocolError):
        session.write_all(b"late")


class BrokenSocket(FakeSocket):
    def send(self, _data: bytes | memoryview) -> int:
        raise OSError("connection lost")


def test_socket_errors_map_to_stable_transport_error() -> None:
    session = SocketDockerAttachSession(BrokenSocket())

    with pytest.raises(FWAPProtocolError) as exc_info:
        session.write_all(b"data")
    assert exc_info.value.error_code == "FWAP_BAD_DOCKER_STREAM"
    assert "connection lost" not in exc_info.value.message


class ThreadRecordingSession:
    def __init__(self) -> None:
        self.called_thread: int | None = None

    def write_all(self, _data: bytes) -> None:
        self.called_thread = threading.get_ident()

    def read_stdout(self, _max_bytes: int) -> bytes:
        self.called_thread = threading.get_ident()
        return b""

    def shutdown_write(self) -> None:
        self.called_thread = threading.get_ident()

    def close(self) -> None:
        self.called_thread = threading.get_ident()


@pytest.mark.asyncio
async def test_async_facade_moves_blocking_calls_off_event_loop() -> None:
    blocking = ThreadRecordingSession()
    session = AsyncDockerAttachSession(blocking)
    event_loop_thread = threading.get_ident()

    await session.write_all(b"data")

    assert blocking.called_thread is not None
    assert blocking.called_thread != event_loop_thread

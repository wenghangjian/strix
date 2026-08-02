"""Bounded Docker attach raw-stream transport."""

from __future__ import annotations

import asyncio
import socket
from collections import deque
from typing import Never, Protocol

from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError


DOCKER_HEADER_SIZE = 8
DOCKER_STDOUT_STREAM = 1
MAXIMUM_DECODED_STDOUT_BYTES = 2 * 1024 * 1024
DEFAULT_SOCKET_READ_BYTES = 64 * 1024


class DockerAttachSession(Protocol):
    def write_all(self, data: bytes) -> None: ...

    def read_stdout(self, max_bytes: int) -> bytes: ...

    def shutdown_write(self) -> None: ...

    def close(self) -> None: ...


class _SocketLike(Protocol):
    def send(self, data: bytes | memoryview) -> int: ...

    def recv(self, maximum: int) -> bytes: ...

    def shutdown(self, how: int) -> None: ...

    def close(self) -> None: ...


class DockerRawStreamDecoder:
    def __init__(self, *, max_payload_bytes: int = MAXIMUM_DECODED_STDOUT_BYTES) -> None:
        if max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")
        self._max_payload_bytes = max_payload_bytes
        self._header = bytearray()
        self._payload = bytearray()
        self._expected_payload: int | None = None

    @property
    def buffered_bytes(self) -> int:
        return len(self._header) + len(self._payload)

    def feed(self, data: bytes) -> list[bytes]:
        view = memoryview(data)
        cursor = 0
        decoded: list[bytes] = []
        decoded_bytes = 0
        try:
            while cursor < len(view):
                if self._expected_payload is None:
                    needed = DOCKER_HEADER_SIZE - len(self._header)
                    consumed = min(needed, len(view) - cursor)
                    self._header.extend(view[cursor : cursor + consumed])
                    cursor += consumed
                    if len(self._header) < DOCKER_HEADER_SIZE:
                        break
                    self._expected_payload = self._parse_header()
                    self._header.clear()
                    if self._expected_payload == 0:
                        self._expected_payload = None
                        continue

                needed = self._expected_payload - len(self._payload)
                consumed = min(needed, len(view) - cursor)
                self._payload.extend(view[cursor : cursor + consumed])
                cursor += consumed
                if len(self._payload) < self._expected_payload:
                    break

                decoded_bytes += len(self._payload)
                if decoded_bytes > self._max_payload_bytes:
                    _raise_bad_stream("Decoded Docker stdout exceeds its buffer limit.")
                decoded.append(bytes(self._payload))
                self._payload.clear()
                self._expected_payload = None
        except FWAPProtocolError:
            self._reset()
            raise
        return decoded

    def finish(self) -> None:
        if self._header or self._expected_payload is not None:
            self._reset()
            _raise_bad_stream("Docker raw stream ended in a partial frame.")

    def _parse_header(self) -> int:
        stream_type = self._header[0]
        if stream_type != DOCKER_STDOUT_STREAM:
            _raise_bad_stream("Docker raw stream contains a non-stdout frame.")
        if bytes(self._header[1:4]) != b"\0\0\0":
            _raise_bad_stream("Docker raw stream reserved bytes are non-zero.")
        payload_length = int.from_bytes(self._header[4:8], "big")
        if payload_length > self._max_payload_bytes:
            _raise_bad_stream("Docker raw stream payload exceeds its limit.")
        return payload_length

    def _reset(self) -> None:
        self._header.clear()
        self._payload.clear()
        self._expected_payload = None


class SocketDockerAttachSession:
    def __init__(
        self,
        raw_socket: _SocketLike,
        *,
        socket_read_bytes: int = DEFAULT_SOCKET_READ_BYTES,
        max_decoded_bytes: int = MAXIMUM_DECODED_STDOUT_BYTES,
    ) -> None:
        if socket_read_bytes <= 0 or socket_read_bytes > max_decoded_bytes:
            raise ValueError("socket_read_bytes must fit inside the decoded buffer limit")
        self._socket = raw_socket
        self._socket_read_bytes = socket_read_bytes
        self._max_decoded_bytes = max_decoded_bytes
        self._decoder = DockerRawStreamDecoder(max_payload_bytes=max_decoded_bytes)
        self._stdout = deque[bytes]()
        self._queued_bytes = 0
        self._eof = False
        self._write_shutdown = False
        self._closed = False

    def write_all(self, data: bytes) -> None:
        self._require_open()
        if self._write_shutdown:
            _raise_bad_stream("Docker attach socket is closed for writing.")
        view = memoryview(data)
        sent = 0
        try:
            while sent < len(view):
                count = self._socket.send(view[sent:])
                if count <= 0:
                    _raise_bad_stream("Docker attach socket closed during write.")
                sent += count
        except OSError as exc:
            _raise_socket_error(exc)

    def read_stdout(self, max_bytes: int) -> bytes:
        self._require_open()
        if max_bytes <= 0 or max_bytes > self._max_decoded_bytes:
            raise ValueError("max_bytes must fit inside the decoded buffer limit")

        while not self._stdout:
            if self._eof:
                return b""
            try:
                raw = self._socket.recv(self._socket_read_bytes)
            except OSError as exc:
                _raise_socket_error(exc)
            if not raw:
                self._decoder.finish()
                self._eof = True
                return b""
            decoded = self._decoder.feed(raw)
            for chunk in decoded:
                self._stdout.append(chunk)
                self._queued_bytes += len(chunk)
            if self._queued_bytes > self._max_decoded_bytes:
                self._stdout.clear()
                self._queued_bytes = 0
                _raise_bad_stream("Decoded Docker stdout exceeds its buffer limit.")

        chunk = self._stdout.popleft()
        if len(chunk) > max_bytes:
            result = chunk[:max_bytes]
            self._stdout.appendleft(chunk[max_bytes:])
        else:
            result = chunk
        self._queued_bytes -= len(result)
        return result

    def shutdown_write(self) -> None:
        self._require_open()
        if self._write_shutdown:
            return
        try:
            self._socket.shutdown(socket.SHUT_WR)
        except OSError as exc:
            _raise_socket_error(exc)
        self._write_shutdown = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._socket.close()
        except OSError as exc:
            _raise_socket_error(exc)

    def _require_open(self) -> None:
        if self._closed:
            _raise_bad_stream("Docker attach session is closed.")


class AsyncDockerAttachSession:
    def __init__(self, blocking_session: DockerAttachSession) -> None:
        self._session = blocking_session

    async def write_all(self, data: bytes) -> None:
        await asyncio.to_thread(self._session.write_all, data)

    async def read_stdout(self, max_bytes: int) -> bytes:
        return await asyncio.to_thread(self._session.read_stdout, max_bytes)

    async def shutdown_write(self) -> None:
        await asyncio.to_thread(self._session.shutdown_write)

    async def close(self) -> None:
        await asyncio.to_thread(self._session.close)


def _raise_socket_error(error: OSError) -> Never:
    raise FWAPProtocolError(
        "FWAP_BAD_DOCKER_STREAM",
        "Docker attach socket operation failed.",
    ) from error


def _raise_bad_stream(message: str) -> Never:
    raise FWAPProtocolError("FWAP_BAD_DOCKER_STREAM", message)

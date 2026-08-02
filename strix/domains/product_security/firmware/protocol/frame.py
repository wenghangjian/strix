"""Bounded incremental FWAP 1.0 frame encoding and decoding."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from strix.domains.product_security.firmware.protocol.constants import (
    GLOBAL_MAX_PAYLOAD,
    HEADER_SIZE,
    KNOWN_FLAG_MASK,
    MAGIC,
    MESSAGE_PAYLOAD_LIMITS,
    PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
    UINT32_MAX,
    FrameFlags,
    MessageType,
)
from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError


HEADER_STRUCT = struct.Struct(">4sBBBBIIQII")
HEADER_PREFIX_STRUCT = struct.Struct(">4sBBBBIIQI")
assert HEADER_STRUCT.size == HEADER_SIZE
assert HEADER_PREFIX_STRUCT.size == 28


class Frame(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True)

    message_type: MessageType
    flags: FrameFlags = FrameFlags.NONE
    stream_id: int = Field(ge=0, le=UINT32_MAX)
    sequence: int = Field(ge=0, le=UINT32_MAX)
    payload: bytes = Field(max_length=GLOBAL_MAX_PAYLOAD)


class FrameEncoder:
    @staticmethod
    def encode(frame: Frame) -> bytes:
        payload_length = len(frame.payload)
        _require_known_flags(int(frame.flags))
        _require_payload_limit(frame.message_type, payload_length)
        payload_crc = _crc32(frame.payload)
        prefix = HEADER_PREFIX_STRUCT.pack(
            MAGIC,
            PROTOCOL_MAJOR,
            PROTOCOL_MINOR,
            int(frame.message_type),
            int(frame.flags),
            frame.stream_id,
            frame.sequence,
            payload_length,
            payload_crc,
        )
        return prefix + struct.pack(">I", _crc32(prefix)) + frame.payload


@dataclass(frozen=True, slots=True)
class _PendingHeader:
    message_type: MessageType
    flags: FrameFlags
    stream_id: int
    sequence: int
    payload_length: int
    payload_crc: int


class FrameDecoder:
    def __init__(self) -> None:
        self._buffer = bytearray()
        self._pending: _PendingHeader | None = None

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> list[Frame]:
        self._buffer.extend(data)
        decoded: list[Frame] = []
        try:
            while True:
                if self._pending is None:
                    if len(self._buffer) < HEADER_SIZE:
                        break
                    raw_header = bytes(self._buffer[:HEADER_SIZE])
                    del self._buffer[:HEADER_SIZE]
                    self._pending = _decode_header(raw_header)

                pending = self._pending
                if len(self._buffer) < pending.payload_length:
                    break
                payload = bytes(self._buffer[: pending.payload_length])
                del self._buffer[: pending.payload_length]
                _require_payload_crc(payload, pending.payload_crc)
                decoded.append(
                    Frame(
                        message_type=pending.message_type,
                        flags=pending.flags,
                        stream_id=pending.stream_id,
                        sequence=pending.sequence,
                        payload=payload,
                    )
                )
                self._pending = None
        except (FWAPProtocolError, ValueError):
            self._buffer.clear()
            self._pending = None
            raise
        return decoded

    def finish(self) -> None:
        if self._pending is not None:
            self._buffer.clear()
            self._pending = None
            raise FWAPProtocolError(
                "FWAP_TRUNCATED_PAYLOAD",
                "FWAP stream ended before the declared payload was complete.",
            )
        if self._buffer:
            self._buffer.clear()
            raise FWAPProtocolError(
                "FWAP_TRUNCATED_HEADER",
                "FWAP stream ended before a complete header was received.",
            )


class FrameSequenceValidator:
    def __init__(self) -> None:
        self._expected = 0

    def accept(self, frame: Frame) -> None:
        if self._expected > UINT32_MAX or frame.sequence != self._expected:
            raise FWAPProtocolError(
                "FWAP_SEQUENCE_MISMATCH",
                f"FWAP sequence expected {self._expected}, received {frame.sequence}.",
            )
        self._expected += 1


def _decode_header(raw_header: bytes) -> _PendingHeader:
    if _crc32(raw_header[:28]) != struct.unpack(">I", raw_header[28:32])[0]:
        raise FWAPProtocolError(
            "FWAP_BAD_HEADER_CRC",
            "FWAP header CRC is invalid.",
        )
    (
        magic,
        major,
        minor,
        raw_message_type,
        raw_flags,
        stream_id,
        sequence,
        payload_length,
        payload_crc,
        _,
    ) = HEADER_STRUCT.unpack(raw_header)
    if magic != MAGIC:
        raise FWAPProtocolError("FWAP_BAD_MAGIC", "FWAP header has invalid magic bytes.")
    if (major, minor) != (PROTOCOL_MAJOR, PROTOCOL_MINOR):
        raise FWAPProtocolError(
            "FWAP_UNSUPPORTED_VERSION",
            f"FWAP version {major}.{minor} is not supported.",
        )
    try:
        message_type = MessageType(raw_message_type)
    except ValueError as exc:
        raise FWAPProtocolError(
            "FWAP_UNKNOWN_MESSAGE",
            f"FWAP message type {raw_message_type} is unknown.",
        ) from exc
    _require_known_flags(raw_flags)
    _require_payload_limit(message_type, payload_length)
    return _PendingHeader(
        message_type=message_type,
        flags=FrameFlags(raw_flags),
        stream_id=stream_id,
        sequence=sequence,
        payload_length=payload_length,
        payload_crc=payload_crc,
    )


def _require_known_flags(raw_flags: int) -> None:
    if raw_flags & ~int(KNOWN_FLAG_MASK):
        raise FWAPProtocolError(
            "FWAP_BAD_FLAGS",
            f"FWAP flags 0x{raw_flags:02x} contain unsupported bits.",
        )


def _require_payload_limit(message_type: MessageType, payload_length: int) -> None:
    maximum = min(GLOBAL_MAX_PAYLOAD, MESSAGE_PAYLOAD_LIMITS[message_type])
    if payload_length > maximum:
        raise FWAPProtocolError(
            "FWAP_PAYLOAD_TOO_LARGE",
            f"FWAP {message_type.name} payload exceeds its {maximum}-byte limit.",
        )


def _require_payload_crc(payload: bytes, expected_crc: int) -> None:
    if _crc32(payload) != expected_crc:
        raise FWAPProtocolError(
            "FWAP_BAD_PAYLOAD_CRC",
            "FWAP payload CRC does not match its header.",
        )


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & UINT32_MAX

"""Normative FWAP 1.0 constants and limits."""

from __future__ import annotations

from enum import IntEnum, IntFlag


MAGIC = b"FWAP"
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0
HEADER_SIZE = 32
GLOBAL_MAX_PAYLOAD = 8 * 1024 * 1024
UINT32_MAX = (1 << 32) - 1


class MessageType(IntEnum):
    HELLO = 0x01
    HELLO_ACK = 0x02
    ANALYSIS_REQUEST = 0x03
    REQUEST_ACCEPTED = 0x04
    INPUT_BEGIN = 0x05
    INPUT_CHUNK = 0x06
    INPUT_END = 0x07
    INPUT_ACCEPTED = 0x08
    MANIFEST = 0x09
    MANIFEST_ACCEPTED = 0x0A
    BLOB_BEGIN = 0x0B
    BLOB_CHUNK = 0x0C
    BLOB_END = 0x0D
    PROGRESS = 0x0E
    RESULT = 0x0F
    ERROR = 0x10
    CANCEL = 0x11


class FrameFlags(IntFlag):
    NONE = 0
    JSON_PAYLOAD = 0x01
    FINAL = 0x02


KNOWN_FLAG_MASK = FrameFlags.JSON_PAYLOAD | FrameFlags.FINAL

MESSAGE_PAYLOAD_LIMITS: dict[MessageType, int] = {
    MessageType.HELLO: 64 * 1024,
    MessageType.HELLO_ACK: 64 * 1024,
    MessageType.ANALYSIS_REQUEST: 256 * 1024,
    MessageType.REQUEST_ACCEPTED: 64 * 1024,
    MessageType.INPUT_BEGIN: 64 * 1024,
    MessageType.INPUT_CHUNK: 1024 * 1024,
    MessageType.INPUT_END: 64 * 1024,
    MessageType.INPUT_ACCEPTED: 64 * 1024,
    MessageType.MANIFEST: GLOBAL_MAX_PAYLOAD,
    MessageType.MANIFEST_ACCEPTED: 64 * 1024,
    MessageType.BLOB_BEGIN: 64 * 1024,
    MessageType.BLOB_CHUNK: 1024 * 1024,
    MessageType.BLOB_END: 64 * 1024,
    MessageType.PROGRESS: 16 * 1024,
    MessageType.RESULT: 256 * 1024,
    MessageType.ERROR: 64 * 1024,
    MessageType.CANCEL: 64 * 1024,
}

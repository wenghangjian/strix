from __future__ import annotations

import struct
import zlib

import pytest

from strix.domains.product_security.firmware.protocol.constants import (
    HEADER_SIZE,
    FrameFlags,
    MessageType,
)
from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError
from strix.domains.product_security.firmware.protocol.frame import (
    Frame,
    FrameDecoder,
    FrameEncoder,
    FrameSequenceValidator,
)


def _frame(
    *,
    sequence: int = 0,
    payload: bytes = b"{}",
    message_type: MessageType = MessageType.HELLO,
) -> Frame:
    return Frame(
        message_type=message_type,
        flags=FrameFlags.JSON_PAYLOAD,
        stream_id=0,
        sequence=sequence,
        payload=payload,
    )


def _assert_error(data: bytes, error_code: str) -> None:
    with pytest.raises(FWAPProtocolError) as exc_info:
        FrameDecoder().feed(data)
    assert exc_info.value.error_code == error_code


def test_header_is_exactly_32_bytes_and_big_endian() -> None:
    encoded = FrameEncoder.encode(_frame(sequence=0x01020304, payload=b"{}"))

    assert encoded[:4] == b"FWAP"
    assert HEADER_SIZE == 32
    assert encoded[12:16] == b"\x01\x02\x03\x04"
    assert encoded[16:24] == b"\x00\x00\x00\x00\x00\x00\x00\x02"
    assert len(encoded[:HEADER_SIZE]) == HEADER_SIZE


def test_decoder_accepts_one_byte_at_a_time() -> None:
    expected = _frame(payload=b'{"hello":"worker"}')
    decoder = FrameDecoder()
    decoded: list[Frame] = []

    for value in FrameEncoder.encode(expected):
        decoded.extend(decoder.feed(bytes([value])))

    decoder.finish()
    assert decoded == [expected]
    assert decoder.buffered_bytes == 0


def test_decoder_returns_multiple_frames_from_one_chunk() -> None:
    frames = [
        _frame(sequence=0, payload=b"{}"),
        _frame(sequence=1, payload=b"raw", message_type=MessageType.INPUT_CHUNK),
    ]
    encoded = b"".join(FrameEncoder.encode(frame) for frame in frames)

    assert FrameDecoder().feed(encoded) == frames


def test_empty_payload_has_zero_crc() -> None:
    encoded = FrameEncoder.encode(
        Frame(
            message_type=MessageType.CANCEL,
            flags=FrameFlags.FINAL,
            stream_id=0,
            sequence=0,
            payload=b"",
        )
    )

    assert encoded[24:28] == b"\x00\x00\x00\x00"
    assert FrameDecoder().feed(encoded)[0].payload == b""


@pytest.mark.parametrize(
    ("offset", "replacement", "error_code"),
    [
        (0, b"NOPE", "FWAP_BAD_MAGIC"),
        (4, b"\x02", "FWAP_UNSUPPORTED_VERSION"),
        (7, b"\x80", "FWAP_BAD_FLAGS"),
    ],
)
def test_decoder_rejects_invalid_header_fields(
    offset: int,
    replacement: bytes,
    error_code: str,
) -> None:
    encoded = bytearray(FrameEncoder.encode(_frame()))
    encoded[offset : offset + len(replacement)] = replacement
    prefix = bytes(encoded[:28])
    encoded[28:32] = struct.pack(">I", zlib.crc32(prefix) & 0xFFFFFFFF)

    _assert_error(bytes(encoded), error_code)


def test_decoder_rejects_bad_header_crc() -> None:
    encoded = bytearray(FrameEncoder.encode(_frame()))
    encoded[28] ^= 0x01

    _assert_error(bytes(encoded), "FWAP_BAD_HEADER_CRC")


def test_decoder_rejects_bad_payload_crc() -> None:
    encoded = bytearray(FrameEncoder.encode(_frame(payload=b"payload")))
    encoded[-1] ^= 0x01

    _assert_error(bytes(encoded), "FWAP_BAD_PAYLOAD_CRC")


def test_decoder_rejects_message_specific_payload_overlimit_before_body() -> None:
    encoded = bytearray(FrameEncoder.encode(_frame()))
    encoded[16:24] = struct.pack(">Q", 65 * 1024)
    encoded[28:32] = struct.pack(">I", zlib.crc32(bytes(encoded[:28])) & 0xFFFFFFFF)

    _assert_error(bytes(encoded[:HEADER_SIZE]), "FWAP_PAYLOAD_TOO_LARGE")


@pytest.mark.parametrize(
    ("data", "error_code"),
    [
        (b"FWAP", "FWAP_TRUNCATED_HEADER"),
        (FrameEncoder.encode(_frame(payload=b"payload"))[:-1], "FWAP_TRUNCATED_PAYLOAD"),
    ],
)
def test_finish_rejects_truncated_frame(data: bytes, error_code: str) -> None:
    decoder = FrameDecoder()
    decoder.feed(data)

    with pytest.raises(FWAPProtocolError) as exc_info:
        decoder.finish()
    assert exc_info.value.error_code == error_code


def test_sequence_validator_rejects_skip_and_repeat() -> None:
    validator = FrameSequenceValidator()
    validator.accept(_frame(sequence=0))

    with pytest.raises(FWAPProtocolError, match="sequence") as skipped:
        validator.accept(_frame(sequence=2))
    assert skipped.value.error_code == "FWAP_SEQUENCE_MISMATCH"

    validator = FrameSequenceValidator()
    validator.accept(_frame(sequence=0))
    with pytest.raises(FWAPProtocolError) as repeated:
        validator.accept(_frame(sequence=0))
    assert repeated.value.error_code == "FWAP_SEQUENCE_MISMATCH"

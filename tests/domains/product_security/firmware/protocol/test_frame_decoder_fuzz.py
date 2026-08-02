from __future__ import annotations

import contextlib
import random

from strix.domains.product_security.firmware.protocol.constants import HEADER_SIZE
from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError
from strix.domains.product_security.firmware.protocol.frame import FrameDecoder


def test_deterministic_random_input_never_grows_decoder_unbounded() -> None:
    randomizer = random.Random(20260802)  # noqa: S311 - deterministic parser fuzzing

    for _ in range(512):
        decoder = FrameDecoder()
        data = randomizer.randbytes(randomizer.randrange(0, 512))
        with contextlib.suppress(FWAPProtocolError):
            decoder.feed(data)
        assert decoder.buffered_bytes <= HEADER_SIZE

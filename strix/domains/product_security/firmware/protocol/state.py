"""Explicit fail-closed state machines for both FWAP endpoints."""

from __future__ import annotations

from enum import StrEnum
from typing import Never

from strix.domains.product_security.firmware.protocol.constants import MessageType
from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError


class HostState(StrEnum):
    CREATED = "created"
    CONTAINER_STARTED = "container_started"
    ATTACHED = "attached"
    HELLO_SENT = "hello_sent"
    HELLO_CONFIRMED = "hello_confirmed"
    REQUEST_SENT = "request_sent"
    REQUEST_ACCEPTED = "request_accepted"
    INPUT_STREAMING = "input_streaming"
    INPUT_CONFIRMED = "input_confirmed"
    WAITING_MANIFEST = "waiting_manifest"
    MANIFEST_VALIDATED = "manifest_validated"
    RECEIVING_BLOBS = "receiving_blobs"
    RESULT_RECEIVED = "result_received"
    OUTPUT_VERIFIED = "output_verified"
    COMMITTING = "committing"
    COMPLETE = "complete"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    PROTOCOL_ERROR = "protocol_error"
    WORKER_ERROR = "worker_error"
    CONTAINER_ERROR = "container_error"
    OUTPUT_REJECTED = "output_rejected"
    CORRUPT = "corrupt"


class WorkerState(StrEnum):
    WAIT_HELLO = "wait_hello"
    WAIT_REQUEST = "wait_request"
    WAIT_INPUT_BEGIN = "wait_input_begin"
    RECEIVE_INPUT = "receive_input"
    VERIFY_INPUT = "verify_input"
    ANALYZE = "analyze"
    WAIT_MANIFEST_ACCEPTANCE = "wait_manifest_acceptance"
    EXPORT_BLOBS = "export_blobs"
    SEND_RESULT = "send_result"
    EXIT = "exit"


_HOST_MESSAGE_TRANSITIONS: dict[tuple[HostState, MessageType], HostState] = {
    (HostState.HELLO_SENT, MessageType.HELLO_ACK): HostState.HELLO_CONFIRMED,
    (HostState.REQUEST_SENT, MessageType.REQUEST_ACCEPTED): HostState.REQUEST_ACCEPTED,
    (HostState.INPUT_STREAMING, MessageType.INPUT_ACCEPTED): HostState.INPUT_CONFIRMED,
    (HostState.WAITING_MANIFEST, MessageType.PROGRESS): HostState.WAITING_MANIFEST,
    (HostState.WAITING_MANIFEST, MessageType.MANIFEST): HostState.MANIFEST_VALIDATED,
    (HostState.RECEIVING_BLOBS, MessageType.BLOB_BEGIN): HostState.RECEIVING_BLOBS,
    (HostState.RECEIVING_BLOBS, MessageType.BLOB_CHUNK): HostState.RECEIVING_BLOBS,
    (HostState.RECEIVING_BLOBS, MessageType.BLOB_END): HostState.RECEIVING_BLOBS,
    (HostState.RECEIVING_BLOBS, MessageType.RESULT): HostState.RESULT_RECEIVED,
}

_HOST_ERROR_STATES = (
    HostState.HELLO_SENT,
    HostState.HELLO_CONFIRMED,
    HostState.REQUEST_SENT,
    HostState.REQUEST_ACCEPTED,
    HostState.INPUT_STREAMING,
    HostState.INPUT_CONFIRMED,
    HostState.WAITING_MANIFEST,
    HostState.MANIFEST_VALIDATED,
    HostState.RECEIVING_BLOBS,
)
_HOST_MESSAGE_TRANSITIONS.update(
    {(state, MessageType.ERROR): HostState.WORKER_ERROR for state in _HOST_ERROR_STATES}
)

_HOST_INTERNAL_TRANSITIONS: dict[HostState, HostState] = {
    HostState.CREATED: HostState.CONTAINER_STARTED,
    HostState.CONTAINER_STARTED: HostState.ATTACHED,
    HostState.ATTACHED: HostState.HELLO_SENT,
    HostState.HELLO_CONFIRMED: HostState.REQUEST_SENT,
    HostState.REQUEST_ACCEPTED: HostState.INPUT_STREAMING,
    HostState.INPUT_CONFIRMED: HostState.WAITING_MANIFEST,
    HostState.MANIFEST_VALIDATED: HostState.RECEIVING_BLOBS,
    HostState.RESULT_RECEIVED: HostState.OUTPUT_VERIFIED,
    HostState.OUTPUT_VERIFIED: HostState.COMMITTING,
    HostState.COMMITTING: HostState.COMPLETE,
}

_WORKER_MESSAGE_TRANSITIONS: dict[tuple[WorkerState, MessageType], WorkerState] = {
    (WorkerState.WAIT_HELLO, MessageType.HELLO): WorkerState.WAIT_REQUEST,
    (WorkerState.WAIT_REQUEST, MessageType.ANALYSIS_REQUEST): WorkerState.WAIT_INPUT_BEGIN,
    (WorkerState.WAIT_INPUT_BEGIN, MessageType.INPUT_BEGIN): WorkerState.RECEIVE_INPUT,
    (WorkerState.RECEIVE_INPUT, MessageType.INPUT_CHUNK): WorkerState.RECEIVE_INPUT,
    (WorkerState.RECEIVE_INPUT, MessageType.INPUT_END): WorkerState.VERIFY_INPUT,
    (
        WorkerState.WAIT_MANIFEST_ACCEPTANCE,
        MessageType.MANIFEST_ACCEPTED,
    ): WorkerState.EXPORT_BLOBS,
}
_WORKER_ACTIVE_STATES = tuple(state for state in WorkerState if state is not WorkerState.EXIT)
_WORKER_MESSAGE_TRANSITIONS.update(
    {(state, MessageType.CANCEL): WorkerState.EXIT for state in _WORKER_ACTIVE_STATES}
)

_WORKER_INTERNAL_TRANSITIONS: dict[WorkerState, WorkerState] = {
    WorkerState.VERIFY_INPUT: WorkerState.ANALYZE,
    WorkerState.ANALYZE: WorkerState.WAIT_MANIFEST_ACCEPTANCE,
    WorkerState.EXPORT_BLOBS: WorkerState.SEND_RESULT,
    WorkerState.SEND_RESULT: WorkerState.EXIT,
}


class HostStateMachine:
    def __init__(self, *, initial_state: HostState = HostState.CREATED) -> None:
        self.state = initial_state

    def accept(self, message_type: MessageType) -> None:
        next_state = _HOST_MESSAGE_TRANSITIONS.get((self.state, message_type))
        if next_state is None:
            _raise_unexpected_message(self.state, message_type)
        self.state = next_state

    def advance(self, target: HostState) -> None:
        expected = _HOST_INTERNAL_TRANSITIONS.get(self.state)
        if expected is not target:
            _raise_unexpected_state(self.state, target)
        self.state = target


class WorkerStateMachine:
    def __init__(self, *, initial_state: WorkerState = WorkerState.WAIT_HELLO) -> None:
        self.state = initial_state

    def accept(self, message_type: MessageType) -> None:
        next_state = _WORKER_MESSAGE_TRANSITIONS.get((self.state, message_type))
        if next_state is None:
            _raise_unexpected_message(self.state, message_type)
        self.state = next_state

    def advance(self, target: WorkerState) -> None:
        expected = _WORKER_INTERNAL_TRANSITIONS.get(self.state)
        if expected is not target:
            _raise_unexpected_state(self.state, target)
        self.state = target


def _raise_unexpected_message(state: StrEnum, message_type: MessageType) -> Never:
    raise FWAPProtocolError(
        "FWAP_UNEXPECTED_MESSAGE",
        f"FWAP {message_type.name} is not permitted in state {state.value}.",
    )


def _raise_unexpected_state(state: StrEnum, target: StrEnum) -> Never:
    raise FWAPProtocolError(
        "FWAP_UNEXPECTED_STATE",
        f"FWAP state {state.value} cannot advance to {target.value}.",
    )

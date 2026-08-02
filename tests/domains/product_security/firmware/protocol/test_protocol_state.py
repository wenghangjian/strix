from __future__ import annotations

import pytest

from strix.domains.product_security.firmware.protocol.constants import MessageType
from strix.domains.product_security.firmware.protocol.errors import FWAPProtocolError
from strix.domains.product_security.firmware.protocol.state import (
    HostState,
    HostStateMachine,
    WorkerState,
    WorkerStateMachine,
)


HOST_MESSAGES: dict[HostState, set[MessageType]] = {
    HostState.HELLO_SENT: {MessageType.HELLO_ACK, MessageType.ERROR},
    HostState.HELLO_CONFIRMED: {MessageType.ERROR},
    HostState.REQUEST_SENT: {MessageType.REQUEST_ACCEPTED, MessageType.ERROR},
    HostState.REQUEST_ACCEPTED: {MessageType.ERROR},
    HostState.INPUT_STREAMING: {MessageType.INPUT_ACCEPTED, MessageType.ERROR},
    HostState.INPUT_CONFIRMED: {MessageType.ERROR},
    HostState.WAITING_MANIFEST: {
        MessageType.PROGRESS,
        MessageType.MANIFEST,
        MessageType.ERROR,
    },
    HostState.MANIFEST_VALIDATED: {MessageType.ERROR},
    HostState.RECEIVING_BLOBS: {
        MessageType.BLOB_BEGIN,
        MessageType.BLOB_CHUNK,
        MessageType.BLOB_END,
        MessageType.RESULT,
        MessageType.ERROR,
    },
}

WORKER_MESSAGES: dict[WorkerState, set[MessageType]] = {
    WorkerState.WAIT_HELLO: {MessageType.HELLO, MessageType.CANCEL},
    WorkerState.WAIT_REQUEST: {MessageType.ANALYSIS_REQUEST, MessageType.CANCEL},
    WorkerState.WAIT_INPUT_BEGIN: {MessageType.INPUT_BEGIN, MessageType.CANCEL},
    WorkerState.RECEIVE_INPUT: {
        MessageType.INPUT_CHUNK,
        MessageType.INPUT_END,
        MessageType.CANCEL,
    },
    WorkerState.VERIFY_INPUT: {MessageType.CANCEL},
    WorkerState.ANALYZE: {MessageType.CANCEL},
    WorkerState.WAIT_MANIFEST_ACCEPTANCE: {MessageType.MANIFEST_ACCEPTED, MessageType.CANCEL},
    WorkerState.EXPORT_BLOBS: {MessageType.CANCEL},
    WorkerState.SEND_RESULT: {MessageType.CANCEL},
}


def test_complete_valid_host_flow() -> None:
    machine = HostStateMachine()

    machine.advance(HostState.CONTAINER_STARTED)
    machine.advance(HostState.ATTACHED)
    machine.advance(HostState.HELLO_SENT)
    machine.accept(MessageType.HELLO_ACK)
    machine.advance(HostState.REQUEST_SENT)
    machine.accept(MessageType.REQUEST_ACCEPTED)
    machine.advance(HostState.INPUT_STREAMING)
    machine.accept(MessageType.INPUT_ACCEPTED)
    machine.advance(HostState.WAITING_MANIFEST)
    machine.accept(MessageType.PROGRESS)
    machine.accept(MessageType.PROGRESS)
    machine.accept(MessageType.MANIFEST)
    machine.advance(HostState.RECEIVING_BLOBS)
    machine.accept(MessageType.BLOB_BEGIN)
    machine.accept(MessageType.BLOB_CHUNK)
    machine.accept(MessageType.BLOB_END)
    machine.accept(MessageType.RESULT)
    machine.advance(HostState.OUTPUT_VERIFIED)
    machine.advance(HostState.COMMITTING)
    machine.advance(HostState.COMPLETE)

    assert machine.state is HostState.COMPLETE


def test_complete_valid_worker_flow() -> None:
    machine = WorkerStateMachine()

    machine.accept(MessageType.HELLO)
    machine.accept(MessageType.ANALYSIS_REQUEST)
    machine.accept(MessageType.INPUT_BEGIN)
    machine.accept(MessageType.INPUT_CHUNK)
    machine.accept(MessageType.INPUT_CHUNK)
    machine.accept(MessageType.INPUT_END)
    machine.advance(WorkerState.ANALYZE)
    machine.advance(WorkerState.WAIT_MANIFEST_ACCEPTANCE)
    machine.accept(MessageType.MANIFEST_ACCEPTED)
    machine.advance(WorkerState.SEND_RESULT)
    machine.advance(WorkerState.EXIT)

    assert machine.state is WorkerState.EXIT


@pytest.mark.parametrize("state", list(HostState))
@pytest.mark.parametrize("message_type", list(MessageType))
def test_every_invalid_host_state_message_pair_is_rejected(
    state: HostState,
    message_type: MessageType,
) -> None:
    if message_type in HOST_MESSAGES.get(state, set()):
        return

    machine = HostStateMachine(initial_state=state)
    with pytest.raises(FWAPProtocolError) as exc_info:
        machine.accept(message_type)
    assert exc_info.value.error_code == "FWAP_UNEXPECTED_MESSAGE"
    assert machine.state is state


@pytest.mark.parametrize("state", list(WorkerState))
@pytest.mark.parametrize("message_type", list(MessageType))
def test_every_invalid_worker_state_message_pair_is_rejected(
    state: WorkerState,
    message_type: MessageType,
) -> None:
    if message_type in WORKER_MESSAGES.get(state, set()):
        return

    machine = WorkerStateMachine(initial_state=state)
    with pytest.raises(FWAPProtocolError) as exc_info:
        machine.accept(message_type)
    assert exc_info.value.error_code == "FWAP_UNEXPECTED_MESSAGE"
    assert machine.state is state


def test_streaming_states_only_accept_declared_repeatable_messages() -> None:
    host = HostStateMachine(initial_state=HostState.WAITING_MANIFEST)
    host.accept(MessageType.PROGRESS)
    assert host.state is HostState.WAITING_MANIFEST

    worker = WorkerStateMachine(initial_state=WorkerState.RECEIVE_INPUT)
    worker.accept(MessageType.INPUT_CHUNK)
    assert worker.state is WorkerState.RECEIVE_INPUT


def test_worker_cancel_exits_from_active_state() -> None:
    machine = WorkerStateMachine(initial_state=WorkerState.ANALYZE)

    machine.accept(MessageType.CANCEL)

    assert machine.state is WorkerState.EXIT


def test_invalid_internal_transition_is_rejected_without_state_change() -> None:
    machine = HostStateMachine()

    with pytest.raises(FWAPProtocolError) as exc_info:
        machine.advance(HostState.ATTACHED)

    assert exc_info.value.error_code == "FWAP_UNEXPECTED_STATE"
    assert machine.state is HostState.CREATED

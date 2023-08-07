import logging
from returns.result import Result, Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_owner_agent_and_her_device_and_attacker,
)
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.storage.secure_db import SecureDB
import ureka_framework.data_model.ticket as ticket
from typing import Iterator


class TestArbitraryInput:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self) -> Iterator[None]:
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SecureDB.delete_secure_db_in_test()

        # GIVEN: Initialized DO's UA and DO's IoTD
        # GIVEN: Initialized ATK's CS
        current_test_given_log()
        (
            self.user_agent_do,
            self.iot_device,
            self.cloud_server_atk,
        ) = device_owner_agent_and_her_device_and_attacker()

        # WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SecureDB.delete_secure_db_in_test()

    def test_apply_wrong_ticket_schema(self) -> None:
        # WHEN: Not fit with json format '{"key": "value"}'
        current_test_when_and_then_log()
        test_ticket: str = "WRONG-TICKET-SCHEMA"
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Fail to do anything on DO's IoTD
        assert type(result) == Failure

    def test_apply_wrong_ticket_protocol_version(self) -> None:
        # WHEN: Wrong ticket protocol version
        current_test_when_and_then_log()
        test_ticket: str = (
            '{"ticket_protocol_verision": "WRONG-TICKET-PROTOCOL-VERSION"}'
        )
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Fail to do anything on DO's IoTD
        assert type(result) == Failure

    def test_apply_wrong_ticket_type(self) -> None:
        # WHEN: Wrong ticket type
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"",
            "holder_id": f"",
            "ticket_type": f"WRONG-TICKET-TYPE",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_atk.generate_xxx_ticket(test_request)
        # logging.warning(f"test_ticket: {test_ticket}")
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Fail to do anything on DO's IoTD
        assert type(result) == Failure

    def test_apply_wrong_device_id(self) -> None:
        # WHEN: Wrong ticket type
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"WRONG-DEVICE-ID",
            "holder_id": f"",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_atk.generate_xxx_ticket(test_request)
        # logging.warning(f"test_ticket: {test_ticket}")
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Fail to do anything on DO's IoTD
        assert type(result) == Failure

    @pytest.mark.skip(reason="Not implemented yet")
    def test_apply_no_signature(self) -> None:
        # WHEN: ...
        current_test_when_and_then_log()

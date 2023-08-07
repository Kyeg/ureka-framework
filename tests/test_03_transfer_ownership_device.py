import logging
from returns.result import Result, Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_owner_agent,
    device_manufacturer_server,
    device_manufacturer_server_and_her_device,
    device_owner_agent_and_her_device,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.storage.secure_db import SecureDB
from typing import Iterator


class TestTransferOwnershipDevice:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self) -> Iterator[None]:
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SecureDB.delete_secure_db_in_test()

        # GIVEN+WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SecureDB.delete_secure_db_in_test()

    def test_apply_management_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # GIVEN: Initialized DO's UA
        self.user_agent_do = device_owner_agent()

        # WHEN: DM's CS allow DO's UA to apply_management_ticket() on DM's IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER})}",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert type(result) == Success
        assert (
            self.iot_device.owner_pub_key_str == self.user_agent_do.device_pub_key_str
        )

    def test_apply_management_ticket_wrong_owner_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: DO's UA do not allow DM's CS to apply_management_ticket() on DO's IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_dm.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER})}",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        logging.warning(f"test_ticket: {test_ticket}")
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Fail to transfer ownership (still DO's IoTD)
        assert type(result) == Failure
        assert (
            self.iot_device.owner_pub_key_str == self.user_agent_do.device_pub_key_str
        )

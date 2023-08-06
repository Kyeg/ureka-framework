from returns.result import Result, Success, Failure
import pytest
import logging
from tests.conftest import current_setup_log, current_teardown_log, current_test_log
from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.storage.secure_db import SecureDB


class TestTransferOwnershipDevice:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self):
        # GIVEN: (A') Initialized DM's CS
        current_setup_log()
        SecureDB.delete_secure_db_in_test()
        self.cloud_server_dm = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_dm",
        )
        self.cloud_server_dm.execute_one_time_intialize_agent_or_server()

        # GIVEN: (A') Initialized DO's UA
        self.user_agent_do = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="user_agent_do",
        )
        self.user_agent_do.execute_one_time_intialize_agent_or_server()

        # GIVEN: (B') Initialized DM's IoTD
        self.iot_device = DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
        )
        test_request: dict = {
            "device_id": f"",
            "holder_id": f"{self.cloud_server_dm.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_INITIALIZATION_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        self.iot_device.verify_xxx_ticket(test_ticket)

        # (GIVEN)+WHEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SecureDB.delete_secure_db_in_test()

    def test_apply_management_ticket(self) -> None:
        # WHEN: DM's CS apply_management_ticket() on DM's IoTD
        current_test_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER})}",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B'') Initialized DO's IoTD
        assert type(result) == Success
        assert (
            self.iot_device.owner_pub_key_str == self.user_agent_do.device_pub_key_str
        )

    def test_apply_management_ticket_failed(self) -> None:
        # GIVEN: (B'') Initialized DO's IoTD
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER})}",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        self.iot_device.verify_xxx_ticket(test_ticket)

        # WHEN: DM's CS apply_management_ticket() on DO's IoTD
        current_test_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER})}",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B'') Initialized DO's IoTD
        assert type(result) == Failure

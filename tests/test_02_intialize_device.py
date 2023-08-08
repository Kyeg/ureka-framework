from returns.result import Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
    device_manufacturer_server_and_her_device,
)
from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.storage.secure_db import SecureDB
from typing import Iterator


class TestIntializeDevice:
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

    def test_apply_initialization_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
        )
        assert self.iot_device.this_device.is_initialized == False
        assert self.iot_device.this_device.device_priv_key_str == ""
        assert self.iot_device.this_device.device_pub_key_str == ""
        assert self.iot_device.this_device.owner_pub_key_str == ""
        assert self.iot_device.this_person.person_priv_key_str == ""
        assert self.iot_device.this_person.person_pub_key_str == ""

        # WHEN: DM's CS apply_initialization_ticket() on Uninitialized IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_INITIALIZATION_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Succeed to initialize DM's IoTD
        assert type(result) == Success
        assert self.iot_device.this_device.is_initialized == True
        assert self.iot_device.this_device.device_priv_key_str != ""
        assert self.iot_device.this_device.device_pub_key_str != ""
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.cloud_server_dm.this_person.person_pub_key_str
        )
        assert self.iot_device.this_person.person_priv_key_str == ""
        assert self.iot_device.this_person.person_pub_key_str == ""

    def test_intialize_device_with_reboot(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # WHEN: DM reboot the CS
        current_test_when_and_then_log()
        self.iot_device.reboot_device()

        # THEN: Still is initialized  IoTD
        assert self.iot_device.this_device.is_initialized == True
        assert self.iot_device.this_device.device_priv_key_str != ""
        assert self.iot_device.this_device.device_pub_key_str != ""
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.cloud_server_dm.this_person.person_pub_key_str
        )
        assert self.iot_device.this_person.person_priv_key_str == ""
        assert self.iot_device.this_person.person_pub_key_str == ""

    def test_apply_initialization_ticket_reintialized_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # WHEN: DM's CS apply_initialization_ticket() on Initialized IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_INITIALIZATION_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Failed to re-initialize DM's IoTD
        assert type(result) == Failure

    def test_apply_initialization_ticket_to_agent_or_server_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized UA
        self.user_agent = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="user_agent",
        )

        # WHEN: DM's CS apply_initialization_ticket() on UA
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_INITIALIZATION_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        result = self.user_agent.verify_xxx_ticket(test_ticket)

        # THEN: Failed to initialize UA
        assert type(result) == Failure

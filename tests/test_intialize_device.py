from returns.result import Result, Success, Failure
import pytest
from tests.conftest import current_setup_log, current_teardown_log, current_test_log
from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.storage.secure_db import SecureDB


class TestIntializeDevice:
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

        # GIVEN: (B) Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
        )

        # (GIVEN)+WHEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SecureDB.delete_secure_db_in_test()

    def test_apply_initialization_ticket(self) -> None:
        # WHEN: DM's CS apply_initialization_ticket() on Uninitialized IoTD
        current_test_log()
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization", holder_id=self.cloud_server_dm.device_pub_key_str
        )
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B') Initialized DM's IoTD
        assert type(result) == Success
        assert self.iot_device.is_initialized == True
        assert self.iot_device.device_priv_key_str != ""
        assert self.iot_device.device_pub_key_str != ""
        assert (
            self.iot_device.owner_pub_key_str == self.cloud_server_dm.device_pub_key_str
        )

    def test_apply_initialization_ticket_reintialized_failed(self) -> None:
        # GIVEN: (B') Initialized DM's IoTD
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization", holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # WHEN: DM's CS apply_initialization_ticket() on Initialized IoTD
        current_test_log()
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization", holder_id=self.cloud_server_dm.device_pub_key_str
        )
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B') Cannot re-initialize DM's IoTD
        assert type(result) == Failure

    def test_apply_initialization_ticket_initialize_user_or_server_failed(self) -> None:
        # GIVEN: (B') A CS or UA
        self.user_agent_do = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="user_agent_do",
        )
        self.user_agent_do.execute_one_time_intialize_agent_or_server()

        # WHEN: DM's CS apply_initialization_ticket() on Initialized UA's Agent
        current_test_log()
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization", holder_id=self.cloud_server_dm.device_pub_key_str
        )
        result = self.user_agent_do.verify_xxx_ticket(test_ticket)

        # THEN: (B') Cannot initialize CS or UA
        assert type(result) == Failure

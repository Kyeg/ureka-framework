from returns.result import Result, Success, Failure
import pytest
import logging
from tests.conftest import current_setup_log, current_teardown_log, current_test_log
from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.storage.secure_db import SecureDB


class TestIntializeAgentOrServer:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self):
        # GIVEN: (A) Uninitialized CS
        current_setup_log()
        SecureDB.delete_secure_db_in_test()
        self.cloud_server = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server",
        )

        # (GIVEN)+WHEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SecureDB.delete_secure_db_in_test()

    def test_one_time_intialization_command(self) -> None:
        # WHEN: DM apply one_time_intialization_command() on Uninitialized CS
        current_test_log()
        result = self.cloud_server.execute_one_time_intialize_agent_or_server()

        # THEN: (A') Initialize DM's CS
        assert type(result) == Success
        assert self.cloud_server.is_initialized == True
        assert self.cloud_server.device_priv_key_str != ""
        assert self.cloud_server.device_pub_key_str != ""

    def test_one_time_intialization_command_with_reboot(self) -> None:
        # GIVEN: (A') Initialized DM's CS
        self.cloud_server.execute_one_time_intialize_agent_or_server()

        # WHEN: DM reboot the CS
        current_test_log()
        self.cloud_server.reboot_device()

        # THEN: (A') Initialized DM's CS
        assert self.cloud_server.is_initialized == True
        assert self.cloud_server.device_priv_key_str != ""
        assert self.cloud_server.device_pub_key_str != ""

    def test_one_time_intialization_command_reintialized_failed(self) -> None:
        # GIVEN: (A') Initialized DM's CS
        self.cloud_server.execute_one_time_intialize_agent_or_server()

        # WHEN: DM apply one_time_intialization_command() on Initialized CS
        current_test_log()
        result = self.cloud_server.execute_one_time_intialize_agent_or_server()

        # THEN: (A') Cannot re-initialize DM's CS
        assert type(result) == Failure
        assert (
            result.failure().args[0]
            == "FAILURE: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED"
        )

    def test_one_time_intialization_command_initialize_device_failed(self) -> None:
        # GIVEN: (A) Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
        )

        # WHEN: DM apply one_time_intialization_command() on Initialized CS
        current_test_log()
        result = self.iot_device.execute_one_time_intialize_agent_or_server()

        # THEN: (A') Cannot initialize IoTD
        assert type(result) == Failure

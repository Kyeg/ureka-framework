import pytest
import logging
from tests.conftest import setup_log, teardown_log, test_log
from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.storage.secure_db import SecureDB


class TestIntializeAgentOrServer:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self):
        # GIVEN: (A) Uninitialized CS
        setup_log()
        self.cloud_server_1 = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_1",
            db_path="/secure_db/cloud_server_1",
        )

        # (GIVEN)+WHEN:
        yield

        # RE-GIVEN: Reset the test environment
        teardown_log()
        SecureDB.delete_secure_db_in_test()

    def test_one_time_intialization_command(self) -> None:
        # WHEN: DM apply one_time_intialization_command() on Uninitialized CS
        test_log()
        assert self.cloud_server_1.execute_one_time_intialization_command() == True

        # THEN: (A') Initialize DM's CS
        assert self.cloud_server_1.is_initialized == True
        assert self.cloud_server_1.device_priv_key_str != ""
        assert self.cloud_server_1.device_pub_key_str != ""

    def test_one_time_intialization_command_with_reboot(self) -> None:
        # GIVEN: (A') Initialized DM's CS
        assert self.cloud_server_1.execute_one_time_intialization_command() == True

        # WHEN: DM reboot the CS
        test_log()
        self.cloud_server_1.reboot_device()

        # THEN: (A') Initialized DM's CS
        assert self.cloud_server_1.is_initialized == True
        assert self.cloud_server_1.device_priv_key_str != ""
        assert self.cloud_server_1.device_pub_key_str != ""

    def test_one_time_intialization_command_reintialized_failed(self) -> None:
        # GIVEN: (A') Initialized DM's CS
        self.cloud_server_1.execute_one_time_intialization_command()

        # WHEN: DM apply one_time_intialization_command() on Initialized CS
        test_log()
        # THEN: (A') Cannot re-initialize DM's CS
        assert self.cloud_server_1.execute_one_time_intialization_command() == False
        # logging.error(f"FAILURE: {self.device_name} ALREADY INITIALIZED")

    # @pytest.mark.skip(reason="WIP")
    def test_one_time_intialization_command_initialize_device_failed(self) -> None:
        # GIVEN: (A) Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
            db_path="/secure_db/iot_device",
        )

        # WHEN: DM apply one_time_intialization_command() on Initialized CS
        test_log()
        # THEN: (A') Cannot initialize IoTD
        assert self.iot_device.execute_one_time_intialization_command() == False
        # logging.error("FAILURE: ONLY USER-AGENT-OR-CLOUD-SERVER CAN DO THIS OPERATION")

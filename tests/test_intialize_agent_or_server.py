import pytest
import logging
from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket


class TestIntializeAgentOrServer:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self, caplog):
        caplog.set_level(logging.INFO)

        logging.info("*" * 50)
        logging.info("TestIntializeAgentOrServer")
        logging.info("*" * 50)

        # GIVEN: (A) Uninitialized CS
        self.cloud_server_1 = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_1",
            db_path="/secure_db/cloud_server_1",
        )

        # (GIVEN)+WHEN:
        yield

        # RE-GIVEN: Reset the test environment
        self.cloud_server_1.execute_reset_device()

    def test_one_time_intialization_command(self, caplog) -> None:
        caplog.set_level(logging.INFO)

        # WHEN: one_time_intialization_command()
        logging.info("*" * 50)
        logging.info("test_one_time_intialization_command")
        logging.info("*" * 50)
        assert self.cloud_server_1.execute_one_time_intialization_command() == True

        # THEN: (A') Initialize DM's CS
        assert self.cloud_server_1.is_initialized == True
        assert self.cloud_server_1.device_priv_key_str != ""
        assert self.cloud_server_1.device_pub_key_str != ""

    def test_one_time_intialization_command_failed(self, caplog) -> None:
        caplog.set_level(logging.INFO)

        # GIVEN: (A') Initialized DM's CS
        self.cloud_server_1.execute_one_time_intialization_command()

        # WHEN: one_time_intialization_command()
        logging.info("*" * 50)
        logging.info("test_one_time_intialization_command_failed")
        logging.info("*" * 50)
        # THEN: (A') Cannot re-initialize DM's CS
        assert self.cloud_server_1.execute_one_time_intialization_command() == False

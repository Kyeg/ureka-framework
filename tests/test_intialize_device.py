import pytest
import logging
from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket


class TestIntializeDevice:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self):
        logging.info("")
        logging.info("*" * 50)
        logging.info("Setup")
        logging.info("*" * 50)

        # GIVEN: (A') Initialized DM's CS
        self.cloud_server_dm = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_dm",
            db_path="/secure_db/cloud_server_dm",
        )
        self.cloud_server_dm.execute_one_time_intialization_command()

        # GIVEN: (B) Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
            db_path="/secure_db/iot_device",
        )

        # (GIVEN)+WHEN:
        yield

        logging.info("*" * 50)
        logging.info("TearDown")
        logging.info("*" * 50)
        # RE-GIVEN: Reset the test environment
        self.cloud_server_dm.execute_reset_device()
        self.iot_device.execute_reset_device()

    def test_apply_initialization_ticket(self) -> None:
        # WHEN: DM's CS apply_initialization_ticket() on Uninitialized IoTD
        logging.info("*" * 50)
        logging.info("test_apply_initialization_ticket")
        logging.info("*" * 50)
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization", holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B') Initialized DM's IoTD
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
        logging.info("*" * 50)
        logging.info("test_apply_initialization_ticket_reintialized_failed")
        logging.info("*" * 50)
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization", holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B') Cannot re-initialize DM's IoTD
        assert self.iot_device.is_initialized == True
        # logging.error("FAILURE: ALREADY INITIALIZED")

    # @pytest.mark.skip(reason="WIP")
    def test_apply_initialization_ticket_initialize_user_or_server_failed(self) -> None:
        # GIVEN: (B') A CS or UA
        self.user_agent_do = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="user_agent_do",
            db_path="/secure_db/user_agent_do",
        )
        self.user_agent_do.execute_one_time_intialization_command()

        # WHEN: DM's CS apply_initialization_ticket() on Initialized UA's Agent
        logging.info("*" * 50)
        logging.info("test_apply_initialization_ticket_failed")
        logging.info("*" * 50)
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization", holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.user_agent_do.verify_xxx_ticket(test_ticket)

        # THEN: (B') Cannot initialize CS or UA
        assert self.user_agent_do.is_initialized == True
        # logging.error("FAILURE: ONLY IOT_DEVICE CAN DO THIS OPERATION")

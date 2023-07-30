import ureka_framework.controller.device_controller as device_controller
import ureka_framework.data_model.ticket as ticket


class TestIntializeDevice:
    # Setup in every class method
    def setup_method(self) -> None:
        # GIVEN: (A') Initialized DM's CS
        self.cloud_server_dm = device_controller.DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_dm",
            db_path="/secure_db/cloud_server_dm",
        )
        self.cloud_server_dm.one_time_intialization_command()

        # GIVEN: (B) Uninitialized IoTD
        self.iot_device = device_controller.DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
            db_path="/secure_db/iot_device",
        )

    def test_apply_initialization_ticket(self) -> None:
        # WHEN: apply_initialization_ticket()
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

    def test_apply_initialization_ticket_failed(self) -> None:
        # GIVEN: (B') Initialized DM's IoTD
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization", holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # WHEN: apply_initialization_ticket()
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization", holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B') Cannot re-initialize DM's IoTD
        assert (
            self.iot_device.is_initialized == True
        )  # logging.debug("ERROR: ALREADY INITIALIZED")

    # Teardown in every class method
    def teardown_method(self) -> None:
        # RE-GIVEN: Remove the secure_db
        self.cloud_server_dm.reset_device()
        self.iot_device.reset_device()

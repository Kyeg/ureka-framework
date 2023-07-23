# Ureka Module
import legacy.ticket_module as ticket_module
import legacy.ticket as ticket


class TestIntializeDevice:
    # Setup in every class method
    def setup_method(self):
        # GIVEN: (A') Initialized DM's CS
        self.cloud_server_dm = ticket_module.TicketModule(
            module_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            module_name="cloud_server_dm",
            db_path="/secure_db/cloud_server_dm",
        )
        self.cloud_server_dm.one_time_intialization_command()

        # GIVEN: (B) Uninitialized IoTD
        self.iot_device = ticket_module.TicketModule(
            module_type=ticket.IOT_DEVICE,
            module_name="iot_device",
            db_path="/secure_db/iot_device",
        )

    def test_apply_initialization_ticket(self):
        # WHEN: apply_initialization_ticket()
        test_ticket = self.cloud_server_dm.generate_initialization_ticket(
            holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B') Initialized DM's IoTD
        assert self.iot_device.is_initialized == True
        assert self.iot_device.device_priv_key_str != ""
        assert self.iot_device.device_pub_key_str != ""
        assert (
            self.iot_device.owner_pub_key_str == self.cloud_server_dm.device_pub_key_str
        )

    def test_apply_initialization_ticket_failed(self):
        # GIVEN: (B') Initialized DM's IoTD
        test_ticket = self.cloud_server_dm.generate_initialization_ticket(
            holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # WHEN: apply_initialization_ticket()
        test_ticket = self.cloud_server_dm.generate_initialization_ticket(
            holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B') Cannot re-initialize DM's IoTD
        assert (
            self.iot_device.is_initialized == True
        )  # logging.debug("ERROR: ALREADY INITIALIZED")

    # Teardown in every class method
    def teardown_method(self):
        # RE-GIVEN: Remove the secure_db
        self.cloud_server_dm.reset_device()
        self.iot_device.reset_device()

from legacy import key_serialization
import legacy.ticket_module as ticket_module
import legacy.ticket as ticket


class TestTransferOwnershipDevice:
    # Setup in every class method
    def setup_method(self):
        # GIVEN: (A') Initialized DM's CS
        self.cloud_server_dm = ticket_module.TicketModule(
            module_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            module_name="cloud_server_dm",
            db_path="/secure_db/cloud_server_dm",
        )
        self.cloud_server_dm.one_time_intialization_command()

        # GIVEN: (A') Initialized DO's UA
        self.user_agent_do = ticket_module.TicketModule(
            module_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            module_name="user_agent_do",
            db_path="/secure_db/user_agent_do",
        )
        self.user_agent_do.one_time_intialization_command()

        # GIVEN: (B') Initialized DM's IoTD
        self.iot_device = ticket_module.TicketModule(
            module_type=ticket.IOT_DEVICE,
            module_name="iot_device",
            db_path="/secure_db/iot_device",
        )
        test_ticket = self.cloud_server_dm.generate_initialization_ticket(
            holder_id=self.cloud_server_dm.device_pub_key_str
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

    def test_apply_management_ticket(self):
        # WHEN: apply_management_ticket()
        test_ticket = self.cloud_server_dm.generate_management_ticket(
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.user_agent_do.device_pub_key_str,
            request_body=key_serialization.dict_to_jsonstr(
                {
                    ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER
                }
            ),
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B'') Initialized DO's IoTD
        assert (
            self.iot_device.owner_pub_key_str == self.user_agent_do.device_pub_key_str
        )

    def test_apply_management_ticket_failed(self):
        # GIVEN: (B'') Initialized DO's IoTD
        test_ticket = self.cloud_server_dm.generate_management_ticket(
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.user_agent_do.device_pub_key_str,
            request_body=key_serialization.dict_to_jsonstr(
                {
                    ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER
                }
            ),
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # WHEN: apply_management_ticket()
        test_ticket = self.cloud_server_dm.generate_management_ticket(
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.user_agent_do.device_pub_key_str,
            request_body=key_serialization.dict_to_jsonstr(
                {
                    ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER
                }
            ),
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: (B'') Initialized DO's IoTD
        assert (
            self.iot_device.owner_pub_key_str == self.user_agent_do.device_pub_key_str
        )  # logging.debug("ERROR: ISSUER_SIGNATURE on MANAGEMENT_TICKET")

    # Teardown in every class method
    def teardown_method(self):
        # RE-GIVEN: Remove the secure_db
        self.cloud_server_dm.reset_device()
        self.user_agent_do.reset_device()
        self.iot_device.reset_device()

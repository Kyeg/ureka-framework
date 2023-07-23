import pytest
from legacy import key_serialization
import legacy.ticket_module as ticket_module
import legacy.ticket as ticket


class TestAccessDevice:
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

        # GIVEN: (A') Initialized EP's CS
        self.cloud_server_ep = ticket_module.TicketModule(
            module_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            module_name="cloud_server_ep",
            db_path="/secure_db/cloud_server_ep",
        )
        self.cloud_server_ep.one_time_intialization_command()

    def test_apply_access_permission_ticket(self):
        # WHEN: apply_access_permission_ticket()
        # -----------------------------------------------------
        #     - (->) Access Permission Ticket (->)
        # -----------------------------------------------------
        test_ticket = self.user_agent_do.generate_access_permission_ticket(
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.cloud_server_ep.device_pub_key_str,
            request_body=key_serialization.dict_to_jsonstr(
                {
                    ticket.REQUEST_BODY_CCESS_PERMISSION_RESOURCE_TREE: key_serialization.dict_to_jsonstr(
                        {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
                    )  # sort_keys = True
                }
            ),  # sort_keys = True,
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Challenge Ticket (<-)
        # -----------------------------------------------------
        test_ticket = self.iot_device.generate_challenge_ticket(
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.cloud_server_ep.device_pub_key_str,
        )
        self.cloud_server_ep.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (->) Repsonse Ticket (->)
        # -----------------------------------------------------
        test_ticket = self.cloud_server_ep.generate_response_ticket(
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.cloud_server_ep.device_pub_key_str,
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Key-exchange Ticket (<-)
        # -----------------------------------------------------
        test_ticket = self.iot_device.generate_key_exchange_ticket(
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.cloud_server_ep.device_pub_key_str,
        )
        self.cloud_server_ep.verify_xxx_ticket(test_ticket)

        # THEN: (B'') EP's CS can Limitedly Access DO's IoTD
        assert (
            self.iot_device.owner_pub_key_str == self.user_agent_do.device_pub_key_str
        )
        assert (
            self.iot_device.current_session_key_byte
            == self.cloud_server_ep.current_session_key_byte
        )

    @pytest.mark.skip(reason="Not Implemented")
    def test_apply_access_permission_ticket_failed(self):
        pass

    # Teardown in every class method
    def teardown_method(self):
        # RE-GIVEN: Remove the secure_db
        self.cloud_server_dm.reset_device()
        self.user_agent_do.reset_device()
        self.iot_device.reset_device()
        self.cloud_server_ep.reset_device()

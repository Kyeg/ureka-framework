# Ureka Module
import legacy.ticket_module as ticket_module
import legacy.ticket as ticket


class TestIntializeAgentOrServer:
    # Setup in every class method
    def setup_method(self):
        # GIVEN: (A) Uninitialized CS
        self.cloud_server_1 = ticket_module.TicketModule(
            module_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            module_name="cloud_server_1",
            db_path="/secure_db/cloud_server_1",
        )

    def test_one_time_intialization_command(self):
        # WHEN: one_time_intialization_command()
        assert self.cloud_server_1.one_time_intialization_command() == True

        # THEN: (A') Initialize DM's CS
        assert self.cloud_server_1.is_initialized == True
        assert self.cloud_server_1.device_priv_key_str != ""
        assert self.cloud_server_1.device_pub_key_str != ""

    def test_one_time_intialization_command_failed(self):
        # GIVEN: (A') Initialized DM's CS
        self.cloud_server_1.one_time_intialization_command()

        # WHEN: one_time_intialization_command()
        # THEN: (A') Cannot re-initialize DM's CS
        assert self.cloud_server_1.one_time_intialization_command() == False

    # Teardown in every class method
    def teardown_method(self):
        # RE-GIVEN: Remove the secure_db
        self.cloud_server_1.reset_device()

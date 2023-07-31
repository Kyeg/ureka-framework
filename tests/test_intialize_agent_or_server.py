from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket


class TestIntializeAgentOrServer:
    # Setup in every class method
    def setup_method(self) -> None:
        # GIVEN: (A) Uninitialized CS
        self.cloud_server_1 = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_1",
            db_path="/secure_db/cloud_server_1",
        )

    def test_one_time_intialization_command(self) -> None:
        # WHEN: one_time_intialization_command()
        assert self.cloud_server_1.execute_one_time_intialization_command() == True

        # THEN: (A') Initialize DM's CS
        assert self.cloud_server_1.is_initialized == True
        assert self.cloud_server_1.device_priv_key_str != ""
        assert self.cloud_server_1.device_pub_key_str != ""

    def test_one_time_intialization_command_failed(self) -> None:
        # GIVEN: (A') Initialized DM's CS
        self.cloud_server_1.execute_one_time_intialization_command()

        # WHEN: one_time_intialization_command()
        # THEN: (A') Cannot re-initialize DM's CS
        assert self.cloud_server_1.execute_one_time_intialization_command() == False

    # Teardown in every class method
    def teardown_method(self) -> None:
        # RE-GIVEN: Remove the secure_db
        self.cloud_server_1.execute_reset_device()

import pytest
from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.crypto import serialization_util


class TestAccessDevice:
    # Setup in every class method
    def setup_method(self) -> None:
        # GIVEN: (A') Initialized DM's CS
        self.cloud_server_dm = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_dm",
            db_path="/secure_db/cloud_server_dm",
        )
        self.cloud_server_dm.execute_one_time_intialization_command()

        # GIVEN: (A') Initialized DO's UA
        self.user_agent_do = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="user_agent_do",
            db_path="/secure_db/user_agent_do",
        )
        self.user_agent_do.execute_one_time_intialization_command()

        # GIVEN: (B') Initialized DM's IoTD
        self.iot_device = DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
            db_path="/secure_db/iot_device",
        )
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "intialization",
            holder_id=self.cloud_server_dm.device_pub_key_str,
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # GIVEN: (B'') Initialized DO's IoTD
        test_ticket = self.cloud_server_dm.ticket_generation_router.generate_xxx_ticket(
            "management",
            device_priv_key=self.cloud_server_dm.device_priv_key,
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.user_agent_do.device_pub_key_str,
            task_scope=serialization_util.dict_to_jsonstr(
                {
                    ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER
                }
            ),
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # GIVEN: (A') Initialized EP's CS
        self.cloud_server_ep = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_ep",
            db_path="/secure_db/cloud_server_ep",
        )
        self.cloud_server_ep.execute_one_time_intialization_command()

    def test_apply_access_permission_ticket(self) -> None:
        # WHEN: apply_access_permission_ticket()
        # -----------------------------------------------------
        #     - (->) Access Permission Ticket (->)
        # -----------------------------------------------------
        test_ticket = self.user_agent_do.ticket_generation_router.generate_xxx_ticket(
            "access_permission",
            device_priv_key=self.user_agent_do.device_priv_key,
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.cloud_server_ep.device_pub_key_str,
            task_scope=serialization_util.dict_to_jsonstr(
                {
                    ticket.REQUEST_BODY_ACCESS_PERMISSION_RESOURCE_TREE: serialization_util.dict_to_jsonstr(
                        {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
                    )  # sort_keys = True
                }
            ),  # sort_keys = True,
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Challenge Ticket (<-)
        # -----------------------------------------------------
        test_ticket = self.iot_device.ticket_generation_router.generate_xxx_ticket(
            "challenge",
            device_priv_key=self.iot_device.device_priv_key,
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.cloud_server_ep.device_pub_key_str,
        )
        self.cloud_server_ep.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (->) Repsonse Ticket (->)
        # -----------------------------------------------------
        test_ticket = self.cloud_server_ep.ticket_generation_router.generate_xxx_ticket(
            "response",
            device_priv_key=self.cloud_server_ep.device_priv_key,
            device_id=self.iot_device.device_pub_key_str,
            holder_id=self.cloud_server_ep.device_pub_key_str,
        )
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Key-exchange Ticket (<-)
        # -----------------------------------------------------
        test_ticket = self.iot_device.ticket_generation_router.generate_xxx_ticket(
            "key_exchange",
            device_priv_key=self.iot_device.device_priv_key,
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
    def teardown_method(self) -> None:
        # RE-GIVEN: Remove the secure_db
        self.cloud_server_dm.execute_reset_device()
        self.user_agent_do.execute_reset_device()
        self.iot_device.execute_reset_device()
        self.cloud_server_ep.execute_reset_device()

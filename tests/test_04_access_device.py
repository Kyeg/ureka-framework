from returns.result import Success, Failure
import pytest
from tests.conftest import (
    attacker_server,
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_owner_agent_and_her_device,
    enterprise_provider_server,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.storage.secure_db import SecureDB


class TestAccessDevice:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self):
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SecureDB.delete_secure_db_in_test()

        # GIVEN+WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SecureDB.delete_secure_db_in_test()

    def test_apply_access_permission_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()
        assert self.iot_device.current_holder_pub_key_str == ""
        assert self.iot_device.current_session_key_byte == b""

        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN: DO's UA allow EP's CS to apply_access_permission_ticket() on DO's IoTD
        current_test_when_and_then_log()
        # -----------------------------------------------------
        #     - (->) Access Permission Ticket (->)
        # -----------------------------------------------------
        permission_resource_tree = serialization_util.dict_to_jsonstr(
            {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
        )
        task_scope = serialization_util.dict_to_jsonstr(
            {
                ticket.REQUEST_BODY_ACCESS_PERMISSION_RESOURCE_TREE: permission_resource_tree
            }
        )
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_ACCESS_PERMISSION_TICKET}",
            "task_scope": f"{task_scope}",
        }
        test_ticket: str = self.user_agent_do.generate_xxx_ticket(test_request)
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Challenge Ticket (<-)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_CHALLENGE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.iot_device.generate_xxx_ticket(test_request)
        self.cloud_server_ep.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (->) Repsonse Ticket (->)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_RESPONSE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_ep.generate_xxx_ticket(test_request)
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Key-exchange Ticket (<-)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_KEY_EXCHANGE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.iot_device.generate_xxx_ticket(test_request)
        result = self.cloud_server_ep.verify_xxx_ticket(test_ticket)

        # THEN: Succeed to allow EP's CS Limitedly Access DO's IoTD
        assert type(result) == Success
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.owner_pub_key_str == self.user_agent_do.device_pub_key_str
        )
        # THEN: EP's CS can open a session with DO's IoTD
        assert (
            self.iot_device.current_holder_pub_key_str
            == self.cloud_server_ep.device_pub_key_str
        )
        assert (
            self.iot_device.current_session_key_byte
            == self.cloud_server_ep.current_session_key_byte
        )

    def test_apply_access_permission_ticket_wrong_owner_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN: DO's UA do not allow EP's CS to apply_access_permission_ticket() on DO's IoTD
        current_test_when_and_then_log()
        # -----------------------------------------------------
        #     - (->) Access Permission Ticket (->)
        # -----------------------------------------------------
        permission_resource_tree = serialization_util.dict_to_jsonstr(
            {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
        )
        task_scope = serialization_util.dict_to_jsonstr(
            {
                ticket.REQUEST_BODY_ACCESS_PERMISSION_RESOURCE_TREE: permission_resource_tree
            }
        )
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_ACCESS_PERMISSION_TICKET}",
            "task_scope": f"{task_scope}",
        }
        test_ticket: str = self.cloud_server_ep.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Failed to allow EP's CS Access DO's IoTD
        assert type(result) == Failure
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.owner_pub_key_str == self.user_agent_do.device_pub_key_str
        )
        # THEN: EP's CS cannot open a session with DO's IoTD
        assert self.iot_device.current_session_key_byte == b""

    def test_apply_access_permission_ticket_unauthorized_holder_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: DO's UA allow EP's CS to apply_access_permission_ticket() on DO's IoTD
        # WHEN: But the holder is not EP's CS
        current_test_when_and_then_log()
        # -----------------------------------------------------
        #     - (->) Access Permission Ticket (->)
        # -----------------------------------------------------
        permission_resource_tree = serialization_util.dict_to_jsonstr(
            {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
        )
        task_scope = serialization_util.dict_to_jsonstr(
            {
                ticket.REQUEST_BODY_ACCESS_PERMISSION_RESOURCE_TREE: permission_resource_tree
            }
        )
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_ACCESS_PERMISSION_TICKET}",
            "task_scope": f"{task_scope}",
        }
        test_ticket: str = self.user_agent_do.generate_xxx_ticket(test_request)
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Challenge Ticket (<-)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_CHALLENGE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.iot_device.generate_xxx_ticket(test_request)
        self.cloud_server_atk.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (->) Repsonse Ticket (->)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_RESPONSE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_ep.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Failed to allow ATK's CS Access DO's IoTD
        assert type(result) == Failure
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.owner_pub_key_str == self.user_agent_do.device_pub_key_str
        )
        # THEN: ATK's CS cannot open a session with DO's IoTD
        assert self.iot_device.current_session_key_byte == b""

    @pytest.mark.skip(reason="Not implemented yet")
    def test_apply_access_permission_ticket_unauthenticated_holder_failed(self) -> None:
        # WHEN: ...
        current_test_when_and_then_log()

from returns.result import Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_owner_agent_and_her_device,
    enterprise_provider_server,
    attacker_server,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.storage.simple_storage import SimpleStorage


class TestAccessDevice:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self):
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SimpleStorage.delete_storage_in_test()

        # GIVEN+WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SimpleStorage.delete_storage_in_test()

    def test_apply_access_permission_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()
        assert self.iot_device.this_device.current_holder_pub_key_str == ""
        assert self.iot_device.this_device.current_session_key_byte == b""

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
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_ACCESS_PERMISSION_TICKET}",
            "task_scope": f"{task_scope}",
        }
        test_ticket: str = self.user_agent_do.generate_xxx_ticket(test_request)
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Challenge Ticket (<-)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_CHALLENGE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.iot_device.generate_xxx_ticket(test_request)
        self.cloud_server_ep.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (->) Repsonse Ticket (->)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_RESPONSE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_ep.generate_xxx_ticket(test_request)
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Key-exchange Ticket (<-)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_KEY_EXCHANGE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.iot_device.generate_xxx_ticket(test_request)
        result = self.cloud_server_ep.verify_xxx_ticket(test_ticket)

        # THEN: Succeed to allow EP's CS Limitedly Access DO's IoTD
        assert type(result) == Success
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )
        # THEN: EP's CS can open a session with DO's IoTD
        assert (
            self.iot_device.this_device.current_holder_pub_key_str
            == self.cloud_server_ep.this_person.person_pub_key_str
        )
        assert (
            self.iot_device.this_device.current_session_key_byte
            == self.cloud_server_ep.this_device.current_session_key_byte
        )

    @pytest.mark.skip(reason="Implemented but not tested yet")
    def test_apply_access_permission_ticket_with_reboot(self) -> None:
        current_test_given_log()
        # GIVEN: Initialized DO's UA and DO's IoTD
        # GIVEN: Initialized EP's CS
        # GIVEN: DO's UA allow EP's CS to apply_access_permission_ticket() on DO's IoTD
        # GIVEN: Succeed to allow EP's CS Limitedly Access DO's IoTD

        # WHEN: Reboot the DO's IoTD

        # THEN: Becuase the session between EP's CS and DO's IoTD is not persistently stored,
        #       so EP's CS need to create a new session by re-issue the Ticket

    def test_apply_access_permission_ticket_wrong_owner_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: DO's UA do not allow ATK's CS to apply_access_permission_ticket() on DO's IoTD
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
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_ACCESS_PERMISSION_TICKET}",
            "task_scope": f"{task_scope}",
        }
        test_ticket: str = self.cloud_server_atk.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Failed to allow ATK's CS Access DO's IoTD
        assert type(result) == Failure
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )
        # THEN: ATK's CS cannot open a session with DO's IoTD
        assert self.iot_device.this_device.current_session_key_byte == b""

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
        # WHEN: But the ATK's CS attempt to replace the holder in this session
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
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_ACCESS_PERMISSION_TICKET}",
            "task_scope": f"{task_scope}",
        }
        test_ticket: str = self.user_agent_do.generate_xxx_ticket(test_request)
        self.iot_device.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (<-) Challenge Ticket (<-)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_CHALLENGE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.iot_device.generate_xxx_ticket(test_request)
        self.cloud_server_atk.verify_xxx_ticket(test_ticket)

        # -----------------------------------------------------
        #     - (->) Repsonse Ticket (->)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_RESPONSE_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_ep.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Failed to allow ATK's CS Access DO's IoTD
        assert type(result) == Failure
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )
        # THEN: ATK's CS cannot open a session with DO's IoTD
        assert self.iot_device.this_device.current_session_key_byte == b""

    @pytest.mark.skip(reason="Not implemented yet")
    def test_apply_access_permission_ticket_unauthenticated_holder_failed(self) -> None:
        # WHEN: DO's UA allow EP's CS to apply_access_permission_ticket() on DO's IoTD
        # WHEN: But the ATK's CS pretend EP's CS and try to use this Access Permission Ticket
        current_test_when_and_then_log()

import logging
from returns.result import Success, Failure
import pytest
from tests.conftest import (
    create_comm_connection,
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_owner_agent_and_her_device,
    enterprise_provider_server,
    attacker_server,
)
import ureka_framework.data_model.u_ticket as u_ticket
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

    def test_apply_access_permission_u_ticket_in_io_level(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Issuer: DO's UA generate & send the access_permission_u_ticket to EP's CS
        create_comm_connection(self.user_agent_do, self.cloud_server_ep)
        owned_device_id = self.iot_device.this_device.device_pub_key_str
        resource_tree = serialization_util.dict_to_jsonstr(
            {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
        )
        generated_task_scope = serialization_util.dict_to_jsonstr(
            {u_ticket.TASK_SCOPE_RESOURCE_TREE: resource_tree}
        )
        generated_request: dict = {
            "device_id": f"{owned_device_id}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_PERMISSION_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.user_agent_do.issuer_issue_consent_to_holder(
            device_id=owned_device_id, arbitrary_dict=generated_request
        )

        # WHEN: Holder: EP's CS receive & store the access_permission_u_ticket
        self.cloud_server_ep.holder_receive_consent()

        # WHEN: Holder: EP's CS forward the access_permission_u_ticket
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        self.cloud_server_ep.holder_access_device(
            self.iot_device.this_device.device_pub_key_str
        )

        # WHEN: Device: DO's IoTD receive the access_permission_u_ticket
        self.iot_device.device_be_accessed()

        # WHEN: Holder: EP's CS receive the access_permission_r_tickets (i.e., CR-KE-PS_r_tickets)
        self.cloud_server_ep._holder_recv_cr_ke_1()

        # THEN: Succeed to allow EP's CS Limitedly Access DO's IoTD
        # THEN: Still DO's IoTD
        # THEN: EP's CS can open a session with DO's IoTD

    @pytest.mark.skip(reason="Remove old version of CR-KE")
    def test_apply_access_permission_u_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()
        assert self.iot_device.this_device.current_holder_pub_key_str == None
        assert self.iot_device.this_device.current_session_key_byte == None

        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN: DO's UA allow EP's CS to apply_access_permission_u_ticket() on DO's IoTD
        current_test_when_and_then_log()
        # -----------------------------------------------------
        #     - (->) Access Permission UTicket (->)
        # -----------------------------------------------------
        permission_resource_tree = serialization_util.dict_to_jsonstr(
            {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
        )
        task_scope = serialization_util.dict_to_jsonstr(
            {u_ticket.TASK_SCOPE_RESOURCE_TREE: permission_resource_tree}
        )
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_PERMISSION_UTICKET}",
            "task_scope": f"{task_scope}",
        }
        test_u_ticket: str = self.user_agent_do._generate_xxx_u_ticket(test_request)
        self.user_agent_do._stored_generated_xxx_u_ticket(test_u_ticket)
        logging.debug(f"ACCESS_PERMISSION_UTICKET: {test_u_ticket}")
        self.iot_device._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # -----------------------------------------------------
        #     - (<-) Challenge UTicket (<-)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_CHALLENGE_UTICKET}",
        }
        test_u_ticket: str = self.iot_device._generate_xxx_u_ticket(test_request)
        self.iot_device._stored_generated_xxx_u_ticket(test_u_ticket)
        logging.debug(f"CHALLENGE_UTICKET: {test_u_ticket}")
        self.cloud_server_ep._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # -----------------------------------------------------
        #     - (->) Repsonse UTicket (->)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_RESPONSE_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_ep._generate_xxx_u_ticket(test_request)
        self.cloud_server_ep._stored_generated_xxx_u_ticket(test_u_ticket)
        logging.debug(f"RESPONSE_UTICKET: {test_u_ticket}")
        self.iot_device._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # -----------------------------------------------------
        #     - (<-) Key-exchange UTicket (<-)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_KEY_EXCHANGE_UTICKET}",
        }
        test_u_ticket: str = self.iot_device._generate_xxx_u_ticket(test_request)
        self.iot_device._stored_generated_xxx_u_ticket(test_u_ticket)
        logging.debug(f"KEY_EXCHANGE_UTICKET: {test_u_ticket}")
        result = self.cloud_server_ep._verify_and_execute_xxx_u_ticket(test_u_ticket)

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

    @pytest.mark.skip(reason="Remove old version of CR-KE")
    def test_apply_access_permission_u_ticket_wrong_owner_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: DO's UA do not allow ATK's CS to apply_access_permission_u_ticket() on DO's IoTD
        current_test_when_and_then_log()
        # -----------------------------------------------------
        #     - (->) Access Permission UTicket (->)
        # -----------------------------------------------------
        permission_resource_tree = serialization_util.dict_to_jsonstr(
            {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
        )
        task_scope = serialization_util.dict_to_jsonstr(
            {u_ticket.TASK_SCOPE_RESOURCE_TREE: permission_resource_tree}
        )
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_PERMISSION_UTICKET}",
            "task_scope": f"{task_scope}",
        }
        test_u_ticket: str = self.cloud_server_atk._generate_xxx_u_ticket(test_request)
        result = self.iot_device._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # THEN: Failed to allow ATK's CS Access DO's IoTD
        assert type(result) == Failure
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )
        # THEN: ATK's CS cannot open a session with DO's IoTD
        assert self.iot_device.this_device.current_session_key_byte == None

    @pytest.mark.skip(reason="Remove old version of CR-KE")
    def test_apply_access_permission_u_ticket_unauthorized_holder_failed(self) -> None:
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

        # WHEN: DO's UA allow EP's CS to apply_access_permission_u_ticket() on DO's IoTD
        # WHEN: But the ATK's CS attempt to replace the holder in this session
        current_test_when_and_then_log()
        # -----------------------------------------------------
        #     - (->) Access Permission UTicket (->)
        # -----------------------------------------------------
        permission_resource_tree = serialization_util.dict_to_jsonstr(
            {"OPEN-DOOR": "1", "CLOSE-DOOR": "1", "DOOR-LOG": "1"}
        )
        task_scope = serialization_util.dict_to_jsonstr(
            {u_ticket.TASK_SCOPE_RESOURCE_TREE: permission_resource_tree}
        )
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_PERMISSION_UTICKET}",
            "task_scope": f"{task_scope}",
        }
        test_u_ticket: str = self.user_agent_do._generate_xxx_u_ticket(test_request)
        self.iot_device._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # -----------------------------------------------------
        #     - (<-) Challenge UTicket (<-)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_CHALLENGE_UTICKET}",
        }
        test_u_ticket: str = self.iot_device._generate_xxx_u_ticket(test_request)
        self.cloud_server_atk._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # -----------------------------------------------------
        #     - (->) Repsonse UTicket (->)
        # -----------------------------------------------------
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_RESPONSE_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_ep._generate_xxx_u_ticket(test_request)
        result = self.iot_device._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # THEN: Failed to allow ATK's CS Access DO's IoTD
        assert type(result) == Failure
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )
        # THEN: ATK's CS cannot open a session with DO's IoTD
        assert self.iot_device.this_device.current_session_key_byte == None

    @pytest.mark.skip(reason="Implemented but not tested yet")
    def test_apply_access_permission_u_ticket_with_reboot(self) -> None:
        current_test_given_log()
        # GIVEN: Initialized DO's UA and DO's IoTD
        # GIVEN: Initialized EP's CS
        # GIVEN: DO's UA allow EP's CS to apply_access_permission_u_ticket() on DO's IoTD
        # GIVEN: Succeed to allow EP's CS Limitedly Access DO's IoTD

        # WHEN: Reboot the DO's IoTD

        # THEN: Becuase the session between EP's CS and DO's IoTD is not persistently stored,
        #       so EP's CS need to create a new session by re-issue the UTicket

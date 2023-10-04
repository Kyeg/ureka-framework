import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    create_comm_connection,
    enterprise_provider_server_and_her_session,
    wait_comm_completed,
    device_owner_agent_and_her_device,
    enterprise_provider_server,
    attacker_server,
)
from ureka_framework.data_model.current_session import current_session_to_jsonstr
from ureka_framework.resource.logger.simple_logger import simple_log
from returns.result import Success, Failure
import ureka_framework.data_model.u_ticket as u_ticket
from ureka_framework.resource.crypto.serialization_util import (
    dict_to_jsonstr,
)
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

    def test_apply_access_u_ticket_in_io_level(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
        create_comm_connection(self.user_agent_do, self.cloud_server_ep)
        owned_device_id = self.iot_device.this_device.device_pub_key_str
        resource_tree = dict_to_jsonstr(
            {
                "SAY-HELLO": "allow",
                "SAY-GOOD-MORNING": "allow",
                "SAY-GOOD-NIGHT": "forbid",
            }
        )
        generated_task_scope = dict_to_jsonstr(
            {u_ticket.TASK_SCOPE_RESOURCE_TREE: resource_tree}
        )
        generated_request: dict = {
            "device_id": f"{owned_device_id}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.user_agent_do.issuer_issue_u_ticket_to_holder(
            device_id=owned_device_id, arbitrary_dict=generated_request
        )
        wait_comm_completed(self.cloud_server_ep, self.user_agent_do)

        # WHEN: Holder: EP's CS forward the access_u_ticket
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        generated_command = "HELLO"
        self.cloud_server_ep.holder_apply_u_ticket(owned_device_id, generated_command)
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: Succeed to allow EP's CS Limitedly Access DO's IoTD
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            self.iot_device.current_session.current_holder_id
            == self.cloud_server_ep.current_session.current_holder_id
        )
        assert (
            self.iot_device.current_session.current_task_scope
            == self.cloud_server_ep.current_session.current_task_scope
        )
        assert (
            self.iot_device.current_session.current_session_key_str
            == self.cloud_server_ep.current_session.current_session_key_str
        )
        assert (
            self.iot_device.current_session.plaintext_cmd
            == self.cloud_server_ep.current_session.plaintext_cmd
        )
        assert (
            self.iot_device.current_session.plaintext_data
            == self.cloud_server_ep.current_session.plaintext_data
        )
        assert current_session_to_jsonstr(
            self.iot_device.current_session
        ) == current_session_to_jsonstr(self.cloud_server_ep.current_session)

    def test_private_session_in_io_level(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS has Limitedly Access DO's IoTD
        (
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Holder: EP's CS forward the u_token
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        owned_device_id = self.iot_device.this_device.device_pub_key_str
        generated_command = "HELLO-2"
        self.cloud_server_ep.holder_send_cmd(
            device_id=owned_device_id, cmd=generated_command
        )
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            self.iot_device.current_session.plaintext_cmd
            == self.cloud_server_ep.current_session.plaintext_cmd
        )
        assert (
            self.iot_device.current_session.plaintext_data
            == self.cloud_server_ep.current_session.plaintext_data
        )
        assert current_session_to_jsonstr(
            self.iot_device.current_session
        ) == current_session_to_jsonstr(self.cloud_server_ep.current_session)

        # WHEN: Holder: EP's CS forward the u_token
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        owned_device_id = self.iot_device.this_device.device_pub_key_str
        generated_command = "HELLO-3"
        self.cloud_server_ep.holder_send_cmd(
            device_id=owned_device_id, cmd=generated_command
        )
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            self.iot_device.current_session.plaintext_cmd
            == self.cloud_server_ep.current_session.plaintext_cmd
        )
        assert (
            self.iot_device.current_session.plaintext_data
            == self.cloud_server_ep.current_session.plaintext_data
        )
        assert current_session_to_jsonstr(
            self.iot_device.current_session
        ) == current_session_to_jsonstr(self.cloud_server_ep.current_session)

        # WHEN: Holder: EP's CS forward the u_token (TX_END)
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        owned_device_id = self.iot_device.this_device.device_pub_key_str
        original_device_order = self.iot_device.this_device.ticket_order
        original_agent_order = self.cloud_server_ep.device_table[
            owned_device_id
        ].ticket_order
        generated_command = "TX_END"
        self.cloud_server_ep.holder_send_cmd(
            device_id=owned_device_id, cmd=generated_command, tx_end=True
        )
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: EP's CS can end this private session with DO's IoTD (& ticket order++)
        assert self.iot_device.this_device.ticket_order == original_device_order + 1
        assert (
            self.cloud_server_ep.device_table[owned_device_id].ticket_order
            == original_agent_order + 1
        )
        # THEN: EP's CS cannot access DO's IoTD anymore

    @pytest.mark.skip(reason="Remove old version of CR-KE")
    def test_apply_access_u_ticket(self) -> None:
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

        # WHEN: DO's UA allow EP's CS to apply_access_u_ticket() on DO's IoTD
        current_test_when_and_then_log()
        # -----------------------------------------------------
        #     - (->) Access UTicket (->)
        # -----------------------------------------------------
        permission_resource_tree = dict_to_jsonstr(
            {
                "SAY-HELLO": "allow",
                "SAY-GOOD-MORNING": "allow",
                "SAY-GOOD-NIGHT": "forbid",
            }
        )
        task_scope = dict_to_jsonstr(
            {u_ticket.TASK_SCOPE_RESOURCE_TREE: permission_resource_tree}
        )
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"{task_scope}",
        }
        test_u_ticket: str = self.user_agent_do._generate_xxx_u_ticket(test_request)
        self.user_agent_do._store_generated_xxx_u_ticket(test_u_ticket)
        simple_log("debug", f"ACCESS_UTICKET: {test_u_ticket}")
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
        self.iot_device._store_generated_xxx_u_ticket(test_u_ticket)
        simple_log("debug", f"CHALLENGE_UTICKET: {test_u_ticket}")
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
        self.cloud_server_ep._store_generated_xxx_u_ticket(test_u_ticket)
        simple_log("debug", f"RESPONSE_UTICKET: {test_u_ticket}")
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
        self.iot_device._store_generated_xxx_u_ticket(test_u_ticket)
        simple_log("debug", f"KEY_EXCHANGE_UTICKET: {test_u_ticket}")
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
    def test_apply_access_u_ticket_wrong_owner_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: DO's UA do not allow ATK's CS to apply_access_u_ticket() on DO's IoTD
        current_test_when_and_then_log()
        # -----------------------------------------------------
        #     - (->) Access UTicket (->)
        # -----------------------------------------------------
        permission_resource_tree = dict_to_jsonstr(
            {
                "SAY-HELLO": "allow",
                "SAY-GOOD-MORNING": "allow",
                "SAY-GOOD-NIGHT": "forbid",
            }
        )
        task_scope = dict_to_jsonstr(
            {u_ticket.TASK_SCOPE_RESOURCE_TREE: permission_resource_tree}
        )
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
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
    def test_apply_access_u_ticket_unauthorized_holder_failed(self) -> None:
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

        # WHEN: DO's UA allow EP's CS to apply_access_u_ticket() on DO's IoTD
        # WHEN: But the ATK's CS attempt to replace the holder in this session
        current_test_when_and_then_log()
        # -----------------------------------------------------
        #     - (->) Access UTicket (->)
        # -----------------------------------------------------
        permission_resource_tree = dict_to_jsonstr(
            {
                "SAY-HELLO": "allow",
                "SAY-GOOD-MORNING": "allow",
                "SAY-GOOD-NIGHT": "forbid",
            }
        )
        task_scope = dict_to_jsonstr(
            {u_ticket.TASK_SCOPE_RESOURCE_TREE: permission_resource_tree}
        )
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
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
    def test_apply_access_u_ticket_with_reboot(self) -> None:
        current_test_given_log()
        # GIVEN: Initialized DO's UA and DO's IoTD
        # GIVEN: Initialized EP's CS
        # GIVEN: DO's UA allow EP's CS to apply_access_u_ticket() on DO's IoTD
        # GIVEN: Succeed to allow EP's CS Limitedly Access DO's IoTD

        # WHEN: Reboot the DO's IoTD

        # THEN: Becuase the session between EP's CS and DO's IoTD is not persistently stored,
        #       so EP's CS need to create a new session by re-issue the UTicket

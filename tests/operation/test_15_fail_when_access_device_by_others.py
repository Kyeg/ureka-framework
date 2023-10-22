######################################################
# Test Fixtures
######################################################
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
)
from tests.conftest import (
    create_comm_connection,
    wait_comm_completed,
)
from tests.conftest import (
    device_manufacturer_server,
    device_manufacturer_server_and_her_device,
    device_owner_agent,
    device_owner_agent_and_her_device,
    device_owner_agent_and_her_session,
    enterprise_provider_server,
    enterprise_provider_server_and_her_session,
    attacker_server,
    device_owner_agent_and_her_device_and_attacker,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator

######################################################
# Import
######################################################
from ureka_framework.resource.logger.simple_logger import simple_log
import ureka_framework.model.message_model.message as message
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.message_model.u_ticket import jsonstr_to_u_ticket
from ureka_framework.model.data_model.other_device import OtherDevice
import ureka_framework.model.data_model.this_device as this_device
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr


class TestFailWhenAccessDeviceByOthers:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self) -> Iterator[None]:
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SimpleStorage.delete_storage_in_test()

        # WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SimpleStorage.delete_storage_in_test()

    ######################################################
    # Threat: (S) Spoofing, (T) Tampering, (E) Elevation of Privilege
    ######################################################
    def test_fail_when_forge_holder_id_and_issuer_sig_and_apply_the_uticket(
        self,
    ) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: Forge & Apply
        current_test_when_and_then_log()

        # WHEN: Interception (Know Latest State)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        intercepted_uticket_json = self.user_agent_do.shared_data.device_table[
            target_device_id
        ].device_u_ticket_for_owner
        intercepted_rticket_json = self.user_agent_do.shared_data.device_table[
            target_device_id
        ].device_r_ticket_for_owner

        # WHEN: Pretend Issuer: Owner
        self.cloud_server_atk.shared_data.device_table[target_device_id] = OtherDevice(
            device_id=target_device_id,
            device_u_ticket_for_owner=intercepted_uticket_json,
            device_r_ticket_for_owner=intercepted_rticket_json,
            ticket_order=2,
        )
        # WHEN: Forge Flow (issuer_issue_u_ticket_to_holder)
        generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{self.cloud_server_atk.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        generated_u_ticket_json: str = (
            self.cloud_server_atk.msg_generator._generate_xxx_u_ticket(
                generated_request
            )
        )

        # WHEN: Pretend Holder: Other
        # WHEN: Forge Flow (_holder_recv_u_ticket)
        self.cloud_server_atk.flow_issuer_issue_u_ticket._holder_recv_u_ticket(
            jsonstr_to_u_ticket(generated_u_ticket_json)
        )

        # WHEN: Apply Flow (holder_apply_u_ticket)
        create_comm_connection(self.cloud_server_atk, self.iot_device)
        generated_command = "HELLO-1"
        self.cloud_server_atk.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id, generated_command
        )
        wait_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: Because no legal issuer private key, legal authorization (issuer signature) cannot be generated
        assert (
            "-> FAILURE: VERIFY_ISSUER_SIGNATURE on ACCESS UTICKET"
            in self.iot_device.shared_data.result_message
        )
        assert (
            "-> FAILURE: VERIFY_RESULT"
            in self.cloud_server_atk.shared_data.result_message
        )

    # @pytest.mark.skip(reason="TODO: Simulate interception")
    def test_fail_when_intercept_and_preempt_to_apply_the_uticket(self) -> None:
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

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS,
        #       but ATK's CS intercept the u_ticket & pretend to be EP's CS
        create_comm_connection(self.user_agent_do, self.cloud_server_atk)
        owned_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
        generated_request: dict = {
            "device_id": f"{owned_device_id}",
            "holder_id": f"{self.cloud_server_ep.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.user_agent_do.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=owned_device_id, arbitrary_dict=generated_request
        )
        wait_comm_completed(self.cloud_server_atk, self.user_agent_do)

        # WHEN: Holder: ATK's CS forward the access_u_ticket
        create_comm_connection(self.cloud_server_atk, self.iot_device)
        generated_command = "HELLO-1"
        self.cloud_server_atk.flow_apply_u_ticket.holder_apply_u_ticket(
            owned_device_id, generated_command
        )
        wait_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: ATK's CS cannot share a private session with DO's IoTD
        #       (because no legal holder private key, legal challenge-response (holder signature) cannot be generated)
        assert "FAILURE" in self.iot_device.shared_data.result_message
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            != generated_command
        )

    def test_fail_when_intercept_and_reuse_the_uticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS can limitedly access DO's IoTD
        (
            self.user_agent_do,
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # GIVEN: ATK's CS intercept the DO's u_ticket
        owned_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        intercepted_uticket_json = self.cloud_server_ep.shared_data.device_table[
            owned_device_id
        ].device_u_ticket_for_owner

        # GIVEN: Holder: EP's CS forward the u_token (ACCESS_END)
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        generated_command = "ACCESS_END"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=owned_device_id, cmd=generated_command, access_end=True
        )
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: ATK's CS reuse the intercepted u_ticket on IoTD
        simple_log("debug", f"Intercepted UTicket: {intercepted_uticket_json}")
        create_comm_connection(self.iot_device, self.cloud_server_atk)
        generated_command = "HELLO-1"
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        self.cloud_server_atk.shared_data.device_table[target_device_id] = OtherDevice(
            device_id=target_device_id,
            device_u_ticket_for_owner=intercepted_uticket_json,
            ticket_order=2,
        )
        self.cloud_server_atk.shared_data.current_session.current_device_id = (
            target_device_id
        )
        self.cloud_server_atk.executor._change_state(
            this_device.STATE_AGENT_WAIT_FOR_CRKE1
        )
        self.cloud_server_atk.msg_sender._send_xxx_message(
            message.MESSAGE_VERIFY_AND_EXECUTE,
            u_ticket.MESSAGE_TYPE,
            intercepted_uticket_json,
        )
        wait_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: ATK's CS cannot share a private session with DO's IoTD
        #       (because ticket order is different after the u-ticket is used, the same u-ticket cannot be reused)
        assert "FAILURE" in self.iot_device.shared_data.result_message
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            != generated_command
        )

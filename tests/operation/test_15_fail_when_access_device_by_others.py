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
    create_simulated_comm_connection,
    wait_simulated_comm_completed,
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
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr
from ureka_framework.model.data_model.other_device import OtherDevice
import ureka_framework.model.data_model.this_device as this_device


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

        # WHEN: Intercept, Forge, & Apply
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
        create_simulated_comm_connection(self.cloud_server_atk, self.iot_device)
        generated_command = "HELLO-1"
        self.cloud_server_atk.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id, generated_command
        )
        wait_simulated_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: Because no legal issuer private key,
        #       legal authorization (issuer signature) cannot be generated
        assert (
            "-> FAILURE: VERIFY_ISSUER_SIGNATURE on ACCESS UTICKET"
            in self.iot_device.shared_data.result_message
        )
        assert (
            "-> FAILURE: VERIFY_RESULT"
            in self.cloud_server_atk.shared_data.result_message
        )

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

        # WHEN: Intercept & Preempt
        current_test_when_and_then_log()

        # WHEN: Interception (TYPE_ACCESS_UTICKET)
        #         Because TYPE_ACCESS_UTICKET has sent on BC, & maybe have been sent in WPAN (Reopen Session)
        #           the attacker can intercept & preempt it.
        create_simulated_comm_connection(self.user_agent_do, self.cloud_server_ep)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{self.cloud_server_ep.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.user_agent_do.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=target_device_id, arbitrary_dict=generated_request
        )
        wait_simulated_comm_completed(self.cloud_server_ep, self.user_agent_do)

        # WHEN: Pretend Holder: Other
        # WHEN: Interception (_holder_recv_u_ticket)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        intercepted_uticket_json = (
            self.cloud_server_ep.shared_data.received_message_json
        )
        self.cloud_server_atk.flow_issuer_issue_u_ticket._holder_recv_u_ticket(
            jsonstr_to_u_ticket(intercepted_uticket_json)
        )

        # WHEN: Preempt (holder_apply_u_ticket)
        create_simulated_comm_connection(self.cloud_server_atk, self.iot_device)
        generated_command = "HELLO-1"
        self.cloud_server_atk.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id, generated_command
        )
        wait_simulated_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: Because no legal holder private key,
        #       legal authentication (holder signature) cannot be generated
        assert (
            "-> FAILURE: VERIFY_HOLDER_SIGNATURE"
            in self.iot_device.shared_data.result_message
        )
        assert (
            "-> FAILURE: VERIFY_RESULT"
            in self.cloud_server_atk.shared_data.result_message
        )

    def test_fail_when_intercept_and_reuse_the_uticket(self) -> None:
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

        # WHEN: Intercept & Reuse
        current_test_when_and_then_log()

        # WHEN: Interception (TYPE_ACCESS_UTICKET)
        #         Because TYPE_ACCESS_UTICKET has sent on BC, & maybe have been sent in WPAN (Reopen Session)
        #           the attacker can intercept & reuse it.
        create_simulated_comm_connection(self.user_agent_do, self.cloud_server_ep)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{self.cloud_server_ep.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.user_agent_do.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=target_device_id, arbitrary_dict=generated_request
        )
        wait_simulated_comm_completed(self.cloud_server_ep, self.user_agent_do)

        # WHEN: Holder: EP's CS forward the access_u_ticket
        create_simulated_comm_connection(self.cloud_server_ep, self.iot_device)
        generated_command = "HELLO-1"
        self.cloud_server_ep.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id, generated_command
        )
        wait_simulated_comm_completed(self.cloud_server_ep, self.iot_device)

        # GIVEN: EP's CS close the session (ACCESS_END)
        create_simulated_comm_connection(self.cloud_server_ep, self.iot_device)
        generated_command = "ACCESS_END"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command, access_end=True
        )
        wait_simulated_comm_completed(self.cloud_server_ep, self.iot_device)

        # WHEN: Pretend Holder: Other
        # WHEN: Interception (_holder_recv_u_ticket)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        intercepted_uticket_json = self.cloud_server_ep.shared_data.device_table[
            target_device_id
        ].device_u_ticket_for_owner
        self.cloud_server_atk.flow_issuer_issue_u_ticket._holder_recv_u_ticket(
            jsonstr_to_u_ticket(intercepted_uticket_json)
        )

        # WHEN: Reuse (holder_apply_u_ticket)
        create_simulated_comm_connection(self.cloud_server_atk, self.iot_device)
        generated_command = "HELLO-1"
        self.cloud_server_atk.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id, generated_command
        )
        wait_simulated_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: Because no legal holder private key, legal authentication (holder signature) cannot be generated
        assert (
            "-> FAILURE: VERIFY_TICKET_ORDER"
            in self.iot_device.shared_data.result_message
        )
        assert (
            "-> FAILURE: VERIFY_RESULT"
            in self.cloud_server_atk.shared_data.result_message
        )

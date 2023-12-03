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
    enterprise_provider_server_and_her_limited_session,
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
from ureka_framework.model.data_model.current_session import current_session_to_jsonstr
from ureka_framework.model.data_model.other_device import OtherDevice
import ureka_framework.model.data_model.this_device as this_device


class TestFailWhenAccessDeviceByPrivateSession:
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
    # Threat: (E) Elevation of Privilege
    ######################################################
    def test_fail_when_apply_wrong_task_scope(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS open a seesion on DO's IoTD
        (
            self.user_agent_do,
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_limited_session()

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Holder: EP's CS forward the u_token
        create_simulated_comm_connection(self.cloud_server_ep, self.iot_device)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_command = "HELLO-2"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command
        )
        wait_simulated_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: Succeed to allow EP's CS to limitedly access DO's IoTD
        assert "SUCCESS" in self.iot_device.shared_data.result_message
        assert "SUCCESS" in self.cloud_server_ep.shared_data.result_message
        # THEN: Device: EP's CS can share a private session with DO's IoTD
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            == generated_command
        )
        assert (
            self.iot_device.shared_data.current_session.plaintext_data
            == "DATA: " + generated_command
        )
        assert (
            current_session_to_jsonstr(self.iot_device.shared_data.current_session)
            == current_session_to_jsonstr(
                self.cloud_server_ep.shared_data.current_session
            )
            != "{}"
        )

        # WHEN: Holder: EP's CS forward the u_token
        #   (with Forbidden command)
        create_simulated_comm_connection(self.cloud_server_ep, self.iot_device)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_command = "HELLO-3"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command
        )
        wait_simulated_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: Fail to allow EP's CS to limitedly access DO's IoTD
        assert "FAILURE" in self.iot_device.shared_data.result_message
        # THEN: Device: Not execute the forbidden command
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            != generated_command
        )
        assert (
            self.iot_device.shared_data.current_session.plaintext_data
            != "DATA: " + generated_command
        )

        # WHEN: Holder: EP's CS forward the u_token (ACCESS_END)
        create_simulated_comm_connection(self.cloud_server_ep, self.iot_device)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        original_device_order = self.iot_device.shared_data.this_device.ticket_order
        original_agent_order = self.cloud_server_ep.shared_data.device_table[
            target_device_id
        ].ticket_order
        generated_command = "ACCESS_END"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command, access_end=True
        )
        wait_simulated_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: Succeed to end this session
        assert "SUCCESS" in self.iot_device.shared_data.result_message
        assert "SUCCESS" in self.cloud_server_ep.shared_data.result_message
        # THEN: Device: Update ticket order, EP's CS cannot access DO's IoTD anymore
        assert (
            self.iot_device.shared_data.this_device.ticket_order
            == original_device_order + 1
        )
        assert (
            self.cloud_server_ep.shared_data.device_table[target_device_id].ticket_order
            == original_agent_order + 1
        )

        # WHEN: Holder: EP's CS return the access_end_r_ticket to DO's UA
        create_simulated_comm_connection(self.user_agent_do, self.cloud_server_ep)
        self.cloud_server_ep.flow_issuer_issue_u_ticket.holder_send_r_ticket_to_issuer(
            target_device_id
        )
        wait_simulated_comm_completed(self.user_agent_do, self.cloud_server_ep)

        # THEN: Issuer: DM's CS know that EP's CS has ended the private session with DO's IoTD (& ticket order++)
        assert "SUCCESS" in self.user_agent_do.shared_data.result_message
        assert (
            self.user_agent_do.shared_data.device_table[target_device_id].ticket_order
            == original_agent_order + 1
        )

    ######################################################
    # Threat: (S) Spoofing, (T) Tampering, (E) Elevation of Privilege
    ######################################################
    def test_fail_when_forge_hmac_and_apply_the_utoken(
        self,
    ) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS open a seesion on DO's IoTD
        (
            self.user_agent_do,
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: Intercept, Forge, & Apply
        current_test_when_and_then_log()

        # WHEN: Interception (Know Latest State)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        intercepted_uticket_json = self.cloud_server_ep.shared_data.device_table[
            target_device_id
        ].device_u_ticket_for_owner

        # WHEN: Pretend Holder: Other
        self.cloud_server_atk.shared_data.device_table[target_device_id] = OtherDevice(
            device_id=target_device_id,
            device_u_ticket_for_owner=intercepted_uticket_json,
            ticket_order=2,
        )
        # WHEN: Pretend Holder: Session
        # WHEN: Forge Flow (holder_apply_u_ticket, incl. _execute_cr_ke + _execute_ps)
        self.cloud_server_atk.shared_data.current_session.current_device_id = (
            target_device_id
        )
        self.cloud_server_atk.shared_data.current_session.current_session_key_str = (
            "TkVqlRZLmNoBwaso0I04jwMFPEIT0kQu1hJZWK9S90E="
        )
        self.cloud_server_atk.shared_data.current_session.iv_cmd = (
            self.cloud_server_ep.shared_data.current_session.iv_cmd
        )

        # WHEN: Apply Flow (holder_send_cmd, incl. _execute_ps)
        create_simulated_comm_connection(self.cloud_server_atk, self.iot_device)
        generated_command = "HELLO-2"
        self.cloud_server_atk.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command
        )
        wait_simulated_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: Because no legal session key,
        #       legal authentication (iv+hmac) cannot be generated
        assert (
            "-> FAILURE: VERIFY_IV_AND_HMAC"
            in self.iot_device.shared_data.result_message
        )
        assert (
            "-> FAILURE: VERIFY_RESULT"
            in self.cloud_server_atk.shared_data.result_message
        )

    # @pytest.mark.skip(reason="No mean to intercept so that not a valid attack pattern")
    def test_fail_when_intercept_and_preempt_to_apply_the_utoken(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS open a seesion on DO's IoTD
        (
            self.user_agent_do,
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: Intercept & Preempt
        current_test_when_and_then_log()

        # WHEN: Interception (TYPE_CMD_UTOKEN)
        #         Indeed, because TYPE_CMD_UTOKEN has NOT on BC & has NOT been Sent in WPAN (only used once),
        #           the attacker cannot intercept & preempt it.

    def test_fail_when_intercept_and_reuse_the_utoken(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS open a seesion on DO's IoTD
        (
            self.user_agent_do,
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: Intercept & Reuse
        current_test_when_and_then_log()

        # WHEN: Interception (TYPE_CMD_UTOKEN)
        #         Here, after TYPE_CMD_UTOKEN has been Sent in WPAN (i.e., used),
        #           the attacker can intercept & use it.
        create_simulated_comm_connection(self.cloud_server_ep, self.iot_device)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_command = "HELLO-2"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command
        )
        wait_simulated_comm_completed(self.cloud_server_ep, self.iot_device)

        # WHEN: Interception (_holder_recv_u_ticket, incl. _execute_cr_ke + _execute_ps)
        target_device_id = target_device_id
        intercepted_uticket_json = self.cloud_server_ep.shared_data.device_table[
            target_device_id
        ].device_u_ticket_for_owner

        # WHEN: Pretend Holder: Other
        # WHEN: Pretend Holder: Session
        self.cloud_server_atk.flow_issuer_issue_u_ticket._holder_recv_u_ticket(
            jsonstr_to_u_ticket(intercepted_uticket_json)
        )
        # WHEN: Interception (_device_recv_cmd)
        target_device_id = target_device_id
        intercepted_utoken_json = self.iot_device.shared_data.received_message_json

        # WHEN: Reuse (holder_send_cmd, incl. _execute_ps)
        create_simulated_comm_connection(self.cloud_server_atk, self.iot_device)
        self.cloud_server_atk.executor._change_state(
            this_device.STATE_AGENT_WAIT_FOR_DATA
        )
        self.cloud_server_atk.msg_sender._send_xxx_message(
            message.MESSAGE_VERIFY_AND_EXECUTE,
            u_ticket.MESSAGE_TYPE,
            intercepted_utoken_json,
        )
        wait_simulated_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: Because no legal session key & iv will be different in every use,
        #       legal authentication (iv+hmac) cannot be generated
        assert (
            "-> FAILURE: VERIFY_IV_AND_HMAC"
            in self.iot_device.shared_data.result_message
        )
        assert (
            "-> FAILURE: VERIFY_RESULT"
            in self.cloud_server_atk.shared_data.result_message
        )

    ######################################################
    # Threat: (R) Repudiation
    ######################################################
    @pytest.mark.skip(reason="TODO: More complete Tx")
    def test_fail_when_double_issuing_or_double_spending(self) -> None:
        current_test_given_log()

    ######################################################
    # Threat: (I) Information Disclosure
    ######################################################
    @pytest.mark.skip(reason="TODO: Not sure how to test")
    def test_fail_when_eavesdropping(self) -> None:
        current_test_given_log()

    ######################################################
    # Threat: (D) Denial of Service
    ######################################################
    @pytest.mark.skip(reason="TODO: Not implement yet")
    def test_fail_when_flooding(self) -> None:
        current_test_given_log()

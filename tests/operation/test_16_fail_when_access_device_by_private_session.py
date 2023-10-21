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
from ureka_framework.model.data_model.other_device import OtherDevice
import ureka_framework.model.data_model.this_device as this_device
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr


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
    @pytest.mark.skip(reason="TODO: Gather the failed test cases")
    def test_fail_when_apply_wrong_task_scope(self) -> None:
        current_test_given_log()

    ######################################################
    # Threat: (S) Spoofing, (T) Tampering, (E) Elevation of Privilege
    ######################################################
    def test_fail_when_forge_hmac_and_apply_the_utoken(
        self,
    ) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS can limitedly access DO's IoTD
        (
            self.user_agent_do,
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Holder: ATK's CS attempt to forward an u_token without session_key
        create_comm_connection(self.cloud_server_atk, self.iot_device)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        intercepted_uticket_json = self.cloud_server_ep.shared_data.device_table[
            target_device_id
        ].device_u_ticket_for_owner
        self.cloud_server_atk.shared_data.device_table[target_device_id] = OtherDevice(
            device_id=target_device_id,
            device_u_ticket_for_owner=intercepted_uticket_json,
            ticket_order=2,
        )
        self.cloud_server_atk.shared_data.current_session.current_device_id = (
            target_device_id
        )
        self.cloud_server_atk.shared_data.current_session.current_session_key_str = (
            "TkVqlRZLmNoBwaso0I04jwMFPEIT0kQu1hJZWK9S90E="
        )
        self.cloud_server_atk.shared_data.current_session.iv_cmd = (
            self.cloud_server_ep.shared_data.current_session.iv_cmd
        )

        generated_command = "HELLO-2"
        self.cloud_server_atk.flow_issue_u_token.holder_send_cmd(
            device_id=target_device_id, cmd=generated_command
        )
        wait_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: ATK's CS cannot share a private session with DO's IoTD
        #       (because no legal session key, legal u-token (& its hmac) cannot be generated)
        assert "FAILURE" in self.iot_device.shared_data.result_message
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            != generated_command
        )

    @pytest.mark.skip(reason="TODO: To be tested")
    def test_fail_when_intercept_and_preempt_to_apply_the_utoken(self) -> None:
        current_test_given_log()

    def test_fail_when_intercept_and_reuse_the_utoken(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS can limitedly access DO's IoTD
        (
            self.user_agent_do,
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # GIVEN: Holder: EP's CS forward the u_token
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        owned_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_command = "HELLO-2"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=owned_device_id, cmd=generated_command
        )
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: ATK's CS intercept the DO's u_token
        intercepted_utoken_json = self.iot_device.shared_data.received_message_json
        simple_log("debug", f"Intercepted UToken: {intercepted_utoken_json}")

        # WHEN: ATK's CS reuse the u_token on IoTD
        create_comm_connection(self.iot_device, self.cloud_server_atk)
        target_device_id = owned_device_id
        self.cloud_server_atk.shared_data.device_table[target_device_id] = OtherDevice(
            device_id=target_device_id,
            device_u_ticket_for_owner=intercepted_utoken_json,
            ticket_order=2,
        )
        self.cloud_server_atk.shared_data.current_session.iv_cmd = (
            self.cloud_server_ep.shared_data.current_session.iv_cmd
        )
        self.cloud_server_atk.executor._change_state(
            this_device.STATE_AGENT_WAIT_FOR_DATA
        )
        self.cloud_server_atk.msg_sender._send_xxx_message(
            message.MESSAGE_VERIFY_AND_EXECUTE,
            u_ticket.MESSAGE_TYPE,
            intercepted_utoken_json,
        )
        wait_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: ATK's CS cannot reuse the generated_command with DO's IoTD
        #       (because iv is different after the u-token is used, the same u-token (& its hmac) cannot be reused)
        assert "FAILURE" in self.iot_device.shared_data.result_message

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

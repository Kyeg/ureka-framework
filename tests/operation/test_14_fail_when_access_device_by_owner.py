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
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.data_model.other_device import OtherDevice


class TestFailWhenAccessDeviceByOwner:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self) -> Iterator[None]:
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SimpleStorage.delete_storage_in_test()

        # GIVEN+WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SimpleStorage.delete_storage_in_test()

    def test_fail_when_apply_wrong_holder_id(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Issuer: ATK's CS generate the self_access_u_ticket to herself
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        self.cloud_server_atk.shared_data.device_table[target_device_id] = OtherDevice(
            device_id=target_device_id,
            device_u_ticket="pretend to have legal ownership u-ticket",
            ticket_order=2,
        )
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{self.cloud_server_atk.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_SELFACCESS_UTICKET}",
        }
        self.cloud_server_atk.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=target_device_id, arbitrary_dict=generated_request
        )

        # WHEN: Holder: ATK's CS forward the self_access_u_ticket
        create_comm_connection(self.cloud_server_atk, self.iot_device)
        generated_command = "HELLO-1"
        self.cloud_server_atk.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id, generated_command
        )
        wait_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: ATK's CS cannot share a private session with DO's IoTD
        #       (because only device owner can be the ticket holder of self-access ticket)
        assert "FAILURE" in self.iot_device.shared_data.result_message
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            != generated_command
        )

    def test_fail_when_apply_wrong_holder_signature(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Issuer: DO's UA generate the access_u_ticket,
        #       but ATK's CS intercept the access_u_ticket & pretend to be DO's UA
        create_comm_connection(self.user_agent_do, self.cloud_server_atk)
        owned_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_request: dict = {
            "device_id": f"{owned_device_id}",
            "holder_id": f"{self.user_agent_do.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_SELFACCESS_UTICKET}",
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

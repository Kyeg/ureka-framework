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
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.model.data_model.current_session import current_session_to_jsonstr
from ureka_framework.resource.crypto.serialization_util import dict_to_jsonstr


class TestSuccessWhenAccessDeviceByOthers:
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

    def test_success_when_apply_access_u_ticket_on_device(self) -> None:
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

        # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
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

        # THEN: Succeed to allow EP's CS to limitedly access DO's IoTD
        assert "SUCCESS" in self.iot_device.shared_data.result_message
        assert "SUCCESS" in self.cloud_server_ep.shared_data.result_message
        # THEN: Device: Still DO's IoTD
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.user_agent_do.shared_data.this_person.person_pub_key_str
        )
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

    def test_success_when_reboot_device(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS open a seesion on DO's IoTD
        (
            self.user_agent_do,
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        assert (
            current_session_to_jsonstr(self.iot_device.shared_data.current_session)
            == current_session_to_jsonstr(
                self.cloud_server_ep.shared_data.current_session
            )
            != "{}"
        )

        # WHEN: Reboot DO's IoTD
        current_test_when_and_then_log()
        self.cloud_server_ep.reboot_device()
        self.iot_device.reboot_device()

        # THEN: The session is deleted (RAM-only)
        assert (
            current_session_to_jsonstr(self.cloud_server_ep.shared_data.current_session)
            == "{}"
        )
        assert (
            current_session_to_jsonstr(self.iot_device.shared_data.current_session)
            == "{}"
        )

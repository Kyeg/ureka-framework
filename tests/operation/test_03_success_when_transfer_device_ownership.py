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
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator

######################################################
# Import
######################################################
import ureka_framework.model.message_model.u_ticket as u_ticket


class TestSuccessWhenIntializeAgentOrServer:
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

    def test_success_when_apply_ownership_u_ticket_on_device(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.cloud_server_dm.shared_data.this_person.person_pub_key_str
        )

        # GIVEN: Initialized DO's UA
        self.user_agent_do = device_owner_agent()

        # WHEN:
        current_test_when_and_then_log()
        # WHEN: Issuer: DM's CS generate & send the ownership_u_ticket to DO's UA
        create_comm_connection(self.cloud_server_dm, self.user_agent_do)
        owned_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_request: dict = {
            "device_id": f"{owned_device_id}",
            "holder_id": f"{self.user_agent_do.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
        }
        self.cloud_server_dm.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=owned_device_id, arbitrary_dict=generated_request
        )
        wait_comm_completed(self.user_agent_do, self.cloud_server_dm)

        # WHEN: Holder: DO's UA forward the ownership_u_ticket
        create_comm_connection(self.user_agent_do, self.iot_device)
        self.user_agent_do.flow_apply_u_ticket.holder_apply_u_ticket(owned_device_id)
        wait_comm_completed(self.user_agent_do, self.iot_device)

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert "SUCCESS" in self.iot_device.shared_data.result_message
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.user_agent_do.shared_data.this_person.person_pub_key_str
        )

        # WHEN: Holder: DO's UA return the ownership_r_ticket to DM's CS
        create_comm_connection(self.user_agent_do, self.cloud_server_dm)
        self.user_agent_do.flow_issuer_issue_u_ticket.holder_send_r_ticket_to_issuer(
            owned_device_id
        )
        wait_comm_completed(self.cloud_server_dm, self.user_agent_do)

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert "SUCCESS" in self.iot_device.shared_data.result_message

    def test_success_when_reboot_device(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # WHEN: Reboot DO's IoTD
        current_test_when_and_then_log()
        self.iot_device.reboot_device()

        # THEN: Still be Initialized DO's IoTD
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.user_agent_do.shared_data.this_person.person_pub_key_str
        )

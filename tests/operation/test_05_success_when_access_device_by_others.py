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

        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.user_agent_do.shared_data.this_person.person_pub_key_str
        )

        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Issuer: DO's UA generate & send the access_u_ticket to EP's CS
        create_comm_connection(self.user_agent_do, self.cloud_server_ep)
        owned_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
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
            "holder_id": f"{self.cloud_server_ep.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"{generated_task_scope}",
        }
        self.user_agent_do.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=owned_device_id, arbitrary_dict=generated_request
        )
        wait_comm_completed(self.cloud_server_ep, self.user_agent_do)

        # WHEN: Holder: EP's CS forward the access_u_ticket
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        generated_command = "HELLO"
        self.cloud_server_ep.flow_apply_u_ticket.holder_apply_u_ticket(
            owned_device_id, generated_command
        )
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: Succeed to allow EP's CS to limitedly access DO's IoTD
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.user_agent_do.shared_data.this_person.person_pub_key_str
        )
        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            self.iot_device.shared_data.current_session.current_holder_id
            == self.cloud_server_ep.shared_data.current_session.current_holder_id
            != None
        )
        assert (
            self.iot_device.shared_data.current_session.current_task_scope
            == self.cloud_server_ep.shared_data.current_session.current_task_scope
            != None
        )
        assert (
            self.iot_device.shared_data.current_session.current_session_key_str
            == self.cloud_server_ep.shared_data.current_session.current_session_key_str
            != None
        )
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            == self.cloud_server_ep.shared_data.current_session.plaintext_cmd
            != None
        )
        assert (
            self.iot_device.shared_data.current_session.plaintext_data
            == self.cloud_server_ep.shared_data.current_session.plaintext_data
            != None
        )
        assert current_session_to_jsonstr(
            self.iot_device.shared_data.current_session
        ) == current_session_to_jsonstr(
            self.cloud_server_ep.shared_data.current_session
        )

    def test_success_when_open_private_session_on_device(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS can limitedly access DO's IoTD
        (
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        # WHEN:
        current_test_when_and_then_log()

        # WHEN: Holder: EP's CS forward the u_token
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        owned_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_command = "HELLO-2"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=owned_device_id, cmd=generated_command
        )
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            == self.cloud_server_ep.shared_data.current_session.plaintext_cmd
        )
        assert (
            self.iot_device.shared_data.current_session.plaintext_data
            == self.cloud_server_ep.shared_data.current_session.plaintext_data
        )
        assert current_session_to_jsonstr(
            self.iot_device.shared_data.current_session
        ) == current_session_to_jsonstr(
            self.cloud_server_ep.shared_data.current_session
        )

        # WHEN: Holder: EP's CS forward the u_token
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        owned_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        generated_command = "HELLO-3"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=owned_device_id, cmd=generated_command
        )
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: EP's CS can share a private session with DO's IoTD
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            == self.cloud_server_ep.shared_data.current_session.plaintext_cmd
        )
        assert (
            self.iot_device.shared_data.current_session.plaintext_data
            == self.cloud_server_ep.shared_data.current_session.plaintext_data
        )
        assert current_session_to_jsonstr(
            self.iot_device.shared_data.current_session
        ) == current_session_to_jsonstr(
            self.cloud_server_ep.shared_data.current_session
        )

        # WHEN: Holder: EP's CS forward the u_token (TX_END)
        create_comm_connection(self.cloud_server_ep, self.iot_device)
        owned_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        original_device_order = self.iot_device.shared_data.this_device.ticket_order
        original_agent_order = self.cloud_server_ep.shared_data.device_table[
            owned_device_id
        ].ticket_order
        generated_command = "TX_END"
        self.cloud_server_ep.flow_issue_u_token.holder_send_cmd(
            device_id=owned_device_id, cmd=generated_command, tx_end=True
        )
        wait_comm_completed(self.cloud_server_ep, self.iot_device)

        # THEN: EP's CS can end this private session with DO's IoTD (& ticket order++)
        assert (
            self.iot_device.shared_data.this_device.ticket_order
            == original_device_order + 1
        )
        assert (
            self.cloud_server_ep.shared_data.device_table[owned_device_id].ticket_order
            == original_agent_order + 1
        )
        # THEN: EP's CS cannot access DO's IoTD anymore

    def test_success_when_reboot_device(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized EP's CS can limitedly access DO's IoTD
        (
            self.cloud_server_ep,
            self.iot_device,
        ) = enterprise_provider_server_and_her_session()

        assert current_session_to_jsonstr(
            self.iot_device.shared_data.current_session
        ) == current_session_to_jsonstr(
            self.cloud_server_ep.shared_data.current_session
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

    @pytest.mark.skip(reason="TODO: Access Agent")
    def test_success_when_apply_access_u_ticket_on_agent(self) -> None:
        current_test_given_log()
        current_test_when_and_then_log()

    @pytest.mark.skip(reason="TODO: Access Agent")
    def test_success_when_open_private_session_on_agent(self) -> None:
        current_test_given_log()
        current_test_when_and_then_log()

    @pytest.mark.skip(reason="TODO: Access Agent")
    def test_success_when_reboot_agent(self) -> None:
        current_test_given_log()
        current_test_when_and_then_log()

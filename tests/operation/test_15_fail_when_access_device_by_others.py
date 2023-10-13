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
from ureka_framework.model.data_model.other_device import OtherDevice


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
    # (S) Spoofing, (T) Tampering, (E) Elevation of privilege
    ######################################################
    def test_fail_when_apply_wrong_issuer_signature(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        # GIVEN: Initialized ATK's CS
        current_test_given_log()
        (
            self.user_agent_do,
            self.iot_device,
            self.cloud_server_atk,
        ) = device_owner_agent_and_her_device_and_attacker()

        # WHEN:
        current_test_when_and_then_log()
        # WHEN: Issuer: ATK's CS forge an access_u_ticket to herself
        create_comm_connection(self.cloud_server_atk, self.iot_device)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        self.cloud_server_atk.shared_data.device_table[target_device_id] = OtherDevice(
            device_id=target_device_id,
            device_u_ticket="not important",
            ticket_order=2,
        )
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{self.cloud_server_atk.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"not important",
        }
        self.cloud_server_atk.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=target_device_id, arbitrary_dict=generated_request
        )
        generated_command = "HELLO"
        self.cloud_server_atk.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id, generated_command
        )
        wait_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: Fail to allow ATK's CS to limitedly access DO's IoTD (wrong issuer signature)
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.user_agent_do.shared_data.this_person.person_pub_key_str
        )
        # THEN: ATK's CS cannot share a private session with DO's IoTD
        assert (
            self.iot_device.shared_data.current_session.current_session_key_str == None
        )
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            != self.cloud_server_atk.shared_data.current_session.plaintext_cmd
        )

    def test_fail_when_apply_wrong_holder_signature(self) -> None:
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
        generated_request: dict = {
            "device_id": f"{owned_device_id}",
            "holder_id": f"{self.cloud_server_ep.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_ACCESS_UTICKET}",
            "task_scope": f"not important",
        }
        self.user_agent_do.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
            device_id=owned_device_id, arbitrary_dict=generated_request
        )
        wait_comm_completed(self.cloud_server_atk, self.user_agent_do)

        # WHEN: Holder: ATK's CS forward the access_u_ticket
        create_comm_connection(self.cloud_server_atk, self.iot_device)
        generated_command = "HELLO"
        self.cloud_server_atk.flow_apply_u_ticket.holder_apply_u_ticket(
            owned_device_id, generated_command
        )
        wait_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: Fail to allow ATK's CS to limitedly access DO's IoTD (wrong holder signature)
        # THEN: Still DO's IoTD
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.user_agent_do.shared_data.this_person.person_pub_key_str
        )
        # THEN: ATK's CS cannot share a private session with DO's IoTD
        assert (
            self.iot_device.shared_data.current_session.current_session_key_str == None
        )
        assert (
            self.iot_device.shared_data.current_session.plaintext_cmd
            != self.cloud_server_atk.shared_data.current_session.plaintext_cmd
        )

    @pytest.mark.skip(reason="TO-DO: Should be tested")
    def test_fail_when_apply_wrong_hmac(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TO-DO: Should be tested")
    def test_fail_when_reuse_the_same_uticket(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TO-DO: Should be tested")
    def test_fail_when_reuse_the_same_utoken(self) -> None:
        current_test_given_log()

    ######################################################
    # (R) Repudiation
    ######################################################
    @pytest.mark.skip(reason="TODO: More complete Tx")
    def test_fail_when_double_issuing_or_double_spending(self) -> None:
        current_test_given_log()

    ######################################################
    # (I) Information Disclosure
    ######################################################
    @pytest.mark.skip(reason="TODO: Not sure how to test")
    def test_fail_when_eavesdropping(self) -> None:
        current_test_given_log()

    ######################################################
    # (D) Denial of Service
    ######################################################
    @pytest.mark.skip(reason="TODO: Not implement yet")
    def test_fail_when_flooding(self) -> None:
        current_test_given_log()

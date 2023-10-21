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


class TestFailWhenTransferDeviceOwnership:
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

    ######################################################
    # Threat: (S) Spoofing, (T) Tampering, (E) Elevation of Privilege
    ######################################################
    @pytest.mark.skip(reason="TODO: Simulate interception")
    def test_fail_when_forge_holder_id_and_issuer_sig_and_apply_the_uticket(
        self,
    ) -> None:
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
        # WHEN: Issuer: ATK's CS forge an access_u_ticket to herself without issuer's signature
        create_comm_connection(self.cloud_server_atk, self.iot_device)
        target_device_id = self.iot_device.shared_data.this_device.device_pub_key_str
        intercepted_uticket_json = self.user_agent_do.shared_data.device_table[
            target_device_id
        ].device_u_ticket_for_owner
        self.cloud_server_atk.shared_data.device_table[target_device_id] = OtherDevice(
            device_id=target_device_id,
            device_u_ticket_for_owner=intercepted_uticket_json,
            ticket_order=2,
        )
        generated_request: dict = {
            "device_id": f"{target_device_id}",
            "holder_id": f"{self.cloud_server_atk.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
        }
        self.cloud_server_atk.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=target_device_id, arbitrary_dict=generated_request
        )
        self.cloud_server_atk.flow_apply_u_ticket.holder_apply_u_ticket(
            target_device_id
        )
        wait_comm_completed(self.cloud_server_atk, self.iot_device)

        # THEN: ATK's CS cannot share a private session with DO's IoTD (wrong issuer signature)
        #       (because no legal issuer private key, legal authorization (issuer signature) cannot be generated)
        assert "FAILURE" in self.iot_device.shared_data.result_message
        assert "VERIFY_ISSUER_SIGNATURE" in self.iot_device.shared_data.result_message

    @pytest.mark.skip(reason="TODO: To be tested")
    def test_fail_when_intercept_and_preempt_to_apply_the_uticket(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TODO: To be tested")
    def test_fail_when_intercept_and_reuse_the_uticket(self) -> None:
        current_test_given_log()

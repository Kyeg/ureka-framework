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
from ureka_framework.model.message_model.r_ticket import jsonstr_to_r_ticket
from ureka_framework.resource.logger.simple_logger import simple_log
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


######################################################
# Import
######################################################
import ureka_framework.model.message_model.u_ticket as u_ticket


class TestFailWhenInitializeDevice:
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

    # @pytest.mark.skip(reason="Implemented but not tested")
    def test_fail_when_re_initialize_device(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # WHEN:
        current_test_when_and_then_log()
        # WHEN: DM's CS re-generate & re-send the intialization_u_ticket to Initialized IoTD
        create_comm_connection(self.cloud_server_dm, self.iot_device)
        id_for_initialization_u_ticket = "no_id"
        generated_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        self.cloud_server_dm.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
        )
        self.cloud_server_dm.flow_apply_u_ticket.holder_apply_u_ticket(
            id_for_initialization_u_ticket
        )
        wait_comm_completed(self.cloud_server_dm, self.iot_device)

        # THEN: Fail to re-initialize IoTD & R-Ticket will provide the reason
        for value in self.cloud_server_dm.shared_data.device_table.values():
            if value.device_id != "no_id":
                assert (
                    jsonstr_to_r_ticket(value.device_r_ticket).result
                    == "FAILURE: IOT_DEVICE ALREADY INITIALIZED"
                )

    @pytest.mark.skip(reason="Implemented but not tested")
    def test_fail_when_initialize_device_by_intializing_agent_or_server(self) -> None:
        current_test_given_log()

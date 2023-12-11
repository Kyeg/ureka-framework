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
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.message_model.u_ticket as u_ticket
import ureka_framework.model.data_model.this_device as this_device


class TestSuccessWhenIntializeDevice:
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

    def test_success_when_apply_initialization_u_ticket_on_device(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=this_device.IOT_DEVICE,
            device_name="iot_device",
        )
        assert self.iot_device.shared_data.this_device.ticket_order == 0
        assert self.iot_device.shared_data.this_device.device_priv_key_str == None
        assert self.iot_device.shared_data.this_device.device_pub_key_str == None
        assert self.iot_device.shared_data.this_device.owner_pub_key_str == None
        assert self.iot_device.shared_data.this_person.person_priv_key_str == None
        assert self.iot_device.shared_data.this_person.person_pub_key_str == None

        # WHEN:
        current_test_when_and_then_log()
        # WHEN: Issuer: DM's CS generate the intialization_u_ticket to herself
        id_for_initialization_u_ticket = "no_id"
        generated_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        self.cloud_server_dm.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
            device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
        )

        # WHEN: Holder: DM's CS forward the access_u_ticket to Uninitialized IoTD
        create_simulated_comm_connection(self.cloud_server_dm, self.iot_device)
        self.cloud_server_dm.flow_apply_u_ticket.holder_apply_u_ticket(
            id_for_initialization_u_ticket
        )
        wait_simulated_comm_completed(self.cloud_server_dm, self.iot_device)

        # THEN: Succeed to initialize DM's IoTD
        assert "SUCCESS" in self.iot_device.shared_data.result_message
        assert "SUCCESS" in self.cloud_server_dm.shared_data.result_message
        # THEN: Device: Set New Owner, Update ticket order
        assert self.iot_device.shared_data.this_device.ticket_order == 1
        assert self.iot_device.shared_data.this_device.device_priv_key_str != None
        assert self.iot_device.shared_data.this_device.device_pub_key_str != None
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.cloud_server_dm.shared_data.this_person.person_pub_key_str
        )
        assert self.iot_device.shared_data.this_person.person_priv_key_str == None
        assert self.iot_device.shared_data.this_person.person_pub_key_str == None

    def test_success_when_reboot_device(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # WHEN: Reboot DM's IoTD
        current_test_when_and_then_log()
        self.iot_device.reboot_device()

        # THEN: Still be Initialized DM's IoTD
        assert self.iot_device.shared_data.this_device.ticket_order == 1
        assert self.iot_device.shared_data.this_device.device_priv_key_str != None
        assert self.iot_device.shared_data.this_device.device_pub_key_str != None
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.cloud_server_dm.shared_data.this_person.person_pub_key_str
        )
        assert self.iot_device.shared_data.this_person.person_priv_key_str == None
        assert self.iot_device.shared_data.this_person.person_pub_key_str == None

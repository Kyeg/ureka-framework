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

    def test_success_when_apply_initialization_u_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=this_device.IOT_DEVICE,
            device_name="iot_device",
        )
        assert self.iot_device.shared_data.this_device.is_initialized == False
        assert self.iot_device.shared_data.this_device.device_priv_key_str == None
        assert self.iot_device.shared_data.this_device.device_pub_key_str == None
        assert self.iot_device.shared_data.this_device.owner_pub_key_str == None
        assert self.iot_device.shared_data.this_person.person_priv_key_str == None
        assert self.iot_device.shared_data.this_person.person_pub_key_str == None

        # WHEN:
        current_test_when_and_then_log()
        # WHEN: Issuer: DM's CS generate & send the intialization_u_ticket to Uninitialized IoTD
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

        # THEN: Succeed to initialize DM's IoTD
        assert self.iot_device.shared_data.this_device.is_initialized == True
        assert self.iot_device.shared_data.this_device.device_priv_key_str != None
        assert self.iot_device.shared_data.this_device.device_pub_key_str != None
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.cloud_server_dm.shared_data.this_person.person_pub_key_str
        )
        assert self.iot_device.shared_data.this_person.person_priv_key_str == None
        assert self.iot_device.shared_data.this_person.person_pub_key_str == None

    @pytest.mark.skip(reason="Implemented but not tested")
    def test_success_when_reboot(self) -> None:
        current_test_given_log()

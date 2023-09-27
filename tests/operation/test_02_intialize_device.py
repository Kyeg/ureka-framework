from returns.result import Success, Failure
import pytest
from tests.conftest import (
    create_comm_connection,
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
    device_manufacturer_server_and_her_device,
)
from ureka_framework.logic.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.u_ticket as u_ticket
import ureka_framework.data_model.this_device as this_device
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


class TestIntializeDevice:
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

    def test_apply_initialization_u_ticket_in_io_level(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=this_device.IOT_DEVICE,
            device_name="iot_device",
        )
        assert self.iot_device.this_device.is_initialized == False
        assert self.iot_device.this_device.device_priv_key_str == None
        assert self.iot_device.this_device.device_pub_key_str == None
        assert self.iot_device.this_device.owner_pub_key_str == None
        assert self.iot_device.this_person.person_priv_key_str == None
        assert self.iot_device.this_person.person_pub_key_str == None

        # WHEN:
        current_test_when_and_then_log()
        # WHEN: Issuer: DM's CS generate & send the intialization_u_ticket to Uninitialized IoTD
        create_comm_connection(self.cloud_server_dm, self.iot_device)
        id_for_initialization_u_ticket = "no_id"
        generated_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        self.cloud_server_dm.issuer_issue_consent_to_herself(
            device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
        )
        self.cloud_server_dm.holder_access_device(id_for_initialization_u_ticket)

        # [Test Only] Wait for all threads to finish their works (block last 1st make log beautiful)
        self.cloud_server_dm.wait_all_test_completed()
        self.iot_device.wait_all_test_completed()

        # THEN: Succeed to initialize DM's IoTD
        assert self.iot_device.this_device.is_initialized == True
        assert self.iot_device.this_device.device_priv_key_str != None
        assert self.iot_device.this_device.device_pub_key_str != None
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.cloud_server_dm.this_person.person_pub_key_str
        )
        assert self.iot_device.this_person.person_priv_key_str == None
        assert self.iot_device.this_person.person_pub_key_str == None

    def test_apply_initialization_u_ticket_reintialized_failed_in_io_level(
        self,
    ) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # WHEN: DM's CS apply_initialization_u_ticket() on Initialized IoTD
        current_test_when_and_then_log()
        # WHEN: Issuer: DM's CS generate & send the intialization_u_ticket to Initialized IoTD
        create_comm_connection(self.cloud_server_dm, self.iot_device)
        id_for_initialization_u_ticket = "no_id"
        generated_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        self.cloud_server_dm.issuer_issue_consent_to_herself(
            device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
        )
        self.cloud_server_dm.holder_access_device(id_for_initialization_u_ticket)

        # [Test Only] Wait for all threads to finish their works (block last 1st make log beautiful)
        self.cloud_server_dm.wait_all_test_completed()
        self.iot_device.wait_all_test_completed()

        # THEN: Failed to re-initialize DM's IoTD

    def test_apply_initialization_u_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=this_device.IOT_DEVICE,
            device_name="iot_device",
        )
        assert self.iot_device.this_device.is_initialized == False
        assert self.iot_device.this_device.device_priv_key_str == None
        assert self.iot_device.this_device.device_pub_key_str == None
        assert self.iot_device.this_device.owner_pub_key_str == None
        assert self.iot_device.this_person.person_priv_key_str == None
        assert self.iot_device.this_person.person_pub_key_str == None

        # WHEN: DM's CS apply_initialization_u_ticket() on Uninitialized IoTD
        current_test_when_and_then_log()

        id_for_initialization_u_ticket = "no_id"
        test_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_dm._generate_xxx_u_ticket(test_request)
        result = self.iot_device._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # THEN: Succeed to initialize DM's IoTD
        assert type(result) == Success
        assert self.iot_device.this_device.is_initialized == True
        assert self.iot_device.this_device.device_priv_key_str != None
        assert self.iot_device.this_device.device_pub_key_str != None
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.cloud_server_dm.this_person.person_pub_key_str
        )
        assert self.iot_device.this_person.person_priv_key_str == None
        assert self.iot_device.this_person.person_pub_key_str == None

    def test_apply_initialization_u_ticket_reintialized_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # WHEN: DM's CS apply_initialization_u_ticket() on Initialized IoTD
        current_test_when_and_then_log()
        id_for_initialization_u_ticket = "no_id"
        test_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_dm._generate_xxx_u_ticket(test_request)
        result = self.iot_device._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # THEN: Failed to re-initialize DM's IoTD
        assert type(result) == Failure
        assert result.failure().args[0] == "FAILURE: IOT_DEVICE ALREADY INITIALIZED"

    def test_apply_initialization_u_ticket_to_agent_or_server_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized UA
        self.user_agent = DeviceController(
            device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
            device_name="user_agent",
        )

        # WHEN: DM's CS apply_initialization_u_ticket() on UA
        current_test_when_and_then_log()
        id_for_initialization_u_ticket = "no_id"
        test_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_dm._generate_xxx_u_ticket(test_request)
        result = self.user_agent._verify_and_execute_xxx_u_ticket(test_u_ticket)

        # THEN: Failed to initialize UA
        assert type(result) == Failure

    def test_intialize_device_with_reboot(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # WHEN: Reboot the DM's IoTD
        current_test_when_and_then_log()
        self.iot_device.reboot_device()

        # THEN: Still is initialized IoTD
        assert self.iot_device.this_device.is_initialized == True
        assert self.iot_device.this_device.device_priv_key_str != None
        assert self.iot_device.this_device.device_pub_key_str != None
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.cloud_server_dm.this_person.person_pub_key_str
        )
        assert self.iot_device.this_person.person_priv_key_str == None
        assert self.iot_device.this_person.person_pub_key_str == None

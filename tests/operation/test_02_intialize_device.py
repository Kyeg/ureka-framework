import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    create_comm_connection,
    wait_comm_completed,
    device_manufacturer_server,
    device_manufacturer_server_and_her_device,
)
from ureka_framework.logic.device_controller import (
    DeviceController,
)
import ureka_framework.model.message.u_ticket as u_ticket
import ureka_framework.model.data_model.this_device as this_device
from ureka_framework.resource.logger.simple_logger import simple_log
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
        self.cloud_server_dm.issuer_issue_u_ticket_to_herself(
            device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
        )
        self.cloud_server_dm.holder_apply_u_ticket(id_for_initialization_u_ticket)
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

    @pytest.mark.skip(reason="Not implemented Error Ticket")
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
            "holder_id": f"{self.cloud_server_dm.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        self.cloud_server_dm.issuer_issue_u_ticket_to_herself(
            device_id=id_for_initialization_u_ticket, arbitrary_dict=generated_request
        )
        self.cloud_server_dm.holder_apply_u_ticket(id_for_initialization_u_ticket)
        wait_comm_completed(self.cloud_server_dm, self.iot_device)

        # THEN: Failed to re-initialize DM's IoTD

    @pytest.mark.skip(reason="Broken test")
    def test_apply_initialization_u_ticket(self) -> None:
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

        # WHEN: DM's CS apply_initialization_u_ticket() on Uninitialized IoTD
        current_test_when_and_then_log()

        id_for_initialization_u_ticket = "no_id"
        test_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_dm.msg_generator._generate_xxx_u_ticket(
            test_request
        )
        result = self.iot_device.msg_verifier.verify_u_ticket_can_execute(test_u_ticket)

        # THEN: Succeed to initialize DM's IoTD
        assert type(result) == Success
        assert self.iot_device.shared_data.this_device.is_initialized == True
        assert self.iot_device.shared_data.this_device.device_priv_key_str != None
        assert self.iot_device.shared_data.this_device.device_pub_key_str != None
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.cloud_server_dm.shared_data.this_person.person_pub_key_str
        )
        assert self.iot_device.shared_data.this_person.person_priv_key_str == None
        assert self.iot_device.shared_data.this_person.person_pub_key_str == None

    @pytest.mark.skip(reason="Broken test")
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
            "holder_id": f"{self.cloud_server_dm.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_dm.msg_generator._generate_xxx_u_ticket(
            test_request
        )
        simple_log("debug", f"test_u_ticket = {test_u_ticket}")
        result = self.iot_device.msg_verifier.verify_u_ticket_can_execute(test_u_ticket)

        # THEN: Failed to re-initialize DM's IoTD
        assert type(result) == Failure
        # assert result.failure().args[0] == "FAILURE: IOT_DEVICE ALREADY INITIALIZED"
        assert result.failure().args[0] == "-> FAILURE: VERIFY_TICKET_ORDER"

    @pytest.mark.skip(reason="Broken test")
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
            "holder_id": f"{self.cloud_server_dm.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_dm.msg_generator._generate_xxx_u_ticket(
            test_request
        )
        result = self.user_agent.msg_verifier.verify_u_ticket_can_execute(test_u_ticket)

        # THEN: Failed to initialize UA
        assert type(result) == Failure

    @pytest.mark.skip(reason="Broken test")
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
        assert self.iot_device.shared_data.this_device.is_initialized == True
        assert self.iot_device.shared_data.this_device.device_priv_key_str != None
        assert self.iot_device.shared_data.this_device.device_pub_key_str != None
        assert (
            self.iot_device.shared_data.this_device.owner_pub_key_str
            == self.cloud_server_dm.shared_data.this_person.person_pub_key_str
        )
        assert self.iot_device.shared_data.this_person.person_priv_key_str == None
        assert self.iot_device.shared_data.this_person.person_pub_key_str == None

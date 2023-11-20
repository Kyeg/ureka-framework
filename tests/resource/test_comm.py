######################################################
# Test Fixtures
######################################################
import pytest
from tests.conftest import (
    create_simulated_comm_connection,
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator

######################################################
# Import
######################################################
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.message_model.message as message
from ureka_framework.model.message_model import u_ticket
import ureka_framework.model.data_model.this_device as this_device


class TestStorage:
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

    @pytest.mark.skip(reason="Broken test because of the concurrent receiver")
    def test_simulated_comm_channel(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=this_device.IOT_DEVICE,
            device_name="iot_device",
        )

        # WHEN: Construct a Comm Channel between two devices
        current_test_when_and_then_log()
        create_simulated_comm_connection(self.cloud_server_dm, self.iot_device)

        # WHEN: Send/Recv the message through Comm Channel
        id_for_initialization_u_ticket = "no_id"
        test_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_dm.msg_generator._generate_xxx_u_ticket(
            test_request
        )
        self.cloud_server_dm.msg_sender._send_xxx_message(
            message.MESSAGE_VERIFY_AND_EXECUTE, u_ticket.MESSAGE_TYPE, test_u_ticket
        )

        self.iot_device.msg_receiver._recv_xxx_message()
        result = self.iot_device.msg_verifier.verify_u_ticket_can_execute(test_u_ticket)

        # THEN: The messages sent and received are the same
        assert (
            self.cloud_server_dm.simulated_comm_channel.recv_message
            == self.iot_device.simulated_comm_channel.recv_message
            == test_u_ticket
        )

        # THEN: The message is verified
        assert self.cloud_server_dm.shared_data.this_device.ticket_order == 1

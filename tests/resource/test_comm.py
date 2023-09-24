from returns.result import Success, Failure
import pytest
from tests.conftest import (
    create_comm_connection,
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.logic.device_controller import DeviceController
from ureka_framework.data_model import u_ticket

from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


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

    def test_comm_channel(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=u_ticket.IOT_DEVICE,
            device_name="iot_device",
        )

        # WHEN: Construct a Comm Channel between two devices
        current_test_when_and_then_log()
        create_comm_connection(self.cloud_server_dm, self.iot_device)

        # WHEN: Send/Recv the message through Comm Channel
        id_for_initialization_u_ticket = "no_id"
        test_request: dict = {
            "device_id": f"{id_for_initialization_u_ticket}",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_INITIALIZATION_UTICKET}",
        }
        test_u_ticket: str = self.cloud_server_dm._generate_xxx_u_ticket(test_request)
        self.cloud_server_dm._send_xxx_message(test_u_ticket)

        self.iot_device._recv_xxx_message()
        result = self.iot_device._verify_xxx_u_ticket(test_u_ticket)

        # THEN: The messages sent and received are the same
        assert (
            self.cloud_server_dm.comm_channel.message_in_channel
            == self.iot_device.comm_channel.message_in_channel
            == test_u_ticket
        )

        # THEN: The message is verified
        assert type(result) == Success
        assert self.iot_device.this_device.is_initialized == True

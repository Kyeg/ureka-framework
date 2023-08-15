from returns.result import Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.controller.device_controller import DeviceController
from ureka_framework.data_model import ticket

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
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
        )

        # WHEN: Construct a Comm Channel between two devices
        current_test_when_and_then_log()
        fake_comm_chanel = FakeCommChannel(ends=[self.cloud_server_dm, self.iot_device])
        self.cloud_server_dm.connect(fake_comm_chanel)
        self.iot_device.connect(fake_comm_chanel)

        # WHEN: Send/Recv the message through Comm Channel
        test_request: dict = {
            "device_id": f"",
            "holder_id": f"{self.cloud_server_dm.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_INITIALIZATION_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        self.cloud_server_dm.send_xxx_ticket(test_ticket)

        self.iot_device.recv_xxx_ticket()
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: The messages sent and received are the same
        assert (
            self.cloud_server_dm.comm_channel.message_in_channel
            == self.iot_device.comm_channel.message_in_channel
            == test_ticket
        )

        # THEN: The message is verified
        assert type(result) == Success
        assert self.iot_device.this_device.is_initialized == True

from returns.result import Result, Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.controller.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.storage.secure_db import SecureDB


class TestArbitraryInput:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self):
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SecureDB.delete_secure_db_in_test()

        # GIVEN+WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SecureDB.delete_secure_db_in_test()

    def test_apply_arbitrary_request(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
        )

        # WHEN: DM's CS apply_initialization_ticket() on Uninitialized IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"",
            "holder_id": f"{self.cloud_server_dm.device_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_INITIALIZATION_TICKET}",
            "task_scope": f"",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Initialized DM's IoTD
        assert type(result) == Success
        assert self.iot_device.is_initialized == True
        assert self.iot_device.device_priv_key_str != ""
        assert self.iot_device.device_pub_key_str != ""
        assert (
            self.iot_device.owner_pub_key_str == self.cloud_server_dm.device_pub_key_str
        )

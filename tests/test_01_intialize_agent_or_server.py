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
from typing import Iterator


class TestIntializeAgentOrServer:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self) -> Iterator[None]:
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SecureDB.delete_secure_db_in_test()

        # GIVEN+WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SecureDB.delete_secure_db_in_test()

    def test_intialize_agent_or_server(self) -> None:
        current_test_given_log()

        # GIVEN: Uninitialized CS
        self.cloud_server_dm = DeviceController(
            device_type=ticket.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_dm",
        )
        assert self.cloud_server_dm.is_initialized == False
        assert self.cloud_server_dm.device_priv_key_str == ""
        assert self.cloud_server_dm.device_pub_key_str == ""

        # WHEN: DM apply execute_one_time_intialize_agent_or_server() on Uninitialized CS
        current_test_when_and_then_log()
        result = self.cloud_server_dm.execute_one_time_intialize_agent_or_server()

        # THEN: Succeed to initialized DM's CS
        assert type(result) == Success
        assert self.cloud_server_dm.is_initialized == True
        assert self.cloud_server_dm.device_priv_key_str != ""
        assert self.cloud_server_dm.device_pub_key_str != ""

    def test_intialize_agent_or_server_reintialized_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: DM apply execute_one_time_intialize_agent_or_server() on Initialized CS
        current_test_when_and_then_log()
        result = self.cloud_server_dm.execute_one_time_intialize_agent_or_server()

        # THEN: Failed to re-initialize DM's CS
        assert type(result) == Failure
        assert (
            result.failure().args[0]
            == "FAILURE: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED"
        )

    def test_intialize_agent_or_server_to_device_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Uninitialized IoTD
        self.iot_device = DeviceController(
            device_type=ticket.IOT_DEVICE,
            device_name="iot_device",
        )

        # WHEN: DM apply execute_one_time_intialize_agent_or_server() on IoTD
        current_test_when_and_then_log()
        result = self.iot_device.execute_one_time_intialize_agent_or_server()

        # THEN: Failed to initialize IoTD
        assert type(result) == Failure

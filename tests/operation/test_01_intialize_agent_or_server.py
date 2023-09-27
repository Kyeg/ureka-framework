from returns.result import Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.logic.device_controller import (
    DeviceController,
)
import ureka_framework.data_model.u_ticket as u_ticket
import ureka_framework.data_model.this_device as this_device
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


class TestIntializeAgentOrServer:
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

    @pytest.mark.skip(reason="Implemented but not tested yet")
    def test_intialize_agent_or_server_in_io_level(self) -> None:
        current_test_given_log()

    def test_intialize_agent_or_server(self) -> None:
        current_test_given_log()

        # GIVEN: Uninitialized CS
        self.cloud_server_dm = DeviceController(
            device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_dm",
        )
        assert self.cloud_server_dm.this_device.is_initialized == False
        assert self.cloud_server_dm.this_device.device_priv_key_str == None
        assert self.cloud_server_dm.this_device.device_pub_key_str == None
        assert self.cloud_server_dm.this_device.owner_pub_key_str == None
        assert self.cloud_server_dm.this_person.person_priv_key_str == None
        assert self.cloud_server_dm.this_person.person_pub_key_str == None

        # WHEN: DM apply execute_one_time_intialize_agent_or_server() on Uninitialized CS
        current_test_when_and_then_log()
        result = self.cloud_server_dm._execute_one_time_intialize_agent_or_server()

        # THEN: Succeed to initialized DM's CS
        # logging.debug(f"Successful result = {result.unwrap()}")
        assert type(result) == Success
        assert self.cloud_server_dm.this_device.is_initialized == True
        assert self.cloud_server_dm.this_device.device_priv_key_str != None
        assert self.cloud_server_dm.this_device.device_pub_key_str != None
        assert self.cloud_server_dm.this_device.owner_pub_key_str != None
        assert self.cloud_server_dm.this_person.person_priv_key_str != None
        assert self.cloud_server_dm.this_person.person_pub_key_str != None

    def test_intialize_agent_or_server_reintialized_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: DM apply execute_one_time_intialize_agent_or_server() on Initialized CS
        current_test_when_and_then_log()
        result = self.cloud_server_dm._execute_one_time_intialize_agent_or_server()

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
            device_type=this_device.IOT_DEVICE,
            device_name="iot_device",
        )

        # WHEN: DM apply execute_one_time_intialize_agent_or_server() on IoTD
        current_test_when_and_then_log()
        result = self.iot_device._execute_one_time_intialize_agent_or_server()

        # THEN: Failed to initialize IoTD
        assert type(result) == Failure

    def test_intialize_agent_or_server_with_reboot(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Reboot the DM's CS
        current_test_when_and_then_log()
        self.cloud_server_dm.reboot_device()

        # THEN: Still is initialized  IoTD
        assert self.cloud_server_dm.this_device.is_initialized == True
        assert self.cloud_server_dm.this_device.device_priv_key_str != None
        assert self.cloud_server_dm.this_device.device_pub_key_str != None
        assert self.cloud_server_dm.this_device.owner_pub_key_str != None
        assert self.cloud_server_dm.this_person.person_priv_key_str != None
        assert self.cloud_server_dm.this_person.person_pub_key_str != None

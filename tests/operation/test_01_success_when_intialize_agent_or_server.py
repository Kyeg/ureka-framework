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
import ureka_framework.model.data_model.this_device as this_device


class TestSuccessWhenIntializeAgentOrServer:
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

    def test_success_when_intialize_agent_or_server(self) -> None:
        current_test_given_log()

        # GIVEN: Uninitialized CS
        self.cloud_server_dm = DeviceController(
            device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
            device_name="cloud_server_dm",
        )
        assert self.cloud_server_dm.shared_data.this_device.ticket_order == 0
        assert self.cloud_server_dm.shared_data.this_device.device_priv_key_str == None
        assert self.cloud_server_dm.shared_data.this_device.device_pub_key_str == None
        assert self.cloud_server_dm.shared_data.this_device.owner_pub_key_str == None
        assert self.cloud_server_dm.shared_data.this_person.person_priv_key_str == None
        assert self.cloud_server_dm.shared_data.this_person.person_pub_key_str == None

        # WHEN: DM apply execute_one_time_intialize_agent_or_server() on Uninitialized CS
        current_test_when_and_then_log()
        self.cloud_server_dm.executor._execute_one_time_intialize_agent_or_server()

        # THEN: Succeed to initialized DM's CS
        assert self.cloud_server_dm.shared_data.this_device.ticket_order == 1
        assert self.cloud_server_dm.shared_data.this_device.device_priv_key_str != None
        assert self.cloud_server_dm.shared_data.this_device.device_pub_key_str != None
        assert self.cloud_server_dm.shared_data.this_device.owner_pub_key_str != None
        assert self.cloud_server_dm.shared_data.this_person.person_priv_key_str != None
        assert self.cloud_server_dm.shared_data.this_person.person_pub_key_str != None

    def test_success_when_reboot(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Reboot DM's CS
        current_test_when_and_then_log()
        self.cloud_server_dm.reboot_device()

        # THEN: Still be Initialized DM's CS
        assert self.cloud_server_dm.shared_data.this_device.ticket_order == 1
        assert self.cloud_server_dm.shared_data.this_device.device_priv_key_str != None
        assert self.cloud_server_dm.shared_data.this_device.device_pub_key_str != None
        assert self.cloud_server_dm.shared_data.this_device.owner_pub_key_str != None
        assert self.cloud_server_dm.shared_data.this_person.person_priv_key_str != None
        assert self.cloud_server_dm.shared_data.this_person.person_pub_key_str != None

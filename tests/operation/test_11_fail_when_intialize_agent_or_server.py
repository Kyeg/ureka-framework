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
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device


class TestFailWhenInitializeAgentOrServer:
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

    ######################################################
    # Threat: Reset
    ######################################################
    def test_fail_when_re_initialize_agent_or_server(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: DM re-apply execute_one_time_intialize_agent_or_server() on Initialized CS
        current_test_when_and_then_log()
        with pytest.raises(RuntimeError) as error_info:
            self.cloud_server_dm.executor._execute_one_time_intialize_agent_or_server()

        # THEN: Fail to re-initialize CS
        assert (
            str(error_info.value)
            == "-> FAILURE: VERIFY_TICKET_ORDER: USER-AGENT-OR-CLOUD-SERVER ALREADY INITIALIZED"
        )

    ######################################################
    # Function: Wrong API
    ######################################################
    @pytest.mark.skip(
        reason="TODO: New way for _execute_one_time_intialize_agent_or_server()"
    )
    def test_fail_when_initialize_agent_or_server_by_intializing_device(self) -> None:
        current_test_given_log()
        current_test_when_and_then_log()

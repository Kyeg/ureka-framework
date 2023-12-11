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


class TestFailWhenApplyArbitraryInput:
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
    # Function: Weird UI Input
    ######################################################
    @pytest.mark.skip(reason="TODO: Weird UI Input: Better to be tested")
    def test_fail_when_apply_wrong_format_ticket_request(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TODO: Weird UI Input: Better to be tested")
    def test_fail_when_apply_wrong_format_token_request(self) -> None:
        current_test_given_log()

    ######################################################
    # Function: Weird COMM Input
    ######################################################
    @pytest.mark.skip(reason="TODO: Weird COMM Input: Better to be tested")
    def test_fail_when_apply_wrong_format_u_ticket(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TODO: Weird COMM Input: Better to be tested")
    def test_fail_when_apply_wrong_format_r_ticket(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TODO: Weird COMM Input: Better to be tested")
    def test_fail_when_apply_wrong_format_u_token(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TODO: Weird COMM Input: Better to be tested")
    def test_fail_when_apply_wrong_format_r_token(self) -> None:
        current_test_given_log()

import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    create_comm_connection,
    wait_comm_completed,
    device_owner_agent,
    device_manufacturer_server_and_her_device,
    device_owner_agent_and_her_device,
    attacker_server,
)
from ureka_framework.model.data_model.other_device import OtherDevice
import ureka_framework.model.message_model.u_ticket as u_ticket
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


class TestAccessDeviceByOwner:
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

    # def test_success_when_apply_self_access_u_ticket(self) -> None:
    #     current_test_given_log()

    # def test_success_when_reboot(self) -> None:
    #     current_test_given_log()

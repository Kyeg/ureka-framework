from ureka_framework.resource.logger.simple_logger import simple_log
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_owner_agent_and_her_device_and_attacker,
    enterprise_provider_server,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
import ureka_framework.model.message_model.u_ticket as u_ticket
from typing import Iterator


class TestArbitraryInput:
    @pytest.fixture(scope="function", autouse=True)
    def setup_teardown(self) -> Iterator[None]:
        # RE-GIVEN: Reset the test environment
        current_setup_log()
        SimpleStorage.delete_storage_in_test()

        # GIVEN: Initialized DO's UA and DO's IoTD
        # GIVEN: Initialized ATK's CS
        current_test_given_log()
        (
            self.user_agent_do,
            self.iot_device,
            self.cloud_server_atk,
        ) = device_owner_agent_and_her_device_and_attacker()

        # GIVEN: A Public Key
        self.device_pub_key_str = (
            self.iot_device.shared_data.this_device.device_pub_key_str
        )

        # WHEN+THEN:
        yield

        # RE-GIVEN: Reset the test environment
        current_teardown_log()
        SimpleStorage.delete_storage_in_test()

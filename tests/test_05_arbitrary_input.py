from returns.result import Result, Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_owner_agent_and_her_device,
    enterprise_provider_server,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.crypto import serialization_util
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

    # @pytest.mark.skip(reason="Skip this test for now")
    def test_apply_arbitrary_request(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.cloud_server_dm,
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized EP's CS
        self.cloud_server_ep = enterprise_provider_server()

        # WHEN: DO's UA do not allow EP's CS to apply_any_ticket() on DO's IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_ep.device_pub_key_str}",
            "ticket_type": f"UNDEFINED-TICKET-TYPE",
            "task_scope": f"{serialization_util.dict_to_jsonstr({ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER})}",
        }
        test_ticket: str = self.cloud_server_ep.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Fail to do anything on DO's IoTD
        assert type(result) == Failure

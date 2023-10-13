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
    create_comm_connection,
    wait_comm_completed,
)
from tests.conftest import (
    device_manufacturer_server,
    device_manufacturer_server_and_her_device,
    device_owner_agent,
    device_owner_agent_and_her_device,
    enterprise_provider_server,
    enterprise_provider_server_and_her_session,
    attacker_server,
    device_owner_agent_and_her_device_and_attacker,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator

######################################################
# Import
######################################################


class TestFailWhenAccessDeviceByOthers:
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

    ######################################################
    # (S) Spoofing, (T) Tampering, (E) Elevation of privilege
    ######################################################
    @pytest.mark.skip(reason="TO-DO: Should be tested")
    def test_fail_when_apply_wrong_issuer_signature(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TO-DO: Should be tested")
    def test_fail_when_apply_wrong_holder_signature(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TO-DO: Should be tested")
    def test_fail_when_apply_wrong_hmac(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TO-DO: Should be tested")
    def test_fail_when_reuse_the_same_uticket(self) -> None:
        current_test_given_log()

    @pytest.mark.skip(reason="TO-DO: Should be tested")
    def test_fail_when_reuse_the_same_utoken(self) -> None:
        current_test_given_log()

    ######################################################
    # (R) Repudiation
    ######################################################
    @pytest.mark.skip(reason="TODO: More complete Tx")
    def test_fail_when_double_issuing_or_double_spending(self) -> None:
        current_test_given_log()

    ######################################################
    # (I) Information Disclosure
    ######################################################
    @pytest.mark.skip(reason="TODO: Not sure how to test")
    def test_fail_when_eavesdropping(self) -> None:
        current_test_given_log()

    ######################################################
    # (D) Denial of Service
    ######################################################
    @pytest.mark.skip(reason="TODO: Not implement yet")
    def test_fail_when_flooding(self) -> None:
        current_test_given_log()

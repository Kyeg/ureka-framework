import logging
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.storage.secure_db import SecureDB
from typing import Iterator


class TestSerialization:
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

    def test_device_serialization(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS
        self.cloud_server_dm = device_manufacturer_server()

        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()
        logging.warning(f"device-befo = {self.cloud_server_dm.this_device}")
        json_str = serialization_util.this_device_to_jsonstr(
            self.cloud_server_dm.this_device
        )
        logging.warning(f"json_str = {json_str}")

        obj = serialization_util.jsonstr_to_this_device(json_str)
        logging.warning(f"device-befo = {self.cloud_server_dm.this_device}")
        logging.warning(f"device-aftr = {obj}")

        # THEN: The result of serialization/deserialization should be the same
        logging.warning(
            f"key-befo.str = {self.cloud_server_dm.this_device.device_priv_key_str}"
        )
        logging.warning(f"key-aftr.str = {obj.device_priv_key_str}")
        # assert self.cloud_server_dm.this_device.device_priv_key == obj.device_priv_key    # wont equal...
        assert (
            self.cloud_server_dm.this_device.device_priv_key_str
            == obj.device_priv_key_str
        )

    @pytest.mark.skip(reason="Not tested yet")
    def test_person_serialization(self) -> None:
        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

    @pytest.mark.skip(reason="Not tested yet")
    def test_ticket_serialization(self) -> None:
        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

    @pytest.mark.skip(reason="Not tested yet")
    def test_key_serialization(self) -> None:
        # WHEN: Do some serialization/deserialization
        current_test_when_and_then_log()

import logging
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.data_model.this_device import (
    this_device_to_jsonstr,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator
from ureka_framework.resource.storage.simple_storage import SimpleStorage


class TestStorage:
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

    def test_store_and_load_storage(self) -> None:
        current_test_given_log()

        # GIVEN: A SimpleStorage
        self.simple_storage = SimpleStorage("test_storage")

        # GIVEN: An initialized DM's CS as test data
        self.cloud_server_dm = device_manufacturer_server()
        logging.debug(
            f"Original Device in RAM = {this_device_to_jsonstr(self.cloud_server_dm.this_device)}"
        )

        # WHEN: Variables are modified in the RAM
        current_test_when_and_then_log()
        self.cloud_server_dm.this_device.device_name = "another_new_device_name"
        logging.debug(
            f"Modified Device in RAM = {this_device_to_jsonstr(self.cloud_server_dm.this_device)}"
        )
        # WHEN: Variables are stored in the Storage
        self.simple_storage.store_storage(
            self.cloud_server_dm.this_device, self.cloud_server_dm.this_person
        )
        # WHEN: Variables are loaded from the Storage
        (
            updated_this_device,
            updated_this_person,
        ) = self.simple_storage.load_storage()
        logging.debug(
            f"Loaded Device from Storage = {this_device_to_jsonstr(updated_this_device)}"
        )

        # THEN: Check SimpleStorage/test_storage/this_device.json to ensure the variables are stored correctly
        # THEN: The variables loaded from the Storage should be the same with the variables modified in the RAM
        assert (
            updated_this_device.device_name
            == self.cloud_server_dm.this_device.device_name
        )

    def test_create_existed_dir(self) -> None:
        current_test_given_log()

        # GIVEN: A SimpleStorage
        self.simple_storage = SimpleStorage("test_storage")

        # WHEN: A repeated SimpleStorage is created
        current_test_when_and_then_log()
        self.another_storage = SimpleStorage("test_storage")

        # THEN: It's ok to create a repeated SimpleStorage
        # logging.debug(f"Exist: {self.path_device_controller}")

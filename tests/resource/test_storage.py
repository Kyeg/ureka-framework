from ureka_framework.resource.logger.simple_logger import simple_log
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_manufacturer_server,
)
from ureka_framework.model.message_model import u_ticket
from ureka_framework.model.data_model.other_device import (
    OtherDevice,
    device_table_to_jsonstr,
)
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


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

    def test_store_and_load_this_device(self) -> None:
        current_test_given_log()

        # GIVEN: A SimpleStorage
        self.simple_storage = SimpleStorage("test_storage")

        # GIVEN: An initialized DM's CS as test data
        self.cloud_server_dm = device_manufacturer_server()
        # simple_log("debug",
        #     f"Original Device in RAM = {this_device_to_jsonstr(self.cloud_server_dm.shared_data.this_device)}"
        # )

        # WHEN: Variables are modified in the RAM
        current_test_when_and_then_log()

        self.cloud_server_dm.shared_data.this_device.device_name = (
            "another_new_device_name"
        )
        # simple_log("debug",
        #     f"Modified Device in RAM = {this_device_to_jsonstr(self.cloud_server_dm.shared_data.this_device)}"
        # )

        # WHEN: Variables are stored in the Storage
        self.simple_storage.store_storage(
            self.cloud_server_dm.shared_data.this_device,
            self.cloud_server_dm.shared_data.device_table,
            self.cloud_server_dm.shared_data.this_person,
            self.cloud_server_dm.shared_data.current_session,
        )

        # WHEN: Variables are loaded from the Storage
        (
            updated_this_device,
            updated_device_table,
            updated_this_person,
            updated_current_session,
        ) = self.simple_storage.load_storage()

        # simple_log("debug",
        #     f"Loaded Device from Storage = {this_device_to_jsonstr(updated_this_device)}"
        # )

        # THEN: Check SimpleStorage/test_storage/this_device.json to ensure the variables are stored correctly
        # THEN: The variables loaded from the Storage should be the same with the variables modified in the RAM
        assert (
            updated_this_device.device_name
            == self.cloud_server_dm.shared_data.this_device.device_name
        )

    def test_store_and_load_device_table(self) -> None:
        current_test_given_log()

        # GIVEN: A SimpleStorage
        self.simple_storage = SimpleStorage("test_storage")

        # GIVEN: An initialized DM's CS as test data
        self.cloud_server_dm = device_manufacturer_server()
        simple_log(
            "debug",
            f"Original Other Devices in RAM = {device_table_to_jsonstr(self.cloud_server_dm.shared_data.device_table)}",
        )

        # WHEN: Variables are modified in the RAM
        current_test_when_and_then_log()
        self.cloud_server_dm.shared_data.this_device.device_name = (
            "another_new_device_name"
        )

        test_request_1: dict = {
            "device_id": f"device_id_1",
            "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
        }
        # u_ticket_json_1: str = self.cloud_server_dm.msg_generator._generate_xxx_u_ticket(
        #     test_request_1
        # )

        test_request_2: dict = {
            "device_id": f"device_id_1",
            "u_ticket_type": f"{u_ticket.TYPE_OWNERSHIP_UTICKET}",
        }
        # u_ticket_json_2: str = self.cloud_server_dm.msg_generator._generate_xxx_u_ticket(
        #     test_request_2
        # )

        self.cloud_server_dm.shared_data.device_table["device_id_1"] = OtherDevice(
            device_id="device_id_1",
            device_u_ticket_for_owner="u_ticket_json_1",
        )
        self.cloud_server_dm.shared_data.device_table["device_id_2"] = OtherDevice(
            device_id="device_id_2",
            device_u_ticket_for_owner="u_ticket_json_2",
        )
        simple_log(
            "debug",
            f"Modified Other Devices in RAM = {device_table_to_jsonstr(self.cloud_server_dm.shared_data.device_table)}",
        )

        # WHEN: Variables are stored in the Storage
        self.simple_storage.store_storage(
            self.cloud_server_dm.shared_data.this_device,
            self.cloud_server_dm.shared_data.device_table,
            self.cloud_server_dm.shared_data.this_person,
            self.cloud_server_dm.shared_data.current_session,
        )

        # WHEN: Variables are loaded from the Storage
        (
            updated_this_device,
            updated_device_table,
            updated_this_person,
            updated_current_session,
        ) = self.simple_storage.load_storage()

        simple_log(
            "debug",
            f"Loaded Other Devices from Storage = {device_table_to_jsonstr(updated_device_table)}",
        )

        # THEN: Check SimpleStorage/test_storage/device_table.json to ensure the variables are stored correctly
        # THEN: The variables loaded from the Storage should be the same with the variables modified in the RAM
        assert updated_device_table["device_id_1"].device_id == "device_id_1"
        assert updated_device_table["device_id_2"].device_id == "device_id_2"
        assert (
            self.cloud_server_dm.shared_data.device_table[
                "device_id_1"
            ].device_u_ticket_for_owner
            == "u_ticket_json_1"
        )
        assert (
            self.cloud_server_dm.shared_data.device_table[
                "device_id_2"
            ].device_u_ticket_for_owner
            == "u_ticket_json_2"
        )

    def test_create_existed_dir(self) -> None:
        current_test_given_log()

        # GIVEN: A SimpleStorage
        self.simple_storage = SimpleStorage("test_storage")

        # WHEN: A repeated SimpleStorage is created
        current_test_when_and_then_log()
        self.another_storage = SimpleStorage("test_storage")

        # THEN: It's ok to create a repeated SimpleStorage
        # simple_log("debug",f"Exist: {self.path_device_controller}")

import logging
from returns.result import Success, Failure
import pytest
from tests.conftest import (
    current_setup_log,
    current_teardown_log,
    current_test_given_log,
    current_test_when_and_then_log,
    device_owner_agent,
    device_manufacturer_server_and_her_device,
    device_owner_agent_and_her_device,
    attacker_server,
)
import ureka_framework.data_model.ticket as ticket
from ureka_framework.resource.communication.fake_comm_channel import FakeCommChannel
from ureka_framework.resource.crypto import serialization_util
from ureka_framework.resource.storage.simple_storage import SimpleStorage
from typing import Iterator


class TestTransferOwnershipDevice:
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

    def test_apply_management_ticket_with_storage_and_comm(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # GIVEN: Initialized DO's UA
        self.user_agent_do = device_owner_agent()

        # WHEN: DM's CS generate the management_ticket for DO's UA
        current_test_when_and_then_log()
        generated_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER})}",
        }
        generated_ticket: str = self.cloud_server_dm.generate_xxx_ticket(
            generated_request
        )
        logging.debug(f"Generated Ticket: {generated_ticket}")

        # WHEN: DM's CS send the management_ticket to DO's UA through Comm Channel
        fake_comm_chanel = FakeCommChannel(
            ends=[self.cloud_server_dm, self.user_agent_do]
        )
        self.cloud_server_dm.connect(fake_comm_chanel)
        self.user_agent_do.connect(fake_comm_chanel)
        self.cloud_server_dm.send_xxx_ticket(generated_ticket)
        received_ticket: str = self.user_agent_do.recv_xxx_ticket()
        logging.debug(f"Recveived Ticket: {received_ticket}")

        # WHEN: DO's UA query the management_ticket from device table
        stored_ticket: str = self.user_agent_do.device_table[
            self.iot_device.this_device.device_pub_key_str
        ].device_ticket
        logging.debug(f"Stored Ticket: {stored_ticket}")

        # WHEN: DO's UA foward the management_ticket on DM's IoTD through Comm Channel
        fake_comm_chanel = FakeCommChannel(ends=[self.user_agent_do, self.iot_device])
        self.user_agent_do.connect(fake_comm_chanel)
        self.iot_device.connect(fake_comm_chanel)
        self.user_agent_do.send_xxx_ticket(stored_ticket)
        forwarded_ticket: str = self.iot_device.recv_xxx_ticket()
        logging.debug(f"Forwarded Ticket: {forwarded_ticket}")
        result = self.iot_device.verify_xxx_ticket(forwarded_ticket)

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert type(result) == Success
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # GIVEN: Initialized DO's UA
        self.user_agent_do = device_owner_agent()

        # WHEN: DM's CS allow DO's UA to apply_management_ticket() on DM's IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER})}",
        }
        test_ticket: str = self.cloud_server_dm.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert type(result) == Success
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_ticket_with_reboot(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # WHEN: Reboot the DO's IoTD
        current_test_when_and_then_log()
        self.iot_device.reboot_device()

        # THEN: Still is successful to transfer ownership (become DO's IoTD)
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_ticket_wrong_owner_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: DO's UA do not allow ATK's CS to apply_management_ticket() on DO's IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "ticket_type": f"{ticket.TYPE_MANAGEMENT_TICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: ticket.MANAGEMENT_OWNER})}",
        }
        test_ticket: str = self.cloud_server_atk.generate_xxx_ticket(test_request)
        result = self.iot_device.verify_xxx_ticket(test_ticket)

        # THEN: Fail to transfer ownership (still DO's IoTD)
        assert type(result) == Failure
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

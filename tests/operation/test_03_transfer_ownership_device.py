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
import ureka_framework.data_model.u_ticket as u_ticket
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

    def test_apply_management_u_ticket_with_storage_and_comm(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # GIVEN: Initialized DO's UA
        self.user_agent_do = device_owner_agent()

        # WHEN: DM's CS generate the management_u_ticket for DO's UA
        current_test_when_and_then_log()
        generated_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        generated_u_ticket: str = self.cloud_server_dm.generate_xxx_u_ticket(
            generated_request
        )
        logging.debug(f"Generated UTicket: {generated_u_ticket}")

        # WHEN: DM's CS send the management_u_ticket to DO's UA through Comm Channel
        fake_comm_chanel = FakeCommChannel(
            ends=[self.cloud_server_dm, self.user_agent_do]
        )
        self.cloud_server_dm.connect(fake_comm_chanel)
        self.user_agent_do.connect(fake_comm_chanel)
        self.cloud_server_dm.send_xxx_u_ticket(generated_u_ticket)
        received_u_ticket: str = self.user_agent_do.recv_xxx_u_ticket()
        logging.debug(f"Recveived UTicket: {received_u_ticket}")

        # WHEN: DO's UA query the management_u_ticket from device table
        stored_u_ticket: str = self.user_agent_do.device_table[
            self.iot_device.this_device.device_pub_key_str
        ].device_u_ticket
        logging.debug(f"Stored UTicket: {stored_u_ticket}")

        # WHEN: DO's UA foward the management_u_ticket on DM's IoTD through Comm Channel
        fake_comm_chanel = FakeCommChannel(ends=[self.user_agent_do, self.iot_device])
        self.user_agent_do.connect(fake_comm_chanel)
        self.iot_device.connect(fake_comm_chanel)
        self.user_agent_do.send_xxx_u_ticket(stored_u_ticket)
        forwarded_u_ticket: str = self.iot_device.recv_xxx_u_ticket()
        logging.debug(f"Forwarded UTicket: {forwarded_u_ticket}")
        result = self.iot_device.verify_xxx_u_ticket(forwarded_u_ticket)

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert type(result) == Success
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_u_ticket(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DM's CS and DM's IoTD
        (
            self.cloud_server_dm,
            self.iot_device,
        ) = device_manufacturer_server_and_her_device()

        # GIVEN: Initialized DO's UA
        self.user_agent_do = device_owner_agent()

        # WHEN: DM's CS allow DO's UA to apply_management_u_ticket() on DM's IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.user_agent_do.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        test_u_ticket: str = self.cloud_server_dm.generate_xxx_u_ticket(test_request)
        result = self.iot_device.verify_xxx_u_ticket(test_u_ticket)

        # THEN: Succeed to transfer ownership (become DO's IoTD)
        assert type(result) == Success
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )

    def test_apply_management_u_ticket_with_reboot(self) -> None:
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

    def test_apply_management_u_ticket_wrong_owner_failed(self) -> None:
        current_test_given_log()

        # GIVEN: Initialized DO's UA and DO's IoTD
        (
            self.user_agent_do,
            self.iot_device,
        ) = device_owner_agent_and_her_device()

        # GIVEN: Initialized ATK's CS
        self.cloud_server_atk = attacker_server()

        # WHEN: DO's UA do not allow ATK's CS to apply_management_u_ticket() on DO's IoTD
        current_test_when_and_then_log()
        test_request: dict = {
            "device_id": f"{self.iot_device.this_device.device_pub_key_str}",
            "holder_id": f"{self.cloud_server_atk.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket.TYPE_MANAGEMENT_UTICKET}",
            "task_scope": f"{serialization_util.dict_to_jsonstr({u_ticket.REQUEST_BODY_MANAGEMENT_MANAGEMENT_TYPE: u_ticket.MANAGEMENT_OWNER})}",
        }
        test_u_ticket: str = self.cloud_server_atk.generate_xxx_u_ticket(test_request)
        result = self.iot_device.verify_xxx_u_ticket(test_u_ticket)

        # THEN: Fail to transfer ownership (still DO's IoTD)
        assert type(result) == Failure
        assert (
            self.iot_device.this_device.owner_pub_key_str
            == self.user_agent_do.this_person.person_pub_key_str
        )
